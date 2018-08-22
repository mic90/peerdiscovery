package peerdiscovery

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/ipv4"
)

const (
	// https://en.wikipedia.org/wiki/User_Datagram_Protocol#Packet_structure
	maxDatagramSize = 66507
)

// Discovered is the structure of the discovered peers,
// which holds their local address (port removed) and
// a payload if there is one.
type Discovered struct {
	// Address is the local address of a discovered peer.
	Address string
	// Payload is the associated payload from discovered peer.
	Payload []byte
}

// Settings are the settings that can be specified for
// doing peer discovery.
type Settings struct {
	// Limit is the number of peers to discover, use < 1 for unlimited.
	Limit int
	// Port is the port to broadcast on (the peers must also broadcast using the same port).
	// The default port is 9999.
	Port string
	// MulticastAddress specifies the multicast address.
	// You should be able to use any between 224.0.0.0 to 239.255.255.255.
	// By default it uses the Simple Service Discovery Protocol
	// address (239.255.255.250).
	MulticastAddress string
	// Payload is the bytes that are sent out with each broadcast. Must be short.
	Payload []byte
	// ResponsePayload is the bytes that are sent back to the client on each received Payload message
	ResponsePayload []byte
	// Delay is the amount of time between broadcasts. The default delay is 1 second.
	Delay time.Duration
	// AllowSelf will allow discovery the local machine (default false)
	AllowSelf bool

	portNum                 int
	multicastAddressNumbers []uint8
}

// PeerDiscovery is the object that can do the discovery for finding LAN peers.
type PeerDiscovery struct {
	settings Settings

	received map[string][]byte
	sync.RWMutex
}

// NewPeerDiscovery returns a new peerDiscovery object which can be used to discover peers.
// The settings are optional. If any setting is not supplied, then defaults are used.
// See the Settings for more information.
func NewPeerDiscovery(settings ...Settings) (p *PeerDiscovery, err error) {
	p = new(PeerDiscovery)

	// initialize settings
	s := Settings{}
	if len(settings) > 0 {
		s = settings[0]
	}
	p.settings = s

	// defaults
	if p.settings.Port == "" {
		p.settings.Port = "9999"
	}
	if p.settings.MulticastAddress == "" {
		p.settings.MulticastAddress = "239.255.255.250"
	}
	if len(p.settings.Payload) == 0 {
		p.settings.Payload = []byte("hi")
	}
	if p.settings.Delay == 0 {
		p.settings.Delay = 1 * time.Second
	}
	p.received = make(map[string][]byte)
	p.settings.multicastAddressNumbers = []uint8{0, 0, 0, 0}
	for i, num := range strings.Split(p.settings.MulticastAddress, ".") {
		var nInt int
		nInt, err = strconv.Atoi(num)
		if err != nil {
			return nil, err
		}
		p.settings.multicastAddressNumbers[i] = uint8(nInt)
	}
	p.settings.portNum, err = strconv.Atoi(p.settings.Port)
	if err != nil {
		return nil, err
	}
	return
}

func (p *PeerDiscovery) Listen(ctx context.Context) {
	go p.readAndRespond(ctx)
}

// Discover will use the created settings to scan for LAN peers. It will return
// an array of the discovered peers and their associate payloads. It will not
// return broadcasts sent to itself.
func (p *PeerDiscovery) Discover(ctx context.Context) (discoveries []Discovered, err error) {
	p.RLock()
	portNum := p.settings.portNum
	payload := p.settings.Payload
	tickerDuration := p.settings.Delay
	p.RUnlock()

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	conn, packetConn, group, err := p.multicastConnect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	go p.readAndRespond(ctx)

	ticker := time.NewTicker(tickerDuration)
	defer ticker.Stop()

	stop := false
	for !stop {
		select {
		case <-ticker.C:
			p.RLock()
			if p.settings.Limit > 0 && len(p.received) >= p.settings.Limit {
				stop = true
			}
			p.RUnlock()

			// write to multicast
			dst := &net.UDPAddr{IP: group, Port: portNum}
			for i := range ifaces {
				if errMulticast := packetConn.SetMulticastInterface(&ifaces[i]); errMulticast != nil {
					continue
				}
				packetConn.SetMulticastTTL(2)
				if _, errMulticast := packetConn.WriteTo([]byte(payload), nil, dst); errMulticast != nil {
					continue
				}
			}
		case <-ctx.Done():
			stop = true
		}
	}

	discoveries = make([]Discovered, len(p.received))
	i := 0
	p.RLock()
	for ip, payload := range p.received {
		discoveries[i] = Discovered{
			Address: ip,
			Payload: payload,
		}
		i++
	}
	p.RUnlock()
	return
}

// listens for incoming packets on all interfaces
func (p *PeerDiscovery) readAndRespond(ctx context.Context) {
	p.RLock()
	allowSelf := p.settings.AllowSelf
	response := p.settings.ResponsePayload
	p.RUnlock()

	localIPs := getLocalIPs()

	conn, packetConn, _, err := p.multicastConnect()
	if err != nil {
		return
	}
	defer conn.Close()

	// Loop forever reading from the socket
	buffer := make([]byte, maxDatagramSize)
	for {
		select {
		default:
			n, _, src, err := packetConn.ReadFrom(buffer)
			if err != nil {
				return
			}

			if _, ok := localIPs[strings.Split(src.String(), ":")[0]]; ok && !allowSelf {
				continue
			}

			if len(response) > 0 {
				_, err = packetConn.WriteTo(response, nil, src)
				if err != nil {
					return
				}
			}

			ip := strings.Split(src.String(), ":")[0]
			p.Lock()
			if _, ok := p.received[ip]; !ok {
				p.received[ip] = buffer[:n]
			}
			p.Unlock()
			p.RLock()
			if p.settings.Limit > 0 && len(p.received) >= p.settings.Limit {
				p.RUnlock()
				return
			}
			p.RUnlock()
		case <-ctx.Done():
			return
		}
	}
}

func (p *PeerDiscovery) multicastConnect() (net.PacketConn, *ipv4.PacketConn, net.IP, error) {
	p.RLock()
	address := p.settings.MulticastAddress + ":" + p.settings.Port
	portNum := p.settings.portNum
	multicastAddressNumbers := p.settings.multicastAddressNumbers
	p.RUnlock()

	// get interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, nil, err
	}

	// Open up a connection
	connection, err := net.ListenPacket("udp4", address)
	if err != nil {
		return nil, nil, nil, err
	}

	group := net.IPv4(multicastAddressNumbers[0], multicastAddressNumbers[1], multicastAddressNumbers[2], multicastAddressNumbers[3])
	packetConnection := ipv4.NewPacketConn(connection)

	for i := range ifaces {
		if errJoinGroup := packetConnection.JoinGroup(&ifaces[i], &net.UDPAddr{IP: group, Port: portNum}); errJoinGroup != nil {
			continue
		}
	}
	return connection, packetConnection, group, nil
}

// getLocalIPs returns the local ip address
func getLocalIPs() (ips map[string]struct{}) {
	ips = make(map[string]struct{})
	ips["localhost"] = struct{}{}
	ips["127.0.0.1"] = struct{}{}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return
	}
	for _, address := range addrs {
		ips[strings.Split(address.String(), "/")[0]] = struct{}{}
	}
	return
}
