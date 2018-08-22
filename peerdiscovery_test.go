package peerdiscovery

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDiscoveryWithSelfDiscoverDisabled(t *testing.T) {
	// should not be able to "discover" itself
	// GIVEN
	discovery, err := NewPeerDiscovery()
	timeoutCtx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	// WHEN
	discoveries, err := discovery.Discover(timeoutCtx)
	// THEN
	assert.Nil(t, err)
	assert.Zero(t, len(discoveries))
}

func TestDiscoveryWithSelfDiscoverEnabled(t *testing.T) {
	// should be able to "discover" itself
	// GIVEN
	discovery, err := NewPeerDiscovery(Settings{
		Limit:     -1,
		AllowSelf: true,
		Payload:   []byte("payload"),
		Delay:     500 * time.Millisecond,
	})
	timeoutCtx, _ := context.WithTimeout(context.Background(), 1*time.Second)
	// WHEN
	discoveries, err := discovery.Discover(timeoutCtx)
	// THEN
	assert.Nil(t, err)
	assert.NotZero(t, len(discoveries))
}

func TestListen(t *testing.T) {
	//GIVEN
	discovery, err := NewPeerDiscovery(Settings{
		Limit:           -1,
		Payload:         []byte("expected_msg"),
		ResponsePayload: []byte("answer"),
	})
	timeoutCtx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	//WHEN
	discovery.Listen(timeoutCtx)
	select {
	case <-timeoutCtx.Done():
		break
	}
	//THEN
	assert.Nil(t, err)
}
