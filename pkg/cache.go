package goauthkit

import (
	"github.com/bradfitz/gomemcache/memcache"
	"github.com/sony/gobreaker/v2"

	"github.com/arpansaha13/goauthkit/internal/cache"
)

// NewSessionCache creates a new session cache instance backed by memcached.
// The cache implementation uses the provided circuit breaker for fault tolerance.
// If either client or circuit breaker is nil, operations will gracefully degrade to no-ops.
func NewSessionCache(
	client *memcache.Client,
	cb *gobreaker.CircuitBreaker[any],
) cache.ISessionCache {
	return cache.NewSessionCache(client, cb)
}
