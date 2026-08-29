package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/arpansaha13/gotoolkit/gtk"
	"github.com/bradfitz/gomemcache/memcache"

	"github.com/arpansaha13/goauthkit/domain"
)

// MemcachedSessionCache implements ISessionCache using memcached as the backend.
// Circuit protection lives on the memcached client.
type MemcachedSessionCache struct {
	client *gtk.MemcachedClient
}

// NewMemcachedSessionCache creates a new session cache with a memcached client wrapper.
// If client is nil, operations become no-ops (graceful degradation).
func NewMemcachedSessionCache(client *gtk.MemcachedClient) *MemcachedSessionCache {
	return &MemcachedSessionCache{client: client}
}

// GetSessionByToken retrieves a full session from cache by token hash.
func (c *MemcachedSessionCache) GetSessionByToken(ctx context.Context, tokenHash string) (*domain.Session, error) {
	if c.client == nil {
		return nil, &gtk.NotFoundError{Message: "cache not available"}
	}

	item, err := c.client.Get(fmt.Sprintf("session:%s", tokenHash))
	if err != nil {
		if errors.Is(err, memcache.ErrCacheMiss) {
			return nil, &gtk.NotFoundError{Message: "session not found in cache"}
		}
		return nil, &gtk.InternalError{Message: "failed to get session from cache", Err: err}
	}

	var session domain.Session
	if err := json.Unmarshal(item.Value, &session); err != nil {
		return nil, &gtk.InternalError{Message: "failed to unmarshal session from cache", Err: err}
	}

	return &session, nil
}

// IsTokenValid checks if a token is valid in cache (exists, not expired, not deleted).
func (c *MemcachedSessionCache) IsTokenValid(ctx context.Context, tokenHash string) (bool, int64, error) {
	if c.client == nil {
		return false, 0, &gtk.NotFoundError{Message: "cache not available"}
	}

	item, err := c.client.Get(fmt.Sprintf("token_valid:%s", tokenHash))
	if err != nil {
		if errors.Is(err, memcache.ErrCacheMiss) {
			return false, 0, &gtk.NotFoundError{Message: "token validity not found in cache"}
		}
		return false, 0, &gtk.InternalError{Message: "failed to check token validity in cache", Err: err}
	}

	var data struct {
		Valid  bool  `json:"valid"`
		UserID int64 `json:"user_id"`
	}

	if err := json.Unmarshal(item.Value, &data); err != nil {
		return false, 0, &gtk.InternalError{Message: "failed to unmarshal token validity from cache", Err: err}
	}

	return data.Valid, data.UserID, nil
}

// SetSession stores a session in cache with a TTL.
// Errors are logged but not fatal - cache operations are best-effort.
func (c *MemcachedSessionCache) SetSession(ctx context.Context, tokenHash string, session *domain.Session, ttl time.Duration) error {
	if c.client == nil {
		return nil
	}

	sessionJSON, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	ttlSeconds := int32(ttl.Seconds())
	if ttlSeconds <= 0 {
		ttlSeconds = 1
	}

	if err := c.client.Set(&memcache.Item{
		Key:        fmt.Sprintf("session:%s", tokenHash),
		Value:      sessionJSON,
		Expiration: ttlSeconds,
	}); err != nil {
		return fmt.Errorf("failed to set session in cache: %w", err)
	}

	tokenValidData, err := json.Marshal(map[string]any{
		"valid":   true,
		"user_id": session.UserID,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal token validity: %w", err)
	}

	if err := c.client.Set(&memcache.Item{
		Key:        fmt.Sprintf("token_valid:%s", tokenHash),
		Value:      tokenValidData,
		Expiration: ttlSeconds,
	}); err != nil {
		return fmt.Errorf("failed to set token validity in cache: %w", err)
	}

	return nil
}

// InvalidateSessionToken removes a session token from cache.
// Errors are logged but not fatal - cache operations are best-effort.
func (c *MemcachedSessionCache) InvalidateSessionToken(ctx context.Context, tokenHash string) error {
	if c.client == nil {
		return nil
	}

	deleteCacheKey := func(key string) error {
		err := c.client.Delete(key)
		if err != nil && !errors.Is(err, memcache.ErrCacheMiss) {
			return err
		}
		return nil
	}

	// Delete session and token validity cache entries
	cacheKey := fmt.Sprintf("session:%s", tokenHash)
	tokenValidKey := fmt.Sprintf("token_valid:%s", tokenHash)

	if err := deleteCacheKey(cacheKey); err != nil {
		// Log but don't fail - cache is best-effort
		return fmt.Errorf("failed to delete session from cache: %w", err)
	}

	if err := deleteCacheKey(tokenValidKey); err != nil {
		// Log but don't fail - cache is best-effort
		return fmt.Errorf("failed to delete token validity from cache: %w", err)
	}

	// Double delete prevents stale session entries from being re-cached by concurrent readers.
	time.Sleep(25 * time.Millisecond)

	if err := deleteCacheKey(cacheKey); err != nil {
		// Log but don't fail - cache is best-effort
		return fmt.Errorf("failed to delete session from cache (second pass): %w", err)
	}

	if err := deleteCacheKey(tokenValidKey); err != nil {
		// Log but don't fail - cache is best-effort
		return fmt.Errorf("failed to delete token validity from cache (second pass): %w", err)
	}

	return nil
}
