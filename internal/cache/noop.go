package cache

import (
	"context"
	"time"
	"github.com/arpansaha13/goauthkit/internal/domain"
)

// NoopSessionCache is a no-op implementation of ISessionCache.
type NoopSessionCache struct{}

func (n *NoopSessionCache) GetSessionByToken(ctx context.Context, tokenHash string) (*domain.Session, error) {
	return nil, nil
}

func (n *NoopSessionCache) IsTokenValid(ctx context.Context, tokenHash string) (bool, int64, error) {
	return false, 0, nil
}

func (n *NoopSessionCache) SetSession(ctx context.Context, tokenHash string, session *domain.Session, ttl time.Duration) error {
	return nil
}

func (n *NoopSessionCache) InvalidateSessionToken(ctx context.Context, tokenHash string) error {
	return nil
}

// Compile-time check to ensure NoopSessionCache implements ISessionCache
var _ ISessionCache = (*NoopSessionCache)(nil)
