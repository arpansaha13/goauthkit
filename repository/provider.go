package repository

import (
	"context"
	"errors"
	"time"

	"github.com/arpansaha13/gotoolkit/gtk"
	"github.com/sony/gobreaker/v2"

	"github.com/arpansaha13/goauthkit/domain"
)

type ProviderRepository struct {
	db *gtk.PostgresClient
	cb *gobreaker.CircuitBreaker[any]
}

func NewProviderRepository(db *gtk.PostgresClient, cb *gobreaker.CircuitBreaker[any]) *ProviderRepository {
	return &ProviderRepository{db: db, cb: cb}
}

func (r *ProviderRepository) Create(ctx context.Context, provider *domain.UserProvider) error {
	_, err := r.cb.Execute(func() (any, error) {
		_, err := r.db.Exec(ctx, `
			INSERT INTO user_providers (provider_id, provider_sub, user_id, last_login_at, created_at)
			VALUES ($1, $2, $3, NOW(), NOW())`,
			provider.ProviderID, provider.ProviderSub, provider.UserID)
		return nil, err
	})
	if err != nil {
		return &gtk.InternalError{Message: "failed to link provider", Err: err}
	}
	return nil
}

func (r *ProviderRepository) GetByProvider(ctx context.Context, providerID domain.ProviderType, providerSub string) (*domain.UserProvider, error) {
	result, err := r.cb.Execute(func() (any, error) {
		var provider domain.UserProvider
		err := gtk.MapNoRows(r.db.QueryRow(ctx, `
			SELECT provider_id, provider_sub, user_id, last_login_at, created_at
			FROM user_providers WHERE provider_id = $1 AND provider_sub = $2`,
			providerID, providerSub,
		).Scan(&provider.ProviderID, &provider.ProviderSub, &provider.UserID, &provider.LastLoginAt, &provider.CreatedAt))
		if err != nil {
			return nil, err
		}
		return &provider, nil
	})
	if err != nil {
		if errors.Is(err, &gtk.RecordNotFoundError{}) {
			return nil, &gtk.NotFoundError{Message: "provider link not found"}
		}
		return nil, &gtk.InternalError{Message: "failed to get provider link", Err: err}
	}
	return result.(*domain.UserProvider), nil
}

func (r *ProviderRepository) UpdateLastLogin(ctx context.Context, providerID domain.ProviderType, providerSub string) error {
	_, err := r.cb.Execute(func() (any, error) {
		_, err := r.db.Exec(ctx, `
			UPDATE user_providers SET last_login_at = $3
			WHERE provider_id = $1 AND provider_sub = $2`,
			providerID, providerSub, time.Now())
		return nil, err
	})
	return err
}
