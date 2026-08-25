package repository

import (
	"context"
	"errors"
	"time"

	"github.com/arpansaha13/gotoolkit/gtk"
	"github.com/sony/gobreaker/v2"

	"github.com/arpansaha13/goauthkit/internal/domain"
)

type SessionRepository struct {
	db *gtk.PostgresClient
	cb *gobreaker.CircuitBreaker[any]
}

func NewSessionRepository(db *gtk.PostgresClient, cb *gobreaker.CircuitBreaker[any]) *SessionRepository {
	return &SessionRepository{db: db, cb: cb}
}

func (r *SessionRepository) Create(ctx context.Context, session *domain.Session) error {
	_, err := r.cb.Execute(func() (any, error) {
		return nil, r.db.QueryRow(ctx, `
			INSERT INTO sessions (user_id, token_hash, expires_at, created_at)
			VALUES ($1, $2, $3, NOW())
			RETURNING id, created_at`,
			session.UserID, session.TokenHash, session.ExpiresAt,
		).Scan(&session.ID, &session.CreatedAt)
	})
	return err
}

func (r *SessionRepository) GetByTokenHash(ctx context.Context, tokenHash string) (*domain.Session, error) {
	result, err := r.cb.Execute(func() (any, error) {
		var session domain.Session
		err := gtk.MapNoRows(r.db.QueryRow(ctx, `
			SELECT id, user_id, token_hash, expires_at, deleted_at, created_at
			FROM sessions WHERE token_hash = $1 AND deleted_at IS NULL`, tokenHash,
		).Scan(&session.ID, &session.UserID, &session.TokenHash, &session.ExpiresAt, &session.DeletedAt, &session.CreatedAt))
		if err != nil {
			return nil, err
		}
		return &session, nil
	})
	if err != nil {
		if errors.Is(err, &gtk.RecordNotFoundError{}) {
			return nil, &gtk.NotFoundError{Message: "session not found"}
		}
		return nil, &gtk.InternalError{Message: "failed to get session", Err: err}
	}
	return result.(*domain.Session), nil
}

func (r *SessionRepository) GetByUserID(ctx context.Context, userID int64) ([]domain.Session, error) {
	result, err := r.cb.Execute(func() (any, error) {
		rows, err := r.db.Query(ctx, `
			SELECT id, user_id, token_hash, expires_at, deleted_at, created_at
			FROM sessions WHERE user_id = $1 AND expires_at > $2 AND deleted_at IS NULL`, userID, time.Now())
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var sessions []domain.Session
		for rows.Next() {
			var session domain.Session
			if err := rows.Scan(&session.ID, &session.UserID, &session.TokenHash, &session.ExpiresAt, &session.DeletedAt, &session.CreatedAt); err != nil {
				return nil, err
			}
			sessions = append(sessions, session)
		}
		return sessions, rows.Err()
	})
	if err != nil {
		return nil, &gtk.InternalError{Message: "failed to get sessions", Err: err}
	}
	return result.([]domain.Session), nil
}

func (r *SessionRepository) Update(ctx context.Context, session *domain.Session) error {
	_, err := r.cb.Execute(func() (any, error) {
		_, err := r.db.Exec(ctx, `
			UPDATE sessions SET user_id = $2, token_hash = $3, expires_at = $4, deleted_at = $5
			WHERE id = $1`,
			session.ID, session.UserID, session.TokenHash, session.ExpiresAt, session.DeletedAt)
		return nil, err
	})
	return err
}

func (r *SessionRepository) Delete(ctx context.Context, sessionID int64) error {
	_, err := r.cb.Execute(func() (any, error) {
		_, err := r.db.Exec(ctx, `DELETE FROM sessions WHERE id = $1`, sessionID)
		return nil, err
	})
	return err
}

func (r *SessionRepository) SoftDelete(ctx context.Context, sessionID int64) error {
	_, err := r.cb.Execute(func() (any, error) {
		_, err := r.db.Exec(ctx, `UPDATE sessions SET deleted_at = $2 WHERE id = $1`, sessionID, time.Now())
		return nil, err
	})
	return err
}

func (r *SessionRepository) SoftDeleteByUserID(ctx context.Context, userID int64) error {
	_, err := r.cb.Execute(func() (any, error) {
		_, err := r.db.Exec(ctx, `UPDATE sessions SET deleted_at = $2 WHERE user_id = $1`, userID, time.Now())
		return nil, err
	})
	return err
}

func (r *SessionRepository) DeleteExpiredAndSoftDeleted(ctx context.Context) error {
	_, err := r.cb.Execute(func() (any, error) {
		_, err := r.db.Exec(ctx, `DELETE FROM sessions WHERE expires_at < $1 OR deleted_at IS NOT NULL`, time.Now())
		return nil, err
	})
	return err
}

func (r *SessionRepository) IsTokenValid(ctx context.Context, tokenHash string) (bool, int64, error) {
	type tokenResult struct {
		valid  bool
		userID int64
	}

	res, err := r.cb.Execute(func() (any, error) {
		var userID int64
		err := gtk.MapNoRows(r.db.QueryRow(ctx, `
			SELECT user_id FROM sessions
			WHERE token_hash = $1 AND expires_at > $2 AND deleted_at IS NULL`,
			tokenHash, time.Now(),
		).Scan(&userID))
		if err != nil {
			if errors.Is(err, &gtk.RecordNotFoundError{}) {
				return tokenResult{false, 0}, nil
			}
			return nil, err
		}
		return tokenResult{true, userID}, nil
	})

	if err != nil {
		return false, 0, &gtk.InternalError{Message: "failed to validate token", Err: err}
	}

	r2 := res.(tokenResult)
	return r2.valid, r2.userID, nil
}
