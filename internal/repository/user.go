package repository

import (
	"context"
	"errors"
	"time"

	"github.com/arpansaha13/gotoolkit/gtk"
	"github.com/jackc/pgx/v5"
	"github.com/sony/gobreaker/v2"

	"github.com/arpansaha13/goauthkit/internal/domain"
)

type UserRepository struct {
	db QueryDB
	cb *gobreaker.CircuitBreaker[any]
}

func NewUserRepository(db QueryDB, cb *gobreaker.CircuitBreaker[any]) *UserRepository {
	return &UserRepository{db: db, cb: cb}
}

func (r *UserRepository) Create(ctx context.Context, user *domain.User, credentials *domain.Credentials) error {
	_, err := r.cb.Execute(func() (any, error) {
		tx, err := r.db.Begin(ctx)
		if err != nil {
			return nil, err
		}
		defer func() { _ = tx.Rollback(ctx) }()

		err = tx.QueryRow(ctx, `
			INSERT INTO users (email, username, verified, last_login, created_at)
			VALUES ($1, $2, $3, $4, NOW())
			RETURNING id, created_at`,
			user.Email, user.Username, user.Verified, user.LastLogin,
		).Scan(&user.ID, &user.CreatedAt)
		if err != nil {
			return nil, err
		}

		credentials.UserID = user.ID
		_, err = tx.Exec(ctx, `
			INSERT INTO credentials (user_id, password_hash) VALUES ($1, $2)`,
			credentials.UserID, credentials.PasswordHash)
		if err != nil {
			return nil, err
		}
		return nil, tx.Commit(ctx)
	})
	return err
}

func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	return r.getUser(ctx, `SELECT id, email, username, verified, last_login, created_at FROM users WHERE email = $1`, email, "user not found")
}

func (r *UserRepository) GetByID(ctx context.Context, userID int64) (*domain.User, error) {
	return r.getUser(ctx, `SELECT id, email, username, verified, last_login, created_at FROM users WHERE id = $1`, userID, "user not found")
}

func (r *UserRepository) GetByUsername(ctx context.Context, username string) (*domain.User, error) {
	return r.getUser(ctx, `SELECT id, email, username, verified, last_login, created_at FROM users WHERE username = $1`, username, "user not found")
}

func (r *UserRepository) getUser(ctx context.Context, query string, arg any, notFoundMsg string) (*domain.User, error) {
	result, err := r.cb.Execute(func() (any, error) {
		var user domain.User
		err := r.db.QueryRow(ctx, query, arg).Scan(
			&user.ID, &user.Email, &user.Username, &user.Verified, &user.LastLogin, &user.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		if err := r.loadRelations(ctx, &user); err != nil {
			return nil, err
		}
		return &user, nil
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, &gtk.NotFoundError{Message: notFoundMsg}
		}
		return nil, &gtk.InternalError{Message: "failed to get user", Err: err}
	}
	return result.(*domain.User), nil
}

func (r *UserRepository) loadRelations(ctx context.Context, user *domain.User) error {
	var creds domain.Credentials
	err := r.db.QueryRow(ctx, `SELECT user_id, password_hash FROM credentials WHERE user_id = $1`, user.ID).
		Scan(&creds.UserID, &creds.PasswordHash)
	if err == nil {
		user.Credentials = &creds
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}

	var otp domain.OTP
	err = r.db.QueryRow(ctx, `
		SELECT id, user_id, otp_hash, hashed_code, purpose, expires_at, deleted_at, created_at
		FROM otps WHERE user_id = $1 AND deleted_at IS NULL
		ORDER BY created_at DESC LIMIT 1`, user.ID,
	).Scan(&otp.ID, &otp.UserID, &otp.OTPHash, &otp.HashedCode, &otp.Purpose, &otp.ExpiresAt, &otp.DeletedAt, &otp.CreatedAt)
	if err == nil {
		user.OTP = &otp
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	return nil
}

func (r *UserRepository) UpdateVerified(ctx context.Context, userID int64, username string) error {
	_, err := r.cb.Execute(func() (any, error) {
		_, err := r.db.Exec(ctx, `UPDATE users SET verified = true, username = $2 WHERE id = $1`, userID, username)
		return nil, err
	})
	return err
}

func (r *UserRepository) UpdateLastLogin(ctx context.Context, userID int64) error {
	_, err := r.cb.Execute(func() (any, error) {
		_, err := r.db.Exec(ctx, `UPDATE users SET last_login = $2 WHERE id = $1`, userID, time.Now())
		return nil, err
	})
	return err
}

func (r *UserRepository) UpdatePassword(ctx context.Context, userID int64, newPasswordHash string) error {
	_, err := r.cb.Execute(func() (any, error) {
		_, err := r.db.Exec(ctx, `UPDATE credentials SET password_hash = $2 WHERE user_id = $1`, userID, newPasswordHash)
		return nil, err
	})
	return err
}

func (r *UserRepository) ExistsUsername(ctx context.Context, username string) (bool, error) {
	return r.exists(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)`, username, "failed to check username")
}

func (r *UserRepository) ExistsEmail(ctx context.Context, email string) (bool, error) {
	return r.exists(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)`, email, "failed to check email")
}

func (r *UserRepository) exists(ctx context.Context, query string, arg any, errMsg string) (bool, error) {
	result, err := r.cb.Execute(func() (any, error) {
		var exists bool
		if err := r.db.QueryRow(ctx, query, arg).Scan(&exists); err != nil {
			return nil, err
		}
		return exists, nil
	})
	if err != nil {
		return false, &gtk.InternalError{Message: errMsg, Err: err}
	}
	return result.(bool), nil
}

func (r *UserRepository) Delete(ctx context.Context, userID int64) error {
	_, err := r.cb.Execute(func() (any, error) {
		_, err := r.db.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
		return nil, err
	})
	return err
}
