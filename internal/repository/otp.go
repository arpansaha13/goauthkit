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

type OTPRepository struct {
	db QueryDB
	cb *gobreaker.CircuitBreaker[any]
}

func NewOTPRepository(db QueryDB, cb *gobreaker.CircuitBreaker[any]) *OTPRepository {
	return &OTPRepository{db: db, cb: cb}
}

func (r *OTPRepository) Create(ctx context.Context, otp *domain.OTP) error {
	_, err := r.cb.Execute(func() (any, error) {
		return nil, r.db.QueryRow(ctx, `
			INSERT INTO otps (user_id, otp_hash, hashed_code, purpose, expires_at, created_at)
			VALUES ($1, $2, $3, $4, $5, NOW())
			RETURNING id, created_at`,
			otp.UserID, otp.OTPHash, otp.HashedCode, otp.Purpose, otp.ExpiresAt,
		).Scan(&otp.ID, &otp.CreatedAt)
	})
	return err
}

func (r *OTPRepository) GetByOTPHash(ctx context.Context, otpHash string, purpose domain.OTPPurpose) (*domain.OTP, error) {
	return r.getOTP(ctx, `
		SELECT id, user_id, otp_hash, hashed_code, purpose, expires_at, deleted_at, created_at
		FROM otps WHERE otp_hash = $1 AND purpose = $2 AND deleted_at IS NULL`, otpHash, purpose)
}

func (r *OTPRepository) GetByUserIDAndPurpose(ctx context.Context, userID int64, purpose domain.OTPPurpose) (*domain.OTP, error) {
	return r.getOTP(ctx, `
		SELECT id, user_id, otp_hash, hashed_code, purpose, expires_at, deleted_at, created_at
		FROM otps WHERE user_id = $1 AND purpose = $2 AND deleted_at IS NULL`, userID, purpose)
}

func (r *OTPRepository) getOTP(ctx context.Context, query string, arg1 any, purpose domain.OTPPurpose) (*domain.OTP, error) {
	result, err := r.cb.Execute(func() (any, error) {
		var otp domain.OTP
		err := r.db.QueryRow(ctx, query, arg1, purpose).Scan(
			&otp.ID, &otp.UserID, &otp.OTPHash, &otp.HashedCode, &otp.Purpose, &otp.ExpiresAt, &otp.DeletedAt, &otp.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		return &otp, nil
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, &gtk.NotFoundError{Message: "otp not found"}
		}
		return nil, &gtk.InternalError{Message: "failed to get otp", Err: err}
	}
	return result.(*domain.OTP), nil
}

func (r *OTPRepository) SoftDeleteByOTPHash(ctx context.Context, otpHash string, purpose domain.OTPPurpose) error {
	_, err := r.cb.Execute(func() (any, error) {
		_, err := r.db.Exec(ctx, `UPDATE otps SET deleted_at = $3 WHERE otp_hash = $1 AND purpose = $2`, otpHash, purpose, time.Now())
		return nil, err
	})
	return err
}

func (r *OTPRepository) SoftDeleteByUserIDAndPurpose(ctx context.Context, userID int64, purpose domain.OTPPurpose) error {
	_, err := r.cb.Execute(func() (any, error) {
		_, err := r.db.Exec(ctx, `UPDATE otps SET deleted_at = $3 WHERE user_id = $1 AND purpose = $2`, userID, purpose, time.Now())
		return nil, err
	})
	return err
}

func (r *OTPRepository) DeleteExpiredAndSoftDeleted(ctx context.Context) error {
	_, err := r.cb.Execute(func() (any, error) {
		_, err := r.db.Exec(ctx, `DELETE FROM otps WHERE expires_at < $1 OR deleted_at IS NOT NULL`, time.Now())
		return nil, err
	})
	return err
}
