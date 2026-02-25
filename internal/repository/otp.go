package repository

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/arpansaha13/goauthkit/internal/domain"
	"github.com/arpansaha13/gotoolkit"
)

// OTPRepository handles OTP-related database operations
type OTPRepository struct {
	db *gorm.DB
}

// NewOTPRepository creates a new OTP repository
func NewOTPRepository(db *gorm.DB) *OTPRepository {
	return &OTPRepository{db: db}
}

// Create creates a new OTP record
func (r *OTPRepository) Create(ctx context.Context, otp *domain.OTP) error {
	return r.db.WithContext(ctx).Create(otp).Error
}

// GetByOTPHash retrieves OTP by OTP hash and purpose (excludes soft-deleted)
func (r *OTPRepository) GetByOTPHash(ctx context.Context, otpHash string, purpose domain.OTPPurpose) (*domain.OTP, error) {
	var otp domain.OTP
	err := r.db.WithContext(ctx).
		Where("otp_hash = ? AND purpose = ? AND deleted_at IS NULL", otpHash, purpose).
		First(&otp).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, &gotoolkit.NotFoundError{Message: "otp not found"}
		}
		return nil, &gotoolkit.InternalError{Message: "failed to get otp", Err: err}
	}

	return &otp, nil
}

// GetByUserIDAndPurpose retrieves OTP by user ID and purpose (excludes soft-deleted)
func (r *OTPRepository) GetByUserIDAndPurpose(ctx context.Context, userID int64, purpose domain.OTPPurpose) (*domain.OTP, error) {
	var otp domain.OTP
	err := r.db.WithContext(ctx).
		Where("user_id = ? AND purpose = ? AND deleted_at IS NULL", userID, purpose).
		First(&otp).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, &gotoolkit.NotFoundError{Message: "otp not found"}
		}
		return nil, &gotoolkit.InternalError{Message: "failed to get otp", Err: err}
	}

	return &otp, nil
}

// SoftDelete soft-deletes an OTP record by OTP hash and purpose
func (r *OTPRepository) SoftDeleteByOTPHash(ctx context.Context, otpHash string, purpose domain.OTPPurpose) error {
	return r.db.WithContext(ctx).
		Model(&domain.OTP{}).
		Where("otp_hash = ? AND purpose = ?", otpHash, purpose).
		Update("deleted_at", time.Now()).Error
}

// SoftDeleteByUserIDAndPurpose soft-deletes an OTP record by user ID and purpose
func (r *OTPRepository) SoftDeleteByUserIDAndPurpose(ctx context.Context, userID int64, purpose domain.OTPPurpose) error {
	return r.db.WithContext(ctx).
		Model(&domain.OTP{}).
		Where("user_id = ? AND purpose = ?", userID, purpose).
		Update("deleted_at", time.Now()).Error
}

// DeleteExpiredAndSoftDeleted physically deletes expired and soft-deleted OTPs
func (r *OTPRepository) DeleteExpiredAndSoftDeleted(ctx context.Context) error {
	return r.db.WithContext(ctx).
		Where("expires_at < ? OR deleted_at IS NOT NULL", time.Now()).
		Delete(&domain.OTP{}).Error
}
