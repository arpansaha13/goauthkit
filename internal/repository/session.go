package repository

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/arpansaha13/goauthkit/internal/domain"
	"github.com/arpansaha13/gotoolkit"
)

// SessionRepository handles session-related database operations
type SessionRepository struct {
	db *gorm.DB
}

// NewSessionRepository creates a new session repository
func NewSessionRepository(db *gorm.DB) *SessionRepository {
	return &SessionRepository{db: db}
}

// Create creates a new session
func (r *SessionRepository) Create(ctx context.Context, session *domain.Session) error {
	return r.db.WithContext(ctx).Create(session).Error
}

// GetByTokenHash retrieves a session by token hash
func (r *SessionRepository) GetByTokenHash(ctx context.Context, tokenHash string) (*domain.Session, error) {
	var session domain.Session
	err := r.db.WithContext(ctx).
		Where("token_hash = ?", tokenHash).
		First(&session).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, &gotoolkit.NotFoundError{Message: "session not found"}
		}
		return nil, &gotoolkit.InternalError{Message: "failed to get session", Err: err}
	}

	return &session, nil
}

// GetByUserID retrieves all valid sessions for a user
func (r *SessionRepository) GetByUserID(ctx context.Context, userID int64) ([]domain.Session, error) {
	var sessions []domain.Session
	err := r.db.WithContext(ctx).
		Where("user_id = ? AND expires_at > ?", userID, time.Now()).
		Find(&sessions).Error

	if err != nil {
		return nil, &gotoolkit.InternalError{Message: "failed to get sessions", Err: err}
	}

	return sessions, nil
}

// Update updates a session
func (r *SessionRepository) Update(ctx context.Context, session *domain.Session) error {
	return r.db.WithContext(ctx).Save(session).Error
}

// Delete removes a session (hard delete)
func (r *SessionRepository) Delete(ctx context.Context, sessionID int64) error {
	return r.db.WithContext(ctx).
		Where("id = ?", sessionID).
		Delete(&domain.Session{}).Error
}

// SoftDelete soft-deletes a session by setting deleted_at
func (r *SessionRepository) SoftDelete(ctx context.Context, sessionID int64) error {
	return r.db.WithContext(ctx).
		Model(&domain.Session{}).
		Where("id = ?", sessionID).
		Update("deleted_at", time.Now()).Error
}

// SoftDeleteByUserID soft-deletes all sessions for a user
func (r *SessionRepository) SoftDeleteByUserID(ctx context.Context, userID int64) error {
	return r.db.WithContext(ctx).
		Model(&domain.Session{}).
		Where("user_id = ?", userID).
		Update("deleted_at", time.Now()).Error
}

// DeleteExpiredAndSoftDeleted physically deletes expired and soft-deleted sessions
func (r *SessionRepository) DeleteExpiredAndSoftDeleted(ctx context.Context) error {
	return r.db.WithContext(ctx).
		Where("expires_at < ? OR deleted_at IS NOT NULL", time.Now()).
		Delete(&domain.Session{}).Error
}

// IsTokenValid checks if a token is valid (exists, not expired, and not soft-deleted)
func (r *SessionRepository) IsTokenValid(ctx context.Context, tokenHash string) (bool, int64, error) {
	var session domain.Session
	err := r.db.WithContext(ctx).
		Where("token_hash = ? AND expires_at > ? AND deleted_at IS NULL", tokenHash, time.Now()).
		First(&session).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, 0, nil
		}
		return false, 0, &gotoolkit.InternalError{Message: "failed to validate token", Err: err}
	}

	return true, session.UserID, nil
}
