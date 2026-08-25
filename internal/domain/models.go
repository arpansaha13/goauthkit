package domain

import "time"

// ProviderType represents the type of OAuth provider
type ProviderType int16

const (
	ProviderTypeGoogle ProviderType = 1
)

// User represents the users table
type User struct {
	ID        int64
	Email     string
	Username  *string
	Verified  bool
	LastLogin *time.Time
	CreatedAt time.Time

	Credentials *Credentials
	OTP         *OTP
	Sessions    []Session
}

// Credentials represents the credentials table (one-to-one)
type Credentials struct {
	UserID       int64
	PasswordHash string
	User         *User
}

// OTPPurpose defines the purpose of an OTP code
type OTPPurpose int16

const (
	OTPPurposeSignupVerification OTPPurpose = 1
	OTPPurposeResetPassword      OTPPurpose = 2
)

// OTP represents the otps table
type OTP struct {
	ID         int64
	UserID     int64
	OTPHash    string
	HashedCode string
	Purpose    OTPPurpose
	ExpiresAt  time.Time
	DeletedAt  *time.Time
	CreatedAt  time.Time
	User       *User
}

// Session represents the sessions table
type Session struct {
	ID        int64
	UserID    int64
	TokenHash string
	ExpiresAt time.Time
	DeletedAt *time.Time
	CreatedAt time.Time
	User      *User
}

// UserProvider represents the user_providers table
type UserProvider struct {
	ProviderID  ProviderType
	ProviderSub string
	UserID      int64
	LastLoginAt time.Time
	CreatedAt   time.Time
	User        *User
}
