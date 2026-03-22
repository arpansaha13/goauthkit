package pkg

import (
	"fmt"

	"github.com/bradfitz/gomemcache/memcache"
	"github.com/sony/gobreaker/v2"
	"google.golang.org/grpc"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	iccache "github.com/arpansaha13/goauthkit/internal/cache"
	"github.com/arpansaha13/goauthkit/internal/controller"
	"github.com/arpansaha13/goauthkit/internal/middleware"
	irepo "github.com/arpansaha13/goauthkit/internal/repository"
	isvc "github.com/arpansaha13/goauthkit/internal/service"
	iutil "github.com/arpansaha13/goauthkit/internal/utils"
	iworker "github.com/arpansaha13/goauthkit/internal/worker"
)

// ============================================================================
// Error Types
// ============================================================================

// ValidationError represents validation failures
type ValidationError struct {
	Message string
	Field   string
}

func (e *ValidationError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("validation error on field %s: %s", e.Field, e.Message)
	}
	return fmt.Sprintf("validation error: %s", e.Message)
}

// ConflictError represents resource conflict (e.g., duplicate email)
type ConflictError struct {
	Message string
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("conflict: %s", e.Message)
}

// NotFoundError represents missing resource
type NotFoundError struct {
	Message string
}

func (e *NotFoundError) Error() string {
	return fmt.Sprintf("not found: %s", e.Message)
}

// UnauthorizedError represents authentication failures
type UnauthorizedError struct {
	Message string
}

func (e *UnauthorizedError) Error() string {
	return fmt.Sprintf("unauthorized: %s", e.Message)
}

// InternalError represents unexpected server errors
type InternalError struct {
	Message string
	Err     error
}

func (e *InternalError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("internal error: %s - %v", e.Message, e.Err)
	}
	return fmt.Sprintf("internal error: %s", e.Message)
}

// IsConflict checks if an error is a ConflictError
func IsConflict(err error) bool {
	_, ok := err.(*ConflictError)
	return ok
}

// IsNotFound checks if an error is a NotFoundError
func IsNotFound(err error) bool {
	_, ok := err.(*NotFoundError)
	return ok
}

// IsUnauthorized checks if an error is an UnauthorizedError
func IsUnauthorized(err error) bool {
	_, ok := err.(*UnauthorizedError)
	return ok
}

// IsValidation checks if an error is a ValidationError
func IsValidation(err error) bool {
	_, ok := err.(*ValidationError)
	return ok
}

// ============================================================================
// Service Exports
// ============================================================================

// Interfaces
type IAuthService = isvc.IAuthService

// Service implementations
type AuthService = isvc.AuthService
type AuthServiceConfig = isvc.AuthServiceConfig

// Request/Response types
type SignupRequest = isvc.SignupRequest
type SignupResponse = isvc.SignupResponse
type VerifyOTPRequest = isvc.VerifyOTPRequest
type VerifyOTPResponse = isvc.VerifyOTPResponse
type LoginRequest = isvc.LoginRequest
type LoginResponse = isvc.LoginResponse
type ValidateSessionRequest = isvc.ValidateSessionRequest
type ValidateSessionResponse = isvc.ValidateSessionResponse
type RefreshSessionRequest = isvc.RefreshSessionRequest
type RefreshSessionResponse = isvc.RefreshSessionResponse
type LogoutRequest = isvc.LogoutRequest
type LogoutResponse = isvc.LogoutResponse
type ForgotPasswordRequest = isvc.ForgotPasswordRequest
type ForgotPasswordResponse = isvc.ForgotPasswordResponse
type ResetPasswordRequest = isvc.ResetPasswordRequest
type ResetPasswordResponse = isvc.ResetPasswordResponse
type GetUserRequest = isvc.GetUserRequest
type GetUserResponse = isvc.GetUserResponse
type GetUserByEmailRequest = isvc.GetUserByEmailRequest
type GetUserByEmailResponse = isvc.GetUserByEmailResponse
type DeleteUserRequest = isvc.DeleteUserRequest
type DeleteUserResponse = isvc.DeleteUserResponse

// NewAuthService creates a new auth service
func NewAuthService(
	userRepo IUserRepository,
	otpRepo IOTPRepository,
	sessionRepo ISessionRepository,
	sessionCache ISessionCache,
	hasher *PasswordHasher,
	config AuthServiceConfig,
) IAuthService {
	return isvc.NewAuthService(userRepo, otpRepo, sessionRepo, sessionCache, hasher, config)
}

// ============================================================================
// Repository Exports
// ============================================================================

// Interfaces
type IUserRepository = irepo.IUserRepository
type IOTPRepository = irepo.IOTPRepository
type ISessionRepository = irepo.ISessionRepository

// Repository implementations
type UserRepository = irepo.UserRepository
type OTPRepository = irepo.OTPRepository
type SessionRepository = irepo.SessionRepository

// NewUserRepository creates a new user repository
func NewUserRepository(db *gorm.DB, cb *gobreaker.CircuitBreaker[any]) IUserRepository {
	return irepo.NewUserRepository(db, cb)
}

// NewOTPRepository creates a new OTP repository
func NewOTPRepository(db *gorm.DB, cb *gobreaker.CircuitBreaker[any]) IOTPRepository {
	return irepo.NewOTPRepository(db, cb)
}

// NewSessionRepository creates a new session repository
func NewSessionRepository(db *gorm.DB, cb *gobreaker.CircuitBreaker[any]) ISessionRepository {
	return irepo.NewSessionRepository(db, cb)
}

// ============================================================================
// Cache Exports
// ============================================================================

// Interfaces
type ISessionCache = iccache.ISessionCache

// Cache implementations
type SessionCache = iccache.SessionCache

// NewSessionCache creates a new session cache backed by memcached
func NewSessionCache(client *memcache.Client, cb *gobreaker.CircuitBreaker[any]) ISessionCache {
	return iccache.NewSessionCache(client, cb)
}

// ============================================================================
// Utils Exports
// ============================================================================

type PasswordHasher = iutil.PasswordHasher
type Validator = iutil.Validator

// NewPasswordHasher creates a new password hasher
func NewPasswordHasher() *PasswordHasher {
	return iutil.NewPasswordHasher()
}

// NewValidator creates a new validator
func NewValidator() *Validator {
	return iutil.NewValidator()
}

// GenerateOTP generates a random OTP code
func GenerateOTP(length int) (string, error) {
	return iutil.GenerateOTP(length)
}

// ============================================================================
// Worker Exports
// ============================================================================

// Interfaces
type EmailProvider = iworker.EmailProvider

// Worker implementations
type EmailWorkerPool = iworker.EmailWorkerPool
type MockEmailProvider = iworker.MockEmailProvider
type SMTPEmailProvider = iworker.SMTPEmailProvider

// NewEmailWorkerPool creates a new email worker pool
func NewEmailWorkerPool(poolSize, queueSize int, provider EmailProvider) *iworker.EmailWorkerPool {
	return iworker.NewEmailWorkerPool(poolSize, queueSize, provider)
}

// NewMockEmailProvider creates a new mock email provider
func NewMockEmailProvider() EmailProvider {
	return iworker.NewMockEmailProvider()
}

// NewSMTPEmailProvider creates a new SMTP email provider
func NewSMTPEmailProvider(host string, port int, user, password, from string) EmailProvider {
	return iworker.NewSMTPEmailProvider(host, port, user, password, from)
}

// ============================================================================
// Controller Exports
// ============================================================================

// Controller implementations
type AuthServiceImpl = controller.AuthServiceImpl

// NewAuthServiceImpl creates a new gRPC auth service controller
func NewAuthServiceImpl(authService IAuthService, validator *Validator) *AuthServiceImpl {
	return controller.NewAuthServiceImpl(authService, validator)
}

// ============================================================================
// Middleware Exports
// ============================================================================

// AuthorizationInterceptor intercepts gRPC requests to validate session tokens
func AuthorizationInterceptor() grpc.UnaryServerInterceptor {
	return middleware.AuthorizationInterceptor()
}

// ============================================================================
// Database Helpers
// ============================================================================

// InitDB initializes a PostgreSQL database connection
func InitDB(dsn string) (*gorm.DB, error) {
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}
	return db, nil
}

// CloseDB closes the database connection
func CloseDB(db *gorm.DB) error {
	if db == nil {
		return nil
	}
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("failed to get database connection: %w", err)
	}
	return sqlDB.Close()
}
