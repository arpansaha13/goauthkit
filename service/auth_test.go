package service_test

import (
	"context"
	"testing"
	"time"

	"github.com/arpansaha13/gotoolkit/gtk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/arpansaha13/goauthkit/domain"
	"github.com/arpansaha13/goauthkit/service"
	"github.com/arpansaha13/goauthkit/utils"
)

func TestAuthService_Signup(t *testing.T) {
	tests := []struct {
		name             string
		email            string
		password         string
		mockUserRepo     func() *MockUserRepository
		mockOTPRepo      func() *MockOTPRepository
		mockSessionRepo  func() *MockSessionRepository
		expectedError    bool
		validateResponse func(t *testing.T, resp *service.SignupResponse)
	}{
		{
			name:     "successful signup",
			email:    "test@example.com",
			password: "SecurePass123",
			mockUserRepo: func() *MockUserRepository {
				return &MockUserRepository{
					ExistsEmailFunc: func(ctx context.Context, email string) (bool, error) {
						return false, nil
					},
					CreateFunc: func(ctx context.Context, user *domain.User, credentials *domain.Credentials) error {
						user.ID = 1
						return nil
					},
				}
			},
			mockOTPRepo: func() *MockOTPRepository {
				return &MockOTPRepository{
					CreateFunc: func(ctx context.Context, otp *domain.OTP) error {
						return nil
					},
				}
			},
			mockSessionRepo: func() *MockSessionRepository {
				return &MockSessionRepository{}
			},
			expectedError: false,
			validateResponse: func(t *testing.T, resp *service.SignupResponse) {
				assert.NotEmpty(t, resp.Message)
				assert.NotEmpty(t, resp.OTPHash)
			},
		},
		{
			name:     "email already exists",
			email:    "existing@example.com",
			password: "SecurePass123",
			mockUserRepo: func() *MockUserRepository {
				return &MockUserRepository{
					ExistsEmailFunc: func(ctx context.Context, email string) (bool, error) {
						return true, nil
					},
				}
			},
			mockOTPRepo: func() *MockOTPRepository {
				return &MockOTPRepository{}
			},
			mockSessionRepo: func() *MockSessionRepository {
				return &MockSessionRepository{}
			},
			expectedError: true,
		},
	}

	hasher := utils.NewPasswordHasher()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userRepo := tt.mockUserRepo()
			otpRepo := tt.mockOTPRepo()
			sessionRepo := tt.mockSessionRepo()

			config := service.AuthServiceConfig{
				OTPExpiry:  time.Minute * 10,
				OTPLength:  6,
				SessionTTL: time.Hour * 24,
				SecretKey:  "secret",
			}
			svc, err := service.NewAuthService(userRepo, otpRepo, sessionRepo, &MockProviderRepository{}, &MockSessionCache{}, hasher, config, nil)
			require.NoError(t, err)
			resp, err := svc.Signup(context.Background(), service.SignupRequest{Email: tt.email, Password: tt.password})

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				tt.validateResponse(t, resp)
			}
		})
	}
}

func TestAuthService_Login(t *testing.T) {
	tests := []struct {
		name             string
		email            string
		password         string
		mockUserRepo     func() *MockUserRepository
		mockOTPRepo      func() *MockOTPRepository
		mockSessionRepo  func() *MockSessionRepository
		expectedError    bool
		validateResponse func(t *testing.T, resp *service.LoginResponse)
	}{
		{
			name:     "successful login",
			email:    "test@example.com",
			password: "SecurePass123",
			mockUserRepo: func() *MockUserRepository {
				hasher := utils.NewPasswordHasher()
				hashedPassword, _ := hasher.Hash("SecurePass123")
				creds := &domain.Credentials{PasswordHash: hashedPassword}
				return &MockUserRepository{
					GetByEmailFunc: func(ctx context.Context, email string) (*domain.User, error) {
						return &domain.User{
							ID:          1,
							Email:       email,
							Verified:    true,
							Credentials: creds,
						}, nil
					},
					UpdateLastLoginFunc: func(ctx context.Context, userID int64) error {
						return nil
					},
				}
			},
			mockOTPRepo: func() *MockOTPRepository {
				return &MockOTPRepository{}
			},
			mockSessionRepo: func() *MockSessionRepository {
				return &MockSessionRepository{
					CreateFunc: func(ctx context.Context, session *domain.Session) error {
						return nil
					},
				}
			},
			expectedError: false,
			validateResponse: func(t *testing.T, resp *service.LoginResponse) {
				assert.NotEmpty(t, resp.SessionToken)
				assert.False(t, resp.ExpiresAt.IsZero())
			},
		},
		{
			name:     "user not found",
			email:    "notfound@example.com",
			password: "SecurePass123",
			mockUserRepo: func() *MockUserRepository {
				return &MockUserRepository{
					GetByEmailFunc: func(ctx context.Context, email string) (*domain.User, error) {
						return nil, &gtk.NotFoundError{Message: "user not found"}
					},
				}
			},
			mockOTPRepo: func() *MockOTPRepository {
				return &MockOTPRepository{}
			},
			mockSessionRepo: func() *MockSessionRepository {
				return &MockSessionRepository{}
			},
			expectedError: true,
		},
	}

	hasher := utils.NewPasswordHasher()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userRepo := tt.mockUserRepo()
			otpRepo := tt.mockOTPRepo()
			sessionRepo := tt.mockSessionRepo()

			config := service.AuthServiceConfig{
				OTPExpiry:  time.Minute * 10,
				OTPLength:  6,
				SessionTTL: time.Hour * 24,
				SecretKey:  "secret",
			}
			svc, err := service.NewAuthService(userRepo, otpRepo, sessionRepo, &MockProviderRepository{}, &MockSessionCache{}, hasher, config, nil)
			require.NoError(t, err)
			resp, err := svc.Login(context.Background(), service.LoginRequest{Email: tt.email, Password: tt.password})

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				tt.validateResponse(t, resp)
			}
		})
	}
}

func TestAuthService_ValidateSession(t *testing.T) {
	tests := []struct {
		name             string
		token            string
		mockUserRepo     func() *MockUserRepository
		mockOTPRepo      func() *MockOTPRepository
		mockSessionRepo  func() *MockSessionRepository
		expectedError    bool
		validateResponse func(t *testing.T, resp *service.ValidateSessionResponse)
	}{
		{
			name:  "valid session token",
			token: "valid_token_123",
			mockUserRepo: func() *MockUserRepository {
				username := "alice"
				return &MockUserRepository{
					GetByIDFunc: func(ctx context.Context, userID int64) (*domain.User, error) {
						return &domain.User{
							ID:        userID,
							Email:     "alice@example.com",
							Username:  &username,
							Verified:  true,
							CreatedAt: time.Unix(1, 0).UTC(),
						}, nil
					},
				}
			},
			mockOTPRepo: func() *MockOTPRepository {
				return &MockOTPRepository{}
			},
			mockSessionRepo: func() *MockSessionRepository {
				return &MockSessionRepository{
					IsTokenValidFunc: func(ctx context.Context, tokenHash string) (bool, int64, error) {
						return true, 1, nil
					},
				}
			},
			expectedError: false,
			validateResponse: func(t *testing.T, resp *service.ValidateSessionResponse) {
				assert.Equal(t, int64(1), resp.UserID)
				assert.True(t, resp.Valid)
				require.NotNil(t, resp.User)
				assert.Equal(t, "alice@example.com", resp.User.Email)
				assert.Equal(t, "alice", resp.User.Username)
				assert.True(t, resp.User.Verified)
			},
		},
		{
			name:  "invalid session token",
			token: "invalid_token",
			mockUserRepo: func() *MockUserRepository {
				return &MockUserRepository{}
			},
			mockOTPRepo: func() *MockOTPRepository {
				return &MockOTPRepository{}
			},
			mockSessionRepo: func() *MockSessionRepository {
				return &MockSessionRepository{
					IsTokenValidFunc: func(ctx context.Context, tokenHash string) (bool, int64, error) {
						return false, 0, nil
					},
				}
			},
			expectedError: false,
			validateResponse: func(t *testing.T, resp *service.ValidateSessionResponse) {
				assert.Equal(t, int64(0), resp.UserID)
				assert.False(t, resp.Valid)
				assert.Nil(t, resp.User)
			},
		},
	}

	hasher := utils.NewPasswordHasher()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userRepo := tt.mockUserRepo()
			otpRepo := tt.mockOTPRepo()
			sessionRepo := tt.mockSessionRepo()

			config := service.AuthServiceConfig{
				OTPExpiry:  time.Minute * 10,
				OTPLength:  6,
				SessionTTL: time.Hour * 24,
				SecretKey:  "secret",
			}
			svc, err := service.NewAuthService(userRepo, otpRepo, sessionRepo, &MockProviderRepository{}, &MockSessionCache{}, hasher, config, nil)
			require.NoError(t, err)
			resp, err := svc.ValidateSession(context.Background(), service.ValidateSessionRequest{Token: tt.token})

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				tt.validateResponse(t, resp)
			}
		})
	}
}
