package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/arpansaha13/goauthkit/internal/service"
	"github.com/arpansaha13/goauthkit/internal/utils"
	"github.com/arpansaha13/goauthkit/pb"
	"github.com/arpansaha13/goauthkit/tests/mocks"
	"github.com/arpansaha13/gotoolkit"
)

// newTestController creates a new AuthServiceImpl with a real validator for testing
func newTestController(mockService service.IAuthService) *AuthServiceImpl {
	validator := utils.NewValidator()
	return NewAuthServiceImpl(mockService, validator)
}

// TestSignupValidation tests request validation for Signup endpoint
func TestSignupValidation(t *testing.T) {
	type TestCaseData struct {
		Name          string
		Request       *pb.SignupRequest
		ExpectedError bool
		ErrorType     error
		MockFunc      func(ctx context.Context, req service.SignupRequest) (*service.SignupResponse, error)
	}

	testCases := []TestCaseData{
		{
			Name: "Valid signup request",
			Request: &pb.SignupRequest{
				Email:    "test@example.com",
				Password: "securePassword123",
			},
			ExpectedError: false,
			MockFunc: func(ctx context.Context, req service.SignupRequest) (*service.SignupResponse, error) {
				return &service.SignupResponse{Message: "success", OTPHash: "test-hash"}, nil
			},
		},
		{
			Name: "Missing email",
			Request: &pb.SignupRequest{
				Email:    "",
				Password: "securePassword123",
			},
			ExpectedError: true,
			ErrorType:     (*gotoolkit.ValidationError)(nil),
		},
		{
			Name: "Missing password",
			Request: &pb.SignupRequest{
				Email:    "test@example.com",
				Password: "",
			},
			ExpectedError: true,
			ErrorType:     (*gotoolkit.ValidationError)(nil),
		},
		{
			Name: "Both fields missing",
			Request: &pb.SignupRequest{
				Email:    "",
				Password: "",
			},
			ExpectedError: true,
			ErrorType:     (*gotoolkit.ValidationError)(nil),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			mockService := &mocks.MockAuthService{
				SignupFunc: tc.MockFunc,
			}
			controller := newTestController(mockService)
			resp, err := controller.Signup(context.Background(), tc.Request)

			if tc.ExpectedError {
				require.Error(t, err)
				assert.IsType(t, tc.ErrorType, err)
				assert.Nil(t, resp)
			} else {
				require.NoError(t, err)
				require.NotNil(t, resp)
				assert.Equal(t, "success", resp.Message)
				assert.Equal(t, "test-hash", resp.OtpHash)
			}
		})
	}
}

// TestVerifyOTPValidation tests request validation for VerifyOTP endpoint
func TestVerifyOTPValidation(t *testing.T) {
	type TestCaseData struct {
		Name          string
		Request       *pb.VerifyOTPRequest
		ExpectedError bool
		ErrorType     error
		MockFunc      func(ctx context.Context, req service.VerifyOTPRequest) (*service.VerifyOTPResponse, error)
	}

	testCases := []TestCaseData{
		{
			Name: "Valid verify OTP request",
			Request: &pb.VerifyOTPRequest{
				OtpHash: "test-hash-12345",
				Code:    "123456",
			},
			ExpectedError: false,
			MockFunc: func(ctx context.Context, req service.VerifyOTPRequest) (*service.VerifyOTPResponse, error) {
				return &service.VerifyOTPResponse{
					Message:      "success",
					Username:     "test_user",
					SessionToken: "token",
					OTPHash:      req.OTPHash,
				}, nil
			},
		},
		{
			Name: "Missing OTP hash",
			Request: &pb.VerifyOTPRequest{
				OtpHash: "",
				Code:    "123456",
			},
			ExpectedError: true,
			ErrorType:     (*gotoolkit.ValidationError)(nil),
		},
		{
			Name: "Missing OTP code",
			Request: &pb.VerifyOTPRequest{
				OtpHash: "test-hash-12345",
				Code:    "",
			},
			ExpectedError: true,
			ErrorType:     (*gotoolkit.ValidationError)(nil),
		},
		{
			Name: "Both fields missing",
			Request: &pb.VerifyOTPRequest{
				OtpHash: "",
				Code:    "",
			},
			ExpectedError: true,
			ErrorType:     (*gotoolkit.ValidationError)(nil),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			mockService := &mocks.MockAuthService{
				VerifyOTPFunc: tc.MockFunc,
			}
			controller := newTestController(mockService)
			resp, err := controller.VerifyOTP(context.Background(), tc.Request)

			if tc.ExpectedError {
				require.Error(t, err)
				assert.IsType(t, tc.ErrorType, err)
				assert.Nil(t, resp)
			} else {
				require.NoError(t, err)
				require.NotNil(t, resp)
				assert.Equal(t, "success", resp.Message)
				assert.Equal(t, "test_user", resp.Username)
				assert.NotEmpty(t, resp.SessionToken)
			}
		})
	}
}

// TestLoginValidation tests request validation for Login endpoint
func TestLoginValidation(t *testing.T) {
	type TestCaseData struct {
		Name          string
		Request       *pb.LoginRequest
		ExpectedError bool
		ErrorType     error
		MockFunc      func(ctx context.Context, req service.LoginRequest) (*service.LoginResponse, error)
	}

	testCases := []TestCaseData{
		{
			Name: "Valid login request",
			Request: &pb.LoginRequest{
				Email:    "test@example.com",
				Password: "securePassword123",
			},
			ExpectedError: false,
			MockFunc: func(ctx context.Context, req service.LoginRequest) (*service.LoginResponse, error) {
				return &service.LoginResponse{SessionToken: "token"}, nil
			},
		},
		{
			Name: "Missing email",
			Request: &pb.LoginRequest{
				Email:    "",
				Password: "securePassword123",
			},
			ExpectedError: true,
			ErrorType:     (*gotoolkit.ValidationError)(nil),
		},
		{
			Name: "Missing password",
			Request: &pb.LoginRequest{
				Email:    "test@example.com",
				Password: "",
			},
			ExpectedError: true,
			ErrorType:     (*gotoolkit.ValidationError)(nil),
		},
		{
			Name: "Both fields missing",
			Request: &pb.LoginRequest{
				Email:    "",
				Password: "",
			},
			ExpectedError: true,
			ErrorType:     (*gotoolkit.ValidationError)(nil),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			mockService := &mocks.MockAuthService{
				LoginFunc: tc.MockFunc,
			}
			controller := newTestController(mockService)
			resp, err := controller.Login(context.Background(), tc.Request)

			if tc.ExpectedError {
				require.Error(t, err)
				assert.IsType(t, tc.ErrorType, err)
				assert.Nil(t, resp)
			} else {
				require.NoError(t, err)
				require.NotNil(t, resp)
				assert.NotEmpty(t, resp.SessionToken)
			}
		})
	}
}

// TestSignupErrorHandling tests error handling for Signup endpoint
func TestSignupErrorHandling(t *testing.T) {
	type TestCaseData struct {
		Name          string
		Request       *pb.SignupRequest
		ServiceError  error
		ExpectedError bool
		ErrorType     error
		MockFunc      func(ctx context.Context, req service.SignupRequest) (*service.SignupResponse, error)
	}

	testCases := []TestCaseData{
		{
			Name: "Service returns conflict error",
			Request: &pb.SignupRequest{
				Email:    "test@example.com",
				Password: "securePassword123",
			},
			ServiceError:  &gotoolkit.ConflictError{Message: "email already registered"},
			ExpectedError: true,
			ErrorType:     (*gotoolkit.ConflictError)(nil),
			MockFunc: func(ctx context.Context, req service.SignupRequest) (*service.SignupResponse, error) {
				return nil, &gotoolkit.ConflictError{Message: "email already registered"}
			},
		},
		{
			Name: "Service returns validation error",
			Request: &pb.SignupRequest{
				Email:    "test@example.com",
				Password: "securePassword123",
			},
			ServiceError:  &gotoolkit.ValidationError{Message: "invalid email format", Field: "email"},
			ExpectedError: true,
			ErrorType:     (*gotoolkit.ValidationError)(nil),
			MockFunc: func(ctx context.Context, req service.SignupRequest) (*service.SignupResponse, error) {
				return nil, &gotoolkit.ValidationError{Message: "invalid email format", Field: "email"}
			},
		},
		{
			Name: "Service returns internal error",
			Request: &pb.SignupRequest{
				Email:    "test@example.com",
				Password: "securePassword123",
			},
			ServiceError:  &gotoolkit.InternalError{Message: "database error"},
			ExpectedError: true,
			ErrorType:     (*gotoolkit.InternalError)(nil),
			MockFunc: func(ctx context.Context, req service.SignupRequest) (*service.SignupResponse, error) {
				return nil, &gotoolkit.InternalError{Message: "database error"}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			mockService := &mocks.MockAuthService{
				SignupFunc: tc.MockFunc,
			}

			controller := newTestController(mockService)
			resp, err := controller.Signup(context.Background(), tc.Request)

			require.Error(t, err)
			assert.IsType(t, tc.ErrorType, err)
			assert.Nil(t, resp)
		})
	}
}

// TestForgotPasswordValidation tests request validation for ForgotPassword endpoint
func TestForgotPasswordValidation(t *testing.T) {
	type TestCaseData struct {
		Name          string
		Request       *pb.ForgotPasswordRequest
		ExpectedError bool
		ErrorType     error
		MockFunc      func(ctx context.Context, req service.ForgotPasswordRequest) (*service.ForgotPasswordResponse, error)
	}

	testCases := []TestCaseData{
		{
			Name: "Valid forgot password request",
			Request: &pb.ForgotPasswordRequest{
				Email: "user@example.com",
			},
			ExpectedError: false,
			MockFunc: func(ctx context.Context, req service.ForgotPasswordRequest) (*service.ForgotPasswordResponse, error) {
				return &service.ForgotPasswordResponse{
					Message: "if email exists, reset link will be sent",
					OTPHash: "test-hash",
				}, nil
			},
		},
		{
			Name: "Empty email",
			Request: &pb.ForgotPasswordRequest{
				Email: "",
			},
			ExpectedError: true,
			ErrorType:     (*gotoolkit.ValidationError)(nil),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			mockService := &mocks.MockAuthService{
				ForgotPasswordFunc: tc.MockFunc,
			}

			controller := newTestController(mockService)
			resp, err := controller.ForgotPassword(context.Background(), tc.Request)

			if tc.ExpectedError {
				require.Error(t, err)
				assert.IsType(t, tc.ErrorType, err)
				assert.Nil(t, resp)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, resp)
			}
		})
	}
}

// TestResetPasswordValidation tests request validation for ResetPassword endpoint
func TestResetPasswordValidation(t *testing.T) {
	type TestCaseData struct {
		Name          string
		Request       *pb.ResetPasswordRequest
		ExpectedError bool
		ErrorType     error
		MockFunc      func(ctx context.Context, req service.ResetPasswordRequest) (*service.ResetPasswordResponse, error)
	}

	testCases := []TestCaseData{
		{
			Name: "Valid reset password request",
			Request: &pb.ResetPasswordRequest{
				OtpHash:  "test-hash",
				Code:     "123456",
				Password: "newPassword123",
			},
			ExpectedError: false,
			MockFunc: func(ctx context.Context, req service.ResetPasswordRequest) (*service.ResetPasswordResponse, error) {
				return &service.ResetPasswordResponse{
					Message: "password reset successfully",
				}, nil
			},
		},
		{
			Name: "Empty OTP hash",
			Request: &pb.ResetPasswordRequest{
				OtpHash:  "",
				Code:     "123456",
				Password: "newPassword123",
			},
			ExpectedError: true,
			ErrorType:     (*gotoolkit.ValidationError)(nil),
		},
		{
			Name: "Invalid OTP code format",
			Request: &pb.ResetPasswordRequest{
				OtpHash:  "test-hash",
				Code:     "12345", // Too short
				Password: "newPassword123",
			},
			ExpectedError: true,
			ErrorType:     (*gotoolkit.ValidationError)(nil),
		},
		{
			Name: "Password too short",
			Request: &pb.ResetPasswordRequest{
				OtpHash:  "test-hash",
				Code:     "123456",
				Password: "short", // Less than 8 characters
			},
			ExpectedError: true,
			ErrorType:     (*gotoolkit.ValidationError)(nil),
		},
		{
			Name: "Unauthorized - invalid OTP",
			Request: &pb.ResetPasswordRequest{
				OtpHash:  "invalid-hash",
				Code:     "123456",
				Password: "newPassword123",
			},
			ExpectedError: true,
			ErrorType:     (*gotoolkit.UnauthorizedError)(nil),
			MockFunc: func(ctx context.Context, req service.ResetPasswordRequest) (*service.ResetPasswordResponse, error) {
				return nil, &gotoolkit.UnauthorizedError{Message: "invalid otp code"}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			mockService := &mocks.MockAuthService{
				ResetPasswordFunc: tc.MockFunc,
			}

			controller := newTestController(mockService)
			resp, err := controller.ResetPassword(context.Background(), tc.Request)

			if tc.ExpectedError {
				require.Error(t, err)
				assert.IsType(t, tc.ErrorType, err)
				assert.Nil(t, resp)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, resp)
			}
		})
	}
}
