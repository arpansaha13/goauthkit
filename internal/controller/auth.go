package controller

import (
	"context"

	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/arpansaha13/goauthkit/internal/service"
	"github.com/arpansaha13/goauthkit/internal/utils"
	"github.com/arpansaha13/goauthkit/pb"
	"github.com/arpansaha13/gotoolkit"
	"github.com/arpansaha13/gotoolkit/logger"
)

// AuthServiceImpl implements the gRPC AuthService
type AuthServiceImpl struct {
	pb.UnimplementedAuthServiceServer
	authService service.IAuthService
	validator   *utils.Validator
}

// NewAuthServiceImpl creates a new auth service implementation
func NewAuthServiceImpl(authService service.IAuthService, validator *utils.Validator) *AuthServiceImpl {
	return &AuthServiceImpl{
		authService: authService,
		validator:   validator,
	}
}

// Signup handles user registration
func (s *AuthServiceImpl) Signup(ctx context.Context, req *pb.SignupRequest) (*pb.SignupResponse, error) {
	// Validate request
	if err := s.validateSignupRequest(req); err != nil {
		logger.FromContext(ctx).Warn("signup validation error", zap.Error(err))
		return nil, err
	}

	// Call service
	serviceReq := service.SignupRequest{
		Email:    req.Email,
		Password: req.Password,
	}

	resp, err := s.authService.Signup(ctx, serviceReq)
	if err != nil {
		logger.FromContext(ctx).Error("signup error", zap.Error(err))
		return nil, err
	}

	return &pb.SignupResponse{
		Message: resp.Message,
		OtpHash: resp.OTPHash,
	}, nil
}

// VerifyOTP verifies an OTP and marks user as verified
func (s *AuthServiceImpl) VerifyOTP(ctx context.Context, req *pb.VerifyOTPRequest) (*pb.VerifyOTPResponse, error) {
	// Validate request
	if err := s.validateVerifyOTPRequest(req); err != nil {
		logger.FromContext(ctx).Warn("verify otp validation error", zap.Error(err))
		return nil, err
	}

	// Call service
	serviceReq := service.VerifyOTPRequest{
		OTPHash: req.OtpHash,
		Code:    req.Code,
	}

	resp, err := s.authService.VerifyOTP(ctx, serviceReq)
	if err != nil {
		logger.FromContext(ctx).Error("verify otp error", zap.Error(err))
		return nil, err
	}

	return &pb.VerifyOTPResponse{
		Message:      resp.Message,
		Username:     resp.Username,
		SessionToken: resp.SessionToken,
	}, nil
}

// Login authenticates a user
func (s *AuthServiceImpl) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	// Validate request
	if err := s.validateLoginRequest(req); err != nil {
		logger.FromContext(ctx).Warn("login validation error", zap.Error(err))
		return nil, err
	}

	// Call service
	serviceReq := service.LoginRequest{
		Email:    req.Email,
		Password: req.Password,
	}

	resp, err := s.authService.Login(ctx, serviceReq)
	if err != nil {
		logger.FromContext(ctx).Error("login error", zap.Error(err))
		return nil, err
	}

	return &pb.LoginResponse{
		SessionToken: resp.SessionToken,
		ExpiresAt:    timestamppb.New(resp.ExpiresAt),
	}, nil
}

// ValidateSession validates a session token
func (s *AuthServiceImpl) ValidateSession(ctx context.Context, req *pb.ValidateSessionRequest) (*pb.ValidateSessionResponse, error) {
	// Extract token from metadata
	token := extractToken(ctx)
	if token == "" {
		return nil, status.Error(codes.Unauthenticated, "missing authorization token")
	}

	// Call service
	serviceReq := service.ValidateSessionRequest{
		Token: token,
	}

	resp, err := s.authService.ValidateSession(ctx, serviceReq)
	if err != nil {
		logger.FromContext(ctx).Error("validate session error", zap.Error(err))
		return nil, err
	}

	return &pb.ValidateSessionResponse{
		UserId: resp.UserID,
		Valid:  resp.Valid,
	}, nil
}

// RefreshSession extends a valid session
func (s *AuthServiceImpl) RefreshSession(ctx context.Context, req *pb.RefreshSessionRequest) (*pb.RefreshSessionResponse, error) {
	// Extract token from metadata
	token := extractToken(ctx)
	if token == "" {
		return nil, status.Error(codes.Unauthenticated, "missing authorization token")
	}

	// Call service
	serviceReq := service.RefreshSessionRequest{
		Token: token,
	}

	resp, err := s.authService.RefreshSession(ctx, serviceReq)
	if err != nil {
		logger.FromContext(ctx).Error("refresh session error", zap.Error(err))
		return nil, err
	}

	return &pb.RefreshSessionResponse{
		NewSessionToken: resp.NewSessionToken,
	}, nil
}

// Logout logs out a session
func (s *AuthServiceImpl) Logout(ctx context.Context, req *pb.LogoutRequest) (*pb.LogoutResponse, error) {
	// Extract token from metadata
	token := extractToken(ctx)
	if token == "" {
		return nil, status.Error(codes.Unauthenticated, "missing authorization token")
	}

	// Call service
	serviceReq := service.LogoutRequest{
		Token: token,
	}

	resp, err := s.authService.Logout(ctx, serviceReq)
	if err != nil {
		logger.FromContext(ctx).Error("logout error", zap.Error(err))
		return nil, err
	}

	return &pb.LogoutResponse{
		Message: resp.Message,
	}, nil
}

// ForgotPassword initiates password reset by sending OTP to email
func (s *AuthServiceImpl) ForgotPassword(ctx context.Context, req *pb.ForgotPasswordRequest) (*pb.ForgotPasswordResponse, error) {
	// Validate request
	if err := s.validateForgotPasswordRequest(req); err != nil {
		logger.FromContext(ctx).Warn("forgot password validation error", zap.Error(err))
		return nil, err
	}

	// Call service
	serviceReq := service.ForgotPasswordRequest{
		Email: req.Email,
	}

	resp, err := s.authService.ForgotPassword(ctx, serviceReq)
	if err != nil {
		logger.FromContext(ctx).Error("forgot password error", zap.Error(err))
		return nil, err
	}

	return &pb.ForgotPasswordResponse{
		Message: resp.Message,
		OtpHash: resp.OTPHash,
	}, nil
}

// ResetPassword verifies OTP and resets user's password
func (s *AuthServiceImpl) ResetPassword(ctx context.Context, req *pb.ResetPasswordRequest) (*pb.ResetPasswordResponse, error) {
	// Validate request
	if err := s.validateResetPasswordRequest(req); err != nil {
		logger.FromContext(ctx).Warn("reset password validation error", zap.Error(err))
		return nil, err
	}

	serviceReq := service.ResetPasswordRequest{
		OTPHash:  req.OtpHash,
		Code:     req.Code,
		Password: req.Password,
	}

	resp, err := s.authService.ResetPassword(ctx, serviceReq)
	if err != nil {
		logger.FromContext(ctx).Error("reset password error", zap.Error(err))
		return nil, err
	}

	return &pb.ResetPasswordResponse{
		Message: resp.Message,
	}, nil
}

// Private helper and validation methods

func (s *AuthServiceImpl) validateSignupRequest(req *pb.SignupRequest) error {
	if req.Email == "" {
		return &gotoolkit.ValidationError{Message: "email is required", Field: "email"}
	}
	if req.Password == "" {
		return &gotoolkit.ValidationError{Message: "password is required", Field: "password"}
	}
	if err := s.validator.ValidateEmail(req.Email); err != nil {
		return &gotoolkit.ValidationError{Message: err.Error(), Field: "email"}
	}
	if err := s.validator.ValidatePassword(req.Password); err != nil {
		return &gotoolkit.ValidationError{Message: err.Error(), Field: "password"}
	}
	return nil
}

func (s *AuthServiceImpl) validateVerifyOTPRequest(req *pb.VerifyOTPRequest) error {
	if req.OtpHash == "" {
		return &gotoolkit.ValidationError{Message: "otp_hash is required", Field: "otp_hash"}
	}
	if req.Code == "" {
		return &gotoolkit.ValidationError{Message: "code is required", Field: "code"}
	}
	return nil
}

func (s *AuthServiceImpl) validateLoginRequest(req *pb.LoginRequest) error {
	if req.Email == "" {
		return &gotoolkit.ValidationError{Message: "email is required", Field: "email"}
	}
	if req.Password == "" {
		return &gotoolkit.ValidationError{Message: "password is required", Field: "password"}
	}
	if err := s.validator.ValidateEmail(req.Email); err != nil {
		return &gotoolkit.ValidationError{Message: err.Error(), Field: "email"}
	}
	return nil
}

func (s *AuthServiceImpl) validateForgotPasswordRequest(req *pb.ForgotPasswordRequest) error {
	if req.Email == "" {
		return &gotoolkit.ValidationError{Message: "email is required", Field: "email"}
	}
	if err := s.validator.ValidateEmail(req.Email); err != nil {
		return &gotoolkit.ValidationError{Message: err.Error(), Field: "email"}
	}
	return nil
}

func (s *AuthServiceImpl) validateResetPasswordRequest(req *pb.ResetPasswordRequest) error {
	if req.OtpHash == "" {
		return &gotoolkit.ValidationError{Message: "otp_hash is required", Field: "otp_hash"}
	}
	if req.Code == "" {
		return &gotoolkit.ValidationError{Message: "code is required", Field: "code"}
	}
	if req.Password == "" {
		return &gotoolkit.ValidationError{Message: "password is required", Field: "password"}
	}
	if err := s.validator.ValidateOTPCode(req.Code, 6); err != nil {
		return &gotoolkit.ValidationError{Message: err.Error(), Field: "code"}
	}
	if err := s.validator.ValidatePassword(req.Password); err != nil {
		return &gotoolkit.ValidationError{Message: err.Error(), Field: "password"}
	}
	return nil
}

func extractToken(ctx context.Context) string {
	// Extract from context metadata
	// This will be populated by the interceptor
	token, ok := ctx.Value("authorization").(string)
	if !ok {
		return ""
	}
	return token
}
