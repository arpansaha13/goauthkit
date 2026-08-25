package tests

import (
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/arpansaha13/goauthkit"
	"github.com/arpansaha13/goauthkit/internal/domain"
	"github.com/arpansaha13/goauthkit/pb"
)

func (s *AuthIntegrationTestSuite) TestValidateSession() {
	testCases := []TableDrivenTestCase{
		{
			Name: "Valid Session",
			Test: func(f *TestFixture) error {
				user, err := f.TestDB.CreateTestUser("session@example.com", "Password123!", true)
				s.Require().NoError(err)

				token, err := f.TestDB.CreateTestSession(user.ID)
				s.Require().NoError(err)

				md := metadata.Pairs("authorization", fmt.Sprintf("Bearer %s", token))
				ctxWithToken := metadata.NewOutgoingContext(s.Ctx, md)

				resp, err := f.AuthClient.ValidateSession(ctxWithToken, &pb.ValidateSessionRequest{})
				s.Require().NoError(err)
				s.Require().True(resp.Valid)
				s.Require().Equal(user.ID, resp.UserId)
				return nil
			},
		},
		{
			Name: "Invalid Token / Missing Metadata",
			Test: func(f *TestFixture) error {
				_, err := f.AuthClient.ValidateSession(s.Ctx, &pb.ValidateSessionRequest{})
				s.Require().Error(err)
				st, ok := status.FromError(err)
				s.Require().True(ok)
				s.Require().Equal(codes.Unauthenticated, st.Code())
				return nil
			},
		},
	}

	for _, tc := range testCases {
		s.Run(tc.Name, func() {
			s.cleanupTables()
			if tc.Setup != nil {
				s.Require().NoError(tc.Setup(s.Fixture))
			}
			s.Require().NoError(tc.Test(s.Fixture))
			if tc.Verify != nil {
				s.Require().NoError(tc.Verify(s.Fixture))
			}
		})
	}
}

func (s *AuthIntegrationTestSuite) TestRefreshSession() {
	testCases := []TableDrivenTestCase{
		{
			Name: "Valid Session Refresh",
			Test: func(f *TestFixture) error {
				user, err := f.TestDB.CreateTestUser("refresh@example.com", "Password123!", true)
				s.Require().NoError(err)

				token, err := f.TestDB.CreateTestSession(user.ID)
				s.Require().NoError(err)

				md := metadata.Pairs("authorization", fmt.Sprintf("Bearer %s", token))
				ctxWithToken := metadata.NewOutgoingContext(s.Ctx, md)

				resp, err := f.AuthClient.RefreshSession(ctxWithToken, &pb.RefreshSessionRequest{})
				s.Require().NoError(err)
				s.Require().NotEmpty(resp.NewSessionToken)
				s.Require().NotEqual(token, resp.NewSessionToken)

				// Old token should be invalid (or cache invalidated, DB updated)
				// Let's verify ValidateSession on old token returns false
				validateOldResp, err := f.AuthClient.ValidateSession(ctxWithToken, &pb.ValidateSessionRequest{})
				s.Require().NoError(err)
				s.Require().False(validateOldResp.Valid)

				// New token should be valid
				newMd := metadata.Pairs("authorization", fmt.Sprintf("Bearer %s", resp.NewSessionToken))
				newCtxWithToken := metadata.NewOutgoingContext(s.Ctx, newMd)
				validateNewResp, err := f.AuthClient.ValidateSession(newCtxWithToken, &pb.ValidateSessionRequest{})
				s.Require().NoError(err)
				s.Require().True(validateNewResp.Valid)
				s.Require().Equal(user.ID, validateNewResp.UserId)

				return nil
			},
		},
		{
			Name: "Invalid Token Refresh",
			Test: func(f *TestFixture) error {
				_, err := f.AuthClient.RefreshSession(s.Ctx, &pb.RefreshSessionRequest{})
				s.Require().Error(err)
				st, ok := status.FromError(err)
				s.Require().True(ok)
				s.Require().Equal(codes.Unauthenticated, st.Code())
				return nil
			},
		},
	}

	for _, tc := range testCases {
		s.Run(tc.Name, func() {
			s.cleanupTables()
			if tc.Setup != nil {
				s.Require().NoError(tc.Setup(s.Fixture))
			}
			s.Require().NoError(tc.Test(s.Fixture))
			if tc.Verify != nil {
				s.Require().NoError(tc.Verify(s.Fixture))
			}
		})
	}
}

func (s *AuthIntegrationTestSuite) TestForgotPassword() {
	testCases := []TableDrivenTestCase{
		{
			Name: "Existing User",
			Test: func(f *TestFixture) error {
				user, err := f.TestDB.CreateTestUser("forgot@example.com", "Password123!", true)
				s.Require().NoError(err)

				resp, err := f.AuthClient.ForgotPassword(s.Ctx, &pb.ForgotPasswordRequest{
					Email: user.Email,
				})
				s.Require().NoError(err)
				s.Require().NotEmpty(resp.OtpHash)

				// Verify in DB that OTP record exists for this user and purpose
				var otp domain.OTP
				err = s.DB.QueryRow(s.Ctx, `
					SELECT id, user_id, otp_hash, hashed_code, purpose, expires_at, deleted_at, created_at
					FROM otps WHERE user_id = $1 AND purpose = $2 AND deleted_at IS NULL`,
					user.ID, domain.OTPPurposeResetPassword,
				).Scan(&otp.ID, &otp.UserID, &otp.OTPHash, &otp.HashedCode, &otp.Purpose, &otp.ExpiresAt, &otp.DeletedAt, &otp.CreatedAt)
				s.Require().NoError(err)
				s.Require().Equal(resp.OtpHash, otp.OTPHash)

				return nil
			},
		},
		{
			Name: "Non-existent User",
			Test: func(f *TestFixture) error {
				resp, err := f.AuthClient.ForgotPassword(s.Ctx, &pb.ForgotPasswordRequest{
					Email: "nonexistent@example.com",
				})
				s.Require().NoError(err)
				s.Require().Empty(resp.OtpHash)
				return nil
			},
		},
	}

	for _, tc := range testCases {
		s.Run(tc.Name, func() {
			s.cleanupTables()
			if tc.Setup != nil {
				s.Require().NoError(tc.Setup(s.Fixture))
			}
			s.Require().NoError(tc.Test(s.Fixture))
			if tc.Verify != nil {
				s.Require().NoError(tc.Verify(s.Fixture))
			}
		})
	}
}

func (s *AuthIntegrationTestSuite) TestResetPassword() {
	testCases := []TableDrivenTestCase{
		{
			Name: "Successful Reset",
			Test: func(f *TestFixture) error {
				user, err := f.TestDB.CreateTestUser("reset@example.com", "OldPassword123!", true)
				s.Require().NoError(err)

				code := "654321"
				otpHash, err := goauthkit.GenerateToken(32)
				s.Require().NoError(err)

				hashedCode, err := f.TestDB.Hasher.Hash(code)
				s.Require().NoError(err)

				err = f.TestDB.InsertOTP(&domain.OTP{
					UserID:     user.ID,
					OTPHash:    otpHash,
					HashedCode: hashedCode,
					Purpose:    domain.OTPPurposeResetPassword,
					ExpiresAt:  time.Now().Add(10 * time.Minute),
				})
				s.Require().NoError(err)

				resp, err := f.AuthClient.ResetPassword(s.Ctx, &pb.ResetPasswordRequest{
					OtpHash:  otpHash,
					Code:     code,
					Password: "NewPassword123!",
				})
				s.Require().NoError(err)
				s.Require().NotEmpty(resp.Message)

				// Verify credentials password update in DB
				var cred domain.Credentials
				err = s.DB.QueryRow(s.Ctx, `SELECT user_id, password_hash FROM credentials WHERE user_id = $1`, user.ID).
					Scan(&cred.UserID, &cred.PasswordHash)
				s.Require().NoError(err)
				s.Require().True(f.TestDB.Hasher.Verify(cred.PasswordHash, "NewPassword123!"))

				return nil
			},
		},
		{
			Name: "Invalid Code",
			Test: func(f *TestFixture) error {
				user, err := f.TestDB.CreateTestUser("invalidcode@example.com", "OldPassword123!", true)
				s.Require().NoError(err)

				code := "654321"
				otpHash, err := goauthkit.GenerateToken(32)
				s.Require().NoError(err)

				hashedCode, err := f.TestDB.Hasher.Hash(code)
				s.Require().NoError(err)

				err = f.TestDB.InsertOTP(&domain.OTP{
					UserID:     user.ID,
					OTPHash:    otpHash,
					HashedCode: hashedCode,
					Purpose:    domain.OTPPurposeResetPassword,
					ExpiresAt:  time.Now().Add(10 * time.Minute),
				})
				s.Require().NoError(err)

				_, err = f.AuthClient.ResetPassword(s.Ctx, &pb.ResetPasswordRequest{
					OtpHash:  otpHash,
					Code:     "wrongcode",
					Password: "NewPassword123!",
				})
				s.Require().Error(err)
				st, ok := status.FromError(err)
				s.Require().True(ok)
				s.Require().Equal(codes.InvalidArgument, st.Code()) // gRPC validation checks length of code (should be 6 digits)
				return nil
			},
		},
		{
			Name: "Wrong OTP Code (Valid length)",
			Test: func(f *TestFixture) error {
				user, err := f.TestDB.CreateTestUser("wrongotp@example.com", "OldPassword123!", true)
				s.Require().NoError(err)

				code := "654321"
				otpHash, err := goauthkit.GenerateToken(32)
				s.Require().NoError(err)

				hashedCode, err := f.TestDB.Hasher.Hash(code)
				s.Require().NoError(err)

				err = f.TestDB.InsertOTP(&domain.OTP{
					UserID:     user.ID,
					OTPHash:    otpHash,
					HashedCode: hashedCode,
					Purpose:    domain.OTPPurposeResetPassword,
					ExpiresAt:  time.Now().Add(10 * time.Minute),
				})
				s.Require().NoError(err)

				_, err = f.AuthClient.ResetPassword(s.Ctx, &pb.ResetPasswordRequest{
					OtpHash:  otpHash,
					Code:     "111111",
					Password: "NewPassword123!",
				})
				s.Require().Error(err)
				st, ok := status.FromError(err)
				s.Require().True(ok)
				s.Require().Equal(codes.Unauthenticated, st.Code())
				return nil
			},
		},
		{
			Name: "Expired OTP",
			Test: func(f *TestFixture) error {
				user, err := f.TestDB.CreateTestUser("expiredreset@example.com", "OldPassword123!", true)
				s.Require().NoError(err)

				code := "654321"
				otpHash, err := goauthkit.GenerateToken(32)
				s.Require().NoError(err)

				hashedCode, err := f.TestDB.Hasher.Hash(code)
				s.Require().NoError(err)

				err = f.TestDB.InsertOTP(&domain.OTP{
					UserID:     user.ID,
					OTPHash:    otpHash,
					HashedCode: hashedCode,
					Purpose:    domain.OTPPurposeResetPassword,
					ExpiresAt:  time.Now().Add(-10 * time.Minute),
				})
				s.Require().NoError(err)

				_, err = f.AuthClient.ResetPassword(s.Ctx, &pb.ResetPasswordRequest{
					OtpHash:  otpHash,
					Code:     code,
					Password: "NewPassword123!",
				})
				s.Require().Error(err)
				st, ok := status.FromError(err)
				s.Require().True(ok)
				s.Require().Equal(codes.Unauthenticated, st.Code())
				return nil
			},
		},
	}

	for _, tc := range testCases {
		s.Run(tc.Name, func() {
			s.cleanupTables()
			if tc.Setup != nil {
				s.Require().NoError(tc.Setup(s.Fixture))
			}
			s.Require().NoError(tc.Test(s.Fixture))
			if tc.Verify != nil {
				s.Require().NoError(tc.Verify(s.Fixture))
			}
		})
	}
}

func (s *AuthIntegrationTestSuite) TestGetUser() {
	testCases := []TableDrivenTestCase{
		{
			Name: "Valid User ID",
			Test: func(f *TestFixture) error {
				user, err := f.TestDB.CreateTestUser("getuser@example.com", "Password123!", true)
				s.Require().NoError(err)

				token, err := f.TestDB.CreateTestSession(user.ID)
				s.Require().NoError(err)

				md := metadata.Pairs("authorization", fmt.Sprintf("Bearer %s", token))
				ctxWithToken := metadata.NewOutgoingContext(s.Ctx, md)

				resp, err := f.AuthClient.GetUser(ctxWithToken, &pb.GetUserRequest{UserId: user.ID})
				s.Require().NoError(err)
				s.Require().NotNil(resp.User)
				s.Require().Equal(user.ID, resp.User.UserId)
				s.Require().Equal("getuser@example.com", resp.User.Email)
				return nil
			},
		},
		{
			Name: "User Not Found",
			Test: func(f *TestFixture) error {
				user, err := f.TestDB.CreateTestUser("authuser@example.com", "Password123!", true)
				s.Require().NoError(err)

				token, err := f.TestDB.CreateTestSession(user.ID)
				s.Require().NoError(err)

				md := metadata.Pairs("authorization", fmt.Sprintf("Bearer %s", token))
				ctxWithToken := metadata.NewOutgoingContext(s.Ctx, md)

				_, err = f.AuthClient.GetUser(ctxWithToken, &pb.GetUserRequest{UserId: 99999})
				s.Require().Error(err)
				st, ok := status.FromError(err)
				s.Require().True(ok)
				s.Require().Equal(codes.NotFound, st.Code())
				return nil
			},
		},
		{
			Name: "Invalid User ID Validation Error",
			Test: func(f *TestFixture) error {
				user, err := f.TestDB.CreateTestUser("authuser@example.com", "Password123!", true)
				s.Require().NoError(err)

				token, err := f.TestDB.CreateTestSession(user.ID)
				s.Require().NoError(err)

				md := metadata.Pairs("authorization", fmt.Sprintf("Bearer %s", token))
				ctxWithToken := metadata.NewOutgoingContext(s.Ctx, md)

				_, err = f.AuthClient.GetUser(ctxWithToken, &pb.GetUserRequest{UserId: 0})
				s.Require().Error(err)
				st, ok := status.FromError(err)
				s.Require().True(ok)
				s.Require().Equal(codes.InvalidArgument, st.Code())
				return nil
			},
		},
	}

	for _, tc := range testCases {
		s.Run(tc.Name, func() {
			s.cleanupTables()
			if tc.Setup != nil {
				s.Require().NoError(tc.Setup(s.Fixture))
			}
			s.Require().NoError(tc.Test(s.Fixture))
			if tc.Verify != nil {
				s.Require().NoError(tc.Verify(s.Fixture))
			}
		})
	}
}

func (s *AuthIntegrationTestSuite) TestGetUserByEmail() {
	testCases := []TableDrivenTestCase{
		{
			Name: "Valid Email",
			Test: func(f *TestFixture) error {
				user, err := f.TestDB.CreateTestUser("lookup@example.com", "Password123!", true)
				s.Require().NoError(err)

				token, err := f.TestDB.CreateTestSession(user.ID)
				s.Require().NoError(err)

				md := metadata.Pairs("authorization", fmt.Sprintf("Bearer %s", token))
				ctxWithToken := metadata.NewOutgoingContext(s.Ctx, md)

				resp, err := f.AuthClient.GetUserByEmail(ctxWithToken, &pb.GetUserByEmailRequest{Email: user.Email})
				s.Require().NoError(err)
				s.Require().NotNil(resp.User)
				s.Require().Equal(user.ID, resp.User.UserId)
				s.Require().Equal("lookup@example.com", resp.User.Email)
				return nil
			},
		},
		{
			Name: "User Not Found",
			Test: func(f *TestFixture) error {
				user, err := f.TestDB.CreateTestUser("authuser@example.com", "Password123!", true)
				s.Require().NoError(err)

				token, err := f.TestDB.CreateTestSession(user.ID)
				s.Require().NoError(err)

				md := metadata.Pairs("authorization", fmt.Sprintf("Bearer %s", token))
				ctxWithToken := metadata.NewOutgoingContext(s.Ctx, md)

				_, err = f.AuthClient.GetUserByEmail(ctxWithToken, &pb.GetUserByEmailRequest{Email: "nonexistent@example.com"})
				s.Require().Error(err)
				st, ok := status.FromError(err)
				s.Require().True(ok)
				s.Require().Equal(codes.NotFound, st.Code())
				return nil
			},
		},
		{
			Name: "Invalid Email Validation Error",
			Test: func(f *TestFixture) error {
				user, err := f.TestDB.CreateTestUser("authuser@example.com", "Password123!", true)
				s.Require().NoError(err)

				token, err := f.TestDB.CreateTestSession(user.ID)
				s.Require().NoError(err)

				md := metadata.Pairs("authorization", fmt.Sprintf("Bearer %s", token))
				ctxWithToken := metadata.NewOutgoingContext(s.Ctx, md)

				_, err = f.AuthClient.GetUserByEmail(ctxWithToken, &pb.GetUserByEmailRequest{Email: ""})
				s.Require().Error(err)
				st, ok := status.FromError(err)
				s.Require().True(ok)
				s.Require().Equal(codes.InvalidArgument, st.Code())
				return nil
			},
		},
	}

	for _, tc := range testCases {
		s.Run(tc.Name, func() {
			s.cleanupTables()
			if tc.Setup != nil {
				s.Require().NoError(tc.Setup(s.Fixture))
			}
			s.Require().NoError(tc.Test(s.Fixture))
			if tc.Verify != nil {
				s.Require().NoError(tc.Verify(s.Fixture))
			}
		})
	}
}

func (s *AuthIntegrationTestSuite) TestDeleteUser() {
	testCases := []TableDrivenTestCase{
		{
			Name: "Valid User Deletion",
			Test: func(f *TestFixture) error {
				user, err := f.TestDB.CreateTestUser("delete@example.com", "Password123!", true)
				s.Require().NoError(err)

				token, err := f.TestDB.CreateTestSession(user.ID)
				s.Require().NoError(err)

				md := metadata.Pairs("authorization", fmt.Sprintf("Bearer %s", token))
				ctxWithToken := metadata.NewOutgoingContext(s.Ctx, md)

				resp, err := f.AuthClient.DeleteUser(ctxWithToken, &pb.DeleteUserRequest{UserId: user.ID})
				s.Require().NoError(err)
				s.Require().NotEmpty(resp.Message)

				// Verify database record deletion
				var dbUser domain.User
				err = s.DB.QueryRow(s.Ctx, `SELECT id FROM users WHERE id = $1`, user.ID).Scan(&dbUser.ID)
				s.Require().Error(err) // Should be record not found

				return nil
			},
		},
		{
			Name: "User Not Found",
			Test: func(f *TestFixture) error {
				user, err := f.TestDB.CreateTestUser("authuser@example.com", "Password123!", true)
				s.Require().NoError(err)

				token, err := f.TestDB.CreateTestSession(user.ID)
				s.Require().NoError(err)

				md := metadata.Pairs("authorization", fmt.Sprintf("Bearer %s", token))
				ctxWithToken := metadata.NewOutgoingContext(s.Ctx, md)

				_, err = f.AuthClient.DeleteUser(ctxWithToken, &pb.DeleteUserRequest{UserId: 99999})
				s.Require().Error(err)
				st, ok := status.FromError(err)
				s.Require().True(ok)
				s.Require().Equal(codes.NotFound, st.Code())
				return nil
			},
		},
		{
			Name: "Invalid User ID Validation Error",
			Test: func(f *TestFixture) error {
				user, err := f.TestDB.CreateTestUser("authuser@example.com", "Password123!", true)
				s.Require().NoError(err)

				token, err := f.TestDB.CreateTestSession(user.ID)
				s.Require().NoError(err)

				md := metadata.Pairs("authorization", fmt.Sprintf("Bearer %s", token))
				ctxWithToken := metadata.NewOutgoingContext(s.Ctx, md)

				_, err = f.AuthClient.DeleteUser(ctxWithToken, &pb.DeleteUserRequest{UserId: 0})
				s.Require().Error(err)
				st, ok := status.FromError(err)
				s.Require().True(ok)
				s.Require().Equal(codes.InvalidArgument, st.Code())
				return nil
			},
		},
	}

	for _, tc := range testCases {
		s.Run(tc.Name, func() {
			s.cleanupTables()
			if tc.Setup != nil {
				s.Require().NoError(tc.Setup(s.Fixture))
			}
			s.Require().NoError(tc.Test(s.Fixture))
			if tc.Verify != nil {
				s.Require().NoError(tc.Verify(s.Fixture))
			}
		})
	}
}

func (s *AuthIntegrationTestSuite) TestLiveZ() {
	testCases := []TableDrivenTestCase{
		{
			Name: "Liveness Probe Success",
			Test: func(f *TestFixture) error {
				resp, err := f.AuthClient.LiveZ(s.Ctx, &pb.LiveZRequest{})
				s.Require().NoError(err)
				s.Require().NotNil(resp)
				return nil
			},
		},
	}

	for _, tc := range testCases {
		s.Run(tc.Name, func() {
			s.cleanupTables()
			if tc.Setup != nil {
				s.Require().NoError(tc.Setup(s.Fixture))
			}
			s.Require().NoError(tc.Test(s.Fixture))
			if tc.Verify != nil {
				s.Require().NoError(tc.Verify(s.Fixture))
			}
		})
	}
}
