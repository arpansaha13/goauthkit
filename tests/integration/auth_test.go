package tests

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"

	"github.com/arpansaha13/goauthkit/pkg"
)

func (s *AuthIntegrationTestSuite) TestSignup() {
	testCases := []TableDrivenTestCase{
		{
			Name: "Successful Signup",
			Test: func(f *TestFixture) error {
				payload := pkg.SignupRequest{
					Email:           "signup@example.com",
					Password:        "Password123!",
					ConfirmPassword: "Password123!",
					GlobalName:      "Signup User",
				}
				resp, err := f.HTTPClient.POST("/api/auth/signup", payload)
				if err != nil {
					return err
				}
				s.Require().Equal(http.StatusCreated, resp.StatusCode)
				return nil
			},
		},
		{
			Name: "Invalid Email",
			Test: func(f *TestFixture) error {
				payload := pkg.SignupRequest{
					Email:           "invalid-email",
					Password:        "Password123!",
					ConfirmPassword: "Password123!",
					GlobalName:      "Invalid User",
				}
				resp, err := f.HTTPClient.POST("/api/auth/signup", payload)
				if err != nil {
					return err
				}
				s.Require().Equal(http.StatusBadRequest, resp.StatusCode)
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

func (s *AuthIntegrationTestSuite) TestLogin() {
	testCases := []TableDrivenTestCase{
		{
			Name: "Successful Login",
			Setup: func(f *TestFixture) error {
				_, err := f.TestDB.CreateTestUser("login@example.com", "Password123!", true)
				return err
			},
			Test: func(f *TestFixture) error {
				payload := pkg.LoginRequest{
					Email:    "login@example.com",
					Password: "Password123!",
				}
				resp, err := f.HTTPClient.POST("/api/auth/login", payload)
				if err != nil {
					return err
				}
				s.Require().Equal(http.StatusOK, resp.StatusCode)

				cookies := resp.Cookies()
				var found bool
				for _, c := range cookies {
					if c.Name == "test_session" {
						found = true
						break
					}
				}
				if !found {
					fmt.Printf("Set-Cookie header: %s\n", resp.Header.Get("Set-Cookie"))
				}
				s.Require().True(found, "Auth cookie not found")
				return nil
			},
		},
		{
			Name: "Invalid Credentials",
			Setup: func(f *TestFixture) error {
				_, err := f.TestDB.CreateTestUser("wrong@example.com", "Password123!", true)
				return err
			},
			Test: func(f *TestFixture) error {
				payload := pkg.LoginRequest{
					Email:    "wrong@example.com",
					Password: "WrongPassword123!",
				}
				resp, err := f.HTTPClient.POST("/api/auth/login", payload)
				if err != nil {
					return err
				}
				s.Require().Equal(http.StatusUnauthorized, resp.StatusCode)
				return nil
			},
		},
		{
			Name: "Unverified User",
			Setup: func(f *TestFixture) error {
				_, err := f.TestDB.CreateTestUser("unverified@example.com", "Password123!", false)
				return err
			},
			Test: func(f *TestFixture) error {
				payload := pkg.LoginRequest{
					Email:    "unverified@example.com",
					Password: "Password123!",
				}
				resp, err := f.HTTPClient.POST("/api/auth/login", payload)
				if err != nil {
					return err
				}
				s.Require().Equal(http.StatusUnauthorized, resp.StatusCode)
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

func (s *AuthIntegrationTestSuite) TestVerifyOTP() {
	testCases := []TableDrivenTestCase{
		{
			Name: "Successful Verification",
			Test: func(f *TestFixture) error {
				user, _ := f.TestDB.CreateTestUser("verify@example.com", "Password123!", false)
				code := "123456"
				otpHash, _ := f.TestDB.CreateTestOTP(user.ID, code)

				payload := pkg.VerifyOTPRequest{
					OTPHash: otpHash,
					Code:    code,
					UserId:  user.ID,
				}
				resp, err := f.HTTPClient.POST("/api/auth/verify", payload)
				if err != nil {
					return err
				}
				s.Require().Equal(http.StatusOK, resp.StatusCode)
				return nil
			},
		},
		{
			Name: "Invalid Code",
			Test: func(f *TestFixture) error {
				user, _ := f.TestDB.CreateTestUser("invalid-code@example.com", "Password123!", false)
				otpHash, _ := f.TestDB.CreateTestOTP(user.ID, "123456")

				payload := pkg.VerifyOTPRequest{
					OTPHash: otpHash,
					Code:    "654321",
					UserId:  user.ID,
				}
				resp, err := f.HTTPClient.POST("/api/auth/verify", payload)
				if err != nil {
					return err
				}
				s.Require().Equal(http.StatusUnauthorized, resp.StatusCode)
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

func (s *AuthIntegrationTestSuite) TestLogout() {
	testCases := []TableDrivenTestCase{
		{
			Name: "Successful Logout",
			Test: func(f *TestFixture) error {
				user, _ := f.TestDB.CreateTestUser("logout@example.com", "Password123!", true)
				token, _ := f.TestDB.CreateTestSession(user.ID)
				cookie := &http.Cookie{
					Name:  "test_session",
					Value: token,
				}

				resp, err := f.HTTPClient.POSTWithCookie("/api/auth/logout", nil, cookie)
				if err != nil {
					return err
				}
				s.Require().Equal(http.StatusOK, resp.StatusCode)

				// Check if session is deleted
				hasher := sha256.New()
				hasher.Write([]byte(token + "test-secret-key-at-least-32-characters-long-ok"))
				tokenHash := hex.EncodeToString(hasher.Sum(nil))

				var count int64
				s.DB.Table("sessions").Where("token_hash = ? AND deleted_at IS NULL", tokenHash).Count(&count)
				s.Require().Equal(int64(0), count)

				// Check if cookie is cleared
				cookies := resp.Cookies()
				var cleared bool
				for _, c := range cookies {
					if c.Name == "test_session" && (c.Value == "" || c.MaxAge < 0) {
						cleared = true
						break
					}
				}
				s.Require().True(cleared, "Auth cookie not cleared")
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
