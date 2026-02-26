package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/arpansaha13/goauthkit/internal/domain"
	pkgrepo "github.com/arpansaha13/goauthkit/pkg/repository"
	pkgservice "github.com/arpansaha13/goauthkit/pkg/service"
	pkgutils "github.com/arpansaha13/goauthkit/pkg/utils"
	pkgworker "github.com/arpansaha13/goauthkit/pkg/worker"
)

// HTTPPlaygroundTestSuite tests the HTTP playground server using pkg exports
type HTTPPlaygroundTestSuite struct {
	suite.Suite
	Container   testcontainers.Container
	DB          *gorm.DB
	Ctx         context.Context
	HTTPClient  *http.Client
	HTTPServer  *http.Server
	ServerAddr  string
	AuthService pkgservice.IAuthService
	EmailPool   *pkgworker.EmailWorkerPool
}

// SetupSuite initializes test environment
func (s *HTTPPlaygroundTestSuite) SetupSuite() {
	ctx := context.Background()
	s.Ctx = ctx

	// Start PostgreSQL container
	req := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "testuser",
			"POSTGRES_PASSWORD": "testpass",
			"POSTGRES_DB":       "test_playground_http",
		},
		WaitingFor: wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).
			WithStartupTimeout(60 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	s.Require().NoError(err, "Failed to start PostgreSQL container")
	s.Container = container

	// Get container host and port
	host, err := container.Host(ctx)
	s.Require().NoError(err, "Failed to get container host")

	port, err := container.MappedPort(ctx, "5432")
	s.Require().NoError(err, "Failed to get container port")

	// Connect to database
	dsn := fmt.Sprintf(
		"host=%s port=%s user=testuser password=testpass dbname=test_playground_http sslmode=disable",
		host, port.Port(),
	)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	s.Require().NoError(err, "Failed to connect to database")
	s.DB = db

	// Run migrations
	err = domain.AutoMigrate(db)
	s.Require().NoError(err, "Failed to run migrations")

	// Setup HTTP server using pkg exports
	err = s.setupHTTPServer(ctx, db)
	s.Require().NoError(err, "Failed to setup HTTP server")

	s.HTTPClient = &http.Client{}
}

// TearDownSuite cleans up
func (s *HTTPPlaygroundTestSuite) TearDownSuite() {
	if s.HTTPServer != nil {
		s.HTTPServer.Shutdown(s.Ctx)
	}
	if s.Container != nil {
		s.Container.Terminate(s.Ctx)
	}
	if s.EmailPool != nil {
		s.EmailPool.Stop()
	}
}

// SetupTest prepares each test
func (s *HTTPPlaygroundTestSuite) SetupTest() {
	s.cleanupTables()
}

// cleanupTables truncates all tables
func (s *HTTPPlaygroundTestSuite) cleanupTables() {
	tables := []string{"sessions", "otps", "credentials", "users"}
	for _, table := range tables {
		err := s.DB.Exec(fmt.Sprintf("TRUNCATE TABLE %s CASCADE", table)).Error
		s.Require().NoError(err, "Failed to truncate table %s", table)
	}
}

// setupHTTPServer sets up the HTTP server using pkg exports (playground pattern)
func (s *HTTPPlaygroundTestSuite) setupHTTPServer(ctx context.Context, db *gorm.DB) error {
	// Create listener for random port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}

	s.ServerAddr = fmt.Sprintf("http://%s", listener.Addr().String())

	// Initialize services using pkg exports (this is how the playground uses the library)
	userRepo := pkgrepo.NewUserRepository(db)
	otpRepo := pkgrepo.NewOTPRepository(db)
	sessionRepo := pkgrepo.NewSessionRepository(db)
	hasher := pkgutils.NewPasswordHasher()
	emailProvider := pkgworker.NewMockEmailProvider()
	s.EmailPool = pkgworker.NewEmailWorkerPool(2, 50, emailProvider)

	s.AuthService = pkgservice.NewAuthService(
		userRepo,
		otpRepo,
		sessionRepo,
		hasher,
		pkgservice.AuthServiceConfig{
			OTPExpiry:  10 * time.Minute,
			OTPLength:  6,
			SessionTTL: 30 * time.Minute,
			SecretKey:  "test-secret-key-at-least-32-characters-long-ok",
			EmailPool:  s.EmailPool,
		},
	)

	// Setup HTTP routes
	mux := http.NewServeMux()

	// Auth routes
	mux.HandleFunc("POST /api/auth/signup", func(w http.ResponseWriter, r *http.Request) {
		s.signupHandler(w, r)
	})

	mux.HandleFunc("POST /api/auth/verify-otp", func(w http.ResponseWriter, r *http.Request) {
		s.verifyOTPHandler(w, r)
	})

	mux.HandleFunc("POST /api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		s.loginHandler(w, r)
	})

	// User routes
	mux.HandleFunc("GET /api/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		s.getUserHandler(w, r)
	})

	mux.HandleFunc("DELETE /api/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		s.deleteUserHandler(w, r)
	})

	// Health check
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok"}`)
	})

	s.HTTPServer = &http.Server{
		Handler: mux,
	}

	// Start server in goroutine
	go func() {
		if err := s.HTTPServer.Serve(listener); err != nil && err != http.ErrServerClosed {
			fmt.Printf("HTTP server error: %v\n", err)
		}
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	return nil
}

// Handler implementations
func (s *HTTPPlaygroundTestSuite) signupHandler(w http.ResponseWriter, r *http.Request) {
	var req pkgservice.SignupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error":"invalid request"}`)
		return
	}

	resp, err := s.AuthService.Signup(r.Context(), req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error":"%v"}`, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *HTTPPlaygroundTestSuite) verifyOTPHandler(w http.ResponseWriter, r *http.Request) {
	var req pkgservice.VerifyOTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error":"invalid request"}`)
		return
	}

	resp, err := s.AuthService.VerifyOTP(r.Context(), req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error":"%v"}`, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *HTTPPlaygroundTestSuite) loginHandler(w http.ResponseWriter, r *http.Request) {
	var req pkgservice.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error":"invalid request"}`)
		return
	}

	resp, err := s.AuthService.Login(r.Context(), req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error":"%v"}`, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *HTTPPlaygroundTestSuite) getUserHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"message":"get user handler for user %s"}`, userID)
}

func (s *HTTPPlaygroundTestSuite) deleteUserHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"message":"delete user handler for user %s"}`, userID)
}

// TestHTTPPlaygroundSignup tests signup via HTTP
func (s *HTTPPlaygroundTestSuite) TestHTTPPlaygroundSignup() {
	payload := pkgservice.SignupRequest{
		Email:    "http@example.com",
		Password: "securePassword123",
	}

	body, _ := json.Marshal(payload)
	resp, err := s.HTTPClient.Post(
		fmt.Sprintf("%s/api/auth/signup", s.ServerAddr),
		"application/json",
		bytes.NewReader(body),
	)

	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, resp.StatusCode)

	var result pkgservice.SignupResponse
	respBody, _ := io.ReadAll(resp.Body)
	err = json.Unmarshal(respBody, &result)
	s.Require().NoError(err)
	s.Require().NotEmpty(result.OTPHash)
}

// TestHTTPPlaygroundVerifyOTP tests OTP verification via HTTP
func (s *HTTPPlaygroundTestSuite) TestHTTPPlaygroundVerifyOTP() {
	testOTPCode := "123456"

	// First signup
	signupPayload := pkgservice.SignupRequest{
		Email:    "httpverify@example.com",
		Password: "securePassword123",
	}
	body, _ := json.Marshal(signupPayload)
	resp, _ := s.HTTPClient.Post(
		fmt.Sprintf("%s/api/auth/signup", s.ServerAddr),
		"application/json",
		bytes.NewReader(body),
	)

	var signupResult pkgservice.SignupResponse
	respBody, _ := io.ReadAll(resp.Body)
	json.Unmarshal(respBody, &signupResult)

	// Update OTP with test code
	hasher := pkgutils.NewPasswordHasher()
	otpHashCode, _ := hasher.Hash(testOTPCode)
	s.DB.Model(&domain.OTP{}).
		Where("otp_hash = ?", signupResult.OTPHash).
		Update("hashed_code", otpHashCode)

	// Verify OTP
	verifyPayload := pkgservice.VerifyOTPRequest{
		OTPHash: signupResult.OTPHash,
		Code:    testOTPCode,
	}
	body, _ = json.Marshal(verifyPayload)
	resp, err := s.HTTPClient.Post(
		fmt.Sprintf("%s/api/auth/verify-otp", s.ServerAddr),
		"application/json",
		bytes.NewReader(body),
	)

	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, resp.StatusCode)

	var verifyResult pkgservice.VerifyOTPResponse
	respBody, _ = io.ReadAll(resp.Body)
	err = json.Unmarshal(respBody, &verifyResult)
	s.Require().NoError(err)
	s.Require().NotEmpty(verifyResult.SessionToken)
}

// TestHTTPPlaygroundLogin tests login via HTTP
func (s *HTTPPlaygroundTestSuite) TestHTTPPlaygroundLogin() {
	testOTPCode := "123456"
	testEmail := "httplogin@example.com"
	testPassword := "password123"

	// Signup
	signupPayload := pkgservice.SignupRequest{
		Email:    testEmail,
		Password: testPassword,
	}
	body, _ := json.Marshal(signupPayload)
	resp, _ := s.HTTPClient.Post(
		fmt.Sprintf("%s/api/auth/signup", s.ServerAddr),
		"application/json",
		bytes.NewReader(body),
	)

	var signupResult pkgservice.SignupResponse
	respBody, _ := io.ReadAll(resp.Body)
	json.Unmarshal(respBody, &signupResult)

	// Update OTP and verify
	hasher := pkgutils.NewPasswordHasher()
	otpHashCode, _ := hasher.Hash(testOTPCode)
	s.DB.Model(&domain.OTP{}).
		Where("otp_hash = ?", signupResult.OTPHash).
		Update("hashed_code", otpHashCode)

	verifyPayload := pkgservice.VerifyOTPRequest{
		OTPHash: signupResult.OTPHash,
		Code:    testOTPCode,
	}
	body, _ = json.Marshal(verifyPayload)
	s.HTTPClient.Post(
		fmt.Sprintf("%s/api/auth/verify-otp", s.ServerAddr),
		"application/json",
		bytes.NewReader(body),
	)

	// Login
	loginPayload := pkgservice.LoginRequest{
		Email:    testEmail,
		Password: testPassword,
	}
	body, _ = json.Marshal(loginPayload)
	resp, err := s.HTTPClient.Post(
		fmt.Sprintf("%s/api/auth/login", s.ServerAddr),
		"application/json",
		bytes.NewReader(body),
	)

	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, resp.StatusCode)

	var loginResult pkgservice.LoginResponse
	respBody, _ = io.ReadAll(resp.Body)
	err = json.Unmarshal(respBody, &loginResult)
	s.Require().NoError(err)
	s.Require().NotEmpty(loginResult.SessionToken)
}

// TestHTTPPlaygroundHealth tests health endpoint
func (s *HTTPPlaygroundTestSuite) TestHTTPPlaygroundHealth() {
	resp, err := s.HTTPClient.Get(fmt.Sprintf("%s/health", s.ServerAddr))

	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, resp.StatusCode)

	var result map[string]string
	respBody, _ := io.ReadAll(resp.Body)
	json.Unmarshal(respBody, &result)
	s.Require().Equal("ok", result["status"])
}

// TestHTTPPlaygroundDuplicateSignup tests duplicate signup
func (s *HTTPPlaygroundTestSuite) TestHTTPPlaygroundDuplicateSignup() {
	// First signup
	payload := pkgservice.SignupRequest{
		Email:    "httpduplicate@example.com",
		Password: "password123",
	}
	body, _ := json.Marshal(payload)
	s.HTTPClient.Post(
		fmt.Sprintf("%s/api/auth/signup", s.ServerAddr),
		"application/json",
		bytes.NewReader(body),
	)

	// Second signup with same email
	resp, err := s.HTTPClient.Post(
		fmt.Sprintf("%s/api/auth/signup", s.ServerAddr),
		"application/json",
		bytes.NewReader(body),
	)

	s.Require().NoError(err)
	s.Require().Equal(http.StatusBadRequest, resp.StatusCode)
}

// TestHTTPPlayground runs the HTTP playground test suite
func TestHTTPPlayground(t *testing.T) {
	suite.Run(t, new(HTTPPlaygroundTestSuite))
}
