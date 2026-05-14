package tests

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/arpansaha13/gotoolkit/gtk"
	"github.com/sony/gobreaker/v2"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/arpansaha13/goauthkit/internal/domain"
	"github.com/arpansaha13/goauthkit/pkg"
	"github.com/arpansaha13/goauthkit/tests/mocks"
)

type AuthIntegrationTestSuite struct {
	suite.Suite
	Container   testcontainers.Container
	DB          *gorm.DB
	Ctx         context.Context
	ServerAddr  string
	HTTPServer  *http.Server
	AuthService pkg.IAuthService
	EmailPool   *pkg.EmailWorkerPool
	Fixture     *TestFixture
}

func (s *AuthIntegrationTestSuite) SetupSuite() {
	ctx := context.Background()
	s.Ctx = ctx

	// Start PostgreSQL container
	req := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "testuser",
			"POSTGRES_PASSWORD": "testpass",
			"POSTGRES_DB":       "test_auth_integration",
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

	host, _ := container.Host(ctx)
	port, _ := container.MappedPort(ctx, "5432")
	dsn := fmt.Sprintf("host=%s port=%s user=testuser password=testpass dbname=test_auth_integration sslmode=disable", host, port.Port())

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	s.Require().NoError(err, "Failed to connect to database")
	s.DB = db

	err = domain.AutoMigrate(db)
	s.Require().NoError(err, "Failed to run migrations")

	s.setupHTTPServer(db)
}

func (s *AuthIntegrationTestSuite) TearDownSuite() {
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

func (s *AuthIntegrationTestSuite) SetupTest() {
	s.cleanupTables()
	s.Fixture = NewTestFixture(s.T(), s.DB, s.ServerAddr, nil)
}

func (s *AuthIntegrationTestSuite) cleanupTables() {
	tables := []string{"sessions", "otps", "credentials", "users"}
	for _, table := range tables {
		s.DB.Exec(fmt.Sprintf("TRUNCATE TABLE %s CASCADE", table))
	}
}

func (s *AuthIntegrationTestSuite) setupHTTPServer(db *gorm.DB) {
	cb := gobreaker.NewCircuitBreaker[any](gobreaker.Settings{Name: "test-postgres"})
	userRepo := pkg.NewUserRepository(db, cb)
	otpRepo := pkg.NewOTPRepository(db, cb)
	sessionRepo := pkg.NewSessionRepository(db, cb)
	hasher := pkg.NewPasswordHasher()
	emailProvider := pkg.NewMockEmailProvider()
	s.EmailPool = pkg.NewEmailWorkerPool(2, 50, emailProvider)

	providerRepo := pkg.NewProviderRepository(db, cb)
	sessionCache := &mocks.MockSessionCache{}
	s.AuthService = pkg.NewAuthService(
		userRepo, otpRepo, sessionRepo, providerRepo, sessionCache, hasher,
		pkg.AuthServiceConfig{
			OTPExpiry:  10 * time.Minute,
			OTPLength:  6,
			SessionTTL: 30 * time.Minute,
			SecretKey:  "test-secret-key-at-least-32-characters-long-ok",
			EmailPool:  s.EmailPool,
		},
		nil,
	)

	validator := pkg.NewValidator()
	cookieConfig := pkg.CookieConfig{
		Name:     "test_session",
		Path:     "/",
		HttpOnly: true,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/auth/signup", gtk.HttpControllerAdaptor(pkg.NewSignupController(s.AuthService, validator)))
	mux.HandleFunc("POST /api/auth/login", gtk.HttpControllerAdaptor(pkg.NewLoginController(s.AuthService, validator, cookieConfig)))
	mux.HandleFunc("POST /api/auth/verify", gtk.HttpControllerAdaptor(pkg.NewVerifyOTPController(s.AuthService, validator, cookieConfig)))
	mux.HandleFunc("POST /api/auth/logout", gtk.HttpControllerAdaptor(pkg.NewLogoutController(s.AuthService, cookieConfig)))

	// Wrap mux with middlewares
	handler := TokenExtractionMiddleware(cookieConfig.Name)(gtk.HttpRecoveryMiddleware(gtk.HttpErrorMiddleware(mux)))

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	s.Require().NoError(err)
	s.ServerAddr = "http://" + listener.Addr().String()

	s.HTTPServer = &http.Server{Handler: handler}
	go s.HTTPServer.Serve(listener)
	time.Sleep(100 * time.Millisecond)
}

func TokenExtractionMiddleware(cookieName string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := ""
			// Try cookie
			if cookie, err := r.Cookie(cookieName); err == nil {
				token = cookie.Value
			}
			// Try header
			if token == "" {
				authHeader := r.Header.Get("Authorization")
				if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
					token = authHeader[7:]
				}
			}

			if token != "" {
				ctx := context.WithValue(r.Context(), "authorization", token)
				next.ServeHTTP(w, r.WithContext(ctx))
			} else {
				next.ServeHTTP(w, r)
			}
		})
	}
}

func TestAuthIntegration(t *testing.T) {
	suite.Run(t, new(AuthIntegrationTestSuite))
}
