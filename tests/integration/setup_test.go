package tests

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/arpansaha13/gotoolkit/gtk"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sony/gobreaker/v2"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/arpansaha13/goauthkit"
	"github.com/arpansaha13/goauthkit/internal/middleware"
	"github.com/arpansaha13/goauthkit/pb"
	"github.com/arpansaha13/goauthkit/tests/mocks"
)

type AuthIntegrationTestSuite struct {
	suite.Suite
	Container     testcontainers.Container
	DB            *pgxpool.Pool
	Ctx           context.Context
	ServerAddr    string
	HTTPServer    *http.Server
	GRPCServer    *grpc.Server
	GRPCConn      *grpc.ClientConn
	GRPCClient    pb.AuthServiceClient
	AuthService   goauthkit.IAuthService
	EmailPool     *goauthkit.EmailWorkerPool
	EmailProvider *goauthkit.MockEmailProvider
	Fixture       *TestFixture
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
	dsn := fmt.Sprintf("postgres://testuser:testpass@%s:%s/test_auth_integration?sslmode=disable", host, port.Port())

	pg := gtk.NewPostgresClient(ctx, gtk.PostgresClientConfig{DatabaseURL: dsn})
	s.Require().NoError(pg.Start(), "Failed to connect to database")
	s.DB = pg.Pool()

	migrationSQL, err := os.ReadFile(filepath.Join("..", "..", "migrations", "0001_initial_schema.up.sql"))
	s.Require().NoError(err, "Failed to read migration")
	_, err = s.DB.Exec(ctx, string(migrationSQL))
	s.Require().NoError(err, "Failed to run migrations")

	// Set up dependencies
	cb := gobreaker.NewCircuitBreaker[any](gobreaker.Settings{Name: "test-postgres"})
	userRepo := goauthkit.NewUserRepository(pg, cb)
	otpRepo := goauthkit.NewOTPRepository(pg, cb)
	sessionRepo := goauthkit.NewSessionRepository(pg, cb)
	hasher := goauthkit.NewPasswordHasher()

	emailProviderInterface := goauthkit.NewMockEmailProvider()
	s.EmailProvider = emailProviderInterface.(*goauthkit.MockEmailProvider)
	s.EmailPool = goauthkit.NewEmailWorkerPool(
		goauthkit.EmailWorkerPoolConfig{WorkerCount: 2, QueueSize: 50},
		emailProviderInterface,
	)

	providerRepo := goauthkit.NewProviderRepository(pg, cb)
	sessionCache := &mocks.MockSessionCache{}
	s.AuthService, err = goauthkit.NewAuthService(
		userRepo, otpRepo, sessionRepo, providerRepo, sessionCache, hasher,
		s.EmailPool,
		goauthkit.AuthServiceConfig{
			OTPExpiry:  10 * time.Minute,
			OTPLength:  6,
			SessionTTL: 30 * time.Minute,
			SecretKey:  "test-secret-key-at-least-32-characters-long-ok",
		},
		nil,
	)
	s.Require().NoError(err, "Failed to create auth service")

	s.setupHTTPServer()
	s.setupGRPCServer()
}

func (s *AuthIntegrationTestSuite) TearDownSuite() {
	if s.HTTPServer != nil {
		s.HTTPServer.Shutdown(s.Ctx)
	}
	if s.GRPCServer != nil {
		s.GRPCServer.Stop()
	}
	if s.GRPCConn != nil {
		s.GRPCConn.Close()
	}
	if s.Container != nil {
		s.Container.Terminate(s.Ctx)
	}
	if s.EmailPool != nil {
		s.EmailPool.Stop()
	}
	if s.DB != nil {
		s.DB.Close()
	}
}

func (s *AuthIntegrationTestSuite) SetupTest() {
	s.cleanupTables()
	s.Fixture = NewTestFixture(s.T(), s.DB, s.ServerAddr, s.GRPCClient)
}

func (s *AuthIntegrationTestSuite) cleanupTables() {
	tables := []string{"sessions", "otps", "credentials", "users"}
	for _, table := range tables {
		_, _ = s.DB.Exec(s.Ctx, fmt.Sprintf("TRUNCATE TABLE %s CASCADE", table))
	}
}

func (s *AuthIntegrationTestSuite) setupHTTPServer() {
	validator := goauthkit.NewValidator()
	cookieConfig := goauthkit.NewCookieConfig("test_session", false)

	authCtrl := goauthkit.NewAuthController(s.AuthService, validator, cookieConfig)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/auth/signup", gtk.HttpControllerAdaptor(authCtrl.Signup))
	mux.HandleFunc("POST /api/auth/login", gtk.HttpControllerAdaptor(authCtrl.Login))
	mux.HandleFunc("POST /api/auth/verify", gtk.HttpControllerAdaptor(authCtrl.VerifyOTP))
	mux.HandleFunc("POST /api/auth/logout", gtk.HttpControllerAdaptor(authCtrl.Logout))

	// Wrap mux with middlewares
	handler := TokenExtractionMiddleware(cookieConfig.Name)(gtk.HttpRecoveryMiddleware(gtk.HttpErrorMiddleware(mux)))

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	s.Require().NoError(err)
	s.ServerAddr = "http://" + listener.Addr().String()

	s.HTTPServer = &http.Server{Handler: handler}
	go s.HTTPServer.Serve(listener)
	time.Sleep(100 * time.Millisecond)
}

func (s *AuthIntegrationTestSuite) setupGRPCServer() {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	s.Require().NoError(err)

	s.GRPCServer = grpc.NewServer(
		grpc.UnaryInterceptor(middleware.ChainUnaryInterceptors(
			gtk.GrpcErrorInterceptor(),
			gtk.GrpcRecoveryInterceptor(),
			middleware.AuthorizationInterceptor(),
		)),
	)

	validator := goauthkit.NewValidator()
	authServiceImpl := goauthkit.NewAuthServiceImpl(s.AuthService, validator)
	pb.RegisterAuthServiceServer(s.GRPCServer, authServiceImpl)

	go func() {
		if err := s.GRPCServer.Serve(listener); err != nil {
			// Don't fail if we stop the server intentionally
		}
	}()

	conn, err := grpc.Dial(
		listener.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	s.Require().NoError(err)

	s.GRPCConn = conn
	s.GRPCClient = pb.NewAuthServiceClient(conn)
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
