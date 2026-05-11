package tests

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/arpansaha13/gotoolkit/gtk"
	"github.com/sony/gobreaker/v2"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/arpansaha13/goauthkit/internal/domain"
	"github.com/arpansaha13/goauthkit/internal/middleware"
	"github.com/arpansaha13/goauthkit/pb"
	"github.com/arpansaha13/goauthkit/pkg"
)

// GRPCPlaygroundTestSuite tests the gRPC playground server using pkg exports
type GRPCPlaygroundTestSuite struct {
	suite.Suite
	Container     testcontainers.Container
	DB            *gorm.DB
	Ctx           context.Context
	GRPCClient    pb.AuthServiceClient
	GRPCConn      *grpc.ClientConn
	GRPCListener  net.Listener
	GRPCServer    *grpc.Server
	AuthService   pkg.IAuthService
	EmailPool     *pkg.EmailWorkerPool
	EmailProvider *pkg.MockEmailProvider
	Fixture       *TestFixture
}

// SetupSuite initializes test environment
func (s *GRPCPlaygroundTestSuite) SetupSuite() {
	ctx := context.Background()
	s.Ctx = ctx

	// Start PostgreSQL container
	req := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "testuser",
			"POSTGRES_PASSWORD": "testpass",
			"POSTGRES_DB":       "test_playground_grpc",
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
		"host=%s port=%s user=testuser password=testpass dbname=test_playground_grpc sslmode=disable",
		host, port.Port(),
	)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	s.Require().NoError(err, "Failed to connect to database")
	s.DB = db

	// Run migrations
	err = domain.AutoMigrate(db)
	s.Require().NoError(err, "Failed to run migrations")

	// Setup gRPC server using pkg exports (this is how the playground uses the library)
	err = s.setupGRPCServer(ctx, db)
	s.Require().NoError(err, "Failed to setup gRPC server")
}

// TearDownSuite cleans up
func (s *GRPCPlaygroundTestSuite) TearDownSuite() {
	if s.GRPCServer != nil {
		s.GRPCServer.Stop()
	}
	if s.GRPCConn != nil {
		s.GRPCConn.Close()
	}
	if s.Container != nil {
		s.Container.Terminate(s.Ctx)
	}
}

// SetupTest prepares each test
func (s *GRPCPlaygroundTestSuite) SetupTest() {
	s.cleanupTables()
	s.Fixture = NewTestFixture(s.T(), s.DB, "", s.GRPCClient)
}

// cleanupTables truncates all tables
func (s *GRPCPlaygroundTestSuite) cleanupTables() {
	tables := []string{"sessions", "otps", "credentials", "users"}
	for _, table := range tables {
		err := s.DB.Exec(fmt.Sprintf("TRUNCATE TABLE %s CASCADE", table)).Error
		s.Require().NoError(err, "Failed to truncate table %s", table)
	}
}

// setupGRPCServer sets up the gRPC server using pkg exports (playground pattern)
func (s *GRPCPlaygroundTestSuite) setupGRPCServer(ctx context.Context, db *gorm.DB) error {
	var err error

	// Create listener
	s.GRPCListener, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}

	// Create gRPC server with interceptors
	s.GRPCServer = grpc.NewServer(
		grpc.UnaryInterceptor(middleware.ChainUnaryInterceptors(
			gtk.GrpcErrorInterceptor(),
			gtk.GrpcRecoveryInterceptor(),
			middleware.AuthorizationInterceptor(),
		)),
	)

	// Register auth service using pkg exports (this is how the playground uses the library)
	// Initialize circuit breaker for repositories
	cb := gobreaker.NewCircuitBreaker[any](gobreaker.Settings{
		Name: "test-postgres",
	})

	userRepo := pkg.NewUserRepository(db, cb)
	otpRepo := pkg.NewOTPRepository(db, cb)
	sessionRepo := pkg.NewSessionRepository(db, cb)
	hasher := pkg.NewPasswordHasher()
	validator := pkg.NewValidator()
	emailProviderInterface := pkg.NewMockEmailProvider()
	s.EmailProvider = emailProviderInterface.(*pkg.MockEmailProvider)
	s.EmailPool = pkg.NewEmailWorkerPool(2, 50, emailProviderInterface)

	providerRepo := pkg.NewProviderRepository(db, cb)
	s.AuthService = pkg.NewAuthService(
		userRepo,
		otpRepo,
		sessionRepo,
		providerRepo,
		nil,
		hasher,
		pkg.AuthServiceConfig{
			OTPExpiry:  10 * time.Minute,
			OTPLength:  6,
			SessionTTL: 30 * time.Minute,
			SecretKey:  "test-secret-key-at-least-32-characters-long-ok",
			EmailPool:  s.EmailPool,
		},
		nil,
	)

	// Use pkg exports for controller (this demonstrates playground usage)
	authServiceImpl := pkg.NewAuthServiceImpl(s.AuthService, validator)
	pb.RegisterAuthServiceServer(s.GRPCServer, authServiceImpl)

	// Start server in goroutine
	go func() {
		if err := s.GRPCServer.Serve(s.GRPCListener); err != nil {
			fmt.Printf("gRPC server error: %v\n", err)
		}
	}()

	// Create client
	conn, err := grpc.Dial(
		s.GRPCListener.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return fmt.Errorf("failed to create gRPC connection: %w", err)
	}

	s.GRPCConn = conn
	s.GRPCClient = pb.NewAuthServiceClient(conn)

	return nil
}

// TestPlaygroundGRPCFlows tests gRPC endpoints using TableDrivenTestCase
func (s *GRPCPlaygroundTestSuite) TestPlaygroundGRPCFlows() {
	testCases := []TableDrivenTestCase{
		{
			Name: "Validate Session",
			Test: func(f *TestFixture) error {
				// Create and verify user
				user, _ := s.setupVerifiedUser("session@example.com", "password123")
				
				// Create session manually in DB
				token := "test-session-token"
				hasher := sha256.New()
				hasher.Write([]byte(token + "test-secret-key-at-least-32-characters-long-ok"))
				tokenHash := hex.EncodeToString(hasher.Sum(nil))

				err := s.DB.Create(&domain.Session{
					UserID:    user.ID,
					TokenHash: tokenHash,
					ExpiresAt: time.Now().Add(24 * time.Hour),
				}).Error
				s.Require().NoError(err)

				// Validate session
				md := metadata.Pairs("authorization", fmt.Sprintf("Bearer %s", token))
				ctxWithToken := metadata.NewOutgoingContext(s.Ctx, md)

				resp, err := f.AuthClient.ValidateSession(ctxWithToken, &pb.ValidateSessionRequest{})
				s.Require().NoError(err)
				s.Require().True(resp.Valid)
				return nil
			},
		},
		{
			Name: "Get User",
			Test: func(f *TestFixture) error {
				// Create and verify user
				user, _ := s.setupVerifiedUser("getuser@example.com", "password123")

				md := metadata.Pairs("authorization", "Bearer test-token")
				ctxWithToken := metadata.NewOutgoingContext(s.Ctx, md)

				resp, err := f.AuthClient.GetUser(ctxWithToken, &pb.GetUserRequest{UserId: int64(user.ID)})
				s.Require().NoError(err)
				s.Require().NotNil(resp.User)
				s.Require().Equal("getuser@example.com", resp.User.Email)
				return nil
			},
		},
		{
			Name: "Delete User",
			Test: func(f *TestFixture) error {
				// Create and verify user
				user, _ := s.setupVerifiedUser("deleteuser@example.com", "password123")

				md := metadata.Pairs("authorization", "Bearer test-token")
				ctxWithToken := metadata.NewOutgoingContext(s.Ctx, md)

				// Delete user
				resp, err := f.AuthClient.DeleteUser(ctxWithToken, &pb.DeleteUserRequest{UserId: int64(user.ID)})
				s.Require().NoError(err)
				s.Require().NotEmpty(resp.Message)

				// Verify deletion
				_, verifyErr := f.AuthClient.GetUser(ctxWithToken, &pb.GetUserRequest{UserId: int64(user.ID)})
				s.Require().Error(verifyErr)
				return nil
			},
		},
	}

	for _, tc := range testCases {
		s.Run(tc.Name, func() {
			s.SetupTest()
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

func (s *GRPCPlaygroundTestSuite) setupVerifiedUser(email, password string) (*domain.User, error) {
	hasher := pkg.NewPasswordHasher()
	hashedPassword, _ := hasher.Hash(password)
	
	username := "testuser"
	user := &domain.User{
		Email:    email,
		Username: &username,
		Verified: true,
		Credentials: &domain.Credentials{
			PasswordHash: hashedPassword,
		},
	}
	
	err := s.DB.Create(user).Error
	return user, err
}

// TestGRPCPlayground runs the gRPC playground test suite
func TestGRPCPlayground(t *testing.T) {
	suite.Run(t, new(GRPCPlaygroundTestSuite))
}
