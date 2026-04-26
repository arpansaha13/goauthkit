package grpc

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/arpansaha13/gotoolkit/gtk"
	"github.com/sony/gobreaker/v2"
	"go.uber.org/zap"
	"google.golang.org/grpc"

	"github.com/arpansaha13/goauthkit/pb"
	"github.com/arpansaha13/goauthkit/pkg"
	"github.com/arpansaha13/goauthkit/playground/config"
)

var (
	environment = flag.String("env", "development", "Environment: development, staging, production")
)

func main() {
	flag.Parse()

	// Initialize zap logger
	otelLogger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("failed to initialize zap logger: %v", err)
	}
	defer otelLogger.Sync()
	zap.ReplaceGlobals(otelLogger)

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	log.Printf("Starting auth service (gRPC) in %s environment", cfg.Environment)

	// Initialize database
	db, err := pkg.InitDB(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer func() {
		if err := pkg.CloseDB(db); err != nil {
			log.Printf("Error closing database: %v", err)
		}
	}()

	// Initialize circuit breaker for playground
	cb := gobreaker.NewCircuitBreaker[any](gobreaker.Settings{
		Name: "playground-postgres",
	})

	// Initialize session cache (optional - can be nil for database-only mode)
	var sessionCache pkg.ISessionCache
	// For now, we skip memcached in playground - pass nil to use database-only mode
	// To enable memcached: initialize memcache.Client and pass it to pkg.NewSessionCache
	sessionCache = nil

	// Initialize repositories
	userRepo := pkg.NewUserRepository(db, cb)
	otpRepo := pkg.NewOTPRepository(db, cb)
	sessionRepo := pkg.NewSessionRepository(db, cb)
	providerRepo := pkg.NewProviderRepository(db, cb)

	// Initialize email provider
	var emailProvider pkg.EmailProvider
	if cfg.Environment == "production" {
		emailProvider = pkg.NewSMTPEmailProvider(
			cfg.SMTPHost,
			cfg.SMTPPort,
			cfg.SMTPUser,
			cfg.SMTPPassword,
			cfg.EmailFrom,
		)
	} else {
		emailProvider = pkg.NewMockEmailProvider()
	}

	// Initialize password hasher and validator
	hasher := pkg.NewPasswordHasher()
	validator := pkg.NewValidator()

	// Initialize email worker pool
	emailPool := pkg.NewEmailWorkerPool(
		cfg.EmailWorkerPoolSize,
		cfg.EmailTaskQueueSize,
		emailProvider,
	)
	defer emailPool.Stop()

	// Initialize auth service
	authService := pkg.NewAuthService(
		userRepo,
		otpRepo,
		sessionRepo,
		providerRepo,
		sessionCache,
		hasher,
		pkg.AuthServiceConfig{
			OTPExpiry:  cfg.OTPExpiry,
			OTPLength:  cfg.OTPLength,
			SessionTTL: cfg.SessionTTL,
			SecretKey:  cfg.SecretKey,
			EmailPool:  emailPool,
		},
	)

	// Create gRPC server with chained interceptors
	opts := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(
			gtk.GrpcRecoveryInterceptor(),
			gtk.GrpcErrorInterceptor(),
		),
	}
	grpcServer := grpc.NewServer(opts...)

	// Register services
	authController := pkg.NewAuthServiceImpl(authService, validator)

	pb.RegisterAuthServiceServer(grpcServer, authController)

	// Start gRPC server
	grpcPort := fmt.Sprintf("%s:%s", cfg.GRPCHost, cfg.GRPCPort)
	listener, err := net.Listen("tcp", grpcPort)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", grpcPort, err)
	}

	go func() {
		log.Printf("Starting gRPC server on %s", grpcPort)
		if err := grpcServer.Serve(listener); err != nil {
			log.Fatalf("gRPC server error: %v", err)
		}
	}()

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down gRPC server...")
	grpcServer.GracefulStop()
	log.Println("gRPC server stopped")
}
