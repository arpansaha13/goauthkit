package http

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/arpansaha13/gotoolkit/gtk"
	"github.com/sony/gobreaker/v2"
	"go.uber.org/zap"

	"github.com/arpansaha13/goauthkit/internal/domain"
	"github.com/arpansaha13/goauthkit"
	"github.com/arpansaha13/goauthkit/playground/config"
)

type noopSessionCache struct{}

func (n *noopSessionCache) GetSessionByToken(ctx context.Context, tokenHash string) (*domain.Session, error) {
	return nil, nil
}
func (n *noopSessionCache) IsTokenValid(ctx context.Context, tokenHash string) (bool, int64, error) {
	return false, 0, nil
}
func (n *noopSessionCache) SetSession(ctx context.Context, tokenHash string, session *domain.Session, ttl time.Duration) error {
	return nil
}
func (n *noopSessionCache) InvalidateSessionToken(ctx context.Context, tokenHash string) error {
	return nil
}

func main() {
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

	log.Printf("Starting auth service (HTTP) in %s environment", cfg.Environment)

	// Initialize database
	db, err := goauthkit.InitDB(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer func() {
		if err := goauthkit.CloseDB(db); err != nil {
			log.Printf("Error closing database: %v", err)
		}
	}()

	// Initialize circuit breaker for playground
	cb := gobreaker.NewCircuitBreaker[any](gobreaker.Settings{
		Name: "playground-postgres",
	})

	// Initialize session cache (required)
	var sessionCache goauthkit.ISessionCache = &noopSessionCache{}

	// Initialize repositories
	userRepo := goauthkit.NewUserRepository(db, cb)
	otpRepo := goauthkit.NewOTPRepository(db, cb)
	sessionRepo := goauthkit.NewSessionRepository(db, cb)
	providerRepo := goauthkit.NewProviderRepository(db, cb)

	// Initialize email provider
	var emailProvider goauthkit.EmailProvider
	if cfg.Environment == "production" {
		emailProvider = goauthkit.NewSMTPEmailProvider(
			cfg.SMTPHost,
			cfg.SMTPPort,
			cfg.SMTPUser,
			cfg.SMTPPassword,
			cfg.EmailFrom,
		)
	} else {
		emailProvider = goauthkit.NewMockEmailProvider()
	}

	// Initialize password hasher and validator
	hasher := goauthkit.NewPasswordHasher()
	validator := goauthkit.NewValidator()

	// Initialize email worker pool
	emailPool := goauthkit.NewEmailWorkerPool(
		cfg.EmailWorkerPoolSize,
		cfg.EmailTaskQueueSize,
		emailProvider,
	)
	defer emailPool.Stop()

	// Initialize auth service
	authService := goauthkit.NewAuthService(
		userRepo,
		otpRepo,
		sessionRepo,
		providerRepo,
		sessionCache,
		hasher,
		goauthkit.AuthServiceConfig{
			OTPExpiry:  cfg.OTPExpiry,
			OTPLength:  cfg.OTPLength,
			SessionTTL: cfg.SessionTTL,
			SecretKey:  cfg.SecretKey,
			EmailPool:  emailPool,
		},
		nil,
	)

	// Setup HTTP routes
	mux := http.NewServeMux()

	// Auth routes
	mux.HandleFunc("POST /api/auth/signup", func(w http.ResponseWriter, r *http.Request) {
		signupHandler(w, r, authService, validator)
	})

	mux.HandleFunc("POST /api/auth/verify-otp", func(w http.ResponseWriter, r *http.Request) {
		verifyOTPHandler(w, r, authService, validator)
	})

	mux.HandleFunc("POST /api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		loginHandler(w, r, authService, validator)
	})

	mux.HandleFunc("POST /api/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		logoutHandler(w, r, authService)
	})

	mux.HandleFunc("POST /api/auth/validate-session", func(w http.ResponseWriter, r *http.Request) {
		validateSessionHandler(w, r, authService)
	})

	// User routes
	mux.HandleFunc("GET /api/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		getUserHandler(w, r, authService)
	})

	mux.HandleFunc("DELETE /api/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		deleteUserHandler(w, r, authService)
	})

	// Health check
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok"}`)
	})

	// Wrap mux with middleware chain
	var handler http.Handler = mux
	handler = gtk.HttpErrorMiddleware(handler)
	handler = gtk.HttpRecoveryMiddleware(handler)

	// Server setup
	port := ":8080"
	server := &http.Server{
		Addr:    port,
		Handler: handler,
	}

	// Start server in goroutine
	go func() {
		log.Printf("Starting HTTP server on %s", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down server...")
	if err := server.Close(); err != nil {
		log.Fatalf("Error closing server: %v", err)
	}

	log.Println("Server stopped")
}

// Handler stubs - these will be implemented with proper HTTP request/response handling
func signupHandler(w http.ResponseWriter, r *http.Request, authService goauthkit.IAuthService, validator *goauthkit.Validator) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"message":"signup handler"}`)
}

func verifyOTPHandler(w http.ResponseWriter, r *http.Request, authService goauthkit.IAuthService, validator *goauthkit.Validator) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"message":"verify otp handler"}`)
}

func loginHandler(w http.ResponseWriter, r *http.Request, authService goauthkit.IAuthService, validator *goauthkit.Validator) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"message":"login handler"}`)
}

func logoutHandler(w http.ResponseWriter, r *http.Request, authService goauthkit.IAuthService) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"message":"logout handler"}`)
}

func validateSessionHandler(w http.ResponseWriter, r *http.Request, authService goauthkit.IAuthService) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"message":"validate session handler"}`)
}

func getUserHandler(w http.ResponseWriter, r *http.Request, authService goauthkit.IAuthService) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"message":"get user handler"}`)
}

func deleteUserHandler(w http.ResponseWriter, r *http.Request, authService goauthkit.IAuthService) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"message":"delete user handler"}`)
}

func handleError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprintf(w, `{"error":"%v"}`, err)
}
