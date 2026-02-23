package http

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"

	"github.com/arpansaha13/goauthkit/pkg/repository"
	"github.com/arpansaha13/goauthkit/pkg/service"
	"github.com/arpansaha13/goauthkit/pkg/utils"
	"github.com/arpansaha13/goauthkit/pkg/worker"
	"github.com/arpansaha13/goauthkit/playground/config"
)

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
	db, err := utils.InitDB(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer func() {
		if err := utils.CloseDB(db); err != nil {
			log.Printf("Error closing database: %v", err)
		}
	}()

	// Initialize repositories
	userRepo := repository.NewUserRepository(db)
	otpRepo := repository.NewOTPRepository(db)
	sessionRepo := repository.NewSessionRepository(db)

	// Initialize email provider
	var emailProvider worker.EmailProvider
	if cfg.Environment == "production" {
		emailProvider = worker.NewSMTPEmailProvider(
			cfg.SMTPHost,
			cfg.SMTPPort,
			cfg.SMTPUser,
			cfg.SMTPPassword,
			cfg.EmailFrom,
		)
	} else {
		emailProvider = worker.NewMockEmailProvider()
	}

	// Initialize password hasher and validator
	hasher := utils.NewPasswordHasher()
	validator := utils.NewValidator()

	// Initialize email worker pool
	emailPool := worker.NewEmailWorkerPool(
		cfg.EmailWorkerPoolSize,
		cfg.EmailTaskQueueSize,
		emailProvider,
	)
	defer emailPool.Stop()

	// Initialize auth service
	authService := service.NewAuthService(
		userRepo,
		otpRepo,
		sessionRepo,
		hasher,
		service.AuthServiceConfig{
			OTPExpiry:  cfg.OTPExpiry,
			OTPLength:  cfg.OTPLength,
			SessionTTL: cfg.SessionTTL,
			SecretKey:  cfg.SecretKey,
			EmailPool:  emailPool,
		},
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

	// Server setup
	port := ":8080"
	server := &http.Server{
		Addr:    port,
		Handler: mux,
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
func signupHandler(w http.ResponseWriter, r *http.Request, authService service.IAuthService, validator *utils.Validator) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"message":"signup handler"}`)
}

func verifyOTPHandler(w http.ResponseWriter, r *http.Request, authService service.IAuthService, validator *utils.Validator) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"message":"verify otp handler"}`)
}

func loginHandler(w http.ResponseWriter, r *http.Request, authService service.IAuthService, validator *utils.Validator) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"message":"login handler"}`)
}

func logoutHandler(w http.ResponseWriter, r *http.Request, authService service.IAuthService) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"message":"logout handler"}`)
}

func validateSessionHandler(w http.ResponseWriter, r *http.Request, authService service.IAuthService) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"message":"validate session handler"}`)
}

func getUserHandler(w http.ResponseWriter, r *http.Request, authService service.IAuthService) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"message":"get user handler"}`)
}

func deleteUserHandler(w http.ResponseWriter, r *http.Request, authService service.IAuthService) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"message":"delete user handler"}`)
}

func handleError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprintf(w, `{"error":"%v"}`, err)
}
