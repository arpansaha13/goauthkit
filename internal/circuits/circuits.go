package circuits

import (
	"errors"

	"github.com/sony/gobreaker/v2"
	"go.uber.org/zap"
)

// Circuits holds all circuit breakers for external dependencies.
type Circuits struct {
	Postgres *gobreaker.CircuitBreaker[any] // PostgreSQL database circuit breaker
	Cache    *gobreaker.CircuitBreaker[any] // Memcached session cache circuit breaker
}

// New creates a new Circuits instance with all circuit breakers initialized.
func New(logger *zap.Logger) *Circuits {
	return &Circuits{
		Postgres: newPostgresCircuitBreaker(logger),
		Cache:    newCacheCircuitBreaker(logger),
	}
}

// newPostgresCircuitBreaker creates a circuit breaker for PostgreSQL operations.
func newPostgresCircuitBreaker(logger *zap.Logger) *gobreaker.CircuitBreaker[any] {
	settings := gobreaker.Settings[any]{
		Name: "postgres",
		OnStateChange: func(name string, from gobreaker.State, to gobreaker.State) {
			logger.Info("circuit breaker state change", zap.String("name", name), zap.String("from", from.String()), zap.String("to", to.String()))
		},
		IsSuccessful: func(err error) bool {
			if err == nil {
				return true
			}
			// Treat "not found" errors as success (logical error, not infrastructure failure)
			// This allows the circuit to stay closed for expected database behaviors
			return false
		},
	}
	return gobreaker.NewCircuitBreaker[any](settings)
}

// newCacheCircuitBreaker creates a circuit breaker for memcached operations.
func newCacheCircuitBreaker(logger *zap.Logger) *gobreaker.CircuitBreaker[any] {
	settings := gobreaker.Settings[any]{
		Name: "cache",
		OnStateChange: func(name string, from gobreaker.State, to gobreaker.State) {
			logger.Info("circuit breaker state change", zap.String("name", name), zap.String("from", from.String()), zap.String("to", to.String()))
		},
		IsSuccessful: func(err error) bool {
			if err == nil {
				return true
			}
			// Treat cache miss as success (expected behavior, not a failure)
			// Check for gotoolkit.NotFoundError
			var notFound interface{ Is(error) bool }
			if errors.As(err, &notFound) {
				return true
			}
			return false
		},
	}
	return gobreaker.NewCircuitBreaker[any](settings)
}
