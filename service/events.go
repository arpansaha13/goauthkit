package service

import (
	"context"

	"github.com/arpansaha13/gotoolkit/gtk"
)

// AuthEventBus is the closed catalog of auth-service events.
type AuthEventBus struct {
	Logout      *gtk.EventBusTopic[LogoutEvent]
	UserCreated *gtk.EventBusTopic[UserCreatedEvent]
	OTPIssued   *gtk.EventBusTopic[OTPIssuedEvent]
}

// NewAuthEventBus returns an event bus with default topic buffers.
// ctx cancellation unsubscribes every topic listener.
func NewAuthEventBus(ctx context.Context) *AuthEventBus {
	return &AuthEventBus{
		Logout:      gtk.NewEventBusTopic[LogoutEvent](ctx),
		UserCreated: gtk.NewEventBusTopic[UserCreatedEvent](ctx),
		OTPIssued:   gtk.NewEventBusTopic[OTPIssuedEvent](ctx),
	}
}
