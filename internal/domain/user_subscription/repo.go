// Repository port for the user_subscription aggregate. Hexagonal:
// adapters implement; domain never imports adapters.
package user_subscription

import (
	"context"
	"errors"
)

// ErrNotFound — sentinel for missing subscriptions.
var ErrNotFound = errors.New("user_subscription: not found")

// ErrConflict — optimistic-concurrency mismatch on Save.
var ErrConflict = errors.New("user_subscription: optimistic concurrency conflict")

// Repository is the persistence port.
type Repository interface {
	Save(ctx context.Context, s *Subscription) error
	GetByID(ctx context.Context, subscriptionID string) (*Subscription, error)
	ListByGcid(ctx context.Context, gcid string) ([]*Subscription, error)
	// GetByStripeSubscriptionID returns the Subscription whose Stripe
	// Subscription handle matches the given id. Returns ErrNotFound when
	// no live (non-soft-deleted) Subscription holds the handle.
	//
	// Used by the chora.payments.user_subscription.*.v1 subscriber to
	// dispatch payment-lifecycle events back to the chora-identity-owned
	// UserSubscription aggregate (per ADR-164 Wave 1 Stage E).
	GetByStripeSubscriptionID(ctx context.Context, stripeSubscriptionID string) (*Subscription, error)
}
