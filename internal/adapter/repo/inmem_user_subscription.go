// Package repo holds in-memory adapter implementations for the per-user
// economy aggregates (BE-USR-1). These are dependency-free, used for tests
// and the M10 skeleton; pgx-backed adapters arrive at M12+.
package repo

import (
	"context"
	"sort"
	"sync"

	usersub "github.com/apollo-chora/chora-identity/internal/domain/user_subscription"
)

// InMemUserSubscriptionRepo is the in-memory implementation of
// usersub.Repository. Thread-safe via mutex.
type InMemUserSubscriptionRepo struct {
	mu    sync.RWMutex
	store map[string]*usersub.Subscription // keyed by subscription_id
}

// NewInMemUserSubscriptionRepo constructs an empty repo.
func NewInMemUserSubscriptionRepo() *InMemUserSubscriptionRepo {
	return &InMemUserSubscriptionRepo{store: make(map[string]*usersub.Subscription)}
}

// Save upserts. OCC enforcement is intentionally loose for in-memory; the
// production pgx repo enforces version match.
func (r *InMemUserSubscriptionRepo) Save(_ context.Context, s *usersub.Subscription) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	clone := *s
	if s.CancelledAt != nil {
		t := *s.CancelledAt
		clone.CancelledAt = &t
	}
	if s.DeletedAt != nil {
		t := *s.DeletedAt
		clone.DeletedAt = &t
	}
	r.store[s.SubscriptionID] = &clone
	return nil
}

// GetByID returns the Subscription with the given id, or ErrNotFound.
func (r *InMemUserSubscriptionRepo) GetByID(_ context.Context, id string) (*usersub.Subscription, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.store[id]
	if !ok || s.DeletedAt != nil {
		return nil, usersub.ErrNotFound
	}
	clone := *s
	return &clone, nil
}

// ListByGcid returns all live (non-soft-deleted) subscriptions for a gcid.
func (r *InMemUserSubscriptionRepo) ListByGcid(_ context.Context, gcid string) ([]*usersub.Subscription, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*usersub.Subscription, 0)
	for _, s := range r.store {
		if s.Gcid != gcid || s.DeletedAt != nil {
			continue
		}
		clone := *s
		out = append(out, &clone)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

// GetByStripeSubscriptionID returns the live (non-soft-deleted)
// Subscription whose StripeSubscriptionID matches the given handle, or
// ErrNotFound when no match exists.
func (r *InMemUserSubscriptionRepo) GetByStripeSubscriptionID(_ context.Context, stripeSubscriptionID string) (*usersub.Subscription, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if stripeSubscriptionID == "" {
		return nil, usersub.ErrNotFound
	}
	for _, s := range r.store {
		if s.DeletedAt != nil {
			continue
		}
		if s.StripeSubscriptionID == stripeSubscriptionID {
			clone := *s
			return &clone, nil
		}
	}
	return nil, usersub.ErrNotFound
}

// Compile-time guard.
var _ usersub.Repository = (*InMemUserSubscriptionRepo)(nil)
