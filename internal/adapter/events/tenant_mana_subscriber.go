// Package events — Pub/Sub subscriber for cross-domain tenant subsidy
// events flowing from chora-tenancy → chora-identity.
//
// Topic: chora.tenancy.tenant_mana_allocation.granted.v1
// Action: credit UserMana with reason=tenant_subsidy + register an
// Allocation row that participates in the FIFO Spend Order.
//
// Per ADR-142 cross-domain flow: chora-tenancy holds the source-of-truth
// for TenantManaPool + TenantManaAllocation; chora-identity maintains a
// projection for FIFO drain.
//
// Idempotency: M12.3 W2a (2026-05-12) — the inbox check is a
// chora-go-common/idempotent.Store; replays land on the same key and the
// subsequent attempts return early without re-crediting. The Quoter's
// own IdempotencyKey is a defense-in-depth backstop inside the credit
// path. The inbox protects against pod-restart + multi-replica failure
// modes that an in-process map cannot survive.
package events

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/apollo-chora/chora-common/idempotent"
	mana "github.com/apollo-chora/chora-identity/internal/domain/user_mana"
)

// TopicTenantManaAllocationGranted is the canonical inbound topic this
// subscriber binds to.
const TopicTenantManaAllocationGranted = "chora.tenancy.tenant_mana_allocation.granted.v1"

// TenantManaInboxTTL is the dedupe-key retention window for the
// tenant_mana subscriber's inbox. 24h matches the closure + enrollment
// subscriber canonicals.
const TenantManaInboxTTL = 24 * time.Hour

// TenantAllocationGrantedPayload mirrors the wire shape of
// chora.tenancy.tenant_mana_allocation.granted.v1 payloads (as decoded
// from the event envelope by the underlying Pub/Sub adapter at M12+).
//
// The chora-tenancy proto is the source-of-truth; this struct is the
// loose JSON projection used during local dev / integration tests.
type TenantAllocationGrantedPayload struct {
	AllocationID string     `json:"allocation_id"`
	TenantID     string     `json:"tenant_id"`
	Gcid         string     `json:"gcid"`
	Units        int64      `json:"units"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	AllocatedAt  time.Time  `json:"allocated_at"`
}

// TenantManaSubscriber wires the Quoter to the tenant_mana_allocation
// topic. The cmd/server entrypoint subscribes to the topic and dispatches
// every message through Handle.
//
// Inbox dedupe (W2a): IdempotencyKey from the envelope (or a synthetic
// "tenant-alloc:" + allocation_id key) is checked against a
// chora-go-common/idempotent.Store to skip duplicate deliveries.
type TenantManaSubscriber struct {
	quoter *mana.Quoter
	inbox  idempotent.Store
	ttl    time.Duration
}

// NewTenantManaSubscriber constructs the subscriber with the Quoter +
// an inbox store. nil inbox triggers a defensive MemoryStore fallback
// (dev-only; production passes PostgresStore).
func NewTenantManaSubscriber(quoter *mana.Quoter, inbox idempotent.Store) *TenantManaSubscriber {
	if inbox == nil {
		inbox = idempotent.NewMemoryStore()
	}
	return &TenantManaSubscriber{
		quoter: quoter,
		inbox:  inbox,
		ttl:    TenantManaInboxTTL,
	}
}

// WithInboxTTL overrides the inbox dedupe TTL. Returns the same subscriber
// for fluent wiring in tests.
func (s *TenantManaSubscriber) WithInboxTTL(d time.Duration) *TenantManaSubscriber {
	if d > 0 {
		s.ttl = d
	}
	return s
}

// SubscribedTopic returns the canonical topic this subscriber binds to —
// surfaced so the cmd/server wiring can register the subscription with the
// Pub/Sub adapter.
func (s *TenantManaSubscriber) SubscribedTopic() string {
	return TopicTenantManaAllocationGranted
}

// Handle processes one tenant_mana_allocation.granted.v1 message. The
// envelope's idempotency_key is used to dedup replays via the inbox
// store; a synthetic "tenant-alloc:" + allocation_id key is used when
// the envelope omits one.
func (s *TenantManaSubscriber) Handle(ctx context.Context, env Envelope, payload TenantAllocationGrantedPayload) error {
	if s == nil || s.quoter == nil || s.inbox == nil {
		return errors.New("events: TenantManaSubscriber not initialised")
	}
	if payload.Gcid == "" {
		return errors.New("events: tenant_mana_allocation payload requires gcid")
	}
	if payload.AllocationID == "" {
		return errors.New("events: tenant_mana_allocation payload requires allocation_id")
	}
	if payload.Units <= 0 {
		return fmt.Errorf("events: tenant_mana_allocation units must be > 0; got %d", payload.Units)
	}

	idem := strings.TrimSpace(env.IdempotencyKey)
	if idem == "" {
		idem = "tenant-alloc:" + payload.AllocationID
	}

	return s.inbox.Process(ctx, idem, s.ttl, func() error {
		_, err := s.quoter.CreditMana(ctx, mana.CreditInput{
			Gcid:               payload.Gcid,
			Source:             mana.SourceTenantSubsidy,
			Units:              payload.Units,
			Reason:             mana.ReasonTenantSubsidy,
			IdempotencyKey:     idem,
			SourceAllocationID: payload.AllocationID,
			TenantID:           payload.TenantID,
			ExpiresAt:          payload.ExpiresAt,
		})
		return err
	})
}
