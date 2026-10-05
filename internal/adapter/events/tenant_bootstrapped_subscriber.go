// Package events — Pub/Sub subscriber for
// chora.tenancy.tenant.bootstrapped.v1 (CHO-1630 Phase 2).
//
// chora-tenancy publishes this event from its outbox when a caller
// self-onboards via POST /api/v1/tenants/bootstrap (CHO-1628). The
// chora-identity-side subscriber inserts the mirror row into
// chora_identity.tenant_memberships so the BFF session-mint can find
// the bootstrapped tenant in the caller's tenant set.
//
// At-least-once delivery — the upserter MUST be idempotent (the pg
// adapter uses ON CONFLICT (gcid, tenant_id) DO NOTHING). The inbox
// store provides a second dedupe layer keyed on the envelope's
// idempotency_key so domain logic + audit emissions run at most once
// per logical bootstrap.
//
// The mirror row carries `owner` (UX refactor R21, migration
// 0041_owner_role). Until then the identity-side `membership_role` ENUM
// had no owner value, so this subscriber deliberately downgraded the
// bootstrapping owner to `admin`; the JWT carried `owner` regardless,
// because its roles come from the authoritative chora_tenancy.members,
// and the result was ownership the platform enforced and no human could
// see. Storing it is not granting it: `owner` stays out of
// identity.Role.Grantable() and out of the tenancy UpsertMembership
// RPC, so no API can hand it to anybody.
//
// Hexagonal note: ADAPTER. The TenantMembershipUpserter port keeps the
// pgx-backed adapter out of this file.
package events

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/apollo-chora/chora-common/idempotent"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// TopicTenancyTenantBootstrappedV1 is the canonical topic the subscriber
// binds to.
const TopicTenancyTenantBootstrappedV1 = "chora.tenancy.tenant.bootstrapped.v1"

// TenantBootstrappedInboxTTL — dedupe retention window. Matches the
// 24h pattern used by PaymentsSubscriber + EnrollmentSubscriber.
const TenantBootstrappedInboxTTL = 24 * time.Hour

// TenantBootstrappedPayload mirrors the wire shape of the
// chora.tenancy.v1.TenantBootstrapped proto message. JSON-projectable
// for the in-process bus + dev tooling; the production Pub/Sub adapter
// decodes the binary protobuf into this struct shape.
type TenantBootstrappedPayload struct {
	TenantID       string    `json:"tenant_id"`
	OwnerGCID      string    `json:"owner_gcid"`
	DisplayName    string    `json:"display_name"`
	OwnerMemberID  string    `json:"owner_member_id"`
	EntitlementID  string    `json:"entitlement_id"`
	BootstrappedAt time.Time `json:"bootstrapped_at"`
}

// TenantMembershipUpserter is the persistence port the subscriber
// depends on. Production wires the pg-backed adapter that does
// `INSERT INTO tenant_memberships ... ON CONFLICT (gcid, tenant_id)
// DO NOTHING` inside a SET LOCAL chora.tenant_id transaction. Tests
// inject a fake.
type TenantMembershipUpserter interface {
	UpsertMembershipOnBootstrap(ctx context.Context, gcid, tenantID, role string) error
}

// TenantBootstrappedSubscriber consumes the v1 topic and mirrors the
// membership into chora_identity.tenant_memberships.
type TenantBootstrappedSubscriber struct {
	upserter TenantMembershipUpserter
	inbox    idempotent.Store
	ttl      time.Duration
}

// NewTenantBootstrappedSubscriber constructs the subscriber. Panics on
// nil upserter — wiring bug should fail loud at boot. nil inbox falls
// back to MemoryStore (dev / test only; production wires the
// PostgresStore against chora_identity.idempotency_keys).
func NewTenantBootstrappedSubscriber(
	upserter TenantMembershipUpserter,
	inbox idempotent.Store,
) *TenantBootstrappedSubscriber {
	if upserter == nil {
		panic("events.NewTenantBootstrappedSubscriber: nil upserter")
	}
	if inbox == nil {
		inbox = idempotent.NewMemoryStore()
	}
	return &TenantBootstrappedSubscriber{
		upserter: upserter,
		inbox:    inbox,
		ttl:      TenantBootstrappedInboxTTL,
	}
}

// WithInboxTTL overrides the dedupe TTL (tests + custom prod tuning).
func (s *TenantBootstrappedSubscriber) WithInboxTTL(d time.Duration) *TenantBootstrappedSubscriber {
	if d > 0 {
		s.ttl = d
	}
	return s
}

// SubscribedTopics surfaces the one canonical topic this subscriber
// binds to — cmd/server wiring registers the Pub/Sub subscription
// against it.
func (s *TenantBootstrappedSubscriber) SubscribedTopics() []string {
	return []string{TopicTenancyTenantBootstrappedV1}
}

// HandleTenantBootstrapped processes one inbound event. Returns a
// non-nil error on validation failure or persistence error; nil on
// duplicate delivery (inbox skip) and on successful insert.
//
// The mirror row is written with role=owner: this event announces that a
// tenant was bootstrapped BY that GCID, so the owner row is the fact
// being mirrored. See the file header.
func (s *TenantBootstrappedSubscriber) HandleTenantBootstrapped(
	ctx context.Context,
	env Envelope,
	payload TenantBootstrappedPayload,
) error {
	tenantID := strings.TrimSpace(payload.TenantID)
	if tenantID == "" {
		return errors.New("events: tenant_bootstrapped payload missing tenant_id")
	}
	gcid := strings.TrimSpace(payload.OwnerGCID)
	if gcid == "" {
		return errors.New("events: tenant_bootstrapped payload missing owner_gcid")
	}

	idemKey := strings.TrimSpace(env.IdempotencyKey)
	if idemKey == "" {
		// Fallback synthetic key keeps dedupe live even when an upstream
		// publisher forgets to mint one. Mirrors PaymentsSubscriber's
		// "payments-{event_type}:{stripe_subscription_id}" pattern.
		idemKey = "tenant-bootstrapped:" + tenantID
	}

	return s.inbox.Process(ctx, idemKey, s.ttl, func() error {
		if err := s.upserter.UpsertMembershipOnBootstrap(ctx, gcid, tenantID, string(identity.RoleOwner)); err != nil {
			return fmt.Errorf("events: upsert mirror tenant_memberships: %w", err)
		}
		return nil
	})
}
