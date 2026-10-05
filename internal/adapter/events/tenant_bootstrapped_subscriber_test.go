// tenant_bootstrapped_subscriber_test.go — RED-phase tests for the
// chora-identity consumer of chora.tenancy.tenant.bootstrapped.v1
// (CHO-1630 Phase 2). Exercises payload decoding, idempotency, and the
// mirror insert flow against a fake upserter.
package events_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/apollo-chora/chora-common/idempotent"
	"github.com/apollo-chora/chora-identity/internal/adapter/events"
)

type fakeTenantMembershipUpserter struct {
	calls      int
	lastGCID   string
	lastTenant string
	lastRole   string
	err        error
}

func (f *fakeTenantMembershipUpserter) UpsertMembershipOnBootstrap(
	_ context.Context, gcid, tenantID, role string,
) error {
	f.calls++
	f.lastGCID = gcid
	f.lastTenant = tenantID
	f.lastRole = role
	return f.err
}

func sampleEnv() events.Envelope {
	now := time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC)
	return events.Envelope{
		EventID:        "01935f12-0000-7000-8000-0000000000aa",
		IdempotencyKey: "tenant-bootstrapped:01935f12-0000-7000-8000-000000000111",
		TenantID:       "01935f12-0000-7000-8000-000000000111",
		GCID:           "01935f12-0000-7000-8000-000000000222",
		OccurredAt:     now,
		PublishedAt:    now,
		Traceparent:    "",
		SourceProject:  "chora-local",
		SourceService:  "chora-tenancy",
		SchemaVersion:  1,
	}
}

func samplePayload() events.TenantBootstrappedPayload {
	return events.TenantBootstrappedPayload{
		TenantID:       "01935f12-0000-7000-8000-000000000111",
		OwnerGCID:      "01935f12-0000-7000-8000-000000000222",
		DisplayName:    "Phase 2 Sample",
		OwnerMemberID:  "01935f12-0000-7000-8000-000000000333",
		EntitlementID:  "01935f12-0000-7000-8000-000000000444",
		BootstrappedAt: time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC),
	}
}

func TestTenantBootstrappedSubscriber_Handle_happyPath_insertsAdminMembership(t *testing.T) {
	upsert := &fakeTenantMembershipUpserter{}
	sub := events.NewTenantBootstrappedSubscriber(upsert, idempotent.NewMemoryStore())

	err := sub.HandleTenantBootstrapped(context.Background(), sampleEnv(), samplePayload())
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if upsert.calls != 1 {
		t.Errorf("upsert calls = %d, want 1", upsert.calls)
	}
	if upsert.lastGCID != "01935f12-0000-7000-8000-000000000222" {
		t.Errorf("upsert gcid = %q", upsert.lastGCID)
	}
	if upsert.lastTenant != "01935f12-0000-7000-8000-000000000111" {
		t.Errorf("upsert tenant_id = %q", upsert.lastTenant)
	}
	// S7-B3 / UX refactor R21: the mirror carries `owner`, not a downgrade to
	// `admin`. Migration 0041 added the ENUM value; before it the subscriber
	// had nowhere to put the truth, so it wrote admin and the H+ roster showed
	// the owner of the organisation as an ordinary admin.
	if upsert.lastRole != "owner" {
		t.Errorf("upsert role = %q, want owner (membership_role ENUM, migration 0041)", upsert.lastRole)
	}
}

func TestTenantBootstrappedSubscriber_Handle_duplicateDelivery_secondCallIsNoop(t *testing.T) {
	upsert := &fakeTenantMembershipUpserter{}
	store := idempotent.NewMemoryStore()
	sub := events.NewTenantBootstrappedSubscriber(upsert, store)

	if err := sub.HandleTenantBootstrapped(context.Background(), sampleEnv(), samplePayload()); err != nil {
		t.Fatalf("first call err: %v", err)
	}
	// Same envelope → same idempotency key → second call is a no-op.
	if err := sub.HandleTenantBootstrapped(context.Background(), sampleEnv(), samplePayload()); err != nil {
		t.Fatalf("second call err: %v", err)
	}
	if upsert.calls != 1 {
		t.Errorf("upsert should be called once for duplicate delivery, got %d", upsert.calls)
	}
}

func TestTenantBootstrappedSubscriber_Handle_emptyTenantID_rejected(t *testing.T) {
	upsert := &fakeTenantMembershipUpserter{}
	sub := events.NewTenantBootstrappedSubscriber(upsert, idempotent.NewMemoryStore())

	payload := samplePayload()
	payload.TenantID = ""
	err := sub.HandleTenantBootstrapped(context.Background(), sampleEnv(), payload)
	if err == nil {
		t.Errorf("empty tenant_id should be rejected")
	}
	if upsert.calls != 0 {
		t.Errorf("upsert must NOT be called on bad payload")
	}
}

func TestTenantBootstrappedSubscriber_Handle_emptyGCID_rejected(t *testing.T) {
	upsert := &fakeTenantMembershipUpserter{}
	sub := events.NewTenantBootstrappedSubscriber(upsert, idempotent.NewMemoryStore())

	payload := samplePayload()
	payload.OwnerGCID = ""
	err := sub.HandleTenantBootstrapped(context.Background(), sampleEnv(), payload)
	if err == nil {
		t.Errorf("empty owner_gcid should be rejected")
	}
}

func TestTenantBootstrappedSubscriber_Handle_upserterError_propagates(t *testing.T) {
	boom := errors.New("db kaput")
	upsert := &fakeTenantMembershipUpserter{err: boom}
	sub := events.NewTenantBootstrappedSubscriber(upsert, idempotent.NewMemoryStore())

	err := sub.HandleTenantBootstrapped(context.Background(), sampleEnv(), samplePayload())
	if !errors.Is(err, boom) {
		t.Errorf("expected wrapped %v, got %v", boom, err)
	}
}

func TestTenantBootstrappedSubscriber_SubscribedTopics(t *testing.T) {
	upsert := &fakeTenantMembershipUpserter{}
	sub := events.NewTenantBootstrappedSubscriber(upsert, idempotent.NewMemoryStore())

	topics := sub.SubscribedTopics()
	if len(topics) != 1 {
		t.Fatalf("expected 1 topic, got %d", len(topics))
	}
	if topics[0] != "chora.tenancy.tenant.bootstrapped.v1" {
		t.Errorf("topic = %q", topics[0])
	}
}

func TestNewTenantBootstrappedSubscriber_nilUpserter_panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("nil upserter should panic — required dep")
		}
	}()
	events.NewTenantBootstrappedSubscriber(nil, idempotent.NewMemoryStore())
}

func TestNewTenantBootstrappedSubscriber_nilInbox_fallsBackToMemoryStore(t *testing.T) {
	upsert := &fakeTenantMembershipUpserter{}
	// nil inbox should not panic — should default to MemoryStore
	sub := events.NewTenantBootstrappedSubscriber(upsert, nil)
	if sub == nil {
		t.Fatal("expected non-nil subscriber")
	}
	// Sanity: a Handle call still works.
	if err := sub.HandleTenantBootstrapped(context.Background(), sampleEnv(), samplePayload()); err != nil {
		t.Errorf("Handle with nil inbox → MemoryStore: %v", err)
	}
}

func TestTenantBootstrappedSubscriber_WithInboxTTL_Fluent(t *testing.T) {
	sub := events.NewTenantBootstrappedSubscriber(&fakeTenantMembershipUpserter{}, nil)
	if sub == nil {
		t.Fatal("expected non-nil subscriber")
	}
	fluent := sub.WithInboxTTL(5 * time.Minute)
	if fluent != sub {
		t.Error("WithInboxTTL must return the same subscriber (fluent wiring)")
	}
	sub.WithInboxTTL(-1) // d<=0 keeps the TTL unchanged (no-op branch)
}

// TestTenantBootstrappedSubscriber_SyntheticIdempotencyKey drives the
// fallback dedupe key when the upstream forgot to mint an envelope
// idempotency_key ("tenant-bootstrapped:{tenant_id}").
func TestTenantBootstrappedSubscriber_SyntheticIdempotencyKey(t *testing.T) {
	upsert := &fakeTenantMembershipUpserter{}
	sub := events.NewTenantBootstrappedSubscriber(upsert, idempotent.NewMemoryStore())

	env := sampleEnv()
	env.IdempotencyKey = ""
	if err := sub.HandleTenantBootstrapped(context.Background(), env, samplePayload()); err != nil {
		t.Fatalf("HandleTenantBootstrapped: %v", err)
	}
	if upsert.calls != 1 {
		t.Errorf("upsert calls = %d, want 1", upsert.calls)
	}
}
