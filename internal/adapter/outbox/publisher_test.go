// Package outbox_test — OutboxPublisher adapter tests.
//
// OutboxPublisher satisfies events.Publisher by writing the identity event
// to the outbox_events table (via the Store port) instead of publishing
// directly to Pub/Sub. A separate Dispatcher drains the outbox to Cloud
// Pub/Sub. This decouples identity event emission from Pub/Sub
// availability: a crash between domain state-write and Pub/Sub publish no
// longer loses events because the row is durably committed to
// chora_identity before the HTTP request returns.
//
// Per `feedback_d6_resilience_first_class` B.6.2.a — producer-side durable
// emission for chora-identity's `chora.identity.*.v1` + governance evidence
// streams. Composes with the LangGraph PostgresSaver pattern used by the
// closure saga + AI Kernel orchestrator.
package outbox_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/apollo-chora/chora-identity/internal/adapter/events"
	"github.com/apollo-chora/chora-identity/internal/adapter/outbox"
)

func userCreatedEnvelope(t *testing.T) (events.Envelope, map[string]any) {
	t.Helper()
	now := time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC)
	env := events.Envelope{
		EventID:        "01970000-0000-7000-8000-000000000001",
		IdempotencyKey: "01970000-0000-7000-8000-000000000001",
		TenantID:       "22222222-2222-7222-8222-222222222222",
		GCID:           "00000000-0000-7000-8000-000000001002",
		OccurredAt:     now,
		PublishedAt:    now,
		Traceparent:    "00-0af7651916cd43dd8448eb211c80319c-b9c7c989f97918e1-01",
		SourceProject:  "chora-local",
		SourceService:  "chora-identity",
		SchemaVersion:  1,
	}
	payload := map[string]any{
		"user_id":   "00000000-0000-7000-8000-0000000050e1",
		"gcid":      env.GCID,
		"email":     "phyllis@chora.site",
		"tenant_id": env.TenantID,
	}
	return env, payload
}

func TestOutboxPublisher_Publish_WritesRowToStore(t *testing.T) {
	t.Parallel()
	store := outbox.NewInMemoryStore()
	pub := outbox.NewPublisher(outbox.PublisherConfig{
		Store:         store,
		SourceProject: "chora-local",
		SourceService: "chora-identity",
	})

	env, payload := userCreatedEnvelope(t)
	if err := pub.Publish("chora.identity.user.created.v1", env, payload); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	rows, _ := store.FetchPending(context.Background(), 10)
	if len(rows) != 1 {
		t.Fatalf("store rows = %d; want 1", len(rows))
	}
	row := rows[0]
	if row.Topic != "chora.identity.user.created.v1" {
		t.Errorf("row.Topic = %q; want chora.identity.user.created.v1", row.Topic)
	}
	if row.TenantID != env.TenantID {
		t.Errorf("row.TenantID = %q; want %q", row.TenantID, env.TenantID)
	}
	if row.GCID != env.GCID {
		t.Errorf("row.GCID = %q; want %q", row.GCID, env.GCID)
	}
	if row.IdempotencyKey != env.IdempotencyKey {
		t.Errorf("row.IdempotencyKey = %q; want %q", row.IdempotencyKey, env.IdempotencyKey)
	}
	// EventType is the canonical chora.{domain}.{aggregate}.{event_type} suffix
	// past the chora.{domain}. prefix — but per chora-identity events.deriveEventType
	// the suffix includes the v{N} segment for cross-domain registry alignment.
	if row.EventType == "" {
		t.Errorf("row.EventType empty; want event-type derived from topic")
	}
}

func TestOutboxPublisher_Publish_StampsEnvelopeFields(t *testing.T) {
	t.Parallel()
	store := outbox.NewInMemoryStore()
	now := time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC)
	pub := outbox.NewPublisher(outbox.PublisherConfig{
		Store:         store,
		SourceProject: "chora-local",
		SourceService: "chora-identity",
		Now:           func() time.Time { return now },
	})
	env, payload := userCreatedEnvelope(t)
	if err := pub.Publish("chora.identity.user.created.v1", env, payload); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	rows, _ := store.FetchPending(context.Background(), 1)
	if len(rows) != 1 {
		t.Fatalf("rows = %d; want 1", len(rows))
	}
	rowEnv := rows[0].Envelope

	for _, key := range []string{
		"event_id", "idempotency_key", "tenant_id", "occurred_at", "published_at",
		"traceparent", "source_project", "source_service", "schema_version",
	} {
		if rowEnv[key] == "" {
			t.Errorf("envelope.%s empty; want non-empty (mandatory per CLAUDE.md §6)", key)
		}
	}
	if rowEnv["source_project"] != "chora-local" {
		t.Errorf("envelope.source_project = %q; want chora-local", rowEnv["source_project"])
	}
	if rowEnv["source_service"] != "chora-identity" {
		t.Errorf("envelope.source_service = %q; want chora-identity", rowEnv["source_service"])
	}
	if rowEnv["schema_version"] != "1" {
		t.Errorf("envelope.schema_version = %q; want 1", rowEnv["schema_version"])
	}
	if rowEnv["tenant_id"] != env.TenantID {
		t.Errorf("envelope.tenant_id = %q; want %q", rowEnv["tenant_id"], env.TenantID)
	}
	if rowEnv["idempotency_key"] != env.IdempotencyKey {
		t.Errorf("envelope.idempotency_key = %q; want %q", rowEnv["idempotency_key"], env.IdempotencyKey)
	}
}

func TestOutboxPublisher_Publish_RejectsNilStore(t *testing.T) {
	t.Parallel()
	pub := outbox.NewPublisher(outbox.PublisherConfig{})
	env, payload := userCreatedEnvelope(t)
	err := pub.Publish("chora.identity.user.created.v1", env, payload)
	if err == nil {
		t.Errorf("Publish without store = nil err; want error")
	}
}

func TestOutboxPublisher_Publish_RejectsInvalidTopic(t *testing.T) {
	t.Parallel()
	store := outbox.NewInMemoryStore()
	pub := outbox.NewPublisher(outbox.PublisherConfig{Store: store})
	env, payload := userCreatedEnvelope(t)
	// Legacy / non-canonical topic name.
	err := pub.Publish("chora.iam.events", env, payload)
	if err == nil {
		t.Errorf("Publish with legacy topic err = nil; want error")
	}
}

func TestOutboxPublisher_Publish_RejectsCrossDomainTopic(t *testing.T) {
	t.Parallel()
	store := outbox.NewInMemoryStore()
	pub := outbox.NewPublisher(outbox.PublisherConfig{Store: store})
	env, payload := userCreatedEnvelope(t)
	// Cross-domain — chora-identity emits identity.* + governance.* per
	// events.AllowedDomains; tenancy is not allowed.
	err := pub.Publish("chora.tenancy.user.created.v1", env, payload)
	if err == nil {
		t.Errorf("Publish with cross-domain (tenancy) topic = nil err; want error")
	}
}

func TestOutboxPublisher_Publish_AllowsGovernanceTopic(t *testing.T) {
	t.Parallel()
	store := outbox.NewInMemoryStore()
	pub := outbox.NewPublisher(outbox.PublisherConfig{Store: store})
	env, payload := userCreatedEnvelope(t)
	// chora-identity emits IMDA evidence into chora.governance.* per Tier 5
	// D17 + S3.6 P1.7 — see internal/adapter/events.AllowedDomains.
	if err := pub.Publish("chora.governance.evidence.recorded.v1", env, payload); err != nil {
		t.Errorf("Publish governance topic failed: %v", err)
	}
}

func TestOutboxPublisher_Publish_PayloadIsJSONOfMap(t *testing.T) {
	t.Parallel()
	store := outbox.NewInMemoryStore()
	pub := outbox.NewPublisher(outbox.PublisherConfig{Store: store, SourceProject: "chora-local"})
	env, payload := userCreatedEnvelope(t)
	if err := pub.Publish("chora.identity.user.created.v1", env, payload); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	rows, _ := store.FetchPending(context.Background(), 1)
	if len(rows) != 1 {
		t.Fatalf("rows = %d; want 1", len(rows))
	}
	var pl map[string]any
	if err := json.Unmarshal(rows[0].Payload, &pl); err != nil {
		t.Fatalf("payload not JSON: %v (%s)", err, string(rows[0].Payload))
	}
	if pl["user_id"] != payload["user_id"] {
		t.Errorf("payload.user_id = %v; want %v", pl["user_id"], payload["user_id"])
	}
	if pl["email"] != payload["email"] {
		t.Errorf("payload.email = %v; want %v", pl["email"], payload["email"])
	}
}

func TestOutboxPublisher_Publish_DuplicateIdempotencyKeyError(t *testing.T) {
	t.Parallel()
	store := outbox.NewInMemoryStore()
	pub := outbox.NewPublisher(outbox.PublisherConfig{Store: store, SourceProject: "chora-local"})
	env, payload := userCreatedEnvelope(t)
	if err := pub.Publish("chora.identity.user.created.v1", env, payload); err != nil {
		t.Fatalf("Publish 1: %v", err)
	}
	// Re-publish same envelope → store rejects duplicate idempotency_key.
	err := pub.Publish("chora.identity.user.created.v1", env, payload)
	if err == nil {
		t.Errorf("expected duplicate idempotency_key rejection on second Publish")
	}
	if !errors.Is(err, outbox.ErrDuplicateIdempotencyKey) {
		t.Errorf("err = %v; want ErrDuplicateIdempotencyKey", err)
	}
}

func TestOutboxPublisher_Publish_DefaultsSourceProjectAndService(t *testing.T) {
	t.Parallel()
	store := outbox.NewInMemoryStore()
	pub := outbox.NewPublisher(outbox.PublisherConfig{Store: store}) // no project/service
	env, payload := userCreatedEnvelope(t)
	env.SourceProject = ""
	env.SourceService = ""
	if err := pub.Publish("chora.identity.user.created.v1", env, payload); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	rows, _ := store.FetchPending(context.Background(), 1)
	if rows[0].Envelope["source_project"] != "chora-local" {
		t.Errorf("default source_project = %q; want chora-local", rows[0].Envelope["source_project"])
	}
	if rows[0].Envelope["source_service"] != "chora-identity" {
		t.Errorf("default source_service = %q; want chora-identity", rows[0].Envelope["source_service"])
	}
}

func TestOutboxPublisher_Publish_RejectsInvalidEnvelope(t *testing.T) {
	t.Parallel()
	store := outbox.NewInMemoryStore()
	pub := outbox.NewPublisher(outbox.PublisherConfig{Store: store, SourceProject: "chora-local"})
	// Empty tenant_id is mandatory per envelope.proto; should reject.
	env := events.Envelope{
		EventID:        "01970000-0000-7000-8000-000000000099",
		IdempotencyKey: "01970000-0000-7000-8000-000000000099",
		OccurredAt:     time.Now().UTC(),
		PublishedAt:    time.Now().UTC(),
		Traceparent:    "00-0af7651916cd43dd8448eb211c80319c-b9c7c989f97918e1-01",
		SourceProject:  "chora-local",
		SourceService:  "chora-identity",
		SchemaVersion:  1,
		// TenantID missing
	}
	err := pub.Publish("chora.identity.user.created.v1", env, map[string]any{})
	if err == nil {
		t.Errorf("Publish without tenant_id = nil; want error")
	}
}

// Compile-time check that OutboxPublisher satisfies events.Publisher.
var _ events.Publisher = (*outbox.Publisher)(nil)
