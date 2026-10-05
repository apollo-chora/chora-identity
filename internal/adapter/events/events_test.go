// Package events_test holds the RED-phase TDD specs for the in-process
// event publisher used by chora-identity (the Identity supporting/platform
// domain).
//
// Aligned with:
//   - chora-contracts/proto/common/envelope.proto — mandatory envelope fields
//   - .claude/rules/ddd-enforcement.md — "Event envelope mandatory fields"
//   - CLAUDE.md §6 — "Trace context across Pub/Sub" mandatory
//
// Topic taxonomy: chora.{domain}.{aggregate}.{event_type}.v{N}
//
// In-scope topics emitted by chora-identity:
//   - chora.identity.singpass.linked.v1 (this worktree, CHO-31)
//   - chora.identity.* future events (closure saga, etc — added incrementally)
package events_test

import (
	"testing"
	"time"

	"github.com/apollo-chora/chora-identity/internal/adapter/events"
)

const tenantA = "01970000-0000-7000-8000-0000000000aa"

func TestNewRecorder_Empty(t *testing.T) {
	t.Parallel()
	p := events.NewRecorder()
	if p == nil {
		t.Fatalf("expected non-nil recorder")
	}
	if got := len(p.Recorded()); got != 0 {
		t.Fatalf("expected empty recorder, got %d", got)
	}
}

func TestRecorder_Publish_PopulatesEnvelope(t *testing.T) {
	t.Parallel()
	p := events.NewRecorder()
	env := events.NewEnvelope(tenantA, "gcid-1", "00-aabb-ccdd-01", "")
	if err := p.Publish("chora.identity.singpass.linked.v1", env, map[string]any{
		"sub":      "S1234567A",
		"provider": "singpass",
	}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	all := p.Recorded()
	if len(all) != 1 {
		t.Fatalf("expected 1 record, got %d", len(all))
	}
	rec := all[0]
	if rec.Topic != "chora.identity.singpass.linked.v1" {
		t.Fatalf("topic = %q", rec.Topic)
	}
	if rec.Envelope.EventID == "" {
		t.Errorf("event_id empty")
	}
	if rec.Envelope.IdempotencyKey == "" {
		t.Errorf("idempotency_key empty")
	}
	if rec.Envelope.TenantID != tenantA {
		t.Errorf("tenant_id = %q", rec.Envelope.TenantID)
	}
	if rec.Envelope.GCID != "gcid-1" {
		t.Errorf("gcid = %q", rec.Envelope.GCID)
	}
	if rec.Envelope.Traceparent != "00-aabb-ccdd-01" {
		t.Errorf("traceparent = %q", rec.Envelope.Traceparent)
	}
	if rec.Envelope.SourceProject != "chora-local" {
		t.Errorf("source_project = %q", rec.Envelope.SourceProject)
	}
	if rec.Envelope.SourceService != "chora-identity" {
		t.Errorf("source_service = %q", rec.Envelope.SourceService)
	}
	if rec.Envelope.SchemaVersion != 1 {
		t.Errorf("schema_version = %d", rec.Envelope.SchemaVersion)
	}
	if rec.Envelope.OccurredAt.IsZero() || rec.Envelope.PublishedAt.IsZero() {
		t.Errorf("timestamps zero")
	}
}

func TestRecorder_Publish_RejectsEmptyTopic(t *testing.T) {
	t.Parallel()
	p := events.NewRecorder()
	env := events.NewEnvelope(tenantA, "gcid-1", "00-aabb", "")
	if err := p.Publish("", env, nil); err == nil {
		t.Fatalf("expected error for empty topic")
	}
}

func TestRecorder_Publish_RejectsMalformedTopic(t *testing.T) {
	t.Parallel()
	p := events.NewRecorder()
	env := events.NewEnvelope(tenantA, "gcid-1", "00-aabb", "")
	cases := []string{
		"chora.bogus.singpass.linked.v1", // wrong domain
		"chora.identity.singpass.linked", // missing version suffix
		"not.a.real.topic",
		"chora.identity",
	}
	for _, topic := range cases {
		if err := p.Publish(topic, env, nil); err == nil {
			t.Errorf("expected error for malformed topic %q", topic)
		}
	}
}

func TestRecorder_Publish_RejectsEnvelopeMissingMandatoryFields(t *testing.T) {
	t.Parallel()
	p := events.NewRecorder()
	// Missing tenant_id
	bad := events.NewEnvelope("", "gcid-1", "00-aabb", "")
	if err := p.Publish("chora.identity.singpass.linked.v1", bad, nil); err == nil {
		t.Errorf("expected error for empty tenant_id")
	}
	// Missing traceparent
	bad2 := events.NewEnvelope(tenantA, "gcid-1", "", "")
	if err := p.Publish("chora.identity.singpass.linked.v1", bad2, nil); err == nil {
		t.Errorf("expected error for empty traceparent (W3C trace context mandatory)")
	}
}

func TestRecorder_RecordedByTopic(t *testing.T) {
	t.Parallel()
	p := events.NewRecorder()
	env := events.NewEnvelope(tenantA, "gcid-1", "00-aabb", "")
	_ = p.Publish("chora.identity.singpass.linked.v1", env, nil)
	_ = p.Publish("chora.identity.singpass.linked.v1", env, nil)
	got := p.RecordedByTopic("chora.identity.singpass.linked.v1")
	if len(got) != 2 {
		t.Fatalf("expected 2 records, got %d", len(got))
	}
	if got := p.RecordedByTopic("chora.identity.other.event.v1"); len(got) != 0 {
		t.Fatalf("expected 0 records for other topic, got %d", len(got))
	}
}

func TestEnvelopeIDsAreUnique(t *testing.T) {
	t.Parallel()
	seen := make(map[string]struct{})
	for i := 0; i < 50; i++ {
		env := events.NewEnvelope(tenantA, "gcid-1", "00-aabb", "")
		if env.EventID == "" {
			t.Fatalf("event_id empty")
		}
		if _, dup := seen[env.EventID]; dup {
			t.Fatalf("duplicate event_id %q", env.EventID)
		}
		seen[env.EventID] = struct{}{}
		time.Sleep(time.Microsecond)
	}
}

// -----------------------------------------------------------------------------
// SingpassAdapter — wires the events.Recorder up to the singpass.Publisher port.
// -----------------------------------------------------------------------------

func TestSingpassAdapter_BridgesPort(t *testing.T) {
	t.Parallel()
	rec := events.NewRecorder()
	adapter := events.NewSingpassPublisher(rec)
	// Publish via the adapter using the singpass-shaped envelope.
	env := events.SingpassEnvelopeFor(tenantA, "gcid-1", "00-aabb-cc-01", "")
	if err := adapter.Publish("chora.identity.singpass.linked.v1", env, map[string]any{"sub": "S1234567A"}); err != nil {
		t.Fatalf("adapter.Publish: %v", err)
	}
	if got := len(rec.Recorded()); got != 1 {
		t.Fatalf("expected 1 record via bridge, got %d", got)
	}
}
