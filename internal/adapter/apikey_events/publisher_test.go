package apikey_events

import (
	"context"
	"strings"
	"testing"

	"github.com/apollo-chora/chora-identity/internal/adapter/events"
	"github.com/apollo-chora/chora-identity/internal/domain/apikey"
)

func TestPublisher_Publish_Created_TopicEnvelope(t *testing.T) {
	t.Parallel()
	rec := events.NewRecorder()
	pub := NewPublisher(rec, "00-00000000000000000000000000000000-0000000000000000-01", "")

	if err := pub.Publish(context.Background(), apikey.PublishedEvent{
		Topic:     apikey.TopicCreated,
		TenantID:  "01970000-0000-7000-8000-000000000001",
		Gcid:      "01975555-0000-7000-8000-000000000001",
		EventID:   "01975555-0000-7000-9000-000000000001",
		EventType: apikey.EventCreated,
		APIKeyID:  "01975555-0000-7000-9000-000000000001",
		Name:      "Test Key",
		Scopes:    []string{"read"},
	}); err != nil {
		t.Fatalf("publish: %v", err)
	}
	got := rec.RecordedByTopic(apikey.TopicCreated)
	if len(got) != 1 {
		t.Fatalf("expected 1 record on %q; got %d", apikey.TopicCreated, len(got))
	}
	r := got[0]
	if r.Envelope.TenantID == "" {
		t.Fatalf("envelope.tenant_id empty")
	}
	if r.Envelope.GCID == "" {
		t.Fatalf("envelope.gcid empty")
	}
	if r.Envelope.EventID == "" {
		t.Fatalf("envelope.event_id empty")
	}
	if r.Envelope.Traceparent == "" {
		t.Fatalf("envelope.traceparent empty (mandatory per ddd-enforcement)")
	}
	if r.Envelope.SourceService != "chora-identity" {
		t.Fatalf("envelope.source_service = %q; want chora-identity", r.Envelope.SourceService)
	}
	if r.Envelope.SchemaVersion != 1 {
		t.Fatalf("envelope.schema_version = %d; want 1", r.Envelope.SchemaVersion)
	}
	// Payload carries event_type + api_key fields.
	if r.Payload["event_type"] != apikey.EventCreated {
		t.Fatalf("payload.event_type = %v; want %q", r.Payload["event_type"], apikey.EventCreated)
	}
	if r.Payload["name"] != "Test Key" {
		t.Fatalf("payload.name = %v", r.Payload["name"])
	}
}

func TestPublisher_Publish_Revoked(t *testing.T) {
	t.Parallel()
	rec := events.NewRecorder()
	pub := NewPublisher(rec, "00-00000000000000000000000000000000-0000000000000000-01", "")

	if err := pub.Publish(context.Background(), apikey.PublishedEvent{
		Topic:     apikey.TopicRevoked,
		TenantID:  "01970000-0000-7000-8000-000000000001",
		Gcid:      "01975555-0000-7000-8000-000000000001",
		EventID:   "01975555-0000-7000-9000-000000000099",
		EventType: apikey.EventRevoked,
		APIKeyID:  "01975555-0000-7000-9000-000000000001",
	}); err != nil {
		t.Fatalf("publish: %v", err)
	}
	got := rec.RecordedByTopic(apikey.TopicRevoked)
	if len(got) != 1 {
		t.Fatalf("expected 1 record")
	}
	if got[0].Payload["event_type"] != apikey.EventRevoked {
		t.Fatalf("payload.event_type mismatch")
	}
}

func TestPublisher_Publish_RejectsUnknownTopic(t *testing.T) {
	t.Parallel()
	rec := events.NewRecorder()
	pub := NewPublisher(rec, "00-00000000000000000000000000000000-0000000000000000-01", "")

	err := pub.Publish(context.Background(), apikey.PublishedEvent{
		Topic:     "chora.iam.events", // legacy topic — must be rejected
		TenantID:  "t",
		Gcid:      "g",
		EventID:   "e",
		EventType: "x",
	})
	if err == nil {
		t.Fatalf("expected error on unknown topic")
	}
	if !strings.Contains(err.Error(), "topic") && !strings.Contains(err.Error(), "domain") {
		t.Fatalf("expected topic-shape error; got %v", err)
	}
}
