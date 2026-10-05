// publisher_test.go — tenant_idp_provider_events adapter tests.
//
// The Publisher is a thin translator from the domain's PublishedEvent to an
// envelope-conformant events.Publish call on the canonical
// `chora.identity.tenant_idp_provider.configured.v1` topic. These tests
// lock the translation contract: W3C trace context (event-first, then
// constructor defaults), the idempotency/EventID coupling, and the payload
// shape (actor_gcid only when present).
package tenant_idp_provider_events

import (
	"context"
	"errors"
	"testing"

	"github.com/apollo-chora/chora-identity/internal/adapter/events"
	tip "github.com/apollo-chora/chora-identity/internal/domain/tenant_idp_provider"
)

const (
	tiTenantID  = "01970000-0000-7000-8000-00000000ee01"
	tiActorGCID = "01970000-0000-7000-8000-000000000001"
)

// failingPublisher is a Publisher that always returns the scripted error —
// used to assert the adapter propagates inner failures untouched.
type failingPublisher struct{ err error }

func (f *failingPublisher) Publish(topic string, env events.Envelope, payload map[string]any) error {
	return f.err
}

func TestPublisher_PublishesConfiguredEventWithTraceFromEvent(t *testing.T) {
	t.Parallel()
	rec := events.NewRecorder()
	p := NewPublisher(rec, "00-default-trace", "00-default-state")

	evt := tip.PublishedEvent{
		Topic:        "chora.identity.tenant_idp_provider.configured.v1",
		TenantID:     tiTenantID,
		ActorGCID:    tiActorGCID,
		Traceparent:  "00-event-trace",
		Tracestate:   "00-event-state",
		EventID:      "evt-id-1",
		EventType:    "configured",
		IdpID:        "idp-1",
		ProviderType: tip.ProviderOIDC,
	}
	if err := p.Publish(context.Background(), evt); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	got := rec.RecordedByTopic("chora.identity.tenant_idp_provider.configured.v1")
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1", len(got))
	}
	env := got[0].Envelope
	if env.Traceparent != "00-event-trace" {
		t.Errorf("traceparent = %q, want the event's value", env.Traceparent)
	}
	if env.Tracestate != "00-event-state" {
		t.Errorf("tracestate = %q, want the event's value", env.Tracestate)
	}
	if env.EventID != "evt-id-1" || env.IdempotencyKey != "evt-id-1" {
		t.Errorf("EventID/IdempotencyKey = %q/%q, want evt-id-1/evt-id-1 (coupled)", env.EventID, env.IdempotencyKey)
	}
	if got[0].Payload["event_type"] != "configured" {
		t.Errorf("payload event_type = %v, want configured", got[0].Payload["event_type"])
	}
	if got[0].Payload["idp_id"] != "idp-1" {
		t.Errorf("payload idp_id = %v, want idp-1", got[0].Payload["idp_id"])
	}
	if got[0].Payload["provider_type"] != "oidc" {
		t.Errorf("payload provider_type = %v, want oidc", got[0].Payload["provider_type"])
	}
	if got[0].Payload["actor_gcid"] != tiActorGCID {
		t.Errorf("payload actor_gcid = %v, want %s", got[0].Payload["actor_gcid"], tiActorGCID)
	}
}

func TestPublisher_FallsBackToConstructorTrace(t *testing.T) {
	t.Parallel()
	rec := events.NewRecorder()
	p := NewPublisher(rec, "00-default-trace", "00-default-state")

	evt := tip.PublishedEvent{
		Topic:        "chora.identity.tenant_idp_provider.configured.v1",
		TenantID:     tiTenantID,
		EventType:    "configured",
		IdpID:        "idp-2",
		ProviderType: tip.ProviderSAML,
	}
	if err := p.Publish(context.Background(), evt); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	got := rec.Recorded()
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1", len(got))
	}
	if got[0].Envelope.Traceparent != "00-default-trace" {
		t.Errorf("traceparent = %q, want constructor default", got[0].Envelope.Traceparent)
	}
	if got[0].Envelope.Tracestate != "00-default-state" {
		t.Errorf("tracestate = %q, want constructor default", got[0].Envelope.Tracestate)
	}
	// Empty actor_gcid must NOT appear in the payload.
	if _, present := got[0].Payload["actor_gcid"]; present {
		t.Errorf("actor_gcid present in payload %v, want omitted", got[0].Payload)
	}
}

func TestPublisher_CopiesEventIDIntoEnvelopeWhenResponseSet(t *testing.T) {
	t.Parallel()
	rec := events.NewRecorder()
	p := NewPublisher(rec, "00-fallback-trace", "00-fallback-state")

	evt := tip.PublishedEvent{
		Topic:        "chora.identity.tenant_idp_provider.configured.v1",
		TenantID:     tiTenantID,
		EventID:      "fixed-id",
		EventType:    "configured",
		ProviderType: tip.ProviderSingpass,
	}
	if err := p.Publish(context.Background(), evt); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	got := rec.Recorded()
	if got[0].Envelope.EventID != "fixed-id" {
		t.Errorf("Envelope.EventID = %q, want the publisher-supplied fixed-id", got[0].Envelope.EventID)
	}
	// NewEnvelope mints a fresh UUID when the caller supplies no EventID —
	// assert the default path still emits a non-empty envelope id.
	evtDefault := evt
	evtDefault.EventID = ""
	evtDefault.ProviderType = tip.ProviderOIDC
	if err := p.Publish(context.Background(), evtDefault); err != nil {
		t.Fatalf("Publish (default id): %v", err)
	}
	got = rec.Recorded()
	if len(got) != 2 {
		t.Fatalf("got %d records, want 2", len(got))
	}
	if got[1].Envelope.EventID == "" {
		t.Error("Envelope.EventID empty for default (fresh-UUID) path")
	}
}

func TestPublisher_PropagatesInnerError(t *testing.T) {
	t.Parallel()
	boom := errors.New("inner publish exploded")
	p := NewPublisher(&failingPublisher{err: boom}, "", "")
	err := p.Publish(context.Background(), tip.PublishedEvent{
		Topic:     "chora.identity.tenant_idp_provider.configured.v1",
		TenantID:  tiTenantID,
		EventType: "configured",
	})
	if !errors.Is(err, boom) {
		t.Fatalf("Publish error = %v, want the inner error to propagate untouched", err)
	}
}
