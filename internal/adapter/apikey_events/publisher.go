// Package apikey_events is the EventPublisher adapter for the apikey domain.
//
// Wraps the existing internal/adapter/events.Publisher (the Recorder + future
// outbox-relay + Cloud Pub/Sub bridge) so the apikey service emits envelope-
// conformant events on the chora.identity.api_key.* topics per the locked
// architecture's topic taxonomy.
//
// Hexagonal: ADAPTER. Implements apikey.EventPublisher; depends on
// events.Publisher + domain/apikey only. The outbox concern (atomic enqueue
// inside the domain transaction) is the events.Publisher's job — this adapter
// is a thin translator from domain.PublishedEvent to events.Envelope + payload.
//
// Production wiring (cmd/server/main.go) injects an events.Publisher that
// writes to outbox_events in chora_identity (migrations/0005_outbox.sql); the
// existing Relay process forwards to Cloud Pub/Sub. The apikey service is
// therefore D6-resilience-compliant for free.
package apikey_events

import (
	"context"

	"github.com/apollo-chora/chora-identity/internal/adapter/events"
	"github.com/apollo-chora/chora-identity/internal/domain/apikey"
)

// Publisher implements apikey.EventPublisher.
type Publisher struct {
	inner       events.Publisher
	traceparent string
	tracestate  string
}

// NewPublisher constructs an adapter bound to the given events.Publisher
// (typically a Recorder in tests; outbox-backed in production).
//
// `traceparent` + `tracestate` are the W3C trace context to stamp on the
// envelope. Callers MUST propagate the inbound request's traceparent here —
// the HTTPMiddleware extracts it from the request and stores it on the request
// context; the caller wires a per-request adapter instance OR passes the value
// from ctx.Value(...).
func NewPublisher(inner events.Publisher, traceparent, tracestate string) *Publisher {
	return &Publisher{inner: inner, traceparent: traceparent, tracestate: tracestate}
}

// Publish forwards the domain event to the inner publisher with a fully-
// populated envelope.
func (p *Publisher) Publish(_ context.Context, evt apikey.PublishedEvent) error {
	env := events.NewEnvelope(evt.TenantID, evt.Gcid, p.traceparent, p.tracestate)
	// Use the domain-supplied event_id so callers' idempotency lines up with
	// the API key aggregate's UUIDv7.
	if evt.EventID != "" {
		env.EventID = evt.EventID
		env.IdempotencyKey = evt.EventID
	}
	payload := map[string]any{
		"event_type": evt.EventType,
		"api_key_id": evt.APIKeyID,
		"gcid":       evt.Gcid,
		"tenant_id":  evt.TenantID,
	}
	if evt.Name != "" {
		payload["name"] = evt.Name
	}
	if len(evt.Scopes) > 0 {
		payload["scopes"] = evt.Scopes
	}
	return p.inner.Publish(evt.Topic, env, payload)
}
