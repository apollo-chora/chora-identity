// Package tenant_idp_provider_events is the EventPublisher adapter for the
// Setup Wizard Phase C tenant identity-provider domain (CHO-1682).
//
// Wraps the existing internal/adapter/events.Publisher (outbox-backed
// Recorder) so the domain Service emits envelope-conformant events on
// the canonical topic `chora.identity.tenant_idp_provider.configured.v1`
// per the locked architecture's topic taxonomy.
//
// Hexagonal: ADAPTER. Implements tenant_idp_provider.EventPublisher;
// depends on events.Publisher + the domain only. The outbox concern
// (atomic enqueue inside the domain transaction) is the events.Publisher's
// job — this adapter is a thin translator from domain.PublishedEvent to
// events.Envelope + payload.
//
// Production wiring (cmd/server/main.go) injects an events.Publisher that
// writes to outbox_events in chora_identity (migrations/0005_outbox.sql);
// the existing Relay process forwards to Cloud Pub/Sub.
package tenant_idp_provider_events

import (
	"context"

	"github.com/apollo-chora/chora-identity/internal/adapter/events"
	tip "github.com/apollo-chora/chora-identity/internal/domain/tenant_idp_provider"
)

// Publisher implements tip.EventPublisher.
type Publisher struct {
	inner       events.Publisher
	traceparent string
	tracestate  string
}

// NewPublisher constructs an adapter bound to the given events.Publisher.
// `traceparent` + `tracestate` MUST be the W3C trace context the HTTP
// middleware extracted from the inbound request — callers wire a per-
// request adapter instance OR thread the values from ctx.
func NewPublisher(inner events.Publisher, traceparent, tracestate string) *Publisher {
	return &Publisher{inner: inner, traceparent: traceparent, tracestate: tracestate}
}

// Publish forwards the domain event to the inner publisher with a fully-
// populated envelope. W3C trace context is taken from the event itself
// when present (per-request value extracted by the HTTP handler); the
// constructor-time defaults are the fallback for non-HTTP callers.
func (p *Publisher) Publish(_ context.Context, evt tip.PublishedEvent) error {
	tp := evt.Traceparent
	if tp == "" {
		tp = p.traceparent
	}
	ts := evt.Tracestate
	if ts == "" {
		ts = p.tracestate
	}
	env := events.NewEnvelope(evt.TenantID, evt.ActorGCID, tp, ts)
	if evt.EventID != "" {
		env.EventID = evt.EventID
		env.IdempotencyKey = evt.EventID
	}
	payload := map[string]any{
		"event_type":    evt.EventType,
		"idp_id":        evt.IdpID,
		"tenant_id":     evt.TenantID,
		"provider_type": string(evt.ProviderType),
	}
	if evt.ActorGCID != "" {
		payload["actor_gcid"] = evt.ActorGCID
	}
	return p.inner.Publish(evt.Topic, env, payload)
}
