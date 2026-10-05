// gcid_resolved_publisher.go — typed wrapper for the
// chora.identity.gcid.resolved.v1 event emitted by the resolve handler
// (Bucket 2, 2026-05-14 multi-tenant identity).
//
// Why: chora-identity's POST /v1/identity/resolve handler MUST emit an
// audit-trail event each time a ID-token-validated identity gets resolved
// to a GCID + tenant set. That event flows via the canonical events
// Publisher port (Recorder in dev, outbox-backed CloudPublisher in prod)
// so it picks up the same DLQ + retry + idempotency guarantees as every
// other chora-identity event.
//
// Idempotency: the caller supplies an idempotency_key derived from
// sha256(email+firebase_uid) so downstream subscribers can dedupe on
// retry without coordination.
//
// WIRE-COMPAT (history): `firebase_uid` is a RETAINED legacy field name from
// the pre-migration chora-contracts GcidResolved proto (field 5). The value is
// the generic federated subject; the name is kept so existing proto consumers
// keep decoding. It carries no Google Cloud import.
//
// Out-of-scope (M14+): a subscriber consuming this event is the
// M14 BLANKET consumer work. For now we just publish.
//
// Hexagonal note: the publisher MUST NOT import the http adapter
// (otherwise we induce a cycle, since http adapter already imports
// events for the blocking-function handler). The resolve-handler-native
// EmittedEvent shape lives in the http adapter; the binding from
// http.EmittedEvent → this publisher's GCIDResolvedEvent happens in
// cmd/server/main.go (no cycle).
package events

import (
	"context"
	"errors"

	"go.opentelemetry.io/otel/trace"
)

// TopicGCIDResolved is the canonical Pub/Sub topic for the event.
// Aligned with the chora.{domain}.{aggregate}.{event_type}.v{N} taxonomy.
const TopicGCIDResolved = "chora.identity.gcid.resolved.v1"

// GCIDResolvedEvent is the events-package-native shape. Mirrors the
// httpadapter.EmittedEvent fields one-for-one so cmd/server/main.go can
// adapt between them with a trivial struct-copy.
type GCIDResolvedEvent struct {
	GCID             string
	TenantID         string
	Email            string
	FirebaseUID      string
	IdempotencyKey   string
	MembershipsCount int
}

// GCIDResolvedPublisher emits chora.identity.gcid.resolved.v1 events.
type GCIDResolvedPublisher struct {
	inner Publisher
}

// NewGCIDResolvedPublisher constructs the typed publisher around the
// supplied generic events.Publisher (outbox-backed in prod, Recorder in
// tests + dev).
func NewGCIDResolvedPublisher(inner Publisher) *GCIDResolvedPublisher {
	return &GCIDResolvedPublisher{inner: inner}
}

// PublishGCIDResolved emits chora.identity.gcid.resolved.v1.
func (p *GCIDResolvedPublisher) PublishGCIDResolved(ctx context.Context, ev GCIDResolvedEvent) error {
	if p == nil || p.inner == nil {
		return errors.New("events: GCIDResolvedPublisher not initialised")
	}
	if ev.GCID == "" {
		return errors.New("events: GCID required for gcid.resolved.v1")
	}
	if ev.IdempotencyKey == "" {
		return errors.New("events: IdempotencyKey required for gcid.resolved.v1")
	}

	// W3C traceparent extraction from the active OTel span when available.
	// Falls back to a synthesised placeholder so the envelope validator
	// accepts the event even outside OTLP-instrumented call paths (tests
	// + cold-start dev mode).
	traceparent := w3cTraceparentFromContext(ctx)

	env := NewEnvelope(ev.TenantID, ev.GCID, traceparent, "" /*tracestate*/)
	env.IdempotencyKey = ev.IdempotencyKey

	payload := map[string]any{
		"gcid":              ev.GCID,
		"tenant_id":         ev.TenantID,
		"email":             ev.Email,
		"firebase_uid":      ev.FirebaseUID,
		"memberships_count": ev.MembershipsCount,
	}
	return p.inner.Publish(TopicGCIDResolved, env, payload)
}

// w3cTraceparentFromContext extracts the W3C traceparent header from the
// active OTel span in ctx. Returns a placeholder "00-...-..." string when
// no span is active so the envelope validator (which requires non-empty
// traceparent) accepts the event.
//
// Format: `00-{trace_id_32_hex}-{span_id_16_hex}-{flags_2_hex}`.
// Per W3C Trace Context spec.
func w3cTraceparentFromContext(ctx context.Context) string {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		// Synthesised placeholder — keeps the validator happy when the
		// caller isn't running under OTel.
		return "00-00000000000000000000000000000000-0000000000000000-00"
	}
	flags := "00"
	if sc.IsSampled() {
		flags = "01"
	}
	return "00-" + sc.TraceID().String() + "-" + sc.SpanID().String() + "-" + flags
}
