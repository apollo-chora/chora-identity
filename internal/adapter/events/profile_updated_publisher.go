// profile_updated_publisher.go — typed wrapper for the
// chora.identity.user.profile_updated.v1 event (Q3 GCID→display-name
// projection).
//
// Why: chora-identity is the sole owner of the (gcid → display_name)
// mapping, but every other domain needs a human-readable name for a gcid
// (rosters, feeds, leaderboards, …). Cross-DB reads are forbidden, so
// identity emits this event whenever a user's display name is SET or CHANGED;
// downstream domains (chora-delivery first) project it into a local
// gcid→display-name directory keyed by the GLOBAL gcid.
//
// Wire shape: the topic is SCHEMALESS — identity's outbox JSON-marshals the
// payload (no Pub/Sub Schema Registry binary schema). The payload is EXACTLY
// {gcid, display_name, email, updated_at}; the mandatory chora event envelope
// rides as the outbox row's envelope attribute set (source_service=
// chora-identity, schema_version=1, …).
//
// This publisher mirrors gcid_resolved_publisher.go one-for-one: it builds the
// envelope + payload from a native event struct and forwards to the injected
// events.Publisher port. In production that inner Publisher is the outbox
// tx-bound publisher (same DB tx as the users UPDATE — true transactional
// outbox); in tests it is the in-memory Recorder.
package events

import (
	"context"
	"errors"
	"strings"
	"time"
)

// TopicProfileUpdated is the canonical Pub/Sub topic for the event.
// Aligned with the chora.{domain}.{aggregate}.{event_type}.v{N} taxonomy:
// domain=identity, aggregate=user, event_type=profile_updated, v1.
const TopicProfileUpdated = "chora.identity.user.profile_updated.v1"

// updatedAtLayout renders updated_at as a FIXED-WIDTH nanosecond RFC3339 UTC
// timestamp. It is valid/parseable RFC3339 AND lexicographically monotonic, so
// the consumer's last-writer-wins ordering is correct whether it parses the
// value or compares it as a string. (time.RFC3339Nano trims trailing zeros →
// variable width → unsafe for a naive string comparison.)
const updatedAtLayout = "2006-01-02T15:04:05.000000000Z"

// ProfileUpdatedEvent is the events-package-native shape carried into the
// publisher. TenantID is the acting/provenance tenant (the consumer keys its
// directory by the global gcid and ignores tenant_id); it MUST be non-empty
// to satisfy the mandatory envelope contract.
type ProfileUpdatedEvent struct {
	Gcid        string
	DisplayName string
	Email       string
	TenantID    string
	UpdatedAt   time.Time
}

// ProfileUpdatedPublisher emits chora.identity.user.profile_updated.v1 events.
type ProfileUpdatedPublisher struct {
	inner Publisher
}

// NewProfileUpdatedPublisher constructs the typed publisher around the supplied
// generic events.Publisher (outbox tx-bound in prod, Recorder in tests).
func NewProfileUpdatedPublisher(inner Publisher) *ProfileUpdatedPublisher {
	return &ProfileUpdatedPublisher{inner: inner}
}

// PublishProfileUpdated emits chora.identity.user.profile_updated.v1.
//
// The caller (pg.UserRepository.UpdateDisplayName / the create path) owns the
// changed-vs-unchanged decision; this publisher unconditionally emits a
// non-empty-name projection. display_name MUST be non-empty — an empty name is
// the resolve-time "nothing to project" state and is refused loud.
func (p *ProfileUpdatedPublisher) PublishProfileUpdated(ctx context.Context, ev ProfileUpdatedEvent) error {
	if p == nil || p.inner == nil {
		return errors.New("events: ProfileUpdatedPublisher not initialised")
	}
	if ev.Gcid == "" {
		return errors.New("events: gcid required for user.profile_updated.v1")
	}
	if strings.TrimSpace(ev.DisplayName) == "" {
		return errors.New("events: display_name required for user.profile_updated.v1 (empty name = nothing to project)")
	}
	if strings.TrimSpace(ev.TenantID) == "" {
		// The mandatory-envelope contract requires a non-empty tenant_id, and
		// the delivery consumer fail-louds / DLQs on an empty tenant_id
		// attribute. Refuse at the source (before building the envelope) so an
		// empty acting-tenant surfaces here — not as a silent dead-letter.
		return errors.New("events: tenant_id required for user.profile_updated.v1 (acting-tenant provenance; consumer rejects empty)")
	}

	// W3C traceparent from the active OTel span; placeholder when uninstrumented
	// so the envelope validator (non-empty traceparent) accepts the event.
	traceparent := w3cTraceparentFromContext(ctx)

	env := NewEnvelope(ev.TenantID, ev.Gcid, traceparent, "" /*tracestate*/)

	updatedAt := ev.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = env.OccurredAt
	}

	payload := map[string]any{
		"gcid":         ev.Gcid,
		"display_name": ev.DisplayName,
		"email":        ev.Email,
		"updated_at":   updatedAt.UTC().Format(updatedAtLayout),
	}
	return p.inner.Publish(TopicProfileUpdated, env, payload)
}
