// Package events provides an envelope-conformant in-memory event publisher
// for the chora-identity service plus an adapter that bridges the singpass
// adapter's local Publisher port to a shared recorder.
//
// Aligned with:
//   - chora-contracts/proto/common/envelope.proto — mandatory envelope fields
//   - .claude/rules/ddd-enforcement.md — "Event envelope mandatory fields"
//   - CLAUDE.md §6 — "Trace context across Pub/Sub" mandatory
//
// Hexagonal note: ADAPTER. Domain code never imports this package; the HTTP
// handler / orchestrator injects a Publisher interface; tests inject the
// in-memory implementation; production injects the Pub/Sub adapter (M12).
//
// Topic taxonomy: chora.{domain}.{aggregate}.{event_type}.v{N}.
package events

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/apollo-chora/chora-identity/internal/adapter/idp/singpass"

	"github.com/apollo-chora/chora-common/env"
)

// SourceProject + SourceService for envelope provenance. chora-identity
// runs in chora-local (platform host).
const (
	SourceService = "chora-identity"
)

// SourceProject + SourceService for envelope provenance. chora-identity
// runs in chora-local (platform host).
//
// Was a hardcoded literal until 2026-09-02 (CHO-2419). No manifest could reach
// it, so a second org stamped every event with chora-local and any consumer
// filtering on source_project would have been filtering on a lie.
// CHORA_SOURCE_PROJECT is now set on every event-emitting service; the literal
// stays as the fallback so this estate is provably unchanged.
var SourceProject = env.GetOrDefault("CHORA_SOURCE_PROJECT", "chora-local")

// AllowedDomain is the primary second-segment for topics emitted by this
// service — sanity-check guard against typos at publish time.
const AllowedDomain = "identity"

// allowedDomains is the set of valid second-segments for topics this
// service may emit:
//   - identity   — domain-owned topics (kyc/role/passkey/federation/etc.)
//   - governance — IMDA evidence topics (chora.governance.evidence.recorded.v1)
//
// chora-governance is the canonical domain owner of governance topics, but
// per Tier 5 D17 + S3.6 P1.7 every domain may emit evidence into the shared
// governance topic.
var allowedDomains = map[string]struct{}{
	"identity":   {},
	"governance": {},
}

// Envelope mirrors the mandatory fields of chora.common.v1.EventEnvelope.
type Envelope struct {
	EventID        string    `json:"event_id"`
	IdempotencyKey string    `json:"idempotency_key"`
	TenantID       string    `json:"tenant_id"`
	GCID           string    `json:"gcid"`
	OccurredAt     time.Time `json:"occurred_at"`
	PublishedAt    time.Time `json:"published_at"`
	Traceparent    string    `json:"traceparent"`
	Tracestate     string    `json:"tracestate"`
	SourceProject  string    `json:"source_project"`
	SourceService  string    `json:"source_service"`
	SchemaVersion  int32     `json:"schema_version"`
}

// Record is a published envelope + topic + payload, kept for assertions.
type Record struct {
	Topic    string
	Envelope Envelope
	Payload  map[string]any
}

// Publisher is the port the orchestrator depends on.
type Publisher interface {
	Publish(topic string, env Envelope, payload map[string]any) error
}

// Recorder buffers published events into an internal slice. Thread-safe.
type Recorder struct {
	mu      sync.Mutex
	records []Record
}

// NewRecorder constructs an empty recorder.
func NewRecorder() *Recorder {
	return &Recorder{records: make([]Record, 0, 16)}
}

// Publish records an event after validating envelope + topic taxonomy.
func (r *Recorder) Publish(topic string, env Envelope, payload map[string]any) error {
	if err := validateTopic(topic); err != nil {
		return err
	}
	if err := validateEnvelope(env); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, Record{Topic: topic, Envelope: env, Payload: payload})
	return nil
}

// Recorded returns a defensive copy of all records.
func (r *Recorder) Recorded() []Record {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Record, len(r.records))
	copy(out, r.records)
	return out
}

// RecordedByTopic returns the records matching the given topic.
func (r *Recorder) RecordedByTopic(topic string) []Record {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Record, 0)
	for _, rec := range r.records {
		if rec.Topic == topic {
			out = append(out, rec)
		}
	}
	return out
}

// validateTopic enforces the chora.{domain}.{aggregate}.{event_type}.v{N}
// shape and locks domain to "identity" for this package.
func validateTopic(topic string) error {
	t := strings.TrimSpace(topic)
	if t == "" {
		return errors.New("events: topic required")
	}
	parts := strings.Split(t, ".")
	if len(parts) < 5 {
		return errors.New("events: topic must follow chora.{domain}.{aggregate}.{event_type}.v{N}")
	}
	if parts[0] != "chora" {
		return errors.New("events: topic must start with 'chora.'")
	}
	if _, ok := allowedDomains[parts[1]]; !ok {
		return errors.New("events: topic domain must be 'identity' or 'governance'")
	}
	last := parts[len(parts)-1]
	if !strings.HasPrefix(last, "v") || len(last) < 2 {
		return errors.New("events: topic must end with v{N} version suffix")
	}
	for _, ch := range last[1:] {
		if ch < '0' || ch > '9' {
			return errors.New("events: topic version suffix must be numeric")
		}
	}
	return nil
}

// validateEnvelope enforces the mandatory-field contract from
// envelope.proto + ddd-enforcement.md.
func validateEnvelope(env Envelope) error {
	if env.EventID == "" {
		return errors.New("events: envelope.event_id required")
	}
	if env.IdempotencyKey == "" {
		return errors.New("events: envelope.idempotency_key required")
	}
	if env.TenantID == "" {
		return errors.New("events: envelope.tenant_id required")
	}
	if env.OccurredAt.IsZero() {
		return errors.New("events: envelope.occurred_at required")
	}
	if env.PublishedAt.IsZero() {
		return errors.New("events: envelope.published_at required")
	}
	if env.Traceparent == "" {
		return errors.New("events: envelope.traceparent required (W3C trace context)")
	}
	if env.SourceProject == "" {
		return errors.New("events: envelope.source_project required")
	}
	if env.SourceService == "" {
		return errors.New("events: envelope.source_service required")
	}
	if env.SchemaVersion < 1 {
		return errors.New("events: envelope.schema_version >= 1 required")
	}
	return nil
}

// NewEnvelope mints a fresh Envelope with UUIDv7 event_id + populated
// provenance + timestamps. Caller supplies tenant_id, gcid, trace context.
func NewEnvelope(tenantID, gcid, traceparent, tracestate string) Envelope {
	now := time.Now().UTC()
	id := newUUIDv7()
	return Envelope{
		EventID:        id,
		IdempotencyKey: id,
		TenantID:       tenantID,
		GCID:           gcid,
		OccurredAt:     now,
		PublishedAt:    now,
		Traceparent:    traceparent,
		Tracestate:     tracestate,
		SourceProject:  SourceProject,
		SourceService:  SourceService,
		SchemaVersion:  1,
	}
}

// newUUIDv7 returns a freshly generated UUIDv7 string (RFC 9562 §5.7).
// Inline implementation keeps this adapter dependency-free.
func newUUIDv7() string {
	const buflen = 16
	var b [buflen]byte
	now := uint64(time.Now().UnixMilli())
	b[0] = byte(now >> 40)
	b[1] = byte(now >> 32)
	b[2] = byte(now >> 24)
	b[3] = byte(now >> 16)
	b[4] = byte(now >> 8)
	b[5] = byte(now)
	var randTail [10]byte
	_, _ = rand.Read(randTail[:])
	copy(b[6:], randTail[:])
	b[6] = (b[6] & 0x0f) | 0x70
	b[8] = (b[8] & 0x3f) | 0x80
	hexstr := hex.EncodeToString(b[:])
	return hexstr[0:8] + "-" + hexstr[8:12] + "-" + hexstr[12:16] + "-" + hexstr[16:20] + "-" + hexstr[20:32]
}

// -----------------------------------------------------------------------------
// SingpassAdapter — bridges singpass.Publisher port to events.Publisher.
// -----------------------------------------------------------------------------

// SingpassPublisher is a thin shim that satisfies the singpass.Publisher
// interface by translating the local singpass.EventEnvelope into the canonical
// events.Envelope and forwarding to the underlying Recorder/Publisher.
//
// This is the recommended wiring at the cmd/server entrypoint:
//
//	rec := events.NewRecorder()                       // or PubSubPublisher in M12
//	bridge := events.NewSingpassPublisher(rec)
//	singpass.New(singpass.Config{..., Publisher: bridge})
type SingpassPublisher struct {
	inner Publisher
}

// NewSingpassPublisher constructs the bridge.
func NewSingpassPublisher(inner Publisher) *SingpassPublisher {
	return &SingpassPublisher{inner: inner}
}

// Publish translates a singpass envelope and forwards.
func (s *SingpassPublisher) Publish(topic string, env singpass.EventEnvelope, payload map[string]any) error {
	return s.inner.Publish(topic, Envelope{
		EventID:        env.EventID,
		IdempotencyKey: env.IdempotencyKey,
		TenantID:       env.TenantID,
		GCID:           env.GCID,
		OccurredAt:     env.OccurredAt,
		PublishedAt:    env.PublishedAt,
		Traceparent:    env.Traceparent,
		Tracestate:     env.Tracestate,
		SourceProject:  env.SourceProject,
		SourceService:  env.SourceService,
		SchemaVersion:  env.SchemaVersion,
	}, payload)
}

// SingpassEnvelopeFor builds a singpass.EventEnvelope without invoking the
// singpass adapter — useful for callers that want to publish a singpass-shaped
// event directly through the bridge for tests or admin tooling.
func SingpassEnvelopeFor(tenantID, gcid, traceparent, tracestate string) singpass.EventEnvelope {
	now := time.Now().UTC()
	id := newUUIDv7()
	return singpass.EventEnvelope{
		EventID:        id,
		IdempotencyKey: id,
		TenantID:       tenantID,
		GCID:           gcid,
		OccurredAt:     now,
		PublishedAt:    now,
		Traceparent:    traceparent,
		Tracestate:     tracestate,
		SourceProject:  singpass.SourceProject,
		SourceService:  singpass.SourceService,
		SchemaVersion:  1,
	}
}
