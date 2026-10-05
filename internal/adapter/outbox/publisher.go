// Package outbox — OutboxPublisher implementation.
//
// OutboxPublisher satisfies `events.Publisher` by writing the identity event
// to the outbox_events table instead of publishing directly to Pub/Sub.
// The Dispatcher (see dispatcher.go) drains the table to Cloud Pub/Sub on
// a separate goroutine. This decouples event emission from Pub/Sub
// availability — a crash between the domain state-change and Pub/Sub
// publish no longer loses events.
//
// The wire shape of the payload matches the existing
// `internal/adapter/events.CloudPublisher` payload (JSON marshalling of
// the `map[string]any` payload) so subscribers see identical bytes whether
// they receive from the legacy direct-publish path or the new outbox path.
// Migration is a constructor swap in main().
//
// Per `feedback_d6_resilience_first_class` B.6.2.a producer-side durable
// emission for chora-identity's `chora.identity.*.v1` + governance evidence
// streams.
package outbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/apollo-chora/chora-identity/internal/adapter/events"
	"github.com/apollo-chora/chora-identity/internal/adapter/events/protomarshal"
)

// defaultSchemaVersion is the default major version of the on-wire payload
// schema. Matches the v{N} suffix in the canonical topic names. Producers
// may override via events.Envelope.SchemaVersion.
const defaultSchemaVersion = int32(1)

// allowedDomains mirrors `internal/adapter/events.AllowedDomains` — chora-
// identity emits identity-owned topics + IMDA evidence into chora.governance.*
// per Tier 5 D17 + S3.6 P1.7. Kept duplicated here so the outbox publisher
// can validate without an internal-package import cycle.
var allowedDomains = map[string]struct{}{
	"identity":   {},
	"governance": {},
}

// PublisherConfig wires the OutboxPublisher.
type PublisherConfig struct {
	// Store is the outbox table backend. Required.
	Store Store

	// SourceProject is the project label the service runs in (e.g.
	// chora-local). Defaults to "chora-local".
	SourceProject string

	// SourceService is the publisher's service name. Defaults to
	// "chora-identity".
	SourceService string

	// Now is injectable for tests; defaults to time.Now().UTC.
	Now func() time.Time
}

// Publisher satisfies events.Publisher by enqueueing the event into
// outbox_events.
type Publisher struct {
	cfg PublisherConfig
}

// NewPublisher constructs an OutboxPublisher.
func NewPublisher(cfg PublisherConfig) *Publisher {
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	if cfg.SourceProject == "" {
		cfg.SourceProject = "chora-local"
	}
	if cfg.SourceService == "" {
		cfg.SourceService = "chora-identity"
	}
	return &Publisher{cfg: cfg}
}

// Publish satisfies events.Publisher. Writes the event as a pending row in
// outbox_events. The Dispatcher publishes to Pub/Sub asynchronously.
//
// The signature matches `internal/adapter/events.Publisher.Publish(topic,
// env, payload)` so call-sites (singpass adapter, kyc handler, blocking
// function, economy publisher, etc.) drop in unchanged.
func (p *Publisher) Publish(topic string, env events.Envelope, payload map[string]any) error {
	if p.cfg.Store == nil {
		return fmt.Errorf("outbox: store not wired")
	}
	row, err := p.buildRow(topic, env, payload)
	if err != nil {
		return err
	}
	return p.cfg.Store.Insert(context.Background(), row)
}

// buildRow validates the topic + envelope, applies the publisher config
// defaults, encodes the payload, and assembles the pending outbox Row. It is
// pure (touches no DB) so both Publish (Store-connection insert) and
// TxBoundPublisher (caller-transaction insert, see tx_publisher.go) share ONE
// row-shape — the on-wire bytes are identical whichever path enqueues them.
func (p *Publisher) buildRow(topic string, env events.Envelope, payload map[string]any) (Row, error) {
	if err := validateCanonicalTopic(topic); err != nil {
		return Row{}, err
	}

	now := p.cfg.Now()

	// Apply config defaults BEFORE envelope validation — chora-identity's
	// PublisherConfig stamps source_project + source_service when the
	// caller leaves them empty (mirrors how internal/adapter/events
	// builds envelopes via NewEnvelope which hardcodes SourceProject /
	// SourceService constants).
	if env.SourceProject == "" {
		env.SourceProject = p.cfg.SourceProject
	}
	if env.SourceService == "" {
		env.SourceService = p.cfg.SourceService
	}
	if env.SchemaVersion < 1 {
		env.SchemaVersion = defaultSchemaVersion
	}

	if err := validateEnvelope(env); err != nil {
		return Row{}, err
	}

	// Use the envelope's event_id; mint UUIDv7 if missing.
	eventID := env.EventID
	if eventID == "" {
		eventID = newUUIDv7()
	}
	idemKey := env.IdempotencyKey
	if idemKey == "" {
		idemKey = eventID
	}

	occurred := env.OccurredAt
	if occurred.IsZero() {
		occurred = now
	}
	publishedAt := env.PublishedAt
	if publishedAt.IsZero() {
		publishedAt = now
	}

	sourceProject := env.SourceProject
	sourceService := env.SourceService
	schemaVersion := env.SchemaVersion

	// Build the envelope as a flat string map for the JSONB column. This
	// is the on-wire attribute set published to Pub/Sub (subscribers can
	// filter without parsing the payload).
	envelope := map[string]string{
		"event_id":        eventID,
		"idempotency_key": idemKey,
		"tenant_id":       env.TenantID,
		"gcid":            env.GCID,
		"occurred_at":     occurred.UTC().Format(time.RFC3339Nano),
		"published_at":    publishedAt.UTC().Format(time.RFC3339Nano),
		"traceparent":     env.Traceparent,
		"tracestate":      env.Tracestate,
		"source_project":  sourceProject,
		"source_service":  sourceService,
		"schema_version":  strconv.Itoa(int(schemaVersion)),
	}

	body, err := encodeOutboxPayload(topic, env, payload)
	if err != nil {
		return Row{}, fmt.Errorf("outbox: marshal payload: %w", err)
	}

	// Derive aggregate_type + aggregate_id from the topic + envelope.
	aggregateType := deriveAggregateType(topic)
	aggregateID := env.GCID
	if aggregateID == "" {
		// Cross-tenant platform events use envelope.tenant_id="platform".
		// Fall back to event_id so every row has a non-empty aggregate_id.
		aggregateID = eventID
	}

	row := Row{
		ID:             eventID,
		TenantID:       env.TenantID,
		GCID:           env.GCID,
		AggregateType:  aggregateType,
		AggregateID:    aggregateID,
		EventType:      deriveEventType(topic),
		Topic:          topic,
		Payload:        body,
		Envelope:       envelope,
		IdempotencyKey: idemKey,
		OccurredAt:     occurred.UTC(),
	}
	return row, nil
}

// validateCanonicalTopic enforces `chora.{identity|governance}.{aggregate}.
// {event_type}.v{N}` at the publisher boundary. Legacy topic strings (e.g.
// `chora.iam.events`) MUST migrate to the canonical name before reaching
// this publisher; the outbox `topic` column therefore always holds canonical
// names.
func validateCanonicalTopic(topic string) error {
	t := strings.TrimSpace(topic)
	if t == "" {
		return errors.New("outbox: topic required")
	}
	parts := strings.Split(t, ".")
	if len(parts) < 5 {
		return fmt.Errorf("outbox: topic %q must follow chora.{identity|governance}.{aggregate}.{event_type}.v{N}", topic)
	}
	if parts[0] != "chora" {
		return fmt.Errorf("outbox: topic %q must start with 'chora.'", topic)
	}
	if _, ok := allowedDomains[parts[1]]; !ok {
		return fmt.Errorf("outbox: topic domain segment = %q; want 'identity' or 'governance' (legacy topics MUST migrate)", parts[1])
	}
	last := parts[len(parts)-1]
	if !strings.HasPrefix(last, "v") || len(last) < 2 {
		return fmt.Errorf("outbox: topic %q must end with v{N} version suffix", topic)
	}
	for _, ch := range last[1:] {
		if ch < '0' || ch > '9' {
			return fmt.Errorf("outbox: topic %q version suffix must be numeric", topic)
		}
	}
	return nil
}

// validateEnvelope mirrors the events package validateEnvelope but operates
// on the events.Envelope value directly. Keeps the outbox publisher
// dependency-flat: no import cycle on internal/adapter/events validation
// helpers (which are unexported).
func validateEnvelope(env events.Envelope) error {
	if env.EventID == "" {
		return errors.New("outbox: envelope.event_id required")
	}
	if env.IdempotencyKey == "" {
		return errors.New("outbox: envelope.idempotency_key required")
	}
	if env.TenantID == "" {
		return errors.New("outbox: envelope.tenant_id required")
	}
	if env.OccurredAt.IsZero() {
		return errors.New("outbox: envelope.occurred_at required")
	}
	if env.PublishedAt.IsZero() {
		return errors.New("outbox: envelope.published_at required")
	}
	if env.Traceparent == "" {
		return errors.New("outbox: envelope.traceparent required (W3C trace context)")
	}
	if env.SourceProject == "" {
		return errors.New("outbox: envelope.source_project required")
	}
	if env.SourceService == "" {
		return errors.New("outbox: envelope.source_service required")
	}
	if env.SchemaVersion < 1 {
		return errors.New("outbox: envelope.schema_version >= 1 required")
	}
	return nil
}

// deriveEventType extracts the `{aggregate}.{event_type}.v{N}` segment from
// a canonical topic past the `chora.{domain}.` prefix. e.g.
//
//	"chora.identity.user.created.v1" → "user.created.v1"
//
// Used as the indexable event_type column on the outbox row. Mirrors
// `internal/adapter/events.deriveEventType`.
func deriveEventType(topic string) string {
	parts := strings.SplitN(topic, ".", 3)
	if len(parts) < 3 {
		return topic
	}
	return parts[2]
}

// deriveAggregateType extracts the `{aggregate}` segment from a canonical
// topic. e.g.
//
//	"chora.identity.user.created.v1" → "user"
//	"chora.governance.evidence.recorded.v1" → "evidence"
//
// Falls back to "event" when the topic is malformed (validation runs
// before; this is a defensive default).
func deriveAggregateType(topic string) string {
	parts := strings.Split(topic, ".")
	if len(parts) < 3 {
		return "event"
	}
	return parts[2]
}

func newUUIDv7() string {
	return uuid.Must(uuid.NewV7()).String()
}

// Compile-time port assertion.
var _ events.Publisher = (*Publisher)(nil)

// -----------------------------------------------------------------------------
// Payload encoding — binary protobuf for Schema-Registry-attached topics, JSON
// fallback for topics that don't yet have a binary encoder.
//
// JSON fallback exists to preserve behaviour for chora.identity.* topics that
// pre-date the protomarshal package. Each unknown topic logs a one-time WARN
// so its missing encoder is visible in production. New topics MUST add a case
// in protomarshal.MarshalPayload.
// -----------------------------------------------------------------------------

var (
	outboxWarnedUnknownTopicsMu sync.Mutex
	outboxWarnedUnknownTopics   = map[string]bool{}
)

// toProtoEnvelope projects the local events.Envelope onto the encoder's flat
// envelope type. Keeps protomarshal import-cycle-free.
func toProtoEnvelope(env events.Envelope) protomarshal.Envelope {
	return protomarshal.Envelope{
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
	}
}

func encodeOutboxPayload(topic string, env events.Envelope, payload map[string]any) ([]byte, error) {
	bz, err := protomarshal.MarshalPayload(topic, toProtoEnvelope(env), payload)
	if err == nil {
		return bz, nil
	}
	if !protomarshal.IsUnsupportedTopic(err) {
		return nil, err
	}

	outboxWarnedUnknownTopicsMu.Lock()
	if !outboxWarnedUnknownTopics[topic] {
		outboxWarnedUnknownTopics[topic] = true
		log.Printf("WARN outbox: topic %q has no binary protobuf encoder — payload will JSON-marshal and Schema Registry will REJECT at publish; expect outbox_deadletter. Add a case to internal/adapter/events/protomarshal/MarshalPayload.", topic)
	}
	outboxWarnedUnknownTopicsMu.Unlock()

	bz, mErr := json.Marshal(payload)
	if mErr != nil {
		return nil, fmt.Errorf("outbox: json fallback marshal: %w", mErr)
	}
	return bz, nil
}
