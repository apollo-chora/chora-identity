// cloud_publisher.go — production drop-in replacement for events.Recorder.
//
// CloudPublisher satisfies the local events.Publisher port and atomically
// writes events to the chora_identity outbox_events table via the shared
// chora-go-common/outbox.Recorder. A separate Relay process drains
// pending rows to Cloud Pub/Sub.
//
// Why an outbox + Relay (vs direct publish)?
//
//   - Atomic: domain state-change + event-publish in ONE transaction.
//     A network failure mid-publish never leaves orphan state nor orphan
//     events.
//   - Resilient: dead pods leave outbox rows pending; replacement pods
//     pick up via the SKIP-LOCKED claim contract.
//   - Auditable: every emitted event has a durable row in chora_identity
//     before the wire-publish, with retry telemetry.
//
// The relay daemon lives in cmd/relay/ (M14+); this adapter is the
// publisher half.
package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	cgcenvelope "github.com/apollo-chora/chora-common/envelope"
	cgcoutbox "github.com/apollo-chora/chora-common/outbox"

	"github.com/apollo-chora/chora-identity/internal/adapter/events/protomarshal"
)

// CloudPublisherConfig tunes a CloudPublisher.
type CloudPublisherConfig struct {
	// AggregateType labels every outbox row this publisher emits. Must
	// match the aggregate the events come from (e.g. "user", "membership").
	AggregateType string
}

// CloudPublisher writes events to the chora-go-common outbox recorder.
// It satisfies the local events.Publisher port so existing call sites
// (kyc handler, blocking function, singpass adapter) drop in unchanged.
type CloudPublisher struct {
	rec cgcoutbox.Recorder
	cfg CloudPublisherConfig
}

// NewCloudPublisher constructs a CloudPublisher.
func NewCloudPublisher(rec cgcoutbox.Recorder, cfg CloudPublisherConfig) *CloudPublisher {
	if cfg.AggregateType == "" {
		cfg.AggregateType = "user"
	}
	return &CloudPublisher{rec: rec, cfg: cfg}
}

// Publish satisfies events.Publisher. Validates topic + envelope (via the
// existing local rules), marshals the payload to canonical binary protobuf
// wire format, and writes an outbox row.
//
// Per `feedback_resilience_priority`: this is intentionally OUTBOX-FIRST.
// Direct publish at the call site is a footgun — under partial failure
// the caller can never know whether the event was committed or not.
//
// Producer-side encoding: emit canonical binary protobuf for topics whose
// Pub/Sub Schema Registry schema is BINARY-encoded. JSON payloads on a
// schema-attached topic dead-letter forever with "Invalid binary proto
// message". Per the gap surfaced 2026-05-15 (task #33).
func (p *CloudPublisher) Publish(topic string, env Envelope, payload map[string]any) error {
	if err := validateTopic(topic); err != nil {
		return err
	}
	if err := validateEnvelope(env); err != nil {
		return err
	}

	body, err := encodeCloudPublisherPayload(topic, env, payload)
	if err != nil {
		return fmt.Errorf("events.CloudPublisher: marshal payload: %w", err)
	}

	aggregateID := env.GCID
	if aggregateID == "" {
		// Cross-tenant platform events use envelope.tenant_id="platform".
		// Fall back to event_id so every row has a non-empty aggregate_id.
		aggregateID = env.EventID
	}

	eventType := deriveEventType(topic)

	commonEnv := cgcenvelope.Envelope{
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

	row := &cgcoutbox.Row{
		ID:            newRowID(),
		AggregateType: p.cfg.AggregateType,
		AggregateID:   aggregateID,
		EventType:     eventType,
		Topic:         topic,
		Payload:       body,
		Envelope:      commonEnv,
		OccurredAt:    env.OccurredAt,
		Status:        cgcoutbox.StatusPending,
	}
	return p.rec.Record(context.Background(), nil, row)
}

// PublishWithTx is the transactional variant: the outbox row is written
// inside the supplied tx so the caller can pair it atomically with the
// surrounding domain state-change.
func (p *CloudPublisher) PublishWithTx(ctx context.Context, tx cgcoutbox.Tx, topic string, env Envelope, payload map[string]any) error {
	if err := validateTopic(topic); err != nil {
		return err
	}
	if err := validateEnvelope(env); err != nil {
		return err
	}
	body, err := encodeCloudPublisherPayload(topic, env, payload)
	if err != nil {
		return fmt.Errorf("events.CloudPublisher.PublishWithTx: marshal: %w", err)
	}
	aggregateID := env.GCID
	if aggregateID == "" {
		aggregateID = env.EventID
	}
	commonEnv := cgcenvelope.Envelope{
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
	row := &cgcoutbox.Row{
		ID:            newRowID(),
		AggregateType: p.cfg.AggregateType,
		AggregateID:   aggregateID,
		EventType:     deriveEventType(topic),
		Topic:         topic,
		Payload:       body,
		Envelope:      commonEnv,
		OccurredAt:    env.OccurredAt,
		Status:        cgcoutbox.StatusPending,
	}
	return p.rec.Record(ctx, tx, row)
}

// deriveEventType returns the suffix of topic past `chora.{domain}.`,
// matching the canonical chora.{domain}.{aggregate}.{event_type}.v{N}
// shape. e.g. "chora.identity.user.created.v1" → "user.created.v1".
func deriveEventType(topic string) string {
	parts := strings.SplitN(topic, ".", 3)
	if len(parts) < 3 {
		return topic
	}
	return parts[2]
}

func newRowID() string {
	return uuid.Must(uuid.NewV7()).String()
}

// Compile-time check.
var _ Publisher = (*CloudPublisher)(nil)

// Ensure unused symbol prevention.
var _ = errors.New
var _ = time.Now

// -----------------------------------------------------------------------------
// Payload encoding — binary protobuf for Schema-Registry-attached topics, JSON
// fallback for topics that don't yet have a binary encoder. New topics MUST
// add a case in internal/adapter/events/protomarshal/MarshalPayload.
// -----------------------------------------------------------------------------

var (
	cloudWarnedUnknownTopicsMu sync.Mutex
	cloudWarnedUnknownTopics   = map[string]bool{}
)

// toProtoEnvelope projects the local events.Envelope onto the encoder's flat
// envelope type. Keeps protomarshal import-cycle-free.
func toProtoEnvelope(env Envelope) protomarshal.Envelope {
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

// encodeCloudPublisherPayload marshals a topic+envelope+payload to binary
// protobuf wire bytes for the supplied topic's Schema Registry schema. Falls
// back to JSON (with a one-shot WARN log) for topics not yet wired in
// protomarshal.MarshalPayload — those rows WILL be rejected by Pub/Sub Schema
// Registry at publish; the fallback exists to preserve the pre-fix behaviour
// for topics not yet migrated.
func encodeCloudPublisherPayload(topic string, env Envelope, payload map[string]any) ([]byte, error) {
	bz, err := protomarshal.MarshalPayload(topic, toProtoEnvelope(env), payload)
	if err == nil {
		return bz, nil
	}
	if !protomarshal.IsUnsupportedTopic(err) {
		// Real encoding error (e.g. type mismatch) — fail loud.
		return nil, err
	}

	cloudWarnedUnknownTopicsMu.Lock()
	if !cloudWarnedUnknownTopics[topic] {
		cloudWarnedUnknownTopics[topic] = true
		log.Printf("WARN events.CloudPublisher: topic %q has no binary protobuf encoder — payload will JSON-marshal and Schema Registry will REJECT at publish; expect outbox_deadletter. Add a case to internal/adapter/events/protomarshal/MarshalPayload.", topic)
	}
	cloudWarnedUnknownTopicsMu.Unlock()

	bz, jErr := json.Marshal(payload)
	if jErr != nil {
		return nil, fmt.Errorf("events.CloudPublisher: json fallback marshal: %w", jErr)
	}
	return bz, nil
}
