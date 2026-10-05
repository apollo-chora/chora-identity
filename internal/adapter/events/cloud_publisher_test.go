// cloud_publisher_test.go — verifies the outbox-backed CloudPublisher
// satisfies the events.Publisher port and atomically writes to the outbox.
package events_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	cgcoutbox "github.com/apollo-chora/chora-common/outbox"

	"github.com/apollo-chora/chora-identity/internal/adapter/events"
)

// stubRecorder captures rows the CloudPublisher would write.
type stubRecorder struct {
	rows   []*cgcoutbox.Row
	lastTx cgcoutbox.Tx
}

func (s *stubRecorder) Record(_ context.Context, tx cgcoutbox.Tx, row *cgcoutbox.Row) error {
	s.rows = append(s.rows, row)
	s.lastTx = tx
	return nil
}
func (s *stubRecorder) Claim(_ context.Context, _ int) ([]*cgcoutbox.Row, error) {
	return nil, nil
}
func (s *stubRecorder) MarkPublished(_ context.Context, _ []string) error { return nil }
func (s *stubRecorder) MarkFailed(_ context.Context, _ string, _ string, _ bool) error {
	return nil
}

func TestCloudPublisher_WritesToOutbox(t *testing.T) {
	t.Parallel()

	rec := &stubRecorder{}
	pub := events.NewCloudPublisher(rec, events.CloudPublisherConfig{
		AggregateType: "user",
	})

	env := events.Envelope{
		EventID:        "01970000-0000-7000-8000-000000000001",
		IdempotencyKey: "01970000-0000-7000-8000-000000000002",
		TenantID:       "01970000-0000-7000-8000-000000000003",
		GCID:           "01970000-0000-7000-8000-000000000004",
		OccurredAt:     time.Now().UTC(),
		PublishedAt:    time.Now().UTC(),
		Traceparent:    "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
		SourceProject:  events.SourceProject,
		SourceService:  events.SourceService,
		SchemaVersion:  1,
	}
	payload := map[string]any{"gcid": env.GCID}
	if err := pub.Publish("chora.identity.user.created.v1", env, payload); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if len(rec.rows) != 1 {
		t.Fatalf("expected 1 outbox row, got %d", len(rec.rows))
	}
	row := rec.rows[0]
	if row.Topic != "chora.identity.user.created.v1" {
		t.Errorf("topic = %q", row.Topic)
	}
	if row.AggregateType != "user" {
		t.Errorf("aggregate_type = %q", row.AggregateType)
	}
	if row.AggregateID == "" {
		t.Errorf("aggregate_id required")
	}
	if row.EventType != "user.created.v1" {
		t.Errorf("event_type = %q", row.EventType)
	}
	if len(row.Payload) == 0 {
		t.Errorf("payload should be non-empty")
	}
	if row.Envelope.EventID != env.EventID {
		t.Errorf("envelope.event_id = %q", row.Envelope.EventID)
	}
}

func TestCloudPublisher_RejectsInvalidTopic(t *testing.T) {
	t.Parallel()
	rec := &stubRecorder{}
	pub := events.NewCloudPublisher(rec, events.CloudPublisherConfig{AggregateType: "user"})
	env := events.Envelope{}
	err := pub.Publish("not.a.valid.topic", env, nil)
	if err == nil {
		t.Fatalf("expected validation error")
	}
}

func TestCloudPublisher_DerivesAggregateIDFromGCID(t *testing.T) {
	t.Parallel()
	rec := &stubRecorder{}
	pub := events.NewCloudPublisher(rec, events.CloudPublisherConfig{AggregateType: "user"})
	env := events.Envelope{
		EventID:        "01970000-0000-7000-8000-000000000001",
		IdempotencyKey: "01970000-0000-7000-8000-000000000002",
		TenantID:       "01970000-0000-7000-8000-000000000003",
		GCID:           "01970000-0000-7000-8000-000000000004",
		OccurredAt:     time.Now().UTC(),
		PublishedAt:    time.Now().UTC(),
		Traceparent:    "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
		SourceProject:  events.SourceProject,
		SourceService:  events.SourceService,
		SchemaVersion:  1,
	}
	if err := pub.Publish("chora.identity.user.created.v1", env, map[string]any{}); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if rec.rows[0].AggregateID != env.GCID {
		t.Errorf("expected aggregate_id = gcid, got %q", rec.rows[0].AggregateID)
	}
}

// --- PublishWithTx (transactional outbox variant) ------------------------------

// minimalTx is a no-op cgcoutbox.Tx used to prove the tx is forwarded to the
// recorder untouched. nil is a legal Tx per the outbox contract, but a typed
// non-nil tx exercises the pass-through on the way in.
type minimalTx struct{}

func (minimalTx) ExecContext(context.Context, string, ...interface{}) (sql.Result, error) {
	return nil, nil
}

func TestCloudPublisher_PublishWithTx_WritesRowInsideTx(t *testing.T) {
	t.Parallel()
	rec := &stubRecorder{}
	pub := events.NewCloudPublisher(rec, events.CloudPublisherConfig{AggregateType: "user"})

	env := events.Envelope{
		EventID:        "01970000-0000-7000-8000-000000000001",
		IdempotencyKey: "01970000-0000-7000-8000-000000000002",
		TenantID:       "01970000-0000-7000-8000-000000000003",
		GCID:           "01970000-0000-7000-8000-000000000004",
		OccurredAt:     time.Now().UTC(),
		PublishedAt:    time.Now().UTC(),
		Traceparent:    "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
		SourceProject:  events.SourceProject,
		SourceService:  events.SourceService,
		SchemaVersion:  1,
	}
	payload := map[string]any{"gcid": env.GCID}
	tx := minimalTx{}
	if err := pub.PublishWithTx(context.Background(), tx, "chora.identity.user.created.v1", env, payload); err != nil {
		t.Fatalf("PublishWithTx: %v", err)
	}
	if len(rec.rows) != 1 {
		t.Fatalf("expected 1 outbox row, got %d", len(rec.rows))
	}
	row := rec.rows[0]
	if row.Topic != "chora.identity.user.created.v1" {
		t.Errorf("topic = %q", row.Topic)
	}
	if row.AggregateType != "user" {
		t.Errorf("aggregate_type = %q", row.AggregateType)
	}
	if row.AggregateID != env.GCID {
		t.Errorf("aggregate_id = %q", row.AggregateID)
	}
	if rec.lastTx == nil {
		t.Error("the supplied tx must be forwarded to the recorder")
	}
}

func TestCloudPublisher_PublishWithTx_RejectsInvalidTopic(t *testing.T) {
	t.Parallel()
	rec := &stubRecorder{}
	pub := events.NewCloudPublisher(rec, events.CloudPublisherConfig{AggregateType: "user"})
	err := pub.PublishWithTx(context.Background(), nil, "not.a.valid.topic", events.Envelope{}, nil)
	if err == nil {
		t.Fatalf("expected validation error")
	}
}

func TestCloudPublisher_PublishWithTx_RejectsInvalidEnvelope(t *testing.T) {
	t.Parallel()
	rec := &stubRecorder{}
	pub := events.NewCloudPublisher(rec, events.CloudPublisherConfig{AggregateType: "user"})
	err := pub.PublishWithTx(context.Background(), nil, "chora.identity.user.created.v1", events.Envelope{}, nil)
	if err == nil {
		t.Fatalf("expected envelope validation error")
	}
}

// --- encoder-driven branches ----------------------------------------------------

func cloudEnv(gcid string) events.Envelope {
	return events.Envelope{
		EventID:        "01970000-0000-7000-8000-000000000001",
		IdempotencyKey: "01970000-0000-7000-8000-000000000002",
		TenantID:       "01970000-0000-7000-8000-000000000003",
		GCID:           gcid,
		OccurredAt:     time.Now().UTC(),
		PublishedAt:    time.Now().UTC(),
		Traceparent:    "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
		SourceProject:  events.SourceProject,
		SourceService:  events.SourceService,
		SchemaVersion:  1,
	}
}

func TestCloudPublisher_New_DefaultsAggregateType(t *testing.T) {
	t.Parallel()
	rec := &stubRecorder{}
	pub := events.NewCloudPublisher(rec, events.CloudPublisherConfig{}) // empty → "user"
	if err := pub.Publish("chora.identity.kyc.verified.v1", cloudEnv("g-1"), map[string]any{}); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if rec.rows[0].AggregateType != "user" {
		t.Errorf("default aggregate_type = %q, want user", rec.rows[0].AggregateType)
	}
}

func TestCloudPublisher_Publish_BinaryEncoderTopic(t *testing.T) {
	t.Parallel()
	rec := &stubRecorder{}
	pub := events.NewCloudPublisher(rec, events.CloudPublisherConfig{AggregateType: "user"})
	// kyc.verified.v1 has a binary protobuf encoder — empty payload means
	// every optional field is skipped, exercising the canonical encode path.
	if err := pub.Publish("chora.identity.kyc.verified.v1", cloudEnv("g-1"), map[string]any{}); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if len(rec.rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rec.rows))
	}
	if len(rec.rows[0].Payload) == 0 {
		t.Error("binary-encoded payload must be non-empty")
	}
}

func TestCloudPublisher_Publish_EncodeErrorPropagates(t *testing.T) {
	t.Parallel()
	rec := &stubRecorder{}
	pub := events.NewCloudPublisher(rec, events.CloudPublisherConfig{AggregateType: "user"})
	// kyc.verified.v1 encodes skillsfuture_scope_granted as a bool — a string
	// value triggers a real (non-unsupported-topic) encoder error.
	err := pub.Publish("chora.identity.kyc.verified.v1", cloudEnv("g-1"), map[string]any{"skillsfuture_scope_granted": "yes"})
	if err == nil {
		t.Fatal("type-mismatched payload must fail the binary encoder")
	}
	if len(rec.rows) != 0 {
		t.Errorf("no outbox row must be written on encode failure, got %d", len(rec.rows))
	}
}

func TestCloudPublisher_Publish_JSONFallbackMarshalError(t *testing.T) {
	t.Parallel()
	rec := &stubRecorder{}
	pub := events.NewCloudPublisher(rec, events.CloudPublisherConfig{AggregateType: "user"})
	// user.created.v1 has no binary encoder → JSON fallback — a channel value
	// makes the fallback marshal fail loud.
	err := pub.Publish("chora.identity.user.created.v1", cloudEnv("g-1"), map[string]any{"ch": make(chan int)})
	if err == nil {
		t.Fatal("json fallback marshal must error on an un-marshalable payload")
	}
	if len(rec.rows) != 0 {
		t.Errorf("no outbox row must be written on marshal failure, got %d", len(rec.rows))
	}
}

func TestCloudPublisher_Publish_EmptyGCIDFallsBackToEventID(t *testing.T) {
	t.Parallel()
	rec := &stubRecorder{}
	pub := events.NewCloudPublisher(rec, events.CloudPublisherConfig{AggregateType: "user"})
	env := cloudEnv("")
	if err := pub.Publish("chora.identity.user.created.v1", env, map[string]any{}); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if rec.rows[0].AggregateID != env.EventID {
		t.Errorf("aggregate_id = %q, want event_id %q", rec.rows[0].AggregateID, env.EventID)
	}
}

func TestCloudPublisher_PublishWithTx_EncodeErrorPropagates(t *testing.T) {
	t.Parallel()
	rec := &stubRecorder{}
	pub := events.NewCloudPublisher(rec, events.CloudPublisherConfig{AggregateType: "user"})
	err := pub.PublishWithTx(context.Background(), minimalTx{}, "chora.identity.kyc.verified.v1", cloudEnv("g-1"), map[string]any{"skillsfuture_scope_granted": "yes"})
	if err == nil {
		t.Fatal("type-mismatched payload must fail PublishWithTx")
	}
	if len(rec.rows) != 0 {
		t.Errorf("no outbox row must be written on encode failure, got %d", len(rec.rows))
	}
}

func TestCloudPublisher_PublishWithTx_EmptyGCIDFallsBackToEventID(t *testing.T) {
	t.Parallel()
	rec := &stubRecorder{}
	pub := events.NewCloudPublisher(rec, events.CloudPublisherConfig{AggregateType: "user"})
	env := cloudEnv("")
	if err := pub.PublishWithTx(context.Background(), nil, "chora.identity.user.created.v1", env, map[string]any{}); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if rec.rows[0].AggregateID != env.EventID {
		t.Errorf("aggregate_id = %q, want event_id %q", rec.rows[0].AggregateID, env.EventID)
	}
}
