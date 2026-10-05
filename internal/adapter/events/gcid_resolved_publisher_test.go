// gcid_resolved_publisher_test.go — Bucket 2 publisher coverage.
package events_test

import (
	"context"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/trace"

	"github.com/apollo-chora/chora-identity/internal/adapter/events"
)

func TestGCIDResolvedPublisher_EmitsCanonicalTopic(t *testing.T) {
	t.Parallel()
	rec := events.NewRecorder()
	p := events.NewGCIDResolvedPublisher(rec)
	err := p.PublishGCIDResolved(context.Background(), events.GCIDResolvedEvent{
		GCID:             "01970000-0000-7000-8000-0000000000aa",
		TenantID:         "01970000-0000-7000-8000-0000000000bb",
		Email:            "alice@example.com",
		FirebaseUID:      "fed-sub-1",
		IdempotencyKey:   "deadbeefdeadbeef",
		MembershipsCount: 1,
	})
	if err != nil {
		t.Fatalf("PublishGCIDResolved: %v", err)
	}
	got := rec.RecordedByTopic(events.TopicGCIDResolved)
	if len(got) != 1 {
		t.Fatalf("expected 1 record on %s, got %d", events.TopicGCIDResolved, len(got))
	}
	if got[0].Envelope.GCID != "01970000-0000-7000-8000-0000000000aa" {
		t.Errorf("envelope GCID = %q", got[0].Envelope.GCID)
	}
	if got[0].Envelope.IdempotencyKey != "deadbeefdeadbeef" {
		t.Errorf("envelope IdempotencyKey = %q", got[0].Envelope.IdempotencyKey)
	}
	// memberships_count round-trips through map[string]any as the native int.
	switch v := got[0].Payload["memberships_count"].(type) {
	case int:
		if v != 1 {
			t.Errorf("payload memberships_count int = %d", v)
		}
	case float64:
		if int(v) != 1 {
			t.Errorf("payload memberships_count float = %v", v)
		}
	default:
		t.Errorf("payload memberships_count unexpected type %T = %v", v, v)
	}
}

func TestGCIDResolvedPublisher_RejectsMissingGCID(t *testing.T) {
	t.Parallel()
	rec := events.NewRecorder()
	p := events.NewGCIDResolvedPublisher(rec)
	err := p.PublishGCIDResolved(context.Background(), events.GCIDResolvedEvent{
		GCID:           "",
		IdempotencyKey: "x",
	})
	if err == nil {
		t.Fatalf("expected error for empty GCID")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "gcid") {
		t.Errorf("error should mention gcid, got %q", err)
	}
}

func TestGCIDResolvedPublisher_RejectsMissingIdempotencyKey(t *testing.T) {
	t.Parallel()
	rec := events.NewRecorder()
	p := events.NewGCIDResolvedPublisher(rec)
	err := p.PublishGCIDResolved(context.Background(), events.GCIDResolvedEvent{
		GCID:           "01970000-0000-7000-8000-0000000000aa",
		IdempotencyKey: "",
	})
	if err == nil {
		t.Fatalf("expected error for empty IdempotencyKey")
	}
}

func TestGCIDResolvedPublisher_TopicConstantMatchesTaxonomy(t *testing.T) {
	t.Parallel()
	if events.TopicGCIDResolved != "chora.identity.gcid.resolved.v1" {
		t.Errorf("topic = %q, want chora.identity.gcid.resolved.v1", events.TopicGCIDResolved)
	}
}

// TestGCIDResolvedPublisher_PropagatesOTelTraceparent asserts the W3C
// traceparent is derived from the active OTel span (sampled → "-01" flags,
// unsampled → "-00") and stamped on the published envelope.
func TestGCIDResolvedPublisher_PropagatesOTelTraceparent(t *testing.T) {
	t.Parallel()
	rec := events.NewRecorder()
	p := events.NewGCIDResolvedPublisher(rec)

	tid, err := trace.TraceIDFromHex("0af7651916cd43dd8448eb211c80319c")
	if err != nil {
		t.Fatal(err)
	}
	sid, err := trace.SpanIDFromHex("b7ad6b7169203331")
	if err != nil {
		t.Fatal(err)
	}

	// Sampled span → flags "01".
	sampled := trace.NewSpanContext(trace.SpanContextConfig{TraceID: tid, SpanID: sid, TraceFlags: trace.FlagsSampled})
	if err := p.PublishGCIDResolved(trace.ContextWithSpanContext(context.Background(), sampled), events.GCIDResolvedEvent{
		GCID: "01970000-0000-7000-8000-0000000000dd", TenantID: tenantA, IdempotencyKey: "k-sampled",
	}); err != nil {
		t.Fatalf("publish sampled: %v", err)
	}
	wantSampled := "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
	if got := rec.RecordedByTopic(events.TopicGCIDResolved)[0].Envelope.Traceparent; got != wantSampled {
		t.Errorf("sampled traceparent = %q, want %q", got, wantSampled)
	}

	// Unsampled span → flags "00".
	plain := trace.NewSpanContext(trace.SpanContextConfig{TraceID: tid, SpanID: sid})
	if err := p.PublishGCIDResolved(trace.ContextWithSpanContext(context.Background(), plain), events.GCIDResolvedEvent{
		GCID: "01970000-0000-7000-8000-0000000000de", TenantID: tenantA, IdempotencyKey: "k-plain",
	}); err != nil {
		t.Fatalf("publish plain: %v", err)
	}
	got := rec.RecordedByTopic(events.TopicGCIDResolved)[1].Envelope.Traceparent
	if want := "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-00"; got != want {
		t.Errorf("unsampled traceparent = %q, want %q", got, want)
	}
}

func TestGCIDResolvedPublisher_NilInner_Errors(t *testing.T) {
	t.Parallel()
	p := events.NewGCIDResolvedPublisher(nil)
	if err := p.PublishGCIDResolved(context.Background(), events.GCIDResolvedEvent{
		GCID: "g-1", IdempotencyKey: "k-1",
	}); err == nil {
		t.Error("nil inner publisher must error")
	}
}
