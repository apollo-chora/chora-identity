// profile_updated_publisher_test.go — Q3 GCID→display-name projection.
//
// chora.identity.user.profile_updated.v1 is the event other domains
// (chora-delivery et al.) project into their local gcid→display-name
// directory. These tests mirror gcid_resolved_publisher_test.go: assert the
// canonical topic, the mandatory envelope provenance, and the exact JSON
// payload contract {gcid, display_name, email, updated_at}.
package events_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/apollo-chora/chora-identity/internal/adapter/events"
)

func TestProfileUpdatedPublisher_EmitsCanonicalTopicAndPayload(t *testing.T) {
	t.Parallel()
	rec := events.NewRecorder()
	p := events.NewProfileUpdatedPublisher(rec)

	updatedAt := time.Date(2026, 7, 8, 12, 30, 0, 0, time.UTC)
	err := p.PublishProfileUpdated(context.Background(), events.ProfileUpdatedEvent{
		Gcid:        "01970000-0000-7000-8000-0000000000aa",
		DisplayName: "Alice Wonder",
		Email:       "alice@example.com",
		TenantID:    "01970000-0000-7000-8000-0000000000bb",
		UpdatedAt:   updatedAt,
	})
	if err != nil {
		t.Fatalf("PublishProfileUpdated: %v", err)
	}

	got := rec.RecordedByTopic(events.TopicProfileUpdated)
	if len(got) != 1 {
		t.Fatalf("expected 1 record on %s, got %d", events.TopicProfileUpdated, len(got))
	}
	rec0 := got[0]

	// Envelope provenance — source_service + schema_version + gcid + tenant.
	if rec0.Envelope.SourceService != "chora-identity" {
		t.Errorf("envelope source_service = %q, want chora-identity", rec0.Envelope.SourceService)
	}
	if rec0.Envelope.SchemaVersion != 1 {
		t.Errorf("envelope schema_version = %d, want 1", rec0.Envelope.SchemaVersion)
	}
	if rec0.Envelope.GCID != "01970000-0000-7000-8000-0000000000aa" {
		t.Errorf("envelope gcid = %q", rec0.Envelope.GCID)
	}
	if rec0.Envelope.TenantID != "01970000-0000-7000-8000-0000000000bb" {
		t.Errorf("envelope tenant_id = %q", rec0.Envelope.TenantID)
	}
	if rec0.Envelope.EventID == "" || rec0.Envelope.IdempotencyKey == "" {
		t.Errorf("envelope must carry event_id + idempotency_key; got %+v", rec0.Envelope)
	}

	// Payload EXACTLY {gcid, display_name, email, updated_at}.
	if rec0.Payload["gcid"] != "01970000-0000-7000-8000-0000000000aa" {
		t.Errorf("payload gcid = %v", rec0.Payload["gcid"])
	}
	if rec0.Payload["display_name"] != "Alice Wonder" {
		t.Errorf("payload display_name = %v", rec0.Payload["display_name"])
	}
	if rec0.Payload["email"] != "alice@example.com" {
		t.Errorf("payload email = %v", rec0.Payload["email"])
	}
	// updated_at is fixed-width nanosecond RFC3339 UTC (valid RFC3339 +
	// lexicographically monotonic for the consumer's last-writer-wins).
	const wantFixedLayout = "2006-01-02T15:04:05.000000000Z"
	if got, want := rec0.Payload["updated_at"], updatedAt.Format(wantFixedLayout); got != want {
		t.Errorf("payload updated_at = %v, want %q", got, want)
	}
	// It MUST parse back as RFC3339 (the contract).
	if _, err := time.Parse(time.RFC3339, rec0.Payload["updated_at"].(string)); err != nil {
		t.Errorf("updated_at %v is not parseable RFC3339: %v", rec0.Payload["updated_at"], err)
	}
	// Contract is EXACTLY four keys — no leakage.
	if len(rec0.Payload) != 4 {
		t.Errorf("payload must carry exactly 4 keys, got %d: %v", len(rec0.Payload), rec0.Payload)
	}
}

func TestProfileUpdatedPublisher_FirstNameSet_EmptyOldName(t *testing.T) {
	t.Parallel()
	// "First name-set" case: a resolve-created user (display_name "") gets its
	// name populated. The publisher emits regardless of prior state — the
	// caller (pg.UpdateDisplayName) owns the changed/unchanged decision.
	rec := events.NewRecorder()
	p := events.NewProfileUpdatedPublisher(rec)
	err := p.PublishProfileUpdated(context.Background(), events.ProfileUpdatedEvent{
		Gcid:        "01970000-0000-7000-8000-0000000000cc",
		DisplayName: "Brand New",
		Email:       "new@example.com",
		TenantID:    "01970000-0000-7000-8000-0000000000bb",
		UpdatedAt:   time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("PublishProfileUpdated: %v", err)
	}
	if n := len(rec.RecordedByTopic(events.TopicProfileUpdated)); n != 1 {
		t.Fatalf("expected 1 record, got %d", n)
	}
}

func TestProfileUpdatedPublisher_RejectsMissingGCID(t *testing.T) {
	t.Parallel()
	rec := events.NewRecorder()
	p := events.NewProfileUpdatedPublisher(rec)
	err := p.PublishProfileUpdated(context.Background(), events.ProfileUpdatedEvent{
		Gcid:        "",
		DisplayName: "No GCID",
		Email:       "x@example.com",
		TenantID:    "01970000-0000-7000-8000-0000000000bb",
		UpdatedAt:   time.Now().UTC(),
	})
	if err == nil {
		t.Fatalf("expected error for empty GCID")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "gcid") {
		t.Errorf("error should mention gcid, got %q", err)
	}
}

func TestProfileUpdatedPublisher_RejectsEmptyDisplayName(t *testing.T) {
	t.Parallel()
	// The event is a projection of a NON-EMPTY name — an empty name is nothing
	// to project (the resolve-time empty state) and must be refused loud.
	rec := events.NewRecorder()
	p := events.NewProfileUpdatedPublisher(rec)
	err := p.PublishProfileUpdated(context.Background(), events.ProfileUpdatedEvent{
		Gcid:        "01970000-0000-7000-8000-0000000000aa",
		DisplayName: "",
		Email:       "x@example.com",
		TenantID:    "01970000-0000-7000-8000-0000000000bb",
		UpdatedAt:   time.Now().UTC(),
	})
	if err == nil {
		t.Fatalf("expected error for empty display_name")
	}
}

// countingPublisher records Publish calls WITHOUT validating — so the tenant_id
// guard is proven at the typed-publisher boundary, independent of any inner
// envelope validation (the real Recorder would also reject empty tenant_id).
type countingPublisher struct{ calls int }

func (c *countingPublisher) Publish(_ string, _ events.Envelope, _ map[string]any) error {
	c.calls++
	return nil
}

func TestProfileUpdatedPublisher_RejectsEmptyTenantID(t *testing.T) {
	t.Parallel()
	// The delivery consumer fail-louds / DLQs on an empty tenant_id attribute
	// (mandatory-envelope contract). Refuse at the source instead.
	inner := &countingPublisher{}
	p := events.NewProfileUpdatedPublisher(inner)
	err := p.PublishProfileUpdated(context.Background(), events.ProfileUpdatedEvent{
		Gcid:        "01970000-0000-7000-8000-0000000000aa",
		DisplayName: "Alice Wonder",
		Email:       "alice@example.com",
		TenantID:    "   ", // blank / whitespace-only acting tenant
		UpdatedAt:   time.Now().UTC(),
	})
	if err == nil {
		t.Fatalf("expected error for empty tenant_id")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "tenant") {
		t.Errorf("error should mention tenant, got %q", err)
	}
	if inner.calls != 0 {
		t.Errorf("must NOT reach the inner publisher when tenant_id is empty; got %d calls", inner.calls)
	}
}

func TestProfileUpdatedPublisher_TopicConstantMatchesTaxonomy(t *testing.T) {
	t.Parallel()
	if events.TopicProfileUpdated != "chora.identity.user.profile_updated.v1" {
		t.Errorf("topic = %q, want chora.identity.user.profile_updated.v1", events.TopicProfileUpdated)
	}
}
