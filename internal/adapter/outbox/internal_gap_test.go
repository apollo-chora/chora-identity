// internal_gap_test.go — internal-package tests for the outbox helpers that
// the external outbox_test suite reaches only indirectly (envelope/time/type
// derivations + the fallback UUID generator).
package outbox

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/apollo-chora/chora-identity/internal/adapter/events"
)

func TestNewUUIDv7_ReturnsUUID(t *testing.T) {
	t.Parallel()
	got := newUUIDv7()
	if got == "" {
		t.Fatal("newUUIDv7 returned empty string")
	}
	if !strings.Contains(got, "-") {
		t.Errorf("newUUIDv7 output %q does not look like a UUID", got)
	}
}

func TestParseEnvelopeTime_AllFormats(t *testing.T) {
	t.Parallel()
	fallback := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	nano := time.Date(2026, 5, 1, 12, 30, 45, 123456789, time.UTC)
	sec := time.Date(2026, 5, 1, 12, 30, 45, 0, time.UTC)

	cases := []struct {
		name string
		in   string
		want time.Time
	}{
		{"empty falls back", "", fallback},
		{"RFC3339Nano", nano.Format(time.RFC3339Nano), nano},
		{"RFC3339", sec.Format(time.RFC3339), sec},
		{"garbage falls back", "not-a-time", fallback},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := parseEnvelopeTime(c.in, fallback); !got.Equal(c.want) {
				t.Errorf("parseEnvelopeTime(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestDeriveEventType_PrefixStrip(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{"chora.identity.user.created.v1", "user.created.v1"},
		{"chora.governance.evidence.recorded.v1", "evidence.recorded.v1"},
		{"short", "short"}, // defensive fallback returns input unchanged
	}
	for _, c := range cases {
		if got := deriveEventType(c.in); got != c.want {
			t.Errorf("deriveEventType(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDeriveAggregateType_SegmentExtraction(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{"chora.identity.user.created.v1", "user"},
		{"chora.governance.evidence.recorded.v1", "evidence"},
		{"chora.identity", "event"}, // malformed defensive default
		{"chora", "event"},
		{"", "event"},
	}
	for _, c := range cases {
		if got := deriveAggregateType(c.in); got != c.want {
			t.Errorf("deriveAggregateType(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// validEnvelope returns an events.Envelope that passes the outbox
// validateEnvelope checks — each test mutates one field to hit a branch.
func validEnvelope() events.Envelope {
	now := time.Now().UTC()
	return events.Envelope{
		EventID:        "evt-1",
		IdempotencyKey: "idem-1",
		TenantID:       "01970000-0000-7000-8000-00000000ee01",
		GCID:           "01970000-0000-7000-8000-000000000001",
		OccurredAt:     now,
		PublishedAt:    now,
		Traceparent:    "00-trace-01",
		SourceProject:  "chora-local",
		SourceService:  "chora-identity",
		SchemaVersion:  1,
	}
}

func TestValidateEnvelope_RejectsEachMissingField(t *testing.T) {
	t.Parallel()
	base := validEnvelope()
	cases := []struct {
		name   string
		mutate func(*events.Envelope)
	}{
		{"event_id", func(e *events.Envelope) { e.EventID = "" }},
		{"idempotency_key", func(e *events.Envelope) { e.IdempotencyKey = "" }},
		{"tenant_id", func(e *events.Envelope) { e.TenantID = "" }},
		{"occurred_at", func(e *events.Envelope) { e.OccurredAt = time.Time{} }},
		{"published_at", func(e *events.Envelope) { e.PublishedAt = time.Time{} }},
		{"traceparent", func(e *events.Envelope) { e.Traceparent = "" }},
		{"source_project", func(e *events.Envelope) { e.SourceProject = "" }},
		{"source_service", func(e *events.Envelope) { e.SourceService = "" }},
		{"schema_version", func(e *events.Envelope) { e.SchemaVersion = 0 }},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			e := base
			c.mutate(&e)
			if err := validateEnvelope(e); err == nil {
				t.Errorf("validateEnvelope accepted envelope with missing %s", c.name)
			}
		})
	}
}

func TestValidateEnvelope_AcceptsComplete(t *testing.T) {
	t.Parallel()
	if err := validateEnvelope(validEnvelope()); err != nil {
		t.Errorf("validateEnvelope rejected a complete envelope: %v", err)
	}
}
func TestIsUniqueViolation_Detection(t *testing.T) {
	t.Parallel()
	if isUniqueViolation(nil) {
		t.Error("nil error must not be a unique violation")
	}
	if !isUniqueViolation(errors.New("SQLSTATE 23505 duplicate")) {
		t.Error("SQLSTATE 23505 must be detected")
	}
	if !isUniqueViolation(errors.New(`pq: duplicate key value violates unique constraint`)) {
		t.Error("duplicate-key message must be detected")
	}
	if isUniqueViolation(errors.New("connection reset")) {
		t.Error("unrelated error must not be detected")
	}
}

func TestNullUUIDArg_MapsEmptyToNil(t *testing.T) {
	t.Parallel()
	if nullUUIDArg("") != nil {
		t.Error("empty string must map to nil")
	}
	if got := nullUUIDArg("01970000-0000-7000-8000-000000000001"); got != "01970000-0000-7000-8000-000000000001" {
		t.Errorf("non-empty string = %v, want passthrough", got)
	}
}
