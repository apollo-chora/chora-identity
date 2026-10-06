// events_internal_test.go — direct coverage for the unexported topic +
// envelope validators. The external events_test.go drives them indirectly
// through Recorder.Publish; this file table-tests every error branch
// explicitly.
package events

import (
	"strings"
	"testing"
	"time"
)

func TestValidateTopic_FullBranchCoverage(t *testing.T) {
	valid := "chora.identity.singpass.linked.v1"
	if err := validateTopic(valid); err != nil {
		t.Fatalf("valid topic %q rejected: %v", valid, err)
	}

	cases := []struct {
		name, topic, wantSubstr string
	}{
		{"empty", "  ", "required"},
		{"too few parts", "chora.identity.v1", "must follow"},
		{"not chora prefix", "x.identity.singpass.linked.v1", "start with 'chora.'"},
		{"foreign domain", "chora.payments.singpass.linked.v1", "domain must be"},
		{"missing version", "chora.identity.singpass.linked", "v{N}"},
		{"bare version", "chora.identity.singpass.linked.v", "version suffix"},
		{"non-numeric version", "chora.identity.singpass.linked.v1x", "numeric"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := validateTopic(tc.topic)
			if err == nil {
				t.Fatalf("topic %q must be rejected", tc.topic)
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Errorf("err = %q, want substring %q", err, tc.wantSubstr)
			}
		})
	}
}

func TestValidateEnvelope_FullBranchCoverage(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	base := Envelope{
		EventID:        "e-1",
		IdempotencyKey: "i-1",
		TenantID:       "t-1",
		GCID:           "g-1",
		OccurredAt:     now,
		PublishedAt:    now,
		Traceparent:    "00-trace-01",
		SourceProject:  "chora-local",
		SourceService:  "chora-identity",
		SchemaVersion:  1,
	}
	if err := validateEnvelope(base); err != nil {
		t.Fatalf("valid envelope rejected: %v", err)
	}

	unset := func(mut func(*Envelope)) Envelope {
		e := base
		mut(&e)
		return e
	}
	cases := []struct {
		name string
		env  Envelope
	}{
		{"event_id", unset(func(e *Envelope) { e.EventID = "" })},
		{"idempotency_key", unset(func(e *Envelope) { e.IdempotencyKey = "" })},
		{"tenant_id", unset(func(e *Envelope) { e.TenantID = "" })},
		{"occurred_at", unset(func(e *Envelope) { e.OccurredAt = time.Time{} })},
		{"published_at", unset(func(e *Envelope) { e.PublishedAt = time.Time{} })},
		{"traceparent", unset(func(e *Envelope) { e.Traceparent = "" })},
		{"source_project", unset(func(e *Envelope) { e.SourceProject = "" })},
		{"source_service", unset(func(e *Envelope) { e.SourceService = "" })},
		{"schema_version", unset(func(e *Envelope) { e.SchemaVersion = 0 })},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if err := validateEnvelope(tc.env); err == nil {
				t.Errorf("envelope missing %s must be rejected", tc.name)
			}
		})
	}
}
