// imda_evidence_test.go — RED-phase TDD specs for the IMDA Model AI
// Governance Framework evidence emitter.
//
// Per S3.6 spec §7 (carried forward from S2): chora-identity emits
// chora.governance.evidence.recorded.v1 for the following events with
// IMDA dimension labels:
//
//   - passkey verify success      → accountability (D1)
//   - role grant                  → accountability (D1)
//   - KYC verify success          → accountability (D1)
//   - account closure complete    → accountability (D1)
//   - OIDC federation success     → accountability (D1)
//   - OIDC federation rejection   → safety_and_robustness (D3)
//
// Per ADR-141 the canonical IMDA dimension labels (post v1 deprecation) are:
//
//   - accountability               (D1)
//   - transparency                 (D2)
//   - safety_and_robustness        (D3)
//   - fairness_and_human_oversight (D4)
//
// The publisher writes to `chora.governance.evidence.recorded.v1` (single
// topic; payload includes evidence_type, source_event_type, dimension).
package events_test

import (
	"strings"
	"testing"
	"time"

	"github.com/apollo-chora/chora-identity/internal/adapter/events"
)

func TestGovernancePublisher_EmitsEvidenceWithCorrectDimensionForPasskeyVerify(t *testing.T) {
	t.Parallel()
	rec := events.NewRecorder()
	pub := events.NewGovernancePublisher(rec)

	env := events.NewEnvelope("01970000-0000-7000-8000-0000000000aa", "gcid-1", "00-aabb-ccdd-01", "")
	if err := pub.RecordEvidence(env, events.EvidenceInput{
		EvidenceType:     "passkey_verify_success",
		SourceEventType:  "chora.identity.passkey.verified.v1",
		Dimension:        "accountability",
		LifecycleStage:   "runtime",
		PolicyReference:  "TP-04 (auth + identity)",
		AdditionalFields: map[string]any{"gcid": "gcid-1", "credential_id": "cred-xyz"},
	}); err != nil {
		t.Fatalf("RecordEvidence: %v", err)
	}
	recs := rec.RecordedByTopic("chora.governance.evidence.recorded.v1")
	if len(recs) != 1 {
		t.Fatalf("expected 1 evidence event, got %d", len(recs))
	}
	got := recs[0]
	if got.Payload["evidence_type"] != "passkey_verify_success" {
		t.Errorf("evidence_type = %v", got.Payload["evidence_type"])
	}
	if got.Payload["chora_imda_dimension"] != "accountability" {
		t.Errorf("chora_imda_dimension = %v", got.Payload["chora_imda_dimension"])
	}
	if got.Payload["imda_lifecycle_stage"] != "runtime" {
		t.Errorf("imda_lifecycle_stage = %v", got.Payload["imda_lifecycle_stage"])
	}
	if got.Payload["source_event_type"] != "chora.identity.passkey.verified.v1" {
		t.Errorf("source_event_type = %v", got.Payload["source_event_type"])
	}
	if got.Envelope.GCID != "gcid-1" {
		t.Errorf("GCID = %q", got.Envelope.GCID)
	}
}

func TestGovernancePublisher_EmitsEvidenceForRoleGrant(t *testing.T) {
	t.Parallel()
	rec := events.NewRecorder()
	pub := events.NewGovernancePublisher(rec)

	env := events.NewEnvelope("t", "g", "00-aabb-ccdd-01", "")
	if err := pub.RecordEvidence(env, events.EvidenceInput{
		EvidenceType:    "role_grant",
		SourceEventType: "chora.identity.role.granted.v1",
		Dimension:       "accountability",
		LifecycleStage:  "runtime",
	}); err != nil {
		t.Fatalf("RecordEvidence: %v", err)
	}
	recs := rec.RecordedByTopic("chora.governance.evidence.recorded.v1")
	if len(recs) != 1 {
		t.Fatalf("expected 1 evidence event, got %d", len(recs))
	}
	if recs[0].Payload["chora_imda_dimension"] != "accountability" {
		t.Errorf("expected accountability, got %v", recs[0].Payload["chora_imda_dimension"])
	}
}

func TestGovernancePublisher_EmitsSafetyEvidenceForFederationRejection(t *testing.T) {
	t.Parallel()
	rec := events.NewRecorder()
	pub := events.NewGovernancePublisher(rec)

	env := events.NewEnvelope("t", "g", "00-aabb-ccdd-01", "")
	if err := pub.RecordEvidence(env, events.EvidenceInput{
		EvidenceType:    "oidc_federation_rejected",
		SourceEventType: "chora.identity.federation.rejected.v1",
		Dimension:       "safety_and_robustness",
		LifecycleStage:  "runtime",
		AdditionalFields: map[string]any{
			"provider": "google",
			"reason":   "invalid_grant",
		},
	}); err != nil {
		t.Fatalf("RecordEvidence: %v", err)
	}
	recs := rec.RecordedByTopic("chora.governance.evidence.recorded.v1")
	if len(recs) != 1 {
		t.Fatalf("expected 1 event")
	}
	got := recs[0].Payload
	if got["chora_imda_dimension"] != "safety_and_robustness" {
		t.Errorf("dimension = %v", got["chora_imda_dimension"])
	}
	if got["provider"] != "google" {
		t.Errorf("payload merge missing provider: %v", got)
	}
	if got["reason"] != "invalid_grant" {
		t.Errorf("payload merge missing reason: %v", got)
	}
}

func TestGovernancePublisher_RejectsInvalidDimension(t *testing.T) {
	t.Parallel()
	rec := events.NewRecorder()
	pub := events.NewGovernancePublisher(rec)
	env := events.NewEnvelope("t", "g", "00-aabb-ccdd-01", "")
	err := pub.RecordEvidence(env, events.EvidenceInput{
		EvidenceType:    "x",
		SourceEventType: "chora.x.y.z.v1",
		Dimension:       "internal_governance", // v1 deprecated label
	})
	// v1 deprecated labels SHOULD canonicalise (per ADR-141 + envelope.go).
	if err != nil {
		t.Fatalf("v1 alias should be accepted but got %v", err)
	}
	recs := rec.RecordedByTopic("chora.governance.evidence.recorded.v1")
	if len(recs) != 1 {
		t.Fatalf("expected 1 event")
	}
	if got := recs[0].Payload["chora_imda_dimension"]; got != "safety_and_robustness" {
		t.Errorf("expected canonicalised safety_and_robustness, got %v", got)
	}
}

func TestGovernancePublisher_RejectsTrulyUnknownDimension(t *testing.T) {
	t.Parallel()
	rec := events.NewRecorder()
	pub := events.NewGovernancePublisher(rec)
	env := events.NewEnvelope("t", "g", "00-aabb-ccdd-01", "")
	err := pub.RecordEvidence(env, events.EvidenceInput{
		EvidenceType:    "x",
		SourceEventType: "chora.x.y.z.v1",
		Dimension:       "nonsense",
	})
	if err == nil {
		t.Fatalf("expected rejection for nonsense dimension")
	}
}

func TestGovernancePublisher_RejectsEmptyEvidenceType(t *testing.T) {
	t.Parallel()
	rec := events.NewRecorder()
	pub := events.NewGovernancePublisher(rec)
	env := events.NewEnvelope("t", "g", "00-aabb-ccdd-01", "")
	if err := pub.RecordEvidence(env, events.EvidenceInput{
		Dimension: "accountability",
	}); err == nil {
		t.Fatalf("expected error empty evidence_type")
	}
}

func TestGovernancePublisher_RecordedAtIsSet(t *testing.T) {
	t.Parallel()
	rec := events.NewRecorder()
	pub := events.NewGovernancePublisher(rec)
	env := events.NewEnvelope("t", "g", "00-aabb-ccdd-01", "")
	before := time.Now().UTC()
	_ = pub.RecordEvidence(env, events.EvidenceInput{
		EvidenceType: "kyc_verify_success", Dimension: "accountability",
		SourceEventType: "chora.identity.kyc.verified.v1",
	})
	after := time.Now().UTC()
	recs := rec.RecordedByTopic("chora.governance.evidence.recorded.v1")
	if len(recs) != 1 {
		t.Fatalf("expected 1 event")
	}
	rt, ok := recs[0].Payload["recorded_at"].(string)
	if !ok || rt == "" {
		t.Fatalf("recorded_at missing or wrong type")
	}
	parsed, err := time.Parse(time.RFC3339Nano, rt)
	if err != nil {
		t.Fatalf("recorded_at parse: %v", err)
	}
	if parsed.Before(before.Add(-time.Second)) || parsed.After(after.Add(time.Second)) {
		t.Errorf("recorded_at = %s outside [%s, %s]", parsed, before, after)
	}
}

func TestGovernancePublisher_TopicValidationFiresOnBadDimension(t *testing.T) {
	t.Parallel()
	rec := events.NewRecorder()
	pub := events.NewGovernancePublisher(rec)
	env := events.NewEnvelope("t", "g", "00-aabb-ccdd-01", "")
	err := pub.RecordEvidence(env, events.EvidenceInput{
		EvidenceType: "x",
		// Dimension has whitespace; canonicalise should still accept after trim.
		Dimension:       "  accountability  ",
		SourceEventType: "chora.x.y.z.v1",
	})
	if err != nil {
		t.Errorf("expected dimension trim to succeed, got %v", err)
	}
	recs := rec.RecordedByTopic("chora.governance.evidence.recorded.v1")
	if len(recs) != 1 {
		t.Fatalf("expected 1 event")
	}
	if got := recs[0].Payload["chora_imda_dimension"]; got != "accountability" {
		t.Errorf("expected accountability after trim, got %v", got)
	}
}

// Sanity check: all governance evidence events MUST land on the
// chora.governance.* topic, NOT chora.identity.*.
func TestGovernancePublisher_DoesNotEmitOnIdentityTopics(t *testing.T) {
	t.Parallel()
	rec := events.NewRecorder()
	pub := events.NewGovernancePublisher(rec)
	env := events.NewEnvelope("t", "g", "00-aabb-ccdd-01", "")
	_ = pub.RecordEvidence(env, events.EvidenceInput{
		EvidenceType: "x", Dimension: "accountability",
		SourceEventType: "chora.identity.passkey.verified.v1",
	})
	for _, r := range rec.Recorded() {
		if !strings.HasPrefix(r.Topic, "chora.governance.") {
			t.Errorf("expected chora.governance.* topic, got %s", r.Topic)
		}
	}
}
