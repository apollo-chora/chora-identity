// imda_evidence.go — IMDA Model AI Governance Framework evidence emitter.
//
// Per S3.6 P1.7 (deferred from S2): chora-identity emits
// chora.governance.evidence.recorded.v1 for federation success/rejection,
// passkey verify, role grant, KYC verify, and account closure events with
// canonical IMDA dimension labels (per ADR-141).
//
// This is the SHARED publisher used across the chora-identity service:
//   - Blocking Function handler emits accountability evidence on user.created
//   - OIDC adapters emit federation.succeeded / .rejected (in their own
//     adapter package — not via this publisher; see microsoft.go / google.go)
//   - Passkey handler emits passkey.verified evidence (caller wires)
//   - Role grant logic emits role.granted evidence (caller wires)
//   - KYC handler emits kyc.verified evidence (caller wires)
//
// Why a separate topic + publisher?
// Per Tier 5 D17 the chora-governance bounded context is the canonical
// owner of all IMDA evidence. Domain services emit into the shared topic
// chora.governance.evidence.recorded.v1; chora-governance subscribes and
// projects into the O+ governance dashboard. Cross-DB queries forbidden —
// events are the only inter-domain mechanism (per ddd-enforcement).
//
// Canonical dimensions per ADR-141:
//   - accountability                 (D1)
//   - transparency                   (D2)
//   - safety_and_robustness          (D3)
//   - fairness_and_human_oversight   (D4)
//
// Deprecated v1 aliases (canonicalised on input):
//   - risk_levels             → accountability
//   - stakeholder_interaction → transparency
//   - internal_governance     → safety_and_robustness
//   - operations_management   → fairness_and_human_oversight
package events

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// canonicalIMDADimensions is the closed v2 vocabulary per ADR-141. Mirrors
// libs/chora-go-common/envelope.canonicalIMDADimensions — kept duplicated
// here to avoid coupling the events adapter to the libs envelope package.
// (The libs envelope package is the canonical source of truth at the
// inter-domain boundary; this map is a defensive copy.)
var canonicalIMDADimensions = map[string]struct{}{
	"accountability":               {},
	"transparency":                 {},
	"safety_and_robustness":        {},
	"fairness_and_human_oversight": {},
}

// imdaV1ToV2 mirrors libs/chora-go-common/envelope.imdaV1ToV2 — kept here
// for the same defensive-copy reason.
var imdaV1ToV2 = map[string]string{
	"risk_levels":             "accountability",
	"stakeholder_interaction": "transparency",
	"internal_governance":     "safety_and_robustness",
	"operations_management":   "fairness_and_human_oversight",
}

// canonicalLifecycleStages is the closed vocabulary for envelope.proto
// field 15.
var canonicalLifecycleStages = map[string]struct{}{
	"ci_pre_merge": {},
	"pre_deploy":   {},
	"runtime":      {},
	"post_deploy":  {},
}

// EvidenceTopic is the single shared topic for IMDA evidence.
const EvidenceTopic = "chora.governance.evidence.recorded.v1"

// EvidenceInput captures the fields the caller supplies; the publisher
// builds the on-wire payload by merging EvidenceInput with the envelope.
type EvidenceInput struct {
	// EvidenceType is the canonical evidence label (e.g. passkey_verify_success,
	// role_grant, kyc_verify_success, oidc_federation_succeeded,
	// oidc_federation_rejected, account_closure_complete).
	EvidenceType string

	// SourceEventType is the chora.{domain}.{aggregate}.{event_type}.v{N}
	// topic that THIS evidence references. The chora-governance subscriber
	// uses this to correlate evidence with the originating event.
	SourceEventType string

	// Dimension is the IMDA dimension label (canonical or v1 alias). The
	// publisher canonicalises v1 aliases per ADR-141.
	Dimension string

	// LifecycleStage is the optional 4-stage IMDA pipeline classifier
	// (ci_pre_merge / pre_deploy / runtime / post_deploy).
	LifecycleStage string

	// PolicyReference is an optional human-readable policy citation
	// (e.g. "TP-04 (auth + identity)" / "ADR-142 §KYC").
	PolicyReference string

	// AdditionalFields are merged into the on-wire payload AFTER the
	// canonical fields. Use this to carry source-event-specific context
	// (provider name, gcid, credential_id, etc).
	AdditionalFields map[string]any
}

// GovernancePublisher emits chora.governance.evidence.recorded.v1 events.
type GovernancePublisher struct {
	inner Publisher
}

// NewGovernancePublisher constructs a GovernancePublisher backed by the
// supplied Publisher. The caller wires either the in-memory Recorder (tests)
// or the Pub/Sub adapter (production, M12).
func NewGovernancePublisher(inner Publisher) *GovernancePublisher {
	return &GovernancePublisher{inner: inner}
}

// RecordEvidence publishes a single IMDA evidence event. Returns an error
// if EvidenceType is empty or Dimension fails canonicalisation.
func (p *GovernancePublisher) RecordEvidence(env Envelope, in EvidenceInput) error {
	if p == nil || p.inner == nil {
		return errors.New("events: GovernancePublisher not initialised")
	}
	if strings.TrimSpace(in.EvidenceType) == "" {
		return errors.New("events: evidence_type required")
	}

	dim, err := canonicaliseDimension(in.Dimension)
	if err != nil {
		return err
	}
	stage, err := canonicaliseLifecycleStage(in.LifecycleStage)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	payload := map[string]any{
		"evidence_type":        strings.TrimSpace(in.EvidenceType),
		"source_event_type":    strings.TrimSpace(in.SourceEventType),
		"chora_imda_dimension": dim,
		"recorded_at":          now.Format(time.RFC3339Nano),
	}
	if stage != "" {
		payload["imda_lifecycle_stage"] = stage
	}
	if strings.TrimSpace(in.PolicyReference) != "" {
		payload["policy_reference"] = strings.TrimSpace(in.PolicyReference)
	}
	for k, v := range in.AdditionalFields {
		// Don't allow additional fields to overwrite the canonical IMDA fields.
		if _, exists := payload[k]; exists {
			continue
		}
		payload[k] = v
	}
	return p.inner.Publish(EvidenceTopic, env, payload)
}

// canonicaliseDimension lowercases + trims input, maps v1 aliases to
// canonical v2 labels, and rejects truly unknown values.
func canonicaliseDimension(in string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(in))
	if v == "" {
		return "", errors.New("events: chora_imda_dimension required")
	}
	if mapped, ok := imdaV1ToV2[v]; ok {
		return mapped, nil
	}
	if _, ok := canonicalIMDADimensions[v]; ok {
		return v, nil
	}
	return "", fmt.Errorf("events: unknown chora_imda_dimension %q (per ADR-141)", in)
}

// canonicaliseLifecycleStage lowercases + trims; empty input is allowed
// (lifecycle stage is optional).
func canonicaliseLifecycleStage(in string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(in))
	if v == "" {
		return "", nil
	}
	if _, ok := canonicalLifecycleStages[v]; !ok {
		return "", fmt.Errorf("events: unknown imda_lifecycle_stage %q", in)
	}
	return v, nil
}
