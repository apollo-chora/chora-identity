// fabric_canonical_test verifies the binary bytes emitted by MarshalPayload for
// the 3 Class-D contracts authored during the event-fabric audit (2026-07-01)
// parse cleanly into their generated chora-contracts proto types. Same
// load-bearing assertion as wire_compat_test: if these pass, the event-bus schema
// Registry accepts the bytes.
//
// The 3 contracts: chora-identity emitted to these topics before any proto /
// schema / topic existed (Class D — "topic not provisioned"):
//   - chora.identity.gcid.resolved.v1
//   - chora.identity.tenant_idp_provider.configured.v1
//   - chora.governance.evidence.recorded.v1  (governance-domain topic; identity
//     is a producer and owns the outbox encoder)
package protomarshal_test

import (
	"testing"

	"google.golang.org/protobuf/proto"

	governancev1 "github.com/apollo-chora/chora-contracts/gen/go/chora/governance/v1"
	identityv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/identity/v1"

	"github.com/apollo-chora/chora-identity/internal/adapter/events/protomarshal"
)

// TestFabric_GcidResolved_DecodesIntoGeneratedType mirrors the payload built by
// GCIDResolvedPublisher.PublishGCIDResolved.
func TestFabric_GcidResolved_DecodesIntoGeneratedType(t *testing.T) {
	env := wireCompatEnvelope()
	payload := map[string]any{
		"gcid":              env.GCID,
		"tenant_id":         env.TenantID,
		"email":             "phyllis@acme.test",
		"firebase_uid":      "fed-sub-abc",
		"memberships_count": 3,
	}
	bz, err := protomarshal.MarshalPayload("chora.identity.gcid.resolved.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	var msg identityv1.GcidResolved
	if err := proto.Unmarshal(bz, &msg); err != nil {
		t.Fatalf("proto.Unmarshal GcidResolved: %v", err)
	}
	if got := msg.GetEnvelope().GetEventId(); got != env.EventID {
		t.Fatalf("envelope.event_id: got %q", got)
	}
	if got := msg.GetEnvelope().GetTraceparent(); got != env.Traceparent {
		t.Fatalf("envelope.traceparent: got %q", got)
	}
	if got := msg.GetGcid(); got != env.GCID {
		t.Fatalf("gcid: got %q", got)
	}
	if got := msg.GetTenantId(); got != env.TenantID {
		t.Fatalf("tenant_id: got %q", got)
	}
	if got := msg.GetEmail(); got != "phyllis@acme.test" {
		t.Fatalf("email: got %q", got)
	}
	if got := msg.GetFirebaseUid(); got != "fed-sub-abc" {
		t.Fatalf("firebase_uid: got %q", got)
	}
	if got := msg.GetMembershipsCount(); got != 3 {
		t.Fatalf("memberships_count: got %d", got)
	}
}

// TestFabric_TenantIdpProviderConfigured_DecodesIntoGeneratedType mirrors the
// payload built by tenant_idp_provider_events.Publisher.Publish.
func TestFabric_TenantIdpProviderConfigured_DecodesIntoGeneratedType(t *testing.T) {
	env := wireCompatEnvelope()
	payload := map[string]any{
		"event_type":    "configured",
		"idp_id":        "idp-01971a90",
		"tenant_id":     env.TenantID,
		"provider_type": "oidc",
		"actor_gcid":    env.GCID,
	}
	bz, err := protomarshal.MarshalPayload("chora.identity.tenant_idp_provider.configured.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	var msg identityv1.TenantIdpProviderConfigured
	if err := proto.Unmarshal(bz, &msg); err != nil {
		t.Fatalf("proto.Unmarshal TenantIdpProviderConfigured: %v", err)
	}
	if got := msg.GetEnvelope().GetTenantId(); got != env.TenantID {
		t.Fatalf("envelope.tenant_id: got %q", got)
	}
	if got := msg.GetEventType(); got != "configured" {
		t.Fatalf("event_type: got %q", got)
	}
	if got := msg.GetIdpId(); got != "idp-01971a90" {
		t.Fatalf("idp_id: got %q", got)
	}
	if got := msg.GetTenantId(); got != env.TenantID {
		t.Fatalf("tenant_id: got %q", got)
	}
	if got := msg.GetProviderType(); got != "oidc" {
		t.Fatalf("provider_type: got %q", got)
	}
	if got := msg.GetActorGcid(); got != env.GCID {
		t.Fatalf("actor_gcid: got %q", got)
	}
}

// TestFabric_EvidenceRecorded_DecodesIntoGeneratedType mirrors the FLAT payload
// map that GovernancePublisher.RecordEvidence produces: canonical fields +
// chora_imda_dimension/imda_lifecycle_stage (which ride the envelope) +
// AdditionalFields merged in flat (heterogeneous: string / bool / []string).
func TestFabric_EvidenceRecorded_DecodesIntoGeneratedType(t *testing.T) {
	env := wireCompatEnvelope()
	recorded := env.OccurredAt
	payload := map[string]any{
		// Canonical message-level fields:
		"evidence_type":     "tenant_membership_granted",
		"source_event_type": "chora.identity.tenant_membership.granted.v1",
		"recorded_at":       recorded,
		"policy_reference":  "ADR-194 D1 (operator cross-tenant grant)",
		// Envelope-borne IMDA fields (encodeEnvelope reads these from payload):
		"chora_imda_dimension": "accountability",
		"imda_lifecycle_stage": "runtime",
		// AdditionalFields flattened by RecordEvidence (free-form context):
		"operator_gcid":    "gcid-operator",
		"grantee_gcid":     env.GCID,
		"target_tenant_id": env.TenantID,
		"granted_roles":    []string{"OWNER", "INSTRUCTOR"},
		"cross_tenant":     true,
	}
	bz, err := protomarshal.MarshalPayload("chora.governance.evidence.recorded.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	var msg governancev1.EvidenceRecorded
	if err := proto.Unmarshal(bz, &msg); err != nil {
		t.Fatalf("proto.Unmarshal EvidenceRecorded: %v", err)
	}

	// IMDA dimension + lifecycle stage ride the shared envelope (fields 14/15).
	if got := msg.GetEnvelope().GetChoraImdaDimension(); got != "accountability" {
		t.Fatalf("envelope.chora_imda_dimension: got %q", got)
	}
	if got := msg.GetEnvelope().GetImdaLifecycleStage(); got != "runtime" {
		t.Fatalf("envelope.imda_lifecycle_stage: got %q", got)
	}

	// Message-level fields.
	if got := msg.GetEvidenceType(); got != "tenant_membership_granted" {
		t.Fatalf("evidence_type: got %q", got)
	}
	if got := msg.GetSourceEventType(); got != "chora.identity.tenant_membership.granted.v1" {
		t.Fatalf("source_event_type: got %q", got)
	}
	if got := msg.GetRecordedAt(); got == nil || got.AsTime().Unix() != recorded.Unix() {
		t.Fatalf("recorded_at: got %+v", got)
	}
	if got := msg.GetPolicyReference(); got != "ADR-194 D1 (operator cross-tenant grant)" {
		t.Fatalf("policy_reference: got %q", got)
	}

	// additional_fields — free-form context rendered to string values.
	af := msg.GetAdditionalFields()
	if got := af["operator_gcid"]; got != "gcid-operator" {
		t.Fatalf("additional_fields[operator_gcid]: got %q", got)
	}
	if got := af["grantee_gcid"]; got != env.GCID {
		t.Fatalf("additional_fields[grantee_gcid]: got %q", got)
	}
	if got := af["target_tenant_id"]; got != env.TenantID {
		t.Fatalf("additional_fields[target_tenant_id]: got %q", got)
	}
	if got := af["granted_roles"]; got != "OWNER,INSTRUCTOR" {
		t.Fatalf("additional_fields[granted_roles] (string-rendered []string): got %q", got)
	}
	if got := af["cross_tenant"]; got != "true" {
		t.Fatalf("additional_fields[cross_tenant] (string-rendered bool): got %q", got)
	}

	// Reserved keys MUST NOT leak into additional_fields (no double-encode with
	// the dedicated message-level / envelope fields).
	for _, reserved := range []string{
		"evidence_type", "source_event_type", "recorded_at", "policy_reference",
		"chora_imda_dimension", "imda_lifecycle_stage",
	} {
		if _, present := af[reserved]; present {
			t.Fatalf("additional_fields leaked reserved key %q", reserved)
		}
	}
}
