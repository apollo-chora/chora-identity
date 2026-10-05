// Package protomarshal_test verifies binary protobuf wire-format encoding for
// chora-identity's outbox event payloads. RED tests written BEFORE the
// encoder lands per CLAUDE.md §development-execution + feedback_strict_tdd.
//
// Gap: outbox writer was persisting JSON-marshalled payload bytes that the
// event-bus schema contract (BINARY encoding) rejects at publish time with
// "Invalid binary proto message". Fix is producer-side: marshal to canonical
// proto wire bytes before the outbox row is written. Dispatcher passes bytes
// through unchanged.
//
// Field-tag-walk tests cover every chora.identity.* topic emitted by this
// service. wire_compat_test.go additionally round-trips select topics
// through the generated chora-contracts/gen/go/chora/identity/v1 types.
package protomarshal_test

import (
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/apollo-chora/chora-identity/internal/adapter/events/protomarshal"
)

// fixedEnvelope returns an envelope with deterministic values for byte-level
// assertions.
func fixedEnvelope() protomarshal.Envelope {
	t := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	return protomarshal.Envelope{
		EventID:        "01971a90-0000-7000-8000-000000000001",
		IdempotencyKey: "idemp-1",
		TenantID:       "tenant-1",
		GCID:           "gcid-phyllis",
		OccurredAt:     t,
		PublishedAt:    t.Add(time.Millisecond),
		Traceparent:    "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
		Tracestate:     "",
		SourceProject:  "chora-local",
		SourceService:  "chora-identity",
		SchemaVersion:  1,
	}
}

// walkTags consumes every top-level wire tag in bz; returns the set of field
// numbers seen plus any structural error. Fails the test on bad TLV.
func walkTags(t *testing.T, bz []byte) map[protowire.Number]bool {
	t.Helper()
	seen := map[protowire.Number]bool{}
	rem := bz
	for len(rem) > 0 {
		num, typ, n := protowire.ConsumeTag(rem)
		if n < 0 {
			t.Fatalf("invalid tag at offset %d", len(bz)-len(rem))
		}
		rem = rem[n:]
		seen[num] = true
		switch typ {
		case protowire.BytesType:
			_, m := protowire.ConsumeBytes(rem)
			if m < 0 {
				t.Fatalf("invalid length-delimited value for field %d", num)
			}
			rem = rem[m:]
		case protowire.VarintType:
			_, m := protowire.ConsumeVarint(rem)
			if m < 0 {
				t.Fatalf("invalid varint value for field %d", num)
			}
			rem = rem[m:]
		default:
			t.Fatalf("unexpected wire type %d for field %d", typ, num)
		}
	}
	return seen
}

// -----------------------------------------------------------------------------
// User Mana — credited / debited / refunded
// Schema: chora-contracts/proto/events-flat/identity/user_mana/{c,d,r}.proto
//
//	1  bytes  Envelope
//	2  string entry_id
//	3  string gcid
//	4  varint ManaDirection direction
//	5  varint int64 units
//	6  varint ManaReason reason
//	7  string (credited: source_subscription_id  | debited: action_code | refunded: reverses_entry_id)
//	8  string (credited: source_topup_id         | debited: source_allocation_id | refunded: request_id)
//	9  string (credited: source_allocation_id    | debited: request_id           | refunded: reason_text)
//	10 varint int64 balance_after_units
//	11 bytes  Timestamp recorded_at
// -----------------------------------------------------------------------------

func TestMarshalUserManaDebited_RoundTripsBinaryProto(t *testing.T) {
	env := fixedEnvelope()
	recorded := env.OccurredAt
	payload := map[string]any{
		"entry_id":             "01971a90-1111-7000-8000-000000000001",
		"gcid":                 "gcid-phyllis",
		"direction":            "debit", // → MANA_DIRECTION_DEBIT (2)
		"units":                int64(5),
		"reason":               "familiar_action", // → MANA_REASON_FAMILIAR_ACTION (2)
		"source_allocation_id": "alloc-1",
		"source_action_id":     "act-chat-turn",
		"balance_after_units":  int64(95),
		"recorded_at":          recorded,
	}
	bz, err := protomarshal.MarshalPayload("chora.identity.user_mana.debited.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	if len(bz) == 0 {
		t.Fatal("empty bytes")
	}
	seen := walkTags(t, bz)
	required := []protowire.Number{1 /*envelope*/, 2 /*entry_id*/, 3 /*gcid*/, 4 /*direction*/, 5 /*units*/, 6 /*reason*/, 10 /*balance_after_units*/, 11 /*recorded_at*/}
	for _, want := range required {
		if !seen[want] {
			t.Fatalf("UserManaDebited: missing field %d (seen: %v)", want, seen)
		}
	}
}

func TestMarshalUserManaRefunded_RoundTripsBinaryProto(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"entry_id":            "01971a90-2222-7000-8000-000000000001",
		"gcid":                "gcid-phyllis",
		"direction":           "refund", // → MANA_DIRECTION_REFUND (4)
		"units":               int64(5),
		"reason":              "refund", // → MANA_REASON_REFUND (3)
		"reverses_entry_id":   "01971a90-1111-7000-8000-000000000001",
		"request_id":          "req-refund-1",
		"reason_text":         "Familiar chat downstream error",
		"balance_after_units": int64(100),
		"recorded_at":         env.OccurredAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.identity.user_mana.refunded.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	seen := walkTags(t, bz)
	required := []protowire.Number{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	for _, want := range required {
		if !seen[want] {
			t.Fatalf("UserManaRefunded: missing field %d (seen: %v)", want, seen)
		}
	}
}

func TestMarshalUserManaCredited_RoundTripsBinaryProto(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"entry_id":               "01971a90-3333-7000-8000-000000000001",
		"gcid":                   "gcid-phyllis",
		"direction":              "credit", // → 1
		"units":                  int64(100),
		"reason":                 "subscription_grant", // → 1
		"source_subscription_id": "sub-1",
		"balance_after_units":    int64(200),
		"recorded_at":            env.OccurredAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.identity.user_mana.credited.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	seen := walkTags(t, bz)
	for _, want := range []protowire.Number{1, 2, 3, 4, 5, 6, 7, 10, 11} {
		if !seen[want] {
			t.Fatalf("UserManaCredited: missing field %d", want)
		}
	}
}

func TestMarshalUserManaSnapshot_RoundTripsBinaryProto(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"gcid":            "gcid-phyllis",
		"balance_units":   int64(200),
		"lifetime_earned": int64(500),
		"lifetime_spent":  int64(300),
		"snapshot_reason": "month_end",
		"snapshot_at":     env.OccurredAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.identity.user_mana.snapshot_taken.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	seen := walkTags(t, bz)
	for _, want := range []protowire.Number{1, 2, 3, 4, 5, 6, 7} {
		if !seen[want] {
			t.Fatalf("UserManaSnapshotTaken: missing field %d", want)
		}
	}
}

// -----------------------------------------------------------------------------
// KYC — submitted / verified / rejected
// Schema: chora-contracts/proto/events-flat/identity/kyc/{s,v,r}.proto
// -----------------------------------------------------------------------------

func TestMarshalKycSubmitted_RoundTripsBinaryProto(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"verification_id":   "ver-1",
		"gcid":              "gcid-phyllis",
		"method":            "singpass", // → KYC_METHOD_SINGPASS (1)
		"provider":          "singpass-myinfo",
		"document_uri":      "",
		"fee_charged_cents": int64(0),
		"currency":          "SGD",
		"submitted_at":      env.OccurredAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.identity.kyc.submitted.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	seen := walkTags(t, bz)
	for _, want := range []protowire.Number{1, 2, 3, 4, 5, 8, 9} {
		if !seen[want] {
			t.Fatalf("KycSubmitted: missing field %d", want)
		}
	}
}

func TestMarshalKycVerified_RoundTripsBinaryProto(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"verification_id":            "ver-1",
		"gcid":                       "gcid-phyllis",
		"method":                     "singpass",
		"provider":                   "singpass-myinfo",
		"verified_by_gcid":           "gcid-admin",
		"skillsfuture_scope_granted": true,
		"verified_at":                env.OccurredAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.identity.kyc.verified.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	seen := walkTags(t, bz)
	for _, want := range []protowire.Number{1, 2, 3, 4, 5, 6, 7, 8} {
		if !seen[want] {
			t.Fatalf("KycVerified: missing field %d", want)
		}
	}
}

func TestMarshalKycRejected_RoundTripsBinaryProto(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"verification_id":  "ver-1",
		"gcid":             "gcid-phyllis",
		"method":           "manual_doc", // → KYC_METHOD_MANUAL_DOC (3)
		"provider":         "in-house",
		"rejected_by_gcid": "gcid-admin",
		"rejection_code":   "DOCUMENT_UNREADABLE",
		"rejection_notes":  "Blurred passport scan",
		"retry_allowed":    true,
		"rejected_at":      env.OccurredAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.identity.kyc.rejected.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	seen := walkTags(t, bz)
	for _, want := range []protowire.Number{1, 2, 3, 4, 5, 6, 7, 8, 9, 10} {
		if !seen[want] {
			t.Fatalf("KycRejected: missing field %d", want)
		}
	}
}

// -----------------------------------------------------------------------------
// User Subscription — created / cancelled / renewed / plan_changed
// -----------------------------------------------------------------------------

func TestMarshalUserSubscriptionCreated_RoundTripsBinaryProto(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"subscription_id":        "sub-1",
		"gcid":                   "gcid-phyllis",
		"tenant_id":              "tenant-1",
		"plan_code":              "standard-monthly",
		"tier":                   "standard", // → FAMILIAR_TIER_STANDARD (2)
		"status":                 "active",   // → USER_SUBSCRIPTION_STATUS_ACTIVE (2)
		"billing_period":         "monthly",  // → BILLING_PERIOD_MONTHLY (1)
		"current_period_start":   env.OccurredAt,
		"current_period_end":     env.OccurredAt.Add(30 * 24 * time.Hour),
		"stripe_subscription_id": "sub_stripe_abc",
		"mana_monthly_units":     int64(500),
		"onboarding_bonus_units": int64(100),
		"created_at":             env.OccurredAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.identity.user_subscription.created.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	seen := walkTags(t, bz)
	for _, want := range []protowire.Number{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14} {
		if !seen[want] {
			t.Fatalf("UserSubscriptionCreated: missing field %d", want)
		}
	}
}

func TestMarshalUserSubscriptionCancelled_RoundTripsBinaryProto(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"subscription_id":     "sub-1",
		"gcid":                "gcid-phyllis",
		"tenant_id":           "tenant-1",
		"plan_code":           "standard-monthly",
		"tier":                "standard",
		"cancellation_reason": "USER_REQUESTED",
		"cancelled_by_gcid":   "gcid-phyllis",
		"effective_at":        env.OccurredAt.Add(30 * 24 * time.Hour),
		"cancelled_at":        env.OccurredAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.identity.user_subscription.cancelled.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	seen := walkTags(t, bz)
	for _, want := range []protowire.Number{1, 2, 3, 4, 5, 6, 7, 8, 9, 10} {
		if !seen[want] {
			t.Fatalf("UserSubscriptionCancelled: missing field %d", want)
		}
	}
}

func TestMarshalUserSubscriptionRenewed_RoundTripsBinaryProto(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"subscription_id":        "sub-1",
		"gcid":                   "gcid-phyllis",
		"tenant_id":              "tenant-1",
		"plan_code":              "standard-monthly",
		"tier":                   "standard",
		"billing_period":         "monthly",
		"prior_period_end":       env.OccurredAt.Add(-1 * time.Second),
		"current_period_start":   env.OccurredAt,
		"current_period_end":     env.OccurredAt.Add(30 * 24 * time.Hour),
		"stripe_subscription_id": "sub_stripe_abc",
		"mana_monthly_units":     int64(500),
		"renewed_at":             env.OccurredAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.identity.user_subscription.renewed.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	seen := walkTags(t, bz)
	for _, want := range []protowire.Number{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13} {
		if !seen[want] {
			t.Fatalf("UserSubscriptionRenewed: missing field %d", want)
		}
	}
}

func TestMarshalUserSubscriptionPlanChanged_RoundTripsBinaryProto(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"subscription_id":     "sub-1",
		"gcid":                "gcid-phyllis",
		"tenant_id":           "tenant-1",
		"from_plan_code":      "basic-monthly",
		"to_plan_code":        "standard-monthly",
		"from_tier":           "basic",
		"to_tier":             "standard",
		"from_billing_period": "monthly",
		"to_billing_period":   "monthly",
		"billing_delta_cents": int64(500),
		"schedule_id":         "sched-1",
		"effective_at":        env.OccurredAt.Add(24 * time.Hour),
		"requested_by_gcid":   "gcid-phyllis",
		"changed_at":          env.OccurredAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.identity.user_subscription.plan_changed.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	seen := walkTags(t, bz)
	for _, want := range []protowire.Number{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} {
		if !seen[want] {
			t.Fatalf("UserSubscriptionPlanChanged: missing field %d", want)
		}
	}
}

// -----------------------------------------------------------------------------
// Role granted — chora.identity.role.granted.v1
// -----------------------------------------------------------------------------

func TestMarshalRoleGranted_RoundTripsBinaryProto(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"role_assignment_id": "ra-1",
		"gcid":               "gcid-phyllis",
		"tenant_id":          "tenant-1",
		"course_id":          "course-1",
		"role":               "learner",   // → COURSE_ROLE_LEARNER (1)
		"source":             "enrolment", // → ROLE_GRANT_SOURCE_ENROLMENT (1)
		"source_event_id":    "evt-enroll-1",
		"granted_by_gcid":    "gcid-system",
		"granted_at":         env.OccurredAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.identity.role.granted.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	seen := walkTags(t, bz)
	for _, want := range []protowire.Number{1, 2, 3, 4, 5, 6, 7, 8, 9, 10} {
		if !seen[want] {
			t.Fatalf("RoleGranted: missing field %d", want)
		}
	}
}

// -----------------------------------------------------------------------------
// Account lifecycle_changed — chora.identity.account.lifecycle_changed.v1
// -----------------------------------------------------------------------------

func TestMarshalAccountLifecycleChanged_RoundTripsBinaryProto(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"account_id":      "acct-1",
		"gcid":            "gcid-phyllis",
		"prior_state":     "active",
		"new_state":       "closing",
		"reason":          "USER_REQUESTED_CLOSURE",
		"dek_id":          "dek-1",
		"saga_id":         "saga-1",
		"transitioned_at": env.OccurredAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.identity.account.lifecycle_changed.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	seen := walkTags(t, bz)
	for _, want := range []protowire.Number{1, 2, 3, 4, 5, 6, 7, 8, 9} {
		if !seen[want] {
			t.Fatalf("AccountLifecycleChanged: missing field %d", want)
		}
	}
}

// -----------------------------------------------------------------------------
// Envelope shape — every encoded topic emits the canonical envelope nested
// fields 1..15.
// -----------------------------------------------------------------------------

func TestMarshalUserManaDebited_EnvelopeIsWireCompatible(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"entry_id":            "e-1",
		"gcid":                env.GCID,
		"direction":           "debit",
		"units":               int64(1),
		"reason":              "familiar_action",
		"balance_after_units": int64(99),
		"recorded_at":         env.OccurredAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.identity.user_mana.debited.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}

	num, typ, n := protowire.ConsumeTag(bz)
	if num != 1 || typ != protowire.BytesType || n < 0 {
		t.Fatalf("expected envelope tag (1, bytes), got num=%d typ=%d", num, typ)
	}
	envBytes, m := protowire.ConsumeBytes(bz[n:])
	if m < 0 {
		t.Fatal("invalid envelope bytes")
	}
	seen := walkTags(t, envBytes)
	required := []protowire.Number{1, 2, 3, 4, 5, 6, 7, 9, 10, 11}
	for _, want := range required {
		if !seen[want] {
			t.Fatalf("envelope: missing required field %d (seen: %v)", want, seen)
		}
	}
}

// -----------------------------------------------------------------------------
// Error contracts: unknown topic + type mismatch fail loud.
// -----------------------------------------------------------------------------

func TestMarshal_UnknownTopic_FailsLoud(t *testing.T) {
	env := fixedEnvelope()
	_, err := protomarshal.MarshalPayload("chora.identity.some.unwired.v1", env, nil)
	if err == nil {
		t.Fatal("expected ErrUnsupportedTopic, got nil")
	}
	if !protomarshal.IsUnsupportedTopic(err) {
		t.Fatalf("expected IsUnsupportedTopic(true), got: %v", err)
	}
}

func TestMarshal_UserManaDebited_RejectsInvalidUnits(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"entry_id": "e-1",
		"gcid":     env.GCID,
		"units":    "not-a-number", // schema demands int64
	}
	_, err := protomarshal.MarshalPayload("chora.identity.user_mana.debited.v1", env, payload)
	if err == nil {
		t.Fatal("expected type error for units=string")
	}
}

func TestMarshal_UserManaDebited_RejectsInvalidRecordedAt(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"entry_id":    "e-1",
		"gcid":        env.GCID,
		"recorded_at": "not-a-time", // schema demands time.Time
	}
	_, err := protomarshal.MarshalPayload("chora.identity.user_mana.debited.v1", env, payload)
	if err == nil {
		t.Fatal("expected type error for recorded_at=string")
	}
}

func TestMarshal_KycSubmitted_RejectsInvalidMethod(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"verification_id": "v-1",
		"gcid":            env.GCID,
		"method":          "not-an-enum-value",
		"submitted_at":    env.OccurredAt,
	}
	_, err := protomarshal.MarshalPayload("chora.identity.kyc.submitted.v1", env, payload)
	if err == nil {
		t.Fatal("expected error for unknown kyc method")
	}
}

func TestMarshal_NilPayloadProducesEnvelopeOnly(t *testing.T) {
	env := fixedEnvelope()
	bz, err := protomarshal.MarshalPayload("chora.identity.user_mana.debited.v1", env, nil)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	if len(bz) == 0 {
		t.Fatal("nil payload should still produce envelope bytes")
	}
	num, _, n := protowire.ConsumeTag(bz)
	if n < 0 {
		t.Fatal("invalid leading tag")
	}
	if num != 1 {
		t.Fatalf("expected leading field=1 (envelope), got %d", num)
	}
}

func TestMarshal_AcceptsTimePointer(t *testing.T) {
	env := fixedEnvelope()
	now := env.OccurredAt
	payload := map[string]any{
		"entry_id":            "e-1",
		"gcid":                env.GCID,
		"direction":           "debit",
		"units":               int64(1),
		"reason":              "familiar_action",
		"balance_after_units": int64(99),
		"recorded_at":         &now,
	}
	bz, err := protomarshal.MarshalPayload("chora.identity.user_mana.debited.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload with *time.Time: %v", err)
	}
	if len(bz) == 0 {
		t.Fatal("empty bytes")
	}
}
