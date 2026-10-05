// wire_compat_test verifies the binary bytes emitted by MarshalPayload parse
// cleanly into the generated proto types from chora-contracts. This is the
// load-bearing assertion — if these tests pass, the event-bus schema contract
// will accept the bytes.
//
// We exercise the highest-traffic chora-identity topics (user_mana.{debited,
// refunded,credited,snapshot_taken}, kyc.{submitted,verified,rejected},
// user_subscription.{created,cancelled,renewed,plan_changed}, role.granted,
// account.lifecycle_changed) end-to-end through proto.Unmarshal.
package protomarshal_test

import (
	"encoding/json"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	identityv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/identity/v1"

	"github.com/apollo-chora/chora-identity/internal/adapter/events/protomarshal"
)

// jsonMarshal/jsonUnmarshal mirror economy_publisher.toMap so the test
// exercises exactly the production producer path.
func jsonMarshal(v any) ([]byte, error)   { return json.Marshal(v) }
func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

func wireCompatEnvelope() protomarshal.Envelope {
	t := time.Date(2026, 5, 16, 9, 30, 0, 0, time.UTC)
	return protomarshal.Envelope{
		EventID:        "01971a90-0000-7000-8000-000000000abc",
		IdempotencyKey: "idemp-wire-1",
		TenantID:       "tenant-acme",
		GCID:           "gcid-phyllis",
		OccurredAt:     t,
		PublishedAt:    t.Add(time.Millisecond),
		Traceparent:    "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
		Tracestate:     "vendor=value",
		SourceProject:  "chora-local",
		SourceService:  "chora-identity",
		SchemaVersion:  1,
	}
}

func TestWireCompat_UserManaDebited_DecodesIntoGeneratedType(t *testing.T) {
	env := wireCompatEnvelope()
	payload := map[string]any{
		"entry_id":             "01971a90-1111-7000-8000-000000000001",
		"gcid":                 env.GCID,
		"direction":            "debit",
		"units":                int64(5),
		"reason":               "familiar_action",
		"action_code":          "familiar_chat_turn",
		"source_allocation_id": "alloc-1",
		"request_id":           "req-1",
		"balance_after_units":  int64(95),
		"recorded_at":          env.OccurredAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.identity.user_mana.debited.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	var msg identityv1.UserManaDebited
	if err := proto.Unmarshal(bz, &msg); err != nil {
		t.Fatalf("proto.Unmarshal UserManaDebited: %v", err)
	}
	if got := msg.GetEnvelope().GetEventId(); got != env.EventID {
		t.Fatalf("envelope.event_id: got %q", got)
	}
	if got := msg.GetEnvelope().GetTenantId(); got != env.TenantID {
		t.Fatalf("envelope.tenant_id: got %q", got)
	}
	if got := msg.GetEnvelope().GetTraceparent(); got != env.Traceparent {
		t.Fatalf("envelope.traceparent: got %q", got)
	}
	if got := msg.GetEntryId(); got != "01971a90-1111-7000-8000-000000000001" {
		t.Fatalf("entry_id: got %q", got)
	}
	if got := msg.GetGcid(); got != env.GCID {
		t.Fatalf("gcid: got %q", got)
	}
	if got := msg.GetDirection(); got != identityv1.ManaDirection_MANA_DIRECTION_DEBIT {
		t.Fatalf("direction: got %v", got)
	}
	if got := msg.GetUnits(); got != 5 {
		t.Fatalf("units: got %d", got)
	}
	if got := msg.GetReason(); got != identityv1.ManaReason_MANA_REASON_COMPANION_ACTION {
		t.Fatalf("reason: got %v", got)
	}
	if got := msg.GetActionCode(); got != "familiar_chat_turn" {
		t.Fatalf("action_code: got %q", got)
	}
	if got := msg.GetBalanceAfterUnits(); got != 95 {
		t.Fatalf("balance_after_units: got %d", got)
	}
	if got := msg.GetRecordedAt(); got == nil || got.AsTime().Unix() != env.OccurredAt.Unix() {
		t.Fatalf("recorded_at: got %+v", got)
	}
}

func TestWireCompat_UserManaRefunded_DecodesIntoGeneratedType(t *testing.T) {
	env := wireCompatEnvelope()
	payload := map[string]any{
		"entry_id":            "01971a90-2222-7000-8000-000000000001",
		"gcid":                env.GCID,
		"direction":           "refund",
		"units":               int64(5),
		"reason":              "refund",
		"reverses_entry_id":   "01971a90-1111-7000-8000-000000000001",
		"request_id":          "req-refund-1",
		"reason_text":         "Downstream Familiar error",
		"balance_after_units": int64(100),
		"recorded_at":         env.OccurredAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.identity.user_mana.refunded.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	var msg identityv1.UserManaRefunded
	if err := proto.Unmarshal(bz, &msg); err != nil {
		t.Fatalf("proto.Unmarshal UserManaRefunded: %v", err)
	}
	if got := msg.GetReversesEntryId(); got != "01971a90-1111-7000-8000-000000000001" {
		t.Fatalf("reverses_entry_id: got %q", got)
	}
	if got := msg.GetReasonText(); got != "Downstream Familiar error" {
		t.Fatalf("reason_text: got %q", got)
	}
	if got := msg.GetDirection(); got != identityv1.ManaDirection_MANA_DIRECTION_REFUND {
		t.Fatalf("direction: got %v", got)
	}
	if got := msg.GetReason(); got != identityv1.ManaReason_MANA_REASON_REFUND {
		t.Fatalf("reason: got %v", got)
	}
}

func TestWireCompat_UserManaCredited_DecodesIntoGeneratedType(t *testing.T) {
	env := wireCompatEnvelope()
	payload := map[string]any{
		"entry_id":               "01971a90-3333-7000-8000-000000000001",
		"gcid":                   env.GCID,
		"direction":              "credit",
		"units":                  int64(100),
		"reason":                 "subscription_grant",
		"source_subscription_id": "sub-1",
		"balance_after_units":    int64(200),
		"recorded_at":            env.OccurredAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.identity.user_mana.credited.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	var msg identityv1.UserManaCredited
	if err := proto.Unmarshal(bz, &msg); err != nil {
		t.Fatalf("proto.Unmarshal UserManaCredited: %v", err)
	}
	if got := msg.GetSourceSubscriptionId(); got != "sub-1" {
		t.Fatalf("source_subscription_id: got %q", got)
	}
	if got := msg.GetReason(); got != identityv1.ManaReason_MANA_REASON_SUBSCRIPTION_GRANT {
		t.Fatalf("reason: got %v", got)
	}
}

func TestWireCompat_UserManaSnapshot_DecodesIntoGeneratedType(t *testing.T) {
	env := wireCompatEnvelope()
	payload := map[string]any{
		"gcid":            env.GCID,
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
	var msg identityv1.UserManaSnapshotTaken
	if err := proto.Unmarshal(bz, &msg); err != nil {
		t.Fatalf("proto.Unmarshal UserManaSnapshotTaken: %v", err)
	}
	if got := msg.GetBalanceUnits(); got != 200 {
		t.Fatalf("balance_units: got %d", got)
	}
	if got := msg.GetLifetimeEarned(); got != 500 {
		t.Fatalf("lifetime_earned: got %d", got)
	}
	if got := msg.GetSnapshotReason(); got != "month_end" {
		t.Fatalf("snapshot_reason: got %q", got)
	}
}

func TestWireCompat_KycSubmitted_DecodesIntoGeneratedType(t *testing.T) {
	env := wireCompatEnvelope()
	payload := map[string]any{
		"verification_id":   "ver-1",
		"gcid":              env.GCID,
		"method":            "singpass",
		"provider":          "singpass-myinfo",
		"fee_charged_cents": int64(0),
		"currency":          "SGD",
		"submitted_at":      env.OccurredAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.identity.kyc.submitted.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	var msg identityv1.KycSubmitted
	if err := proto.Unmarshal(bz, &msg); err != nil {
		t.Fatalf("proto.Unmarshal KycSubmitted: %v", err)
	}
	if got := msg.GetMethod(); got != identityv1.KycMethod_KYC_METHOD_SINGPASS {
		t.Fatalf("method: got %v", got)
	}
	if got := msg.GetCurrency(); got != "SGD" {
		t.Fatalf("currency: got %q", got)
	}
}

func TestWireCompat_KycVerified_DecodesIntoGeneratedType(t *testing.T) {
	env := wireCompatEnvelope()
	payload := map[string]any{
		"verification_id":            "ver-1",
		"gcid":                       env.GCID,
		"method":                     "skillsfuture",
		"provider":                   "skillsfuture-sg",
		"verified_by_gcid":           "gcid-admin",
		"skillsfuture_scope_granted": true,
		"verified_at":                env.OccurredAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.identity.kyc.verified.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	var msg identityv1.KycVerified
	if err := proto.Unmarshal(bz, &msg); err != nil {
		t.Fatalf("proto.Unmarshal KycVerified: %v", err)
	}
	if got := msg.GetMethod(); got != identityv1.KycMethod_KYC_METHOD_SKILLSFUTURE {
		t.Fatalf("method: got %v", got)
	}
	if !msg.GetSkillsfutureScopeGranted() {
		t.Fatal("expected skillsfuture_scope_granted=true")
	}
}

func TestWireCompat_KycRejected_DecodesIntoGeneratedType(t *testing.T) {
	env := wireCompatEnvelope()
	payload := map[string]any{
		"verification_id":  "ver-1",
		"gcid":             env.GCID,
		"method":           "manual_doc",
		"provider":         "in-house",
		"rejected_by_gcid": "gcid-admin",
		"rejection_code":   "DOC_UNREADABLE",
		"rejection_notes":  "Blurred scan",
		"retry_allowed":    true,
		"rejected_at":      env.OccurredAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.identity.kyc.rejected.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	var msg identityv1.KycRejected
	if err := proto.Unmarshal(bz, &msg); err != nil {
		t.Fatalf("proto.Unmarshal KycRejected: %v", err)
	}
	if got := msg.GetMethod(); got != identityv1.KycMethod_KYC_METHOD_MANUAL_DOC {
		t.Fatalf("method: got %v", got)
	}
	if got := msg.GetRejectionCode(); got != "DOC_UNREADABLE" {
		t.Fatalf("rejection_code: got %q", got)
	}
	if !msg.GetRetryAllowed() {
		t.Fatal("expected retry_allowed=true")
	}
}

func TestWireCompat_UserSubscriptionCreated_DecodesIntoGeneratedType(t *testing.T) {
	env := wireCompatEnvelope()
	payload := map[string]any{
		"subscription_id":        "sub-1",
		"gcid":                   env.GCID,
		"tenant_id":              env.TenantID,
		"plan_code":              "standard-monthly",
		"tier":                   "standard",
		"status":                 "active",
		"billing_period":         "monthly",
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
	var msg identityv1.UserSubscriptionCreated
	if err := proto.Unmarshal(bz, &msg); err != nil {
		t.Fatalf("proto.Unmarshal UserSubscriptionCreated: %v", err)
	}
	if got := msg.GetTier(); got != identityv1.CompanionTier_COMPANION_TIER_STANDARD {
		t.Fatalf("tier: got %v", got)
	}
	if got := msg.GetStatus(); got != identityv1.UserSubscriptionStatus_USER_SUBSCRIPTION_STATUS_ACTIVE {
		t.Fatalf("status: got %v", got)
	}
	if got := msg.GetBillingPeriod(); got != identityv1.BillingPeriod_BILLING_PERIOD_MONTHLY {
		t.Fatalf("billing_period: got %v", got)
	}
	if got := msg.GetStripeSubscriptionId(); got != "sub_stripe_abc" {
		t.Fatalf("stripe_subscription_id: got %q", got)
	}
}

func TestWireCompat_UserSubscriptionCancelled_DecodesIntoGeneratedType(t *testing.T) {
	env := wireCompatEnvelope()
	payload := map[string]any{
		"subscription_id":     "sub-1",
		"gcid":                env.GCID,
		"tenant_id":           env.TenantID,
		"plan_code":           "premium-annual",
		"tier":                "premium",
		"cancellation_reason": "USER_REQUESTED",
		"cancelled_by_gcid":   env.GCID,
		"effective_at":        env.OccurredAt.Add(30 * 24 * time.Hour),
		"cancelled_at":        env.OccurredAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.identity.user_subscription.cancelled.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	var msg identityv1.UserSubscriptionCancelled
	if err := proto.Unmarshal(bz, &msg); err != nil {
		t.Fatalf("proto.Unmarshal UserSubscriptionCancelled: %v", err)
	}
	if got := msg.GetTier(); got != identityv1.CompanionTier_COMPANION_TIER_PREMIUM {
		t.Fatalf("tier: got %v", got)
	}
	if got := msg.GetCancellationReason(); got != "USER_REQUESTED" {
		t.Fatalf("cancellation_reason: got %q", got)
	}
}

func TestWireCompat_UserSubscriptionPlanChanged_DecodesIntoGeneratedType(t *testing.T) {
	env := wireCompatEnvelope()
	payload := map[string]any{
		"subscription_id":     "sub-1",
		"gcid":                env.GCID,
		"tenant_id":           env.TenantID,
		"from_plan_code":      "basic-monthly",
		"to_plan_code":        "standard-monthly",
		"from_tier":           "basic",
		"to_tier":             "standard",
		"from_billing_period": "monthly",
		"to_billing_period":   "monthly",
		"billing_delta_cents": int64(500),
		"schedule_id":         "sched-1",
		"effective_at":        env.OccurredAt.Add(24 * time.Hour),
		"requested_by_gcid":   env.GCID,
		"changed_at":          env.OccurredAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.identity.user_subscription.plan_changed.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	var msg identityv1.UserSubscriptionPlanChanged
	if err := proto.Unmarshal(bz, &msg); err != nil {
		t.Fatalf("proto.Unmarshal UserSubscriptionPlanChanged: %v", err)
	}
	if got := msg.GetFromTier(); got != identityv1.CompanionTier_COMPANION_TIER_BASIC {
		t.Fatalf("from_tier: got %v", got)
	}
	if got := msg.GetToTier(); got != identityv1.CompanionTier_COMPANION_TIER_STANDARD {
		t.Fatalf("to_tier: got %v", got)
	}
	if got := msg.GetBillingDeltaCents(); got != 500 {
		t.Fatalf("billing_delta_cents: got %d", got)
	}
}

func TestWireCompat_RoleGranted_DecodesIntoGeneratedType(t *testing.T) {
	env := wireCompatEnvelope()
	payload := map[string]any{
		"role_assignment_id": "ra-1",
		"gcid":               env.GCID,
		"tenant_id":          env.TenantID,
		"course_id":          "course-1",
		"role":               "instructor",
		"source":             "course_creation",
		"source_event_id":    "evt-create-1",
		"granted_by_gcid":    env.GCID,
		"granted_at":         env.OccurredAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.identity.role.granted.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	var msg identityv1.RoleGranted
	if err := proto.Unmarshal(bz, &msg); err != nil {
		t.Fatalf("proto.Unmarshal RoleGranted: %v", err)
	}
	if got := msg.GetRole(); got != identityv1.CourseRole_COURSE_ROLE_INSTRUCTOR {
		t.Fatalf("role: got %v", got)
	}
	if got := msg.GetSource(); got != identityv1.RoleGrantSource_ROLE_GRANT_SOURCE_COURSE_CREATION {
		t.Fatalf("source: got %v", got)
	}
	if got := msg.GetCourseId(); got != "course-1" {
		t.Fatalf("course_id: got %q", got)
	}
}

// TestWireCompat_TomMapJSONRoundtripped_DecodesIntoGeneratedType verifies the
// real economy_publisher.toMap producer path: typed payload → json.Marshal →
// json.Unmarshal into map[string]any → MarshalPayload. After the JSON round-
// trip, time.Time becomes RFC3339Nano string and int64 becomes float64. The
// encoder MUST reconstitute both so the wire bytes still decode cleanly.
func TestWireCompat_ToMapJSONRoundtripped_DecodesIntoGeneratedType(t *testing.T) {
	env := wireCompatEnvelope()

	// Source-typed payload (mirrors user_mana.LedgerEntryPayloadFrom output).
	type entryPayload struct {
		EntryID           string    `json:"entry_id"`
		Gcid              string    `json:"gcid"`
		Direction         string    `json:"direction"`
		Units             int64     `json:"units"`
		Reason            string    `json:"reason"`
		ActionCode        string    `json:"action_code,omitempty"`
		BalanceAfterUnits int64     `json:"balance_after_units"`
		RecordedAt        time.Time `json:"recorded_at"`
	}
	src := entryPayload{
		EntryID:           "01971a90-1111-7000-8000-000000000001",
		Gcid:              env.GCID,
		Direction:         "debit",
		Units:             5,
		Reason:            "familiar_action",
		ActionCode:        "familiar_chat_turn",
		BalanceAfterUnits: 95,
		RecordedAt:        env.OccurredAt,
	}

	raw, err := jsonMarshal(src)
	if err != nil {
		t.Fatalf("jsonMarshal: %v", err)
	}
	payload := map[string]any{}
	if err := jsonUnmarshal(raw, &payload); err != nil {
		t.Fatalf("jsonUnmarshal: %v", err)
	}
	// At this point payload["units"] = float64(5), payload["recorded_at"] = string("2026-05-16T09:30:00Z").

	bz, err := protomarshal.MarshalPayload("chora.identity.user_mana.debited.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	var msg identityv1.UserManaDebited
	if err := proto.Unmarshal(bz, &msg); err != nil {
		t.Fatalf("proto.Unmarshal: %v", err)
	}
	if got := msg.GetUnits(); got != 5 {
		t.Fatalf("units (after JSON roundtrip): got %d", got)
	}
	if got := msg.GetDirection(); got != identityv1.ManaDirection_MANA_DIRECTION_DEBIT {
		t.Fatalf("direction: got %v", got)
	}
	if got := msg.GetActionCode(); got != "familiar_chat_turn" {
		t.Fatalf("action_code: got %q", got)
	}
	if got := msg.GetRecordedAt(); got == nil || got.AsTime().Unix() != env.OccurredAt.Unix() {
		t.Fatalf("recorded_at (after JSON roundtrip): got %+v", got)
	}
}

func TestWireCompat_AccountLifecycleChanged_DecodesIntoGeneratedType(t *testing.T) {
	env := wireCompatEnvelope()
	payload := map[string]any{
		"account_id":      "acct-1",
		"gcid":            env.GCID,
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
	var msg identityv1.AccountLifecycleChanged
	if err := proto.Unmarshal(bz, &msg); err != nil {
		t.Fatalf("proto.Unmarshal AccountLifecycleChanged: %v", err)
	}
	if got := msg.GetPriorState(); got != identityv1.AccountState_ACCOUNT_STATE_ACTIVE {
		t.Fatalf("prior_state: got %v", got)
	}
	if got := msg.GetNewState(); got != identityv1.AccountState_ACCOUNT_STATE_CLOSING {
		t.Fatalf("new_state: got %v", got)
	}
	if got := msg.GetSagaId(); got != "saga-1" {
		t.Fatalf("saga_id: got %q", got)
	}
}
