// Package protomarshal encodes chora-identity outbox event payloads to
// canonical binary protobuf wire format so the event-bus schema contract
// validation (BINARY encoding) passes at publish time.
//
// Why hand-rolled
// ---------------
// Generated Go bindings exist in chora-contracts/gen/go/chora/identity/v1
// for every chora.identity.{user_mana, user_subscription, kyc, role,
// account, tenancy_membership, gcid, agid}.*.v1 topic, but we still emit
// from `map[string]any` payloads to keep the events.Publisher port intact
// (call sites do not depend on the generated structs). We use
// google.golang.org/protobuf/encoding/protowire to emit canonical wire
// bytes for the exact subset of fields each Schema Registry schema
// expects.
//
// Field numbers + wire types are pinned to chora-contracts/proto/events-flat/
// identity/* — those flat protos ARE the Schema Registry schemas.
//
// Invariants per the Schema Registry binary-encoded protos:
//
//   - Field 1 = envelope (length-delimited nested message)
//   - Envelope nested fields 1..15 follow chora.common.v1.EventEnvelope layout
//   - Timestamps are nested messages: int64 seconds (field 1) + int32 nanos
//     (field 2)
//   - Enum fields are varints with the canonical proto enum NUMBER
//   - Unknown topics fail loud (ErrUnsupportedTopic) so the dispatcher
//     dead-letters rather than retrying forever against a schema mismatch
//
// Per CLAUDE.md §6 — wire format MUST be binary protobuf for Pub/Sub-attached
// topics. JSON encoding is rejected at publish time with "Invalid binary proto
// message".
package protomarshal

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
)

// Envelope is the producer-side flat shape of chora.common.v1.EventEnvelope
// that the encoder needs. Mirrors services/chora-identity/internal/adapter/
// events.Envelope; defined locally to keep this package import-cycle-free.
type Envelope struct {
	EventID        string
	IdempotencyKey string
	TenantID       string
	GCID           string
	OccurredAt     time.Time
	PublishedAt    time.Time
	Traceparent    string
	Tracestate     string
	SourceProject  string
	SourceService  string
	SchemaVersion  int32
}

// ErrUnsupportedTopic is returned by MarshalPayload when the topic has no
// registered binary encoder. The dispatcher should dead-letter rows that
// surface this error rather than retrying forever — the row is structurally
// incompatible with its destination schema.
var ErrUnsupportedTopic = errors.New("protomarshal: topic has no binary encoder; outbox row will dead-letter")

// IsUnsupportedTopic reports whether err is (or wraps) ErrUnsupportedTopic.
func IsUnsupportedTopic(err error) bool { return errors.Is(err, ErrUnsupportedTopic) }

// MarshalPayload converts a topic + envelope + loose payload map into the
// canonical binary protobuf wire bytes for that topic's Schema Registry
// schema. Returns ErrUnsupportedTopic if no encoder is registered for the
// supplied topic.
//
// Topics with registered encoders:
//
//   - chora.identity.user_mana.{credited,debited,refunded,snapshot_taken}.v1
//   - chora.identity.kyc.{submitted,verified,rejected}.v1
//   - chora.identity.user_subscription.{created,cancelled,renewed,plan_changed}.v1
//   - chora.identity.role.granted.v1
//   - chora.identity.account.lifecycle_changed.v1
//   - chora.identity.gcid.resolved.v1
//   - chora.identity.tenant_idp_provider.configured.v1
//   - chora.governance.evidence.recorded.v1 (governance-domain topic; identity
//     is a producer and owns this outbox encoder)
//
// Adding more topics: append a case to the switch + implement
// encode{X}(env, payload) returning the wire bytes.
func MarshalPayload(topic string, env Envelope, payload map[string]any) ([]byte, error) {
	switch topic {
	// User Mana
	case "chora.identity.user_mana.credited.v1":
		return encodeUserManaCredited(env, payload)
	case "chora.identity.user_mana.debited.v1":
		return encodeUserManaDebited(env, payload)
	case "chora.identity.user_mana.refunded.v1":
		return encodeUserManaRefunded(env, payload)
	case "chora.identity.user_mana.snapshot_taken.v1":
		return encodeUserManaSnapshotTaken(env, payload)
	// KYC
	case "chora.identity.kyc.submitted.v1":
		return encodeKycSubmitted(env, payload)
	case "chora.identity.kyc.verified.v1":
		return encodeKycVerified(env, payload)
	case "chora.identity.kyc.rejected.v1":
		return encodeKycRejected(env, payload)
	// User Subscription
	case "chora.identity.user_subscription.created.v1":
		return encodeUserSubscriptionCreated(env, payload)
	case "chora.identity.user_subscription.cancelled.v1":
		return encodeUserSubscriptionCancelled(env, payload)
	case "chora.identity.user_subscription.renewed.v1":
		return encodeUserSubscriptionRenewed(env, payload)
	case "chora.identity.user_subscription.plan_changed.v1":
		return encodeUserSubscriptionPlanChanged(env, payload)
	// Role / Account
	case "chora.identity.role.granted.v1":
		return encodeRoleGranted(env, payload)
	case "chora.identity.account.lifecycle_changed.v1":
		return encodeAccountLifecycleChanged(env, payload)
	// GCID resolve (Class D contract paydown — event-fabric audit 2026-07-01)
	case "chora.identity.gcid.resolved.v1":
		return encodeGcidResolved(env, payload)
	// Tenant IdP provider config (Class D contract paydown — 2026-07-01)
	case "chora.identity.tenant_idp_provider.configured.v1":
		return encodeTenantIdpProviderConfigured(env, payload)
	// IMDA evidence — governance-DOMAIN topic, but chora-identity is a producer
	// and owns this outbox encoder (Class D contract paydown — 2026-07-01).
	case "chora.governance.evidence.recorded.v1":
		return encodeEvidenceRecorded(env, payload)
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedTopic, topic)
	}
}

// -----------------------------------------------------------------------------
// Envelope (nested in every event message; field layout matches
// chora.common.v1.EventEnvelope as flattened by chora-contracts/internal/
// protoflatten and embedded as a NESTED type in every events-flat schema).
// -----------------------------------------------------------------------------
//
//	1  string event_id
//	2  string idempotency_key
//	3  string tenant_id
//	4  string gcid
//	5  bytes  Timestamp occurred_at
//	6  bytes  Timestamp published_at
//	7  string traceparent
//	8  string tracestate
//	9  string source_project
//	10 string source_service
//	11 varint int32 schema_version
//	12 string correlation_id
//	13 string causation_id
//	14 string chora_imda_dimension
//	15 string imda_lifecycle_stage
func encodeEnvelope(env Envelope, payload map[string]any) ([]byte, error) {
	out := make([]byte, 0, 256)

	if env.EventID != "" {
		out = appendString(out, 1, env.EventID)
	}
	if env.IdempotencyKey != "" {
		out = appendString(out, 2, env.IdempotencyKey)
	}
	if env.TenantID != "" {
		out = appendString(out, 3, env.TenantID)
	}
	if env.GCID != "" {
		out = appendString(out, 4, env.GCID)
	}
	if !env.OccurredAt.IsZero() {
		out = appendLengthDelimited(out, 5, encodeTimestamp(env.OccurredAt))
	}
	if !env.PublishedAt.IsZero() {
		out = appendLengthDelimited(out, 6, encodeTimestamp(env.PublishedAt))
	}
	if env.Traceparent != "" {
		out = appendString(out, 7, env.Traceparent)
	}
	if env.Tracestate != "" {
		out = appendString(out, 8, env.Tracestate)
	}
	if env.SourceProject != "" {
		out = appendString(out, 9, env.SourceProject)
	}
	if env.SourceService != "" {
		out = appendString(out, 10, env.SourceService)
	}
	if env.SchemaVersion > 0 {
		out = appendVarint(out, 11, uint64(uint32(env.SchemaVersion)))
	}

	// Optional IMDA evidence fields sourced from the payload.
	if payload != nil {
		if v, ok := payload["correlation_id"].(string); ok && v != "" {
			out = appendString(out, 12, v)
		}
		if v, ok := payload["causation_id"].(string); ok && v != "" {
			out = appendString(out, 13, v)
		}
		if v, ok := payload["chora_imda_dimension"].(string); ok && v != "" {
			out = appendString(out, 14, v)
		}
		if v, ok := payload["imda_lifecycle_stage"].(string); ok && v != "" {
			out = appendString(out, 15, v)
		}
	}

	return out, nil
}

// -----------------------------------------------------------------------------
// User Mana — UserManaCredited
//
//	 1 bytes  Envelope envelope
//	 2 string entry_id
//	 3 string gcid
//	 4 varint ManaDirection direction
//	 5 varint int64 units
//	 6 varint ManaReason reason
//	 7 string source_subscription_id
//	 8 string source_topup_id
//	 9 string source_allocation_id
//	10 varint int64 balance_after_units
//	11 bytes  Timestamp recorded_at
//
// -----------------------------------------------------------------------------
func encodeUserManaCredited(env Envelope, payload map[string]any) ([]byte, error) {
	out := make([]byte, 0, 256)
	envBz, err := encodeEnvelope(env, payload)
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	out = appendLengthDelimited(out, 1, envBz)
	if payload == nil {
		return out, nil
	}
	enc := newFieldEncoder(out, payload)
	enc.optString(2, "entry_id")
	enc.optString(3, "gcid")
	if err := enc.optEnumString(4, "direction", manaDirectionEnum); err != nil {
		return nil, err
	}
	if err := enc.optInt64(5, "units"); err != nil {
		return nil, err
	}
	if err := enc.optEnumString(6, "reason", manaReasonEnum); err != nil {
		return nil, err
	}
	enc.optString(7, "source_subscription_id")
	enc.optString(8, "source_topup_id")
	enc.optString(9, "source_allocation_id")
	if err := enc.optInt64(10, "balance_after_units"); err != nil {
		return nil, err
	}
	if err := enc.optTimestamp(11, "recorded_at"); err != nil {
		return nil, err
	}
	return enc.out, nil
}

// -----------------------------------------------------------------------------
// User Mana — UserManaDebited
//
//	 1 bytes  Envelope envelope
//	 2 string entry_id
//	 3 string gcid
//	 4 varint ManaDirection direction
//	 5 varint int64 units
//	 6 varint ManaReason reason
//	 7 string action_code
//	 8 string source_allocation_id
//	 9 string request_id
//	10 varint int64 balance_after_units
//	11 bytes  Timestamp recorded_at
//
// -----------------------------------------------------------------------------
func encodeUserManaDebited(env Envelope, payload map[string]any) ([]byte, error) {
	out := make([]byte, 0, 256)
	envBz, err := encodeEnvelope(env, payload)
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	out = appendLengthDelimited(out, 1, envBz)
	if payload == nil {
		return out, nil
	}
	enc := newFieldEncoder(out, payload)
	enc.optString(2, "entry_id")
	enc.optString(3, "gcid")
	if err := enc.optEnumString(4, "direction", manaDirectionEnum); err != nil {
		return nil, err
	}
	if err := enc.optInt64(5, "units"); err != nil {
		return nil, err
	}
	if err := enc.optEnumString(6, "reason", manaReasonEnum); err != nil {
		return nil, err
	}
	// action_code is a chora-identity domain field carrying the cost-table
	// lookup key for the debit (e.g. familiar_chat_turn). It maps to the
	// proto's field 7 string slot. Source: domain LedgerEntry.SourceActionID.
	if _, present := payload["action_code"]; present {
		enc.optString(7, "action_code")
	} else {
		enc.optString(7, "source_action_id")
	}
	enc.optString(8, "source_allocation_id")
	enc.optString(9, "request_id")
	if err := enc.optInt64(10, "balance_after_units"); err != nil {
		return nil, err
	}
	if err := enc.optTimestamp(11, "recorded_at"); err != nil {
		return nil, err
	}
	return enc.out, nil
}

// -----------------------------------------------------------------------------
// User Mana — UserManaRefunded
//
//	 1 bytes  Envelope envelope
//	 2 string entry_id
//	 3 string gcid
//	 4 varint ManaDirection direction
//	 5 varint int64 units
//	 6 varint ManaReason reason
//	 7 string reverses_entry_id
//	 8 string request_id
//	 9 string reason_text
//	10 varint int64 balance_after_units
//	11 bytes  Timestamp recorded_at
//
// -----------------------------------------------------------------------------
func encodeUserManaRefunded(env Envelope, payload map[string]any) ([]byte, error) {
	out := make([]byte, 0, 256)
	envBz, err := encodeEnvelope(env, payload)
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	out = appendLengthDelimited(out, 1, envBz)
	if payload == nil {
		return out, nil
	}
	enc := newFieldEncoder(out, payload)
	enc.optString(2, "entry_id")
	enc.optString(3, "gcid")
	if err := enc.optEnumString(4, "direction", manaDirectionEnum); err != nil {
		return nil, err
	}
	if err := enc.optInt64(5, "units"); err != nil {
		return nil, err
	}
	if err := enc.optEnumString(6, "reason", manaReasonEnum); err != nil {
		return nil, err
	}
	enc.optString(7, "reverses_entry_id")
	enc.optString(8, "request_id")
	enc.optString(9, "reason_text")
	if err := enc.optInt64(10, "balance_after_units"); err != nil {
		return nil, err
	}
	if err := enc.optTimestamp(11, "recorded_at"); err != nil {
		return nil, err
	}
	return enc.out, nil
}

// -----------------------------------------------------------------------------
// User Mana — UserManaSnapshotTaken
//
//	1 bytes  Envelope envelope
//	2 string gcid
//	3 varint int64 balance_units
//	4 varint int64 lifetime_earned
//	5 varint int64 lifetime_spent
//	6 string snapshot_reason
//	7 bytes  Timestamp snapshot_at
//
// -----------------------------------------------------------------------------
func encodeUserManaSnapshotTaken(env Envelope, payload map[string]any) ([]byte, error) {
	out := make([]byte, 0, 128)
	envBz, err := encodeEnvelope(env, payload)
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	out = appendLengthDelimited(out, 1, envBz)
	if payload == nil {
		return out, nil
	}
	enc := newFieldEncoder(out, payload)
	enc.optString(2, "gcid")
	if err := enc.optInt64(3, "balance_units"); err != nil {
		return nil, err
	}
	if err := enc.optInt64(4, "lifetime_earned"); err != nil {
		return nil, err
	}
	if err := enc.optInt64(5, "lifetime_spent"); err != nil {
		return nil, err
	}
	enc.optString(6, "snapshot_reason")
	if err := enc.optTimestamp(7, "snapshot_at"); err != nil {
		return nil, err
	}
	return enc.out, nil
}

// -----------------------------------------------------------------------------
// KYC — KycSubmitted
//
//	1 bytes  Envelope envelope
//	2 string verification_id
//	3 string gcid
//	4 varint KycMethod method
//	5 string provider
//	6 string document_uri
//	7 varint int64 fee_charged_cents
//	8 string currency
//	9 bytes  Timestamp submitted_at
//
// -----------------------------------------------------------------------------
func encodeKycSubmitted(env Envelope, payload map[string]any) ([]byte, error) {
	out := make([]byte, 0, 256)
	envBz, err := encodeEnvelope(env, payload)
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	out = appendLengthDelimited(out, 1, envBz)
	if payload == nil {
		return out, nil
	}
	enc := newFieldEncoder(out, payload)
	enc.optString(2, "verification_id")
	enc.optString(3, "gcid")
	if err := enc.optEnumString(4, "method", kycMethodEnum); err != nil {
		return nil, err
	}
	enc.optString(5, "provider")
	enc.optString(6, "document_uri")
	if err := enc.optInt64(7, "fee_charged_cents"); err != nil {
		return nil, err
	}
	enc.optString(8, "currency")
	if err := enc.optTimestamp(9, "submitted_at"); err != nil {
		return nil, err
	}
	return enc.out, nil
}

// -----------------------------------------------------------------------------
// KYC — KycVerified
//
//	1 bytes  Envelope envelope
//	2 string verification_id
//	3 string gcid
//	4 varint KycMethod method
//	5 string provider
//	6 string verified_by_gcid
//	7 varint bool skillsfuture_scope_granted
//	8 bytes  Timestamp verified_at
//
// -----------------------------------------------------------------------------
func encodeKycVerified(env Envelope, payload map[string]any) ([]byte, error) {
	out := make([]byte, 0, 256)
	envBz, err := encodeEnvelope(env, payload)
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	out = appendLengthDelimited(out, 1, envBz)
	if payload == nil {
		return out, nil
	}
	enc := newFieldEncoder(out, payload)
	enc.optString(2, "verification_id")
	enc.optString(3, "gcid")
	if err := enc.optEnumString(4, "method", kycMethodEnum); err != nil {
		return nil, err
	}
	enc.optString(5, "provider")
	enc.optString(6, "verified_by_gcid")
	if err := enc.optBool(7, "skillsfuture_scope_granted"); err != nil {
		return nil, err
	}
	if err := enc.optTimestamp(8, "verified_at"); err != nil {
		return nil, err
	}
	return enc.out, nil
}

// -----------------------------------------------------------------------------
// KYC — KycRejected
//
//	 1 bytes  Envelope envelope
//	 2 string verification_id
//	 3 string gcid
//	 4 varint KycMethod method
//	 5 string provider
//	 6 string rejected_by_gcid
//	 7 string rejection_code
//	 8 string rejection_notes
//	 9 varint bool retry_allowed
//	10 bytes  Timestamp rejected_at
//
// -----------------------------------------------------------------------------
func encodeKycRejected(env Envelope, payload map[string]any) ([]byte, error) {
	out := make([]byte, 0, 256)
	envBz, err := encodeEnvelope(env, payload)
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	out = appendLengthDelimited(out, 1, envBz)
	if payload == nil {
		return out, nil
	}
	enc := newFieldEncoder(out, payload)
	enc.optString(2, "verification_id")
	enc.optString(3, "gcid")
	if err := enc.optEnumString(4, "method", kycMethodEnum); err != nil {
		return nil, err
	}
	enc.optString(5, "provider")
	enc.optString(6, "rejected_by_gcid")
	enc.optString(7, "rejection_code")
	enc.optString(8, "rejection_notes")
	if err := enc.optBool(9, "retry_allowed"); err != nil {
		return nil, err
	}
	if err := enc.optTimestamp(10, "rejected_at"); err != nil {
		return nil, err
	}
	return enc.out, nil
}

// -----------------------------------------------------------------------------
// User Subscription — UserSubscriptionCreated
//
//	 1 bytes  Envelope envelope
//	 2 string subscription_id
//	 3 string gcid
//	 4 string tenant_id
//	 5 string plan_code
//	 6 varint FamiliarTier tier
//	 7 varint UserSubscriptionStatus status
//	 8 varint BillingPeriod billing_period
//	 9 bytes  Timestamp current_period_start
//	10 bytes  Timestamp current_period_end
//	11 string stripe_subscription_id
//	12 varint int64 mana_monthly_units
//	13 varint int64 onboarding_bonus_units
//	14 bytes  Timestamp created_at
//
// -----------------------------------------------------------------------------
func encodeUserSubscriptionCreated(env Envelope, payload map[string]any) ([]byte, error) {
	out := make([]byte, 0, 384)
	envBz, err := encodeEnvelope(env, payload)
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	out = appendLengthDelimited(out, 1, envBz)
	if payload == nil {
		return out, nil
	}
	enc := newFieldEncoder(out, payload)
	enc.optString(2, "subscription_id")
	enc.optString(3, "gcid")
	enc.optString(4, "tenant_id")
	enc.optString(5, "plan_code")
	if err := enc.optEnumString(6, "tier", familiarTierEnum); err != nil {
		return nil, err
	}
	if err := enc.optEnumString(7, "status", subscriptionStatusEnum); err != nil {
		return nil, err
	}
	if err := enc.optEnumString(8, "billing_period", billingPeriodEnum); err != nil {
		return nil, err
	}
	if err := enc.optTimestamp(9, "current_period_start"); err != nil {
		return nil, err
	}
	if err := enc.optTimestamp(10, "current_period_end"); err != nil {
		return nil, err
	}
	enc.optString(11, "stripe_subscription_id")
	if err := enc.optInt64(12, "mana_monthly_units"); err != nil {
		return nil, err
	}
	if err := enc.optInt64(13, "onboarding_bonus_units"); err != nil {
		return nil, err
	}
	if err := enc.optTimestamp(14, "created_at"); err != nil {
		return nil, err
	}
	return enc.out, nil
}

// -----------------------------------------------------------------------------
// User Subscription — UserSubscriptionCancelled
//
//	 1 bytes  Envelope envelope
//	 2 string subscription_id
//	 3 string gcid
//	 4 string tenant_id
//	 5 string plan_code
//	 6 varint FamiliarTier tier
//	 7 string cancellation_reason
//	 8 string cancelled_by_gcid
//	 9 bytes  Timestamp effective_at
//	10 bytes  Timestamp cancelled_at
//
// -----------------------------------------------------------------------------
func encodeUserSubscriptionCancelled(env Envelope, payload map[string]any) ([]byte, error) {
	out := make([]byte, 0, 256)
	envBz, err := encodeEnvelope(env, payload)
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	out = appendLengthDelimited(out, 1, envBz)
	if payload == nil {
		return out, nil
	}
	enc := newFieldEncoder(out, payload)
	enc.optString(2, "subscription_id")
	enc.optString(3, "gcid")
	enc.optString(4, "tenant_id")
	enc.optString(5, "plan_code")
	if err := enc.optEnumString(6, "tier", familiarTierEnum); err != nil {
		return nil, err
	}
	enc.optString(7, "cancellation_reason")
	enc.optString(8, "cancelled_by_gcid")
	if err := enc.optTimestamp(9, "effective_at"); err != nil {
		return nil, err
	}
	if err := enc.optTimestamp(10, "cancelled_at"); err != nil {
		return nil, err
	}
	return enc.out, nil
}

// -----------------------------------------------------------------------------
// User Subscription — UserSubscriptionRenewed
//
//	 1 bytes  Envelope envelope
//	 2 string subscription_id
//	 3 string gcid
//	 4 string tenant_id
//	 5 string plan_code
//	 6 varint FamiliarTier tier
//	 7 varint BillingPeriod billing_period
//	 8 bytes  Timestamp prior_period_end
//	 9 bytes  Timestamp current_period_start
//	10 bytes  Timestamp current_period_end
//	11 string stripe_subscription_id
//	12 varint int64 mana_monthly_units
//	13 bytes  Timestamp renewed_at
//
// -----------------------------------------------------------------------------
func encodeUserSubscriptionRenewed(env Envelope, payload map[string]any) ([]byte, error) {
	out := make([]byte, 0, 320)
	envBz, err := encodeEnvelope(env, payload)
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	out = appendLengthDelimited(out, 1, envBz)
	if payload == nil {
		return out, nil
	}
	enc := newFieldEncoder(out, payload)
	enc.optString(2, "subscription_id")
	enc.optString(3, "gcid")
	enc.optString(4, "tenant_id")
	enc.optString(5, "plan_code")
	if err := enc.optEnumString(6, "tier", familiarTierEnum); err != nil {
		return nil, err
	}
	if err := enc.optEnumString(7, "billing_period", billingPeriodEnum); err != nil {
		return nil, err
	}
	if err := enc.optTimestamp(8, "prior_period_end"); err != nil {
		return nil, err
	}
	if err := enc.optTimestamp(9, "current_period_start"); err != nil {
		return nil, err
	}
	if err := enc.optTimestamp(10, "current_period_end"); err != nil {
		return nil, err
	}
	enc.optString(11, "stripe_subscription_id")
	if err := enc.optInt64(12, "mana_monthly_units"); err != nil {
		return nil, err
	}
	if err := enc.optTimestamp(13, "renewed_at"); err != nil {
		return nil, err
	}
	return enc.out, nil
}

// -----------------------------------------------------------------------------
// User Subscription — UserSubscriptionPlanChanged
//
//	 1 bytes  Envelope envelope
//	 2 string subscription_id
//	 3 string gcid
//	 4 string tenant_id
//	 5 string from_plan_code
//	 6 string to_plan_code
//	 7 varint FamiliarTier from_tier
//	 8 varint FamiliarTier to_tier
//	 9 varint BillingPeriod from_billing_period
//	10 varint BillingPeriod to_billing_period
//	11 varint int64 billing_delta_cents
//	12 string schedule_id
//	13 bytes  Timestamp effective_at
//	14 string requested_by_gcid
//	15 bytes  Timestamp changed_at
//
// -----------------------------------------------------------------------------
func encodeUserSubscriptionPlanChanged(env Envelope, payload map[string]any) ([]byte, error) {
	out := make([]byte, 0, 384)
	envBz, err := encodeEnvelope(env, payload)
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	out = appendLengthDelimited(out, 1, envBz)
	if payload == nil {
		return out, nil
	}
	enc := newFieldEncoder(out, payload)
	enc.optString(2, "subscription_id")
	enc.optString(3, "gcid")
	enc.optString(4, "tenant_id")
	enc.optString(5, "from_plan_code")
	enc.optString(6, "to_plan_code")
	if err := enc.optEnumString(7, "from_tier", familiarTierEnum); err != nil {
		return nil, err
	}
	if err := enc.optEnumString(8, "to_tier", familiarTierEnum); err != nil {
		return nil, err
	}
	if err := enc.optEnumString(9, "from_billing_period", billingPeriodEnum); err != nil {
		return nil, err
	}
	if err := enc.optEnumString(10, "to_billing_period", billingPeriodEnum); err != nil {
		return nil, err
	}
	if err := enc.optInt64(11, "billing_delta_cents"); err != nil {
		return nil, err
	}
	enc.optString(12, "schedule_id")
	if err := enc.optTimestamp(13, "effective_at"); err != nil {
		return nil, err
	}
	enc.optString(14, "requested_by_gcid")
	if err := enc.optTimestamp(15, "changed_at"); err != nil {
		return nil, err
	}
	return enc.out, nil
}

// -----------------------------------------------------------------------------
// Role — RoleGranted
//
//	 1 bytes  Envelope envelope
//	 2 string role_assignment_id
//	 3 string gcid
//	 4 string tenant_id
//	 5 string course_id
//	 6 varint CourseRole role
//	 7 varint RoleGrantSource source
//	 8 string source_event_id
//	 9 string granted_by_gcid
//	10 bytes  Timestamp granted_at
//
// -----------------------------------------------------------------------------
func encodeRoleGranted(env Envelope, payload map[string]any) ([]byte, error) {
	out := make([]byte, 0, 256)
	envBz, err := encodeEnvelope(env, payload)
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	out = appendLengthDelimited(out, 1, envBz)
	if payload == nil {
		return out, nil
	}
	enc := newFieldEncoder(out, payload)
	enc.optString(2, "role_assignment_id")
	enc.optString(3, "gcid")
	enc.optString(4, "tenant_id")
	enc.optString(5, "course_id")
	if err := enc.optEnumString(6, "role", courseRoleEnum); err != nil {
		return nil, err
	}
	if err := enc.optEnumString(7, "source", roleGrantSourceEnum); err != nil {
		return nil, err
	}
	enc.optString(8, "source_event_id")
	enc.optString(9, "granted_by_gcid")
	if err := enc.optTimestamp(10, "granted_at"); err != nil {
		return nil, err
	}
	return enc.out, nil
}

// -----------------------------------------------------------------------------
// Account — AccountLifecycleChanged
//
//	1 bytes  Envelope envelope
//	2 string account_id
//	3 string gcid
//	4 varint AccountState prior_state
//	5 varint AccountState new_state
//	6 string reason
//	7 string dek_id
//	8 string saga_id
//	9 bytes  Timestamp transitioned_at
//
// -----------------------------------------------------------------------------
func encodeAccountLifecycleChanged(env Envelope, payload map[string]any) ([]byte, error) {
	out := make([]byte, 0, 256)
	envBz, err := encodeEnvelope(env, payload)
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	out = appendLengthDelimited(out, 1, envBz)
	if payload == nil {
		return out, nil
	}
	enc := newFieldEncoder(out, payload)
	enc.optString(2, "account_id")
	enc.optString(3, "gcid")
	if err := enc.optEnumString(4, "prior_state", accountStateEnum); err != nil {
		return nil, err
	}
	if err := enc.optEnumString(5, "new_state", accountStateEnum); err != nil {
		return nil, err
	}
	enc.optString(6, "reason")
	enc.optString(7, "dek_id")
	enc.optString(8, "saga_id")
	if err := enc.optTimestamp(9, "transitioned_at"); err != nil {
		return nil, err
	}
	return enc.out, nil
}

// -----------------------------------------------------------------------------
// GCID — GcidResolved  (chora.identity.gcid.resolved.v1)
//
//	1 bytes  Envelope envelope
//	2 string gcid
//	3 string tenant_id
//	4 string email
//	5 string firebase_uid   (WIRE-COMPAT history: legacy proto field name;
//	                          the value is the generic federated subject)
//	6 varint int32 memberships_count
//
// Producer: internal/adapter/events/gcid_resolved_publisher.go. Class D
// contract paydown (event-fabric audit 2026-07-01).
// -----------------------------------------------------------------------------
func encodeGcidResolved(env Envelope, payload map[string]any) ([]byte, error) {
	out := make([]byte, 0, 256)
	envBz, err := encodeEnvelope(env, payload)
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	out = appendLengthDelimited(out, 1, envBz)
	if payload == nil {
		return out, nil
	}
	enc := newFieldEncoder(out, payload)
	enc.optString(2, "gcid")
	enc.optString(3, "tenant_id")
	enc.optString(4, "email")
	enc.optString(5, "firebase_uid")
	// memberships_count is a proto int32; a varint is wire-compatible (same as
	// schema_version in the envelope). optInt64 emits the varint.
	if err := enc.optInt64(6, "memberships_count"); err != nil {
		return nil, err
	}
	return enc.out, nil
}

// -----------------------------------------------------------------------------
// Tenant IdP Provider — TenantIdpProviderConfigured
// (chora.identity.tenant_idp_provider.configured.v1)
//
//	1 bytes  Envelope envelope
//	2 string event_type
//	3 string idp_id
//	4 string tenant_id
//	5 string provider_type
//	6 string actor_gcid
//
// Producer: internal/adapter/tenant_idp_provider_events/publisher.go. Class D
// contract paydown (event-fabric audit 2026-07-01).
// -----------------------------------------------------------------------------
func encodeTenantIdpProviderConfigured(env Envelope, payload map[string]any) ([]byte, error) {
	out := make([]byte, 0, 256)
	envBz, err := encodeEnvelope(env, payload)
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	out = appendLengthDelimited(out, 1, envBz)
	if payload == nil {
		return out, nil
	}
	enc := newFieldEncoder(out, payload)
	enc.optString(2, "event_type")
	enc.optString(3, "idp_id")
	enc.optString(4, "tenant_id")
	enc.optString(5, "provider_type")
	enc.optString(6, "actor_gcid")
	return enc.out, nil
}

// -----------------------------------------------------------------------------
// IMDA evidence — EvidenceRecorded  (chora.governance.evidence.recorded.v1)
//
//	1 bytes  Envelope envelope (chora_imda_dimension + imda_lifecycle_stage
//	         ride the envelope at fields 14/15 — encodeEnvelope reads them
//	         from the same payload map)
//	2 string evidence_type
//	3 string source_event_type
//	4 bytes  Timestamp recorded_at
//	5 string policy_reference
//	6 map<string,string> additional_fields  (free-form producer context)
//
// Governance-DOMAIN topic; chora-identity is a producer and owns this encoder.
// Producer: internal/adapter/events/imda_evidence.go (GovernancePublisher.
// RecordEvidence flattens EvidenceInput + AdditionalFields into one payload
// map). Class D contract paydown (event-fabric audit 2026-07-01).
// -----------------------------------------------------------------------------
func encodeEvidenceRecorded(env Envelope, payload map[string]any) ([]byte, error) {
	out := make([]byte, 0, 384)
	envBz, err := encodeEnvelope(env, payload)
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	out = appendLengthDelimited(out, 1, envBz)
	if payload == nil {
		return out, nil
	}
	enc := newFieldEncoder(out, payload)
	enc.optString(2, "evidence_type")
	enc.optString(3, "source_event_type")
	if err := enc.optTimestamp(4, "recorded_at"); err != nil {
		return nil, err
	}
	enc.optString(5, "policy_reference")
	// additional_fields (field 6): every payload key that is NOT mapped to a
	// dedicated message-level field (2-5) or consumed by the envelope encoder
	// (12-15). RecordEvidence merges AdditionalFields flat into the payload, so
	// this reconstitutes exactly that free-form context.
	enc.out = appendEvidenceAdditionalFields(enc.out, 6, payload)
	return enc.out, nil
}

// evidenceReservedKeys are payload keys the EvidenceRecorded encoder maps to
// dedicated message-level fields (2-5) or that encodeEnvelope consumes
// (correlation_id/causation_id/chora_imda_dimension/imda_lifecycle_stage at
// 12-15). They MUST be excluded from the additional_fields map so they are not
// double-encoded.
var evidenceReservedKeys = map[string]struct{}{
	"evidence_type":        {},
	"source_event_type":    {},
	"recorded_at":          {},
	"policy_reference":     {},
	"correlation_id":       {},
	"causation_id":         {},
	"chora_imda_dimension": {},
	"imda_lifecycle_stage": {},
}

// appendEvidenceAdditionalFields emits the proto map<string,string> at `field`.
// Each non-reserved payload entry becomes one length-delimited map entry
// {key=1, value=2}. Keys are emitted in sorted order for deterministic wire
// bytes. Values are rendered to a string via evidenceStringify so a
// heterogeneous map[string]any (bool, []string, ...) NEVER fails the publish —
// this is supplementary audit context, not a typed schema.
func appendEvidenceAdditionalFields(b []byte, field protowire.Number, payload map[string]any) []byte {
	keys := make([]string, 0, len(payload))
	for k := range payload {
		if _, reserved := evidenceReservedKeys[k]; reserved {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		entry := make([]byte, 0, 64)
		entry = appendString(entry, 1, k)
		if v := evidenceStringify(payload[k]); v != "" {
			entry = appendString(entry, 2, v)
		}
		b = appendLengthDelimited(b, field, entry)
	}
	return b
}

// evidenceStringify renders a free-form additional-field value to a
// deterministic string. Strings pass through; bools become "true"/"false";
// string/any slices (e.g. granted_roles) join on ",". Anything else falls back
// to fmt %v. nil renders to "" (an empty-value map entry).
func evidenceStringify(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case []string:
		return strings.Join(t, ",")
	case []any:
		parts := make([]string, len(t))
		for i, e := range t {
			parts[i] = fmt.Sprintf("%v", e)
		}
		return strings.Join(parts, ",")
	default:
		return fmt.Sprintf("%v", t)
	}
}

// -----------------------------------------------------------------------------
// Enum maps — domain string → proto enum NUMBER.
// Source: chora-contracts/gen/go/chora/identity/v1/*.pb.go enum const blocks.
// Unknown values fail loud at marshal time (vs silently sending 0=UNSPECIFIED).
// -----------------------------------------------------------------------------

// manaDirectionEnum maps domain Direction strings to ManaDirection numbers.
var manaDirectionEnum = map[string]int32{
	"":         0,
	"credit":   1,
	"debit":    2,
	"mint":     3,
	"refund":   4,
	"rollover": 5,
}

// manaReasonEnum maps domain Reason strings to ManaReason numbers.
var manaReasonEnum = map[string]int32{
	"":                   0,
	"subscription_grant": 1,
	"familiar_action":    2,
	"refund":             3,
	"account_closure":    4,
	"promo":              5,
	"tenant_subsidy":     6,
	"topup":              7,
	"rollover":           8,
}

// kycMethodEnum maps domain Method strings to KycMethod numbers.
var kycMethodEnum = map[string]int32{
	"":             0,
	"singpass":     1,
	"skillsfuture": 2,
	"manual_doc":   3,
}

// familiarTierEnum maps domain Tier strings to FamiliarTier numbers.
var familiarTierEnum = map[string]int32{
	"":         0,
	"basic":    1,
	"standard": 2,
	"premium":  3,
}

// subscriptionStatusEnum maps domain Status strings to UserSubscriptionStatus
// numbers.
var subscriptionStatusEnum = map[string]int32{
	"":                   0,
	"pending_activation": 1,
	"active":             2,
	"paused":             3,
	"cancelled":          4,
	"expired":            5,
	"grace":              6,
}

// billingPeriodEnum maps domain BillingPeriod strings to BillingPeriod
// numbers.
var billingPeriodEnum = map[string]int32{
	"":         0,
	"monthly":  1,
	"annually": 2,
}

// courseRoleEnum maps domain CourseRole strings to CourseRole numbers.
var courseRoleEnum = map[string]int32{
	"":                   0,
	"learner":            1,
	"instructor":         2,
	"teaching_assistant": 3,
	"observer":           4,
}

// roleGrantSourceEnum maps domain RoleGrantSource strings to RoleGrantSource
// numbers.
var roleGrantSourceEnum = map[string]int32{
	"":                     0,
	"enrolment":            1,
	"course_creation":      2,
	"admin_override":       3,
	"application_accepted": 4,
}

// accountStateEnum maps domain AccountState strings to AccountState numbers.
var accountStateEnum = map[string]int32{
	"":                0,
	"active":          1,
	"closing":         2,
	"suspended":       3,
	"pseudonymized":   4,
	"cold_archived":   5,
	"crypto_shredded": 6,
}

// -----------------------------------------------------------------------------
// fieldEncoder — small closure-free helper that accumulates wire bytes and
// applies type-safe optional-field encoders.
// -----------------------------------------------------------------------------

type fieldEncoder struct {
	out     []byte
	payload map[string]any
}

func newFieldEncoder(out []byte, payload map[string]any) *fieldEncoder {
	return &fieldEncoder{out: out, payload: payload}
}

// optString appends the field if payload[key] is a non-empty string. Missing
// keys + empty strings are skipped (proto3 zero-value convention).
func (e *fieldEncoder) optString(field protowire.Number, key string) {
	raw, present := e.payload[key]
	if !present {
		return
	}
	s, ok := raw.(string)
	if !ok || s == "" {
		return
	}
	e.out = appendString(e.out, field, s)
}

// optInt64 appends a varint int64 field. Type-mismatch returns an error.
// Zero values are skipped per proto3 convention.
func (e *fieldEncoder) optInt64(field protowire.Number, key string) error {
	raw, present := e.payload[key]
	if !present {
		return nil
	}
	v, ok := asInt64(raw)
	if !ok {
		return fmt.Errorf("field %s: expected int64-convertible, got %T", key, raw)
	}
	if v == 0 {
		return nil
	}
	e.out = appendVarint(e.out, field, uint64(v))
	return nil
}

// optBool appends a varint bool field. Type-mismatch returns an error.
// false is skipped per proto3 convention.
func (e *fieldEncoder) optBool(field protowire.Number, key string) error {
	raw, present := e.payload[key]
	if !present {
		return nil
	}
	b, ok := raw.(bool)
	if !ok {
		return fmt.Errorf("field %s: expected bool, got %T", key, raw)
	}
	if !b {
		return nil
	}
	e.out = appendVarint(e.out, field, 1)
	return nil
}

// optTimestamp appends a nested Timestamp message. Type-mismatch returns an
// error. Zero time.Time is skipped.
func (e *fieldEncoder) optTimestamp(field protowire.Number, key string) error {
	raw, present := e.payload[key]
	if !present {
		return nil
	}
	t, ok := asTime(raw)
	if !ok {
		return fmt.Errorf("field %s: expected time.Time, got %T", key, raw)
	}
	if t.IsZero() {
		return nil
	}
	e.out = appendLengthDelimited(e.out, field, encodeTimestamp(t))
	return nil
}

// optEnumString appends an enum varint field. The payload value MUST be a
// string mapped via enumMap; unknown values fail loud (we never want to
// silently emit 0=UNSPECIFIED for a value the producer thought it set).
func (e *fieldEncoder) optEnumString(field protowire.Number, key string, enumMap map[string]int32) error {
	raw, present := e.payload[key]
	if !present {
		return nil
	}
	s, ok := raw.(string)
	if !ok {
		return fmt.Errorf("field %s: expected enum-name string, got %T", key, raw)
	}
	n, mapped := enumMap[s]
	if !mapped {
		return fmt.Errorf("field %s: unknown enum value %q", key, s)
	}
	if n == 0 {
		return nil
	}
	e.out = appendVarint(e.out, field, uint64(uint32(n)))
	return nil
}

// -----------------------------------------------------------------------------
// Wire-format helpers (thin protowire wrappers; reuse keeps callers tidy).
// -----------------------------------------------------------------------------

func appendString(b []byte, field protowire.Number, v string) []byte {
	b = protowire.AppendTag(b, field, protowire.BytesType)
	b = protowire.AppendString(b, v)
	return b
}

func appendVarint(b []byte, field protowire.Number, v uint64) []byte {
	b = protowire.AppendTag(b, field, protowire.VarintType)
	b = protowire.AppendVarint(b, v)
	return b
}

func appendLengthDelimited(b []byte, field protowire.Number, payload []byte) []byte {
	b = protowire.AppendTag(b, field, protowire.BytesType)
	b = protowire.AppendBytes(b, payload)
	return b
}

// encodeTimestamp emits the nested google.protobuf.Timestamp wire shape:
//
//	1 varint int64  seconds
//	2 varint int32  nanos
func encodeTimestamp(t time.Time) []byte {
	out := make([]byte, 0, 16)
	t = t.UTC()
	secs := t.Unix()
	nanos := int32(t.Nanosecond())
	if secs != 0 {
		out = appendVarint(out, 1, uint64(secs))
	}
	if nanos != 0 {
		out = appendVarint(out, 2, uint64(uint32(nanos)))
	}
	return out
}

// -----------------------------------------------------------------------------
// Loose-typed payload coercion (in/out: map[string]any).
// -----------------------------------------------------------------------------

// asInt64 converts the value to int64. Returns false (not 0) if v is nil OR
// is a non-numeric type — caller decides whether to fail or skip.
func asInt64(v any) (int64, bool) {
	if v == nil {
		return 0, false
	}
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int32:
		return int64(n), true
	case int64:
		return n, true
	case float32:
		return int64(n), true
	case float64:
		return int64(n), true
	case uint:
		return int64(n), true
	case uint32:
		return int64(n), true
	case uint64:
		return int64(n), true
	default:
		return 0, false
	}
}

// asTime coerces a value to time.Time. Accepts time.Time directly + nil + an
// RFC3339[Nano] string. The string path is load-bearing: every call-site that
// uses economy_publisher.toMap routes typed time.Time fields through a JSON
// round-trip first which converts them to RFC3339 strings. The encoder must
// reconstitute them so the producer-side wire bytes carry a real Timestamp.
func asTime(v any) (time.Time, bool) {
	if v == nil {
		return time.Time{}, false
	}
	switch t := v.(type) {
	case time.Time:
		return t, true
	case *time.Time:
		if t == nil {
			return time.Time{}, false
		}
		return *t, true
	case string:
		if t == "" {
			return time.Time{}, false
		}
		if parsed, err := time.Parse(time.RFC3339Nano, t); err == nil {
			return parsed, true
		}
		if parsed, err := time.Parse(time.RFC3339, t); err == nil {
			return parsed, true
		}
		return time.Time{}, false
	default:
		return time.Time{}, false
	}
}
