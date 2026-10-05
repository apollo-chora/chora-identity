// Coverage top-up for the protomarshal encoder — drives the loose-typed
// coercion helpers (evidenceStringify / asInt64 / asTime), the optional-field
// encoder error branches, zero-value skips, nil-payload early returns and the
// envelope IMDA fields. Existing wire_compat / guardrail tests are untouched.
package protomarshal_test

import (
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/apollo-chora/chora-identity/internal/adapter/events/protomarshal"
)

// -----------------------------------------------------------------------------
// evidenceStringify — free-form additional_field value rendering
// -----------------------------------------------------------------------------

func TestEvidenceStringify(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   any
		want string
	}{
		{"nil renders empty", nil, ""},
		{"string passes through", "plain", "plain"},
		{"bool true", true, "true"},
		{"bool false", false, "false"},
		{"string slice joins", []string{"a", "b", "c"}, "a,b,c"},
		{"any slice joins with fmt", []any{"x", 7, true}, "x,7,true"},
		{"int falls back to fmt", 42, "42"},
		{"float falls back", 3.5, "3.5"},
		{"empty string slice", []string{}, ""},
	}
	for _, tc := range cases {
		if got := evidenceStringify(t, tc.in); got != tc.want {
			t.Errorf("[%s] evidenceStringify(%v) = %q; want %q", tc.name, tc.in, got, tc.want)
		}
	}
}

// evidenceStringify wraps the package-private helper via MarshalPayload: the
// EvidenceRecorded encoder funnels additional_fields through it, so a payload
// carrying a heterogeneous additional value exercises the exact function.
func evidenceStringify(t *testing.T, v any) string {
	t.Helper()
	env := fixedEnvelope()
	bz, err := protomarshal.MarshalPayload("chora.governance.evidence.recorded.v1", env, map[string]any{
		"extra": v,
	})
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	return extractEvidenceFieldValue(t, bz, "extra")
}

// evidenceFieldValue walks the evidence wire bytes and returns (value, true)
// for the field 6 (additional_fields) map entry whose key equals want, or
// ("", false) when no such key is present.
func evidenceFieldValue(t *testing.T, bz []byte, want string) (string, bool) {
	t.Helper()
	rem := bz
	for len(rem) > 0 {
		num, typ, n := protowire.ConsumeTag(rem)
		if n < 0 {
			t.Fatalf("bad tag (offset %d)", len(bz)-len(rem))
		}
		rem = rem[n:]
		if typ == protowire.BytesType {
			val, m := protowire.ConsumeBytes(rem)
			if m < 0 {
				t.Fatalf("bad bytes for field %d", num)
			}
			rem = rem[m:]
			if num == 6 {
				// Inner map entry: field 1 = key, field 2 = value.
				inner := val
				var key, value string
				for len(inner) > 0 {
					in, it, im := protowire.ConsumeTag(inner)
					if im < 0 {
						t.Fatalf("bad inner tag")
					}
					inner = inner[im:]
					if it == protowire.BytesType {
						b, lm := protowire.ConsumeBytes(inner)
						if lm < 0 {
							t.Fatalf("bad inner bytes")
						}
						inner = inner[lm:]
						if in == 1 {
							key = string(b)
						} else if in == 2 {
							value = string(b)
						}
					}
				}
				if key == want {
					return value, true
				}
			}
		} else if typ == protowire.VarintType {
			_, m := protowire.ConsumeVarint(rem)
			if m < 0 {
				t.Fatalf("bad varint for field %d", num)
			}
			rem = rem[m:]
		}
	}
	return "", false
}

// extractEvidenceFieldValue is the fatal variant used by the stringify table.
func extractEvidenceFieldValue(t *testing.T, bz []byte, want string) string {
	t.Helper()
	v, ok := evidenceFieldValue(t, bz, want)
	if !ok {
		t.Fatalf("additional_fields key %q not found on the wire", want)
	}
	return v
}

// -----------------------------------------------------------------------------
// asInt64 — numeric coercion
// -----------------------------------------------------------------------------

func TestAsInt64(t *testing.T) {
	t.Parallel()
	env := fixedEnvelope()

	// Each numeric kind is accepted and encoded as a varint on field 5.
	for _, in := range []any{
		int(7), int32(7), int64(7), float32(7), float64(7),
		uint(7), uint32(7), uint64(7),
	} {
		bz, err := protomarshal.MarshalPayload("chora.identity.user_mana.debited.v1", env, map[string]any{
			"entry_id": "e", "gcid": env.GCID, "units": in,
		})
		if err != nil {
			t.Errorf("units=%T: MarshalPayload: %v", in, err)
			continue
		}
		if len(bz) == 0 {
			t.Errorf("units=%T: empty bytes", in)
		}
	}

	// nil + non-numeric types fail loud (optInt64 error branch).
	for _, in := range []any{nil, true, "7", []byte("7")} {
		if _, err := protomarshal.MarshalPayload("chora.identity.user_mana.debited.v1", env, map[string]any{
			"entry_id": "e", "gcid": env.GCID, "units": in,
		}); err == nil {
			t.Errorf("units=%T: expected type error, got nil", in)
		}
	}

	// Zero values are skipped (proto3) — encoding still succeeds.
	if _, err := protomarshal.MarshalPayload("chora.identity.user_mana.debited.v1", env, map[string]any{
		"entry_id": "e", "gcid": env.GCID, "units": int64(0),
	}); err != nil {
		t.Errorf("zero units should be skipped, not errored: %v", err)
	}
}

// -----------------------------------------------------------------------------
// asTime — time.Time coercion (direct, pointer, RFC3339 strings)
// -----------------------------------------------------------------------------

func TestAsTime_Branches(t *testing.T) {
	t.Parallel()
	env := fixedEnvelope()
	now := env.OccurredAt

	// Direct time.Time + *time.Time (exists) — covered via optTimestamp.
	for _, in := range []any{now, &now} {
		bz, err := protomarshal.MarshalPayload("chora.identity.user_mana.credited.v1", env, map[string]any{
			"entry_id": "e", "gcid": env.GCID, "recorded_at": in,
		})
		if err != nil {
			t.Errorf("recorded_at=%T: %v", in, err)
			continue
		}
		if len(bz) == 0 {
			t.Errorf("recorded_at=%T: empty bytes", in)
		}
	}

	// RFC3339Nano + RFC3339 string forms (JSON round-trip producer path).
	for _, s := range []string{"2026-05-16T12:00:00.123456789Z", "2026-05-16T12:00:00Z"} {
		bz, err := protomarshal.MarshalPayload("chora.identity.user_mana.credited.v1", env, map[string]any{
			"entry_id": "e", "gcid": env.GCID, "recorded_at": s,
		})
		if err != nil {
			t.Errorf("recorded_at=%q: %v", s, err)
			continue
		}
		if len(bz) == 0 {
			t.Errorf("recorded_at=%q: empty bytes", s)
		}
	}

	// Zero time.Time is skipped, not errored.
	if _, err := protomarshal.MarshalPayload("chora.identity.user_mana.credited.v1", env, map[string]any{
		"entry_id": "e", "gcid": env.GCID, "recorded_at": time.Time{},
	}); err != nil {
		t.Errorf("zero time should be skipped: %v", err)
	}

	// Rejection branches: nil pointer, empty string, unparseable string, wrong type.
	for _, in := range []any{
		(*time.Time)(nil), "", "not-a-time", 123, true,
	} {
		if _, err := protomarshal.MarshalPayload("chora.identity.user_mana.credited.v1", env, map[string]any{
			"entry_id": "e", "gcid": env.GCID, "recorded_at": in,
		}); err == nil {
			t.Errorf("recorded_at=%T(%v): expected error, got nil", in, in)
		}
	}
}

// -----------------------------------------------------------------------------
// optBool + optEnumString edge branches via the KYC encoders
// -----------------------------------------------------------------------------

func TestOptBool_FalseSkippedAndMismatchRejected(t *testing.T) {
	t.Parallel()
	env := fixedEnvelope()

	// false bool → proto3 zero-value skip, no error.
	bz, err := protomarshal.MarshalPayload("chora.identity.kyc.verified.v1", env, map[string]any{
		"verification_id": "v-1", "gcid": env.GCID,
		"method": "singpass", "skillsfuture_scope_granted": false,
	})
	if err != nil {
		t.Fatalf("false bool should be skipped: %v", err)
	}
	if len(bz) == 0 {
		t.Fatal("empty bytes")
	}

	// non-bool value → type-mismatch error.
	if _, err := protomarshal.MarshalPayload("chora.identity.kyc.verified.v1", env, map[string]any{
		"verification_id": "v-1", "gcid": env.GCID,
		"method": "singpass", "skillsfuture_scope_granted": "yes",
	}); err == nil {
		t.Error("expected bool type-mismatch error")
	}
}

func TestOptEnumString_ZeroValueSkippedAndMismatchRejected(t *testing.T) {
	t.Parallel()
	env := fixedEnvelope()

	// "" maps to enum 0 → skipped, no error.
	bz, err := protomarshal.MarshalPayload("chora.identity.user_mana.debited.v1", env, map[string]any{
		"entry_id": "e", "gcid": env.GCID, "direction": "",
	})
	if err != nil {
		t.Fatalf("empty enum value should be skipped: %v", err)
	}
	if len(bz) == 0 {
		t.Fatal("empty bytes")
	}

	// non-string value → type-mismatch error.
	if _, err := protomarshal.MarshalPayload("chora.identity.user_mana.debited.v1", env, map[string]any{
		"entry_id": "e", "gcid": env.GCID, "direction": 42,
	}); err == nil {
		t.Error("expected enum type-mismatch error")
	}
}

// -----------------------------------------------------------------------------
// per-encoder typed-field error branches — one bad payload per optional field
// -----------------------------------------------------------------------------

func TestEncoderTypedFieldErrorBranches(t *testing.T) {
	t.Parallel()
	env := fixedEnvelope()

	badPayloads := []struct {
		name    string
		topic   string
		payload map[string]any
	}{
		{"credited bad direction", "chora.identity.user_mana.credited.v1", map[string]any{"entry_id": "e", "direction": 1}},
		{"credited bad units", "chora.identity.user_mana.credited.v1", map[string]any{"entry_id": "e", "units": "x"}},
		{"credited bad reason", "chora.identity.user_mana.credited.v1", map[string]any{"entry_id": "e", "reason": true}},
		{"credited bad balance", "chora.identity.user_mana.credited.v1", map[string]any{"entry_id": "e", "balance_after_units": "x"}},
		{"credited bad recorded_at", "chora.identity.user_mana.credited.v1", map[string]any{"entry_id": "e", "recorded_at": 5}},

		{"debited bad direction", "chora.identity.user_mana.debited.v1", map[string]any{"entry_id": "e", "direction": 1}},
		{"debited bad units", "chora.identity.user_mana.debited.v1", map[string]any{"entry_id": "e", "units": "x"}},
		{"debited bad reason", "chora.identity.user_mana.debited.v1", map[string]any{"entry_id": "e", "reason": true}},
		{"debited bad balance", "chora.identity.user_mana.debited.v1", map[string]any{"entry_id": "e", "balance_after_units": "x"}},
		{"debited bad recorded_at", "chora.identity.user_mana.debited.v1", map[string]any{"entry_id": "e", "recorded_at": 5}},

		{"refunded bad direction", "chora.identity.user_mana.refunded.v1", map[string]any{"entry_id": "e", "direction": 1}},
		{"refunded bad units", "chora.identity.user_mana.refunded.v1", map[string]any{"entry_id": "e", "units": "x"}},
		{"refunded bad reason", "chora.identity.user_mana.refunded.v1", map[string]any{"entry_id": "e", "reason": true}},
		{"refunded bad balance", "chora.identity.user_mana.refunded.v1", map[string]any{"entry_id": "e", "balance_after_units": "x"}},
		{"refunded bad recorded_at", "chora.identity.user_mana.refunded.v1", map[string]any{"entry_id": "e", "recorded_at": 5}},

		{"snapshot bad balance_units", "chora.identity.user_mana.snapshot_taken.v1", map[string]any{"balance_units": "x"}},
		{"snapshot bad lifetime_earned", "chora.identity.user_mana.snapshot_taken.v1", map[string]any{"lifetime_earned": "x"}},
		{"snapshot bad lifetime_spent", "chora.identity.user_mana.snapshot_taken.v1", map[string]any{"lifetime_spent": "x"}},
		{"snapshot bad snapshot_at", "chora.identity.user_mana.snapshot_taken.v1", map[string]any{"snapshot_at": 5}},

		{"kyc submitted bad method", "chora.identity.kyc.submitted.v1", map[string]any{"verification_id": "v", "method": 3}},
		{"kyc submitted bad fee", "chora.identity.kyc.submitted.v1", map[string]any{"verification_id": "v", "fee_charged_cents": "x"}},
		{"kyc submitted bad submitted_at", "chora.identity.kyc.submitted.v1", map[string]any{"verification_id": "v", "submitted_at": 5}},

		{"kyc verified bad method", "chora.identity.kyc.verified.v1", map[string]any{"verification_id": "v", "method": 3}},
		{"kyc verified bad bool", "chora.identity.kyc.verified.v1", map[string]any{"verification_id": "v", "skillsfuture_scope_granted": "x"}},
		{"kyc verified bad verified_at", "chora.identity.kyc.verified.v1", map[string]any{"verification_id": "v", "verified_at": 5}},

		{"kyc rejected bad method", "chora.identity.kyc.rejected.v1", map[string]any{"verification_id": "v", "method": 3}},
		{"kyc rejected bad retry_allowed", "chora.identity.kyc.rejected.v1", map[string]any{"verification_id": "v", "retry_allowed": "x"}},
		{"kyc rejected bad rejected_at", "chora.identity.kyc.rejected.v1", map[string]any{"verification_id": "v", "rejected_at": 5}},

		{"sub created bad tier", "chora.identity.user_subscription.created.v1", map[string]any{"subscription_id": "s", "tier": 3}},
		{"sub created bad status", "chora.identity.user_subscription.created.v1", map[string]any{"subscription_id": "s", "status": 3}},
		{"sub created bad billing_period", "chora.identity.user_subscription.created.v1", map[string]any{"subscription_id": "s", "billing_period": 3}},
		{"sub created bad period_start", "chora.identity.user_subscription.created.v1", map[string]any{"subscription_id": "s", "current_period_start": 5}},
		{"sub created bad period_end", "chora.identity.user_subscription.created.v1", map[string]any{"subscription_id": "s", "current_period_end": 5}},
		{"sub created bad monthly_units", "chora.identity.user_subscription.created.v1", map[string]any{"subscription_id": "s", "mana_monthly_units": "x"}},
		{"sub created bad bonus_units", "chora.identity.user_subscription.created.v1", map[string]any{"subscription_id": "s", "onboarding_bonus_units": "x"}},
		{"sub created bad created_at", "chora.identity.user_subscription.created.v1", map[string]any{"subscription_id": "s", "created_at": 5}},

		{"sub cancelled bad tier", "chora.identity.user_subscription.cancelled.v1", map[string]any{"subscription_id": "s", "tier": 3}},
		{"sub cancelled bad effective_at", "chora.identity.user_subscription.cancelled.v1", map[string]any{"subscription_id": "s", "effective_at": 5}},
		{"sub cancelled bad cancelled_at", "chora.identity.user_subscription.cancelled.v1", map[string]any{"subscription_id": "s", "cancelled_at": 5}},

		{"sub renewed bad tier", "chora.identity.user_subscription.renewed.v1", map[string]any{"subscription_id": "s", "tier": 3}},
		{"sub renewed bad billing_period", "chora.identity.user_subscription.renewed.v1", map[string]any{"subscription_id": "s", "billing_period": 3}},
		{"sub renewed bad prior_period_end", "chora.identity.user_subscription.renewed.v1", map[string]any{"subscription_id": "s", "prior_period_end": 5}},
		{"sub renewed bad period_start", "chora.identity.user_subscription.renewed.v1", map[string]any{"subscription_id": "s", "current_period_start": 5}},
		{"sub renewed bad period_end", "chora.identity.user_subscription.renewed.v1", map[string]any{"subscription_id": "s", "current_period_end": 5}},
		{"sub renewed bad monthly_units", "chora.identity.user_subscription.renewed.v1", map[string]any{"subscription_id": "s", "mana_monthly_units": "x"}},
		{"sub renewed bad renewed_at", "chora.identity.user_subscription.renewed.v1", map[string]any{"subscription_id": "s", "renewed_at": 5}},

		{"plan_changed bad from_tier", "chora.identity.user_subscription.plan_changed.v1", map[string]any{"subscription_id": "s", "from_tier": 3}},
		{"plan_changed bad to_tier", "chora.identity.user_subscription.plan_changed.v1", map[string]any{"subscription_id": "s", "to_tier": 3}},
		{"plan_changed bad from_billing_period", "chora.identity.user_subscription.plan_changed.v1", map[string]any{"subscription_id": "s", "from_billing_period": 3}},
		{"plan_changed bad to_billing_period", "chora.identity.user_subscription.plan_changed.v1", map[string]any{"subscription_id": "s", "to_billing_period": 3}},
		{"plan_changed bad delta", "chora.identity.user_subscription.plan_changed.v1", map[string]any{"subscription_id": "s", "billing_delta_cents": "x"}},
		{"plan_changed bad effective_at", "chora.identity.user_subscription.plan_changed.v1", map[string]any{"subscription_id": "s", "effective_at": 5}},
		{"plan_changed bad changed_at", "chora.identity.user_subscription.plan_changed.v1", map[string]any{"subscription_id": "s", "changed_at": 5}},

		{"role bad role", "chora.identity.role.granted.v1", map[string]any{"role_assignment_id": "ra", "role": 3}},
		{"role bad source", "chora.identity.role.granted.v1", map[string]any{"role_assignment_id": "ra", "source": 3}},
		{"role bad granted_at", "chora.identity.role.granted.v1", map[string]any{"role_assignment_id": "ra", "granted_at": 5}},

		{"account bad prior_state", "chora.identity.account.lifecycle_changed.v1", map[string]any{"account_id": "a", "prior_state": 3}},
		{"account bad new_state", "chora.identity.account.lifecycle_changed.v1", map[string]any{"account_id": "a", "new_state": 3}},
		{"account bad transitioned_at", "chora.identity.account.lifecycle_changed.v1", map[string]any{"account_id": "a", "transitioned_at": 5}},

		{"gcid resolved bad memberships_count", "chora.identity.gcid.resolved.v1", map[string]any{"gcid": "g", "memberships_count": "x"}},

		{"evidence bad recorded_at", "chora.governance.evidence.recorded.v1", map[string]any{"evidence_type": "e", "recorded_at": 5}},
	}

	for _, tc := range badPayloads {
		_, err := protomarshal.MarshalPayload(tc.topic, env, tc.payload)
		if err == nil {
			t.Errorf("[%s] expected error for typed-field mismatch, got nil", tc.name)
		}
	}
}

// -----------------------------------------------------------------------------
// nil payload → envelope-only output for EVERY registered encoder
// -----------------------------------------------------------------------------

func TestNilPayloadForEveryEncoder(t *testing.T) {
	t.Parallel()
	env := fixedEnvelope()
	topics := []string{
		"chora.identity.user_mana.credited.v1",
		"chora.identity.user_mana.debited.v1",
		"chora.identity.user_mana.refunded.v1",
		"chora.identity.user_mana.snapshot_taken.v1",
		"chora.identity.kyc.submitted.v1",
		"chora.identity.kyc.verified.v1",
		"chora.identity.kyc.rejected.v1",
		"chora.identity.user_subscription.created.v1",
		"chora.identity.user_subscription.cancelled.v1",
		"chora.identity.user_subscription.renewed.v1",
		"chora.identity.user_subscription.plan_changed.v1",
		"chora.identity.role.granted.v1",
		"chora.identity.account.lifecycle_changed.v1",
		"chora.identity.gcid.resolved.v1",
		"chora.identity.tenant_idp_provider.configured.v1",
		"chora.governance.evidence.recorded.v1",
	}
	for _, topic := range topics {
		bz, err := protomarshal.MarshalPayload(topic, env, nil)
		if err != nil {
			t.Errorf("[%s] nil payload: %v", topic, err)
			continue
		}
		num, _, n := protowire.ConsumeTag(bz)
		if n < 0 || num != 1 {
			t.Errorf("[%s] nil payload should still emit envelope field 1", topic)
		}
	}
}

// -----------------------------------------------------------------------------
// Envelope IMDA fields (12-15) sourced from the payload
// -----------------------------------------------------------------------------

func TestEnvelope_PayloadIMDAFields_AreEmitted(t *testing.T) {
	t.Parallel()
	env := fixedEnvelope()
	bz, err := protomarshal.MarshalPayload("chora.governance.evidence.recorded.v1", env, map[string]any{
		"evidence_type":        "imda_integrity",
		"correlation_id":       "corr-1",
		"causation_id":         "cause-1",
		"chora_imda_dimension": "D1",
		"imda_lifecycle_stage": "P0",
	})
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}

	rem := bz
	// Field 1 = envelope; unwrap it and walk its tags.
	num, typ, n := protowire.ConsumeTag(rem)
	if num != 1 || typ != protowire.BytesType || n < 0 {
		t.Fatalf("expected envelope at field 1")
	}
	rem = rem[n:]
	envBytes, m := protowire.ConsumeBytes(rem)
	if m < 0 {
		t.Fatal("bad envelope bytes")
	}
	seen := walkTags(t, envBytes)
	for _, want := range []protowire.Number{12, 13, 14, 15} {
		if !seen[want] {
			t.Errorf("envelope missing IMDA field %d", want)
		}
	}
}

// -----------------------------------------------------------------------------
// EvidenceRecorded — additional_fields map emission + reserved-key exclusion
// -----------------------------------------------------------------------------

func TestMarshalEvidenceRecorded_AdditionalFields(t *testing.T) {
	t.Parallel()
	env := fixedEnvelope()
	bz, err := protomarshal.MarshalPayload("chora.governance.evidence.recorded.v1", env, map[string]any{
		"evidence_type":     "imda_usage",
		"source_event_type": "chora.familiar.usage.recorded.v1",
		"recorded_at":       env.OccurredAt,
		"policy_reference":  "IMDA-TC-2026",
		"correlation_id":    "corr-ev",
		"granted_roles":     []string{"learner", "instructor"},
		"score":             98,
		"flag":              true,
		"reason":            nil,
		"version":           "2.1",
	})
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	if len(bz) == 0 {
		t.Fatal("empty bytes")
	}
	seen := walkTags(t, bz)
	for _, want := range []protowire.Number{1, 2, 3, 4, 5, 6} {
		if !seen[want] {
			t.Errorf("EvidenceRecorded missing field %d", want)
		}
	}

	// Granted roles joined into one string value on the wire;
	// nil reason produces a key-only map entry (empty value).
	if got := extractEvidenceFieldValue(t, bz, "granted_roles"); got != "learner,instructor" {
		t.Errorf("granted_roles = %q; want %q", got, "learner,instructor")
	}
	if got := extractEvidenceFieldValue(t, bz, "reason"); got != "" {
		t.Errorf("reason = %q; want empty (nil value)", got)
	}
	// Reserved keys are NOT emitted as additional_fields.
	for _, k := range []string{"evidence_type", "recorded_at", "correlation_id"} {
		if v, ok := evidenceFieldValue(t, bz, k); ok {
			t.Errorf("reserved key %q leaked into additional_fields (value %q)", k, v)
		}
	}
}
