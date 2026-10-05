// mana_helpers_test.go — direct coverage for the unexported mana helper
// functions: traceparent context plumbing, the proto<->string enum
// translation tables, and the direction code mapper. These sit behind the
// exported ManaProtoServer / ManaServer handlers and are only reachable
// from inside the package.
package grpcadapter

import (
	"context"
	"testing"

	identityv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/services/identity/v1"

	mana "github.com/apollo-chora/chora-identity/internal/domain/user_mana"
)

const defaultTraceparent = "00-00000000000000000000000000000000-0000000000000000-00"

func TestTraceparentFromCtx_StampedValue(t *testing.T) {
	const tp = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
	ctx := WithTraceparent(context.Background(), tp)
	if got := traceparentFromCtx(ctx); got != tp {
		t.Errorf("traceparentFromCtx = %q, want %q", got, tp)
	}
}

func TestTraceparentFromCtx_DefaultWhenAbsent(t *testing.T) {
	if got := traceparentFromCtx(context.Background()); got != defaultTraceparent {
		t.Errorf("absent key must yield the placeholder, got %q", got)
	}
}

func TestTraceparentFromCtx_DefaultWhenBlank(t *testing.T) {
	ctx := WithTraceparent(context.Background(), "   ")
	if got := traceparentFromCtx(ctx); got != defaultTraceparent {
		t.Errorf("blank value must yield the placeholder, got %q", got)
	}
}

// TestManaSourceTranslationTables locks the proto<->string enum tables on
// both directions so a drifted mapping is caught immediately.
func TestStringSourceToProto_AllValues(t *testing.T) {
	cases := map[string]identityv1.ManaSource{
		"subscription_grant": identityv1.ManaSource_MANA_SOURCE_SUBSCRIPTION_GRANT,
		"topup":              identityv1.ManaSource_MANA_SOURCE_TOPUP,
		"promo":              identityv1.ManaSource_MANA_SOURCE_PROMO,
		"tenant_subsidy":     identityv1.ManaSource_MANA_SOURCE_TENANT_SUBSIDY,
		"refund":             identityv1.ManaSource_MANA_SOURCE_REFUND,
		"rollover":           identityv1.ManaSource_MANA_SOURCE_ROLLOVER,
		"mint":               identityv1.ManaSource_MANA_SOURCE_MINT,
	}
	for s, want := range cases {
		if got := stringSourceToProto(s); got != want {
			t.Errorf("stringSourceToProto(%q) = %v, want %v", s, got, want)
		}
	}
	if got := stringSourceToProto("bogus"); got != identityv1.ManaSource_MANA_SOURCE_UNSPECIFIED {
		t.Errorf("unknown source = %v, want UNSPECIFIED", got)
	}
}

func TestProtoSourceToString_AllValues(t *testing.T) {
	cases := map[identityv1.ManaSource]string{
		identityv1.ManaSource_MANA_SOURCE_SUBSCRIPTION_GRANT: "subscription_grant",
		identityv1.ManaSource_MANA_SOURCE_TOPUP:              "topup",
		identityv1.ManaSource_MANA_SOURCE_PROMO:              "promo",
		identityv1.ManaSource_MANA_SOURCE_TENANT_SUBSIDY:     "tenant_subsidy",
		identityv1.ManaSource_MANA_SOURCE_REFUND:             "refund",
		identityv1.ManaSource_MANA_SOURCE_ROLLOVER:           "rollover",
		identityv1.ManaSource_MANA_SOURCE_MINT:               "mint",
	}
	for e, want := range cases {
		got, err := protoSourceToString(e)
		if err != nil || got != want {
			t.Errorf("protoSourceToString(%v) = %q, %v; want %q, nil", e, got, err, want)
		}
	}
	if _, err := protoSourceToString(identityv1.ManaSource_MANA_SOURCE_UNSPECIFIED); err == nil {
		t.Error("UNSPECIFIED source must error (fail-loud)")
	}
}

func TestProtoReasonToString_AllValues(t *testing.T) {
	cases := map[identityv1.ManaReasonCode]string{
		identityv1.ManaReasonCode_MANA_REASON_CODE_SUBSCRIPTION_GRANT: "subscription_grant",
		identityv1.ManaReasonCode_MANA_REASON_CODE_COMPANION_ACTION:   "familiar_action",
		identityv1.ManaReasonCode_MANA_REASON_CODE_REFUND:             "refund",
		identityv1.ManaReasonCode_MANA_REASON_CODE_ACCOUNT_CLOSURE:    "account_closure",
		identityv1.ManaReasonCode_MANA_REASON_CODE_PROMO:              "promo",
		identityv1.ManaReasonCode_MANA_REASON_CODE_TENANT_SUBSIDY:     "tenant_subsidy",
		identityv1.ManaReasonCode_MANA_REASON_CODE_TOPUP:              "topup",
		identityv1.ManaReasonCode_MANA_REASON_CODE_ROLLOVER:           "rollover",
	}
	for e, want := range cases {
		if got := protoReasonToString(e); got != want {
			t.Errorf("protoReasonToString(%v) = %q, want %q", e, got, want)
		}
	}
	if got := protoReasonToString(identityv1.ManaReasonCode_MANA_REASON_CODE_UNSPECIFIED); got != "" {
		t.Errorf("UNSPECIFIED reason = %q, want empty", got)
	}
}

func TestStringReasonToProto_AllValues(t *testing.T) {
	cases := map[string]identityv1.ManaReasonCode{
		"subscription_grant": identityv1.ManaReasonCode_MANA_REASON_CODE_SUBSCRIPTION_GRANT,
		"familiar_action":    identityv1.ManaReasonCode_MANA_REASON_CODE_COMPANION_ACTION,
		"refund":             identityv1.ManaReasonCode_MANA_REASON_CODE_REFUND,
		"account_closure":    identityv1.ManaReasonCode_MANA_REASON_CODE_ACCOUNT_CLOSURE,
		"promo":              identityv1.ManaReasonCode_MANA_REASON_CODE_PROMO,
		"tenant_subsidy":     identityv1.ManaReasonCode_MANA_REASON_CODE_TENANT_SUBSIDY,
		"topup":              identityv1.ManaReasonCode_MANA_REASON_CODE_TOPUP,
		"rollover":           identityv1.ManaReasonCode_MANA_REASON_CODE_ROLLOVER,
	}
	for s, want := range cases {
		if got := stringReasonToProto(s); got != want {
			t.Errorf("stringReasonToProto(%q) = %v, want %v", s, got, want)
		}
	}
	if got := stringReasonToProto("bogus"); got != identityv1.ManaReasonCode_MANA_REASON_CODE_UNSPECIFIED {
		t.Errorf("unknown reason = %v, want UNSPECIFIED", got)
	}
}

func TestDirectionCode_UnknownFallsBackToZero(t *testing.T) {
	if got := directionCode(mana.Direction("mystery")); got != 0 {
		t.Errorf("unknown direction = %d, want 0", got)
	}
}
