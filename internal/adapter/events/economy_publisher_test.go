// Tests for the typed EconomyPublisher (BE-USR-1).
package events_test

import (
	"testing"
	"time"

	"github.com/apollo-chora/chora-identity/internal/adapter/events"
	"github.com/apollo-chora/chora-identity/internal/domain/kyc"
	mana "github.com/apollo-chora/chora-identity/internal/domain/user_mana"
	usersub "github.com/apollo-chora/chora-identity/internal/domain/user_subscription"
)

const tenantE = "01970000-0000-7000-8000-00000000ee01"

func newRecorder() *events.Recorder { return events.NewRecorder() }

func newEnv(gcid string) events.Envelope {
	return events.NewEnvelope(tenantE, gcid, "00-trace-span-01", "")
}

func TestEconomyPublisher_PublishesSubscriptionCreated(t *testing.T) {
	t.Parallel()
	rec := newRecorder()
	p := events.NewEconomyPublisher(rec)

	s, err := usersub.NewSubscription(usersub.NewParams{
		Gcid: "01970000-0000-7000-8000-000000000001", TenantID: tenantE,
		PlanCode: "familiar_basic", Tier: usersub.TierBasic,
		BillingPeriod: usersub.BillingMonthly, ManaMonthlyUnits: 500,
		PeriodStart: time.Now().UTC(),
		PeriodEnd:   time.Now().UTC().Add(30 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := p.PublishSubscriptionCreated(newEnv(s.Gcid), s); err != nil {
		t.Fatalf("PublishSubscriptionCreated: %v", err)
	}
	got := rec.RecordedByTopic("chora.identity.user_subscription.created.v1")
	if len(got) != 1 {
		t.Fatalf("got %d records want 1", len(got))
	}
	if got[0].Payload["plan_code"] != "familiar_basic" {
		t.Errorf("plan_code missing in payload: %+v", got[0].Payload)
	}
}

func TestEconomyPublisher_PublishesManaCreditedAndDebited(t *testing.T) {
	t.Parallel()
	rec := newRecorder()
	p := events.NewEconomyPublisher(rec)

	credit, err := mana.NewLedgerEntry(mana.NewLedgerParams{
		Gcid:      "01970000-0000-7000-8000-000000000002",
		Direction: mana.DirectionCredit, Units: 500,
		Reason:            mana.ReasonSubscriptionGrant,
		BalanceAfterUnits: 500,
	})
	if err != nil {
		t.Fatalf("seed credit: %v", err)
	}
	if err := p.PublishManaCredited(newEnv(credit.Gcid), credit); err != nil {
		t.Fatalf("PublishManaCredited: %v", err)
	}

	debit, err := mana.NewLedgerEntry(mana.NewLedgerParams{
		Gcid: credit.Gcid, Direction: mana.DirectionDebit,
		Units: 25, Reason: mana.ReasonFamiliarAction,
		SourceActionID: "familiar_chat", BalanceAfterUnits: 475,
	})
	if err != nil {
		t.Fatalf("seed debit: %v", err)
	}
	if err := p.PublishManaDebited(newEnv(debit.Gcid), debit); err != nil {
		t.Fatalf("PublishManaDebited: %v", err)
	}

	if len(rec.RecordedByTopic("chora.identity.user_mana.credited.v1")) != 1 {
		t.Errorf("credited.v1 not emitted")
	}
	if len(rec.RecordedByTopic("chora.identity.user_mana.debited.v1")) != 1 {
		t.Errorf("debited.v1 not emitted")
	}
}

func TestEconomyPublisher_PublishesKycVerified(t *testing.T) {
	t.Parallel()
	rec := newRecorder()
	p := events.NewEconomyPublisher(rec)

	v, _ := kyc.NewVerification(kyc.NewParams{
		Gcid:   "01970000-0000-7000-8000-000000000003",
		Method: kyc.MethodSingpass, Provider: "ndi",
	})
	_ = v.Submit("", 0, "")
	_ = v.Verify("admin-1", true)

	if err := p.PublishKycVerified(newEnv(v.Gcid), v); err != nil {
		t.Fatalf("PublishKycVerified: %v", err)
	}
	got := rec.RecordedByTopic("chora.identity.kyc.verified.v1")
	if len(got) != 1 {
		t.Fatalf("got %d want 1", len(got))
	}
	if got[0].Payload["skillsfuture_scope_granted"] != true {
		t.Errorf("scope flag missing")
	}
}

func TestEconomyPublisher_NilInner_ReturnsError(t *testing.T) {
	t.Parallel()
	p := events.NewEconomyPublisher(nil)
	err := p.PublishSubscriptionCreated(events.Envelope{}, nil)
	if err == nil {
		t.Errorf("expected error from nil inner publisher")
	}
}

// -----------------------------------------------------------------------------
// BE-USR-1 remaining emission paths: cancelled / renewed / plan_changed /
// mana refunded / mana snapshot / kyc rejected.
// -----------------------------------------------------------------------------

func TestEconomyPublisher_PublishesSubscriptionCancelled(t *testing.T) {
	t.Parallel()
	rec := newRecorder()
	p := events.NewEconomyPublisher(rec)

	s, err := usersub.NewSubscription(usersub.NewParams{
		Gcid: "01970000-0000-7000-8000-000000000005", TenantID: tenantE,
		PlanCode: "familiar_basic", Tier: usersub.TierBasic,
		BillingPeriod: usersub.BillingMonthly, ManaMonthlyUnits: 500,
		PeriodStart: time.Now().UTC(),
		PeriodEnd:   time.Now().UTC().Add(30 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := s.Cancel("left_for_competitor", "01970000-0000-7000-8000-000000000099", time.Now().UTC()); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if err := p.PublishSubscriptionCancelled(newEnv(s.Gcid), s); err != nil {
		t.Fatalf("PublishSubscriptionCancelled: %v", err)
	}
	got := rec.RecordedByTopic("chora.identity.user_subscription.cancelled.v1")
	if len(got) != 1 {
		t.Fatalf("got %d records want 1", len(got))
	}
	if got[0].Payload["subscription_id"] != s.SubscriptionID {
		t.Errorf("subscription_id missing in payload: %+v", got[0].Payload)
	}
	if got[0].Payload["cancellation_reason"] != "left_for_competitor" {
		t.Errorf("cancellation_reason missing in payload: %+v", got[0].Payload)
	}
}

func TestEconomyPublisher_PublishesSubscriptionRenewed(t *testing.T) {
	t.Parallel()
	rec := newRecorder()
	p := events.NewEconomyPublisher(rec)

	payload := usersub.RenewedPayload{
		SubscriptionID:   "sub-renew-1",
		Gcid:             "01970000-0000-7000-8000-000000000006",
		TenantID:         tenantE,
		PlanCode:         "familiar_basic",
		Tier:             string(usersub.TierBasic),
		BillingPeriod:    string(usersub.BillingMonthly),
		PriorPeriodEnd:   time.Now().UTC().Add(-24 * time.Hour),
		ManaMonthlyUnits: 500,
		RenewedAt:        time.Now().UTC(),
	}
	if err := p.PublishSubscriptionRenewed(newEnv(payload.Gcid), payload); err != nil {
		t.Fatalf("PublishSubscriptionRenewed: %v", err)
	}
	got := rec.RecordedByTopic("chora.identity.user_subscription.renewed.v1")
	if len(got) != 1 {
		t.Fatalf("got %d records want 1", len(got))
	}
	if got[0].Payload["plan_code"] != "familiar_basic" {
		t.Errorf("plan_code missing: %+v", got[0].Payload)
	}
}

func TestEconomyPublisher_PublishesSubscriptionPlanChanged(t *testing.T) {
	t.Parallel()
	rec := newRecorder()
	p := events.NewEconomyPublisher(rec)

	payload := usersub.PlanChangedPayload{
		SubscriptionID:    "sub-plan-1",
		Gcid:              "01970000-0000-7000-8000-000000000007",
		TenantID:          tenantE,
		FromPlanCode:      "familiar_basic",
		ToPlanCode:        "familiar_standard",
		FromTier:          string(usersub.TierBasic),
		ToTier:            string(usersub.TierStandard),
		FromBillingPeriod: string(usersub.BillingMonthly),
		ToBillingPeriod:   string(usersub.BillingMonthly),
		BillingDeltaCents: 1500,
		ScheduleID:        "sched-1",
	}
	if err := p.PublishSubscriptionPlanChanged(newEnv(payload.Gcid), payload); err != nil {
		t.Fatalf("PublishSubscriptionPlanChanged: %v", err)
	}
	got := rec.RecordedByTopic("chora.identity.user_subscription.plan_changed.v1")
	if len(got) != 1 {
		t.Fatalf("got %d records want 1", len(got))
	}
	if got[0].Payload["to_plan_code"] != "familiar_standard" {
		t.Errorf("to_plan_code missing: %+v", got[0].Payload)
	}
}

func TestEconomyPublisher_PublishesManaRefunded(t *testing.T) {
	t.Parallel()
	rec := newRecorder()
	p := events.NewEconomyPublisher(rec)

	refund, err := mana.NewLedgerEntry(mana.NewLedgerParams{
		Gcid:      "01970000-0000-7000-8000-000000000008",
		Direction: mana.DirectionRefund, Units: 50,
		Reason: mana.ReasonRefund, BalanceAfterUnits: 550,
	})
	if err != nil {
		t.Fatalf("seed refund: %v", err)
	}
	if err := p.PublishManaRefunded(newEnv(refund.Gcid), refund); err != nil {
		t.Fatalf("PublishManaRefunded: %v", err)
	}
	got := rec.RecordedByTopic("chora.identity.user_mana.refunded.v1")
	if len(got) != 1 {
		t.Fatalf("got %d records want 1", len(got))
	}
	if got[0].Payload["units"] == nil {
		t.Errorf("units missing from refund payload: %+v", got[0].Payload)
	}
}

func TestEconomyPublisher_PublishesManaSnapshot(t *testing.T) {
	t.Parallel()
	rec := newRecorder()
	p := events.NewEconomyPublisher(rec)

	payload := mana.SnapshotPayload{
		Gcid:           "01970000-0000-7000-8000-000000000009",
		BalanceUnits:   1234,
		LifetimeEarned: 5000,
		LifetimeSpent:  3766,
		SnapshotReason: "scheduled",
		SnapshotAt:     time.Now().UTC(),
	}
	if err := p.PublishManaSnapshot(newEnv(payload.Gcid), payload); err != nil {
		t.Fatalf("PublishManaSnapshot: %v", err)
	}
	got := rec.RecordedByTopic("chora.identity.user_mana.snapshot_taken.v1")
	if len(got) != 1 {
		t.Fatalf("got %d records want 1", len(got))
	}
	if got[0].Payload["balance_units"] == nil {
		t.Errorf("balance_units missing from snapshot payload: %+v", got[0].Payload)
	}
}

func TestEconomyPublisher_PublishesKycRejected(t *testing.T) {
	t.Parallel()
	rec := newRecorder()
	p := events.NewEconomyPublisher(rec)

	v, _ := kyc.NewVerification(kyc.NewParams{
		Gcid:   "01970000-0000-7000-8000-00000000000a",
		Method: kyc.MethodSingpass, Provider: "ndi",
	})
	_ = v.Submit("gs://chora-kyc-sandbox/doc-1", 0, "")
	_ = v.Reject("docs_unclear", "please reupload a clearer copy", false)

	if err := p.PublishKycRejected(newEnv(v.Gcid), v); err != nil {
		t.Fatalf("PublishKycRejected: %v", err)
	}
	got := rec.RecordedByTopic("chora.identity.kyc.rejected.v1")
	if len(got) != 1 {
		t.Fatalf("got %d records want 1", len(got))
	}
	if got[0].Payload["gcid"] != v.Gcid {
		t.Errorf("gcid missing in rejected payload: %+v", got[0].Payload)
	}
}

func TestEconomyPublisher_PublishManaRefunded_NilEntryErrors(t *testing.T) {
	t.Parallel()
	p := events.NewEconomyPublisher(newRecorder())
	if err := p.PublishManaRefunded(newEnv("g"), nil); err == nil {
		t.Error("nil ledger entry must error")
	}
}

func TestEconomyPublisher_NilReceiver_Errors(t *testing.T) {
	t.Parallel()
	var p *events.EconomyPublisher
	if err := p.PublishManaSnapshot(events.Envelope{}, mana.SnapshotPayload{}); err == nil {
		t.Error("nil receiver must error")
	}
}
