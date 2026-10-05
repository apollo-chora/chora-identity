// Tests for user_subscription event payload helpers + soft-delete.
package user_subscription_test

import (
	"testing"
	"time"

	usersub "github.com/apollo-chora/chora-identity/internal/domain/user_subscription"
)

func TestTopicName_AllEvents(t *testing.T) {
	t.Parallel()
	cases := map[usersub.EventType]string{
		usersub.EventCreated:     "chora.identity.user_subscription.created.v1",
		usersub.EventRenewed:     "chora.identity.user_subscription.renewed.v1",
		usersub.EventCancelled:   "chora.identity.user_subscription.cancelled.v1",
		usersub.EventPlanChanged: "chora.identity.user_subscription.plan_changed.v1",
	}
	for evt, want := range cases {
		if got := usersub.TopicName(evt); got != want {
			t.Errorf("TopicName(%q)=%q want %q", evt, got, want)
		}
	}
}

func TestCreatedFrom_PopulatesFields(t *testing.T) {
	t.Parallel()
	s, _ := usersub.NewSubscription(usersub.NewParams{
		Gcid: "g1", TenantID: "t1", PlanCode: "familiar_basic",
		Tier: usersub.TierBasic, BillingPeriod: usersub.BillingMonthly,
		ManaMonthlyUnits: 500, OnboardingBonusUnits: 500,
		StripeSubscriptionID: "sub_x",
		PeriodStart:          time.Now().UTC(),
		PeriodEnd:            time.Now().UTC().Add(30 * 24 * time.Hour),
	})
	p := usersub.CreatedFrom(s)
	if p.SubscriptionID != s.SubscriptionID {
		t.Errorf("SubscriptionID mismatch")
	}
	if p.PlanCode != "familiar_basic" {
		t.Errorf("PlanCode=%q", p.PlanCode)
	}
	if p.ManaMonthlyUnits != 500 {
		t.Errorf("ManaMonthlyUnits=%d", p.ManaMonthlyUnits)
	}
}

func TestCancelledFrom_PreservesCancellationReason(t *testing.T) {
	t.Parallel()
	s, _ := usersub.NewSubscription(usersub.NewParams{
		Gcid: "g1", PlanCode: "familiar_basic", Tier: usersub.TierBasic,
		BillingPeriod: usersub.BillingMonthly, ManaMonthlyUnits: 500,
		PeriodStart: time.Now(), PeriodEnd: time.Now().Add(time.Hour),
	})
	_ = s.Activate()
	_ = s.Cancel("user_request", "g1", time.Now())
	p := usersub.CancelledFrom(s)
	if p.CancellationReason != "user_request" {
		t.Errorf("CancellationReason=%q", p.CancellationReason)
	}
	if p.CancelledAt.IsZero() {
		t.Errorf("CancelledAt should be set")
	}
}

func TestSoftDelete_SetsDeletedAt(t *testing.T) {
	t.Parallel()
	s, _ := usersub.NewSubscription(usersub.NewParams{
		Gcid: "g1", PlanCode: "familiar_basic", Tier: usersub.TierBasic,
		BillingPeriod: usersub.BillingMonthly, ManaMonthlyUnits: 500,
		PeriodStart: time.Now(), PeriodEnd: time.Now().Add(time.Hour),
	})
	s.SoftDelete()
	if s.DeletedAt == nil {
		t.Errorf("DeletedAt should be set")
	}
	prior := s.DeletedAt
	s.SoftDelete()
	if s.DeletedAt != prior {
		t.Errorf("SoftDelete should be idempotent")
	}
}

func TestMarkExpired_FromCancelled_NoOp(t *testing.T) {
	t.Parallel()
	s, _ := usersub.NewSubscription(usersub.NewParams{
		Gcid: "g1", PlanCode: "familiar_basic", Tier: usersub.TierBasic,
		BillingPeriod: usersub.BillingMonthly, ManaMonthlyUnits: 500,
		PeriodStart: time.Now(), PeriodEnd: time.Now().Add(time.Hour),
	})
	_ = s.Activate()
	_ = s.Cancel("x", "g1", time.Now())
	if err := s.MarkExpired(); err != nil {
		t.Fatalf("MarkExpired: %v", err)
	}
	if s.Status != usersub.StatusCancelled {
		t.Errorf("Status should remain cancelled, got %q", s.Status)
	}
}

func TestMarkExpired_FromActive(t *testing.T) {
	t.Parallel()
	s, _ := usersub.NewSubscription(usersub.NewParams{
		Gcid: "g1", PlanCode: "familiar_basic", Tier: usersub.TierBasic,
		BillingPeriod: usersub.BillingMonthly, ManaMonthlyUnits: 500,
		PeriodStart: time.Now(), PeriodEnd: time.Now().Add(time.Hour),
	})
	_ = s.Activate()
	if err := s.MarkExpired(); err != nil {
		t.Fatalf("MarkExpired: %v", err)
	}
	if s.Status != usersub.StatusExpired {
		t.Errorf("Status=%q", s.Status)
	}
	// Idempotent.
	if err := s.MarkExpired(); err != nil {
		t.Fatalf("MarkExpired #2: %v", err)
	}
}

func TestActivate_FromGrace_RecoverPath(t *testing.T) {
	t.Parallel()
	s, _ := usersub.NewSubscription(usersub.NewParams{
		Gcid: "g1", PlanCode: "familiar_basic", Tier: usersub.TierBasic,
		BillingPeriod: usersub.BillingMonthly, ManaMonthlyUnits: 500,
		PeriodStart: time.Now(), PeriodEnd: time.Now().Add(time.Hour),
	})
	_ = s.Activate()
	_ = s.EnterGrace("late")
	if err := s.Activate(); err != nil {
		t.Fatalf("Activate from grace: %v", err)
	}
	if s.Status != usersub.StatusActive {
		t.Errorf("Status=%q", s.Status)
	}
}

func TestRecoverFromGrace_Idempotent(t *testing.T) {
	t.Parallel()
	s, _ := usersub.NewSubscription(usersub.NewParams{
		Gcid: "g1", PlanCode: "familiar_basic", Tier: usersub.TierBasic,
		BillingPeriod: usersub.BillingMonthly, ManaMonthlyUnits: 500,
		PeriodStart: time.Now(), PeriodEnd: time.Now().Add(time.Hour),
	})
	if err := s.RecoverFromGrace(); err == nil {
		t.Errorf("expected error recovering from pending")
	}
}

func TestPause_FromPaused_NoOp(t *testing.T) {
	t.Parallel()
	s, _ := usersub.NewSubscription(usersub.NewParams{
		Gcid: "g1", PlanCode: "familiar_basic", Tier: usersub.TierBasic,
		BillingPeriod: usersub.BillingMonthly, ManaMonthlyUnits: 500,
		PeriodStart: time.Now(), PeriodEnd: time.Now().Add(time.Hour),
	})
	_ = s.Activate()
	_ = s.Pause("x")
	if err := s.Pause("y"); err != nil {
		t.Errorf("expected no-op")
	}
}

func TestRenew_RejectsBackwardsPeriod(t *testing.T) {
	t.Parallel()
	s, _ := usersub.NewSubscription(usersub.NewParams{
		Gcid: "g1", PlanCode: "familiar_basic", Tier: usersub.TierBasic,
		BillingPeriod: usersub.BillingMonthly, ManaMonthlyUnits: 500,
		PeriodStart: time.Now(), PeriodEnd: time.Now().Add(time.Hour),
	})
	_ = s.Activate()
	if err := s.Renew(time.Now(), time.Now().Add(-time.Hour)); err == nil {
		t.Errorf("expected error for backwards period")
	}
}

func TestIsActiveLike(t *testing.T) {
	t.Parallel()
	s, _ := usersub.NewSubscription(usersub.NewParams{
		Gcid: "g1", PlanCode: "familiar_basic", Tier: usersub.TierBasic,
		BillingPeriod: usersub.BillingMonthly, ManaMonthlyUnits: 500,
		PeriodStart: time.Now(), PeriodEnd: time.Now().Add(time.Hour),
	})
	if s.IsActiveLike() {
		t.Errorf("pending should not be active-like")
	}
	_ = s.Activate()
	if !s.IsActiveLike() {
		t.Errorf("active should be active-like")
	}
	_ = s.EnterGrace("x")
	if !s.IsActiveLike() {
		t.Errorf("grace should be active-like")
	}
	_ = s.Cancel("x", "g1", time.Now())
	if s.IsActiveLike() {
		t.Errorf("cancelled should not be active-like")
	}
}

func TestBillingPeriod_Valid(t *testing.T) {
	t.Parallel()
	for _, b := range []usersub.BillingPeriod{usersub.BillingMonthly, usersub.BillingAnnually} {
		if !b.Valid() {
			t.Errorf("%q.Valid()=false", b)
		}
	}
	if usersub.BillingPeriod("decadal").Valid() {
		t.Errorf("invalid billing accepted")
	}
}

func TestChangePlan_FromPaused_OK(t *testing.T) {
	t.Parallel()
	s, _ := usersub.NewSubscription(usersub.NewParams{
		Gcid: "g1", PlanCode: "familiar_basic", Tier: usersub.TierBasic,
		BillingPeriod: usersub.BillingMonthly, ManaMonthlyUnits: 500,
		PeriodStart: time.Now(), PeriodEnd: time.Now().Add(time.Hour),
	})
	_ = s.Activate()
	_ = s.Pause("x")
	if err := s.ChangePlan(usersub.ChangePlanParams{
		ToPlanCode: "familiar_premium", ToTier: usersub.TierPremium,
		ToBillingPeriod: usersub.BillingMonthly, ManaMonthlyUnits: 10000,
		EffectiveAt: time.Now(), RequestedByGcid: "g1",
	}); err != nil {
		t.Errorf("ChangePlan from paused: %v", err)
	}
}

func TestChangePlan_NegativeManaUnits(t *testing.T) {
	t.Parallel()
	s, _ := usersub.NewSubscription(usersub.NewParams{
		Gcid: "g1", PlanCode: "familiar_basic", Tier: usersub.TierBasic,
		BillingPeriod: usersub.BillingMonthly, ManaMonthlyUnits: 500,
		PeriodStart: time.Now(), PeriodEnd: time.Now().Add(time.Hour),
	})
	_ = s.Activate()
	if err := s.ChangePlan(usersub.ChangePlanParams{
		ToPlanCode: "familiar_premium", ToTier: usersub.TierPremium,
		ToBillingPeriod: usersub.BillingMonthly, ManaMonthlyUnits: -1,
		EffectiveAt: time.Now(), RequestedByGcid: "g1",
	}); err == nil {
		t.Errorf("expected error for negative mana_monthly_units")
	}
}
