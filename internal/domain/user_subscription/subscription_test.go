// Package user_subscription_test exercises Subscription state machine + invariants
// for the per-user Familiar plan aggregate (BE-USR-1, ADR-142).
//
// Wave 3 of the per-user economy build. RED-phase TDD specs.
package user_subscription_test

import (
	"strings"
	"testing"
	"time"

	usersub "github.com/apollo-chora/chora-identity/internal/domain/user_subscription"
)

const (
	gcid1     = "01970000-0000-7000-8000-000000000001"
	tenantID1 = "01970000-0000-7000-8000-0000000000a1"
)

// -----------------------------------------------------------------------------
// Construction invariants
// -----------------------------------------------------------------------------

func TestNewSubscription_AssignsUUIDv7AndPendingStatus(t *testing.T) {
	t.Parallel()
	s, err := usersub.NewSubscription(usersub.NewParams{
		Gcid:                 gcid1,
		TenantID:             tenantID1,
		PlanCode:             "familiar_basic",
		Tier:                 usersub.TierBasic,
		BillingPeriod:        usersub.BillingMonthly,
		ManaMonthlyUnits:     500,
		StripeSubscriptionID: "sub_test_1",
		PeriodStart:          time.Now().UTC(),
		PeriodEnd:            time.Now().UTC().Add(30 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if s.SubscriptionID == "" {
		t.Errorf("SubscriptionID empty")
	}
	if len(s.SubscriptionID) != 36 || s.SubscriptionID[14] != '7' {
		t.Errorf("SubscriptionID not UUIDv7: %q", s.SubscriptionID)
	}
	if s.Status != usersub.StatusPendingActivation {
		t.Errorf("Status=%q want pending_activation", s.Status)
	}
}

func TestNewSubscription_RejectsEmptyGcid(t *testing.T) {
	t.Parallel()
	_, err := usersub.NewSubscription(usersub.NewParams{
		Gcid:             "",
		TenantID:         tenantID1,
		PlanCode:         "familiar_basic",
		Tier:             usersub.TierBasic,
		BillingPeriod:    usersub.BillingMonthly,
		ManaMonthlyUnits: 500,
		PeriodStart:      time.Now().UTC(),
		PeriodEnd:        time.Now().UTC().Add(30 * 24 * time.Hour),
	})
	if err == nil {
		t.Fatalf("expected error for empty gcid")
	}
}

func TestNewSubscription_RejectsInvalidTier(t *testing.T) {
	t.Parallel()
	_, err := usersub.NewSubscription(usersub.NewParams{
		Gcid: gcid1, PlanCode: "x", Tier: usersub.Tier("godmode"),
		BillingPeriod: usersub.BillingMonthly, ManaMonthlyUnits: 1,
		PeriodStart: time.Now(), PeriodEnd: time.Now().Add(time.Hour),
	})
	if err == nil {
		t.Fatalf("expected error for invalid tier")
	}
}

func TestNewSubscription_RejectsInvalidBillingPeriod(t *testing.T) {
	t.Parallel()
	_, err := usersub.NewSubscription(usersub.NewParams{
		Gcid: gcid1, PlanCode: "x", Tier: usersub.TierBasic,
		BillingPeriod: usersub.BillingPeriod("weekly"), ManaMonthlyUnits: 1,
		PeriodStart: time.Now(), PeriodEnd: time.Now().Add(time.Hour),
	})
	if err == nil {
		t.Fatalf("expected error for invalid billing_period")
	}
}

func TestNewSubscription_RejectsNegativeManaUnits(t *testing.T) {
	t.Parallel()
	_, err := usersub.NewSubscription(usersub.NewParams{
		Gcid: gcid1, PlanCode: "x", Tier: usersub.TierBasic,
		BillingPeriod: usersub.BillingMonthly, ManaMonthlyUnits: -1,
		PeriodStart: time.Now(), PeriodEnd: time.Now().Add(time.Hour),
	})
	if err == nil {
		t.Fatalf("expected error for negative mana units")
	}
}

func TestNewSubscription_RejectsPeriodEndBeforeStart(t *testing.T) {
	t.Parallel()
	_, err := usersub.NewSubscription(usersub.NewParams{
		Gcid: gcid1, PlanCode: "x", Tier: usersub.TierBasic,
		BillingPeriod: usersub.BillingMonthly, ManaMonthlyUnits: 100,
		PeriodStart: time.Now().UTC(),
		PeriodEnd:   time.Now().UTC().Add(-time.Hour),
	})
	if err == nil {
		t.Fatalf("expected error for period_end < period_start")
	}
}

// -----------------------------------------------------------------------------
// State machine: pending → active → grace → cancelled (+ pause/resume)
// -----------------------------------------------------------------------------

func newPendingSubscription(t *testing.T) *usersub.Subscription {
	t.Helper()
	s, err := usersub.NewSubscription(usersub.NewParams{
		Gcid: gcid1, TenantID: tenantID1, PlanCode: "familiar_basic",
		Tier: usersub.TierBasic, BillingPeriod: usersub.BillingMonthly,
		ManaMonthlyUnits: 500, StripeSubscriptionID: "sub_x",
		PeriodStart: time.Now().UTC(),
		PeriodEnd:   time.Now().UTC().Add(30 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	return s
}

func TestActivate_PendingToActive(t *testing.T) {
	t.Parallel()
	s := newPendingSubscription(t)
	if err := s.Activate(); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if s.Status != usersub.StatusActive {
		t.Errorf("Status=%q want active", s.Status)
	}
}

func TestActivate_RejectsFromCancelled(t *testing.T) {
	t.Parallel()
	s := newPendingSubscription(t)
	_ = s.Activate()
	_ = s.Cancel("user_request", gcid1, time.Now())
	if err := s.Activate(); err == nil {
		t.Fatalf("expected error activating cancelled sub")
	}
}

func TestEnterGrace_OnPaymentFailure(t *testing.T) {
	t.Parallel()
	s := newPendingSubscription(t)
	_ = s.Activate()
	if err := s.EnterGrace("payment_failed"); err != nil {
		t.Fatalf("EnterGrace: %v", err)
	}
	if s.Status != usersub.StatusGrace {
		t.Errorf("Status=%q want grace", s.Status)
	}
}

func TestEnterGrace_RejectsFromPending(t *testing.T) {
	t.Parallel()
	s := newPendingSubscription(t)
	if err := s.EnterGrace("x"); err == nil {
		t.Fatalf("expected error EnterGrace from pending")
	}
}

func TestRecoverFromGrace_BackToActive(t *testing.T) {
	t.Parallel()
	s := newPendingSubscription(t)
	_ = s.Activate()
	_ = s.EnterGrace("late_payment")
	if err := s.RecoverFromGrace(); err != nil {
		t.Fatalf("RecoverFromGrace: %v", err)
	}
	if s.Status != usersub.StatusActive {
		t.Errorf("Status=%q want active", s.Status)
	}
}

func TestCancel_FromActive_SetsCancelledAtAndStatus(t *testing.T) {
	t.Parallel()
	s := newPendingSubscription(t)
	_ = s.Activate()
	now := time.Now().UTC()
	if err := s.Cancel("user_request", gcid1, now); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if s.Status != usersub.StatusCancelled {
		t.Errorf("Status=%q want cancelled", s.Status)
	}
	if s.CancelledAt == nil {
		t.Errorf("CancelledAt should be set")
	}
	if s.CancellationReason != "user_request" {
		t.Errorf("CancellationReason=%q", s.CancellationReason)
	}
}

func TestCancel_IsIdempotent(t *testing.T) {
	t.Parallel()
	s := newPendingSubscription(t)
	_ = s.Activate()
	_ = s.Cancel("user_request", gcid1, time.Now())
	if err := s.Cancel("user_request", gcid1, time.Now()); err != nil {
		t.Fatalf("Cancel should be idempotent: %v", err)
	}
}

func TestPause_ActiveToPaused_AndResume(t *testing.T) {
	t.Parallel()
	s := newPendingSubscription(t)
	_ = s.Activate()
	if err := s.Pause("compliance_hold"); err != nil {
		t.Fatalf("Pause: %v", err)
	}
	if s.Status != usersub.StatusPaused {
		t.Errorf("Status=%q want paused", s.Status)
	}
	if err := s.Resume(); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if s.Status != usersub.StatusActive {
		t.Errorf("Status=%q want active", s.Status)
	}
}

func TestPause_RejectsFromCancelled(t *testing.T) {
	t.Parallel()
	s := newPendingSubscription(t)
	_ = s.Activate()
	_ = s.Cancel("x", gcid1, time.Now())
	if err := s.Pause("x"); err == nil {
		t.Fatalf("expected error Pause from cancelled")
	}
}

func TestRenew_ExtendsPeriod_ActiveOnly(t *testing.T) {
	t.Parallel()
	s := newPendingSubscription(t)
	_ = s.Activate()
	priorEnd := s.CurrentPeriodEnd
	newStart := priorEnd
	newEnd := priorEnd.Add(30 * 24 * time.Hour)
	if err := s.Renew(newStart, newEnd); err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if !s.CurrentPeriodStart.Equal(newStart) || !s.CurrentPeriodEnd.Equal(newEnd) {
		t.Errorf("period not advanced")
	}
}

func TestRenew_RejectsFromCancelled(t *testing.T) {
	t.Parallel()
	s := newPendingSubscription(t)
	_ = s.Activate()
	_ = s.Cancel("x", gcid1, time.Now())
	if err := s.Renew(time.Now(), time.Now().Add(time.Hour)); err == nil {
		t.Fatalf("expected error renewing cancelled sub")
	}
}

// -----------------------------------------------------------------------------
// PlanChange — within active or grace state
// -----------------------------------------------------------------------------

func TestChangePlan_PreservesAuditFields(t *testing.T) {
	t.Parallel()
	s := newPendingSubscription(t)
	_ = s.Activate()
	prior := s.PlanCode
	if err := s.ChangePlan(usersub.ChangePlanParams{
		ToPlanCode:        "familiar_premium",
		ToTier:            usersub.TierPremium,
		ToBillingPeriod:   usersub.BillingMonthly,
		BillingDeltaCents: 3500,
		EffectiveAt:       time.Now().UTC(),
		RequestedByGcid:   gcid1,
		ManaMonthlyUnits:  10000,
	}); err != nil {
		t.Fatalf("ChangePlan: %v", err)
	}
	if s.PlanCode != "familiar_premium" || s.Tier != usersub.TierPremium {
		t.Errorf("plan not updated: %q/%q", s.PlanCode, s.Tier)
	}
	if s.PriorPlanCode != prior {
		t.Errorf("prior plan not retained: %q", s.PriorPlanCode)
	}
	if s.ManaMonthlyUnits != 10000 {
		t.Errorf("mana units not updated: %d", s.ManaMonthlyUnits)
	}
}

func TestChangePlan_RejectsCancelled(t *testing.T) {
	t.Parallel()
	s := newPendingSubscription(t)
	_ = s.Activate()
	_ = s.Cancel("x", gcid1, time.Now())
	err := s.ChangePlan(usersub.ChangePlanParams{
		ToPlanCode: "y", ToTier: usersub.TierBasic,
		ToBillingPeriod: usersub.BillingMonthly, EffectiveAt: time.Now(),
		RequestedByGcid: gcid1, ManaMonthlyUnits: 1,
	})
	if err == nil {
		t.Fatalf("expected error ChangePlan from cancelled")
	}
}

// -----------------------------------------------------------------------------
// Validity helpers
// -----------------------------------------------------------------------------

func TestTier_Valid(t *testing.T) {
	t.Parallel()
	for _, tt := range []usersub.Tier{
		usersub.TierBasic, usersub.TierStandard, usersub.TierPremium,
	} {
		if !tt.Valid() {
			t.Errorf("%q.Valid() = false", tt)
		}
	}
	if usersub.Tier("legendary").Valid() {
		t.Errorf("invalid tier accepted")
	}
}

func TestStatus_Strings(t *testing.T) {
	t.Parallel()
	cases := map[usersub.Status]string{
		usersub.StatusPendingActivation: "pending_activation",
		usersub.StatusActive:            "active",
		usersub.StatusPaused:            "paused",
		usersub.StatusCancelled:         "cancelled",
		usersub.StatusExpired:           "expired",
		usersub.StatusGrace:             "grace",
	}
	for s, want := range cases {
		if !strings.EqualFold(string(s), want) {
			t.Errorf("Status=%q want %q", s, want)
		}
	}
}
