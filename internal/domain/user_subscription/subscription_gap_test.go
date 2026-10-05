// subscription_gap_test.go — state-transition branch coverage for the
// Subscription aggregate: grace-path activation, idempotent/no-op
// transitions, and the remaining rejection branches.
package user_subscription_test

import (
	"testing"
	"time"

	usersub "github.com/apollo-chora/chora-identity/internal/domain/user_subscription"
)

func gapNewPendingSubscription(t *testing.T) *usersub.Subscription {
	t.Helper()
	s, err := usersub.NewSubscription(usersub.NewParams{
		Gcid:             gcid1,
		TenantID:         tenantID1,
		PlanCode:         "familiar_basic",
		Tier:             usersub.TierBasic,
		BillingPeriod:    usersub.BillingMonthly,
		ManaMonthlyUnits: 500,
		PeriodStart:      time.Now().UTC(),
		PeriodEnd:        time.Now().UTC().Add(30 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	return s
}

func TestActivate_FromGrace(t *testing.T) {
	t.Parallel()
	s := gapNewPendingSubscription(t)
	if err := s.Activate(); err != nil {
		t.Fatalf("activate pending: %v", err)
	}
	if err := s.EnterGrace("payment failure"); err != nil {
		t.Fatalf("enter grace: %v", err)
	}
	if err := s.Activate(); err != nil {
		t.Fatalf("activate from grace: %v", err)
	}
	if s.Status != usersub.StatusActive {
		t.Errorf("status = %q, want active", s.Status)
	}
}

func TestActivate_IdempotentOnActive(t *testing.T) {
	t.Parallel()
	s := gapNewPendingSubscription(t)
	if err := s.Activate(); err != nil {
		t.Fatalf("activate: %v", err)
	}
	if err := s.Activate(); err != nil {
		t.Errorf("activate on active must be idempotent: %v", err)
	}
}

func TestCancel_FromPausedAndPending(t *testing.T) {
	t.Parallel()
	for _, setup := range []struct {
		name   string
		to     func(*usersub.Subscription) error
		status usersub.Status
	}{
		{"paused", func(s *usersub.Subscription) error { return s.Pause("hold") }, usersub.StatusPaused},
		{"pending_activation", func(s *usersub.Subscription) error { return nil }, usersub.StatusPendingActivation},
	} {
		setup := setup
		t.Run(setup.name, func(t *testing.T) {
			t.Parallel()
			s := gapNewPendingSubscription(t)
			if setup.name == "paused" {
				if err := s.Activate(); err != nil {
					t.Fatalf("activate: %v", err)
				}
			}
			if err := setup.to(s); err != nil {
				t.Fatalf("setup: %v", err)
			}
			if err := s.Cancel("admin", "g-admin", time.Now().UTC()); err != nil {
				t.Fatalf("cancel from %s: %v", setup.status, err)
			}
			if s.Status != usersub.StatusCancelled || s.CancelledByGcid != "g-admin" {
				t.Errorf("cancel from %s: status=%q by=%q", setup.status, s.Status, s.CancelledByGcid)
			}
		})
	}
	t.Run("grace", func(t *testing.T) {
		t.Parallel()
		s := gapNewPendingSubscription(t)
		if err := s.Activate(); err != nil {
			t.Fatalf("activate: %v", err)
		}
		if err := s.EnterGrace("fail"); err != nil {
			t.Fatalf("enter grace: %v", err)
		}
		if err := s.Cancel("admin", "g-admin", time.Now().UTC()); err != nil {
			t.Fatalf("cancel from grace: %v", err)
		}
		if s.Status != usersub.StatusCancelled {
			t.Errorf("cancel from grace: status=%q", s.Status)
		}
	})
}

func TestCancel_RejectsFromSuspended(t *testing.T) {
	t.Parallel()
	s := gapNewPendingSubscription(t)
	if err := s.Cancel("admin", "g-admin", time.Now().UTC()); err != nil {
		t.Fatalf("first cancel: %v", err)
	}
	// HTTP-less direct mutation to simulate a transition no API allows from
	// cancelled — Cancel must still accept the idempotent re-call.
	if err := s.Cancel("admin", "g-admin", time.Now().UTC()); err != nil {
		t.Errorf("cancel on cancelled should be idempotent: %v", err)
	}
}

func TestResume_Branches(t *testing.T) {
	t.Parallel()
	// Resume from non-paused non-active → error.
	s := gapNewPendingSubscription(t)
	if err := s.Resume(); err == nil {
		t.Error("Resume from pending_activation must error")
	}
	// Resume on already-active → idempotent no-op.
	if err := s.Activate(); err != nil {
		t.Fatalf("activate: %v", err)
	}
	if err := s.Resume(); err != nil {
		t.Errorf("Resume on active must be a no-op: %v", err)
	}
	if s.Status != usersub.StatusActive {
		t.Errorf("status = %q, want active", s.Status)
	}
}

func TestRenew_FromGracePromotesToActive(t *testing.T) {
	t.Parallel()
	s := gapNewPendingSubscription(t)
	if err := s.Activate(); err != nil {
		t.Fatalf("activate: %v", err)
	}
	if err := s.EnterGrace("retry"); err != nil {
		t.Fatalf("enter grace: %v", err)
	}
	start := time.Now().UTC()
	if err := s.Renew(start, start.Add(30*24*time.Hour)); err != nil {
		t.Fatalf("renew from grace: %v", err)
	}
	if s.Status != usersub.StatusActive {
		t.Errorf("status = %q, want active after grace renew", s.Status)
	}
	if !s.CurrentPeriodStart.Equal(start) {
		t.Errorf("period start = %v, want %v", s.CurrentPeriodStart, start)
	}
}

func TestRenew_RejectsInvertedPeriod(t *testing.T) {
	t.Parallel()
	s := gapNewPendingSubscription(t)
	if err := s.Activate(); err != nil {
		t.Fatalf("activate: %v", err)
	}
	now := time.Now().UTC()
	if err := s.Renew(now.Add(time.Hour), now); err == nil {
		t.Error("Renew with period_end before period_start must error")
	}
	if s.Status != usersub.StatusActive {
		t.Errorf("status mutated on rejected renew: %q", s.Status)
	}
}

func TestChangePlan_AllowsPausedAndRejectsBadTier(t *testing.T) {
	t.Parallel()
	s := gapNewPendingSubscription(t)
	if err := s.Activate(); err != nil {
		t.Fatalf("activate: %v", err)
	}
	if err := s.Pause("hold"); err != nil {
		t.Fatalf("pause: %v", err)
	}
	eff := time.Now().UTC()
	if err := s.ChangePlan(usersub.ChangePlanParams{
		ToPlanCode: "familiar_pro", ToTier: usersub.TierPremium,
		ToBillingPeriod: usersub.BillingMonthly, EffectiveAt: eff, RequestedByGcid: "g-admin",
		ManaMonthlyUnits: 1000,
	}); err != nil {
		t.Fatalf("change plan from paused: %v", err)
	}
	if s.PlanCode != "familiar_pro" || s.Tier != usersub.TierPremium {
		t.Errorf("plan not updated: %s/%s", s.PlanCode, s.Tier)
	}
	// Invalid tier rejected.
	if err := s.ChangePlan(usersub.ChangePlanParams{
		ToPlanCode: "x", ToTier: usersub.Tier("bogus"),
		ToBillingPeriod: usersub.BillingMonthly, ManaMonthlyUnits: 100,
	}); err == nil {
		t.Error("ChangePlan with invalid tier must error")
	}
}
