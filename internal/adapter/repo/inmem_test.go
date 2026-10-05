// Tests for the per-user economy in-memory repos.
package repo_test

import (
	"context"
	"testing"
	"time"

	"github.com/apollo-chora/chora-identity/internal/adapter/repo"
	"github.com/apollo-chora/chora-identity/internal/domain/kyc"
	usersub "github.com/apollo-chora/chora-identity/internal/domain/user_subscription"
)

const gcidT = "01970000-0000-7000-8000-00000000abcd"

func newSub(t *testing.T) *usersub.Subscription {
	t.Helper()
	s, err := usersub.NewSubscription(usersub.NewParams{
		Gcid: gcidT, TenantID: "tenant-1", PlanCode: "familiar_basic",
		Tier: usersub.TierBasic, BillingPeriod: usersub.BillingMonthly,
		ManaMonthlyUnits: 500,
		PeriodStart:      time.Now().UTC(),
		PeriodEnd:        time.Now().UTC().Add(30 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	return s
}

func TestInMemUserSubscriptionRepo_SaveAndGet(t *testing.T) {
	t.Parallel()
	r := repo.NewInMemUserSubscriptionRepo()
	s := newSub(t)
	if err := r.Save(context.Background(), s); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := r.GetByID(context.Background(), s.SubscriptionID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.SubscriptionID != s.SubscriptionID {
		t.Errorf("id mismatch")
	}
}

func TestInMemUserSubscriptionRepo_GetMissing(t *testing.T) {
	t.Parallel()
	r := repo.NewInMemUserSubscriptionRepo()
	_, err := r.GetByID(context.Background(), "missing")
	if err == nil {
		t.Errorf("expected ErrNotFound")
	}
}

func TestInMemUserSubscriptionRepo_ListByGcid(t *testing.T) {
	t.Parallel()
	r := repo.NewInMemUserSubscriptionRepo()
	for i := 0; i < 3; i++ {
		s := newSub(t)
		_ = r.Save(context.Background(), s)
	}
	items, err := r.ListByGcid(context.Background(), gcidT)
	if err != nil {
		t.Fatalf("ListByGcid: %v", err)
	}
	if len(items) != 3 {
		t.Errorf("got %d want 3", len(items))
	}
}

func TestInMemUserSubscriptionRepo_SoftDeleteHidden(t *testing.T) {
	t.Parallel()
	r := repo.NewInMemUserSubscriptionRepo()
	s := newSub(t)
	s.SoftDelete()
	_ = r.Save(context.Background(), s)
	if _, err := r.GetByID(context.Background(), s.SubscriptionID); err == nil {
		t.Errorf("expected ErrNotFound for soft-deleted record")
	}
}

func TestInMemUserSubscriptionRepo_GetByStripeSubscriptionID(t *testing.T) {
	t.Parallel()
	r := repo.NewInMemUserSubscriptionRepo()
	s := newSub(t)
	s.StripeSubscriptionID = "sub_test_1234"
	if err := r.Save(context.Background(), s); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := r.GetByStripeSubscriptionID(context.Background(), "sub_test_1234")
	if err != nil {
		t.Fatalf("GetByStripeSubscriptionID: %v", err)
	}
	if got.SubscriptionID != s.SubscriptionID {
		t.Errorf("id mismatch: got %q", got.SubscriptionID)
	}
}

func TestInMemUserSubscriptionRepo_GetByStripeSubscriptionID_NotFound(t *testing.T) {
	t.Parallel()
	r := repo.NewInMemUserSubscriptionRepo()
	if _, err := r.GetByStripeSubscriptionID(context.Background(), "sub_missing"); err == nil {
		t.Errorf("expected ErrNotFound")
	}
}

func TestInMemUserSubscriptionRepo_GetByStripeSubscriptionID_EmptyHandleReturnsNotFound(t *testing.T) {
	t.Parallel()
	r := repo.NewInMemUserSubscriptionRepo()
	if _, err := r.GetByStripeSubscriptionID(context.Background(), ""); err == nil {
		t.Errorf("expected ErrNotFound on empty handle")
	}
}

func TestInMemUserSubscriptionRepo_GetByStripeSubscriptionID_SoftDeletedHidden(t *testing.T) {
	t.Parallel()
	r := repo.NewInMemUserSubscriptionRepo()
	s := newSub(t)
	s.StripeSubscriptionID = "sub_soft_deleted"
	s.SoftDelete()
	if err := r.Save(context.Background(), s); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := r.GetByStripeSubscriptionID(context.Background(), "sub_soft_deleted"); err == nil {
		t.Errorf("expected ErrNotFound for soft-deleted record")
	}
}

func TestInMemKycRepo_SaveAndGetLatest(t *testing.T) {
	t.Parallel()
	r := repo.NewInMemKycRepo()
	v1, _ := kyc.NewVerification(kyc.NewParams{Gcid: gcidT, Method: kyc.MethodSingpass, Provider: "ndi"})
	_ = r.Save(context.Background(), v1)
	time.Sleep(2 * time.Millisecond)
	v2, _ := kyc.NewVerification(kyc.NewParams{Gcid: gcidT, Method: kyc.MethodManualDoc, Provider: "internal_review"})
	_ = r.Save(context.Background(), v2)

	got, err := r.GetLatestByGcid(context.Background(), gcidT)
	if err != nil {
		t.Fatalf("GetLatestByGcid: %v", err)
	}
	if got.VerificationID != v2.VerificationID {
		t.Errorf("expected latest %q, got %q", v2.VerificationID, got.VerificationID)
	}
}

func TestInMemKycRepo_GetByID(t *testing.T) {
	t.Parallel()
	r := repo.NewInMemKycRepo()
	v, _ := kyc.NewVerification(kyc.NewParams{Gcid: gcidT, Method: kyc.MethodSingpass, Provider: "ndi"})
	_ = r.Save(context.Background(), v)
	got, err := r.GetByID(context.Background(), v.VerificationID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Status != kyc.StatusPending {
		t.Errorf("status=%q", got.Status)
	}
}

func TestInMemKycRepo_GetMissing(t *testing.T) {
	t.Parallel()
	r := repo.NewInMemKycRepo()
	if _, err := r.GetByID(context.Background(), "missing"); err == nil {
		t.Errorf("expected ErrNotFound")
	}
	if _, err := r.GetLatestByGcid(context.Background(), gcidT); err == nil {
		t.Errorf("expected ErrNotFound for empty repo")
	}
}
