// Coverage top-up for the repo package in-memory adapters — prefill repo,
// KYC save branches, mana store constructor, subscription pointer fields.
package repo_test

import (
	"context"
	"testing"
	"time"

	"github.com/apollo-chora/chora-identity/internal/adapter/repo"
	"github.com/apollo-chora/chora-identity/internal/domain/kyc"
	mana "github.com/apollo-chora/chora-identity/internal/domain/user_mana"
)

// -----------------------------------------------------------------------------
// InMemPrefillRepo
// -----------------------------------------------------------------------------

func prefill(t *testing.T, gcid string) *kyc.MyInfoPrefill {
	t.Helper()
	p, err := kyc.NewPrefill(kyc.NewPrefillParams{
		Gcid: gcid, FullName: "Phyllis Tan", UINFINRaw: "S1234567A",
		Email: "phyllis@mightymind.sg", MobileE164: "+6590000000",
		Source: "singpass_myinfo",
	})
	if err != nil {
		t.Fatalf("NewPrefill: %v", err)
	}
	return p
}

func TestInMemPrefillRepo_SaveAndGet(t *testing.T) {
	t.Parallel()
	r := repo.NewInMemPrefillRepo()
	ctx := context.Background()
	p := prefill(t, gcidT)

	if err := r.Save(ctx, p); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := r.GetByGcid(ctx, gcidT)
	if err != nil {
		t.Fatalf("GetByGcid: %v", err)
	}
	if got.FullName != p.FullName {
		t.Errorf("FullName = %q; want %q", got.FullName, p.FullName)
	}
	if !r.HasPrefill(gcidT) {
		t.Error("HasPrefill should be true after saving a live prefill")
	}
}

func TestInMemPrefillRepo_SaveUpsertsByGcid(t *testing.T) {
	t.Parallel()
	r := repo.NewInMemPrefillRepo()
	ctx := context.Background()
	p1 := prefill(t, gcidT)
	p2 := prefill(t, gcidT)
	p2.FullName = "Updated Name"
	_ = r.Save(ctx, p1)
	_ = r.Save(ctx, p2)

	got, _ := r.GetByGcid(ctx, gcidT)
	if got.FullName != "Updated Name" {
		t.Errorf("FullName = %q; want updated value", got.FullName)
	}
}

func TestInMemPrefillRepo_SoftDeletedHidden(t *testing.T) {
	t.Parallel()
	r := repo.NewInMemPrefillRepo()
	ctx := context.Background()
	p := prefill(t, gcidT)
	_ = r.Save(ctx, p)
	p.SoftDelete()
	_ = r.Save(ctx, p)

	if _, err := r.GetByGcid(ctx, gcidT); err == nil {
		t.Error("expected ErrPrefillNotFound for soft-deleted prefill")
	}
	if r.HasPrefill(gcidT) {
		t.Error("HasPrefill should be false after soft delete")
	}
}

func TestInMemPrefillRepo_GetMissing(t *testing.T) {
	t.Parallel()
	r := repo.NewInMemPrefillRepo()
	if _, err := r.GetByGcid(context.Background(), "missing-gcid"); err == nil {
		t.Error("expected ErrPrefillNotFound for empty repo")
	}
	if r.HasPrefill("missing-gcid") {
		t.Error("HasPrefill should be false for empty repo")
	}
}

func TestInMemPrefillRepo_DefensiveCopy(t *testing.T) {
	t.Parallel()
	r := repo.NewInMemPrefillRepo()
	ctx := context.Background()
	p := prefill(t, gcidT)
	_ = r.Save(ctx, p)
	p.FullName = "mutated-after-save"

	got, _ := r.GetByGcid(ctx, gcidT)
	if got.FullName == "mutated-after-save" {
		t.Error("stored prefill mutated by caller — Save must defensively copy")
	}
}

// -----------------------------------------------------------------------------
// InMemKycRepo — Save pointer-field branches + GetLatestByGcid filtering
// -----------------------------------------------------------------------------

func TestInMemKycRepo_Save_ClonesPointerFields(t *testing.T) {
	t.Parallel()
	r := repo.NewInMemKycRepo()
	ctx := context.Background()
	v, _ := kyc.NewVerification(kyc.NewParams{Gcid: gcidT, Method: kyc.MethodSingpass, Provider: "ndi"})

	now := time.Now().UTC()
	expires := now.Add(24 * time.Hour)
	v.VerifiedAt = &now
	v.RejectedAt = &now
	v.ExpiresAt = &expires
	v.AuditLog = append(v.AuditLog, kyc.AuditEntry{Event: "verified", ActorGcid: "admin"})
	if err := r.Save(ctx, v); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// All pointer fields survived the clone.
	got, err := r.GetByID(ctx, v.VerificationID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.VerifiedAt == nil || !got.VerifiedAt.Equal(now) {
		t.Errorf("VerifiedAt = %v; want %v", got.VerifiedAt, now)
	}
	if got.RejectedAt == nil || !got.RejectedAt.Equal(now) {
		t.Errorf("RejectedAt = %v; want %v", got.RejectedAt, now)
	}
	if got.ExpiresAt == nil {
		t.Error("ExpiresAt = nil; want set")
	}
	if len(got.AuditLog) != 2 {
		t.Errorf("AuditLog len = %d; want 2", len(got.AuditLog))
	}
}

func TestInMemKycRepo_GetByID_SoftDeletedHidden(t *testing.T) {
	t.Parallel()
	r := repo.NewInMemKycRepo()
	ctx := context.Background()
	v, _ := kyc.NewVerification(kyc.NewParams{Gcid: gcidT, Method: kyc.MethodSingpass, Provider: "ndi"})
	now := time.Now().UTC()
	v.DeletedAt = &now
	_ = r.Save(ctx, v)

	if _, err := r.GetByID(ctx, v.VerificationID); err == nil {
		t.Error("expected ErrNotFound for soft-deleted verification")
	}
}

func TestInMemKycRepo_GetLatestByGcid_FiltersOtherGcidAndDeleted(t *testing.T) {
	t.Parallel()
	r := repo.NewInMemKycRepo()
	ctx := context.Background()
	otherGcid := "01970000-0000-7000-8000-00000000beef"

	// Verification for a DIFFERENT gcid.
	vOther, _ := kyc.NewVerification(kyc.NewParams{Gcid: otherGcid, Method: kyc.MethodSingpass, Provider: "ndi"})
	_ = r.Save(ctx, vOther)

	// Soft-deleted verification for the target gcid.
	vDeleted, _ := kyc.NewVerification(kyc.NewParams{Gcid: gcidT, Method: kyc.MethodManualDoc, Provider: "review"})
	now := time.Now().UTC()
	vDeleted.DeletedAt = &now
	_ = r.Save(ctx, vDeleted)

	// Both must be excluded.
	if _, err := r.GetLatestByGcid(ctx, gcidT); err == nil {
		t.Error("expected ErrNotFound when only other-gcid + deleted rows exist")
	}

	// A live row for the gcid wins over the deleted + other-gcid rows.
	vLive, _ := kyc.NewVerification(kyc.NewParams{Gcid: gcidT, Method: kyc.MethodSingpass, Provider: "ndi"})
	_ = r.Save(ctx, vLive)
	got, err := r.GetLatestByGcid(ctx, gcidT)
	if err != nil {
		t.Fatalf("GetLatestByGcid: %v", err)
	}
	if got.VerificationID != vLive.VerificationID {
		t.Errorf("latest = %q; want %q", got.VerificationID, vLive.VerificationID)
	}
}

// -----------------------------------------------------------------------------
// InMemManaStore constructor
// -----------------------------------------------------------------------------

func TestNewInMemManaStore_IsUsableStore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := repo.NewInMemManaStore()
	if store == nil {
		t.Fatal("NewInMemManaStore returned nil")
	}

	// Exercises the wrapped mana.InMemoryStore via DeductMana + CreditMana.
	q := mana.NewQuoter(store)
	if _, err := q.CreditMana(ctx, mana.CreditInput{
		Gcid: gcidT, Source: mana.SourceSubscriptionGrant, Units: 500,
		Reason: mana.ReasonSubscriptionGrant, IdempotencyKey: "coverage-ck-1",
	}); err != nil {
		t.Fatalf("CreditMana: %v", err)
	}
	res, err := q.DeductMana(ctx, mana.DeductInput{
		Gcid: gcidT, ActionCode: "coverage-action", Units: 200, IdempotencyKey: "coverage-ck-2",
	})
	if err != nil {
		t.Fatalf("DeductMana: %v", err)
	}
	if res.BalanceAfterUnits != 300 {
		t.Errorf("balance = %d; want 300", res.BalanceAfterUnits)
	}
}

// -----------------------------------------------------------------------------
// InMemUserSubscriptionRepo — pointer-field cloning + list filtering
// -----------------------------------------------------------------------------

func TestInMemUserSubscriptionRepo_Save_ClonesPointerFields(t *testing.T) {
	t.Parallel()
	r := repo.NewInMemUserSubscriptionRepo()
	ctx := context.Background()
	s := newSub(t)
	now := time.Now().UTC()
	s.CancelledAt = &now
	_ = r.Save(ctx, s)

	got, err := r.GetByID(ctx, s.SubscriptionID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.CancelledAt == nil || !got.CancelledAt.Equal(now) {
		t.Errorf("CancelledAt = %v; want %v", got.CancelledAt, now)
	}
}

func TestInMemUserSubscriptionRepo_ListByGcid_FiltersOtherGcidAndDeleted(t *testing.T) {
	t.Parallel()
	r := repo.NewInMemUserSubscriptionRepo()
	ctx := context.Background()
	otherGcid := "01970000-0000-7000-8000-00000000cccc"

	live := newSub(t)
	_ = r.Save(ctx, live)

	other := newSub(t)
	other.Gcid = otherGcid
	_ = r.Save(ctx, other)

	deleted := newSub(t)
	deleted.SoftDelete()
	_ = r.Save(ctx, deleted)

	items, err := r.ListByGcid(ctx, gcidT)
	if err != nil {
		t.Fatalf("ListByGcid: %v", err)
	}
	if len(items) != 1 || items[0].SubscriptionID != live.SubscriptionID {
		t.Errorf("items = %d entries, want exactly the live one", len(items))
	}
}
