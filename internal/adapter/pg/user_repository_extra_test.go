// user_repository_extra_test.go — pushes user_repository.go toward 100%: the
// *PgxPoolQuerier constructor, the nil-arg guard, the non-ErrNoRows error
// branches of GetByGcid / FindByFederatedSubject / UpdateDisplayName /
// BackfillProfileDirectory, and the scanUser kyc-field mapping branches.
package pg_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/apollo-chora/chora-identity/internal/adapter/pg"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

func TestUserRepository_New(t *testing.T) {
	t.Parallel()
	r := pg.NewUserRepository(nil)
	if r == nil {
		t.Fatal("NewUserRepository(nil) must return a non-nil repo")
	}
}

func TestUserRepository_Save_NilUser(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{}
	r := pg.NewUserRepositoryWithQuerier(q)
	if err := r.Save(context.Background(), nil); err == nil {
		t.Fatal("Save(nil) err = nil, want fail-loud error")
	}
	if len(q.execCalls) != 0 {
		t.Fatalf("Save(nil) must not Exec; got %d", len(q.execCalls))
	}
}

func TestUserRepository_GetByGcid_ScanErrorWraps(t *testing.T) {
	t.Parallel()
	boom := errors.New("user scan boom")
	q := &stubQuerier{rowResponses: []func(dest ...any) error{
		func(...any) error { return boom },
	}}
	r := pg.NewUserRepositoryWithQuerier(q)
	_, err := r.GetByGcid(context.Background(), "01970000-0000-7000-8000-aaaaaaaaaaaa")
	if err == nil || errors.Is(err, identity.ErrUserNotFound) || !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom (NOT the not-found sentinel)", err)
	}
}

func TestUserRepository_GetByGcid_KycFieldsMapped(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	kycAt := now.Add(-time.Hour)
	q := &stubQuerier{rowResponses: []func(dest ...any) error{
		func(dest ...any) error {
			*dest[0].(*string) = "01970000-0000-7000-8000-aaaaaaaaaaaa"
			*dest[1].(*string) = "phyllis@chora.dev"
			*dest[2].(*string) = "Phyllis"
			*dest[3].(*string) = "oidc"
			*dest[4].(*string) = "sub-1"
			*dest[5].(*string) = "active"
			*dest[6].(*string) = "manual" // kyc_method
			*dest[7].(**time.Time) = &kycAt
			*dest[8].(*string) = "verified"
			*dest[9].(*time.Time) = now
			*dest[10].(*time.Time) = now
			return nil
		},
	}}
	r := pg.NewUserRepositoryWithQuerier(q)
	u, err := r.GetByGcid(context.Background(), "01970000-0000-7000-8000-aaaaaaaaaaaa")
	if err != nil {
		t.Fatalf("GetByGcid: %v", err)
	}
	if u.KycMethod != identity.KycMethod("manual") {
		t.Errorf("KycMethod = %q, want manual", u.KycMethod)
	}
	if u.KycVerifiedAt == nil || !u.KycVerifiedAt.Equal(kycAt) {
		t.Errorf("KycVerifiedAt = %v, want %v", u.KycVerifiedAt, kycAt)
	}
	if u.VerificationStatus != identity.VerificationStatusVerified {
		t.Errorf("VerificationStatus = %q, want verified", u.VerificationStatus)
	}
}

func TestUserRepository_FindByFederatedSubject_ScanErrorWraps(t *testing.T) {
	t.Parallel()
	boom := errors.New("federated scan boom")
	q := &stubQuerier{rowResponses: []func(dest ...any) error{
		func(...any) error { return boom },
	}}
	r := pg.NewUserRepositoryWithQuerier(q)
	_, found, err := r.FindByFederatedSubject(context.Background(), "sub-1")
	if found || err == nil || !errors.Is(err, boom) {
		t.Fatalf("found=%v err=%v, want non-not-found wrap", found, err)
	}
}

func TestUserRepository_UpdateDisplayName_NoTxRunnerFailsLoud(t *testing.T) {
	t.Parallel()
	// A bare stubQuerier does NOT satisfy pg.PlainTxQuerier — the atomic outbox
	// emit must refuse, never silently drop the projection event.
	r := pg.NewUserRepositoryWithQuerier(&stubQuerier{})
	if err := r.UpdateDisplayName(context.Background(), udnGcid, "Alice", udnTenant); err == nil {
		t.Fatal("expected error when the transactional runner is not wired")
	}
}

func TestUserRepository_UpdateDisplayName_SelectErrorWraps(t *testing.T) {
	t.Parallel()
	boom := errors.New("select boom")
	tx := &txStub{rowResponses: []func(dest ...any) error{
		func(...any) error { return boom }, // SELECT ... FOR UPDATE fails
	}}
	q := &txStubQuerier{tx: tx}
	r := pg.NewUserRepositoryWithQuerier(q)
	err := r.UpdateDisplayName(context.Background(), udnGcid, "Alice", udnTenant)
	if err == nil || errors.Is(err, identity.ErrUserNotFound) || !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom (NOT ErrUserNotFound)", err)
	}
}

func TestUserRepository_UpdateDisplayName_UpdateErrorWraps(t *testing.T) {
	t.Parallel()
	boom := errors.New("update boom")
	tx := &txStub{rowResponses: []func(dest ...any) error{
		func(dest ...any) error {
			*dest[0].(*string) = "alice@example.com"
			*dest[1].(*string) = "Old Name"
			return nil
		},
		func(...any) error { return boom }, // UPDATE ... RETURNING fails
	}}
	q := &txStubQuerier{tx: tx}
	r := pg.NewUserRepositoryWithQuerier(q)
	err := r.UpdateDisplayName(context.Background(), udnGcid, "Alice", udnTenant)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom", err)
	}
}

func TestBackfillProfileDirectory_ListQueryErrorWraps(t *testing.T) {
	t.Parallel()
	boom := errors.New("list query boom")
	tx := &txStub{queryErr: boom}
	q := &txStubQuerier{tx: tx}
	r := pg.NewUserRepositoryWithQuerier(q)
	scanned, emitted, err := r.BackfillProfileDirectory(context.Background(), backfillTenant)
	if err == nil || !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped list boom", err)
	}
	if scanned != 0 || emitted != 0 {
		t.Fatalf("scanned/emitted = %d/%d, want 0/0", scanned, emitted)
	}
}

func TestBackfillProfileDirectory_ScanErrorWraps(t *testing.T) {
	t.Parallel()
	boom := errors.New("scan boom")
	now := time.Now().UTC()
	tx := &txStub{queryResult: &rowsStub{
		rows:    [][]any{{"01970000-0000-7000-8000-000000000a01", "alice@example.com", "Alice", now}},
		scanErr: boom,
	}}
	q := &txStubQuerier{tx: tx}
	r := pg.NewUserRepositoryWithQuerier(q)
	if _, _, err := r.BackfillProfileDirectory(context.Background(), backfillTenant); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped scan boom", err)
	}
}

func TestBackfillProfileDirectory_RowsErrPropagates(t *testing.T) {
	t.Parallel()
	boom := errors.New("iter boom")
	now := time.Now().UTC()
	tx := &txStub{queryResult: &rowsStub{
		rows: [][]any{{"01970000-0000-7000-8000-000000000a01", "alice@example.com", "Alice", now}},
		err:  boom,
	}}
	q := &txStubQuerier{tx: tx}
	r := pg.NewUserRepositoryWithQuerier(q)
	if _, _, err := r.BackfillProfileDirectory(context.Background(), backfillTenant); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want rows.Err boom", err)
	}
}

func TestBackfillProfileDirectory_DefensiveBlankNameSkipped(t *testing.T) {
	t.Parallel()
	// Phase 1's WHERE excludes blanks, but the defensive skip in Phase 2 must
	// hold even if one slips through the stub rowset: it is not emitted.
	now := time.Now().UTC()
	tx := &txStub{queryResult: newRowsStub(
		[]any{"01970000-0000-7000-8000-000000000a01", "alice@example.com", "Alice Wonder", now},
		[]any{"01970000-0000-7000-8000-000000000a02", "bob@example.com", "", now}, // blank → skipped
	)}
	q := &txStubQuerier{tx: tx}
	r := pg.NewUserRepositoryWithQuerier(q)
	scanned, emitted, err := r.BackfillProfileDirectory(context.Background(), backfillTenant)
	if err != nil {
		t.Fatalf("BackfillProfileDirectory: %v", err)
	}
	if scanned != 2 || emitted != 1 {
		t.Fatalf("scanned/emitted = %d/%d, want 2/1 (blank name skipped)", scanned, emitted)
	}
	if len(tx.execSQL) != 1 {
		t.Fatalf("outbox INSERTs = %d, want 1", len(tx.execSQL))
	}
}
