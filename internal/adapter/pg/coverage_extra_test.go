// coverage_extra_test.go — last cheap error-branch batch across the pg repos:
// pending_invite, tenant_member_search, membership_admin (ChangeRole /
// GrantMembership / RemoveMember exec+scan errors), and user_mana happy get +
// scan error. All drive the shared stub harness — no live DB.
package pg

import (
	"context"
	"errors"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
	"strings"
	"testing"
	"time"
)

// -----------------------------------------------------------------------------
// user_mana — GetMana happy path (LastCreditedAt mapping) + FindLedger scan err
// -----------------------------------------------------------------------------

func TestManaStore_GetMana_HappyPath(t *testing.T) {
	now := time.Now().UTC()
	tx := &manaStubTx{queryRow: func(string, ...any) Row {
		return manaStubRow{scan: func(dest ...any) error {
			*dest[0].(*string) = manaTestGcid
			*dest[1].(*int64) = 5000
			*dest[2].(*int64) = 9000
			*dest[3].(*int64) = 4000
			*dest[4].(**time.Time) = &now
			*dest[5].(*int64) = 7
			*dest[6].(*time.Time) = now
			return nil
		}}
	}}
	got, err := NewManaStore(&manaStubUserTxr{tx: tx}).GetMana(context.Background(), manaTestGcid)
	if err != nil {
		t.Fatalf("GetMana: %v", err)
	}
	if got == nil || got.BalanceUnits != 5000 || got.Version != 7 {
		t.Fatalf("wallet = %+v", got)
	}
	if got.LastCreditedAt == nil || !got.LastCreditedAt.Equal(now) {
		t.Fatalf("LastCreditedAt = %v, want %v", got.LastCreditedAt, now)
	}
}

func TestManaStore_FindLedgerByIdempotencyKey_ScanErrorWraps(t *testing.T) {
	boom := errors.New("ledger scan boom")
	rows := &manaStubRows{scanFns: []func(dest ...any) error{
		func(...any) error { return boom },
	}}
	tx := &manaStubTx{query: func(string, ...any) (Rows, error) { return rows, nil }}
	_, err := NewManaStore(&manaStubUserTxr{tx: tx}).FindLedgerByIdempotencyKey(context.Background(), manaTestGcid, "idem-1")
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom", err)
	}
}

// -----------------------------------------------------------------------------
// membership_admin — ChangeRole upsert exec error + GrantMembership scan error
// + RemoveMember exec error
// -----------------------------------------------------------------------------

func TestMembershipAdmin_ChangeRole_upsertExecErrorPropagates(t *testing.T) {
	boom := errors.New("upsert blew up")
	tx := &stubTx{queryRowFn: rowQueue(&stubMemberSearchRow{vals: []any{1}}, ownerCounts(0, 1)), execErr: boom, execErrAt: 2}
	repo := NewMembershipAdminRepository(&stubTxQuerier{tx: tx})
	if err := repo.ChangeRole(context.Background(), maGcid, maTenant, identity.RoleAdmin); !errors.Is(err, boom) {
		t.Fatalf("err: got %v want wrapped boom", err)
	}
	if len(tx.queries) != 4 {
		t.Fatalf("queries: got %d want 4 (gate, owner guard, deactivate, upsert)", len(tx.queries))
	}
}

func TestMembershipAdmin_GrantMembership_scanErrorWraps(t *testing.T) {
	boom := errors.New("grant scan boom")
	tx := &stubTx{queryRowFn: rowQueue(&stubMemberSearchRow{err: boom})}
	repo := NewMembershipAdminRepository(&stubTxQuerier{tx: tx})
	_, err := repo.GrantMembership(context.Background(), maGcid, maTenant, []identity.Role{identity.RoleLearner})
	if !errors.Is(err, boom) {
		t.Fatalf("err: got %v want wrapped boom", err)
	}
}

func TestMembershipAdmin_RemoveMember_execErrorPropagates(t *testing.T) {
	boom := errors.New("remove blew up")
	tx := &stubTx{queryRowFn: rowQueue(&stubMemberSearchRow{vals: []any{1}}, ownerCounts(0, 1)), execErr: boom}
	repo := NewMembershipAdminRepository(&stubTxQuerier{tx: tx})
	if err := repo.RemoveMember(context.Background(), maGcid, maTenant); !errors.Is(err, boom) {
		t.Fatalf("err: got %v want wrapped boom", err)
	}
}

// -----------------------------------------------------------------------------
// tenant_member_search — Search query/scan/rows.Err error branches
// -----------------------------------------------------------------------------

func TestTenantMemberSearch_QueryErrorWraps(t *testing.T) {
	boom := errors.New("search query boom")
	tx := &stubTx{queryErr: boom}
	repo := NewTenantMemberSearchRepository(&stubTxQuerier{tx: tx})
	_, err := repo.Search(context.Background(), identity.TenantMemberSearchQuery{
		TenantID: "01970000-0000-7000-8000-0000000000aa", PageSize: 20,
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom", err)
	}
}

func TestTenantMemberSearch_ScanErrorWraps(t *testing.T) {
	boom := errors.New("search scan boom")
	tx := &stubTx{rows: &errRows{err: boom}}
	repo := NewTenantMemberSearchRepository(&stubTxQuerier{tx: tx})
	_, err := repo.Search(context.Background(), identity.TenantMemberSearchQuery{
		TenantID: "01970000-0000-7000-8000-0000000000aa", PageSize: 20,
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom", err)
	}
}

func TestTenantMemberSearch_RowsErrPropagates(t *testing.T) {
	boom := errors.New("search iter boom")
	rows := &stubRows{values: [][]any{phyllisRow(t)}, err: boom}
	tx := &stubTx{rows: rows}
	repo := NewTenantMemberSearchRepository(&stubTxQuerier{tx: tx})
	_, err := repo.Search(context.Background(), identity.TenantMemberSearchQuery{
		TenantID: "01970000-0000-7000-8000-0000000000aa", PageSize: 20,
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want rows.Err boom", err)
	}
}

// -----------------------------------------------------------------------------
// pending_invite — constructor panic + non-unique / scan / query errors
// -----------------------------------------------------------------------------

func TestNewPendingInviteRepository_nilPanicsLoud(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("nil TxQuerier must panic at boot")
		}
	}()
	NewPendingInviteRepository(nil)
}

func TestPendingInvite_Insert_NonUniqueErrorWraps(t *testing.T) {
	boom := errors.New("insert blew up (not a unique violation)")
	tx := &stubTx{execErr: boom}
	err := NewPendingInviteRepository(&stubTxQuerier{tx: tx}).Insert(context.Background(), mustInvite(t))
	if errors.Is(err, identity.ErrPendingInviteExists) || !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom (NOT ErrPendingInviteExists)", err)
	}
}

func TestPendingInvite_ListByTenant_errorBranches(t *testing.T) {
	// query error
	boom := errors.New("list boom")
	repo := NewPendingInviteRepository(&stubTxQuerier{tx: &stubTx{queryErr: boom}})
	if _, err := repo.ListByTenant(context.Background(), maTenant); !errors.Is(err, boom) {
		t.Fatalf("query err = %v, want wrapped boom", err)
	}
	// scan error
	repo = NewPendingInviteRepository(&stubTxQuerier{tx: &stubTx{rows: &errRows{err: boom}}})
	if _, err := repo.ListByTenant(context.Background(), maTenant); !errors.Is(err, boom) {
		t.Fatalf("scan err = %v, want wrapped boom", err)
	}
	// rows.Err
	row := []any{"inv-1", "anika@mtm.sg", []string{"instructor"}, maGcid, "tok-1", "pending",
		time.Now(), nil, nil, time.Now(), time.Now()}
	rows := &stubRows{values: [][]any{row}, err: boom}
	repo = NewPendingInviteRepository(&stubTxQuerier{tx: &stubTx{rows: rows}})
	if _, err := repo.ListByTenant(context.Background(), maTenant); !errors.Is(err, boom) {
		t.Fatalf("rows.Err = %v, want wrapped boom", err)
	}
}

func TestPendingInvite_Revoke_CustomScanErrorWraps(t *testing.T) {
	boom := errors.New("revoke scan boom")
	tx := &stubTx{queryRowFn: rowQueue(&stubMemberSearchRow{err: boom})}
	err := NewPendingInviteRepository(&stubTxQuerier{tx: tx}).Revoke(context.Background(), maTenant, "inv-1")
	if errors.Is(err, identity.ErrPendingInviteNotFound) || !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom (NOT ErrPendingInviteNotFound)", err)
	}
}

func TestPendingInvite_MatchByEmail_QueryErrorWraps(t *testing.T) {
	boom := errors.New("match boom")
	tx := &stubTx{queryErr: boom}
	_, err := NewPendingInviteRepository(&stubTxQuerier{tx: tx}).MatchByEmail(context.Background(), "anika@mtm.sg")
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom", err)
	}
}

func TestPendingInvite_MarkAccepted_CustomScanErrorWraps(t *testing.T) {
	boom := errors.New("accept scan boom")
	tx := &stubTx{queryRowFn: rowQueue(&stubMemberSearchRow{err: boom})}
	err := NewPendingInviteRepository(&stubTxQuerier{tx: tx}).MarkAccepted(context.Background(), maTenant, "inv-1", maGcid)
	if err == nil || !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom", err)
	}
}

// -----------------------------------------------------------------------------
// last reachable branches: ChangeRole validation, SetRoles upsert exec error,
// RemoveMember gate error, pending_invite nil/scan/accepted-branch,
// search default page size
// -----------------------------------------------------------------------------

func TestMembershipAdmin_ChangeRole_validatesInputs(t *testing.T) {
	repo := NewMembershipAdminRepository(&stubTxQuerier{tx: &stubTx{}})
	if err := repo.ChangeRole(context.Background(), "", maTenant, identity.RoleLearner); err == nil {
		t.Error("empty gcid must error")
	}
	if err := repo.ChangeRole(context.Background(), maGcid, "", identity.RoleLearner); err == nil {
		t.Error("empty tenant must error")
	}
	if err := repo.ChangeRole(context.Background(), maGcid, maTenant, identity.Role("bogus")); err == nil {
		t.Error("invalid role must error")
	}
}

func TestMembershipAdmin_SetRoles_upsertExecErrorWraps(t *testing.T) {
	boom := errors.New("role upsert blew up")
	// gate = QueryRow; deactivate = Exec #1 (ok); upsert = Exec #2 (fails).
	tx := &stubTx{queryRowFn: rowQueue(&stubMemberSearchRow{vals: []any{1}}, ownerCounts(0, 1)), execErr: boom, execErrAt: 2}
	repo := NewMembershipAdminRepository(&stubTxQuerier{tx: tx})
	err := repo.SetRoles(context.Background(), maGcid, maTenant, []identity.Role{identity.RoleLearner})
	if !errors.Is(err, boom) || !strings.Contains(err.Error(), "upsert role") {
		t.Fatalf("err = %v, want wrapped upsert boom", err)
	}
}

func TestMembershipAdmin_RemoveMember_CustomGateErrorWraps(t *testing.T) {
	boom := errors.New("gate blew up")
	tx := &stubTx{queryRowFn: rowQueue(&stubMemberSearchRow{err: boom})}
	repo := NewMembershipAdminRepository(&stubTxQuerier{tx: tx})
	err := repo.RemoveMember(context.Background(), maGcid, maTenant)
	if errors.Is(err, identity.ErrMembershipNotFound) || !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom (NOT ErrMembershipNotFound)", err)
	}
}

func TestPendingInvite_Insert_NilInviteErrors(t *testing.T) {
	repo := NewPendingInviteRepository(&stubTxQuerier{tx: &stubTx{}})
	if err := repo.Insert(context.Background(), nil); err == nil {
		t.Fatal("Insert(nil) err = nil, want fail-loud error")
	}
}

func TestPendingInvite_ListByTenant_AcceptedGcidBranch(t *testing.T) {
	now := time.Now()
	row := []any{"inv-1", "anika@mtm.sg", []string{"instructor"}, maGcid, "tok-1", "pending",
		now, now, "01970000-0000-7000-8000-00000000aabb", now, now}
	tx := &stubTx{rows: &stubRows{values: [][]any{row}}}
	out, err := NewPendingInviteRepository(&stubTxQuerier{tx: tx}).ListByTenant(context.Background(), maTenant)
	if err != nil {
		t.Fatalf("ListByTenant: %v", err)
	}
	if len(out) != 1 || out[0].AcceptedGcid != "01970000-0000-7000-8000-00000000aabb" {
		t.Fatalf("rows: %+v", out)
	}
}

func TestPendingInvite_MatchByEmail_ScanErrorWraps(t *testing.T) {
	boom := errors.New("match scan boom")
	tx := &stubTx{rows: &errRows{err: boom}}
	_, err := NewPendingInviteRepository(&stubTxQuerier{tx: tx}).MatchByEmail(context.Background(), "anika@mtm.sg")
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom", err)
	}
}

func TestTenantMemberSearch_DefaultPageSizeWhenZero(t *testing.T) {
	rows := &stubRows{values: [][]any{phyllisRow(t)}}
	tx := &stubTx{rows: rows}
	stq := &stubTxQuerier{tx: tx}
	// PageSize 0 → defaults to 20; LIMIT $3 must be 21 (20+1 sentinel).
	if _, err := NewTenantMemberSearchRepository(stq).Search(context.Background(), identity.TenantMemberSearchQuery{
		TenantID: "01970000-0000-7000-8000-0000000000aa",
	}); err != nil {
		t.Fatalf("Search: %v", err)
	}
	q := tx.queries[0]
	found := false
	for _, a := range q.Args {
		if n, ok := a.(int); ok && n == 21 {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("PageSize 0 must default to 20 (LIMIT 21); args=%v", q.Args)
	}
}
