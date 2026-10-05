// membership_admin_repository_test.go — TDD RED for the L1 Tenant lane
// (CHO-1707): pgx-backed AddMembership / ChangeRole keyed by
// (gcid, tenant_id). Stubs the TxQuerier surface (no live DB) and asserts
// the RLS-tx wrapping + SQL shape invariants, mirroring
// tenant_member_search_test.go. Live RLS isolation is integration-tested
// separately.
package pg

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

const (
	maTenant = "11111111-1111-7111-8111-111111111111"
	maGcid   = "00000000-0000-7000-8000-000000001999"
)

// rowQueue hands out one prepared Row per QueryRow call.
func rowQueue(rows ...Row) func(sql string, args ...any) Row {
	i := 0
	return func(_ string, _ ...any) Row {
		if i >= len(rows) {
			return &stubMemberSearchRow{err: ErrNoRows}
		}
		r := rows[i]
		i++
		return r
	}
}

func TestMembershipAdmin_Add_insertsInsideTenantTx(t *testing.T) {
	tx := &stubTx{queryRowFn: rowQueue(&stubMemberSearchRow{vals: []any{"mem-1"}})}
	q := &stubTxQuerier{tx: tx}
	repo := NewMembershipAdminRepository(q)

	err := repo.AddMembership(context.Background(), maGcid, maTenant, identity.RoleInstructor)
	if err != nil {
		t.Fatalf("AddMembership: %v", err)
	}
	if q.callCount != 1 || q.gotTenantID != maTenant {
		t.Fatalf("RunInTenantTx: calls=%d tenant=%s — RLS tx invariant broken", q.callCount, q.gotTenantID)
	}
	if len(tx.queries) != 1 {
		t.Fatalf("queries: got %d want 1", len(tx.queries))
	}
	sql := tx.queries[0].SQL
	for _, frag := range []string{"INSERT INTO tenant_memberships", "ON CONFLICT (gcid, tenant_id, role) DO NOTHING", "RETURNING membership_id", "membership_role", "'active'"} {
		if !strings.Contains(sql, frag) {
			t.Errorf("SQL missing %q:\n%s", frag, sql)
		}
	}
	args := tx.queries[0].Args
	if len(args) != 3 || args[0] != maGcid || args[1] != maTenant || args[2] != "instructor" {
		t.Errorf("args: got %v want [gcid tenant instructor]", args)
	}
}

func TestMembershipAdmin_Grant_upsertsMultiRoleInsideTenantTx(t *testing.T) {
	tx := &stubTx{queryRowFn: rowQueue(
		&stubMemberSearchRow{vals: []any{"mem-1"}},
		&stubMemberSearchRow{vals: []any{"mem-2"}},
	)}
	q := &stubTxQuerier{tx: tx}
	repo := NewMembershipAdminRepository(q)

	id, err := repo.GrantMembership(context.Background(), maGcid, maTenant,
		[]identity.Role{identity.RoleInstructor, identity.RoleAdmin})
	if err != nil {
		t.Fatalf("GrantMembership: %v", err)
	}
	// Representative id = the first role's row.
	if id != "mem-1" {
		t.Errorf("membership_id: got %q want mem-1", id)
	}
	// One RLS tx wraps the whole multi-role grant.
	if q.callCount != 1 || q.gotTenantID != maTenant {
		t.Fatalf("RunInTenantTx: calls=%d tenant=%s — RLS tx invariant broken", q.callCount, q.gotTenantID)
	}
	// One idempotent upsert per role.
	if len(tx.queries) != 2 {
		t.Fatalf("queries: got %d want 2", len(tx.queries))
	}
	for _, frag := range []string{"INSERT INTO tenant_memberships", "ON CONFLICT (gcid, tenant_id, role) DO UPDATE", "'active'", "RETURNING membership_id"} {
		if !strings.Contains(tx.queries[0].SQL, frag) {
			t.Errorf("SQL missing %q:\n%s", frag, tx.queries[0].SQL)
		}
	}
	if tx.queries[0].Args[2] != "instructor" || tx.queries[1].Args[2] != "admin" {
		t.Errorf("role args (lowercase): got %v / %v", tx.queries[0].Args, tx.queries[1].Args)
	}
}

func TestMembershipAdmin_Grant_validatesInputs(t *testing.T) {
	repo := NewMembershipAdminRepository(&stubTxQuerier{tx: &stubTx{}})
	if _, err := repo.GrantMembership(context.Background(), "", maTenant, []identity.Role{identity.RoleLearner}); err == nil {
		t.Error("empty gcid must error")
	}
	if _, err := repo.GrantMembership(context.Background(), maGcid, maTenant, nil); err == nil {
		t.Error("empty roles must error")
	}
	if _, err := repo.GrantMembership(context.Background(), maGcid, maTenant, []identity.Role{"bogus"}); err == nil {
		t.Error("invalid role must error")
	}
}

func TestMembershipAdmin_Add_duplicateMapsToErrMembershipExists(t *testing.T) {
	tx := &stubTx{queryRowFn: rowQueue(&stubMemberSearchRow{err: ErrNoRows})}
	q := &stubTxQuerier{tx: tx}
	repo := NewMembershipAdminRepository(q)

	err := repo.AddMembership(context.Background(), maGcid, maTenant, identity.RoleLearner)
	if !errors.Is(err, identity.ErrMembershipExists) {
		t.Fatalf("err: got %v want ErrMembershipExists", err)
	}
}

func TestMembershipAdmin_Add_validatesInputs(t *testing.T) {
	repo := NewMembershipAdminRepository(&stubTxQuerier{tx: &stubTx{}})
	if err := repo.AddMembership(context.Background(), "", maTenant, identity.RoleLearner); err == nil {
		t.Error("empty gcid must error")
	}
	if err := repo.AddMembership(context.Background(), maGcid, "", identity.RoleLearner); err == nil {
		t.Error("empty tenant must error")
	}
	if err := repo.AddMembership(context.Background(), maGcid, maTenant, identity.Role("owner")); err == nil {
		t.Error("invalid role must error")
	}
}

// ChangeRole is a SET-REPLACE under the multi-role mirror (identity mig
// 0020 UNIQUE(gcid, tenant_id, role)): existence gate → deactivate every
// OTHER active role → upsert the target role active.
func TestMembershipAdmin_ChangeRole_setReplaceInsideTenantTx(t *testing.T) {
	tx := &stubTx{queryRowFn: rowQueue(&stubMemberSearchRow{vals: []any{1}}, ownerCounts(0, 1))}
	q := &stubTxQuerier{tx: tx}
	repo := NewMembershipAdminRepository(q)

	err := repo.ChangeRole(context.Background(), maGcid, maTenant, identity.RoleAdmin)
	if err != nil {
		t.Fatalf("ChangeRole: %v", err)
	}
	if q.gotTenantID != maTenant {
		t.Fatalf("RunInTenantTx tenant: got %s", q.gotTenantID)
	}
	if len(tx.queries) != 4 {
		t.Fatalf("queries: got %d want 4 (gate, owner guard, deactivate-others, upsert)", len(tx.queries))
	}

	gate := tx.queries[0]
	for _, frag := range []string{"SELECT 1", "FROM tenant_memberships", "status = 'active'"} {
		if !strings.Contains(gate.SQL, frag) {
			t.Errorf("gate SQL missing %q:\n%s", frag, gate.SQL)
		}
	}
	if len(gate.Args) != 2 || gate.Args[0] != maGcid || gate.Args[1] != maTenant {
		t.Errorf("gate args: got %v want [gcid tenant]", gate.Args)
	}

	// Index 1 is the S7-B1 owner guard; the write statements shift by one.
	deact := tx.queries[2]
	for _, frag := range []string{"UPDATE tenant_memberships", "SET status = 'inactive'", "updated_at = now()", "role <> $3", "status = 'active'"} {
		if !strings.Contains(deact.SQL, frag) {
			t.Errorf("deactivate SQL missing %q:\n%s", frag, deact.SQL)
		}
	}
	if len(deact.Args) != 3 || deact.Args[0] != maGcid || deact.Args[1] != maTenant || deact.Args[2] != "admin" {
		t.Errorf("deactivate args: got %v want [gcid tenant admin]", deact.Args)
	}

	upsert := tx.queries[3]
	for _, frag := range []string{"INSERT INTO tenant_memberships", "ON CONFLICT (gcid, tenant_id, role) DO UPDATE", "status = 'active'", "updated_at = now()"} {
		if !strings.Contains(upsert.SQL, frag) {
			t.Errorf("upsert SQL missing %q:\n%s", frag, upsert.SQL)
		}
	}
	if len(upsert.Args) != 3 || upsert.Args[0] != maGcid || upsert.Args[1] != maTenant || upsert.Args[2] != "admin" {
		t.Errorf("upsert args: got %v want [gcid tenant admin]", upsert.Args)
	}
}

func TestMembershipAdmin_ChangeRole_missingRowMapsToNotFound(t *testing.T) {
	tx := &stubTx{queryRowFn: rowQueue(&stubMemberSearchRow{err: ErrNoRows})}
	repo := NewMembershipAdminRepository(&stubTxQuerier{tx: tx})

	err := repo.ChangeRole(context.Background(), maGcid, maTenant, identity.RoleAdmin)
	if !errors.Is(err, identity.ErrMembershipNotFound) {
		t.Fatalf("err: got %v want ErrMembershipNotFound", err)
	}
	if len(tx.queries) != 1 {
		t.Fatalf("queries after gate miss: got %d want 1 (no writes)", len(tx.queries))
	}
}

func TestMembershipAdmin_ChangeRole_execErrorPropagates(t *testing.T) {
	boom := errors.New("write blew up")
	tx := &stubTx{queryRowFn: rowQueue(&stubMemberSearchRow{vals: []any{1}}, ownerCounts(0, 1)), execErr: boom}
	repo := NewMembershipAdminRepository(&stubTxQuerier{tx: tx})

	if err := repo.ChangeRole(context.Background(), maGcid, maTenant, identity.RoleAdmin); !errors.Is(err, boom) {
		t.Fatalf("err: got %v want wrapped boom", err)
	}
}

// RemoveMember (WS2b / CHO-1869): existence gate (any ACTIVE row) → deactivate
// every active row (status → inactive). Soft-delete only; no per-role filter.
func TestMembershipAdmin_RemoveMember_softDeletesAllActiveRows(t *testing.T) {
	tx := &stubTx{queryRowFn: rowQueue(&stubMemberSearchRow{vals: []any{1}}, ownerCounts(0, 1))}
	q := &stubTxQuerier{tx: tx}
	repo := NewMembershipAdminRepository(q)

	if err := repo.RemoveMember(context.Background(), maGcid, maTenant); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}
	if q.gotTenantID != maTenant {
		t.Fatalf("RunInTenantTx tenant: got %s want %s", q.gotTenantID, maTenant)
	}
	if len(tx.queries) != 3 {
		t.Fatalf("queries: got %d want 3 (gate, owner guard, deactivate-all)", len(tx.queries))
	}
	gate := tx.queries[0]
	for _, frag := range []string{"SELECT 1", "FROM tenant_memberships", "status = 'active'"} {
		if !strings.Contains(gate.SQL, frag) {
			t.Errorf("gate SQL missing %q:\n%s", frag, gate.SQL)
		}
	}
	// Index 1 is the S7-B1 owner guard; the write statements shift by one.
	deact := tx.queries[2]
	for _, frag := range []string{"UPDATE tenant_memberships", "SET status = 'inactive'", "updated_at = now()", "status = 'active'"} {
		if !strings.Contains(deact.SQL, frag) {
			t.Errorf("deactivate SQL missing %q:\n%s", frag, deact.SQL)
		}
	}
	// Member-centric remove erases ALL roles — NO per-role filter.
	if strings.Contains(deact.SQL, "role <> $") || strings.Contains(deact.SQL, "<> ALL") {
		t.Errorf("RemoveMember must NOT filter by role:\n%s", deact.SQL)
	}
	if len(deact.Args) != 2 || deact.Args[0] != maGcid || deact.Args[1] != maTenant {
		t.Errorf("deactivate args: got %v want [gcid tenant]", deact.Args)
	}
}

func TestMembershipAdmin_RemoveMember_noActiveRowMapsToNotFound(t *testing.T) {
	tx := &stubTx{queryRowFn: rowQueue(&stubMemberSearchRow{err: ErrNoRows})}
	repo := NewMembershipAdminRepository(&stubTxQuerier{tx: tx})
	if err := repo.RemoveMember(context.Background(), maGcid, maTenant); !errors.Is(err, identity.ErrMembershipNotFound) {
		t.Fatalf("err: got %v want ErrMembershipNotFound", err)
	}
	if len(tx.queries) != 1 {
		t.Fatalf("queries after gate miss: got %d want 1 (no writes)", len(tx.queries))
	}
}

func TestMembershipAdmin_RemoveMember_validatesInputs(t *testing.T) {
	repo := NewMembershipAdminRepository(&stubTxQuerier{tx: &stubTx{}})
	if err := repo.RemoveMember(context.Background(), "", maTenant); err == nil {
		t.Error("empty gcid must error")
	}
	if err := repo.RemoveMember(context.Background(), maGcid, ""); err == nil {
		t.Error("empty tenant must error")
	}
}

// The bootstrap mirror upserter must share the 3-col conflict target —
// migration 0020 drops UNIQUE(gcid, tenant_id), so the 2-col target
// starts 42P10-failing the moment 0020 applies.
func TestMembershipBootstrapUpserter_threeColConflictTarget(t *testing.T) {
	// The constructor demands a *PgxPoolQuerier, so the SQL shape is
	// asserted via the extracted Tx-seam body.
	tx := &stubTx{}
	q := &stubTxQuerier{tx: tx}
	err := q.RunInTenantTx(context.Background(), maTenant, func(ctx context.Context, tx Tx) error {
		return bootstrapUpsertExec(ctx, tx, maGcid, maTenant, "learner")
	})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if len(tx.queries) != 1 {
		t.Fatalf("queries: got %d want 1", len(tx.queries))
	}
	sql := tx.queries[0].SQL
	for _, frag := range []string{"INSERT INTO tenant_memberships", "ON CONFLICT (gcid, tenant_id, role) DO NOTHING"} {
		if !strings.Contains(sql, frag) {
			t.Errorf("SQL missing %q:\n%s", frag, sql)
		}
	}
}

func TestMembershipBootstrapUpserter_validatesInputs(t *testing.T) {
	// Validation fires before the querier is touched, so a zero-value
	// upserter is safe here (the constructor itself panics on nil).
	u := &MembershipBootstrapUpserter{}
	for name, args := range map[string][3]string{
		"empty gcid":   {"", maTenant, "learner"},
		"empty tenant": {maGcid, "", "learner"},
		"empty role":   {maGcid, maTenant, ""},
	} {
		if err := u.UpsertMembershipOnBootstrap(context.Background(), args[0], args[1], args[2]); err == nil {
			t.Errorf("%s: want validation error", name)
		}
	}
}

func TestMembershipBootstrapUpserter_execErrorWraps(t *testing.T) {
	boom := errors.New("insert blew up")
	tx := &stubTx{execErr: boom}
	q := &stubTxQuerier{tx: tx}
	err := q.RunInTenantTx(context.Background(), maTenant, func(ctx context.Context, tx Tx) error {
		return bootstrapUpsertExec(ctx, tx, maGcid, maTenant, "learner")
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err: got %v want wrapped boom", err)
	}
}

func TestMembershipAdmin_beginErrorPropagates(t *testing.T) {
	repo := NewMembershipAdminRepository(&stubTxQuerier{tx: &stubTx{}, errOnBegin: errors.New("pool down")})
	if err := repo.AddMembership(context.Background(), maGcid, maTenant, identity.RoleLearner); err == nil {
		t.Error("begin error must propagate (add)")
	}
	if err := repo.ChangeRole(context.Background(), maGcid, maTenant, identity.RoleLearner); err == nil {
		t.Error("begin error must propagate (change)")
	}
}

// -----------------------------------------------------------------------------
// UserRepository.FindByEmail (L1 — resolves invite email → User)
// -----------------------------------------------------------------------------

type emailStubQuerier struct {
	gotSQL  string
	gotArgs []any
	row     Row
}

func (s *emailStubQuerier) Exec(context.Context, string, ...any) error { return nil }
func (s *emailStubQuerier) QueryRow(_ context.Context, sql string, args ...any) Row {
	s.gotSQL = sql
	s.gotArgs = args
	return s.row
}

func TestUserRepository_FindByEmail_hit(t *testing.T) {
	row := &stubMemberSearchRow{vals: []any{
		maGcid, "anika@mtm.sg", "Anika", "google", "sub-1", "active", "", nil, "unverified", nil, nil,
	}}
	q := &emailStubQuerier{row: row}
	repo := NewUserRepositoryWithQuerier(q)

	u, found, err := repo.FindByEmail(context.Background(), "Anika@MTM.sg")
	if err != nil || !found {
		t.Fatalf("FindByEmail: found=%v err=%v", found, err)
	}
	if u.Gcid != maGcid || u.Email != "anika@mtm.sg" {
		t.Errorf("user: got %+v", u)
	}
	if !strings.Contains(q.gotSQL, "lower(email) = lower($1)") {
		t.Errorf("SQL must match email case-insensitively:\n%s", q.gotSQL)
	}
	if !strings.Contains(q.gotSQL, "deleted_at IS NULL") {
		t.Errorf("SQL must exclude soft-deleted users:\n%s", q.gotSQL)
	}
}

func TestUserRepository_FindByEmail_miss(t *testing.T) {
	q := &emailStubQuerier{row: &stubMemberSearchRow{err: ErrNoRows}}
	repo := NewUserRepositoryWithQuerier(q)
	u, found, err := repo.FindByEmail(context.Background(), "ghost@mtm.sg")
	if err != nil {
		t.Fatalf("miss must not error: %v", err)
	}
	if found || u != nil {
		t.Errorf("miss: found=%v u=%v", found, u)
	}
}

func TestMembershipAdmin_genericScanErrorsWrapNotMap(t *testing.T) {
	boom := errors.New("disk on fire")
	tx := &stubTx{queryRowFn: rowQueue(&stubMemberSearchRow{err: boom})}
	repo := NewMembershipAdminRepository(&stubTxQuerier{tx: tx})
	if err := repo.AddMembership(context.Background(), maGcid, maTenant, identity.RoleLearner); !errors.Is(err, boom) {
		t.Errorf("add: got %v want wrapped boom", err)
	}
	tx2 := &stubTx{queryRowFn: rowQueue(&stubMemberSearchRow{err: boom})}
	repo2 := NewMembershipAdminRepository(&stubTxQuerier{tx: tx2})
	if err := repo2.ChangeRole(context.Background(), maGcid, maTenant, identity.RoleLearner); !errors.Is(err, boom) {
		t.Errorf("change: got %v want wrapped boom", err)
	}
}

func TestNewMembershipAdminRepository_nilPanicsLoud(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("nil TxQuerier must panic at boot")
		}
	}()
	NewMembershipAdminRepository(nil)
}

func TestUserRepository_FindByEmail_dbError(t *testing.T) {
	boom := errors.New("conn reset")
	q := &emailStubQuerier{row: &stubMemberSearchRow{err: boom}}
	repo := NewUserRepositoryWithQuerier(q)
	_, found, err := repo.FindByEmail(context.Background(), "anika@mtm.sg")
	if found || err == nil {
		t.Fatalf("db error must propagate: found=%v err=%v", found, err)
	}
}

// -----------------------------------------------------------------------------
// SetRoles — the REPLACE flavour of ChangeRole (CHO-1809 H+ multi-role editor)
// -----------------------------------------------------------------------------

func TestMembershipAdmin_SetRoles_setReplaceInsideTenantTx(t *testing.T) {
	tx := &stubTx{queryRowFn: rowQueue(&stubMemberSearchRow{vals: []any{1}}, ownerCounts(0, 1))}
	q := &stubTxQuerier{tx: tx}
	repo := NewMembershipAdminRepository(q)

	err := repo.SetRoles(context.Background(), maGcid, maTenant,
		[]identity.Role{identity.RoleInstructor, identity.RoleAdmin, identity.RoleInstructor /* dup deduped */})
	if err != nil {
		t.Fatalf("SetRoles: %v", err)
	}
	if q.gotTenantID != maTenant {
		t.Fatalf("RunInTenantTx tenant: got %s", q.gotTenantID)
	}
	// gate + deactivate + 1 upsert per DEDUPED role = 4 queries.
	if len(tx.queries) != 5 {
		t.Fatalf("queries: got %d want 5 (gate, owner guard, deactivate, 2 upserts)", len(tx.queries))
	}
	gate := tx.queries[0]
	for _, frag := range []string{"SELECT 1", "FROM tenant_memberships"} {
		if !strings.Contains(gate.SQL, frag) {
			t.Errorf("gate SQL missing %q:\n%s", frag, gate.SQL)
		}
	}
	// The deactivate statement must be the role-set-replace: <> ALL ($3::text[]).
	// Index 1 is the S7-B1 owner guard; the write statements shift by one.
	deact := tx.queries[2]
	for _, frag := range []string{"UPDATE tenant_memberships", "SET status = 'inactive'", "role::text <> ALL", "status = 'active'"} {
		if !strings.Contains(deact.SQL, frag) {
			t.Errorf("deactivate SQL missing %q:\n%s", frag, deact.SQL)
		}
	}
	if len(deact.Args) != 3 || deact.Args[0] != maGcid || deact.Args[1] != maTenant {
		t.Errorf("deactivate args: got %v", deact.Args)
	}
	rolesArg, ok := deact.Args[2].([]string)
	if !ok || len(rolesArg) != 2 || rolesArg[0] != "instructor" || rolesArg[1] != "admin" {
		t.Errorf("deactivate roles arg: got %#v want deduped [instructor admin]", deact.Args[2])
	}
	// Per-role upserts reuse the ChangeRole pattern (flip-back support).
	upsert := tx.queries[3]
	for _, frag := range []string{"INSERT INTO tenant_memberships", "ON CONFLICT (gcid, tenant_id, role) DO UPDATE", "status = 'active'"} {
		if !strings.Contains(upsert.SQL, frag) {
			t.Errorf("upsert SQL missing %q:\n%s", frag, upsert.SQL)
		}
	}
	if tx.queries[3].Args[2] != "instructor" || tx.queries[4].Args[2] != "admin" {
		t.Errorf("upsert role args: %v / %v", tx.queries[3].Args, tx.queries[4].Args)
	}
}

func TestMembershipAdmin_SetRoles_validatesInputs(t *testing.T) {
	repo := NewMembershipAdminRepository(&stubTxQuerier{tx: &stubTx{}})
	if err := repo.SetRoles(context.Background(), "", maTenant, []identity.Role{identity.RoleLearner}); err == nil {
		t.Error("empty gcid must error")
	}
	if err := repo.SetRoles(context.Background(), maGcid, "", []identity.Role{identity.RoleLearner}); err == nil {
		t.Error("empty tenant must error")
	}
	if err := repo.SetRoles(context.Background(), maGcid, maTenant, nil); err == nil {
		t.Error("empty roles must error")
	}
	if err := repo.SetRoles(context.Background(), maGcid, maTenant, []identity.Role{}); err == nil {
		t.Error("empty roles slice must error")
	}
}

func TestMembershipAdmin_SetRoles_missingRowMapsToNotFound(t *testing.T) {
	tx := &stubTx{queryRowFn: rowQueue(&stubMemberSearchRow{err: ErrNoRows})}
	repo := NewMembershipAdminRepository(&stubTxQuerier{tx: tx})
	err := repo.SetRoles(context.Background(), maGcid, maTenant, []identity.Role{identity.RoleLearner})
	if !errors.Is(err, identity.ErrMembershipNotFound) {
		t.Fatalf("err: got %v want ErrMembershipNotFound", err)
	}
	if len(tx.queries) != 1 {
		t.Fatalf("queries after gate miss: got %d want 1 (no writes)", len(tx.queries))
	}
}

func TestMembershipAdmin_SetRoles_execErrorsWrap(t *testing.T) {
	// gate error other than ErrNoRows → wraps, no writes.
	boom := errors.New("gate blew up")
	tx := &stubTx{queryRowFn: rowQueue(&stubMemberSearchRow{err: boom})}
	repo := NewMembershipAdminRepository(&stubTxQuerier{tx: tx})
	if err := repo.SetRoles(context.Background(), maGcid, maTenant, []identity.Role{identity.RoleLearner}); !errors.Is(err, boom) {
		t.Fatalf("gate: got %v want wrapped boom", err)
	}
	// deactivate exec error → wraps.
	tx2 := &stubTx{queryRowFn: rowQueue(&stubMemberSearchRow{vals: []any{1}}, ownerCounts(0, 1)), execErr: boom}
	repo2 := NewMembershipAdminRepository(&stubTxQuerier{tx: tx2})
	if err := repo2.SetRoles(context.Background(), maGcid, maTenant, []identity.Role{identity.RoleLearner}); !errors.Is(err, boom) {
		t.Fatalf("deactivate: got %v want wrapped boom", err)
	}
	// upsert exec error → wraps with the role name.
	tx3 := &stubTx{queryRowFn: rowQueue(&stubMemberSearchRow{vals: []any{1}}, ownerCounts(0, 1))}
	tx3.execErr = boom
	repo3 := NewMembershipAdminRepository(&stubTxQuerier{tx: tx3})
	if err := repo3.SetRoles(context.Background(), maGcid, maTenant, []identity.Role{identity.RoleLearner}); !errors.Is(err, boom) {
		t.Fatalf("upsert: got %v want wrapped boom", err)
	}
}

// -----------------------------------------------------------------------------
// MembershipBootstrapUpserter constructor (panics on nil so wiring bugs fail
// loud at boot)
// -----------------------------------------------------------------------------

func TestNewMembershipBootstrapUpserter_panicsOnNil(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("nil PgxPoolQuerier must panic at boot")
		}
	}()
	NewMembershipBootstrapUpserter(nil)
}

func TestMembershipBootstrapUpserter_constructor_acceptsWrapper(t *testing.T) {
	u := NewMembershipBootstrapUpserter(&PgxPoolQuerier{})
	if u == nil {
		t.Fatal("upserter must be non-nil")
	}
	// With a nil-backed pool the RLS tx surface fails loud — the statement
	// itself (RunInTenantTx wrapping) is what the bootstrap path executes.
	if err := u.UpsertMembershipOnBootstrap(context.Background(), maGcid, maTenant, "learner"); err == nil {
		t.Fatal("nil pool must surface a RunInTenantTx error")
	}
}
