//go:build integration

// demo_grant_least_privilege_integration_test.go — the round-4 gate-2 specs:
// NEGATIVE privilege evidence for the demo-grant budget axis, proved against
// real Postgres as the RUNTIME role (chora_identity_app_rw). Run with:
//
//	export CHORA_TEST_DSN=<chora_identity_app_rw DSN>
//	go test -tags integration ./internal/adapter/pg/...
//
// Every spec here asserts a DENIAL or an absence: the app role cannot read
// another GCID's mana rows, cannot acquire the helper's database role, the
// helper's owner holds nothing beyond the aggregate's needs, the helper is
// unreachable through any unintended SQL interface, and the budget counters'
// write privilege set is exactly the credit path's.
package pg_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/apollo-chora/chora-identity/internal/adapter/pg"
	mana "github.com/apollo-chora/chora-identity/internal/domain/user_mana"
)

// demoGrantFn is the hardened SECURITY DEFINER aggregate helper.
const demoGrantFn = "public.mana_demo_grant_total_units()"

// helperRole is the dedicated NOLOGIN owner migration 0044 created.
const helperRole = "chora_identity_demo_budget"

// assertPrivilege evaluates has_*_privilege(role, object, privilege) and fails
// the test unless it equals want.
func assertPrivilege(t *testing.T, pool *pgxpool.Pool, fn, role, object, privilege string, want bool) {
	t.Helper()
	var got bool
	var query string
	var args []any
	if role == "PUBLIC" {
		// has_*_privilege does not accept PUBLIC as a role name on PG18 —
		// check the raw ACL instead (aclexplode: grantee 0 = PUBLIC). A NULL
		// function ACL defaults to PUBLIC EXECUTE, so it counts as PUBLIC.
		if fn == "has_function_privilege" {
			query = `SELECT count(*) > 0 FROM pg_proc
			 WHERE oid = $1::regprocedure
			   AND (proacl IS NULL OR EXISTS (SELECT 1 FROM aclexplode(proacl) WHERE grantee = 0 AND privilege_type = $2))`
		} else {
			query = `SELECT count(*) > 0 FROM pg_class
			 WHERE oid = $1::regclass
			   AND EXISTS (SELECT 1 FROM aclexplode(relacl) WHERE grantee = 0 AND privilege_type = $2)`
		}
		args = []any{object, privilege}
	} else {
		query = fmt.Sprintf("SELECT %s($1, $2, $3)", fn)
		args = []any{role, object, privilege}
	}
	if err := pool.QueryRow(context.Background(), query, args...).Scan(&got); err != nil {
		t.Fatalf("%s(%s, %s, %s): %v", fn, role, object, privilege, err)
	}
	if got != want {
		t.Errorf("%s(%s, %s, %s) = %v, want %v", fn, role, object, privilege, got, want)
	}
}

// TestIntegration_DemoGrant_AppRoleCrossGcidReadsDeniedButHelperWorks — the
// runtime application role CAN invoke the approved aggregate helper but
// CANNOT directly read another GCID's mana_ledger rows or user_mana row: the
// user_isolation RLS policy (migration 0003) filters every direct read and
// write, while the helper's role-targeted policy (migration 0044) is the only
// sanctioned cross-GCID path.
func TestIntegration_DemoGrant_AppRoleCrossGcidReadsDeniedButHelperWorks(t *testing.T) {
	pool := liveDB(t)
	ctx := context.Background()
	store := pg.NewManaStore(pg.NewPgxPoolQuerier(pool))

	gcidA := integrationGcid(t, pool)
	gcidB := integrationGcid(t, pool)
	caps := &mana.DemoGrantCaps{}
	if _, err := store.CreditWallet(ctx, demoGrantInput(gcidA, "priv-a", 200, caps)); err != nil {
		t.Fatalf("credit A: %v", err)
	}
	if _, err := store.CreditWallet(ctx, demoGrantInput(gcidB, "priv-b", 300, caps)); err != nil {
		t.Fatalf("credit B: %v", err)
	}

	// Positive control: the approved aggregate helper works for app_rw and
	// sees BOTH accounts' demo grants.
	total, err := store.DemoGrantTotalUnits(ctx)
	if err != nil {
		t.Fatalf("DemoGrantTotalUnits: %v", err)
	}
	if total < 500 {
		t.Errorf("helper total = %d, want >= 500 (A's 200 + B's 300)", total)
	}

	// Negative: with the GUC scoped to A, B's ledger rows are invisible.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL chora.user_gcid = '%s'", gcidA)); err != nil {
		t.Fatalf("set guc: %v", err)
	}
	// The negative INSERT below is EXPECTED to fail, and a statement failure
	// aborts the transaction — open a savepoint so the remaining negative
	// writes can still run afterwards.
	if _, err := tx.Exec(ctx, `SAVEPOINT cross_gcid_neg`); err != nil {
		t.Fatalf("savepoint: %v", err)
	}

	var bRows int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM mana_ledger WHERE gcid = $1::uuid`, gcidB).Scan(&bRows); err != nil {
		t.Fatalf("count B's ledger rows as A: %v", err)
	}
	if bRows != 0 {
		t.Errorf("A sees %d of B's ledger rows, want 0 (RLS leak)", bRows)
	}
	var visible int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM mana_ledger WHERE reason = 'demo_grant'::mana_reason`).Scan(&visible); err != nil {
		t.Fatalf("count visible ledger rows as A: %v", err)
	}
	if visible != 1 {
		t.Errorf("A sees %d demo_grant rows, want 1 (its own)", visible)
	}

	// B's wallet row is invisible and un-writable from A's scope.
	var bBalance int64
	err = tx.QueryRow(ctx,
		`SELECT balance_units FROM user_mana WHERE gcid = $1::uuid`, gcidB).Scan(&bBalance)
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("reading B's wallet as A: err = %v, want no rows", err)
	}
	var visibleWallets int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM user_mana`).Scan(&visibleWallets); err != nil {
		t.Fatalf("count visible wallets as A: %v", err)
	}
	if visibleWallets != 1 {
		t.Errorf("A sees %d wallet rows, want 1 (its own)", visibleWallets)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO user_mana (gcid, balance_units, lifetime_earned, lifetime_spent, version)
		VALUES ($1::uuid, 1, 1, 0, 1)`, gcidB); err == nil {
		t.Error("inserting B's wallet as A: err = nil, want an RLS violation")
	} else if !strings.Contains(err.Error(), "row-level security") {
		t.Errorf("insert B's wallet as A: err = %v, want an RLS policy violation", err)
	}
	// The failed INSERT aborted the transaction; roll back to the savepoint so
	// the remaining negative writes can still run.
	if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT cross_gcid_neg`); err != nil {
		t.Fatalf("rollback to savepoint: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE user_mana SET balance_units = 0 WHERE gcid = $1::uuid`, gcidB); err != nil {
		t.Fatalf("update B's wallet as A: %v", err)
	}
	if tag, err := tx.Exec(ctx,
		`DELETE FROM mana_ledger WHERE gcid = $1::uuid`, gcidB); err != nil {
		t.Fatalf("delete B's ledger rows as A: %v", err)
	} else if tag.RowsAffected() != 0 {
		t.Errorf("A deleted %d of B's ledger rows, want 0", tag.RowsAffected())
	}

	// Positive control: the budget counters ARE the app role's own interface.
	var counters int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM demo_grant_budget`).Scan(&counters); err != nil {
		t.Fatalf("read demo_grant_budget as A: %v", err)
	}
	if counters == 0 {
		t.Error("A cannot read the demo_grant_budget counters, want them readable")
	}
}

// TestIntegration_DemoGrant_HelperRoleCannotBeAcquired — an ordinary
// application user cannot acquire the helper's database role: no app role is
// a member of it (in either direction), SET ROLE is denied, and the role is
// NOLOGIN so it cannot be connected to directly.
func TestIntegration_DemoGrant_HelperRoleCannotBeAcquired(t *testing.T) {
	pool := liveDB(t)
	ctx := context.Background()

	for _, membership := range [][2]string{
		{"chora_identity_app_rw", helperRole},
		{"chora_identity_app_ro", helperRole},
		{helperRole, "chora_identity_app_rw"},
	} {
		var isMember bool
		if err := pool.QueryRow(ctx,
			`SELECT pg_has_role($1, $2, 'MEMBER')`, membership[0], membership[1]).Scan(&isMember); err != nil {
			t.Fatalf("pg_has_role(%s, %s): %v", membership[0], membership[1], err)
		}
		if isMember {
			t.Errorf("%s is a member of %s — the helper's role must be unacquirable", membership[0], membership[1])
		}
	}

	// Behavioral: SET ROLE as the runtime role is denied.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET ROLE `+helperRole); err == nil {
		t.Errorf("SET ROLE %s as app_rw: err = nil, want permission denied", helperRole)
	}

	// The role cannot be logged into.
	var canLogin bool
	if err := pool.QueryRow(ctx,
		`SELECT rolcanlogin FROM pg_roles WHERE rolname = $1`, helperRole).Scan(&canLogin); err != nil {
		t.Fatalf("read rolcanlogin: %v", err)
	}
	if canLogin {
		t.Errorf("%s is LOGIN — it must be NOLOGIN", helperRole)
	}
}

// TestIntegration_DemoGrant_HelperOwnerHoldsOnlyAggregatePrivileges — the
// helper's owner is the dedicated narrow role, holds nothing beyond what the
// aggregate needs (SELECT on mana_ledger, USAGE on public), owns no table
// (ownership would bypass RLS), and its elevated view is bounded to the
// demo_grant rows by the role-targeted policy.
func TestIntegration_DemoGrant_HelperOwnerHoldsOnlyAggregatePrivileges(t *testing.T) {
	pool := liveDB(t)
	ctx := context.Background()

	// The helper is owned by the dedicated narrow role, not the migrate role.
	var owner string
	if err := pool.QueryRow(ctx,
		`SELECT pg_get_userbyid(proowner) FROM pg_proc WHERE oid = $1::regprocedure`, demoGrantFn).Scan(&owner); err != nil {
		t.Fatalf("read helper owner: %v", err)
	}
	if owner != helperRole {
		t.Errorf("helper owner = %q, want %q", owner, helperRole)
	}

	// Role attributes: a plain NOLOGIN scoped role.
	var superuser, bypassrls, createrole, createdb bool
	if err := pool.QueryRow(ctx, `
		SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb
		  FROM pg_roles WHERE rolname = $1`, helperRole).
		Scan(&superuser, &bypassrls, &createrole, &createdb); err != nil {
		t.Fatalf("read role attributes: %v", err)
	}
	if superuser || bypassrls || createrole || createdb {
		t.Errorf("%s attributes: superuser=%v bypassrls=%v createrole=%v createdb=%v — all must be false",
			helperRole, superuser, bypassrls, createrole, createdb)
	}

	// Table privileges: SELECT on mana_ledger, nothing else on any table.
	assertPrivilege(t, pool, "has_table_privilege", helperRole, "public.mana_ledger", "SELECT", true)
	for _, priv := range []string{"INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"} {
		assertPrivilege(t, pool, "has_table_privilege", helperRole, "public.mana_ledger", priv, false)
	}
	for _, tbl := range []string{"public.user_mana", "public.mana_subsidy_allocations", "public.demo_grant_budget"} {
		for _, priv := range []string{"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"} {
			assertPrivilege(t, pool, "has_table_privilege", helperRole, tbl, priv, false)
		}
	}

	// Schema privileges: USAGE only.
	assertPrivilege(t, pool, "has_schema_privilege", helperRole, "public", "USAGE", true)
	assertPrivilege(t, pool, "has_schema_privilege", helperRole, "public", "CREATE", false)

	// The owner must NOT own mana_ledger: table ownership bypasses RLS, which
	// is exactly the "too broad" boundary the round-3 review rejected.
	var ledgerOwner string
	if err := pool.QueryRow(ctx,
		`SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid = 'public.mana_ledger'::regclass`).Scan(&ledgerOwner); err != nil {
		t.Fatalf("read mana_ledger owner: %v", err)
	}
	if ledgerOwner == helperRole {
		t.Errorf("%s owns mana_ledger — the elevated read must stay RLS-scoped", helperRole)
	}

	// The role-targeted policy exists, is SELECT-only for the narrow role, and
	// is bounded to the demo_grant reason.
	var policyCount int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM pg_policies
		 WHERE schemaname = 'public'
		   AND tablename = 'mana_ledger'
		   AND policyname = 'demo_grant_budget_read'
		   AND cmd = 'SELECT'
		   AND roles = ARRAY[$1]::name[]
		   AND qual LIKE '%demo_grant%'`, helperRole).Scan(&policyCount); err != nil {
		t.Fatalf("read policy: %v", err)
	}
	if policyCount != 1 {
		t.Errorf("demo_grant_budget_read policy count = %d, want 1 (SELECT, role-targeted, demo_grant-bounded)", policyCount)
	}

	// Behavioral boundedness: the helper's total moves ONLY with demo_grant
	// rows — a non-demo-grant credit leaves it unchanged, a demo_grant credit
	// moves it by exactly the credited units.
	store := pg.NewManaStore(pg.NewPgxPoolQuerier(pool))
	gcid := integrationGcid(t, pool)
	before, err := store.DemoGrantTotalUnits(ctx)
	if err != nil {
		t.Fatalf("helper total (before): %v", err)
	}
	if _, err := store.CreditWallet(ctx, mana.CreditWalletInput{
		Gcid:           gcid,
		Units:          12_345,
		Direction:      mana.DirectionMint,
		Reason:         mana.ReasonTopup,
		IdempotencyKey: "priv-topup",
	}); err != nil {
		t.Fatalf("topup credit: %v", err)
	}
	afterTopup, err := store.DemoGrantTotalUnits(ctx)
	if err != nil {
		t.Fatalf("helper total (after topup): %v", err)
	}
	if afterTopup != before {
		t.Errorf("helper total changed on a non-demo-grant credit: %d -> %d, want unchanged", before, afterTopup)
	}
	if _, err := store.CreditWallet(ctx, demoGrantInput(gcid, "priv-demo", 777, &mana.DemoGrantCaps{})); err != nil {
		t.Fatalf("demo credit: %v", err)
	}
	afterDemo, err := store.DemoGrantTotalUnits(ctx)
	if err != nil {
		t.Fatalf("helper total (after demo): %v", err)
	}
	if afterDemo != afterTopup+777 {
		t.Errorf("helper total = %d, want %d — it must move by exactly the demo-grant units", afterDemo, afterTopup+777)
	}
}

// TestIntegration_DemoGrant_HelperFunctionACL — the helper cannot be invoked
// through any unintended public SQL interface: EXECUTE is granted to the
// runtime role only, the raw function ACL names no other grantee, and the
// read stays SECURITY DEFINER with a pinned search_path.
func TestIntegration_DemoGrant_HelperFunctionACL(t *testing.T) {
	pool := liveDB(t)
	ctx := context.Background()

	// The ACL matrix: app_rw yes; PUBLIC and the read-only role no.
	assertPrivilege(t, pool, "has_function_privilege", "chora_identity_app_rw", demoGrantFn, "EXECUTE", true)
	assertPrivilege(t, pool, "has_function_privilege", "PUBLIC", demoGrantFn, "EXECUTE", false)
	assertPrivilege(t, pool, "has_function_privilege", "chora_identity_app_ro", demoGrantFn, "EXECUTE", false)

	// The raw ACL names no grantee beyond the runtime role and the owner.
	// (The owner's own entry is expected — function ownership implies
	// EXECUTE; the dangerous axes are table ownership and PUBLIC/RO grants,
	// which the specs above already rule out.)
	var grantees string
	if err := pool.QueryRow(ctx, `
		SELECT COALESCE(array_agg(grantee), '{}'::text[])::text
		  FROM (
		      SELECT split_part(entry, '=', 1) AS grantee
		        FROM pg_proc
		             CROSS JOIN LATERAL unnest(string_to_array(btrim(proacl::text, '{}'), ',')) AS u(entry)
		       WHERE oid = $1::regprocedure
		         AND proacl IS NOT NULL
		  ) g`, demoGrantFn).Scan(&grantees); err != nil {
		t.Fatalf("read function ACL: %v", err)
	}
	if grantees != "{chora_identity_demo_budget,chora_identity_app_rw}" {
		t.Errorf("helper ACL grantees = %s, want {chora_identity_demo_budget,chora_identity_app_rw} — no unintended interface", grantees)
	}

	// SECURITY DEFINER with the search_path pinned away from public.
	var prosecdef bool
	if err := pool.QueryRow(ctx,
		`SELECT prosecdef FROM pg_proc WHERE oid = $1::regprocedure`, demoGrantFn).Scan(&prosecdef); err != nil {
		t.Fatalf("read prosecdef: %v", err)
	}
	if !prosecdef {
		t.Error("helper is not SECURITY DEFINER — it must run as its narrow owner")
	}
	var proconfig string
	if err := pool.QueryRow(ctx,
		`SELECT proconfig::text FROM pg_proc WHERE oid = $1::regprocedure`, demoGrantFn).Scan(&proconfig); err != nil {
		t.Fatalf("read proconfig: %v", err)
	}
	if proconfig != `{"search_path=pg_catalog, pg_temp"}` {
		t.Errorf("helper proconfig = %s, want {\"search_path=pg_catalog, pg_temp\"}", proconfig)
	}

	// Behavioral: the read-only role is denied at invocation time, not just in
	// the catalog. The DSN is the runtime role's; derive the read-only role's
	// DSN from it (same host/credentials, role swapped).
	dsn := os.Getenv("CHORA_TEST_DSN")
	if dsn == "" {
		t.Fatal("CHORA_TEST_DSN unset")
	}
	roDSN := strings.Replace(dsn, "chora_identity_app_rw", "chora_identity_app_ro", 1)
	if roDSN == dsn {
		t.Skip("CHORA_TEST_DSN does not name chora_identity_app_rw — cannot derive the read-only role's DSN")
	}
	roPool, err := pgxpool.New(ctx, roDSN)
	if err != nil {
		t.Skipf("read-only role DSN unreachable: %v", err)
	}
	defer roPool.Close()
	if err := roPool.QueryRow(ctx, `SELECT public.mana_demo_grant_total_units()`).Scan(new(int64)); err == nil {
		t.Error("app_ro invoked the helper: err = nil, want permission denied")
	} else if !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("app_ro invoked the helper: err = %v, want permission denied", err)
	}
}

// TestIntegration_DemoGrant_BudgetTableWritePrivilegeSet — the demo_grant_budget
// counters cannot be manipulated by unrelated application code: the runtime
// role holds exactly the write set the credit path needs (SELECT/INSERT/
// UPDATE — no DELETE, no TRUNCATE), the read-only role and PUBLIC hold
// nothing, and no app role owns the table.
func TestIntegration_DemoGrant_BudgetTableWritePrivilegeSet(t *testing.T) {
	pool := liveDB(t)
	ctx := context.Background()

	// The runtime role: exactly the credit path's write set.
	for _, priv := range []string{"SELECT", "INSERT", "UPDATE"} {
		assertPrivilege(t, pool, "has_table_privilege", "chora_identity_app_rw", "public.demo_grant_budget", priv, true)
	}
	for _, priv := range []string{"DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"} {
		assertPrivilege(t, pool, "has_table_privilege", "chora_identity_app_rw", "public.demo_grant_budget", priv, false)
	}

	// The read-only role and PUBLIC: nothing at all.
	for _, role := range []string{"chora_identity_app_ro", "PUBLIC"} {
		for _, priv := range []string{"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"} {
			assertPrivilege(t, pool, "has_table_privilege", role, "public.demo_grant_budget", priv, false)
		}
	}

	// No app role owns the counters table.
	var tblOwner string
	if err := pool.QueryRow(ctx,
		`SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid = 'public.demo_grant_budget'::regclass`).Scan(&tblOwner); err != nil {
		t.Fatalf("read demo_grant_budget owner: %v", err)
	}
	if tblOwner == "chora_identity_app_rw" || tblOwner == "chora_identity_app_ro" {
		t.Errorf("demo_grant_budget is owned by %s — an app role must not own the counters", tblOwner)
	}

	// Behavioral: the runtime role cannot DELETE the counters (the credit path
	// only ever INSERTs a lazy row and UPDATEs the consumed columns) but can
	// still UPDATE them.
	if _, err := pool.Exec(ctx, `DELETE FROM demo_grant_budget WHERE budget_key = 'global'`); err == nil {
		t.Error("app_rw deleted from demo_grant_budget: err = nil, want permission denied")
	}
	if _, err := pool.Exec(ctx,
		`UPDATE demo_grant_budget SET updated_at = now() WHERE budget_key = 'global'`); err != nil {
		t.Errorf("app_rw cannot update demo_grant_budget: %v — the credit path needs UPDATE", err)
	}
}
