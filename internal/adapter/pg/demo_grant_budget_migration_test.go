package pg

// demo_grant_budget_migration_test.go: static guards for the demo-grant budget
// axis — migrations 0044_demo_grant_budget.up.sql and
// 9999z_demo_grant_least_privilege.up.sql.
//
// Why SQL-content tests rather than live-DB ones: same rationale as the
// 0027/0030/0036/0037/0041 guards. The deliverable IS the migration text, and a
// shared database is routinely cost-paused. The migrations were additionally
// applied against a local Postgres 18 (pgvector/pgvector:pg18) with the real
// runtime role during development — the live integration specs in
// demo_grant_budget_integration_test.go are the behavioural evidence, this file
// is the regression fence for the properties those specs cannot assert cheaply
// (owner, ACL, search_path, table shape).
//
// Two things are load-bearing and easy to break by a well-meaning edit:
//
//  1. `9999_grant_app_roles.sql` grants EXECUTE on EVERY function in schema
//     public to BOTH app roles and runs LAST, so the least-privilege posture
//     must be re-asserted by a file that sorts after it (9999z).
//  2. The helper must not be owned by the table owner: an owner that owns
//     `mana_ledger` bypasses RLS outright, which is exactly the "too broad"
//     boundary the round-3 review rejected.

import (
	"regexp"
	"strings"
	"testing"
)

const (
	demoBudgetUpFile    = "0044_demo_grant_budget.up.sql"
	demoBudgetDownFile  = "0044_demo_grant_budget.down.sql"
	demoGrantsZUpFile   = "9999z_demo_grant_least_privilege.up.sql"
	demoGrantFnName     = "mana_demo_grant_total_units"
	demoBudgetTableName = "demo_grant_budget"
)

func TestMigration0044_DemoGrantBudget(t *testing.T) {
	up := stripSQLComments(readMigrationFile(t, demoBudgetUpFile))

	t.Run("creates_the_consumed_counter_table", func(t *testing.T) {
		if !regexp.MustCompile(`(?i)CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+` + demoBudgetTableName).MatchString(up) {
			t.Errorf("0044.up must CREATE TABLE IF NOT EXISTS %s", demoBudgetTableName)
		}
		for _, col := range []string{"budget_key", "consumed_units", "consumed_grants"} {
			if !strings.Contains(up, col) {
				t.Errorf("0044.up must define column %q", col)
			}
		}
		// The counters are what make the cap check serializable; a negative
		// counter would silently hand out budget that was already spent.
		if !strings.Contains(up, "consumed_units >= 0") || !strings.Contains(up, "consumed_grants >= 0") {
			t.Errorf("0044.up must constrain the counters to be non-negative")
		}
	})

	t.Run("reconciles_the_counters_with_preexisting_ledger_rows", func(t *testing.T) {
		// A live database upgraded in place may already carry demo_grant rows.
		// The migration must charge every interactive row and none of the
		// seed rows, so the counters end up consistent with the ledger.
		if !regexp.MustCompile(`(?i)INSERT\s+INTO\s+` + demoBudgetTableName).MatchString(up) {
			t.Errorf("0044.up must backfill %s from the ledger", demoBudgetTableName)
		}
		if !strings.Contains(up, "'global'") {
			t.Errorf("0044.up must reconcile the 'global' budget row")
		}
		if !strings.Contains(up, "public.mana_ledger") || !strings.Contains(up, "mana_reason") {
			t.Errorf("0044.up must read the demo_grant rows from mana_ledger")
		}
		// The seed grant shares the reason but must NOT be charged.
		if !strings.Contains(up, "NOT LIKE 'demo-seed:v1:%'") {
			t.Errorf("0044.up must exclude the seed grant's idempotency-key prefix from the reconciliation")
		}
		// The ledger is the source of truth: re-running re-asserts the
		// invariant rather than leaving a half-reconciled counter behind.
		if !regexp.MustCompile(`(?i)ON\s+CONFLICT[^;]*DO\s+UPDATE`).MatchString(up) {
			t.Errorf("0044.up must use ON CONFLICT DO UPDATE so re-runs re-assert counters == interactive ledger rows")
		}
	})

	t.Run("grants_the_runtime_role_and_only_the_runtime_role", func(t *testing.T) {
		if !regexp.MustCompile(`(?i)GRANT\s+SELECT,\s*INSERT,\s*UPDATE\s+ON\s+` + demoBudgetTableName + `\s+TO\s+chora_identity_app_rw`).MatchString(up) {
			t.Errorf("0044.up must grant SELECT/INSERT/UPDATE on %s to chora_identity_app_rw", demoBudgetTableName)
		}
		if !regexp.MustCompile(`(?i)REVOKE\s+ALL\s+ON\s+` + demoBudgetTableName + `\s+FROM\s+chora_identity_app_ro`).MatchString(up) {
			t.Errorf("0044.up must revoke the budget table from the read-only role")
		}
		if !regexp.MustCompile(`(?i)REVOKE\s+ALL\s+ON\s+` + demoBudgetTableName + `\s+FROM\s+PUBLIC`).MatchString(up) {
			t.Errorf("0044.up must revoke the budget table from PUBLIC")
		}
	})

	t.Run("hardens_the_helper_body", func(t *testing.T) {
		if !regexp.MustCompile(`(?i)CREATE\s+OR\s+REPLACE\s+FUNCTION\s+public\.` + demoGrantFnName).MatchString(up) {
			t.Errorf("0044.up must CREATE OR REPLACE the schema-qualified helper (0043 is immutable: it is already applied and checksummed)")
		}
		if !strings.Contains(up, "public.mana_ledger") {
			t.Errorf("0044.up must schema-qualify mana_ledger in the helper body")
		}
		if !strings.Contains(up, "'demo_grant'::public.mana_reason") {
			t.Errorf("0044.up must schema-qualify the mana_reason enum in the helper body")
		}
		if !regexp.MustCompile(`(?i)SET\s+search_path\s*=\s*pg_catalog,\s*pg_temp`).MatchString(up) {
			t.Errorf("0044.up must pin search_path to pg_catalog, pg_temp (NOT public)")
		}
		for _, line := range strings.Split(up, "\n") {
			if strings.Contains(strings.ToLower(line), "search_path") && strings.Contains(line, "public") {
				t.Errorf("0044.up must not put public on the helper's search_path: %q", strings.TrimSpace(line))
			}
		}
	})

	t.Run("narrow_owner_with_a_role_targeted_policy", func(t *testing.T) {
		if !regexp.MustCompile(`(?i)CREATE\s+ROLE\s+chora_identity_demo_budget`).MatchString(up) {
			t.Errorf("0044.up must create the dedicated NOLOGIN owner role")
		}
		for _, attr := range []string{"NOLOGIN", "NOSUPERUSER", "NOCREATEROLE", "NOBYPASSRLS"} {
			if !strings.Contains(up, attr) {
				t.Errorf("0044.up must create the owner role with %s", attr)
			}
		}
		if !regexp.MustCompile(`(?i)ALTER\s+FUNCTION\s+public\.` + demoGrantFnName + `\(\)\s+OWNER\s+TO\s+chora_identity_demo_budget`).MatchString(up) {
			t.Errorf("0044.up must hand the helper to the narrow owner")
		}
		if !regexp.MustCompile(`(?i)CREATE\s+POLICY\s+demo_grant_budget_read`).MatchString(up) {
			t.Errorf("0044.up must scope the narrow owner's view with a role-targeted policy")
		}
		// The elevated read must stay bounded to the demo-grant reason, and the
		// owner must NOT be handed the table: table ownership would bypass RLS.
		if !regexp.MustCompile(`(?i)FOR\s+SELECT\s+TO\s+chora_identity_demo_budget`).MatchString(up) {
			t.Errorf("0044.up's policy must be FOR SELECT TO the narrow owner")
		}
		if regexp.MustCompile(`(?i)(ALTER\s+TABLE\s+mana_ledger\s+OWNER|GRANT\s+ALL\s+ON\s+public\.mana_ledger)`).MatchString(up) {
			t.Errorf("0044.up must not widen the narrow owner beyond SELECT on mana_ledger")
		}
	})

	t.Run("minimal_execute_grant", func(t *testing.T) {
		if !regexp.MustCompile(`(?i)REVOKE\s+ALL\s+ON\s+FUNCTION\s+public\.` + demoGrantFnName + `\(\)\s+FROM\s+PUBLIC`).MatchString(up) {
			t.Errorf("0044.up must revoke the helper from PUBLIC")
		}
		if !regexp.MustCompile(`(?i)REVOKE\s+ALL\s+ON\s+FUNCTION\s+public\.` + demoGrantFnName + `\(\)\s+FROM\s+chora_identity_app_ro`).MatchString(up) {
			t.Errorf("0044.up must revoke the helper from the read-only role")
		}
		if !regexp.MustCompile(`(?i)GRANT\s+EXECUTE\s+ON\s+FUNCTION\s+public\.` + demoGrantFnName + `\(\)\s+TO\s+chora_identity_app_rw`).MatchString(up) {
			t.Errorf("0044.up must grant EXECUTE on the helper to chora_identity_app_rw only")
		}
	})

	t.Run("down_is_destructive_and_reverses_the_axis", func(t *testing.T) {
		down := stripSQLComments(readMigrationFile(t, demoBudgetDownFile))
		for _, want := range []string{
			"DROP TABLE IF EXISTS " + demoBudgetTableName,
			"DROP POLICY IF EXISTS demo_grant_budget_read",
			"DROP FUNCTION IF EXISTS public." + demoGrantFnName,
		} {
			if !strings.Contains(down, want) {
				t.Errorf("0044.down must contain %q", want)
			}
		}
	})
}

// TestMigration9999z_DemoGrantLeastPrivilege — the blanket app-role grant in
// 9999 runs last on a fresh database, so the demo axis' least-privilege posture
// has to be re-asserted after it.
func TestMigration9999z_DemoGrantLeastPrivilege(t *testing.T) {
	up := stripSQLComments(readMigrationFile(t, demoGrantsZUpFile))

	t.Run("sorts_after_the_blanket_grant", func(t *testing.T) {
		// forward() in the migration runner sorts by filename; '_' (0x5F) sorts
		// before 'z' (0x7A) under every collation the runner uses, so this file
		// is applied after 9999_grant_app_roles.sql.
		if !strings.HasPrefix(demoGrantsZUpFile, "9999z") {
			t.Fatalf("%s must keep the 9999z prefix so it runs after 9999_grant_app_roles.sql", demoGrantsZUpFile)
		}
		if !(demoGrantsZUpFile > "9999_grant_app_roles.sql") {
			t.Errorf("%s must sort after 9999_grant_app_roles.sql", demoGrantsZUpFile)
		}
	})

	t.Run("re_revokes_the_read_only_role", func(t *testing.T) {
		if !regexp.MustCompile(`(?i)REVOKE\s+EXECUTE\s+ON\s+FUNCTION\s+public\.` + demoGrantFnName + `\(\)\s+FROM\s+chora_identity_app_ro`).MatchString(up) {
			t.Errorf("9999z must re-revoke EXECUTE on the helper from chora_identity_app_ro")
		}
		if !regexp.MustCompile(`(?i)REVOKE\s+ALL\s+ON\s+public\.` + demoBudgetTableName + `\s+FROM\s+chora_identity_app_ro`).MatchString(up) {
			t.Errorf("9999z must re-revoke the budget table from chora_identity_app_ro")
		}
	})

	t.Run("re_grants_the_runtime_role", func(t *testing.T) {
		if !regexp.MustCompile(`(?i)GRANT\s+EXECUTE\s+ON\s+FUNCTION\s+public\.` + demoGrantFnName + `\(\)\s+TO\s+chora_identity_app_rw`).MatchString(up) {
			t.Errorf("9999z must (re-)grant EXECUTE on the helper to chora_identity_app_rw")
		}
		if !regexp.MustCompile(`(?i)GRANT\s+SELECT,\s*INSERT,\s*UPDATE\s+ON\s+public\.` + demoBudgetTableName + `\s+TO\s+chora_identity_app_rw`).MatchString(up) {
			t.Errorf("9999z must (re-)grant the budget table to chora_identity_app_rw")
		}
	})

	t.Run("trims_the_runtime_role_to_the_credit_paths_write_set", func(t *testing.T) {
		// 9999's blanket grant gives app_rw DELETE on every table. The
		// demo-grant credit path only ever INSERTs a lazy row and UPDATEs the
		// consumed columns, so a DELETE on the counters is a manipulation
		// vector and must be taken back here.
		if !regexp.MustCompile(`(?i)REVOKE\s+DELETE,\s*TRUNCATE\s+ON\s+public\.` + demoBudgetTableName + `\s+FROM\s+chora_identity_app_rw`).MatchString(up) {
			t.Errorf("9999z must revoke DELETE, TRUNCATE on %s from chora_identity_app_rw", demoBudgetTableName)
		}
	})

	t.Run("guards_every_statement_on_existence", func(t *testing.T) {
		// A rolled-back demo axis (0044 down) or a database without the app
		// roles must be a no-op, not a chain-halting error.
		if !strings.Contains(up, "to_regprocedure") || !strings.Contains(up, "to_regclass") {
			t.Errorf("9999z must guard its statements on the function/table existing")
		}
		if !regexp.MustCompile(`(?i)FROM\s+pg_roles\s+WHERE\s+rolname`).MatchString(up) {
			t.Errorf("9999z must guard its statements on the roles existing")
		}
	})
}
