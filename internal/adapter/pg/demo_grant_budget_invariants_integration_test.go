//go:build integration

// demo_grant_budget_invariants_integration_test.go — the round-4 gate-1 specs:
// the demo-grant budget counters' invariants, proved against real Postgres as
// the RUNTIME role (chora_identity_app_rw). Run with:
//
//	export CHORA_TEST_DSN=<chora_identity app_rw DSN>
//	go test -tags integration ./internal/adapter/pg/...
//
// Where the round-3 gate proved the caps hold under concurrency, these specs
// prove the COUNTERS themselves only ever move when a grant actually commits:
// a replay charges nothing, a failed ledger insert charges nothing, and the
// counter rows always agree with the ledger rows counted as interactive
// grants. The last spec upgrades a scratch database through the REAL
// migration files and asserts 0044 reconciles pre-existing demo_grant rows.
package pg_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"unicode"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/apollo-chora/chora-identity/internal/adapter/pg"
	mana "github.com/apollo-chora/chora-identity/internal/domain/user_mana"
)

// demoSeedKeyPrefix mirrors cmd/seed's demoSeedGrantPrefix
// (cmd/seed/main.go): the one-time seed grant's deterministic idempotency key.
// Seed rows share the `demo_grant` reason but are NOT interactive grants, so
// the reconciliation and the invariant checks exclude exactly this prefix.
const demoSeedKeyPrefix = "demo-seed:v1:"

// seedDemoGrant applies the one-time SEED grant (cmd/seed path) for gcid inside
// its own scoped transaction. The seed must never touch demo_grant_budget.
func seedDemoGrant(t *testing.T, pool *pgxpool.Pool, gcid string, units int64) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL chora.user_gcid = '%s'", gcid)); err != nil {
		t.Fatalf("set guc: %v", err)
	}
	if _, err := pg.SeedDemoGrant(ctx, pg.NewTxBridge(tx), gcid, demoSeedKeyPrefix+gcid, units); err != nil {
		t.Fatalf("SeedDemoGrant: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

// scopedLedgerSums reads one GCID's ledger inside a user-scoped transaction and
// returns (interactive units, interactive grants, seed units): the demo_grant
// rows split by the seed key prefix. mana_ledger carries the user_isolation
// policy, so an unscoped pooled read sees nothing.
func scopedLedgerSums(t *testing.T, pool *pgxpool.Pool, gcid string) (interactiveUnits, interactiveGrants, seedUnits int64) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL chora.user_gcid = '%s'", gcid)); err != nil {
		t.Fatalf("set guc: %v", err)
	}
	if err := tx.QueryRow(ctx, `
		SELECT COALESCE(sum(units) FILTER (WHERE idempotency_key NOT LIKE $2), 0)::bigint,
		       count(*) FILTER (WHERE idempotency_key NOT LIKE $2),
		       COALESCE(sum(units) FILTER (WHERE idempotency_key LIKE $2), 0)::bigint
		  FROM mana_ledger
		 WHERE gcid = $1::uuid AND reason = 'demo_grant'::mana_reason`,
		gcid, demoSeedKeyPrefix+"%").Scan(&interactiveUnits, &interactiveGrants, &seedUnits); err != nil {
		t.Fatalf("scoped ledger sums (gcid=%q): %v", gcid, err)
	}
	return interactiveUnits, interactiveGrants, seedUnits
}

// budgetCounterExists reports whether a counter row exists for key.
func budgetCounterExists(t *testing.T, pool *pgxpool.Pool, key string) bool {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM demo_grant_budget WHERE budget_key = $1`, key).Scan(&n); err != nil {
		t.Fatalf("count budget rows: %v", err)
	}
	return n > 0
}

// TestIntegration_DemoGrant_ReplayDoesNotIncrementCounters — replaying an
// idempotency key must not charge the budget a second time: the replay path
// returns before the caps are checked or consumed, so both the per-GCID and
// the global counters stay exactly where the fresh grant left them.
func TestIntegration_DemoGrant_ReplayDoesNotIncrementCounters(t *testing.T) {
	pool := liveDB(t)
	ctx := context.Background()

	gcid := integrationGcid(t, pool)
	store := pg.NewManaStore(pg.NewPgxPoolQuerier(pool))
	resetGlobalBudget(t, pool)
	caps := &mana.DemoGrantCaps{MaxPerGcid: 5, BudgetUnits: 1_000_000}

	res, err := store.CreditWallet(ctx, demoGrantInput(gcid, "replay-key", 100, caps))
	if err != nil {
		t.Fatalf("fresh grant: %v", err)
	}
	if res.Replayed {
		t.Fatal("fresh grant reported a replay")
	}
	if units, grants := budgetRow(t, pool, "gcid:"+gcid); units != 100 || grants != 1 {
		t.Fatalf("after fresh grant: per-gcid counter = (%d,%d), want (100,1)", units, grants)
	}
	gUnits, gGrants := budgetRow(t, pool, "global")

	// Same key, same payload: a successful replay that charges NOTHING.
	res, err = store.CreditWallet(ctx, demoGrantInput(gcid, "replay-key", 100, caps))
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !res.Replayed {
		t.Fatal("replay must report Replayed=true")
	}
	if units, grants := budgetRow(t, pool, "gcid:"+gcid); units != 100 || grants != 1 {
		t.Errorf("replay charged the per-gcid counter: (%d,%d), want (100,1) — unchanged", units, grants)
	}
	if units, grants := budgetRow(t, pool, "global"); units != gUnits || grants != gGrants {
		t.Errorf("replay charged the global counter: (%d,%d), want (%d,%d) — unchanged", units, grants, gUnits, gGrants)
	}
	if n := ledgerRowCount(t, pool, gcid); n != 1 {
		t.Errorf("ledger rows = %d, want 1 — a replay writes nothing", n)
	}
	w, err := store.GetMana(ctx, gcid)
	if err != nil {
		t.Fatalf("GetMana: %v", err)
	}
	if w == nil || w.BalanceUnits != 100 {
		t.Errorf("balance = %+v, want 100 — a replay credits nothing", w)
	}
}

// TestIntegration_DemoGrant_ReplayConflictDoesNotIncrementCounters — the same
// key reused with a DIFFERENT payload is an idempotency conflict, not a
// replay: it must fail and charge nothing.
func TestIntegration_DemoGrant_ReplayConflictDoesNotIncrementCounters(t *testing.T) {
	pool := liveDB(t)
	ctx := context.Background()

	gcid := integrationGcid(t, pool)
	store := pg.NewManaStore(pg.NewPgxPoolQuerier(pool))
	resetGlobalBudget(t, pool)
	caps := &mana.DemoGrantCaps{MaxPerGcid: 5, BudgetUnits: 1_000_000}

	if _, err := store.CreditWallet(ctx, demoGrantInput(gcid, "conflict-key", 100, caps)); err != nil {
		t.Fatalf("fresh grant: %v", err)
	}
	gUnits, gGrants := budgetRow(t, pool, "global")

	// Same key, different amount: a conflict that must not touch the counters.
	_, err := store.CreditWallet(ctx, demoGrantInput(gcid, "conflict-key", 999, caps))
	if !errors.Is(err, mana.ErrIdempotencyConflict) {
		t.Fatalf("conflict replay: err = %v, want ErrIdempotencyConflict", err)
	}
	if units, grants := budgetRow(t, pool, "gcid:"+gcid); units != 100 || grants != 1 {
		t.Errorf("conflict charged the per-gcid counter: (%d,%d), want (100,1) — unchanged", units, grants)
	}
	if units, grants := budgetRow(t, pool, "global"); units != gUnits || grants != gGrants {
		t.Errorf("conflict charged the global counter: (%d,%d), want (%d,%d) — unchanged", units, grants, gUnits, gGrants)
	}
	if n := ledgerRowCount(t, pool, gcid); n != 1 {
		t.Errorf("ledger rows = %d, want 1 — a conflict writes nothing", n)
	}
}

// TestIntegration_DemoGrant_LedgerFailureDoesNotIncrementCounters — a FAILED
// ledger insert rolls the whole credit transaction back, BOTH counters
// included: the caps check locks and (lazily) creates the budget rows before
// the ledger insert runs, so a failure after that point must leave every
// counter exactly where it was.
func TestIntegration_DemoGrant_LedgerFailureDoesNotIncrementCounters(t *testing.T) {
	pool := liveDB(t)
	ctx := context.Background()

	gcid := integrationGcid(t, pool)
	store := pg.NewManaStore(pg.NewPgxPoolQuerier(pool))
	resetGlobalBudget(t, pool)
	caps := &mana.DemoGrantCaps{MaxPerGcid: 5, BudgetUnits: 1_000_000}

	// A 129-char key overflows mana_ledger.idempotency_key VARCHAR(128): the
	// caps check passes, the wallet row is written, and the ledger INSERT fails
	// — the same forced failure as the round-3 ledger-rollback spec, now with
	// the demo-grant caps engaged.
	overLongKey := strings.Repeat("k", 129)
	if _, err := store.CreditWallet(ctx, demoGrantInput(gcid, overLongKey, 1_000, caps)); err == nil {
		t.Fatal("CreditWallet err = nil, want the ledger insert to fail")
	}

	// The caps check lazily created the per-GCID row inside the credit
	// transaction — and the ledger failure rolled the WHOLE transaction
	// back, the lazy insert included. Nothing was committed: no counter row,
	// no wallet, no ledger row.
	if budgetCounterExists(t, pool, "gcid:"+gcid) {
		t.Error("failed grant left a per-gcid counter row behind, want none — the rollback covers the lazy insert")
	}
	if units, grants := budgetRow(t, pool, "global"); units != 0 || grants != 0 {
		t.Errorf("failed grant charged the global counter: (%d,%d), want (0,0)", units, grants)
	}
	// The wallet credit rolled back with the ledger failure.
	w, err := store.GetMana(ctx, gcid)
	if err != nil {
		t.Fatalf("GetMana: %v", err)
	}
	if w != nil {
		t.Errorf("wallet = %+v, want nil — the credit must roll back with the ledger failure", w)
	}
	if n := ledgerRowCount(t, pool, gcid); n != 0 {
		t.Errorf("ledger rows = %d, want 0", n)
	}
}

// TestIntegration_DemoGrant_CounterLedgerInvariant — the counters and the
// ledger cannot disagree. For EVERY per-GCID counter row in the database, the
// scoped interactive ledger sum must equal the counter; the global counter
// must move in lockstep with the sum of the per-GCID counters (asserted as a
// delta across this spec's grants, since the suite's own specs reset the
// shared global row); and the elevated helper total must exceed the global
// counter by exactly the seed units, which the counters deliberately do not
// charge.
func TestIntegration_DemoGrant_CounterLedgerInvariant(t *testing.T) {
	pool := liveDB(t)
	ctx := context.Background()
	store := pg.NewManaStore(pg.NewPgxPoolQuerier(pool))

	// Snapshot the shared counters BEFORE this spec's grants. The global row
	// is shared by every spec in this package (some of which reset it), so
	// the global invariant is asserted as a DELTA across this spec's grants,
	// not as an absolute value.
	sumBefore := func() (units, grants int64) {
		rows, err := pool.Query(ctx, `
			SELECT budget_key, consumed_units, consumed_grants
			  FROM demo_grant_budget
			 WHERE budget_key LIKE 'gcid:%'`)
		if err != nil {
			t.Fatalf("list counter rows: %v", err)
		}
		defer rows.Close()
		for rows.Next() {
			var key string
			var u, g int64
			if err := rows.Scan(&key, &u, &g); err != nil {
				t.Fatalf("scan counter row: %v", err)
			}
			units += u
			grants += g
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("iterate counter rows: %v", err)
		}
		return units, grants
	}
	gUnitsBefore, gGrantsBefore := budgetRow(t, pool, "global")
	sumUnitsBefore, sumGrantsBefore := sumBefore()

	// Three fresh accounts: interactive-only, seed-only, and both.
	gcidInteractive := integrationGcid(t, pool)
	gcidSeedOnly := integrationGcid(t, pool)
	gcidBoth := integrationGcid(t, pool)

	caps := &mana.DemoGrantCaps{}
	if _, err := store.CreditWallet(ctx, demoGrantInput(gcidInteractive, "inv-only", 100, caps)); err != nil {
		t.Fatalf("credit interactive: %v", err)
	}
	if _, err := store.CreditWallet(ctx, demoGrantInput(gcidBoth, "inv-both", 200, caps)); err != nil {
		t.Fatalf("credit both: %v", err)
	}
	seedDemoGrant(t, pool, gcidSeedOnly, 1_000_000)
	seedDemoGrant(t, pool, gcidBoth, 2_000_000)

	// This spec's own expectations, exactly.
	if units, grants := budgetRow(t, pool, "gcid:"+gcidInteractive); units != 100 || grants != 1 {
		t.Errorf("interactive-only counter = (%d,%d), want (100,1)", units, grants)
	}
	if budgetCounterExists(t, pool, "gcid:"+gcidSeedOnly) {
		t.Error("seed-only gcid has a counter row, want none — the seed never consumes budget")
	}
	if units, grants := budgetRow(t, pool, "gcid:"+gcidBoth); units != 200 || grants != 1 {
		t.Errorf("both counter = (%d,%d), want (200,1) — the seed grant must not be charged", units, grants)
	}

	// Database-wide: every per-GCID counter row matches its scoped ledger
	// sum. This equality holds at all times — each interactive grant charges
	// its GCID row and the global row in the same transaction, and the seed
	// charges neither.
	rows, err := pool.Query(ctx, `
		SELECT budget_key, consumed_units, consumed_grants
		  FROM demo_grant_budget
		 WHERE budget_key LIKE 'gcid:%'`)
	if err != nil {
		t.Fatalf("list counter rows: %v", err)
	}
	type counterRow struct {
		key           string
		units, grants int64
	}
	var counters []counterRow
	for rows.Next() {
		var c counterRow
		if err := rows.Scan(&c.key, &c.units, &c.grants); err != nil {
			rows.Close()
			t.Fatalf("scan counter row: %v", err)
		}
		counters = append(counters, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate counter rows: %v", err)
	}

	var sumUnits, sumGrants int64
	for _, c := range counters {
		gcid := strings.TrimPrefix(c.key, "gcid:")
		units, grants, _ := scopedLedgerSums(t, pool, gcid)
		if c.units != units || c.grants != grants {
			t.Errorf("counter %s = (%d,%d), ledger says (%d,%d) — counters must equal interactive ledger rows",
				c.key, c.units, c.grants, units, grants)
		}
		sumUnits += c.units
		sumGrants += c.grants
	}

	// The global counter moves in lockstep with the sum of the per-GCID
	// counters: across this spec's grants the two deltas must be identical.
	gUnits, gGrants := budgetRow(t, pool, "global")
	if dUnits, dGrants := gUnits-gUnitsBefore, gGrants-gGrantsBefore; dUnits != 300 || dGrants != 2 {
		t.Errorf("global counter delta = (%d,%d), want (300,2) — this spec's interactive grants", dUnits, dGrants)
	}
	if dUnits, dGrants := sumUnits-sumUnitsBefore, sumGrants-sumGrantsBefore; dUnits != 300 || dGrants != 2 {
		t.Errorf("per-GCID counters delta = (%d,%d), want (300,2)", dUnits, dGrants)
	}

	// The elevated helper sees EVERY demo_grant row (seed included); the
	// counters see only the interactive ones. Their difference is therefore
	// exactly the seed units — at least this spec's own.
	total, err := store.DemoGrantTotalUnits(ctx)
	if err != nil {
		t.Fatalf("DemoGrantTotalUnits: %v", err)
	}
	_, _, seedOnlyUnits := scopedLedgerSums(t, pool, gcidSeedOnly)
	_, _, bothSeedUnits := scopedLedgerSums(t, pool, gcidBoth)
	if total < gUnits+seedOnlyUnits+bothSeedUnits {
		t.Errorf("helper total = %d, want >= %d (global %d + this spec's seed %d) — the helper must see the seed rows",
			total, gUnits+seedOnlyUnits+bothSeedUnits, gUnits, seedOnlyUnits+bothSeedUnits)
	}
}

// -----------------------------------------------------------------------------
// Migration 0044 reconciliation
// -----------------------------------------------------------------------------

// migrationFiles returns the forward migration filenames (every *.sql except
// *.down.sql) in byte-order — the same set and order chora-stack/scripts/
// migrate.sh's forward() discovers.
func migrationFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}
	var names []string
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".sql") || strings.HasSuffix(name, ".down.sql") {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names) // byte order — the collation the runner's glob uses
	return names
}

// applyMigrationFilesPgx applies the named migration files from dir to conn,
// statement by statement, and records the same version:checksum rows in
// schema_migrations that migrate.sh records (sha256 of the file bytes), so a
// later real migrate.sh run sees them as applied.
//
// Why not shell out to migrate.sh here: the runner needs a psql on PATH, and
// the host running `go test` has none (the gate runs the runner inside the
// Postgres container). The SQL applied is the REAL file content, and the
// checksum tracking is the runner's own — the scratch database is
// indistinguishable from one the runner provisioned.
//
// Statements are split and sent ONE AT A TIME over the simple protocol —
// exactly what psql -f does. Sending a whole file as one query would wrap it
// in a single implicit transaction, which breaks migrations like 0043 that
// add an enum value OUTSIDE their transactional block (SQLSTATE 55P04).
func applyMigrationFilesPgx(t *testing.T, conn *pgx.Conn, dir string, names ...string) {
	t.Helper()
	for _, name := range names {
		path := filepath.Join(dir, name)
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read migration %s: %v", name, err)
		}
		for _, stmt := range splitSQLStatements(t, string(content)) {
			if _, err := conn.Exec(context.Background(), stmt); err != nil {
				t.Fatalf("apply migration %s: %v\nstatement: %.200s", name, err, strings.TrimSpace(stmt))
			}
		}
		sum := sha256.Sum256(content)
		if _, err := conn.Exec(context.Background(), `
			INSERT INTO schema_migrations (version, filename, checksum)
			VALUES ($1, $2, $3)
			ON CONFLICT (version) DO NOTHING`, name, name, hex.EncodeToString(sum[:])); err != nil {
			t.Fatalf("record migration %s: %v", name, err)
		}
	}
}

// splitSQLStatements splits a migration file into individual SQL statements,
// the way psql's input parser does: semicolons terminate statements, except
// inside single-quoted strings (” escape), dollar-quoted strings
// ($tag$...$tag$, including the empty tag $$), and -- line comments.
func splitSQLStatements(t *testing.T, content string) []string {
	t.Helper()
	var stmts []string
	var cur strings.Builder
	flush := func() {
		if strings.TrimSpace(cur.String()) != "" {
			stmts = append(stmts, cur.String())
		}
		cur.Reset()
	}
	for i := 0; i < len(content); {
		c := content[i]
		switch {
		case c == '-' && i+1 < len(content) && content[i+1] == '-':
			for i < len(content) && content[i] != '\n' {
				i++
			}
		case c == '\'':
			cur.WriteByte(c)
			i++
			for i < len(content) {
				cur.WriteByte(content[i])
				if content[i] == '\'' {
					i++
					if i < len(content) && content[i] == '\'' {
						cur.WriteByte(content[i])
						i++
						continue
					}
					break
				}
				i++
			}
		case c == '$':
			tag, ok := dollarTagAt(content, i)
			if !ok {
				cur.WriteByte(c)
				i++
				break
			}
			rest := content[i+len(tag):]
			end := strings.Index(rest, tag)
			if end < 0 {
				t.Fatalf("unterminated dollar quote %q", tag)
			}
			cur.WriteString(content[i : i+len(tag)+end+len(tag)])
			i += len(tag) + end + len(tag)
		case c == ';':
			cur.WriteByte(c)
			i++
			flush()
		default:
			cur.WriteByte(c)
			i++
		}
	}
	flush()
	return stmts
}

// dollarTagAt reports whether a dollar-quote tag starts at s[i] (s[i] == '$')
// and returns it. Tags are the empty tag ($$) or an identifier-shaped tag
// ($tag$); $1-style parameter placeholders are NOT tags.
func dollarTagAt(s string, i int) (string, bool) {
	if s[i] != '$' {
		return "", false
	}
	j := i + 1
	if j < len(s) && s[j] == '$' {
		return "$$", true
	}
	for j < len(s) {
		r := rune(s[j])
		if r == '_' || r == '$' || unicode.IsLetter(r) || unicode.IsDigit(r) {
			j++
			continue
		}
		break
	}
	if j > i+1 && j < len(s) && s[j] == '$' {
		return s[i : j+1], true
	}
	return "", false
}

// TestIntegration_Migration0044_ReconcilesPreExistingLedgerRows — migration
// 0044 is applied on live databases that may ALREADY carry demo_grant ledger
// rows: the one-time seed grant (cmd/seed) and, if the endpoint was enabled
// between 0043 and 0044, interactive grants. The migration must reconcile
// the new counters with those rows: every interactive row is charged, seed
// rows are not, and the counters end up consistent with the ledger.
//
// Method: a scratch database is migrated through the REAL files 0001..0043
// (pre-0044 state), seeded with demo_grant ledger rows, then upgraded with
// the REAL 0044_demo_grant_budget.up.sql. Requires CHORA_TEST_ADMIN_DSN (a
// CREATEDB-capable DSN for the same cluster as CHORA_TEST_DSN); skipped when
// it is unset.
func TestIntegration_Migration0044_ReconcilesPreExistingLedgerRows(t *testing.T) {
	adminDSN := os.Getenv("CHORA_TEST_ADMIN_DSN")
	if adminDSN == "" {
		t.Skip("set CHORA_TEST_ADMIN_DSN (a CREATEDB-capable chora_identity DSN) to run the 0044 reconciliation spec")
	}
	ctx := context.Background()

	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("connect admin: %v", err)
	}
	defer func() { _ = admin.Close(ctx) }()

	scratch := "chora_identity_it_recon_" + strings.ToLower(uuid.NewString()[:8])
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+scratch); err != nil {
		t.Fatalf("create scratch database: %v", err)
	}
	defer func() {
		_, _ = admin.Exec(ctx, "DROP DATABASE "+scratch)
	}()

	cfg, err := pgx.ParseConfig(adminDSN)
	if err != nil {
		t.Fatalf("parse admin DSN: %v", err)
	}
	cfg.Database = scratch
	// The SIMPLE query protocol — the same one psql -f (and therefore
	// chora-stack/scripts/migrate.sh) uses: every statement autocommits
	// unless inside an explicit BEGIN/COMMIT. The extended protocol would wrap
	// the whole file in one implicit transaction, which breaks migrations
	// like 0043 that add an enum value OUTSIDE their transactional block.
	cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("connect scratch: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()

	// The runner's tracker table, exactly as migrate.sh creates it.
	if _, err := conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version TEXT PRIMARY KEY,
			filename TEXT NOT NULL,
			checksum TEXT NOT NULL,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`); err != nil {
		t.Fatalf("create schema_migrations: %v", err)
	}

	// 1. Apply the REAL migrations 0001..0043 — the pre-0044 schema.
	migDir := filepath.Join("..", "..", "..", "migrations")
	var pre0044 []string
	for _, name := range migrationFiles(t, migDir) {
		if name < "0044_demo_grant_budget.up.sql" {
			pre0044 = append(pre0044, name)
		}
	}
	applyMigrationFilesPgx(t, conn, migDir, pre0044...)

	// 2. Insert the demo_grant ledger rows that predate 0044: a seed-grant
	//    account, an interactive-grant account, and a non-demo-grant row that
	//    must not influence the counters at all.
	gcidSeed := uuid.NewString()
	gcidInteractive := uuid.NewString()
	gcidTopup := uuid.NewString()
	for i, gcid := range []string{gcidSeed, gcidInteractive, gcidTopup} {
		if _, err := conn.Exec(ctx, `
			INSERT INTO users (gcid, email, identity_provider, federated_subject, status)
			VALUES ($1::uuid, $2, 'password', $3, 'active')`,
			gcid, fmt.Sprintf("recon-%d@chora.dev", i), "sub-recon-"+gcid); err != nil {
			t.Fatalf("insert users row %d: %v", i, err)
		}
	}
	if _, err := conn.Exec(ctx, `
		INSERT INTO mana_ledger (entry_id, gcid, direction, units, reason, balance_after_units, idempotency_key, recorded_at)
		VALUES (gen_random_uuid(), $1::uuid, 'mint', 1000000000, 'demo_grant', 1000000000, $2, now())`,
		gcidSeed, demoSeedKeyPrefix+gcidSeed); err != nil {
		t.Fatalf("insert seed ledger row: %v", err)
	}
	if _, err := conn.Exec(ctx, `
		INSERT INTO mana_ledger (entry_id, gcid, direction, units, reason, balance_after_units, idempotency_key, recorded_at)
		VALUES (gen_random_uuid(), $1::uuid, 'mint', 5000, 'demo_grant', 5000, 'pre-0044-interactive', now())`,
		gcidInteractive); err != nil {
		t.Fatalf("insert interactive ledger row: %v", err)
	}
	if _, err := conn.Exec(ctx, `
		INSERT INTO mana_ledger (entry_id, gcid, direction, units, reason, balance_after_units, idempotency_key, recorded_at)
		VALUES (gen_random_uuid(), $1::uuid, 'mint', 12345, 'topup', 12345, 'pre-0044-topup', now())`,
		gcidTopup); err != nil {
		t.Fatalf("insert topup ledger row: %v", err)
	}

	// 3. Upgrade with the REAL 0044.
	applyMigrationFilesPgx(t, conn, migDir, "0044_demo_grant_budget.up.sql")

	// 4. The counters are consistent with the ledger: the interactive row is
	//    charged, the seed row is not, the topup row is invisible.
	var gUnits, gGrants int64
	if err := conn.QueryRow(ctx,
		`SELECT consumed_units, consumed_grants FROM demo_grant_budget WHERE budget_key = 'global'`).
		Scan(&gUnits, &gGrants); err != nil {
		t.Fatalf("read global counter: %v", err)
	}
	if gUnits != 5000 || gGrants != 1 {
		t.Errorf("global counter = (%d,%d), want (5000,1) — only the pre-0044 INTERACTIVE grant may be charged", gUnits, gGrants)
	}
	var iUnits, iGrants int64
	if err := conn.QueryRow(ctx,
		`SELECT consumed_units, consumed_grants FROM demo_grant_budget WHERE budget_key = $1`,
		"gcid:"+gcidInteractive).Scan(&iUnits, &iGrants); err != nil {
		t.Fatalf("read interactive counter: %v", err)
	}
	if iUnits != 5000 || iGrants != 1 {
		t.Errorf("interactive counter = (%d,%d), want (5000,1)", iUnits, iGrants)
	}
	var seedRows int
	if err := conn.QueryRow(ctx,
		`SELECT count(*) FROM demo_grant_budget WHERE budget_key = $1`, "gcid:"+gcidSeed).Scan(&seedRows); err != nil {
		t.Fatalf("read seed counter: %v", err)
	}
	if seedRows != 0 {
		t.Errorf("seed gcid has %d counter row(s), want 0 — the seed must not eat the interactive budget", seedRows)
	}

	// 5. As the runtime role, the helper still totals EVERY demo_grant row
	//    (seed included) while the counters hold only the interactive ones.
	if _, err := admin.Exec(ctx, "GRANT CONNECT ON DATABASE "+scratch+" TO chora_identity_app_rw"); err != nil {
		t.Fatalf("grant connect: %v", err)
	}
	appRWDSN := fmt.Sprintf("postgres://chora_identity_app_rw:chora@%s:%d/%s?sslmode=disable",
		cfg.Host, cfg.Port, scratch)
	appPool, err := pgxpool.New(ctx, appRWDSN)
	if err != nil {
		t.Fatalf("connect app_rw to scratch: %v", err)
	}
	defer appPool.Close()
	store := pg.NewManaStore(pg.NewPgxPoolQuerier(appPool))
	total, err := store.DemoGrantTotalUnits(ctx)
	if err != nil {
		t.Fatalf("DemoGrantTotalUnits on scratch: %v", err)
	}
	if total != 1_000_005_000 {
		t.Errorf("helper total = %d, want 1000005000 (seed 1e9 + interactive 5000; the topup row must not count)", total)
	}
}
