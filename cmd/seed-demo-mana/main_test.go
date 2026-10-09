package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/apollo-chora/chora-identity/internal/adapter/pg"
	mana "github.com/apollo-chora/chora-identity/internal/domain/user_mana"
)

const (
	gcidA = "11111111-1111-7111-8111-111111111111"
	gcidB = "22222222-2222-7222-8222-222222222222"
)

// --- config ------------------------------------------------------------------

func TestLoadConfig_RequiresGcids(t *testing.T) {
	t.Setenv(envGcids, "")
	t.Setenv(envDSN, "postgres://x")
	if _, err := loadConfig(nil); err == nil {
		t.Fatal("loadConfig with no GCIDs must error")
	}
}

func TestLoadConfig_RequiresDSN(t *testing.T) {
	t.Setenv(envDSN, "")
	if _, err := loadConfig([]string{"-gcids=" + gcidA}); err == nil {
		t.Fatal("loadConfig without a DSN must error")
	}
}

func TestLoadConfig_DefaultAmountIsOneBillion(t *testing.T) {
	t.Setenv(envGcids, gcidA)
	t.Setenv(envGrantUnits, "")
	t.Setenv(envDSN, "postgres://x")
	cfg, err := loadConfig(nil)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.Units != 1_000_000_000 {
		t.Errorf("units = %d, want the 1e9 default", cfg.Units)
	}
	if cfg.DryRun {
		t.Error("dry run must be OFF by default")
	}
}

func TestLoadConfig_GcidsFromEnvFlagAndRepeatedFlag(t *testing.T) {
	t.Setenv(envGcids, strings.ToUpper(gcidA)) // env supplies A, in upper case
	t.Setenv(envDSN, "postgres://x")
	cfg, err := loadConfig([]string{"-gcid=" + gcidB, "-amount=7", "-dry-run"})
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if len(cfg.Gcids) != 2 || cfg.Gcids[0] != gcidA || cfg.Gcids[1] != gcidB {
		t.Fatalf("gcids = %v, want the canonical [%s %s]", cfg.Gcids, gcidA, gcidB)
	}
	if cfg.Units != 7 || !cfg.DryRun {
		t.Errorf("units=%d dryRun=%t", cfg.Units, cfg.DryRun)
	}
}

func TestLoadConfig_DeduplicatesGcids(t *testing.T) {
	t.Setenv(envGcids, "")
	t.Setenv(envDSN, "postgres://x")
	cfg, err := loadConfig([]string{"-gcids=" + gcidA + "," + strings.ToUpper(gcidA)})
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if len(cfg.Gcids) != 1 {
		t.Errorf("gcids = %v, want one entry — the key is per GCID", cfg.Gcids)
	}
}

func TestLoadConfig_RejectsEmptyEntry(t *testing.T) {
	t.Setenv(envGcids, "")
	t.Setenv(envDSN, "postgres://x")
	if _, err := loadConfig([]string{"-gcids=" + gcidA + ","}); err == nil {
		t.Fatal("a trailing comma must be rejected, not silently skipped")
	}
}

func TestLoadConfig_RejectsNonUUID(t *testing.T) {
	t.Setenv(envGcids, "")
	t.Setenv(envDSN, "postgres://x")
	if _, err := loadConfig([]string{"-gcids=not-a-gcid"}); err == nil {
		t.Fatal("a non-UUID GCID must be rejected")
	}
}

func TestLoadConfig_RejectsNonPositiveAmount(t *testing.T) {
	t.Setenv(envGcids, gcidA)
	t.Setenv(envDSN, "postgres://x")
	if _, err := loadConfig([]string{"-amount=0"}); err == nil {
		t.Fatal("a zero grant must be rejected")
	}
}

// --- authorization gate ------------------------------------------------------

func TestAuthorize_RefusesWithoutFlags(t *testing.T) {
	t.Setenv(envChoraEnv, "")
	t.Setenv(envDemoMode, "")
	t.Setenv(envDemoTopup, "")
	if err := authorize(); err == nil {
		t.Fatal("an unauthorized run must be refused")
	}
}

func TestAuthorize_RefusesWithOnlyOneFlag(t *testing.T) {
	t.Setenv(envChoraEnv, "")
	t.Setenv(envDemoMode, "true")
	t.Setenv(envDemoTopup, "")
	if err := authorize(); err == nil {
		t.Fatal("one flag alone must not authorize a run")
	}
}

func TestAuthorize_RefusesInProdEvenWithBothFlags(t *testing.T) {
	for _, env := range []string{"prod", "PRODUCTION", "Production"} {
		t.Setenv(envChoraEnv, env)
		t.Setenv(envDemoMode, "true")
		t.Setenv(envDemoTopup, "true")
		if err := authorize(); err == nil {
			t.Fatalf("CHORA_ENV=%q with both flags set must still be refused", env)
		}
	}
}

func TestAuthorize_AllowsWhenExplicitlyAuthorized(t *testing.T) {
	t.Setenv(envChoraEnv, "local")
	t.Setenv(envDemoMode, "true")
	t.Setenv(envDemoTopup, "true")
	if err := authorize(); err != nil {
		t.Fatalf("authorize: %v", err)
	}
}

// --- behaviour against the in-memory transaction -----------------------------

// runCmd is the shared harness: an in-memory identity database holding the
// given accounts.
func runCmd(t *testing.T, db *stubDB, cfg config) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := run(context.Background(), db, cfg, &out)
	return out.String(), err
}

func newDB(gcids ...string) *stubDB {
	db := &stubDB{users: map[string]bool{}, wallets: map[string]*mana.UserMana{}}
	for _, g := range gcids {
		db.users[g] = true
	}
	return db
}

func applyCfg(gcids ...string) config {
	return config{Gcids: gcids, Units: 1_000_000_000}
}

// TestRun_FirstRunApplies proves the first run credits the wallet and appends
// exactly one demo_grant ledger row under the deterministic key.
func TestRun_FirstRunApplies(t *testing.T) {
	db := newDB(gcidA)
	out, err := runCmd(t, db, applyCfg(gcidA))
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}
	w := db.wallets[gcidA]
	if w == nil || w.BalanceUnits != 1_000_000_000 {
		t.Fatalf("balance = %+v, want 1000000000", w)
	}
	if len(db.ledger) != 1 {
		t.Fatalf("ledger rows = %d, want 1", len(db.ledger))
	}
	e := db.ledger[0]
	if e.Reason != mana.ReasonDemoGrant || e.Direction != mana.DirectionMint {
		t.Errorf("entry = %s/%s, want demo_grant/mint", e.Reason, e.Direction)
	}
	if e.IdempotencyKey != demoSeedGrantKey(gcidA) {
		t.Errorf("key = %q, want %q", e.IdempotencyKey, demoSeedGrantKey(gcidA))
	}
	if !strings.Contains(out, "status=applied") || !strings.Contains(out, "applied=1") {
		t.Errorf("audit summary does not report the apply:\n%s", out)
	}
}

// TestRun_RerunReplaysWithNoDoubleCredit proves the second run replays: no
// second ledger row, no extra units.
func TestRun_RerunReplaysWithNoDoubleCredit(t *testing.T) {
	db := newDB(gcidA)
	if _, err := runCmd(t, db, applyCfg(gcidA)); err != nil {
		t.Fatalf("first run: %v", err)
	}
	out, err := runCmd(t, db, applyCfg(gcidA))
	if err != nil {
		t.Fatalf("rerun: %v", err)
	}
	if got := db.wallets[gcidA].BalanceUnits; got != 1_000_000_000 {
		t.Errorf("balance = %d, want 1000000000 — a rerun must not double-credit", got)
	}
	if len(db.ledger) != 1 {
		t.Errorf("ledger rows = %d, want 1", len(db.ledger))
	}
	if !strings.Contains(out, "status=replayed") || !strings.Contains(out, "replayed=1") {
		t.Errorf("audit summary does not report the replay:\n%s", out)
	}
	if !strings.Contains(out, "units_credited=0") {
		t.Errorf("a replay credits nothing:\n%s", out)
	}
}

// TestRun_RerunAfterSpendingDoesNotReset proves the grant is additive: a spent
// balance is never topped back up.
func TestRun_RerunAfterSpendingDoesNotReset(t *testing.T) {
	db := newDB(gcidA)
	if _, err := runCmd(t, db, applyCfg(gcidA)); err != nil {
		t.Fatalf("first run: %v", err)
	}
	db.wallets[gcidA].BalanceUnits -= 250_000_000
	if _, err := runCmd(t, db, applyCfg(gcidA)); err != nil {
		t.Fatalf("rerun: %v", err)
	}
	if got := db.wallets[gcidA].BalanceUnits; got != 750_000_000 {
		t.Errorf("balance = %d, want 750000000 — a rerun must not reset a spent balance", got)
	}
}

// TestRun_DryRunMakesNoChanges proves the dry run reports what WOULD happen and
// issues no INSERT/UPDATE/DELETE at all.
func TestRun_DryRunMakesNoChanges(t *testing.T) {
	db := newDB(gcidA, gcidB)
	cfg := applyCfg(gcidA, gcidB)
	cfg.DryRun = true
	out, err := runCmd(t, db, cfg)
	if err != nil {
		t.Fatalf("dry run: %v\n%s", err, out)
	}
	for _, sql := range db.statements {
		up := strings.ToUpper(sql)
		if strings.Contains(up, "INSERT") || strings.Contains(up, "UPDATE") || strings.Contains(up, "DELETE") {
			t.Errorf("dry run issued a write: %s", sql)
		}
	}
	if len(db.wallets) != 0 || len(db.ledger) != 0 {
		t.Fatalf("dry run changed state: wallets=%d ledger=%d", len(db.wallets), len(db.ledger))
	}
	if !strings.Contains(out, "DRY RUN") {
		t.Errorf("the report must say it is a dry run:\n%s", out)
	}
	if strings.Count(out, "status=would-apply") != 2 {
		t.Errorf("want 2 would-apply lines:\n%s", out)
	}
	if !strings.Contains(out, "would-apply=2") || !strings.Contains(out, "units_credited=0") {
		t.Errorf("summary = \n%s", out)
	}
	if !strings.Contains(out, "after=1000000000") {
		t.Errorf("the dry run must project the post-grant balance:\n%s", out)
	}
}

// TestRun_DryRunAfterGrantReportsWouldReplay proves the dry run recognises an
// already-applied grant.
func TestRun_DryRunAfterGrantReportsWouldReplay(t *testing.T) {
	db := newDB(gcidA)
	if _, err := runCmd(t, db, applyCfg(gcidA)); err != nil {
		t.Fatalf("apply: %v", err)
	}
	cfg := applyCfg(gcidA)
	cfg.DryRun = true
	out, err := runCmd(t, db, cfg)
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if !strings.Contains(out, "status=would-replay") {
		t.Errorf("want would-replay:\n%s", out)
	}
	if len(db.ledger) != 1 {
		t.Errorf("ledger rows = %d, want 1", len(db.ledger))
	}
}

// TestRun_UnknownGcidIsReportedAndNotCreated proves a GCID with no account is
// reported and that neither a user nor a wallet row is conjured for it.
func TestRun_UnknownGcidIsReportedAndNotCreated(t *testing.T) {
	const missing = "33333333-3333-7333-8333-333333333333"
	db := newDB(gcidA) // `missing` has no users row
	cfg := applyCfg(gcidA, missing)
	cfg.DryRun = true
	out, err := runCmd(t, db, cfg)
	// The dry run reports the same refusal the real run would make.
	if err == nil {
		t.Fatalf("a dry run naming an unknown GCID must report it as not granted:\n%s", out)
	}
	if !strings.Contains(out, "gcid="+missing+" status=unknown-gcid") {
		t.Errorf("the unknown GCID must be reported:\n%s", out)
	}
	if !strings.Contains(out, "NOT created") {
		t.Errorf("the report must state nothing was created:\n%s", out)
	}
	if strings.Contains(out, "gcid="+missing+" status=would-apply") {
		t.Errorf("an unknown GCID must never be scheduled for a grant:\n%s", out)
	}
	if len(db.wallets) != 0 || len(db.ledger) != 0 {
		t.Fatalf("the dry run changed state: wallets=%d ledger=%d", len(db.wallets), len(db.ledger))
	}

	// The real run must refuse too, and must leave no trace of the account.
	real := applyCfg(gcidA, missing)
	out, err = runCmd(t, db, real)
	if err == nil {
		t.Fatalf("a run naming an unknown GCID must report a failure:\n%s", out)
	}
	if !strings.Contains(err.Error(), missing) {
		t.Errorf("err = %v, want it to name %s", err, missing)
	}
	if !strings.Contains(out, "status=unknown-gcid") {
		t.Errorf("the unknown GCID must be reported on the real run too:\n%s", out)
	}
	if len(db.users) != 1 {
		t.Errorf("users = %v, want the unknown GCID NOT to be created", db.users)
	}
	if _, ok := db.wallets[missing]; ok {
		t.Error("a wallet row was created for an account that does not exist")
	}
	for _, e := range db.ledger {
		if e.Gcid == missing {
			t.Error("a ledger row was created for an account that does not exist")
		}
	}
	// The good GCID in the same batch is still processed.
	if db.wallets[gcidA] == nil {
		t.Error("one unknown GCID must not stop the rest of the batch")
	}
}

// TestRun_WritesOnlyWalletAndLedger proves the command touches no identity
// table — it must never create a user, credential or membership.
func TestRun_WritesOnlyWalletAndLedger(t *testing.T) {
	db := newDB(gcidA)
	if _, err := runCmd(t, db, applyCfg(gcidA)); err != nil {
		t.Fatalf("run: %v", err)
	}
	forbidden := []string{"local_credentials", "tenant_memberships", "INTO users", "UPDATE users", "INSERT INTO tenants"}
	for _, sql := range db.statements {
		up := strings.ToUpper(sql)
		for _, f := range forbidden {
			if strings.Contains(up, strings.ToUpper(f)) {
				t.Errorf("the command must not touch %s: %s", f, sql)
			}
		}
	}
}

// TestRun_ScopesEveryGcidToItsOwnTransaction proves each GCID gets its own
// RLS-scoped transaction, i.e. SET LOCAL chora.user_gcid is applied per GCID.
func TestRun_ScopesEveryGcidToItsOwnTransaction(t *testing.T) {
	db := newDB(gcidA, gcidB)
	if _, err := runCmd(t, db, applyCfg(gcidA, gcidB)); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(db.txGcids) != 2 || db.txGcids[0] != gcidA || db.txGcids[1] != gcidB {
		t.Fatalf("transactions = %v, want one scoped tx per GCID", db.txGcids)
	}
	for _, g := range db.txGcids {
		if !db.gucs[g] {
			t.Errorf("chora.user_gcid was never set for %s", g)
		}
	}
}

// TestRun_ConflictIsReportedAsFailure proves a key reused for a DIFFERENT
// operation is refused rather than treated as a replay.
func TestRun_ConflictIsReportedAsFailure(t *testing.T) {
	db := newDB(gcidA)
	db.ledger = append(db.ledger, mana.LedgerEntry{
		EntryID: "e-1", Gcid: gcidA, Direction: mana.DirectionMint,
		Units: 5, Reason: mana.ReasonDemoGrant,
		IdempotencyKey: demoSeedGrantKey(gcidA), RecordedAt: time.Now().UTC(),
	})
	_, err := runCmd(t, db, applyCfg(gcidA))
	if err == nil {
		t.Fatal("a key recorded with a different amount must be refused")
	}
	if !errors.Is(err, mana.ErrIdempotencyConflict) {
		t.Errorf("err = %v, want ErrIdempotencyConflict", err)
	}
	if db.wallets[gcidA] != nil {
		t.Error("a conflict must not credit the wallet")
	}
}

// TestRun_DryRunReportsAConflictBeforeWriting proves the dry run surfaces the
// conflict the real run would hit.
func TestRun_DryRunReportsAConflictBeforeWriting(t *testing.T) {
	db := newDB(gcidA)
	db.ledger = append(db.ledger, mana.LedgerEntry{
		EntryID: "e-1", Gcid: gcidA, Direction: mana.DirectionMint,
		Units: 5, Reason: mana.ReasonDemoGrant,
		IdempotencyKey: demoSeedGrantKey(gcidA), RecordedAt: time.Now().UTC(),
	})
	cfg := applyCfg(gcidA)
	cfg.DryRun = true
	out, err := runCmd(t, db, cfg)
	if err == nil {
		t.Fatalf("dry run must report the conflict:\n%s", out)
	}
	if !strings.Contains(out, "status=would-conflict") {
		t.Errorf("want would-conflict:\n%s", out)
	}
	if len(db.ledger) != 1 {
		t.Errorf("ledger rows = %d, want 1", len(db.ledger))
	}
}

// TestRun_FailureIsReportedAndNotCredited proves a ledger write failure leaves
// neither the wallet nor the ledger changed.
func TestRun_FailureIsReportedAndNotCredited(t *testing.T) {
	db := newDB(gcidA)
	db.failLedger = true
	out, err := runCmd(t, db, applyCfg(gcidA))
	if err == nil {
		t.Fatalf("a ledger failure must fail the run:\n%s", out)
	}
	if !strings.Contains(out, "status=failed") {
		t.Errorf("want status=failed:\n%s", out)
	}
	if w := db.wallets[gcidA]; w != nil && w.BalanceUnits != 0 {
		t.Errorf("balance = %d, want 0", w.BalanceUnits)
	}
	if len(db.ledger) != 0 {
		t.Errorf("ledger rows = %d, want 0", len(db.ledger))
	}
}

// TestDemoSeedGrantKey_MatchesTheSeedProgram pins the key shape shared with
// cmd/seed, so the two commands replay each other's grants.
func TestDemoSeedGrantKey_MatchesTheSeedProgram(t *testing.T) {
	if got := demoSeedGrantKey(gcidA); got != "demo-seed:v1:"+gcidA {
		t.Errorf("key = %q", got)
	}
}

// -----------------------------------------------------------------------------
// in-memory chora_identity stand-in
// -----------------------------------------------------------------------------

// stubDB is a pg.UserTxQuerier backed by in-memory maps. RunInUserTx models the
// real one: it applies the RLS GUC for the GCID, runs fn on ONE transaction, and
// rolls the whole unit back when fn fails.
type stubDB struct {
	users      map[string]bool
	wallets    map[string]*mana.UserMana
	ledger     []mana.LedgerEntry
	failLedger bool

	statements []string
	txGcids    []string
	gucs       map[string]bool
}

func (db *stubDB) RunInUserTx(ctx context.Context, gcid, _ string, fn func(context.Context, pg.Tx) error) error {
	if db.gucs == nil {
		db.gucs = map[string]bool{}
	}
	tx := &stubTx{db: db, inTx: true}
	if err := tx.Exec(ctx, "SET LOCAL chora.user_gcid = '"+gcid+"'"); err != nil {
		return err
	}
	db.txGcids = append(db.txGcids, gcid)
	db.gucs[gcid] = true

	wallets, ledger := db.snapshot()
	if err := fn(ctx, tx); err != nil {
		db.restore(wallets, ledger)
		return err
	}
	return nil
}

func (db *stubDB) snapshot() (map[string]*mana.UserMana, []mana.LedgerEntry) {
	w := make(map[string]*mana.UserMana, len(db.wallets))
	for k, v := range db.wallets {
		clone := *v
		w[k] = &clone
	}
	l := make([]mana.LedgerEntry, len(db.ledger))
	copy(l, db.ledger)
	return w, l
}

func (db *stubDB) restore(w map[string]*mana.UserMana, l []mana.LedgerEntry) {
	db.wallets, db.ledger = w, l
}

// stubTx implements pg.Tx over the stubDB state.
type stubTx struct {
	db   *stubDB
	inTx bool
}

func (t *stubTx) Exec(_ context.Context, sql string, args ...any) error {
	t.db.statements = append(t.db.statements, sql)
	switch {
	case strings.Contains(sql, "pg_advisory_xact_lock"):
		return nil
	case strings.Contains(sql, "SET LOCAL"):
		return nil
	case strings.Contains(sql, "INSERT INTO mana_ledger"):
		if t.db.failLedger {
			return errors.New("stub: ledger write failed")
		}
		t.db.ledger = append(t.db.ledger, mana.LedgerEntry{
			EntryID: args[0].(string), Gcid: args[1].(string),
			Direction: mana.Direction(args[2].(string)), Units: args[3].(int64),
			Reason: mana.Reason(args[4].(string)), BalanceAfterUnits: args[9].(int64),
			IdempotencyKey: args[10].(string), RecordedAt: args[13].(time.Time),
		})
		return nil
	default:
		return nil
	}
}

func (t *stubTx) QueryRow(_ context.Context, sql string, args ...any) pg.Row {
	t.db.statements = append(t.db.statements, sql)
	switch {
	case strings.Contains(sql, "FROM users"):
		return stubRow{vals: []any{t.db.users[args[0].(string)]}}
	case strings.Contains(sql, "FROM mana_ledger"):
		for _, e := range t.db.ledger {
			if e.Gcid == args[0].(string) && e.IdempotencyKey == args[1].(string) {
				return stubRow{vals: ledgerVals(e)}
			}
		}
		return stubRow{}
	case strings.Contains(sql, "INSERT INTO user_mana"):
		return stubRow{vals: t.upsertWallet(args)}
	case strings.Contains(sql, "FROM user_mana"):
		w, ok := t.db.wallets[args[0].(string)]
		if !ok {
			return stubRow{}
		}
		return stubRow{vals: walletVals(w)}
	case strings.Contains(sql, "FROM mana_subsidy_allocations"):
		return stubRow{vals: []any{int64(0)}}
	}
	return stubRow{vals: []any{int64(0)}}
}

// upsertWallet models lockWalletTx (1 arg: the gcid) and putWalletTx (7 args:
// the full snapshot).
func (t *stubTx) upsertWallet(args []any) []any {
	gcid := args[0].(string)
	if len(args) == 7 {
		m := &mana.UserMana{
			Gcid: gcid, BalanceUnits: args[1].(int64), LifetimeEarned: args[2].(int64),
			LifetimeSpent: args[3].(int64), Version: args[5].(int64), UpdatedAt: args[6].(time.Time),
		}
		if lt, ok := args[4].(*time.Time); ok {
			m.LastCreditedAt = lt
		}
		t.db.wallets[gcid] = m
		return walletVals(m)
	}
	m, ok := t.db.wallets[gcid]
	if !ok {
		m = &mana.UserMana{Gcid: gcid, Version: 1, UpdatedAt: time.Now().UTC()}
		t.db.wallets[gcid] = m
	}
	return walletVals(m)
}

func (t *stubTx) Query(context.Context, string, ...any) (pg.Rows, error) {
	return nil, errors.New("stub: Query not implemented")
}

func walletVals(m *mana.UserMana) []any {
	return []any{m.Gcid, m.BalanceUnits, m.LifetimeEarned, m.LifetimeSpent, nil, m.Version, m.UpdatedAt}
}

func ledgerVals(e mana.LedgerEntry) []any {
	return []any{e.EntryID, e.Gcid, string(e.Direction), e.Units, string(e.Reason),
		nil, nil, nil, nil, e.BalanceAfterUnits, e.IdempotencyKey, nil, nil, e.RecordedAt}
}

// stubRow is a pg.Row stand-in; an empty vals slice is ErrNoRows.
type stubRow struct{ vals []any }

func (r stubRow) Scan(dest ...any) error {
	if len(r.vals) == 0 {
		return pg.ErrNoRows
	}
	for i, d := range dest {
		if i >= len(r.vals) {
			return nil
		}
		switch p := d.(type) {
		case *string:
			if v, ok := r.vals[i].(string); ok {
				*p = v
			}
		case *int64:
			if v, ok := r.vals[i].(int64); ok {
				*p = v
			}
		case *bool:
			if v, ok := r.vals[i].(bool); ok {
				*p = v
			}
		case *time.Time:
			if v, ok := r.vals[i].(time.Time); ok {
				*p = v
			}
		case **time.Time:
			if v, ok := r.vals[i].(*time.Time); ok {
				*p = v
			}
		}
	}
	return nil
}
