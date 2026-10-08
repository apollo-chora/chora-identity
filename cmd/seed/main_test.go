package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	pg "github.com/apollo-chora/chora-identity/internal/adapter/pg"

	mana "github.com/apollo-chora/chora-identity/internal/domain/user_mana"
)

// setAdminEnv sets the required admin seed env to valid values. Optional
// instructor/student vars are cleared unless the caller sets them.
func setAdminEnv(t *testing.T) {
	t.Helper()
	t.Setenv("CHORA_DB_DSN", "postgres://x")
	t.Setenv("CHORA_SEED_TENANT_ID", "22222222-2222-7222-8222-222222222222")
	t.Setenv("CHORA_SEED_TENANT_SLUG", "chora-local")
	t.Setenv("CHORA_SEED_ADMIN_USERNAME", "Admin")
	t.Setenv("CHORA_SEED_ADMIN_EMAIL", "admin@example.com")
	t.Setenv("CHORA_SEED_ADMIN_PASSWORD", "hunter2")
	t.Setenv("CHORA_SEED_INSTRUCTOR_USERNAME", "")
	t.Setenv("CHORA_SEED_INSTRUCTOR_EMAIL", "")
	t.Setenv("CHORA_SEED_INSTRUCTOR_PASSWORD", "")
	t.Setenv("CHORA_SEED_STUDENT_USERNAME", "")
	t.Setenv("CHORA_SEED_STUDENT_EMAIL", "")
	t.Setenv("CHORA_SEED_STUDENT_PASSWORD", "")
}

func TestSeedGcid_Deterministic(t *testing.T) {
	a := seedGcid("admin")
	b := seedGcid("admin")
	if a != b {
		t.Fatalf("seedGcid is not deterministic: %q vs %q", a, b)
	}
	if seedGcid("other") == a {
		t.Fatal("different usernames produced the same gcid")
	}
}

func TestSeedGcid_AdminStableAcrossRefactor(t *testing.T) {
	// The UUIDv5 name string is pinned so the seeded admin keeps its GCID
	// across refactors — changing it orphans the existing admin row.
	const want = "e016f4dc-7b47-5d25-ab63-46bf90953ef7"
	if got := seedGcid("admin"); got != want {
		t.Fatalf("seedGcid(admin) = %q, want %q", got, want)
	}
}

func TestMembershipID_Deterministic(t *testing.T) {
	a := membershipID("g-1", "t-1", "admin")
	b := membershipID("g-1", "t-1", "admin")
	if a != b {
		t.Fatalf("membershipID is not deterministic: %q vs %q", a, b)
	}
	if membershipID("g-1", "t-1", "learner") == a {
		t.Fatal("different roles produced the same membership id")
	}
}

func TestLoadConfig_MissingEnv(t *testing.T) {
	t.Setenv("CHORA_DB_DSN", "")
	t.Setenv("CHORA_SEED_TENANT_ID", "")
	t.Setenv("CHORA_SEED_TENANT_SLUG", "")
	t.Setenv("CHORA_SEED_ADMIN_USERNAME", "")
	t.Setenv("CHORA_SEED_ADMIN_EMAIL", "")
	t.Setenv("CHORA_SEED_ADMIN_PASSWORD", "")
	if _, err := loadConfig(); err == nil {
		t.Fatal("loadConfig with no env must error")
	}
}

func TestLoadConfig_Valid(t *testing.T) {
	setAdminEnv(t)
	c, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if c.Username != "Admin" {
		t.Errorf("username = %q", c.Username)
	}
	if c.InstructorUsername != "" || c.StudentUsername != "" {
		t.Errorf("optional users must default to empty, got instructor=%q student=%q",
			c.InstructorUsername, c.StudentUsername)
	}
}

func TestLoadConfig_RejectsBadTenantID(t *testing.T) {
	setAdminEnv(t)
	t.Setenv("CHORA_SEED_TENANT_ID", "not-a-uuid")
	if _, err := loadConfig(); err == nil {
		t.Fatal("bad tenant id must be rejected")
	}
}

func TestLoadConfig_InstructorUsernameRequiresEmailAndPassword(t *testing.T) {
	setAdminEnv(t)
	t.Setenv("CHORA_SEED_INSTRUCTOR_USERNAME", "instructor")
	if _, err := loadConfig(); err == nil {
		t.Fatal("instructor username without email/password must error")
	}
}

func TestLoadConfig_StudentUsernameRequiresEmailAndPassword(t *testing.T) {
	setAdminEnv(t)
	t.Setenv("CHORA_SEED_STUDENT_USERNAME", "student")
	if _, err := loadConfig(); err == nil {
		t.Fatal("student username without email/password must error")
	}
}

func TestLoadConfig_InstructorInvalidEmail(t *testing.T) {
	setAdminEnv(t)
	t.Setenv("CHORA_SEED_INSTRUCTOR_USERNAME", "instructor")
	t.Setenv("CHORA_SEED_INSTRUCTOR_EMAIL", "not-an-email")
	t.Setenv("CHORA_SEED_INSTRUCTOR_PASSWORD", "hunter2")
	if _, err := loadConfig(); err == nil {
		t.Fatal("invalid instructor email must be rejected")
	}
}

func TestLoadConfig_StudentInvalidEmail(t *testing.T) {
	setAdminEnv(t)
	t.Setenv("CHORA_SEED_STUDENT_USERNAME", "student")
	t.Setenv("CHORA_SEED_STUDENT_EMAIL", "not-an-email")
	t.Setenv("CHORA_SEED_STUDENT_PASSWORD", "hunter2")
	if _, err := loadConfig(); err == nil {
		t.Fatal("invalid student email must be rejected")
	}
}

func TestLoadConfig_InstructorPasswordTooLong(t *testing.T) {
	setAdminEnv(t)
	t.Setenv("CHORA_SEED_INSTRUCTOR_USERNAME", "instructor")
	t.Setenv("CHORA_SEED_INSTRUCTOR_EMAIL", "instructor@example.com")
	t.Setenv("CHORA_SEED_INSTRUCTOR_PASSWORD", strings.Repeat("a", 1025))
	if _, err := loadConfig(); err == nil {
		t.Fatal("over-long instructor password must be rejected")
	}
}

func TestLoadConfig_InstructorStudentValid(t *testing.T) {
	setAdminEnv(t)
	t.Setenv("CHORA_SEED_INSTRUCTOR_USERNAME", "instructor")
	t.Setenv("CHORA_SEED_INSTRUCTOR_EMAIL", "instructor@example.com")
	t.Setenv("CHORA_SEED_INSTRUCTOR_PASSWORD", "hunter2")
	t.Setenv("CHORA_SEED_STUDENT_USERNAME", "student")
	t.Setenv("CHORA_SEED_STUDENT_EMAIL", "student@example.com")
	t.Setenv("CHORA_SEED_STUDENT_PASSWORD", "hunter2")
	c, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if c.InstructorUsername != "instructor" || c.StudentUsername != "student" {
		t.Errorf("optional users not parsed: instructor=%q student=%q",
			c.InstructorUsername, c.StudentUsername)
	}
}

func TestSeedUsers_AdminOnlyByDefault(t *testing.T) {
	setAdminEnv(t)
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	users, err := seedUsers(cfg)
	if err != nil {
		t.Fatalf("seedUsers: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("want 1 seed user (admin), got %d", len(users))
	}
	if users[0].Role != "admin" {
		t.Errorf("admin role = %q", users[0].Role)
	}
}

func TestSeedUsers_InstructorAndStudent(t *testing.T) {
	setAdminEnv(t)
	t.Setenv("CHORA_SEED_INSTRUCTOR_USERNAME", "instructor")
	t.Setenv("CHORA_SEED_INSTRUCTOR_EMAIL", "instructor@example.com")
	t.Setenv("CHORA_SEED_INSTRUCTOR_PASSWORD", "hunter2")
	t.Setenv("CHORA_SEED_STUDENT_USERNAME", "student")
	t.Setenv("CHORA_SEED_STUDENT_EMAIL", "student@example.com")
	t.Setenv("CHORA_SEED_STUDENT_PASSWORD", "hunter2")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	users, err := seedUsers(cfg)
	if err != nil {
		t.Fatalf("seedUsers: %v", err)
	}
	if len(users) != 3 {
		t.Fatalf("want 3 seed users, got %d", len(users))
	}
	if users[0].Username != "Admin" || users[0].Role != "admin" {
		t.Errorf("users[0] = %q role %q, want Admin/admin", users[0].Username, users[0].Role)
	}
	if users[1].Username != "instructor" || users[1].Role != "instructor" {
		t.Errorf("users[1] = %q role %q, want instructor/instructor", users[1].Username, users[1].Role)
	}
	// The student account maps to the stored `learner` membership_role.
	if users[2].Username != "student" || users[2].Role != "learner" {
		t.Errorf("users[2] = %q role %q, want student/learner", users[2].Username, users[2].Role)
	}
}

func TestSeedUsers_RejectsDuplicateUsername(t *testing.T) {
	setAdminEnv(t)
	t.Setenv("CHORA_SEED_STUDENT_USERNAME", "admin") // normalises equal to the admin
	t.Setenv("CHORA_SEED_STUDENT_EMAIL", "student@example.com")
	t.Setenv("CHORA_SEED_STUDENT_PASSWORD", "hunter2")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if _, err := seedUsers(cfg); err == nil {
		t.Fatal("duplicate seed username must be rejected")
	}
}

// --- demo seed grant ---------------------------------------------------------

func TestDemoSeedGrant_KeyIsDeterministicAndPerGcid(t *testing.T) {
	a1 := demoSeedGrantKey(demoSeedGcid)
	a2 := demoSeedGcid
	_ = a2
	if a1 != demoSeedGrantKey(demoSeedGcid) {
		t.Fatal("the demo seed idempotency key must be deterministic across runs")
	}
	if got := demoSeedGrantKey("11111111-1111-7111-8111-111111111111"); got == a1 {
		t.Fatal("distinct seeded accounts must not share a demo idempotency key")
	}
	if !strings.HasPrefix(a1, "demo-seed:v1:") {
		t.Errorf("key = %q, want the demo-seed:v1: prefix", a1)
	}
}

func TestDemoSeedGrant_UnitsAreTheFixedDemoBalance(t *testing.T) {
	if demoSeedGrantUnits != 1_000_000_000 {
		t.Errorf("demoSeedGrantUnits = %d, want 1e9", demoSeedGrantUnits)
	}
}

func TestApplyDemoSeedGrant_SetsUserGUCAndCredits(t *testing.T) {
	// The grant must be scoped to the user it credits, so it stays correct for
	// every seeded user even if the seed DSN is not the table owner.
	tx := newDemoGrantStubTx()
	if err := applyDemoSeedGrant(context.Background(), tx, demoSeedGcid); err != nil {
		t.Fatalf("applyDemoSeedGrant: %v", err)
	}
	if !strings.Contains(tx.lastGUC, "chora.user_gcid") {
		t.Errorf("GUC writes = %v, want chora.user_gcid to be set", tx.gucs)
	}
	if !strings.Contains(tx.lastGUC, demoSeedGcid) {
		t.Errorf("GUC = %q, want it scoped to %s", tx.lastGUC, demoSeedGcid)
	}
	if len(tx.ledger) != 1 {
		t.Fatalf("ledger rows = %d, want 1", len(tx.ledger))
	}
	e := tx.ledger[0]
	if e.Reason != "demo_grant" || e.Direction != "mint" || e.Units != demoSeedGrantUnits {
		t.Errorf("entry = %s/%s/%d, want demo_grant/mint/%d", e.Reason, e.Direction, e.Units, demoSeedGrantUnits)
	}
	if e.IdempotencyKey != demoSeedGrantKey(demoSeedGcid) {
		t.Errorf("idempotency_key = %q, want %q", e.IdempotencyKey, demoSeedGrantKey(demoSeedGcid))
	}
	if tx.wallets[demoSeedGcid].BalanceUnits != demoSeedGrantUnits {
		t.Errorf("balance = %d, want %d", tx.wallets[demoSeedGcid].BalanceUnits, demoSeedGrantUnits)
	}
}

func TestApplyDemoSeedGrant_RerunAddsNothing(t *testing.T) {
	tx := newDemoGrantStubTx()
	ctx := context.Background()
	if err := applyDemoSeedGrant(ctx, tx, demoSeedGcid); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := applyDemoSeedGrant(ctx, tx, demoSeedGcid); err != nil {
		t.Fatalf("rerun: %v", err)
	}
	if len(tx.ledger) != 1 {
		t.Errorf("ledger rows = %d, want 1 — a rerun must not re-add", len(tx.ledger))
	}
	if got := tx.wallets[demoSeedGcid].BalanceUnits; got != demoSeedGrantUnits {
		t.Errorf("balance = %d, want %d", got, demoSeedGrantUnits)
	}
}

func TestApplyDemoSeedGrant_AfterSpendingPreservesSpentBalance(t *testing.T) {
	tx := newDemoGrantStubTx()
	ctx := context.Background()
	if err := applyDemoSeedGrant(ctx, tx, demoSeedGcid); err != nil {
		t.Fatalf("first: %v", err)
	}
	// The user spends part of the grant; a rerun must not top it back up.
	tx.wallets[demoSeedGcid].BalanceUnits -= 250_000_000
	tx.wallets[demoSeedGcid].LifetimeSpent += 250_000_000

	if err := applyDemoSeedGrant(ctx, tx, demoSeedGcid); err != nil {
		t.Fatalf("rerun after spend: %v", err)
	}
	if got := tx.wallets[demoSeedGcid].BalanceUnits; got != 750_000_000 {
		t.Errorf("balance = %d, want 750000000 (the spent balance, never reset)", got)
	}
	if len(tx.ledger) != 1 {
		t.Errorf("ledger rows = %d, want 1", len(tx.ledger))
	}
}

func TestApplyDemoSeedGrant_FailureChangesNeither(t *testing.T) {
	tx := newDemoGrantStubTx()
	tx.failLedger = true
	if err := applyDemoSeedGrant(context.Background(), tx, demoSeedGcid); err == nil {
		t.Fatal("applyDemoSeedGrant err = nil, want the ledger failure")
	}
	if len(tx.ledger) != 0 {
		t.Errorf("ledger rows = %d, want 0", len(tx.ledger))
	}
	if w := tx.wallets[demoSeedGcid]; w != nil && w.BalanceUnits != 0 {
		t.Errorf("balance = %d, want 0 — a failed seed must not credit", w.BalanceUnits)
	}
}

// demoGrantStubTx is a minimal pgx.Tx stand-in covering only what the seed's demo
// grant touches. It records the GUC writes and the ledger/wallet effects.
const demoSeedGcid = "e016f4dc-7b47-5d25-ab63-46bf90953ef7"

type demoGrantStubTx struct {
	gucs       []string
	lastGUC    string
	wallets    map[string]*mana.UserMana
	ledger     []mana.LedgerEntry
	failLedger bool

	inFlight bool
	pending  struct {
		w map[string]*mana.UserMana
		l []mana.LedgerEntry
	}
}

func newDemoGrantStubTx() *demoGrantStubTx {
	return &demoGrantStubTx{wallets: map[string]*mana.UserMana{}}
}

// Exec models the grant unit as ONE transaction: the chora.user_gcid write
// opens it, and any failure rolls the whole unit back, so a failed grant
// changes neither the wallet nor the ledger.
func (t *demoGrantStubTx) Exec(ctx context.Context, sql string, args ...any) error {
	if strings.Contains(sql, "SET LOCAL chora.user_gcid") && !t.inFlight {
		w, l := t.snapshot()
		t.pending.w, t.pending.l = w, l
		t.inFlight = true
	}
	err := t.exec(ctx, sql, args...)
	if err != nil && t.inFlight {
		t.restore(t.pending.w, t.pending.l)
		t.inFlight = false
	}
	return err
}

func (t *demoGrantStubTx) exec(_ context.Context, sql string, args ...any) error {
	if strings.Contains(sql, "SET LOCAL chora.user_gcid") {
		t.lastGUC = sql
		t.gucs = append(t.gucs, sql)
		return nil
	}
	if strings.Contains(sql, "INSERT INTO mana_ledger") {
		if t.failLedger {
			return errors.New("seed demo: ledger write failed")
		}
		t.ledger = append(t.ledger, mana.LedgerEntry{
			EntryID: args[0].(string), Gcid: args[1].(string),
			Direction: mana.Direction(args[2].(string)), Units: args[3].(int64),
			Reason: mana.Reason(args[4].(string)), BalanceAfterUnits: args[9].(int64),
			IdempotencyKey: args[10].(string), RecordedAt: args[13].(time.Time),
		})
		return nil
	}
	if strings.Contains(sql, "INSERT INTO user_mana") {
		t.wallets[args[0].(string)] = &mana.UserMana{Gcid: args[0].(string), BalanceUnits: args[1].(int64), LifetimeEarned: args[2].(int64), LifetimeSpent: args[3].(int64), Version: args[5].(int64), UpdatedAt: args[6].(time.Time)}
		return nil
	}
	return nil
}

func (t *demoGrantStubTx) snapshot() (map[string]*mana.UserMana, []mana.LedgerEntry) {
	w := make(map[string]*mana.UserMana, len(t.wallets))
	for k, v := range t.wallets {
		clone := *v
		w[k] = &clone
	}
	l := make([]mana.LedgerEntry, len(t.ledger))
	copy(l, t.ledger)
	return w, l
}

func (t *demoGrantStubTx) restore(w map[string]*mana.UserMana, l []mana.LedgerEntry) {
	t.wallets = w
	t.ledger = l
}

func (t *demoGrantStubTx) QueryRow(_ context.Context, sql string, args ...any) pg.Row {
	switch {
	case strings.Contains(sql, "FROM mana_ledger"):
		for _, e := range t.ledger {
			if e.Gcid == args[0].(string) && e.IdempotencyKey == args[1].(string) {
				return demoGrantStubRow{vals: []any{e.EntryID, e.Gcid, string(e.Direction), e.Units,
					string(e.Reason), nil, nil, nil, nil, e.BalanceAfterUnits, e.IdempotencyKey,
					nil, nil, e.RecordedAt}}
			}
		}
		return demoGrantStubRow{}
	case strings.Contains(sql, "INSERT INTO user_mana"):
		if len(args) == 7 {
			m := &mana.UserMana{Gcid: args[0].(string)}
			m.BalanceUnits, m.LifetimeEarned, m.LifetimeSpent = args[1].(int64), args[2].(int64), args[3].(int64)
			m.Version, m.UpdatedAt = args[5].(int64), args[6].(time.Time)
			t.wallets[m.Gcid] = m
			return demoGrantStubRow{vals: []any{m.Gcid, m.BalanceUnits, m.LifetimeEarned,
				m.LifetimeSpent, nil, m.Version, m.UpdatedAt}}
		}
		return demoGrantStubRow{vals: []any{args[0].(string), int64(0), int64(0), int64(0), nil, int64(1), time.Time{}}}
	case strings.Contains(sql, "FROM user_mana"):
		if m, ok := t.wallets[args[0].(string)]; ok {
			return demoGrantStubRow{vals: []any{m.Gcid, m.BalanceUnits, m.LifetimeEarned, m.LifetimeSpent, nil, m.Version, m.UpdatedAt}}
		}
		return demoGrantStubRow{}
	}
	return demoGrantStubRow{vals: []any{int64(0)}}
}

func (t *demoGrantStubTx) Query(context.Context, string, ...any) (pg.Rows, error) {
	return nil, errors.New("seed demo: Query not implemented")
}

// demoGrantStubRow is a pgx.Row stand-in; an empty vals list is ErrNoRows.
type demoGrantStubRow struct{ vals []any }

func (r demoGrantStubRow) Scan(dest ...any) error {
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
