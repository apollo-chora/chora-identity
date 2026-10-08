package pg

import (
	"context"
	"errors"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	mana "github.com/apollo-chora/chora-identity/internal/domain/user_mana"
)

// errCreditBoom is the failure the stub raises for a matched Exec.
var errCreditBoom = errors.New("credit stub: ledger write boom")

const (
	creditStubGcid = "00000000-0000-7000-8000-000000001999"
	creditStubKey  = "demo-seed:v1:00000000-0000-7000-8000-000000001999"
)

func creditStubInput() mana.CreditWalletInput {
	return mana.CreditWalletInput{
		Gcid:           creditStubGcid,
		Units:          1_000_000_000,
		Direction:      mana.DirectionMint,
		Reason:         mana.ReasonDemoGrant,
		IdempotencyKey: creditStubKey,
	}
}

// creditStubTx is a stateful in-memory Tx. RunInUserTx snapshots the state and
// restores it when fn returns an error, so a mid-transaction failure leaves the
// wallet and the ledger untouched — the same guarantee the real pgx path gets
// from ROLLBACK. The mutex is held for the whole of fn, which serializes
// concurrent duplicates the way pg_advisory_xact_lock serializes them in pg.
type creditStubTx struct {
	mu      sync.Mutex
	wallets map[string]*mana.UserMana
	ledger  []*mana.LedgerEntry
	budget  map[string][2]int64

	failOn string // an Exec whose SQL contains this returns errCreditBoom
	execs  []string
}

func newCreditStubTx() *creditStubTx {
	return &creditStubTx{
		wallets: map[string]*mana.UserMana{},
		budget:  map[string][2]int64{},
	}
}

func (t *creditStubTx) snapshot() (map[string]*mana.UserMana, []*mana.LedgerEntry, map[string][2]int64) {
	w := make(map[string]*mana.UserMana, len(t.wallets))
	for k, v := range t.wallets {
		clone := *v
		w[k] = &clone
	}
	l := make([]*mana.LedgerEntry, len(t.ledger))
	copy(l, t.ledger)
	b := make(map[string][2]int64, len(t.budget))
	for k, v := range t.budget {
		b[k] = v
	}
	return w, l, b
}

func (t *creditStubTx) restore(w map[string]*mana.UserMana, l []*mana.LedgerEntry, b map[string][2]int64) {
	t.wallets = w
	t.ledger = l
	t.budget = b
}

func (t *creditStubTx) Exec(_ context.Context, sql string, args ...any) error {
	t.execs = append(t.execs, sql)
	if t.failOn != "" && strings.Contains(sql, t.failOn) {
		return errCreditBoom
	}
	switch {
	case strings.Contains(sql, "pg_advisory_xact_lock"):
		return nil
	case strings.Contains(sql, "INSERT INTO demo_grant_budget"):
		key := args[0].(string)
		if _, ok := t.budget[key]; !ok {
			t.budget[key] = [2]int64{}
		}
		return nil
	case strings.Contains(sql, "UPDATE demo_grant_budget"):
		key := args[0].(string)
		row := t.budget[key]
		row[0] += args[1].(int64)
		row[1]++
		t.budget[key] = row
		return nil
	case strings.Contains(sql, "INSERT INTO mana_ledger"):
		t.ledger = append(t.ledger, &mana.LedgerEntry{
			EntryID:           args[0].(string),
			Gcid:              args[1].(string),
			Direction:         mana.Direction(args[2].(string)),
			Units:             args[3].(int64),
			Reason:            mana.Reason(args[4].(string)),
			BalanceAfterUnits: args[9].(int64),
			IdempotencyKey:    args[10].(string),
			RecordedAt:        args[13].(time.Time),
		})
		return nil
	case strings.Contains(sql, "mana_subsidy_allocations"):
		return nil
	}
	return nil
}

func (t *creditStubTx) QueryRow(_ context.Context, sql string, args ...any) Row {
	switch {
	case strings.Contains(sql, "FROM demo_grant_budget"):
		row := t.budget[args[0].(string)]
		return creditStubRow{vals: []any{row[0], row[1]}}
	case strings.Contains(sql, "FROM mana_ledger"):
		key := creditStubKey
		if len(args) > 1 {
			if k, ok := args[1].(string); ok {
				key = k
			}
		}
		for _, e := range t.ledger {
			if e.Gcid == creditStubGcid && e.IdempotencyKey == key {
				var last *time.Time
				if !e.RecordedAt.IsZero() {
					at := e.RecordedAt
					last = &at
				}
				return creditStubRow{vals: []any{
					e.EntryID, e.Gcid, string(e.Direction), e.Units, string(e.Reason),
					nil, nil, nil, nil,
					e.BalanceAfterUnits, e.IdempotencyKey, nil, nil, e.RecordedAt,
					last,
				}}
			}
		}
		return creditStubRow{vals: nil}

	case strings.Contains(sql, "INSERT INTO user_mana"):
		// putWalletTx carries the full 7-arg row and persists it; lockWalletTx
		// carries only the gcid and just takes the row lock.
		if len(args) == 7 {
			m := &mana.UserMana{Gcid: args[0].(string)}
			m.BalanceUnits = args[1].(int64)
			m.LifetimeEarned = args[2].(int64)
			m.LifetimeSpent = args[3].(int64)
			if v, ok := args[4].(*time.Time); ok {
				m.LastCreditedAt = v
			}
			m.Version = args[5].(int64)
			m.UpdatedAt = args[6].(time.Time)
			t.wallets[m.Gcid] = m
			return creditStubRow{vals: walletRowVals(m)}
		}
		m := t.wallets[creditStubGcid]
		if m == nil {
			return creditStubRow{vals: []any{
				creditStubGcid, int64(0), int64(0), int64(0), nil, int64(1), time.Time{}, nil,
			}}
		}
		return creditStubRow{vals: walletRowVals(m)}

	case strings.Contains(sql, "FROM user_mana"):
		m := t.wallets[creditStubGcid]
		if m == nil {
			return creditStubRow{vals: nil}
		}
		return creditStubRow{vals: walletRowVals(m)}
	}
	return creditStubRow{vals: []any{int64(0)}}
}

func (t *creditStubTx) Query(context.Context, string, ...any) (Rows, error) {
	return nil, errors.New("credit stub: Query not implemented")
}

// walletRowVals flattens a wallet into the scan order used by user_mana,
// appending a duplicate of last_credited_at for the trailing *time.Time dest.
func walletRowVals(m *mana.UserMana) []any {
	var last *time.Time
	var lastAt time.Time
	if m.LastCreditedAt != nil {
		at := *m.LastCreditedAt
		last = &at
		lastAt = at
	}
	return []any{m.Gcid, m.BalanceUnits, m.LifetimeEarned, m.LifetimeSpent,
		last, m.Version, m.UpdatedAt, lastAt}
}

// creditStubTxr adapts a creditStubTx to UserTxQuerier, adding the
// snapshot/restore rollback semantics.
type creditStubTxr struct{ tx *creditStubTx }

func (r *creditStubTxr) RunInUserTx(ctx context.Context, userGcid, role string, fn func(context.Context, Tx) error) error {
	r.tx.mu.Lock()
	defer r.tx.mu.Unlock()
	w, l, b := r.tx.snapshot()
	err := fn(ctx, r.tx)
	if err != nil {
		r.tx.restore(w, l, b)
	}
	return err
}

// creditStubRow is a Row over a fixed value list. An empty list is ErrNoRows.
type creditStubRow struct{ vals []any }

func (r creditStubRow) Scan(dest ...any) error {
	if len(r.vals) == 0 {
		return ErrNoRows
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
		case **string:
			if v, ok := r.vals[i].(*string); ok {
				*p = v
			}
		}
	}
	return nil
}

// ledgerRows returns a copy of the stub's ledger.
func ledgerRows(tx *creditStubTx) []*mana.LedgerEntry {
	out := make([]*mana.LedgerEntry, len(tx.ledger))
	copy(out, tx.ledger)
	return out
}

// --- tests -------------------------------------------------------------------

func TestManaStore_CreditWallet_FirstCreditWritesWalletAndLedger(t *testing.T) {
	tx := newCreditStubTx()
	store := NewManaStore(&creditStubTxr{tx: tx})

	res, err := store.CreditWallet(context.Background(), creditStubInput())
	if err != nil {
		t.Fatalf("CreditWallet: %v", err)
	}
	if res.Replayed {
		t.Fatal("first credit must not report a replay")
	}
	if res.Entry == nil {
		t.Fatal("Entry = nil, want the appended ledger row")
	}
	if res.Entry.Reason != mana.ReasonDemoGrant {
		t.Errorf("reason = %q, want %q", res.Entry.Reason, mana.ReasonDemoGrant)
	}
	if res.Entry.Direction != mana.DirectionMint {
		t.Errorf("direction = %q, want %q", res.Entry.Direction, mana.DirectionMint)
	}
	if res.Entry.Units != 1_000_000_000 {
		t.Errorf("units = %d, want 1e9", res.Entry.Units)
	}
	if res.Entry.BalanceAfterUnits != 1_000_000_000 {
		t.Errorf("balance_after = %d, want 1e9", res.Entry.BalanceAfterUnits)
	}
	if res.BalanceAfterUnits != 1_000_000_000 {
		t.Errorf("BalanceAfterUnits = %d, want 1e9", res.BalanceAfterUnits)
	}

	w := tx.wallets[creditStubGcid]
	if w == nil {
		t.Fatal("wallet row was not written")
	}
	if w.BalanceUnits != 1_000_000_000 {
		t.Errorf("balance_units = %d, want 1e9", w.BalanceUnits)
	}
	if w.LifetimeEarned != 1_000_000_000 {
		t.Errorf("lifetime_earned = %d, want 1e9", w.LifetimeEarned)
	}
	if w.LifetimeSpent != 0 {
		t.Errorf("lifetime_spent = %d, want 0", w.LifetimeSpent)
	}
	if w.LastCreditedAt == nil {
		t.Error("last_credited_at not set")
	}
	if w.Version != 2 {
		t.Errorf("version = %d, want 2 (a fresh wallet starts at version 1)", w.Version)
	}

	rows := ledgerRows(tx)
	if len(rows) != 1 {
		t.Fatalf("ledger rows = %d, want 1", len(rows))
	}
	if rows[0].IdempotencyKey != creditStubKey {
		t.Errorf("idempotency_key = %q, want %q", rows[0].IdempotencyKey, creditStubKey)
	}

	// The advisory lock must be taken before anything is written.
	if !strings.Contains(tx.execs[0], "pg_advisory_xact_lock") {
		t.Errorf("first exec = %q, want the advisory lock", tx.execs[0])
	}
}

func TestManaStore_CreditWallet_RerunIsANoOp(t *testing.T) {
	tx := newCreditStubTx()
	store := NewManaStore(&creditStubTxr{tx: tx})
	ctx := context.Background()

	if _, err := store.CreditWallet(ctx, creditStubInput()); err != nil {
		t.Fatalf("first credit: %v", err)
	}
	balanceAfterFirst := tx.wallets[creditStubGcid].BalanceUnits
	execsAfterFirst := len(tx.execs)

	// Re-run with the SAME idempotency key: nothing is re-added.
	res, err := store.CreditWallet(ctx, creditStubInput())
	if err != nil {
		t.Fatalf("re-run: %v", err)
	}
	if !res.Replayed {
		t.Fatal("re-run must report Replayed=true")
	}
	if res.Entry == nil || res.Entry.IdempotencyKey != creditStubKey {
		t.Fatalf("replayed entry = %+v, want the original row", res.Entry)
	}
	if got := tx.wallets[creditStubGcid].BalanceUnits; got != balanceAfterFirst {
		t.Errorf("balance changed on re-run: %d -> %d", balanceAfterFirst, got)
	}
	if len(tx.ledger) != 1 {
		t.Errorf("ledger rows = %d, want 1 (no re-add)", len(tx.ledger))
	}
	if len(tx.execs) != execsAfterFirst+1 {
		t.Errorf("re-run issued %d extra execs, want exactly 1 (the advisory lock) and no writes",
			len(tx.execs)-execsAfterFirst)
	}
	if !strings.Contains(tx.execs[execsAfterFirst], "pg_advisory_xact_lock") {
		t.Errorf("re-run exec = %q, want the advisory lock", tx.execs[execsAfterFirst])
	}
}

func TestManaStore_CreditWallet_ReplayAfterSpendingPreservesSpentBalance(t *testing.T) {
	tx := newCreditStubTx()
	store := NewManaStore(&creditStubTxr{tx: tx})
	ctx := context.Background()

	if _, err := store.CreditWallet(ctx, creditStubInput()); err != nil {
		t.Fatalf("first credit: %v", err)
	}

	// The user spends part of the grant. A re-run must NOT top the balance
	// back up — the grant is additive, never a reset.
	tx.wallets[creditStubGcid].BalanceUnits -= 400_000_000
	tx.wallets[creditStubGcid].LifetimeSpent += 400_000_000
	spentBalance := tx.wallets[creditStubGcid].BalanceUnits

	res, err := store.CreditWallet(ctx, creditStubInput())
	if err != nil {
		t.Fatalf("re-run after spend: %v", err)
	}
	if !res.Replayed {
		t.Fatal("re-run must report Replayed=true")
	}
	if got := tx.wallets[creditStubGcid].BalanceUnits; got != spentBalance {
		t.Errorf("balance = %d, want the spent balance %d (never reset)", got, spentBalance)
	}
	if res.BalanceAfterUnits != spentBalance {
		t.Errorf("BalanceAfterUnits = %d, want %d (current, not the original)", res.BalanceAfterUnits, spentBalance)
	}
	if len(tx.ledger) != 1 {
		t.Errorf("ledger rows = %d, want 1", len(tx.ledger))
	}
}

func TestManaStore_CreditWallet_LedgerFailureLeavesWalletUnchanged(t *testing.T) {
	tx := newCreditStubTx()
	store := NewManaStore(&creditStubTxr{tx: tx})
	ctx := context.Background()

	// Seed a wallet with a balance, then fail the ledger INSERT.
	tx.wallets[creditStubGcid] = &mana.UserMana{
		Gcid: creditStubGcid, BalanceUnits: 500, LifetimeEarned: 500, Version: 1,
	}
	tx.failOn = "INSERT INTO mana_ledger"

	_, err := store.CreditWallet(ctx, creditStubInput())
	if err == nil {
		t.Fatal("CreditWallet err = nil, want the ledger failure")
	}
	if !errors.Is(err, errCreditBoom) {
		t.Fatalf("err = %v, want errCreditBoom", err)
	}

	// The wallet write must have been rolled back with the transaction.
	w := tx.wallets[creditStubGcid]
	if w == nil || w.BalanceUnits != 500 {
		t.Fatalf("balance_units = %+v, want the unchanged 500", w)
	}
	if w.LifetimeEarned != 500 {
		t.Errorf("lifetime_earned = %d, want the unchanged 500", w.LifetimeEarned)
	}
	if w.Version != 1 {
		t.Errorf("version = %d, want the unchanged 1", w.Version)
	}
	if len(tx.ledger) != 0 {
		t.Errorf("ledger rows = %d, want 0", len(tx.ledger))
	}
}

func TestManaStore_CreditWallet_ConcurrentDuplicatesGrantExactlyOnce(t *testing.T) {
	tx := newCreditStubTx()
	store := NewManaStore(&creditStubTxr{tx: tx})
	ctx := context.Background()

	const workers = 16
	var wg sync.WaitGroup
	errs := make([]error, workers)
	results := make([]*mana.CreditWalletResult, workers)
	for i := range workers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = store.CreditWallet(ctx, creditStubInput())
		}(i)
	}
	wg.Wait()

	for i := range workers {
		if errs[i] != nil {
			t.Fatalf("worker %d: %v", i, errs[i])
		}
	}

	var granted, replayed int
	for i := range workers {
		switch {
		case results[i] == nil:
			t.Fatalf("worker %d: nil result", i)
		case results[i].Replayed:
			replayed++
		default:
			granted++
		}
	}
	if granted != 1 {
		t.Errorf("granted = %d, want exactly 1", granted)
	}
	if replayed != workers-1 {
		t.Errorf("replayed = %d, want %d", replayed, workers-1)
	}
	if got := tx.wallets[creditStubGcid].BalanceUnits; got != 1_000_000_000 {
		t.Errorf("balance_units = %d, want 1e9 (credited once)", got)
	}
	if len(tx.ledger) != 1 {
		t.Errorf("ledger rows = %d, want exactly 1", len(tx.ledger))
	}
}

func TestManaStore_CreditWallet_ExistingWalletGetUnchanged(t *testing.T) {
	tx := newCreditStubTx()
	store := NewManaStore(&creditStubTxr{tx: tx})
	ctx := context.Background()

	if _, err := store.CreditWallet(ctx, creditStubInput()); err != nil {
		t.Fatalf("first credit: %v", err)
	}
	before, err := store.GetMana(ctx, creditStubGcid)
	if err != nil {
		t.Fatalf("GetMana before: %v", err)
	}

	// A replay must not disturb the stored wallet row.
	if _, err := store.CreditWallet(ctx, creditStubInput()); err != nil {
		t.Fatalf("replay: %v", err)
	}
	after, err := store.GetMana(ctx, creditStubGcid)
	if err != nil {
		t.Fatalf("GetMana after: %v", err)
	}
	if after.BalanceUnits != before.BalanceUnits {
		t.Errorf("balance %d -> %d, want unchanged", before.BalanceUnits, after.BalanceUnits)
	}
	if after.Version != before.Version {
		t.Errorf("version %d -> %d, want unchanged", before.Version, after.Version)
	}
	if after.LifetimeEarned != before.LifetimeEarned {
		t.Errorf("lifetime_earned %d -> %d, want unchanged", before.LifetimeEarned, after.LifetimeEarned)
	}
}

func TestManaStore_CreditWallet_ReplayWithoutWalletRow(t *testing.T) {
	// A replayed key whose wallet row is gone must still resolve the replay
	// (Wallet nil) rather than erroring or re-crediting.
	tx := newCreditStubTx()
	tx.ledger = append(tx.ledger, &mana.LedgerEntry{
		EntryID: "e-1", Gcid: creditStubGcid, Direction: mana.DirectionMint,
		Units: 1_000_000_000, Reason: mana.ReasonDemoGrant,
		IdempotencyKey: creditStubKey, BalanceAfterUnits: 1_000_000_000,
		RecordedAt: time.Now().UTC(),
	})
	store := NewManaStore(&creditStubTxr{tx: tx})

	res, err := store.CreditWallet(context.Background(), creditStubInput())
	if err != nil {
		t.Fatalf("CreditWallet: %v", err)
	}
	if !res.Replayed {
		t.Fatal("must report Replayed=true")
	}
	if res.Wallet != nil {
		t.Errorf("Wallet = %+v, want nil", res.Wallet)
	}
	if res.BalanceAfterUnits != 0 {
		t.Errorf("BalanceAfterUnits = %d, want 0 (no wallet, no allocations)", res.BalanceAfterUnits)
	}
}

func TestManaStore_CreditWallet_DistinctKeysBothCredit(t *testing.T) {
	tx := newCreditStubTx()
	store := NewManaStore(&creditStubTxr{tx: tx})
	ctx := context.Background()

	if _, err := store.CreditWallet(ctx, creditStubInput()); err != nil {
		t.Fatalf("first: %v", err)
	}
	second := creditStubInput()
	second.IdempotencyKey = "demo-grant:second"
	res, err := store.CreditWallet(ctx, second)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if res.Replayed {
		t.Fatal("a distinct idempotency key must not replay")
	}
	if got := tx.wallets[creditStubGcid].BalanceUnits; got != 2_000_000_000 {
		t.Errorf("balance_units = %d, want 2e9", got)
	}
	if len(tx.ledger) != 2 {
		t.Errorf("ledger rows = %d, want 2", len(tx.ledger))
	}
}

func TestManaStore_CreditWallet_Validation(t *testing.T) {
	store := NewManaStore(&creditStubTxr{tx: newCreditStubTx()})
	base := creditStubInput()

	cases := map[string]func(*mana.CreditWalletInput){
		"empty gcid":        func(in *mana.CreditWalletInput) { in.Gcid = "" },
		"blank gcid":        func(in *mana.CreditWalletInput) { in.Gcid = "   " },
		"zero units":        func(in *mana.CreditWalletInput) { in.Units = 0 },
		"negative units":    func(in *mana.CreditWalletInput) { in.Units = -1 },
		"invalid direction": func(in *mana.CreditWalletInput) { in.Direction = "sideways" },
		"invalid reason":    func(in *mana.CreditWalletInput) { in.Reason = "not_a_reason" },
		"empty key":         func(in *mana.CreditWalletInput) { in.IdempotencyKey = "" },
		"blank key":         func(in *mana.CreditWalletInput) { in.IdempotencyKey = "  " },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			in := base
			mutate(&in)
			if _, err := store.CreditWallet(context.Background(), in); err == nil {
				t.Fatalf("CreditWallet(%s) err = nil, want error", name)
			}
		})
	}
}

// TestManaStore_DemoGrantTotalUnits_FailsClosedWithoutElevatedReader proves the
// cross-GCID total ERRORS when the elevated reader is unavailable. Reporting 0
// would read as "nothing granted yet" to a budget check.
func TestManaStore_DemoGrantTotalUnits_FailsClosedWithoutElevatedReader(t *testing.T) {
	store := NewManaStore(&creditStubTxr{tx: newCreditStubTx()})
	total, err := store.DemoGrantTotalUnits(context.Background())
	if err == nil {
		t.Fatalf("DemoGrantTotalUnits err = nil (total=%d), want an error", total)
	}
	if total != 0 {
		t.Errorf("total = %d, want 0 alongside the error", total)
	}
}

// TestManaStore_CreditWallet_ReplayWithDifferentPayloadConflicts proves a
// reused idempotency key is a CONFLICT — never a successful replay — when the
// incoming operation differs from the recorded one.
func TestManaStore_CreditWallet_ReplayWithDifferentPayloadConflicts(t *testing.T) {
	cases := map[string]func(*mana.CreditWalletInput){
		"different units":     func(in *mana.CreditWalletInput) { in.Units = 999 },
		"different direction": func(in *mana.CreditWalletInput) { in.Direction = mana.DirectionCredit },
		"different reason":    func(in *mana.CreditWalletInput) { in.Reason = mana.ReasonPromo },
		"different source":    func(in *mana.CreditWalletInput) { in.SourceTopupID = "topup-9" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			tx := newCreditStubTx()
			store := NewManaStore(&creditStubTxr{tx: tx})
			ctx := context.Background()

			if _, err := store.CreditWallet(ctx, creditStubInput()); err != nil {
				t.Fatalf("first credit: %v", err)
			}
			in := creditStubInput()
			mutate(&in)
			_, err := store.CreditWallet(ctx, in)
			if !errors.Is(err, mana.ErrIdempotencyConflict) {
				t.Fatalf("err = %v, want ErrIdempotencyConflict", err)
			}
			if got := tx.wallets[creditStubGcid].BalanceUnits; got != 1_000_000_000 {
				t.Errorf("balance = %d, want 1e9 — a conflict must not credit", got)
			}
			if len(tx.ledger) != 1 {
				t.Errorf("ledger rows = %d, want 1", len(tx.ledger))
			}
		})
	}
}

// TestManaStore_CreditWallet_OverflowIsDomainError proves the credit uses
// checked arithmetic: a balance that cannot absorb the credit fails with
// ErrUnitsOverflow instead of wrapping negative.
func TestManaStore_CreditWallet_OverflowIsDomainError(t *testing.T) {
	tx := newCreditStubTx()
	tx.wallets[creditStubGcid] = &mana.UserMana{
		Gcid: creditStubGcid, BalanceUnits: math.MaxInt64, LifetimeEarned: math.MaxInt64, Version: 1,
	}
	store := NewManaStore(&creditStubTxr{tx: tx})

	_, err := store.CreditWallet(context.Background(), creditStubInput())
	if !errors.Is(err, mana.ErrUnitsOverflow) {
		t.Fatalf("err = %v, want ErrUnitsOverflow", err)
	}
	if got := tx.wallets[creditStubGcid].BalanceUnits; got != math.MaxInt64 {
		t.Errorf("balance = %d, want the unchanged MaxInt64", got)
	}
	if len(tx.ledger) != 0 {
		t.Errorf("ledger rows = %d, want 0 — the failed credit must not append", len(tx.ledger))
	}
}

// TestManaStore_CreditWallet_DemoGrantCaps proves the caps are enforced in the
// transaction: the per-GCID cap stops the N+1th grant, the platform budget
// stops a grant that would overshoot it, and a capped rejection writes nothing
// (wallet, ledger and counters all unchanged).
func TestManaStore_CreditWallet_DemoGrantCaps(t *testing.T) {
	ctx := context.Background()

	t.Run("per-gcid cap", func(t *testing.T) {
		tx := newCreditStubTx()
		store := NewManaStore(&creditStubTxr{tx: tx})
		caps := &mana.DemoGrantCaps{MaxPerGcid: 2, BudgetUnits: 10_000_000_000}

		for i, key := range []string{"k-1", "k-2"} {
			in := creditStubInput()
			in.IdempotencyKey = key
			in.DemoGrantCaps = caps
			if _, err := store.CreditWallet(ctx, in); err != nil {
				t.Fatalf("grant %d: %v", i, err)
			}
		}
		before := len(tx.ledger)
		in := creditStubInput()
		in.IdempotencyKey = "k-3"
		in.DemoGrantCaps = caps
		if _, err := store.CreditWallet(ctx, in); !errors.Is(err, mana.ErrDemoGrantLimitReached) {
			t.Fatalf("err = %v, want ErrDemoGrantLimitReached", err)
		}
		if len(tx.ledger) != before {
			t.Errorf("ledger rows = %d, want %d — a capped grant writes nothing", len(tx.ledger), before)
		}
	})

	t.Run("platform budget", func(t *testing.T) {
		tx := newCreditStubTx()
		store := NewManaStore(&creditStubTxr{tx: tx})
		in := creditStubInput()
		in.Units = 600_000_000
		in.DemoGrantCaps = &mana.DemoGrantCaps{MaxPerGcid: 10, BudgetUnits: 1_000_000_000}
		if _, err := store.CreditWallet(ctx, in); err != nil {
			t.Fatalf("first grant: %v", err)
		}
		// 600M + 600M > 1e9.
		in.IdempotencyKey = "k-2"
		if _, err := store.CreditWallet(ctx, in); !errors.Is(err, mana.ErrDemoGrantBudgetExhausted) {
			t.Fatalf("err = %v, want ErrDemoGrantBudgetExhausted", err)
		}
		if len(tx.ledger) != 1 {
			t.Errorf("ledger rows = %d, want 1", len(tx.ledger))
		}
		if got := tx.budget[demoBudgetGlobalKey]; got[0] != 600_000_000 || got[1] != 1 {
			t.Errorf("global counter = %v, want [600000000 1] — a rejected grant must not charge", got)
		}
	})

	t.Run("seed grants do not consume the interactive budget", func(t *testing.T) {
		tx := newCreditStubTx()
		store := NewManaStore(&creditStubTxr{tx: tx})
		// The seed grant carries NO caps (cmd/seed → SeedDemoGrant).
		seed := creditStubInput()
		if _, err := store.CreditWallet(ctx, seed); err != nil {
			t.Fatalf("seed-style credit: %v", err)
		}
		if _, ok := tx.budget[demoBudgetGlobalKey]; ok {
			t.Errorf("seed credit touched the interactive budget: %v", tx.budget)
		}
		// The interactive grant still has its whole allowance.
		in := creditStubInput()
		in.IdempotencyKey = "interactive-1"
		in.DemoGrantCaps = &mana.DemoGrantCaps{MaxPerGcid: 1, BudgetUnits: 1_000_000_000}
		res, err := store.CreditWallet(ctx, in)
		if err != nil {
			t.Fatalf("interactive grant after seed: %v", err)
		}
		if res.Replayed {
			t.Error("interactive grant reported a replay")
		}
	})
}
