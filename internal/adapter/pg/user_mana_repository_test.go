package pg

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	mana "github.com/apollo-chora/chora-identity/internal/domain/user_mana"
)

// --- minimal stubs (uniquely named to avoid collision with sibling tests) ----

type manaStubRow struct{ scan func(dest ...any) error }

func (r manaStubRow) Scan(dest ...any) error { return r.scan(dest...) }

type manaStubTx struct {
	execSQL   []string
	execArgs  [][]any
	execErr   error
	querySQL  []string
	queryArgs [][]any
	queryRow  func(sql string, args ...any) Row
	query     func(sql string, args ...any) (Rows, error)
}

func (t *manaStubTx) Exec(_ context.Context, sql string, args ...any) error {
	t.execSQL = append(t.execSQL, sql)
	t.execArgs = append(t.execArgs, args)
	return t.execErr
}
func (t *manaStubTx) QueryRow(_ context.Context, sql string, args ...any) Row {
	return t.queryRow(sql, args...)
}
func (t *manaStubTx) Query(_ context.Context, sql string, args ...any) (Rows, error) {
	t.querySQL = append(t.querySQL, sql)
	t.queryArgs = append(t.queryArgs, args)
	return t.query(sql, args...)
}

type manaStubUserTxr struct {
	gotGcid string
	gotRole string
	tx      *manaStubTx
}

func (s *manaStubUserTxr) RunInUserTx(ctx context.Context, gcid, role string, fn func(context.Context, Tx) error) error {
	s.gotGcid = gcid
	s.gotRole = role
	return fn(ctx, s.tx)
}

const manaTestGcid = "00000000-0000-7000-8000-000000001999"

// --- tests -------------------------------------------------------------------

func TestManaStore_GetMana_Absent_ReturnsNilNil(t *testing.T) {
	tx := &manaStubTx{queryRow: func(string, ...any) Row {
		return manaStubRow{scan: func(...any) error { return ErrNoRows }}
	}}
	txr := &manaStubUserTxr{tx: tx}
	got, err := NewManaStore(txr).GetMana(context.Background(), manaTestGcid)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if got != nil {
		t.Fatalf("wallet = %+v, want nil (absent)", got)
	}
	if txr.gotGcid != manaTestGcid {
		t.Fatalf("RunInUserTx gcid = %q, want %q", txr.gotGcid, manaTestGcid)
	}
}

func TestManaStore_SaveMana_OCCConflict(t *testing.T) {
	// RETURNING yields no row → OCC guard failed.
	tx := &manaStubTx{queryRow: func(string, ...any) Row {
		return manaStubRow{scan: func(...any) error { return ErrNoRows }}
	}}
	err := NewManaStore(&manaStubUserTxr{tx: tx}).SaveMana(context.Background(),
		&mana.UserMana{Gcid: manaTestGcid, BalanceUnits: 100, Version: 3})
	if !errors.Is(err, ErrManaOCCConflict) {
		t.Fatalf("err = %v, want ErrManaOCCConflict", err)
	}
}

func TestManaStore_SaveMana_OK(t *testing.T) {
	tx := &manaStubTx{queryRow: func(string, ...any) Row {
		return manaStubRow{scan: func(dest ...any) error {
			// RETURNING gcid → set dest[0].
			if p, ok := dest[0].(*string); ok {
				*p = manaTestGcid
			}
			return nil
		}}
	}}
	if err := NewManaStore(&manaStubUserTxr{tx: tx}).SaveMana(context.Background(),
		&mana.UserMana{Gcid: manaTestGcid, BalanceUnits: 5000, LifetimeEarned: 5000, Version: 2}); err != nil {
		t.Fatalf("SaveMana: %v", err)
	}
}

func TestManaStore_AppendLedger_EmptyUUIDsBecomeNil(t *testing.T) {
	tx := &manaStubTx{}
	e := &mana.LedgerEntry{
		EntryID: "e1", Gcid: manaTestGcid, Direction: mana.DirectionCredit, Units: 5000,
		Reason: mana.ReasonTopup, SourceTopupID: "umt-1", // set
		// SourceSubscriptionID / SourceAllocationID / ReversesEntryID left "" → must map to nil
		BalanceAfterUnits: 5000, IdempotencyKey: "idem-1", RecordedAt: time.Now().UTC(),
	}
	if err := NewManaStore(&manaStubUserTxr{tx: tx}).AppendLedger(context.Background(), e); err != nil {
		t.Fatalf("AppendLedger: %v", err)
	}
	if len(tx.execArgs) != 1 {
		t.Fatalf("exec calls = %d, want 1", len(tx.execArgs))
	}
	args := tx.execArgs[0]
	// Arg order matches the INSERT: $1 entry_id, $2 gcid, $3 direction, $4 units,
	// $5 reason, $6 sub_id, $7 action_id, $8 alloc_id, $9 topup_id, ...
	if args[5] != nil { // source_subscription_id (empty → nil)
		t.Fatalf("source_subscription_id = %v, want nil", args[5])
	}
	if args[7] != nil { // source_allocation_id (empty → nil)
		t.Fatalf("source_allocation_id = %v, want nil", args[7])
	}
	if args[8] != "umt-1" { // source_topup_id (set → passthrough)
		t.Fatalf("source_topup_id = %v, want umt-1", args[8])
	}
}

func TestManaStore_FindLedgerByIdempotencyKey_EmptyKeyShortCircuits(t *testing.T) {
	// Empty key must NOT open a tx (returns nil,nil immediately).
	txr := &manaStubUserTxr{tx: &manaStubTx{}}
	got, err := NewManaStore(txr).FindLedgerByIdempotencyKey(context.Background(), manaTestGcid, "")
	if err != nil || got != nil {
		t.Fatalf("got=%v err=%v, want nil,nil", got, err)
	}
	if txr.gotGcid != "" {
		t.Fatalf("RunInUserTx should not have been called for empty key")
	}
}
func TestManaStore_ImplementsStore(t *testing.T) {
	var _ mana.Store = NewManaStore(&manaStubUserTxr{tx: &manaStubTx{}})
}

// --- ledger/allocation suite (ListLedger / ListAllocations / SaveAllocation /
// UpdateAllocationRemaining / scanLedgerRows / FindLedgerByIdempotencyKey) ----

// manaStubRows iterates a canned set of Scan funcs (one per row). Satisfies Rows.
type manaStubRows struct {
	scanFns []func(dest ...any) error
	idx     int
	err     error
}

func (r *manaStubRows) Next() bool { return r.idx < len(r.scanFns) }
func (r *manaStubRows) Scan(dest ...any) error {
	if r.idx >= len(r.scanFns) {
		return errors.New("manaStubRows: scan past end")
	}
	fn := r.scanFns[r.idx]
	r.idx++
	return fn(dest...)
}
func (r *manaStubRows) Close() error { return nil }
func (r *manaStubRows) Err() error   { return r.err }

// ledgerRowScan fills the 14-dest mana_ledger SELECT in column order. nilable
// source ids are *string dests; pass nil to exercise the NULL→"" mapping.
func ledgerRowScan(t *testing.T, eID string, dir, reason string, subID, actionID, allocID, topupID, requestID *string) func(dest ...any) error {
	t.Helper()
	now := time.Now().UTC()
	return func(dest ...any) error {
		*dest[0].(*string) = eID
		*dest[1].(*string) = manaTestGcid
		*dest[2].(*string) = dir
		*dest[3].(*int64) = 100
		*dest[4].(*string) = reason
		*dest[5].(**string) = subID
		*dest[6].(**string) = actionID
		*dest[7].(**string) = allocID
		*dest[8].(**string) = topupID
		*dest[9].(*int64) = 500
		*dest[10].(*string) = "idem-1"
		*dest[11].(**string) = requestID
		*dest[12].(**string) = nil
		*dest[13].(*time.Time) = now
		return nil
	}
}

func TestManaStore_FindLedgerByIdempotencyKey_HappyPath(t *testing.T) {
	rows := &manaStubRows{scanFns: []func(dest ...any) error{
		ledgerRowScan(t, "e-1", "credit", "topup", strp("sub-1"), nil, nil, nil, strp("req-1")),
		ledgerRowScan(t, "e-2", "debit", "familiar_action", nil, nil, strp("alloc-2"), nil, nil),
	}}
	tx := &manaStubTx{query: func(string, ...any) (Rows, error) { return rows, nil }}
	txr := &manaStubUserTxr{tx: tx}
	got, err := NewManaStore(txr).FindLedgerByIdempotencyKey(context.Background(), manaTestGcid, "idem-1")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("entries = %d, want 2", len(got))
	}
	e0 := got[0]
	if e0.Direction != mana.DirectionCredit || e0.Reason != mana.ReasonTopup ||
		e0.SourceSubscriptionID != "sub-1" || e0.SourceAllocationID != "" || e0.SourceTopupID != "" ||
		e0.RequestID != "req-1" || e0.ReversesEntryID != "" {
		t.Fatalf("entry 0 mapping wrong: %+v", e0)
	}
	e1 := got[1]
	if e1.SourceSubscriptionID != "" || e1.SourceAllocationID != "alloc-2" || e1.SourceActionID != "" {
		t.Fatalf("entry 1 nullables wrong: %+v", e1)
	}
	if txr.gotGcid != manaTestGcid {
		t.Fatalf("RunInUserTx gcid = %q, want %q", txr.gotGcid, manaTestGcid)
	}
}

func TestManaStore_FindLedgerByIdempotencyKey_QueryErrorWraps(t *testing.T) {
	boom := errors.New("query boom")
	tx := &manaStubTx{query: func(string, ...any) (Rows, error) { return nil, boom }}
	_, err := NewManaStore(&manaStubUserTxr{tx: tx}).FindLedgerByIdempotencyKey(context.Background(), manaTestGcid, "idem-1")
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom", err)
	}
}

func TestManaStore_FindLedgerByIdempotencyKey_RowsErrPropagates(t *testing.T) {
	boom := errors.New("iter boom")
	rows := &manaStubRows{scanFns: []func(dest ...any) error{ledgerRowScan(t, "e-1", "credit", "topup", nil, nil, nil, nil, nil)}, err: boom}
	tx := &manaStubTx{query: func(string, ...any) (Rows, error) { return rows, nil }}
	_, err := NewManaStore(&manaStubUserTxr{tx: tx}).FindLedgerByIdempotencyKey(context.Background(), manaTestGcid, "idem-1")
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want rows.Err boom", err)
	}
}

func TestManaStore_ListLedger_EmptyGcid_ErrInvalidFilter(t *testing.T) {
	txr := &manaStubUserTxr{tx: &manaStubTx{}}
	_, err := NewManaStore(txr).ListLedger(context.Background(), mana.LedgerFilter{})
	if !errors.Is(err, mana.ErrInvalidFilter) {
		t.Fatalf("err = %v, want ErrInvalidFilter", err)
	}
	if txr.gotGcid != "" {
		t.Fatal("RunInUserTx must not open for an empty gcid")
	}
}

func TestManaStore_ListLedger_MalformedCursor_ErrInvalidFilter(t *testing.T) {
	txr := &manaStubUserTxr{tx: &manaStubTx{}}
	_, err := NewManaStore(txr).ListLedger(context.Background(), mana.LedgerFilter{
		Gcid: manaTestGcid, Cursor: "!!!not-base64!!!",
	})
	if !errors.Is(err, mana.ErrInvalidFilter) {
		t.Fatalf("err = %v, want ErrInvalidFilter (malformed cursor)", err)
	}
	if txr.gotGcid != "" {
		t.Fatal("malformed cursor must fail before opening a tx (CHO-1883)")
	}
}

func TestManaStore_ListLedger_AllFiltersBuildSQL(t *testing.T) {
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	dir := mana.DirectionCredit
	reason := mana.ReasonTopup
	cursor := mana.EncodeLedgerCursor(&mana.LedgerEntry{EntryID: "cur-1", RecordedAt: time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)})
	rows := &manaStubRows{}
	tx := &manaStubTx{query: func(string, ...any) (Rows, error) { return rows, nil }}
	store := NewManaStore(&manaStubUserTxr{tx: tx})

	got, err := store.ListLedger(context.Background(), mana.LedgerFilter{
		Gcid: manaTestGcid, From: &from, To: &to, Direction: &dir, Reason: &reason,
		Cursor: cursor, PageSize: 10,
	})
	if err != nil {
		t.Fatalf("ListLedger: %v", err)
	}
	// Empty rowset → nil slice (callers render "no entries"); zero rows must
	// not error.
	if got != nil || len(got) != 0 {
		t.Fatalf("got = %#v, want nil empty result", got)
	}
	if len(tx.querySQL) != 1 {
		t.Fatalf("queries = %d, want 1", len(tx.querySQL))
	}
	sql := tx.querySQL[0]
	for _, frag := range []string{"recorded_at >= $2", "recorded_at < $3", "direction = $4::mana_direction",
		"reason = $5::mana_reason", "(recorded_at, entry_id) < ($6::timestamptz, $7::uuid)", "LIMIT $8", "ORDER BY recorded_at DESC, entry_id DESC"} {
		if !strings.Contains(sql, frag) {
			t.Errorf("SQL missing %q:\n%s", frag, sql)
		}
	}
}

func TestManaStore_ListLedger_QueryErrorWraps(t *testing.T) {
	boom := errors.New("list boom")
	tx := &manaStubTx{query: func(string, ...any) (Rows, error) { return nil, boom }}
	_, err := NewManaStore(&manaStubUserTxr{tx: tx}).ListLedger(context.Background(), mana.LedgerFilter{Gcid: manaTestGcid})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom", err)
	}
}

func TestManaStore_ListLedger_ScanErrorWraps(t *testing.T) {
	boom := errors.New("scan boom")
	rows := &manaStubRows{scanFns: []func(dest ...any) error{
		func(...any) error { return boom },
	}}
	tx := &manaStubTx{query: func(string, ...any) (Rows, error) { return rows, nil }}
	_, err := NewManaStore(&manaStubUserTxr{tx: tx}).ListLedger(context.Background(), mana.LedgerFilter{Gcid: manaTestGcid})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom", err)
	}
}

func TestManaStore_ListLedger_RowsErrPropagates(t *testing.T) {
	boom := errors.New("iter boom")
	rows := &manaStubRows{scanFns: []func(dest ...any) error{ledgerRowScan(t, "e-1", "credit", "topup", nil, nil, nil, nil, nil)}, err: boom}
	tx := &manaStubTx{query: func(string, ...any) (Rows, error) { return rows, nil }}
	_, err := NewManaStore(&manaStubUserTxr{tx: tx}).ListLedger(context.Background(), mana.LedgerFilter{Gcid: manaTestGcid})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want rows.Err boom", err)
	}
}

func TestManaStore_ListAllocations_HappyPath(t *testing.T) {
	now := time.Now().UTC()
	rows := &manaStubRows{scanFns: []func(dest ...any) error{
		func(dest ...any) error { // expires_at NULL
			*dest[0].(*string) = "alloc-1"
			*dest[1].(*string) = "tenant-a"
			*dest[2].(*int64) = 500
			*dest[3].(**time.Time) = nil
			*dest[4].(*time.Time) = now
			return nil
		},
		func(dest ...any) error { // expires_at set
			*dest[0].(*string) = "alloc-2"
			*dest[1].(*string) = "tenant-b"
			*dest[2].(*int64) = 300
			*dest[3].(**time.Time) = &now
			*dest[4].(*time.Time) = now
			return nil
		},
	}}
	store := NewManaStore(&manaStubUserTxr{tx: &manaStubTx{query: func(string, ...any) (Rows, error) { return rows, nil }}})
	out, err := store.ListAllocations(context.Background(), manaTestGcid)
	if err != nil {
		t.Fatalf("ListAllocations: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("out = %d, want 2", len(out))
	}
	if out[0].ExpiresAt != nil || out[1].ExpiresAt == nil {
		t.Fatalf("expiry mapping wrong: %+v / %+v", out[0], out[1])
	}
	if out[0].RemainingUnits != 500 || out[1].TenantID != "tenant-b" {
		t.Fatalf("allocation mapping wrong: %+v / %+v", out[0], out[1])
	}
}

func TestManaStore_ListAllocations_QueryErrorWraps(t *testing.T) {
	boom := errors.New("alloc boom")
	tx := &manaStubTx{query: func(string, ...any) (Rows, error) { return nil, boom }}
	_, err := NewManaStore(&manaStubUserTxr{tx: tx}).ListAllocations(context.Background(), manaTestGcid)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom", err)
	}
}

func TestManaStore_ListAllocations_ScanErrorWraps(t *testing.T) {
	boom := errors.New("alloc scan boom")
	rows := &manaStubRows{scanFns: []func(dest ...any) error{func(...any) error { return boom }}}
	tx := &manaStubTx{query: func(string, ...any) (Rows, error) { return rows, nil }}
	_, err := NewManaStore(&manaStubUserTxr{tx: tx}).ListAllocations(context.Background(), manaTestGcid)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom", err)
	}
}

func TestManaStore_ListAllocations_RowsErrPropagates(t *testing.T) {
	boom := errors.New("alloc iter boom")
	now := time.Now().UTC()
	rows := &manaStubRows{scanFns: []func(dest ...any) error{
		func(dest ...any) error {
			*dest[0].(*string) = "a1"
			*dest[1].(*string) = "t1"
			*dest[2].(*int64) = 1
			*dest[3].(**time.Time) = nil
			*dest[4].(*time.Time) = now
			return nil
		},
	}, err: boom}
	tx := &manaStubTx{query: func(string, ...any) (Rows, error) { return rows, nil }}
	_, err := NewManaStore(&manaStubUserTxr{tx: tx}).ListAllocations(context.Background(), manaTestGcid)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want rows.Err boom", err)
	}
}

func TestManaStore_SaveAllocation(t *testing.T) {
	now := time.Now().UTC()
	a := &mana.Allocation{AllocationID: "alloc-9", TenantID: "tenant-9", RemainingUnits: 42, ExpiresAt: &now, AllocatedAt: now}
	tx := &manaStubTx{}
	txr := &manaStubUserTxr{tx: tx}
	if err := NewManaStore(txr).SaveAllocation(context.Background(), manaTestGcid, a); err != nil {
		t.Fatalf("SaveAllocation: %v", err)
	}
	if len(tx.execArgs) != 1 || tx.execArgs[0][0] != "alloc-9" || tx.execArgs[0][1] != manaTestGcid {
		t.Fatalf("args = %v", tx.execArgs)
	}
	// nil aggregate fails loud before opening a tx.
	if err := NewManaStore(&manaStubUserTxr{tx: &manaStubTx{}}).SaveAllocation(context.Background(), manaTestGcid, nil); err == nil {
		t.Fatal("SaveAllocation(nil) err = nil, want error")
	}
	// Exec error propagates.
	boom := errors.New("alloc write boom")
	tx2 := &manaStubTx{execErr: boom}
	if err := NewManaStore(&manaStubUserTxr{tx: tx2}).SaveAllocation(context.Background(), manaTestGcid, a); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom", err)
	}
}

func TestManaStore_UpdateAllocationRemaining(t *testing.T) {
	tx := &manaStubTx{}
	txr := &manaStubUserTxr{tx: tx}
	if err := NewManaStore(txr).UpdateAllocationRemaining(context.Background(), manaTestGcid, "alloc-1", 77); err != nil {
		t.Fatalf("UpdateAllocationRemaining: %v", err)
	}
	if len(tx.execArgs) != 1 || tx.execArgs[0][0] != manaTestGcid || tx.execArgs[0][1] != "alloc-1" || tx.execArgs[0][2] != int64(77) {
		t.Fatalf("args = %v", tx.execArgs)
	}
	boom := errors.New("update boom")
	tx2 := &manaStubTx{execErr: boom}
	if err := NewManaStore(&manaStubUserTxr{tx: tx2}).UpdateAllocationRemaining(context.Background(), manaTestGcid, "alloc-1", 1); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom", err)
	}
}

func TestManaStore_GetMana_ScanErrorWraps(t *testing.T) {
	boom := errors.New("scan boom")
	tx := &manaStubTx{queryRow: func(string, ...any) Row {
		return manaStubRow{scan: func(...any) error { return boom }}
	}}
	_, err := NewManaStore(&manaStubUserTxr{tx: tx}).GetMana(context.Background(), manaTestGcid)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom", err)
	}
}

func TestManaStore_SaveMana_NilWalletAndScanError(t *testing.T) {
	if err := NewManaStore(&manaStubUserTxr{tx: &manaStubTx{}}).SaveMana(context.Background(), nil); err == nil {
		t.Fatal("SaveMana(nil) err = nil, want error")
	}
	boom := errors.New("save scan boom")
	tx := &manaStubTx{queryRow: func(string, ...any) Row {
		return manaStubRow{scan: func(...any) error { return boom }}
	}}
	err := NewManaStore(&manaStubUserTxr{tx: tx}).SaveMana(context.Background(),
		&mana.UserMana{Gcid: manaTestGcid, BalanceUnits: 1, Version: 1})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom", err)
	}
}

func TestManaStore_AppendLedger_NilEntryAndExecError(t *testing.T) {
	if err := NewManaStore(&manaStubUserTxr{tx: &manaStubTx{}}).AppendLedger(context.Background(), nil); err == nil {
		t.Fatal("AppendLedger(nil) err = nil, want error")
	}
	boom := errors.New("ledger write boom")
	tx := &manaStubTx{execErr: boom}
	err := NewManaStore(&manaStubUserTxr{tx: tx}).AppendLedger(context.Background(),
		&mana.LedgerEntry{EntryID: "e1", Gcid: manaTestGcid, Direction: mana.DirectionCredit, Units: 1,
			Reason: mana.ReasonTopup, RecordedAt: time.Now().UTC()})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom", err)
	}
}

func TestNullText(t *testing.T) {
	if nullText("") != nil {
		t.Errorf("nullText(\"\") = %v, want nil", nullText(""))
	}
	if v := nullText("kept"); v != "kept" {
		t.Errorf("nullText(\"kept\") = %v, want kept", v)
	}
}

func strp(s string) *string { return &s }
