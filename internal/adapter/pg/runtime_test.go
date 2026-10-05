// runtime_test.go — unit tests for the pgx-surface helpers in runtime.go.
//
// The pgx interfaces (pgx.Row / pgx.Rows / pgx.Tx) are interfaces in pgx v5,
// so pgxPoolRow.Scan, pgxTx.Exec/QueryRow/Query and pgxRows.Next/Scan/Close/Err
// are tested via fake implementations — no live DB needed. The *pgxpool.Pool
// concrete paths (PgxPoolQuerier.Exec/QueryRow + the RunIn* SET LOCAL / commit
// happy paths) NEED a real pool; only the nil-pool + begin-failure paths are
// unit-testable offline (a `pgxpool.New` against 127.0.0.1:1 fails Begin in ms
// — the test guards against a hang with a wall-clock cap).
package pg

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// -----------------------------------------------------------------------------
// pure validators
// -----------------------------------------------------------------------------

func TestValidateTenantID(t *testing.T) {
	valid := "01970000-0000-7000-8000-0000000000aa"
	for name, id := range map[string]string{
		"empty":   "",
		"g char":  "01970000-0000-7000-8000-0000000000ag",
		"colon":   "01970000:0000-7000-8000-0000000000aa",
		"semicol": "01970000-0000-7000-8000-0000000000aa;",
		"quote":   "01970000-0000-7000-8000-0000000000aa'",
		"space":   " 01970000-0000-7000-8000-0000000000aa",
	} {
		if err := validateTenantID(id); err == nil {
			t.Errorf("%s: validateTenantID(%q) = nil, want rejection", name, id)
		}
	}
	// Acceptable shapes: plain UUID, uppercase hex, bare hex+dash run.
	for name, id := range map[string]string{
		"uuid":      valid,
		"uppercase": strings.ToUpper(valid),
		"bare":      "abc123-def456",
	} {
		if err := validateTenantID(id); err != nil {
			t.Errorf("%s: validateTenantID(%q) = %v, want nil", name, id, err)
		}
	}
}

func TestValidateUserGcid(t *testing.T) {
	for name, id := range map[string]string{
		"empty":    "",
		"g char":   "00000000-0000-7000-8000-00000000199g",
		"upper G":  "00000000-0000-7000-8000-00000000199G",
		"slash":    "00000000-0000-7000-8000-00000000199/",
		"backtick": "00000000-0000-7000-8000-00000000199`",
		"dollar":   "$00000000-0000-7000-8000-000000001999",
	} {
		if err := validateUserGcid(id); err == nil {
			t.Errorf("%s: validateUserGcid(%q) = nil, want rejection", name, id)
		}
	}
	if err := validateUserGcid(manaTestGcid); err != nil {
		t.Errorf("validateUserGcid(%q) = %v, want nil", manaTestGcid, err)
	}
}

func TestValidateRLSRole(t *testing.T) {
	for _, role := range []string{"", "learner", "instructor", "admin", "auditor"} {
		if err := validateRLSRole(role); err != nil {
			t.Errorf("validateRLSRole(%q) = %v, want nil", role, err)
		}
	}
	for _, role := range []string{"owner", "LEARNER", "superadmin", "learner "} {
		if err := validateRLSRole(role); err == nil {
			t.Errorf("validateRLSRole(%q) = nil, want rejection", role)
		}
	}
}

// -----------------------------------------------------------------------------
// constructors + pool getter
// -----------------------------------------------------------------------------

func TestNewPgxPoolQuerier_And_Pool(t *testing.T) {
	q := NewPgxPoolQuerier(nil)
	if q == nil || q.Pool() != nil {
		t.Fatalf("NewPgxPoolQuerier(nil): q=%+v, want non-nil wrapper with nil pool", q)
	}
	// The wrapper satisfies the repo-facing surfaces even with a nil pool —
	// compile-time contracts are the point.
	var _ TxQuerier = q
	var _ PlainTxQuerier = q
	var _ UserTxQuerier = q
	var _ Querier = q
}

// -----------------------------------------------------------------------------
// RunInTenantTx / RunInTx / RunInUserTx — validation + nil-pool paths
// -----------------------------------------------------------------------------

func TestRunInTenantTx_validationRejectedBeforePoolAccess(t *testing.T) {
	q := &PgxPoolQuerier{}
	for name, tenant := range map[string]string{
		"empty":     "",
		"forbidden": "tenant;id",
	} {
		if err := q.RunInTenantTx(context.Background(), tenant, func(context.Context, Tx) error {
			t.Fatalf("%s: fn must not run when validation fails", name)
			return nil
		}); err == nil {
			t.Errorf("%s: tenant %q must be rejected", name, tenant)
		}
	}
}

func TestRunInTenantTx_nilPoolFailsLoud(t *testing.T) {
	err := (&PgxPoolQuerier{}).RunInTenantTx(context.Background(), maTenant, func(context.Context, Tx) error {
		t.Fatal("fn must not run with a nil pool")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "nil pool") {
		t.Fatalf("err = %v, want nil-pool error", err)
	}
}

func TestRunInTenantTx_beginErrorWraps(t *testing.T) {
	pool := mustFailBeginPool(t)
	defer pool.Close()
	q := &PgxPoolQuerier{pool: pool}
	err := q.RunInTenantTx(context.Background(), maTenant, func(context.Context, Tx) error {
		t.Fatal("fn must not run after begin fails")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "begin") || !strings.Contains(err.Error(), "RunInTenantTx") {
		t.Fatalf("err = %v, want wrapped begin error", err)
	}
}

func TestRunInTx_nilPoolFailsLoud(t *testing.T) {
	err := (&PgxPoolQuerier{}).RunInTx(context.Background(), func(context.Context, Tx) error {
		t.Fatal("fn must not run with a nil pool")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "nil pool") {
		t.Fatalf("err = %v, want nil-pool error", err)
	}
}

func TestRunInTx_beginErrorWraps(t *testing.T) {
	pool := mustFailBeginPool(t)
	defer pool.Close()
	err := (&PgxPoolQuerier{pool: pool}).RunInTx(context.Background(), func(context.Context, Tx) error {
		t.Fatal("fn must not run after begin fails")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "begin") || !strings.Contains(err.Error(), "RunInTx") {
		t.Fatalf("err = %v, want wrapped begin error", err)
	}
}

func TestRunInUserTx_validationRejectedBeforePoolAccess(t *testing.T) {
	q := &PgxPoolQuerier{}
	for name, gcid := range map[string]string{
		"empty":     "",
		"forbidden": "gcid;drop",
	} {
		if err := q.RunInUserTx(context.Background(), gcid, "", func(context.Context, Tx) error {
			t.Fatalf("%s: fn must not run when gcid validation fails", name)
			return nil
		}); err == nil {
			t.Errorf("%s: gcid %q must be rejected", name, gcid)
		}
	}
	// role is validated AFTER gcid — a valid gcid with a bad role must fail
	// before any pool access too.
	if err := q.RunInUserTx(context.Background(), manaTestGcid, "owner", func(context.Context, Tx) error {
		t.Fatal("fn must not run when role validation fails")
		return nil
	}); err == nil || !strings.Contains(err.Error(), "not in {learner,instructor,admin,auditor}") {
		t.Fatalf("err = %v, want role rejection", err)
	}
}

func TestRunInUserTx_nilPoolFailsLoud(t *testing.T) {
	err := (&PgxPoolQuerier{}).RunInUserTx(context.Background(), manaTestGcid, "", func(context.Context, Tx) error {
		t.Fatal("fn must not run with a nil pool")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "nil pool") {
		t.Fatalf("err = %v, want nil-pool error", err)
	}
	// Non-empty valid role reaches the same nil-pool gate (no SET LOCAL path
	// exists without a pool).
	err = (&PgxPoolQuerier{}).RunInUserTx(context.Background(), manaTestGcid, "admin", func(context.Context, Tx) error {
		t.Fatal("fn must not run with a nil pool")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "nil pool") {
		t.Fatalf("err = %v, want nil-pool error (role set)", err)
	}
}

func TestRunInUserTx_beginErrorWraps(t *testing.T) {
	pool := mustFailBeginPool(t)
	defer pool.Close()
	err := (&PgxPoolQuerier{pool: pool}).RunInUserTx(context.Background(), manaTestGcid, "learner", func(context.Context, Tx) error {
		t.Fatal("fn must not run after begin fails")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "begin") || !strings.Contains(err.Error(), "RunInUserTx") {
		t.Fatalf("err = %v, want wrapped begin error", err)
	}
}

// mustFailBeginPool mints a pool whose Begin fails fast (127.0.0.1:1 has no
// listener → connection refused in ms). Guards the wall clock so a firewall
// that silently drops SYN can never deadlock the suite.
func mustFailBeginPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	start := time.Now()
	pool, err := pgxpool.New(context.Background(), "postgres://user:pass@127.0.0.1:1/cx")
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	if _, err := pool.Begin(context.Background()); err == nil {
		pool.Close()
		t.Fatalf("unexpectedly connected to 127.0.0.1:1 — is a DB running locally?")
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("begin failure took %v — the offline begin-path test is unreliable; would hang CI", elapsed)
	}
	return pool
}

// -----------------------------------------------------------------------------
// pgxPoolRow.Scan — maps pgx.ErrNoRows → ErrNoRows (pgx.Row is an interface)
// -----------------------------------------------------------------------------

type fakePGXRow struct{ scanFn func(dest ...any) error }

func (r fakePGXRow) Scan(dest ...any) error { return r.scanFn(dest...) }

func TestPgxPoolRow_Scan_MapsNoRowsAndPassesErrors(t *testing.T) {
	// pgx.ErrNoRows → local ErrNoRows sentinel.
	row := &pgxPoolRow{r: fakePGXRow{scanFn: func(...any) error { return pgx.ErrNoRows }}}
	if err := row.Scan(); !errors.Is(err, ErrNoRows) {
		t.Fatalf("ErrNoRows mapping: err = %v, want ErrNoRows", err)
	}
	// Arbitrary error passes through unchanged.
	boom := errors.New("disk full")
	row = &pgxPoolRow{r: fakePGXRow{scanFn: func(...any) error { return boom }}}
	if err := row.Scan(); !errors.Is(err, boom) {
		t.Fatalf("error passthrough: err = %v, want boom", err)
	}
	// Happy path: dest filled, nil error.
	row = &pgxPoolRow{r: fakePGXRow{scanFn: func(dest ...any) error {
		*dest[0].(*string) = "rows-are-fine"
		return nil
	}}}
	var got string
	if err := row.Scan(&got); err != nil || got != "rows-are-fine" {
		t.Fatalf("happy scan: got=%q err=%v", got, err)
	}
}

// -----------------------------------------------------------------------------
// pgxTx — adapts pgx.Tx (an interface) onto the local Tx surface
// -----------------------------------------------------------------------------

type fakePGXTx struct {
	execCalls int
	execErr   error
	queryErr  error
	row       pgx.Row
	rows      pgx.Rows
}

func (f *fakePGXTx) Begin(context.Context) (pgx.Tx, error) { return f, nil }
func (f *fakePGXTx) Commit(context.Context) error          { return nil }
func (f *fakePGXTx) Rollback(context.Context) error        { return nil }
func (f *fakePGXTx) CopyFrom(context.Context, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error) {
	return 0, nil
}
func (f *fakePGXTx) SendBatch(context.Context, *pgx.Batch) pgx.BatchResults { return nil }
func (f *fakePGXTx) LargeObjects() pgx.LargeObjects                         { return pgx.LargeObjects{} }
func (f *fakePGXTx) Prepare(context.Context, string, string) (*pgconn.StatementDescription, error) {
	return nil, nil
}
func (f *fakePGXTx) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	f.execCalls++
	if f.execErr != nil {
		return pgconn.CommandTag{}, f.execErr
	}
	return pgconn.CommandTag{}, nil
}
func (f *fakePGXTx) Query(context.Context, string, ...any) (pgx.Rows, error) {
	if f.queryErr != nil {
		return nil, f.queryErr
	}
	return f.rows, nil
}
func (f *fakePGXTx) QueryRow(context.Context, string, ...any) pgx.Row {
	if f.row != nil {
		return f.row
	}
	return fakePGXRow{scanFn: func(...any) error { return ErrNoRows }}
}
func (f *fakePGXTx) Conn() *pgx.Conn { return nil }

func TestPgxTx_Exec(t *testing.T) {
	inner := &fakePGXTx{}
	tx := &pgxTx{tx: inner}
	if err := tx.Exec(context.Background(), "UPDATE users SET x = 1"); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if inner.execCalls != 1 {
		t.Fatalf("inner Exec calls = %d, want 1", inner.execCalls)
	}
	boom := errors.New("exec boom")
	inner = &fakePGXTx{execErr: boom}
	tx = &pgxTx{tx: inner}
	if err := tx.Exec(context.Background(), "UPDATE users SET x = 1"); !errors.Is(err, boom) || !strings.Contains(err.Error(), "pg.Tx.Exec") {
		t.Fatalf("Exec error: err = %v, want wrapped boom", err)
	}
}

func TestPgxTx_QueryRow(t *testing.T) {
	// The returned Row is a pgxPoolRow whose Scan maps pgx.ErrNoRows.
	inner := &fakePGXTx{row: fakePGXRow{scanFn: func(...any) error { return pgx.ErrNoRows }}}
	row := (&pgxTx{tx: inner}).QueryRow(context.Background(), "SELECT 1")
	if err := row.Scan(); !errors.Is(err, ErrNoRows) {
		t.Fatalf("QueryRow scan: err = %v, want ErrNoRows", err)
	}
}

func TestPgxTx_Query(t *testing.T) {
	// Error → wrapped; success → pgxRows-backed Rows.
	inner := &fakePGXTx{queryErr: errors.New("query boom")}
	if _, err := (&pgxTx{tx: inner}).Query(context.Background(), "SELECT 1"); err == nil || !strings.Contains(err.Error(), "pg.Tx.Query") {
		t.Fatalf("Query error: err = %v, want wrapped", err)
	}

	fakeRows := &fakePGXRows{rows: []func(dest ...any) error{
		func(dest ...any) error { *dest[0].(*string) = "ok"; return nil },
	}}
	inner = &fakePGXTx{rows: fakeRows}
	rs, err := (&pgxTx{tx: inner}).Query(context.Background(), "SELECT 1")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if !rs.Next() {
		t.Fatal("Next = false, want true")
	}
	var got string
	if err := rs.Scan(&got); err != nil || got != "ok" {
		t.Fatalf("Scan: got=%q err=%v", got, err)
	}
	if rs.Next() {
		t.Fatal("Next = true after last row, want false")
	}
	if err := rs.Err(); err != nil {
		t.Fatalf("Err: %v", err)
	}
	if err := rs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// -----------------------------------------------------------------------------
// pgxRows — adapts pgx.Rows (an interface) onto the local Rows surface
// -----------------------------------------------------------------------------

type fakePGXRows struct {
	rows   []func(dest ...any) error
	idx    int
	err    error
	closed bool
}

func (f *fakePGXRows) Close()                                       { f.closed = true }
func (f *fakePGXRows) Err() error                                   { return f.err }
func (f *fakePGXRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (f *fakePGXRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (f *fakePGXRows) Next() bool                                   { return f.idx < len(f.rows) }
func (f *fakePGXRows) Scan(dest ...any) error {
	if f.idx >= len(f.rows) {
		return errors.New("fakePGXRows: scan past end")
	}
	fn := f.rows[f.idx]
	f.idx++
	return fn(dest...)
}
func (f *fakePGXRows) Values() ([]any, error) { return nil, nil }
func (f *fakePGXRows) RawValues() [][]byte    { return nil }
func (f *fakePGXRows) Conn() *pgx.Conn        { return nil }

func TestPgxRows_Next_Scan_Close_Err(t *testing.T) {
	fake := &fakePGXRows{rows: []func(dest ...any) error{
		func(dest ...any) error {
			*dest[0].(*int) = 1
			return nil
		},
	}}
	r := &pgxRows{r: fake}
	if !r.Next() {
		t.Fatal("Next = false, want true")
	}
	var n int
	if err := r.Scan(&n); err != nil || n != 1 {
		t.Fatalf("Scan: n=%d err=%v", n, err)
	}
	if r.Next() {
		t.Fatal("Next = true after the single row, want false")
	}
	if err := r.Err(); err != nil {
		t.Fatalf("Err: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !fake.closed {
		t.Fatal("inner pgx.Rows.Close must be forwarded")
	}

	// Scan error propagates untouched.
	fake = &fakePGXRows{rows: []func(dest ...any) error{
		func(...any) error { return errors.New("scan boom") },
	}}
	r = &pgxRows{r: fake}
	if !r.Next() {
		t.Fatal("Next = false, want true")
	}
	if err := r.Scan(); err == nil {
		t.Fatal("Scan error must propagate")
	}

	// Err() reflects the inner rows error.
	fake = &fakePGXRows{err: errors.New("iter boom")}
	if err := (&pgxRows{r: fake}).Err(); err == nil {
		t.Fatal("Err must propagate the inner error")
	}
}
