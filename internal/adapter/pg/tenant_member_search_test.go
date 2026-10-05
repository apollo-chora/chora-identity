// tenant_member_search_test.go — unit tests for the pgx-backed
// TenantMemberSearchRepository. The tests stub the TxQuerier surface so the
// SQL shape + RLS-tx wrapping invariants are asserted WITHOUT a live DB.
// Live RLS isolation is verified separately in integration_test.go.
package pg

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// -----------------------------------------------------------------------------
// stubTxQuerier — records RunInTenantTx invocations + delegates fn to a fake
// Tx that returns the prepared row set.
// -----------------------------------------------------------------------------

type stubTxQuerier struct {
	gotTenantID string
	callCount   int
	tx          *stubTx
	errOnBegin  error
}

func (s *stubTxQuerier) RunInTenantTx(ctx context.Context, tenantID string, fn func(context.Context, Tx) error) error {
	s.gotTenantID = tenantID
	s.callCount++
	if s.errOnBegin != nil {
		return s.errOnBegin
	}
	return fn(ctx, s.tx)
}

type stubTx struct {
	queries    []capturedQuery
	rows       Rows
	execErr    error
	execErrAt  int // 1-based Exec call to fail at; <=0 = first Exec
	execCalls  int
	queryErr   error
	queryRowFn func(sql string, args ...any) Row
}

type capturedQuery struct {
	SQL  string
	Args []any
}

func (s *stubTx) Exec(ctx context.Context, sql string, args ...any) error {
	s.queries = append(s.queries, capturedQuery{SQL: sql, Args: args})
	s.execCalls++
	at := s.execErrAt
	if at <= 0 {
		at = 1
	}
	if s.execErr != nil && s.execCalls == at {
		return s.execErr
	}
	return nil
}

func (s *stubTx) Query(ctx context.Context, sql string, args ...any) (Rows, error) {
	s.queries = append(s.queries, capturedQuery{SQL: sql, Args: args})
	if s.queryErr != nil {
		return nil, s.queryErr
	}
	return s.rows, nil
}

func (s *stubTx) QueryRow(ctx context.Context, sql string, args ...any) Row {
	s.queries = append(s.queries, capturedQuery{SQL: sql, Args: args})
	if s.queryRowFn != nil {
		return s.queryRowFn(sql, args...)
	}
	return &stubMemberSearchRow{err: ErrNoRows}
}

type stubMemberSearchRow struct {
	err  error
	vals []any
}

func (s *stubMemberSearchRow) Scan(dest ...any) error {
	if s.err != nil {
		return s.err
	}
	for i := range dest {
		if i >= len(s.vals) {
			break
		}
		assignScan(dest[i], s.vals[i])
	}
	return nil
}

// stubRows iterates a fixed slice of row value slices.
type stubRows struct {
	values [][]any
	idx    int
	err    error
}

func (s *stubRows) Next() bool   { return s.idx < len(s.values) }
func (s *stubRows) Close() error { return nil }
func (s *stubRows) Err() error   { return s.err }
func (s *stubRows) Scan(dest ...any) error {
	if s.idx >= len(s.values) {
		return errors.New("stubRows: scan past end")
	}
	row := s.values[s.idx]
	s.idx++
	for i := range dest {
		if i >= len(row) {
			break
		}
		assignScan(dest[i], row[i])
	}
	return nil
}

// assignScan is a tiny test helper that copies a value into a *T destination.
func assignScan(dest, src any) {
	switch d := dest.(type) {
	case *string:
		if src == nil {
			*d = ""
		} else if v, ok := src.(string); ok {
			*d = v
		}
	case *bool:
		if v, ok := src.(bool); ok {
			*d = v
		}
	case *int:
		if v, ok := src.(int); ok {
			*d = v
		}
	case *time.Time:
		if v, ok := src.(time.Time); ok {
			*d = v
		}
	case **string:
		if src == nil {
			*d = nil
		} else if v, ok := src.(string); ok {
			s := v
			*d = &s
		}
	case **time.Time:
		if src == nil {
			*d = nil
		} else if t, ok := src.(time.Time); ok {
			x := t
			*d = &x
		}
	case *[]string:
		if v, ok := src.([]string); ok {
			*d = v
		}
	}
}

// -----------------------------------------------------------------------------
// Test fixtures
// -----------------------------------------------------------------------------

func mustTimeMemberSearch(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("time parse: %v", err)
	}
	return v
}

func phyllisRow(t *testing.T) []any {
	return []any{
		"00000000-0000-7000-8000-000000001999",          // gcid
		"daleleung76@gmail.com",                         // email
		"Dale (multi-role test)",                        // display_name
		[]string{"admin"},                               // roles (array_agg → text[], CHO-1809 multi-role)
		mustTimeMemberSearch(t, "2026-05-16T01:32:00Z"), // updated_at
	}
}

// -----------------------------------------------------------------------------
// Happy path — empty q returns recent members, sorted DESC by updated_at
// -----------------------------------------------------------------------------

func TestTenantMemberSearch_HappyPath_EmptyQ(t *testing.T) {
	rows := &stubRows{values: [][]any{phyllisRow(t)}}
	tx := &stubTx{rows: rows}
	stq := &stubTxQuerier{tx: tx}

	repo := NewTenantMemberSearchRepository(stq)

	res, err := repo.Search(context.Background(), identity.TenantMemberSearchQuery{
		TenantID: "01970000-0000-7000-8000-0000000000aa",
		PageSize: 20,
	})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if got, want := len(res.Items), 1; got != want {
		t.Fatalf("items: got %d want %d", got, want)
	}
	got := res.Items[0]
	if got.GCID != "00000000-0000-7000-8000-000000001999" {
		t.Errorf("gcid: got %q", got.GCID)
	}
	if got.Email == nil || *got.Email != "daleleung76@gmail.com" {
		t.Errorf("email: got %v", got.Email)
	}
	if got.DisplayName == nil || *got.DisplayName != "Dale (multi-role test)" {
		t.Errorf("display_name: got %v", got.DisplayName)
	}
	if len(got.Roles) != 1 || got.Roles[0] != "ADMIN" {
		t.Errorf("roles: got %v want [ADMIN]", got.Roles)
	}

	// Adapter MUST have wrapped the SQL in a RunInTenantTx call so RLS scopes
	// the result set. Empty tenant — would have errored at the adapter
	// boundary BEFORE the RunInTenantTx hop.
	if stq.callCount != 1 {
		t.Errorf("RunInTenantTx called %d times; want 1", stq.callCount)
	}
	if stq.gotTenantID != "01970000-0000-7000-8000-0000000000aa" {
		t.Errorf("tenant id propagated wrongly: %q", stq.gotTenantID)
	}

	// The SQL shape MUST filter closure_sagas non-active states + the
	// updated_at DESC sort + the LIMIT $N + 1 sentinel.
	if len(tx.queries) == 0 {
		t.Fatal("no queries captured")
	}
	sql := tx.queries[0].SQL
	if !strings.Contains(sql, "tenant_memberships") {
		t.Errorf("sql missing tenant_memberships join: %s", sql)
	}
	if !strings.Contains(sql, "ORDER BY") || !strings.Contains(sql, "DESC") {
		t.Errorf("sql missing canonical sort: %s", sql)
	}
	if !strings.Contains(sql, "deleted_at IS NULL") {
		t.Errorf("sql missing soft-delete filter: %s", sql)
	}
}

// -----------------------------------------------------------------------------
// Q substring path — wraps q in %...% (case-insensitive LIKE)
// -----------------------------------------------------------------------------

func TestTenantMemberSearch_QSubstring(t *testing.T) {
	rows := &stubRows{values: [][]any{phyllisRow(t)}}
	tx := &stubTx{rows: rows}
	stq := &stubTxQuerier{tx: tx}
	repo := NewTenantMemberSearchRepository(stq)

	_, err := repo.Search(context.Background(), identity.TenantMemberSearchQuery{
		TenantID: "01970000-0000-7000-8000-0000000000aa",
		Q:        "dale",
		PageSize: 20,
	})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}

	// The q parameter MUST be passed as `%dale%` (lowercase) so the SQL
	// expression LOWER(...) LIKE LOWER($q) matches case-insensitively.
	q := tx.queries[0]
	found := false
	for _, a := range q.Args {
		if s, ok := a.(string); ok && s == "%dale%" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected '%%dale%%' in args; got %v", q.Args)
	}
}

// -----------------------------------------------------------------------------
// Role filter — when Role is set, the SQL passes the role as a parameter
// -----------------------------------------------------------------------------

func TestTenantMemberSearch_RoleFilter(t *testing.T) {
	rows := &stubRows{values: [][]any{phyllisRow(t)}}
	tx := &stubTx{rows: rows}
	stq := &stubTxQuerier{tx: tx}
	repo := NewTenantMemberSearchRepository(stq)

	_, err := repo.Search(context.Background(), identity.TenantMemberSearchQuery{
		TenantID: "01970000-0000-7000-8000-0000000000aa",
		Role:     "admin",
		PageSize: 20,
	})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}

	q := tx.queries[0]
	found := false
	for _, a := range q.Args {
		if s, ok := a.(string); ok && s == "admin" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'admin' role in args; got %v", q.Args)
	}
}

// -----------------------------------------------------------------------------
// Empty tenant — adapter MUST reject (defence in depth; the handler already
// validates, but the adapter is a separate boundary)
// -----------------------------------------------------------------------------

func TestTenantMemberSearch_EmptyTenant_Rejected(t *testing.T) {
	stq := &stubTxQuerier{}
	repo := NewTenantMemberSearchRepository(stq)

	_, err := repo.Search(context.Background(), identity.TenantMemberSearchQuery{
		PageSize: 20,
	})
	if err == nil {
		t.Fatal("expected error on empty tenant_id")
	}
	if stq.callCount != 0 {
		t.Errorf("RunInTenantTx invoked despite empty tenant: %d", stq.callCount)
	}
}

// -----------------------------------------------------------------------------
// Pagination — when the underlying query returns PageSize+1 rows, the result
// trims back to PageSize and marks HasMore.
// -----------------------------------------------------------------------------

func TestTenantMemberSearch_PaginationBoundary(t *testing.T) {
	// Build 3 rows for page_size=2 — we expect 2 items + HasMore=true.
	mkRow := func(suffix string) []any {
		return []any{
			"00000000-0000-7000-8000-00000000200" + suffix,
			"u" + suffix + "@chora.dev",
			"User " + suffix,
			"learner",
			mustTimeMemberSearch(t, "2026-05-16T00:00:0"+suffix+"Z"),
		}
	}
	rows := &stubRows{values: [][]any{mkRow("3"), mkRow("2"), mkRow("1")}}
	tx := &stubTx{rows: rows}
	stq := &stubTxQuerier{tx: tx}
	repo := NewTenantMemberSearchRepository(stq)

	res, err := repo.Search(context.Background(), identity.TenantMemberSearchQuery{
		TenantID: "01970000-0000-7000-8000-0000000000aa",
		PageSize: 2,
	})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if got := len(res.Items); got != 2 {
		t.Errorf("trimmed items: got %d want 2", got)
	}
	if !res.HasMore {
		t.Errorf("HasMore: got false want true (3rd row signals more)")
	}
	if res.NextOffset == 0 {
		t.Errorf("NextOffset: got 0 want >0 when HasMore")
	}
}

// -----------------------------------------------------------------------------
// Pagination — no more rows ⇒ HasMore false + NextOffset 0.
// -----------------------------------------------------------------------------

func TestTenantMemberSearch_PaginationEndOfList(t *testing.T) {
	rows := &stubRows{values: [][]any{phyllisRow(t)}}
	tx := &stubTx{rows: rows}
	stq := &stubTxQuerier{tx: tx}
	repo := NewTenantMemberSearchRepository(stq)

	res, err := repo.Search(context.Background(), identity.TenantMemberSearchQuery{
		TenantID: "01970000-0000-7000-8000-0000000000aa",
		PageSize: 20,
	})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if res.HasMore {
		t.Errorf("HasMore: got true want false at end of list")
	}
	if res.NextOffset != 0 {
		t.Errorf("NextOffset: got %d want 0 at end of list", res.NextOffset)
	}
}

// -----------------------------------------------------------------------------
// Offset propagation — when caller passes Offset N, SQL OFFSET $N applies.
// -----------------------------------------------------------------------------

func TestTenantMemberSearch_OffsetPropagation(t *testing.T) {
	rows := &stubRows{}
	tx := &stubTx{rows: rows}
	stq := &stubTxQuerier{tx: tx}
	repo := NewTenantMemberSearchRepository(stq)

	_, err := repo.Search(context.Background(), identity.TenantMemberSearchQuery{
		TenantID: "01970000-0000-7000-8000-0000000000aa",
		PageSize: 20,
		Offset:   40,
	})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	// Offset MUST be carried in args (as int). The SQL string includes
	// `OFFSET $N` (we just verify the value reaches the args list).
	q := tx.queries[0]
	found := false
	for _, a := range q.Args {
		if n, ok := a.(int); ok && n == 40 {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("offset=40 not propagated to args: %v", q.Args)
	}
}

// -----------------------------------------------------------------------------
// Role uppercase canonicalisation — domain row stores lowercase, summary
// must surface uppercase per the contract.
// -----------------------------------------------------------------------------

func TestTenantMemberSearch_RoleUppercase(t *testing.T) {
	rows := &stubRows{values: [][]any{
		{
			"00000000-0000-7000-8000-000000002001",
			"u@chora.dev",
			"User One",
			[]string{"instructor"}, // roles (array_agg → text[], CHO-1809 multi-role)
			mustTimeMemberSearch(t, "2026-05-16T00:00:00Z"),
		},
	}}
	tx := &stubTx{rows: rows}
	stq := &stubTxQuerier{tx: tx}
	repo := NewTenantMemberSearchRepository(stq)

	res, err := repo.Search(context.Background(), identity.TenantMemberSearchQuery{
		TenantID: "01970000-0000-7000-8000-0000000000aa",
		PageSize: 20,
	})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	got := res.Items[0]
	if len(got.Roles) != 1 || got.Roles[0] != "INSTRUCTOR" {
		t.Errorf("role: got %v want [INSTRUCTOR]", got.Roles)
	}
}
