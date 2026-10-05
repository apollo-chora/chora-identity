// tenant_idp_provider_repository_test.go — unit tests for the pgx-backed
// TenantIdpProviderRepository (Setup Wizard Phase C, CHO-1682). Same stub
// TxQuerier harness as the sibling repo tests: asserts the RLS-tx wrapping
// (RunInTenantTx with the tenant id), the SQL shape, the nullable-column
// round-trip and the ErrNoRows → tip.ErrNotFound mapping WITHOUT a live DB.
package pg

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	tip "github.com/apollo-chora/chora-identity/internal/domain/tenant_idp_provider"
)

const (
	tipTenant     = "01970000-0000-7000-8000-0000000000bb"
	tipProviderID = "01970000-0000-7000-8000-0000000000cc"
)

func mustTipProvider() *tip.TenantIdpProvider {
	return &tip.TenantIdpProvider{
		ID:           tipProviderID,
		TenantID:     tipTenant,
		ProviderType: tip.ProviderOIDC,
		ClientID:     "oidc-client",
		CreatedAt:    time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC),
		UpdatedAt:    time.Date(2026, 7, 9, 12, 30, 0, 0, time.UTC),
	}
}

// tipRowScan fills the 10 Get/ListByTenant dest pointers (tenantIdpProviderColumns
// order) from a value slice via the shared assignScan helper.
func tipRowScan(vals []any) func(dest ...any) error {
	return func(dest ...any) error {
		for i := range dest {
			if i >= len(vals) {
				break
			}
			assignScan(dest[i], vals[i])
		}
		return nil
	}
}

func TestNewTenantIdpProviderRepository(t *testing.T) {
	repo := NewTenantIdpProviderRepository(&stubTxQuerier{})
	if repo == nil {
		t.Fatal("repo must be non-nil")
	}
	var _ tip.Repository = repo
}

func TestTenantIdpProvider_Upsert_ReflectsPersistedRow(t *testing.T) {
	tx := &stubTx{queryRowFn: rowQueue(&stubMemberSearchRow{vals: []any{
		"01970000-0000-7000-8000-000000000099", // persisted id (conflict path)
		time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
	}})}
	q := &stubTxQuerier{tx: tx}
	repo := NewTenantIdpProviderRepository(q)

	p := mustTipProvider()
	p.ID = "01970000-0000-7000-8000-00000000fresh" // caller-minted id — must be replaced
	if err := repo.Upsert(context.Background(), p); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if q.gotTenantID != tipTenant {
		t.Fatalf("RunInTenantTx tenant = %q, want %q", q.gotTenantID, tipTenant)
	}
	// The aggregate is mutated to the persisted id + timestamps (matters for
	// the existing-row conflict path).
	if p.ID != "01970000-0000-7000-8000-000000000099" {
		t.Errorf("id after persist = %q, want the RETURNING id", p.ID)
	}
	if !p.CreatedAt.Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("CreatedAt = %v, want RETURNING created_at", p.CreatedAt)
	}
	sql := tx.queries[0].SQL
	for _, frag := range []string{"INSERT INTO tenant_idp_providers", "ON CONFLICT (tenant_id, provider_type)", "RETURNING id, created_at, updated_at"} {
		if !strings.Contains(sql, frag) {
			t.Errorf("SQL missing %q:\n%s", frag, sql)
		}
	}
	// Empty-string nullable fields must be serialised as NULL (nil), not "".
	for _, a := range tx.queries[0].Args {
		if s, ok := a.(string); ok && s == "" {
			t.Errorf("empty-string nullable arg reached pgx: %#v", tx.queries[0].Args)
		}
	}
}

func TestTenantIdpProvider_Upsert_NilAggregateErrors(t *testing.T) {
	repo := NewTenantIdpProviderRepository(&stubTxQuerier{tx: &stubTx{}})
	if err := repo.Upsert(context.Background(), nil); err == nil {
		t.Fatal("Upsert(nil) err = nil, want fail-loud error")
	}
}

func TestTenantIdpProvider_Upsert_ScanErrorWraps(t *testing.T) {
	boom := errors.New("scan boom")
	tx := &stubTx{queryRowFn: rowQueue(&stubMemberSearchRow{err: boom})}
	err := NewTenantIdpProviderRepository(&stubTxQuerier{tx: tx}).Upsert(context.Background(), mustTipProvider())
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom", err)
	}
}

func TestTenantIdpProvider_Get_HappyPathRoundTripsNullables(t *testing.T) {
	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	vals := []any{
		tipProviderID, tipTenant, "oidc", "client-x", "secret-ref",
		"https://idp.example.com/discovery", true, now, now, nil, // deleted_at NULL
	}
	tx := &stubTx{queryRowFn: rowQueue(&stubMemberSearchRow{vals: vals})}
	q := &stubTxQuerier{tx: tx}
	repo := NewTenantIdpProviderRepository(q)

	p, err := repo.Get(context.Background(), tipTenant, tip.ProviderOIDC)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if q.gotTenantID != tipTenant {
		t.Fatalf("RunInTenantTx tenant = %q, want %q", q.gotTenantID, tipTenant)
	}
	if p == nil || p.ProviderType != tip.ProviderOIDC || p.ClientID != "client-x" ||
		p.ClientSecretName != "secret-ref" || p.DiscoveryURL != "https://idp.example.com/discovery" ||
		!p.SingpassEnabled || p.DeletedAt != nil {
		t.Fatalf("bad round-trip: %+v", p)
	}
	sql := tx.queries[0].SQL
	for _, frag := range []string{"tenant_idp_providers", "deleted_at IS NULL"} {
		if !strings.Contains(sql, frag) {
			t.Errorf("SQL missing %q:\n%s", frag, sql)
		}
	}
}

func TestTenantIdpProvider_Get_NullColumnsMapToEmpty(t *testing.T) {
	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	vals := []any{
		tipProviderID, tipTenant, "singpass", nil, nil, nil, false, now, now, nil,
	}
	tx := &stubTx{queryRowFn: rowQueue(&stubMemberSearchRow{vals: vals})}
	p, err := NewTenantIdpProviderRepository(&stubTxQuerier{tx: tx}).Get(
		context.Background(), tipTenant, tip.ProviderSingpass)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if p.ClientID != "" || p.ClientSecretName != "" || p.DiscoveryURL != "" || p.SingpassEnabled {
		t.Fatalf("NULL columns must map to zero values: %+v", p)
	}
}

func TestTenantIdpProvider_Get_NoRowsMapsNotFound(t *testing.T) {
	tx := &stubTx{queryRowFn: rowQueue(&stubMemberSearchRow{err: ErrNoRows})}
	_, err := NewTenantIdpProviderRepository(&stubTxQuerier{tx: tx}).Get(
		context.Background(), tipTenant, tip.ProviderOIDC)
	if !errors.Is(err, tip.ErrNotFound) {
		t.Fatalf("err = %v, want tip.ErrNotFound", err)
	}
}

func TestTenantIdpProvider_Get_ScanErrorWraps(t *testing.T) {
	boom := errors.New("get boom")
	tx := &stubTx{queryRowFn: rowQueue(&stubMemberSearchRow{err: boom})}
	_, err := NewTenantIdpProviderRepository(&stubTxQuerier{tx: tx}).Get(
		context.Background(), tipTenant, tip.ProviderOIDC)
	if err == nil || !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom", err)
	}
}

func TestTenantIdpProvider_ListByTenant_HappyPath(t *testing.T) {
	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	rows := &stubRows{values: [][]any{
		{
			tipProviderID, tipTenant, "oidc", "client-x", nil, nil, true, now, now, nil,
		},
		{
			"01970000-0000-7000-8000-0000000000dd", tipTenant, "singpass", nil, "sec-2", nil,
			false, now, now, nil,
		},
	}}
	tx := &stubTx{rows: rows}
	q := &stubTxQuerier{tx: tx}
	repo := NewTenantIdpProviderRepository(q)

	out, err := repo.ListByTenant(context.Background(), tipTenant)
	if err != nil {
		t.Fatalf("ListByTenant: %v", err)
	}
	if q.gotTenantID != tipTenant {
		t.Fatalf("RunInTenantTx tenant = %q, want %q", q.gotTenantID, tipTenant)
	}
	if len(out) != 2 {
		t.Fatalf("rows = %d, want 2", len(out))
	}
	if out[0].ClientID != "client-x" || out[0].ClientSecretName != "" {
		t.Errorf("row 0 nullables: %+v", out[0])
	}
	if out[1].ProviderType != tip.ProviderSingpass || out[1].ClientSecretName != "sec-2" {
		t.Errorf("row 1: %+v", out[1])
	}
	if !strings.Contains(tx.queries[0].SQL, "ORDER BY created_at ASC") {
		t.Errorf("SQL missing created_at ASC order:\n%s", tx.queries[0].SQL)
	}
}

func TestTenantIdpProvider_ListByTenant_QueryErrorWraps(t *testing.T) {
	boom := errors.New("query boom")
	tx := &stubTx{queryErr: boom}
	_, err := NewTenantIdpProviderRepository(&stubTxQuerier{tx: tx}).ListByTenant(context.Background(), tipTenant)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom", err)
	}
}

func TestTenantIdpProvider_ListByTenant_RowsErrPropagates(t *testing.T) {
	boom := errors.New("iter boom")
	rows := &stubRows{values: [][]any{{tipProviderID, tipTenant, "oidc", nil, nil, nil, true, time.Now(), time.Now(), nil}}, err: boom}
	tx := &stubTx{rows: rows}
	_, err := NewTenantIdpProviderRepository(&stubTxQuerier{tx: tx}).ListByTenant(context.Background(), tipTenant)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want rows.Err boom", err)
	}
}

func TestTenantIdpProvider_ListByTenant_ScanErrorWraps(t *testing.T) {
	boom := errors.New("scan boom")
	// errRows yields one row whose Scan always errors.
	_, err := NewTenantIdpProviderRepository(&stubTxQuerier{tx: &stubTx{rows: &errRows{err: boom}}}).
		ListByTenant(context.Background(), tipTenant)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom", err)
	}
}

// errRows is a Rows stub whose Scan always fails (scan-error branch).
type errRows struct{ err error }

func (e *errRows) Next() bool             { return true }
func (e *errRows) Scan(dest ...any) error { return e.err }
func (e *errRows) Close() error           { return nil }
func (e *errRows) Err() error             { return nil }

func TestTenantIdpProvider_SoftDelete(t *testing.T) {
	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	tx := &stubTx{}
	q := &stubTxQuerier{tx: tx}
	if err := NewTenantIdpProviderRepository(q).SoftDelete(context.Background(), tipTenant, tip.ProviderOIDC, now); err != nil {
		t.Fatalf("SoftDelete: %v", err)
	}
	if q.gotTenantID != tipTenant {
		t.Fatalf("RunInTenantTx tenant = %q, want %q", q.gotTenantID, tipTenant)
	}
	if len(tx.queries) != 1 {
		t.Fatalf("exec calls = %d, want 1", len(tx.queries))
	}
	sql := tx.queries[0].SQL
	for _, frag := range []string{"UPDATE tenant_idp_providers", "SET deleted_at", "deleted_at IS NULL"} {
		if !strings.Contains(sql, frag) {
			t.Errorf("SQL missing %q:\n%s", frag, sql)
		}
	}
	if len(tx.queries[0].Args) != 3 || tx.queries[0].Args[0] != tipTenant || tx.queries[0].Args[1] != "oidc" {
		t.Errorf("args = %v, want [tenant oidc now]", tx.queries[0].Args)
	}
}

func TestTenantIdpProvider_SoftDelete_ExecErrorWraps(t *testing.T) {
	boom := errors.New("delete boom")
	tx := &stubTx{execErr: boom}
	err := NewTenantIdpProviderRepository(&stubTxQuerier{tx: tx}).SoftDelete(
		context.Background(), tipTenant, tip.ProviderOIDC, time.Now())
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom", err)
	}
}

// -----------------------------------------------------------------------------
// tiny helpers
// -----------------------------------------------------------------------------

func TestNullIfEmpty(t *testing.T) {
	if nullIfEmpty("") != nil {
		t.Errorf("nullIfEmpty(\"\") = %v, want nil", nullIfEmpty(""))
	}
	if v := nullIfEmpty("kept"); v != "kept" {
		t.Errorf("nullIfEmpty(\"kept\") = %v, want kept", v)
	}
}

func TestDerefString(t *testing.T) {
	if derefString(nil) != "" {
		t.Errorf("derefString(nil) = %q, want \"\"", derefString(nil))
	}
	s := "v"
	if derefString(&s) != "v" {
		t.Errorf("derefString(&s) = %q, want v", derefString(&s))
	}
}
