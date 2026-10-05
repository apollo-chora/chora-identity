package pg

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/apollo-chora/chora-identity/internal/domain/kyc"
)

// -----------------------------------------------------------------------------
// minimal stubs (uniquely named to avoid collision with sibling pg tests)
// -----------------------------------------------------------------------------

type kycStubRow struct{ scan func(dest ...any) error }

func (r kycStubRow) Scan(dest ...any) error { return r.scan(dest...) }

type kycStubTx struct {
	execSQL  []string
	execArgs [][]any
	queryRow func(sql string, args ...any) Row
	execErr  error
}

func (t *kycStubTx) Exec(_ context.Context, sql string, args ...any) error {
	t.execSQL = append(t.execSQL, sql)
	t.execArgs = append(t.execArgs, args)
	return t.execErr
}
func (t *kycStubTx) QueryRow(_ context.Context, sql string, args ...any) Row {
	return t.queryRow(sql, args...)
}
func (t *kycStubTx) Query(_ context.Context, _ string, _ ...any) (Rows, error) {
	return nil, errors.New("kycStubTx.Query not used")
}

type kycStubUserTxr struct {
	calls   int
	gotGcid string
	gotRole string
	tx      *kycStubTx
}

func (s *kycStubUserTxr) RunInUserTx(ctx context.Context, gcid, role string, fn func(context.Context, Tx) error) error {
	s.calls++
	s.gotGcid = gcid
	s.gotRole = role
	return fn(ctx, s.tx)
}

const (
	kycTestGcid   = "00000000-0000-7000-8000-000000002042"
	kycTestVerify = "01890000-0000-7000-8000-0000000000aa"
)

// verifiedRowScan returns a Scan func that fills the 21 SELECT dest pointers
// (in kycSelectColumns order) from a canonical VERIFIED verification. Couples
// the test to the adapter's column order on purpose — that ordering is the
// read contract the admit gate depends on.
func verifiedRowScan(t *testing.T) func(dest ...any) error {
	t.Helper()
	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	auditJSON, err := json.Marshal([]map[string]any{
		{"event": "initiated", "actor_gcid": "", "notes": "", "occurred_at": now},
		{"event": "verified", "actor_gcid": "ndi", "notes": "", "occurred_at": now},
	})
	if err != nil {
		t.Fatalf("marshal audit: %v", err)
	}
	return func(dest ...any) error {
		if len(dest) != 21 {
			t.Fatalf("Scan dest count = %d, want 21 (kycSelectColumns)", len(dest))
		}
		set := func(i int, v any) {
			switch p := dest[i].(type) {
			case *string:
				*p = v.(string)
			case **string:
				s := v.(string)
				*p = &s
			case *bool:
				*p = v.(bool)
			case *int64:
				*p = v.(int64)
			case **int64:
				n := v.(int64)
				*p = &n
			case *time.Time:
				*p = v.(time.Time)
			case **time.Time:
				tv := v.(time.Time)
				*p = &tv
			case *[]byte:
				*p = v.([]byte)
			default:
				t.Fatalf("dest[%d] unexpected type %T", i, dest[i])
			}
		}
		set(0, kycTestVerify) // verification_id
		set(1, kycTestGcid)   // gcid
		set(2, "singpass")    // method
		set(3, "verified")    // status
		set(4, "ndi")         // provider
		set(5, "")            // document_uri (nullable → leave nil)
		set(6, "")            // singpass_sub (nullable → leave nil)
		set(7, now)           // verified_at
		// index 8 rejected_at, 9 rejection_code, 10 rejection_notes → nil
		set(11, true) // retry_allowed
		// index 12 fee_charged_cents, 13 currency → nil
		set(14, false) // skillsfuture_scope_granted
		// index 15 expires_at → nil
		set(16, []byte(auditJSON)) // audit_log
		set(17, int64(3))          // version
		set(18, now)               // created_at
		set(19, now)               // updated_at
		// index 20 deleted_at → nil
		return nil
	}
}

// -----------------------------------------------------------------------------
// tests
// -----------------------------------------------------------------------------

func TestKycRepository_ImplementsRepository(t *testing.T) {
	var _ kyc.Repository = (*KycRepository)(nil)
}

func TestKycRepository_Save_UpsertsScopedByOwnerGcid(t *testing.T) {
	tx := &kycStubTx{}
	txr := &kycStubUserTxr{tx: tx}
	v, err := kyc.NewVerification(kyc.NewParams{Gcid: kycTestGcid, Method: kyc.MethodManualDoc, Provider: "internal_review"})
	if err != nil {
		t.Fatalf("NewVerification: %v", err)
	}
	if err := NewKycRepository(txr).Save(context.Background(), v); err != nil {
		t.Fatalf("Save err = %v, want nil", err)
	}
	if txr.gotGcid != kycTestGcid {
		t.Fatalf("RunInUserTx gcid = %q, want owner gcid %q", txr.gotGcid, kycTestGcid)
	}
	if len(tx.execSQL) != 1 {
		t.Fatalf("exec count = %d, want 1", len(tx.execSQL))
	}
	sql := tx.execSQL[0]
	if !strings.Contains(sql, "INSERT INTO kyc_verifications") ||
		!strings.Contains(sql, "ON CONFLICT (verification_id) DO UPDATE") {
		t.Fatalf("Save SQL not an upsert on verification_id:\n%s", sql)
	}
	// audit_log must be serialised JSON, not a Go value pgx can't map.
	var foundAuditJSON bool
	for _, a := range tx.execArgs[0] {
		if b, ok := a.([]byte); ok && json.Valid(b) && strings.Contains(string(b), "initiated") {
			foundAuditJSON = true
		}
	}
	if !foundAuditJSON {
		t.Fatalf("Save args missing serialised audit_log JSON: %#v", tx.execArgs[0])
	}
}

func TestKycRepository_Save_NilVerification_Errors(t *testing.T) {
	txr := &kycStubUserTxr{tx: &kycStubTx{}}
	if err := NewKycRepository(txr).Save(context.Background(), nil); err == nil {
		t.Fatal("Save(nil) err = nil, want error (fail loud)")
	}
	if txr.calls != 0 {
		t.Fatalf("RunInUserTx called %d times for nil verification, want 0", txr.calls)
	}
}

func TestKycRepository_GetLatestByGcid_Verified(t *testing.T) {
	tx := &kycStubTx{queryRow: func(sql string, _ ...any) Row {
		if !strings.Contains(sql, "WHERE gcid = $1") ||
			!strings.Contains(sql, "deleted_at IS NULL") ||
			!strings.Contains(sql, "ORDER BY updated_at DESC") {
			t.Fatalf("GetLatestByGcid SQL wrong:\n%s", sql)
		}
		return kycStubRow{scan: verifiedRowScan(t)}
	}}
	txr := &kycStubUserTxr{tx: tx}
	got, err := NewKycRepository(txr).GetLatestByGcid(context.Background(), kycTestGcid)
	if err != nil {
		t.Fatalf("GetLatestByGcid err = %v", err)
	}
	if txr.gotGcid != kycTestGcid {
		t.Fatalf("RunInUserTx gcid = %q, want %q", txr.gotGcid, kycTestGcid)
	}
	if got.Status != kyc.StatusVerified {
		t.Fatalf("status = %q, want verified", got.Status)
	}
	if got.VerificationID != kycTestVerify || got.Gcid != kycTestGcid {
		t.Fatalf("ids = (%q,%q)", got.VerificationID, got.Gcid)
	}
	if len(got.AuditLog) != 2 || got.AuditLog[1].Event != "verified" {
		t.Fatalf("audit_log not round-tripped: %#v", got.AuditLog)
	}
}

func TestKycRepository_GetLatestByGcid_NotFound(t *testing.T) {
	tx := &kycStubTx{queryRow: func(string, ...any) Row {
		return kycStubRow{scan: func(...any) error { return ErrNoRows }}
	}}
	_, err := NewKycRepository(&kycStubUserTxr{tx: tx}).GetLatestByGcid(context.Background(), kycTestGcid)
	if !errors.Is(err, kyc.ErrNotFound) {
		t.Fatalf("err = %v, want kyc.ErrNotFound", err)
	}
}

func TestKycRepository_GetByID_ScopesByContextSubjectGcid(t *testing.T) {
	tx := &kycStubTx{queryRow: func(sql string, _ ...any) Row {
		if !strings.Contains(sql, "WHERE verification_id = $1") ||
			!strings.Contains(sql, "deleted_at IS NULL") {
			t.Fatalf("GetByID SQL wrong:\n%s", sql)
		}
		return kycStubRow{scan: verifiedRowScan(t)}
	}}
	txr := &kycStubUserTxr{tx: tx}
	ctx := kyc.WithSubjectGcid(context.Background(), kycTestGcid)
	got, err := NewKycRepository(txr).GetByID(ctx, kycTestVerify)
	if err != nil {
		t.Fatalf("GetByID err = %v", err)
	}
	if txr.gotGcid != kycTestGcid {
		t.Fatalf("RunInUserTx gcid = %q, want ctx subject gcid %q", txr.gotGcid, kycTestGcid)
	}
	if got.VerificationID != kycTestVerify {
		t.Fatalf("verification_id = %q", got.VerificationID)
	}
}

func TestKycRepository_GetByID_MissingSubjectGcid_FailsLoud(t *testing.T) {
	txr := &kycStubUserTxr{tx: &kycStubTx{}}
	_, err := NewKycRepository(txr).GetByID(context.Background(), kycTestVerify)
	if err == nil {
		t.Fatal("GetByID without ctx subject gcid err = nil, want fail-loud error")
	}
	if errors.Is(err, kyc.ErrNotFound) {
		t.Fatal("missing RLS subject must NOT be reported as ErrNotFound (would false-negative the gate)")
	}
	if txr.calls != 0 {
		t.Fatalf("RunInUserTx called %d times without a subject gcid, want 0", txr.calls)
	}
}

// --- error branches (scanVerification / unmarshalAuditLog / Save exec) -------

func TestKycRepository_Save_ExecErrorWraps(t *testing.T) {
	boom := errors.New("kyc write boom")
	tx := &kycStubTx{execErr: boom}
	v, err := kyc.NewVerification(kyc.NewParams{Gcid: kycTestGcid, Method: kyc.MethodManualDoc, Provider: "internal_review"})
	if err != nil {
		t.Fatalf("NewVerification: %v", err)
	}
	err = NewKycRepository(&kycStubUserTxr{tx: tx}).Save(context.Background(), v)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom", err)
	}
}

func TestKycRepository_GetByID_ScanErrorPropagates(t *testing.T) {
	boom := errors.New("kyc scan boom")
	tx := &kycStubTx{queryRow: func(string, ...any) Row {
		return kycStubRow{scan: func(...any) error { return boom }}
	}}
	ctx := kyc.WithSubjectGcid(context.Background(), kycTestGcid)
	_, err := NewKycRepository(&kycStubUserTxr{tx: tx}).GetByID(ctx, kycTestVerify)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom", err)
	}
}

// scanFill21 fills the 21 kycSelectColumns dests from a label→value map; use it
// to build rows the verifiedRowScan shape does not express (bad audit JSON,
// fee_charged_cents set).
func scanFill21(dest []any, set func(i int, v any)) func(...any) error {
	return func(got ...any) error {
		for i := range got {
			switch p := got[i].(type) {
			case *string:
				*p = ""
			case **string:
				*p = nil
			case *bool:
				*p = false
			case *int64:
				*p = 0
			case **int64:
				*p = nil
			case *time.Time:
				*p = time.Time{}
			case **time.Time:
				*p = nil
			case *[]byte:
				*p = nil
			}
			if set != nil {
				set(i, got[i])
			}
		}
		return nil
	}
}

func TestKycRepository_scanVerification_BadAuditJSONFails(t *testing.T) {
	row := kycStubRow{scan: scanFill21(nil, func(i int, d any) {
		switch p := d.(type) {
		case *string:
			*p = "v-1" // verification_id at 0
		case *[]byte: // audit_log at 16
			*p = []byte(`{not json`)
		}
	})}
	_, err := scanVerification(row)
	if err == nil || !strings.Contains(err.Error(), "audit_log") {
		t.Fatalf("err = %v, want audit_log unmarshal error", err)
	}
}

func TestKycRepository_scanVerification_FeeCentsAndExpiresMap(t *testing.T) {
	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	row := kycStubRow{scan: scanFill21(nil, func(i int, d any) {
		switch p := d.(type) {
		case *[]byte: // audit_log
			*p = []byte(`[]`)
		case **int64: // fee_charged_cents at 12
			n := int64(499)
			*p = &n
		case **time.Time: // expires_at at 15
			*p = &now
		}
	})}
	v, err := scanVerification(row)
	if err != nil {
		t.Fatalf("scanVerification: %v", err)
	}
	if v.FeeChargedCents != 499 {
		t.Errorf("FeeChargedCents = %d, want 499", v.FeeChargedCents)
	}
	if v.ExpiresAt == nil || !v.ExpiresAt.Equal(now) {
		t.Errorf("ExpiresAt = %v, want %v", v.ExpiresAt, now)
	}
}

func TestKycRepository_scanVerification_GenericScanError(t *testing.T) {
	boom := errors.New("scan boom")
	row := kycStubRow{scan: func(...any) error { return boom }}
	_, err := scanVerification(row)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom", err)
	}
}

func TestKycRepository_unmarshalAuditLog_Branches(t *testing.T) {
	// nil/empty raw → nil, nil.
	got, err := unmarshalAuditLog(nil)
	if err != nil || got != nil {
		t.Fatalf("empty raw: got=%v err=%v, want nil,nil", got, err)
	}
	// Empty JSON array → nil, nil (no entries).
	got, err = unmarshalAuditLog([]byte(`[]`))
	if err != nil || got != nil {
		t.Fatalf("[]: got=%v err=%v, want nil,nil", got, err)
	}
	// Malformed JSON → error.
	if _, err := unmarshalAuditLog([]byte(`{`)); err == nil {
		t.Fatal("malformed JSON must error")
	}
	// Well-formed entries map onto the domain slice.
	out, err := unmarshalAuditLog([]byte(`[{"event":"initiated","actor_gcid":"ndi","notes":"n","occurred_at":"2026-07-09T12:00:00Z"}]`))
	if err != nil {
		t.Fatalf("entries: %v", err)
	}
	if len(out) != 1 || out[0].Event != "initiated" || out[0].ActorGcid != "ndi" || out[0].Notes != "n" {
		t.Fatalf("entries mapping: %+v", out)
	}
}
