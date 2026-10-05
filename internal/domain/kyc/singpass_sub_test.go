// singpass_sub_test.go — RED-phase TDD specs for the Path A
// "persist only singpass_sub UUID" refactor (SP-2).
//
// Per migration 0004_singpass_sub_minimisation.sql + PII_Closure_Map.yaml,
// the only Singpass-derived attribute Chora persists is the OIDC `sub` UUID.
// NRIC/FIN, name, DOB, nationality, address, family etc. are NEVER stored.
//
// This file pins the Verification aggregate's behaviour around the new
// SingpassSub field + BindSingpassSub method. Implementation lives in
// verification.go.
package kyc_test

import (
	"strings"
	"testing"

	"github.com/apollo-chora/chora-identity/internal/domain/kyc"
)

const (
	subA  = "01970000-aaaa-7000-8000-000000000001"
	subB  = "01970000-bbbb-7000-8000-000000000002"
	gcidS = "01970000-0000-7000-9000-00000000a0a1"
)

func TestVerification_BindSingpassSub_SetsField(t *testing.T) {
	t.Parallel()
	v, err := kyc.NewVerification(kyc.NewParams{
		Gcid: gcidS, Method: kyc.MethodSingpass, Provider: "ndi",
	})
	if err != nil {
		t.Fatalf("NewVerification: %v", err)
	}
	if v.SingpassSub != "" {
		t.Errorf("default SingpassSub should be empty; got %q", v.SingpassSub)
	}
	if err := v.BindSingpassSub(subA); err != nil {
		t.Fatalf("BindSingpassSub: %v", err)
	}
	if v.SingpassSub != subA {
		t.Errorf("SingpassSub=%q want %q", v.SingpassSub, subA)
	}
}

func TestVerification_BindSingpassSub_RejectsEmpty(t *testing.T) {
	t.Parallel()
	v, _ := kyc.NewVerification(kyc.NewParams{
		Gcid: gcidS, Method: kyc.MethodSingpass, Provider: "ndi",
	})
	if err := v.BindSingpassSub(""); err == nil {
		t.Errorf("expected error binding empty sub")
	}
	if err := v.BindSingpassSub("   "); err == nil {
		t.Errorf("expected error binding whitespace sub")
	}
}

func TestVerification_BindSingpassSub_IdempotentOnSameSub(t *testing.T) {
	t.Parallel()
	v, _ := kyc.NewVerification(kyc.NewParams{
		Gcid: gcidS, Method: kyc.MethodSingpass, Provider: "ndi",
	})
	if err := v.BindSingpassSub(subA); err != nil {
		t.Fatalf("first bind: %v", err)
	}
	// Re-binding the same sub is a no-op (matches the partial unique index
	// idempotency: same Singpass account → same Chora KYC).
	if err := v.BindSingpassSub(subA); err != nil {
		t.Errorf("re-bind of same sub should be idempotent; got %v", err)
	}
	if v.SingpassSub != subA {
		t.Errorf("SingpassSub=%q want %q after re-bind", v.SingpassSub, subA)
	}
}

func TestVerification_BindSingpassSub_RejectsRebindToDifferentSub(t *testing.T) {
	t.Parallel()
	v, _ := kyc.NewVerification(kyc.NewParams{
		Gcid: gcidS, Method: kyc.MethodSingpass, Provider: "ndi",
	})
	_ = v.BindSingpassSub(subA)
	err := v.BindSingpassSub(subB)
	if err == nil {
		t.Fatalf("expected error rebinding to different sub")
	}
	if !strings.Contains(err.Error(), "already bound") {
		t.Errorf("error should mention 'already bound'; got %v", err)
	}
	if v.SingpassSub != subA {
		t.Errorf("SingpassSub mutated on rebind error; got %q want %q", v.SingpassSub, subA)
	}
}

// SoftDelete must zero the singpass_sub field — the closure map declares
// strategy: drop. This proves the domain crypto-shred path.
func TestVerification_SoftDelete_ClearsSingpassSub(t *testing.T) {
	t.Parallel()
	v, _ := kyc.NewVerification(kyc.NewParams{
		Gcid: gcidS, Method: kyc.MethodSingpass, Provider: "ndi",
	})
	_ = v.BindSingpassSub(subA)
	v.SoftDelete()
	if v.SingpassSub != "" {
		t.Errorf("SoftDelete should clear SingpassSub; got %q", v.SingpassSub)
	}
}

// BindSingpassSub appends an audit entry so the binding is observable.
func TestVerification_BindSingpassSub_AppendsAuditEntry(t *testing.T) {
	t.Parallel()
	v, _ := kyc.NewVerification(kyc.NewParams{
		Gcid: gcidS, Method: kyc.MethodSingpass, Provider: "ndi",
	})
	pre := len(v.AuditLog)
	_ = v.BindSingpassSub(subA)
	if len(v.AuditLog) != pre+1 {
		t.Errorf("expected audit entry on bind; before=%d after=%d", pre, len(v.AuditLog))
	}
	last := v.AuditLog[len(v.AuditLog)-1]
	if last.Event != "singpass_sub_bound" {
		t.Errorf("last audit event=%q want singpass_sub_bound", last.Event)
	}
	// The sub itself MUST NOT appear in audit notes (privacy: keep the
	// actual UUID off the log; it's already in the field).
	if strings.Contains(last.Notes, subA) {
		t.Errorf("audit notes should not include the sub UUID; got %q", last.Notes)
	}
}
