// Package kyc_test exercises KYCVerification state machine + invariants.
package kyc_test

import (
	"testing"
	"time"

	"github.com/apollo-chora/chora-identity/internal/domain/kyc"
)

const gcidK = "01970000-0000-7000-9000-00000000a001"

func TestNewVerification_AssignsUUIDv7AndPendingStatus(t *testing.T) {
	t.Parallel()
	v, err := kyc.NewVerification(kyc.NewParams{
		Gcid:     gcidK,
		Method:   kyc.MethodSingpass,
		Provider: "ndi",
	})
	if err != nil {
		t.Fatalf("NewVerification: %v", err)
	}
	if v.VerificationID == "" || len(v.VerificationID) != 36 || v.VerificationID[14] != '7' {
		t.Errorf("VerificationID not UUIDv7: %q", v.VerificationID)
	}
	if v.Status != kyc.StatusPending {
		t.Errorf("Status=%q want pending", v.Status)
	}
	if len(v.AuditLog) != 1 || v.AuditLog[0].Event != "initiated" {
		t.Errorf("audit log should record initiation; got %+v", v.AuditLog)
	}
}

func TestNewVerification_RejectsEmptyGcid(t *testing.T) {
	t.Parallel()
	_, err := kyc.NewVerification(kyc.NewParams{
		Gcid: "", Method: kyc.MethodSingpass, Provider: "ndi",
	})
	if err == nil {
		t.Errorf("expected error for empty gcid")
	}
}

func TestNewVerification_RejectsInvalidMethod(t *testing.T) {
	t.Parallel()
	_, err := kyc.NewVerification(kyc.NewParams{
		Gcid: gcidK, Method: kyc.Method("retina"), Provider: "x",
	})
	if err == nil {
		t.Errorf("expected error for invalid method")
	}
}

func TestSubmit_PendingToSubmitted(t *testing.T) {
	t.Parallel()
	v, _ := kyc.NewVerification(kyc.NewParams{
		Gcid: gcidK, Method: kyc.MethodManualDoc, Provider: "internal_review",
	})
	if err := v.Submit("gs://bucket/doc-1", 999, "USD"); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if v.Status != kyc.StatusSubmitted {
		t.Errorf("Status=%q want submitted", v.Status)
	}
	if v.DocumentURI != "gs://bucket/doc-1" {
		t.Errorf("document_uri not stored")
	}
	if v.FeeChargedCents != 999 {
		t.Errorf("fee not stored")
	}
}

func TestSubmit_RejectsFromVerified(t *testing.T) {
	t.Parallel()
	v, _ := kyc.NewVerification(kyc.NewParams{
		Gcid: gcidK, Method: kyc.MethodSingpass, Provider: "ndi",
	})
	_ = v.Submit("", 0, "")
	_ = v.Verify("", false)
	if err := v.Submit("", 0, ""); err == nil {
		t.Errorf("expected error Submit from verified")
	}
}

func TestVerify_SubmittedToVerified(t *testing.T) {
	t.Parallel()
	v, _ := kyc.NewVerification(kyc.NewParams{
		Gcid: gcidK, Method: kyc.MethodSingpass, Provider: "ndi",
	})
	_ = v.Submit("", 0, "")
	if err := v.Verify("", true); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if v.Status != kyc.StatusVerified {
		t.Errorf("Status=%q want verified", v.Status)
	}
	if !v.SkillsfutureScopeGranted {
		t.Errorf("SkillsfutureScopeGranted should be true")
	}
	if v.VerifiedAt == nil {
		t.Errorf("VerifiedAt should be set")
	}
}

func TestVerify_RejectsFromPending(t *testing.T) {
	t.Parallel()
	v, _ := kyc.NewVerification(kyc.NewParams{
		Gcid: gcidK, Method: kyc.MethodSingpass, Provider: "ndi",
	})
	if err := v.Verify("", false); err == nil {
		t.Errorf("expected error Verify from pending")
	}
}

func TestReject_AnyToRejected(t *testing.T) {
	t.Parallel()
	v, _ := kyc.NewVerification(kyc.NewParams{
		Gcid: gcidK, Method: kyc.MethodManualDoc, Provider: "internal_review",
	})
	_ = v.Submit("gs://bucket/doc", 999, "USD")
	if err := v.Reject("document_unreadable", "blurry image", true); err != nil {
		t.Fatalf("Reject: %v", err)
	}
	if v.Status != kyc.StatusRejected {
		t.Errorf("Status=%q want rejected", v.Status)
	}
	if v.RejectionCode != "document_unreadable" {
		t.Errorf("RejectionCode=%q", v.RejectionCode)
	}
	if !v.RetryAllowed {
		t.Errorf("RetryAllowed should be true")
	}
}

func TestReject_RejectsFromVerified(t *testing.T) {
	t.Parallel()
	v, _ := kyc.NewVerification(kyc.NewParams{
		Gcid: gcidK, Method: kyc.MethodSingpass, Provider: "ndi",
	})
	_ = v.Submit("", 0, "")
	_ = v.Verify("", false)
	if err := v.Reject("x", "y", false); err == nil {
		t.Errorf("expected error Reject from verified")
	}
}

func TestExpire_AnyNonTerminalToExpired(t *testing.T) {
	t.Parallel()
	v, _ := kyc.NewVerification(kyc.NewParams{
		Gcid: gcidK, Method: kyc.MethodSingpass, Provider: "ndi",
	})
	_ = v.Submit("", 0, "")
	_ = v.Verify("", false)
	if err := v.MarkExpired(); err != nil {
		t.Fatalf("MarkExpired: %v", err)
	}
	if v.Status != kyc.StatusExpired {
		t.Errorf("Status=%q want expired", v.Status)
	}
}

func TestVerify_AppendsAuditEntry(t *testing.T) {
	t.Parallel()
	v, _ := kyc.NewVerification(kyc.NewParams{
		Gcid: gcidK, Method: kyc.MethodSingpass, Provider: "ndi",
	})
	pre := len(v.AuditLog)
	_ = v.Submit("", 0, "")
	_ = v.Verify("reviewer-gcid-1", false)
	if len(v.AuditLog) != pre+2 {
		t.Errorf("audit log not appended; got %d entries", len(v.AuditLog))
	}
	last := v.AuditLog[len(v.AuditLog)-1]
	if last.Event != "verified" {
		t.Errorf("last audit event=%q want verified", last.Event)
	}
	if last.OccurredAt.IsZero() {
		t.Errorf("OccurredAt should be set")
	}
}

func TestKycMethod_FeeCents(t *testing.T) {
	t.Parallel()
	cases := map[kyc.Method]int64{
		kyc.MethodSingpass:     0,
		kyc.MethodSkillsFuture: 0,
		kyc.MethodManualDoc:    999, // ADR-142 default $9.99
	}
	for m, want := range cases {
		if got := kyc.DefaultFeeCents(m); got != want {
			t.Errorf("DefaultFeeCents(%q)=%d want %d", m, got, want)
		}
	}
}

// keep time import alive for verification flows that depend on it.
var _ = time.Time{}
