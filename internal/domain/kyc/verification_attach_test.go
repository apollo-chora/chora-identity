// Tests for the fee-gated manual_doc flow's pending-document attach
// transition (ADR-142 + ADR-164 Stage A.5). The document is captured at
// submission while the verification stays pending; it only enters the
// review queue (Submit → submitted) once chora-payments confirms the
// $9.99 fee is captured.
package kyc_test

import (
	"testing"

	"github.com/apollo-chora/chora-identity/internal/domain/kyc"
)

func newPendingManual(t *testing.T) *kyc.Verification {
	t.Helper()
	v, err := kyc.NewVerification(kyc.NewParams{
		Gcid:     "01970000-0000-7000-8000-0000000000aa",
		Method:   kyc.MethodManualDoc,
		Provider: "internal_review",
	})
	if err != nil {
		t.Fatalf("NewVerification: %v", err)
	}
	return v
}

func TestAttachPendingDocument_SetsURIAndKeepsPending(t *testing.T) {
	t.Parallel()
	v := newPendingManual(t)
	prevVersion := v.Version

	if err := v.AttachPendingDocument("gs://chora-kyc-sandbox/doc-1"); err != nil {
		t.Fatalf("AttachPendingDocument: %v", err)
	}
	if v.DocumentURI != "gs://chora-kyc-sandbox/doc-1" {
		t.Errorf("document_uri = %q", v.DocumentURI)
	}
	// Must NOT enter the review queue yet — fee not captured.
	if v.Status != kyc.StatusPending {
		t.Errorf("status = %q, want pending (review-queue entry is fee-gated)", v.Status)
	}
	if v.Version <= prevVersion {
		t.Errorf("version not bumped: got %d want > %d", v.Version, prevVersion)
	}
	// Audit trail records the attach.
	var found bool
	for _, a := range v.AuditLog {
		if a.Event == "document_attached" {
			found = true
		}
	}
	if !found {
		t.Errorf("audit log missing document_attached entry: %+v", v.AuditLog)
	}
}

func TestAttachPendingDocument_EmptyURIRejected(t *testing.T) {
	t.Parallel()
	v := newPendingManual(t)
	if err := v.AttachPendingDocument("   "); err == nil {
		t.Fatalf("expected error for empty uri")
	}
}

func TestAttachPendingDocument_IdempotentOnSameURI(t *testing.T) {
	t.Parallel()
	v := newPendingManual(t)
	if err := v.AttachPendingDocument("gs://chora-kyc-sandbox/doc-1"); err != nil {
		t.Fatalf("first attach: %v", err)
	}
	versionAfterFirst := v.Version
	if err := v.AttachPendingDocument("gs://chora-kyc-sandbox/doc-1"); err != nil {
		t.Fatalf("idempotent re-attach: %v", err)
	}
	if v.Version != versionAfterFirst {
		t.Errorf("idempotent re-attach bumped version: got %d want %d", v.Version, versionAfterFirst)
	}
}

func TestAttachPendingDocument_RejectedAfterSubmit(t *testing.T) {
	t.Parallel()
	v := newPendingManual(t)
	if err := v.Submit("gs://chora-kyc-sandbox/doc-1", 999, "USD"); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if err := v.AttachPendingDocument("gs://chora-kyc-sandbox/doc-2"); err == nil {
		t.Fatalf("expected error attaching after submit")
	}
}

// After fee capture the subscriber transitions pending → submitted via the
// existing Submit() with the captured fee, mirroring the live flow.
func TestPendingThenSubmit_EntersReviewQueue(t *testing.T) {
	t.Parallel()
	v := newPendingManual(t)
	if err := v.AttachPendingDocument("gs://chora-kyc-sandbox/doc-1"); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if err := v.Submit(v.DocumentURI, 999, "USD"); err != nil {
		t.Fatalf("Submit after capture: %v", err)
	}
	if v.Status != kyc.StatusSubmitted {
		t.Errorf("status = %q, want submitted", v.Status)
	}
	if v.FeeChargedCents != 999 {
		t.Errorf("fee_charged_cents = %d, want 999", v.FeeChargedCents)
	}
}
