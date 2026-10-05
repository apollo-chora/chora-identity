// Package portability_test exercises GCID portability — full identity profile
// export (GDPR Art. 20) + cross-tenant transfer + signed proof verification.
//
// Per BP-01 (Learner Ownership) + DP-04 (Data Portability) + ADR-133.
//
// TDD RED: these tests assume implementation does NOT yet exist.
package portability_test

import (
	"strings"
	"testing"
	"time"

	"github.com/apollo-chora/chora-identity/internal/domain/portability"
)

const (
	gcidA   = "01970000-0000-7000-9000-000000000001"
	gcidB   = "01970000-0000-7000-9000-000000000002"
	agidX   = "0197A000-0000-7000-9000-000000000001"
	tenantA = "01970000-0000-7000-8000-000000000001"
	tenantB = "01970000-0000-7000-8000-000000000002"
)

// -----------------------------------------------------------------------------
// Identity export — GDPR Art. 20.
// -----------------------------------------------------------------------------

func TestNewExport_BuildsFullProfile(t *testing.T) {
	t.Parallel()
	e, err := portability.NewExport(portability.NewExportParams{
		Gcid:        gcidA,
		Email:       "alice@chora.dev",
		DisplayName: "Alice",
		RoleHistory: []portability.RoleHistoryEntry{
			{TenantID: tenantA, Role: "learner", AssignedAt: time.Now().Add(-30 * 24 * time.Hour)},
			{TenantID: tenantA, Role: "instructor", AssignedAt: time.Now().Add(-7 * 24 * time.Hour)},
		},
		TenantHistory: []portability.TenantHistoryEntry{
			{TenantID: tenantA, JoinedAt: time.Now().Add(-30 * 24 * time.Hour)},
			{TenantID: tenantB, JoinedAt: time.Now().Add(-1 * 24 * time.Hour)},
		},
		AuditTrailPointer: "gs://chora-audit/" + gcidA + ".jsonl",
	})
	if err != nil {
		t.Fatalf("NewExport: %v", err)
	}
	if e.ExportID == "" {
		t.Errorf("ExportID empty")
	}
	if e.Gcid != gcidA {
		t.Errorf("Gcid mismatch")
	}
	if e.Email != "alice@chora.dev" {
		t.Errorf("Email mismatch")
	}
	if e.DisplayName != "Alice" {
		t.Errorf("DisplayName mismatch")
	}
	if len(e.RoleHistory) != 2 {
		t.Errorf("RoleHistory size=%d; want 2", len(e.RoleHistory))
	}
	if len(e.TenantHistory) != 2 {
		t.Errorf("TenantHistory size=%d; want 2", len(e.TenantHistory))
	}
	if e.AuditTrailPointer == "" {
		t.Errorf("AuditTrailPointer empty")
	}
	if e.GeneratedAt.IsZero() {
		t.Errorf("GeneratedAt zero")
	}
}

func TestNewExport_RejectsAGID(t *testing.T) {
	t.Parallel()
	_, err := portability.NewExport(portability.NewExportParams{
		Gcid:  agidX,
		Email: "agent@chora.dev",
	})
	if err == nil {
		t.Errorf("expected error rejecting AGID; got nil")
	}
}

func TestNewExport_RejectsEmptyGcid(t *testing.T) {
	t.Parallel()
	_, err := portability.NewExport(portability.NewExportParams{
		Gcid: "",
	})
	if err == nil {
		t.Errorf("expected error for empty gcid")
	}
}

// -----------------------------------------------------------------------------
// Transfer — cross-tenant move (ADR-133 GCID portability).
// -----------------------------------------------------------------------------

func TestNewTransfer_BuildsValidRecord(t *testing.T) {
	t.Parallel()
	tr, err := portability.NewTransfer(portability.NewTransferParams{
		Gcid:                gcidA,
		SourceTenantID:      tenantA,
		DestinationTenantID: tenantB,
		Reason:              "graduation_to_university",
		RequestedByGcid:     gcidA,
	})
	if err != nil {
		t.Fatalf("NewTransfer: %v", err)
	}
	if tr.TransferID == "" {
		t.Errorf("TransferID empty")
	}
	if tr.Gcid != gcidA {
		t.Errorf("Gcid mismatch")
	}
	if tr.SourceTenantID != tenantA {
		t.Errorf("SourceTenantID mismatch")
	}
	if tr.DestinationTenantID != tenantB {
		t.Errorf("DestinationTenantID mismatch")
	}
	if tr.Status != portability.TransferStatusPending {
		t.Errorf("Status=%q; want pending", tr.Status)
	}
	if tr.RequestedAt.IsZero() {
		t.Errorf("RequestedAt zero")
	}
}

func TestNewTransfer_RejectsSameTenants(t *testing.T) {
	t.Parallel()
	_, err := portability.NewTransfer(portability.NewTransferParams{
		Gcid:                gcidA,
		SourceTenantID:      tenantA,
		DestinationTenantID: tenantA,
		RequestedByGcid:     gcidA,
	})
	if err == nil {
		t.Errorf("expected error for same source+destination tenant")
	}
}

func TestNewTransfer_RejectsAGID(t *testing.T) {
	t.Parallel()
	_, err := portability.NewTransfer(portability.NewTransferParams{
		Gcid:                agidX,
		SourceTenantID:      tenantA,
		DestinationTenantID: tenantB,
		RequestedByGcid:     agidX,
	})
	if err == nil {
		t.Errorf("expected error rejecting AGID transfer")
	}
}

func TestNewTransfer_RejectsEmptyTenants(t *testing.T) {
	t.Parallel()
	_, err := portability.NewTransfer(portability.NewTransferParams{
		Gcid:                gcidA,
		SourceTenantID:      "",
		DestinationTenantID: tenantB,
		RequestedByGcid:     gcidA,
	})
	if err == nil {
		t.Errorf("expected error for empty source tenant")
	}
	_, err = portability.NewTransfer(portability.NewTransferParams{
		Gcid:                gcidA,
		SourceTenantID:      tenantA,
		DestinationTenantID: "",
		RequestedByGcid:     gcidA,
	})
	if err == nil {
		t.Errorf("expected error for empty destination tenant")
	}
}

func TestTransfer_Complete_TransitionsStatus(t *testing.T) {
	t.Parallel()
	tr, err := portability.NewTransfer(portability.NewTransferParams{
		Gcid:                gcidA,
		SourceTenantID:      tenantA,
		DestinationTenantID: tenantB,
		RequestedByGcid:     gcidA,
	})
	if err != nil {
		t.Fatalf("NewTransfer: %v", err)
	}
	if err := tr.Complete(); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if tr.Status != portability.TransferStatusCompleted {
		t.Errorf("Status=%q; want completed", tr.Status)
	}
	if tr.CompletedAt.IsZero() {
		t.Errorf("CompletedAt zero")
	}
}

func TestTransfer_Complete_IdempotentSecondCallNoop(t *testing.T) {
	t.Parallel()
	tr, _ := portability.NewTransfer(portability.NewTransferParams{
		Gcid:                gcidA,
		SourceTenantID:      tenantA,
		DestinationTenantID: tenantB,
		RequestedByGcid:     gcidA,
	})
	_ = tr.Complete()
	first := tr.CompletedAt
	_ = tr.Complete() // second call
	if !tr.CompletedAt.Equal(first) {
		t.Errorf("Complete should be idempotent; CompletedAt mutated")
	}
}

// -----------------------------------------------------------------------------
// Proof signing + verification (HMAC-SHA256 per spec).
// -----------------------------------------------------------------------------

func TestProof_SignAndVerify_RoundTrip(t *testing.T) {
	t.Parallel()
	secret := []byte("portability-stub-secret-key-do-not-use-in-prod")
	sig, err := portability.SignProof(secret, gcidA, "export:1")
	if err != nil {
		t.Fatalf("SignProof: %v", err)
	}
	if sig == "" {
		t.Errorf("signature empty")
	}
	if !portability.VerifyProof(secret, gcidA, "export:1", sig) {
		t.Errorf("VerifyProof false; want true (round-trip)")
	}
}

func TestProof_VerifyRejectsTamperedPayload(t *testing.T) {
	t.Parallel()
	secret := []byte("portability-stub-secret-key-do-not-use-in-prod")
	sig, _ := portability.SignProof(secret, gcidA, "export:1")
	if portability.VerifyProof(secret, gcidA, "export:2", sig) {
		t.Errorf("verifier accepted tampered payload")
	}
}

func TestProof_VerifyRejectsBadSecret(t *testing.T) {
	t.Parallel()
	sig, _ := portability.SignProof([]byte("good-secret"), gcidA, "export:1")
	if portability.VerifyProof([]byte("bad-secret"), gcidA, "export:1", sig) {
		t.Errorf("verifier accepted wrong-secret signature")
	}
}

func TestProof_VerifyRejectsMalformedSignature(t *testing.T) {
	t.Parallel()
	if portability.VerifyProof([]byte("k"), gcidA, "p", "not-base64-or-hex??") {
		t.Errorf("verifier accepted malformed signature")
	}
	if portability.VerifyProof([]byte("k"), gcidA, "p", "") {
		t.Errorf("verifier accepted empty signature")
	}
}

func TestProof_SignRejectsEmptySecret(t *testing.T) {
	t.Parallel()
	if _, err := portability.SignProof(nil, gcidA, "p"); err == nil {
		t.Errorf("expected error for empty secret")
	}
}

func TestProof_SignRejectsEmptyGcid(t *testing.T) {
	t.Parallel()
	if _, err := portability.SignProof([]byte("k"), "", "p"); err == nil {
		t.Errorf("expected error for empty gcid")
	}
}

func TestProof_VerifyEmptySecretReturnsFalse(t *testing.T) {
	t.Parallel()
	// Sign a known-good signature, then pass empty secret to verify.
	sig, _ := portability.SignProof([]byte("k"), gcidA, "p")
	if portability.VerifyProof(nil, gcidA, "p", sig) {
		t.Errorf("verifier accepted empty secret")
	}
}

// -----------------------------------------------------------------------------
// Transfer.Fail covers the failed transition path.
// -----------------------------------------------------------------------------

func TestTransfer_Fail_TransitionsAndIdempotent(t *testing.T) {
	t.Parallel()
	tr, _ := portability.NewTransfer(portability.NewTransferParams{
		Gcid:                gcidA,
		SourceTenantID:      tenantA,
		DestinationTenantID: tenantB,
		RequestedByGcid:     gcidA,
	})
	if err := tr.Fail("destination_rejected"); err != nil {
		t.Fatalf("Fail: %v", err)
	}
	if tr.Status != portability.TransferStatusFailed {
		t.Errorf("Status=%q; want failed", tr.Status)
	}
	// Idempotent.
	if err := tr.Fail("again"); err != nil {
		t.Errorf("Fail second call should be no-op; got %v", err)
	}
}

func TestTransfer_CompletedCannotFail(t *testing.T) {
	t.Parallel()
	tr, _ := portability.NewTransfer(portability.NewTransferParams{
		Gcid:                gcidA,
		SourceTenantID:      tenantA,
		DestinationTenantID: tenantB,
		RequestedByGcid:     gcidA,
	})
	_ = tr.Complete()
	if err := tr.Fail("late"); err == nil {
		t.Errorf("expected error failing a completed transfer")
	}
}

func TestTransfer_FailedCannotComplete(t *testing.T) {
	t.Parallel()
	tr, _ := portability.NewTransfer(portability.NewTransferParams{
		Gcid:                gcidA,
		SourceTenantID:      tenantA,
		DestinationTenantID: tenantB,
		RequestedByGcid:     gcidA,
	})
	_ = tr.Fail("rejected")
	if err := tr.Complete(); err == nil {
		t.Errorf("expected error completing a failed transfer")
	}
}

func TestNewTransfer_RejectsEmptyRequestedByGcid(t *testing.T) {
	t.Parallel()
	_, err := portability.NewTransfer(portability.NewTransferParams{
		Gcid:                gcidA,
		SourceTenantID:      tenantA,
		DestinationTenantID: tenantB,
		RequestedByGcid:     "",
	})
	if err == nil {
		t.Errorf("expected error for empty requested_by_gcid")
	}
}

// keep imports live
var _ = strings.HasPrefix
