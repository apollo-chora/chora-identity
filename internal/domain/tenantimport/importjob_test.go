// importjob_test.go — RED spec for the P1 ImportJob aggregate + state machine
// (CHO-2021). Strict-TDD: written before importjob.go. States/enums mirror
// migration 0029 (import_job_state / import_run_mode /
// import_materialization_mode / import_row_outcome).
package tenantimport

import (
	"testing"

	"github.com/google/uuid"
)

func TestNewImportJob_operatorExistingOnly_defaults(t *testing.T) {
	j, err := NewImportJob(NewImportJobParams{
		ActorGCID:      "00000000-0000-7000-8000-000000001999",
		RunMode:        RunModeOperatorExistingOnly,
		SourceFilename: "roster.csv",
		SourceBytes:    1234,
	})
	if err != nil {
		t.Fatalf("NewImportJob: unexpected error: %v", err)
	}
	if j.State != StateValidating {
		t.Errorf("state = %q, want validating", j.State)
	}
	// operator mode with no concrete tenant → nil-uuid home scope (0029:93).
	if j.TenantID != NilUUID {
		t.Errorf("tenant_id = %q, want nil-uuid %q", j.TenantID, NilUUID)
	}
	// materialization defaults to cold_invite (0029:97).
	if j.MaterializationMode != MaterializationColdInvite {
		t.Errorf("materialization = %q, want cold_invite", j.MaterializationMode)
	}
	if _, e := uuid.Parse(j.JobID); e != nil {
		t.Errorf("job_id not a uuid: %q (%v)", j.JobID, e)
	}
	// import_batch_id is NOT NULL (0029:94) — must be minted even for cold_invite.
	if _, e := uuid.Parse(j.ImportBatchID); e != nil {
		t.Errorf("import_batch_id not a uuid: %q (%v)", j.ImportBatchID, e)
	}
	if j.JobID == j.ImportBatchID {
		t.Error("job_id and import_batch_id must be distinct")
	}
}

func TestNewImportJob_tenantAdmin_concreteTenant(t *testing.T) {
	j, err := NewImportJob(NewImportJobParams{
		ActorGCID: "00000000-0000-7000-8000-000000001999",
		TenantID:  "11111111-1111-7111-8111-111111111111",
		RunMode:   RunModeTenantAdmin,
	})
	if err != nil {
		t.Fatalf("NewImportJob: %v", err)
	}
	if j.TenantID != "11111111-1111-7111-8111-111111111111" {
		t.Errorf("tenant_id = %q, want the concrete tenant", j.TenantID)
	}
}

func TestNewImportJob_invalid(t *testing.T) {
	cases := map[string]NewImportJobParams{
		"empty actor":      {RunMode: RunModeOperatorExistingOnly},
		"invalid run mode": {ActorGCID: "g", RunMode: RunMode("bogus")},
		"invalid material": {ActorGCID: "g", RunMode: RunModeOperatorExistingOnly, MaterializationMode: MaterializationMode("bogus")},
	}
	for name, p := range cases {
		if _, err := NewImportJob(p); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestImportJob_MarkValidated_toAwaitingConfirm(t *testing.T) {
	j := newTestJob(t)
	if err := j.MarkValidated(ValidationSummary{TotalRows: 100, ValidRows: 98, ErrorRows: 2, TenantCount: 3, Delimiter: ","}); err != nil {
		t.Fatalf("MarkValidated: %v", err)
	}
	if j.State != StateAwaitingConfirm {
		t.Errorf("state = %q, want awaiting_confirm", j.State)
	}
	if j.TotalRows != 100 || j.ValidRows != 98 || j.ErrorRows != 2 || j.TenantCount != 3 {
		t.Errorf("counts not persisted: %+v", j)
	}
	if j.DetectedDelimiter != "," {
		t.Errorf("delimiter = %q, want ,", j.DetectedDelimiter)
	}
}

func TestImportJob_MarkValidated_wrongState(t *testing.T) {
	j := newTestJob(t)
	_ = j.MarkFailed("boom") // now failed (terminal)
	if err := j.MarkValidated(ValidationSummary{}); err == nil {
		t.Error("MarkValidated from failed: expected error")
	}
}

func TestImportJob_MarkFailed(t *testing.T) {
	j := newTestJob(t)
	if err := j.MarkFailed("empty_file"); err != nil {
		t.Fatalf("MarkFailed from validating: %v", err)
	}
	if j.State != StateFailed || j.FailureReason != "empty_file" {
		t.Errorf("state=%q reason=%q, want failed/empty_file", j.State, j.FailureReason)
	}
	if j.CompletedAt == nil {
		t.Error("CompletedAt should be set on terminal transition")
	}
	// double-fail is rejected (already terminal).
	if err := j.MarkFailed("again"); err == nil {
		t.Error("MarkFailed from failed: expected error")
	}
}

func TestImportJob_Confirm_toRunning(t *testing.T) {
	j := newTestJob(t)
	_ = j.MarkValidated(ValidationSummary{TotalRows: 10, ValidRows: 10, TenantCount: 1})
	if err := j.Confirm(); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if j.State != StateRunning {
		t.Errorf("state = %q, want running", j.State)
	}
	if j.StartedAt == nil {
		t.Error("StartedAt should be set on Confirm")
	}
	// confirm is legal ONLY from awaiting_confirm.
	if err := j.Confirm(); err == nil {
		t.Error("Confirm from running: expected error")
	}
}

func TestImportJob_Confirm_wrongState(t *testing.T) {
	j := newTestJob(t) // still validating
	if err := j.Confirm(); err == nil {
		t.Error("Confirm from validating: expected error")
	}
}

func TestImportJob_MarkCompleted_cleanVsErrors(t *testing.T) {
	// clean → completed
	j := runningJob(t)
	if err := j.MarkCompleted(OutcomeCounts{Invited: 6, Granted: 4}); err != nil {
		t.Fatalf("MarkCompleted: %v", err)
	}
	if j.State != StateCompleted {
		t.Errorf("state = %q, want completed", j.State)
	}
	if j.CompletedAt == nil {
		t.Error("CompletedAt should be set")
	}
	// any errored row → completed_with_errors
	j2 := runningJob(t)
	if err := j2.MarkCompleted(OutcomeCounts{Invited: 5, Errored: 1}); err != nil {
		t.Fatalf("MarkCompleted (errors): %v", err)
	}
	if j2.State != StateCompletedWithErrors {
		t.Errorf("state = %q, want completed_with_errors", j2.State)
	}
}

func TestImportJob_MarkCompleted_wrongState(t *testing.T) {
	j := newTestJob(t) // validating, not running
	if err := j.MarkCompleted(OutcomeCounts{}); err == nil {
		t.Error("MarkCompleted from validating: expected error")
	}
}

func TestImportJob_Cancel(t *testing.T) {
	for _, mk := range []func(*testing.T) *ImportJob{
		func(t *testing.T) *ImportJob { return newTestJob(t) },                                                   // validating
		func(t *testing.T) *ImportJob { j := newTestJob(t); _ = j.MarkValidated(ValidationSummary{}); return j }, // awaiting_confirm
		func(t *testing.T) *ImportJob { return runningJob(t) },                                                   // running
	} {
		j := mk(t)
		if err := j.Cancel(); err != nil {
			t.Errorf("Cancel from %q: unexpected error %v", j.State, err)
			continue
		}
		if j.State != StateCancelled {
			t.Errorf("state = %q, want cancelled", j.State)
		}
	}
	// terminal → cannot cancel
	j := newTestJob(t)
	_ = j.MarkFailed("x")
	if err := j.Cancel(); err == nil {
		t.Error("Cancel from failed: expected error")
	}
}

func TestImportJob_Checkpoint(t *testing.T) {
	j := runningJob(t)
	j.Checkpoint(500, 500, OutcomeCounts{Invited: 500})
	if j.LastProcessedRow != 500 || j.ProcessedRows != 500 || j.Counts.Invited != 500 {
		t.Errorf("checkpoint not applied: %+v", j)
	}
}

func TestState_IsTerminalIsActive(t *testing.T) {
	active := []State{StateValidating, StateAwaitingConfirm, StateRunning}
	terminal := []State{StateCompleted, StateCompletedWithErrors, StateFailed, StateCancelled}
	for _, s := range active {
		if !s.IsActive() || s.IsTerminal() {
			t.Errorf("%q should be active, not terminal", s)
		}
	}
	for _, s := range terminal {
		if s.IsActive() || !s.IsTerminal() {
			t.Errorf("%q should be terminal, not active", s)
		}
	}
}

func TestOutcomeCounts_Total(t *testing.T) {
	c := OutcomeCounts{CreatedTenants: 1, Invited: 2, Granted: 3, Merged: 4, Minted: 5, Skipped: 6, Errored: 7}
	if c.Total() != 28 {
		t.Errorf("Total() = %d, want 28", c.Total())
	}
}

// --- helpers ---

func newTestJob(t *testing.T) *ImportJob {
	t.Helper()
	j, err := NewImportJob(NewImportJobParams{
		ActorGCID: "00000000-0000-7000-8000-000000001999",
		RunMode:   RunModeOperatorExistingOnly,
	})
	if err != nil {
		t.Fatalf("newTestJob: %v", err)
	}
	return j
}

func runningJob(t *testing.T) *ImportJob {
	t.Helper()
	j := newTestJob(t)
	if err := j.MarkValidated(ValidationSummary{TotalRows: 10, ValidRows: 10, TenantCount: 1}); err != nil {
		t.Fatalf("runningJob MarkValidated: %v", err)
	}
	if err := j.Confirm(); err != nil {
		t.Fatalf("runningJob Confirm: %v", err)
	}
	return j
}
