// importjob.go — the P1 ImportJob aggregate + state machine (CHO-2021,
// ADR-221 D1/D4; CR §5.3/§5.6). Enums mirror migration 0029 EXACTLY
// (import_run_mode / import_materialization_mode / import_job_state /
// import_row_outcome) so the pg layer serialises without translation.
//
// The job is the aggregate root for one CSV upload: it owns the dry-run →
// confirm → chunked-execution lifecycle. Row-level state lives in the
// import_job_rows ledger (persisted by the repo), NOT here — this type carries
// the roll-up counts + the pod-death checkpoint.
//
// This file is PURE DOMAIN: no infra, no gRPC, no SQL. The tenant-existence
// resolution + email→GCID lookup + writes live in the application service.
package tenantimport

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// NilUUID is the operator home scope: operator-run jobs (create_new /
// existing_only) are NOT owned by a concrete tenant, so they home at the
// all-zero UUID and are visible only under the RLS sentinel GUC
// chora.tenant_id = 'platform' (0029:93, :150-159).
const NilUUID = "00000000-0000-0000-0000-000000000000"

// RunMode is the import run mode (import_run_mode, 0029:56-57).
type RunMode string

const (
	RunModeOperatorCreateNew    RunMode = "operator_create_new"
	RunModeOperatorExistingOnly RunMode = "operator_existing_only"
	RunModeTenantAdmin          RunMode = "tenant_admin"
	RunModeSync                 RunMode = "sync"
)

// Valid reports whether m is a known run mode.
func (m RunMode) Valid() bool {
	switch m {
	case RunModeOperatorCreateNew, RunModeOperatorExistingOnly, RunModeTenantAdmin, RunModeSync:
		return true
	}
	return false
}

// IsOperator reports whether m is an operator (cross-tenant) run mode — these
// home at the nil-uuid scope; tenant_admin/sync bind to a concrete tenant.
func (m RunMode) IsOperator() bool {
	return m == RunModeOperatorCreateNew || m == RunModeOperatorExistingOnly
}

// MaterializationMode is how a validated row becomes a principal
// (import_materialization_mode, 0029:64-65). P1 supports cold_invite only;
// synthetic / synthetic_login are P4 / P5.
type MaterializationMode string

const (
	MaterializationColdInvite     MaterializationMode = "cold_invite"
	MaterializationSynthetic      MaterializationMode = "synthetic"
	MaterializationSyntheticLogin MaterializationMode = "synthetic_login"
)

// Valid reports whether m is a known materialization mode.
func (m MaterializationMode) Valid() bool {
	switch m {
	case MaterializationColdInvite, MaterializationSynthetic, MaterializationSyntheticLogin:
		return true
	}
	return false
}

// State is the ImportJob lifecycle state (import_job_state, 0029:72-77).
type State string

const (
	StateValidating          State = "validating"
	StateAwaitingConfirm     State = "awaiting_confirm"
	StateRunning             State = "running"
	StateCompleted           State = "completed"
	StateCompletedWithErrors State = "completed_with_errors"
	StateFailed              State = "failed"
	StateCancelled           State = "cancelled"
)

// IsActive reports whether the job is still in flight (blocks a new job for the
// same actor — M-7, 0029:123-126).
func (s State) IsActive() bool {
	switch s {
	case StateValidating, StateAwaitingConfirm, StateRunning:
		return true
	}
	return false
}

// IsTerminal reports whether the job has reached a final state.
func (s State) IsTerminal() bool { return !s.IsActive() }

// RowOutcome is the per-row execution result (import_row_outcome, 0029:81-83).
type RowOutcome string

const (
	OutcomeCreatedTenant RowOutcome = "created_tenant"
	OutcomeInvited       RowOutcome = "invited"
	OutcomeGranted       RowOutcome = "granted"
	OutcomeMerged        RowOutcome = "merged"
	OutcomeMinted        RowOutcome = "minted"
	OutcomeSkipped       RowOutcome = "skipped"
	OutcomeError         RowOutcome = "error"
)

// OutcomeCounts is the ImportOutcomeCounts projection (counts_jsonb, 0029:110).
// Total() must reconcile to executed rows (AC-1).
type OutcomeCounts struct {
	CreatedTenants int `json:"created_tenants"`
	Invited        int `json:"invited"`
	Granted        int `json:"granted"`
	Merged         int `json:"merged"`
	Minted         int `json:"minted"`
	Skipped        int `json:"skipped"`
	Errored        int `json:"errored"`
}

// Total is the sum across all outcome buckets.
func (c OutcomeCounts) Total() int {
	return c.CreatedTenants + c.Invited + c.Granted + c.Merged + c.Minted + c.Skipped + c.Errored
}

// ValidationSummary is the dry-run roll-up the validator produces, applied to
// the job at the validating→awaiting_confirm transition.
type ValidationSummary struct {
	TotalRows   int
	ValidRows   int
	ErrorRows   int
	TenantCount int
	Delimiter   string // M-1 echo (',' | ';' | 'TAB')
}

// ImportJob is the aggregate root for one CSV mass-import.
type ImportJob struct {
	JobID               string
	TenantID            string // concrete tenant | NilUUID (operator)
	ImportBatchID       string
	ActorGCID           string
	RunMode             RunMode
	MaterializationMode MaterializationMode
	SendInvites         bool
	State               State
	SourceFilename      string
	SourceBytes         int64
	GCSObject           string
	DetectedDelimiter   string
	TotalRows           int
	ValidRows           int
	ErrorRows           int
	TenantCount         int
	ProcessedRows       int
	LastProcessedRow    int
	Counts              OutcomeCounts
	FailureReason       string
	StartedAt           *time.Time
	CompletedAt         *time.Time
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// NewImportJobParams is the constructor input.
type NewImportJobParams struct {
	ActorGCID           string
	TenantID            string // required for tenant_admin/sync; ignored for operator modes (→ NilUUID)
	RunMode             RunMode
	MaterializationMode MaterializationMode // "" → cold_invite
	SendInvites         bool
	SourceFilename      string
	SourceBytes         int64
}

// NewImportJob constructs a fresh job in the validating state, minting a
// UUIDv7 job_id + a distinct import_batch_id (0029:94 NOT NULL — even
// cold_invite, which never writes import_batch_members, needs a batch handle).
func NewImportJob(p NewImportJobParams) (*ImportJob, error) {
	if p.ActorGCID == "" {
		return nil, errors.New("actor_gcid is required")
	}
	if !p.RunMode.Valid() {
		return nil, fmt.Errorf("invalid run_mode: %q", string(p.RunMode))
	}
	mat := p.MaterializationMode
	if mat == "" {
		mat = MaterializationColdInvite
	}
	if !mat.Valid() {
		return nil, fmt.Errorf("invalid materialization_mode: %q", string(p.MaterializationMode))
	}

	tenantID := p.TenantID
	if p.RunMode.IsOperator() {
		// Operator jobs are cross-tenant — home scope is the nil-uuid (any
		// passed tenant is ignored; the target tenant lives per-row).
		tenantID = NilUUID
	} else if tenantID == "" {
		return nil, fmt.Errorf("tenant_id is required for run_mode %q", string(p.RunMode))
	}

	jobID, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("uuidv7 job_id: %w", err)
	}
	batchID, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("uuidv7 import_batch_id: %w", err)
	}
	now := time.Now().UTC()
	return &ImportJob{
		JobID:               jobID.String(),
		TenantID:            tenantID,
		ImportBatchID:       batchID.String(),
		ActorGCID:           p.ActorGCID,
		RunMode:             p.RunMode,
		MaterializationMode: mat,
		SendInvites:         p.SendInvites,
		State:               StateValidating,
		SourceFilename:      p.SourceFilename,
		SourceBytes:         p.SourceBytes,
		CreatedAt:           now,
		UpdatedAt:           now,
	}, nil
}

// MarkValidated records the dry-run result and advances validating →
// awaiting_confirm. Nothing has been written to tenancy/invites yet — the
// operator must :confirm. Legal only from validating.
func (j *ImportJob) MarkValidated(s ValidationSummary) error {
	if j.State != StateValidating {
		return fmt.Errorf("cannot mark validated from state %q", j.State)
	}
	j.TotalRows = s.TotalRows
	j.ValidRows = s.ValidRows
	j.ErrorRows = s.ErrorRows
	j.TenantCount = s.TenantCount
	j.DetectedDelimiter = s.Delimiter
	j.State = StateAwaitingConfirm
	j.UpdatedAt = time.Now().UTC()
	return nil
}

// MarkFailed drives the job to failed (whole-file reject at validation, or a
// system failure mid-run). Legal from any active state.
func (j *ImportJob) MarkFailed(reason string) error {
	if j.State.IsTerminal() {
		return fmt.Errorf("cannot fail a terminal job (state %q)", j.State)
	}
	now := time.Now().UTC()
	j.State = StateFailed
	j.FailureReason = reason
	j.CompletedAt = &now
	j.UpdatedAt = now
	return nil
}

// Confirm advances awaiting_confirm → running (the operator committed to the
// dry-run). The caller MUST emit the governance audit event BEFORE the first
// write (IMDA-D1). Legal only from awaiting_confirm.
func (j *ImportJob) Confirm() error {
	if j.State != StateAwaitingConfirm {
		return fmt.Errorf("cannot confirm from state %q (need awaiting_confirm)", j.State)
	}
	now := time.Now().UTC()
	j.State = StateRunning
	j.StartedAt = &now
	j.UpdatedAt = now
	return nil
}

// MarkCompleted drives running → completed (clean) or completed_with_errors
// (≥1 errored row). Legal only from running.
func (j *ImportJob) MarkCompleted(counts OutcomeCounts) error {
	if j.State != StateRunning {
		return fmt.Errorf("cannot complete from state %q (need running)", j.State)
	}
	now := time.Now().UTC()
	j.Counts = counts
	j.ProcessedRows = counts.Total()
	if counts.Errored > 0 {
		j.State = StateCompletedWithErrors
	} else {
		j.State = StateCompleted
	}
	j.CompletedAt = &now
	j.UpdatedAt = now
	return nil
}

// Cancel drives any active job → cancelled (honoured at the next chunk
// boundary; already-committed rows stay committed). Legal from active states.
func (j *ImportJob) Cancel() error {
	if j.State.IsTerminal() {
		return fmt.Errorf("cannot cancel a terminal job (state %q)", j.State)
	}
	now := time.Now().UTC()
	j.State = StateCancelled
	j.CompletedAt = &now
	j.UpdatedAt = now
	return nil
}

// Checkpoint records chunk progress for pod-death resume (D4): the last CSV
// line finished + the running outcome counts. No state change.
func (j *ImportJob) Checkpoint(lastProcessedRow, processedRows int, counts OutcomeCounts) {
	j.LastProcessedRow = lastProcessedRow
	j.ProcessedRows = processedRows
	j.Counts = counts
	j.UpdatedAt = time.Now().UTC()
}
