// Cross-tenant Transfer aggregate — one record per (gcid, source -> dest)
// transfer request per ADR-133.
package portability

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// -----------------------------------------------------------------------------
// TransferStatus enum
// -----------------------------------------------------------------------------

type TransferStatus string

const (
	TransferStatusPending   TransferStatus = "pending"
	TransferStatusCompleted TransferStatus = "completed"
	TransferStatusFailed    TransferStatus = "failed"
)

// -----------------------------------------------------------------------------
// Transfer aggregate
// -----------------------------------------------------------------------------

// Transfer captures a cross-tenant authoritative-tenant move for a GCID. The
// GCID itself is not changed (per ADR-133 GCID is opaque + cross-tenant
// portable); the transfer is a record of the new authoritative tenant.
type Transfer struct {
	TransferID          string         `json:"transfer_id"`
	Gcid                string         `json:"gcid"`
	SourceTenantID      string         `json:"source_tenant_id"`
	DestinationTenantID string         `json:"destination_tenant_id"`
	Status              TransferStatus `json:"status"`
	Reason              string         `json:"reason,omitempty"`
	RequestedByGcid     string         `json:"requested_by_gcid"`
	RequestedAt         time.Time      `json:"requested_at"`
	CompletedAt         time.Time      `json:"completed_at,omitempty"`
}

// NewTransferParams is the constructor input.
type NewTransferParams struct {
	Gcid                string
	SourceTenantID      string
	DestinationTenantID string
	Reason              string
	RequestedByGcid     string
}

// NewTransfer constructs a Transfer in `pending` status. Returns an error if
// invariants are violated:
//   - Gcid empty or AGID-shaped (per ddd-enforcement aggregate invariant #10).
//   - Source / destination tenant empty.
//   - Source == destination.
func NewTransfer(p NewTransferParams) (*Transfer, error) {
	gcid := strings.TrimSpace(p.Gcid)
	if gcid == "" {
		return nil, errors.New("gcid is required")
	}
	if isAGID(gcid) {
		return nil, errors.New("AGID cannot be transferred (agents have no tenant authority)")
	}
	src := strings.TrimSpace(p.SourceTenantID)
	dst := strings.TrimSpace(p.DestinationTenantID)
	if src == "" {
		return nil, errors.New("source_tenant_id is required")
	}
	if dst == "" {
		return nil, errors.New("destination_tenant_id is required")
	}
	if src == dst {
		return nil, errors.New("source and destination tenants must differ")
	}
	requestedBy := strings.TrimSpace(p.RequestedByGcid)
	if requestedBy == "" {
		return nil, errors.New("requested_by_gcid is required")
	}

	id, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("uuidv7: %w", err)
	}
	return &Transfer{
		TransferID:          id.String(),
		Gcid:                gcid,
		SourceTenantID:      src,
		DestinationTenantID: dst,
		Status:              TransferStatusPending,
		Reason:              strings.TrimSpace(p.Reason),
		RequestedByGcid:     requestedBy,
		RequestedAt:         time.Now().UTC(),
	}, nil
}

// Complete transitions a pending Transfer to `completed`. Idempotent — a
// second call on a completed transfer is a no-op (CompletedAt preserved).
// Returns an error if the transfer is in a terminal-but-not-completed state.
func (tr *Transfer) Complete() error {
	switch tr.Status {
	case TransferStatusCompleted:
		return nil // idempotent
	case TransferStatusFailed:
		return errors.New("transfer in failed state cannot be completed")
	}
	tr.Status = TransferStatusCompleted
	tr.CompletedAt = time.Now().UTC()
	return nil
}

// Fail transitions a pending Transfer to `failed`. Used by the (future)
// downstream eligibility checker (e.g. destination tenant rejected the
// transfer). One-shot transition — completed transfers cannot fail.
func (tr *Transfer) Fail(reason string) error {
	if tr.Status == TransferStatusCompleted {
		return errors.New("completed transfer cannot fail")
	}
	if tr.Status == TransferStatusFailed {
		return nil // idempotent
	}
	tr.Status = TransferStatusFailed
	tr.Reason = strings.TrimSpace(reason)
	return nil
}
