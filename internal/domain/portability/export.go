// Package portability is the GCID portability domain — full identity profile
// export (GDPR Art. 20) + cross-tenant transfer (ADR-133) + signed proof
// verification.
//
// Per BP-01 (Learner Ownership) + DP-04 (Data Portability):
//   - GET /me/portability/export   → full snapshot (export.go)
//   - POST /me/portability/transfer → cross-tenant move (transfer.go)
//   - GET /portability/proof       → public verification (proof.go)
//
// Hexagonal: this package is dependency-free w.r.t. infrastructure.
package portability

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// -----------------------------------------------------------------------------
// RoleHistoryEntry — one entry per role assignment over the user's lifetime.
// -----------------------------------------------------------------------------

type RoleHistoryEntry struct {
	TenantID   string    `json:"tenant_id"`
	Role       string    `json:"role"`
	AssignedAt time.Time `json:"assigned_at"`
	RevokedAt  time.Time `json:"revoked_at,omitempty"`
}

// -----------------------------------------------------------------------------
// TenantHistoryEntry — one entry per tenant the user has joined / left.
// -----------------------------------------------------------------------------

type TenantHistoryEntry struct {
	TenantID string    `json:"tenant_id"`
	JoinedAt time.Time `json:"joined_at"`
	LeftAt   time.Time `json:"left_at,omitempty"`
}

// -----------------------------------------------------------------------------
// Export aggregate — immutable snapshot of the user's full identity profile.
// -----------------------------------------------------------------------------

// Export is the GDPR Art. 20 portable snapshot. Per ddd-enforcement Aggregate
// Invariant #4 spirit (append-only): once constructed, an Export is not
// mutated; downstream callers receive a fresh export per request.
type Export struct {
	ExportID          string               `json:"export_id"`
	Gcid              string               `json:"gcid"`
	Email             string               `json:"email"`
	DisplayName       string               `json:"display_name,omitempty"`
	RoleHistory       []RoleHistoryEntry   `json:"role_history"`
	TenantHistory     []TenantHistoryEntry `json:"tenant_history"`
	AuditTrailPointer string               `json:"audit_trail_pointer,omitempty"`
	GeneratedAt       time.Time            `json:"generated_at"`
}

// NewExportParams is the constructor input.
type NewExportParams struct {
	Gcid              string
	Email             string
	DisplayName       string
	RoleHistory       []RoleHistoryEntry
	TenantHistory     []TenantHistoryEntry
	AuditTrailPointer string
}

// NewExport constructs a fresh portable identity Export. Returns an error if
// invariants are violated — empty / AGID-shaped Gcid.
func NewExport(p NewExportParams) (*Export, error) {
	gcid := strings.TrimSpace(p.Gcid)
	if gcid == "" {
		return nil, errors.New("gcid is required")
	}
	if isAGID(gcid) {
		return nil, errors.New("AGID cannot be exported as a portable identity")
	}

	id, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("uuidv7: %w", err)
	}
	roleHistory := append([]RoleHistoryEntry(nil), p.RoleHistory...)
	tenantHistory := append([]TenantHistoryEntry(nil), p.TenantHistory...)
	return &Export{
		ExportID:          id.String(),
		Gcid:              gcid,
		Email:             strings.TrimSpace(p.Email),
		DisplayName:       strings.TrimSpace(p.DisplayName),
		RoleHistory:       roleHistory,
		TenantHistory:     tenantHistory,
		AuditTrailPointer: strings.TrimSpace(p.AuditTrailPointer),
		GeneratedAt:       time.Now().UTC(),
	}, nil
}

// -----------------------------------------------------------------------------
// AGID detection — duplicated locally to keep this package dependency-free.
// -----------------------------------------------------------------------------

func isAGID(id string) bool {
	if id == "" {
		return false
	}
	return strings.HasPrefix(strings.ToLower(id), "0197a")
}
