// Saga aggregate — the federated account closure saga's per-user state.
//
// The Saga is the aggregate root. History is append-only (an event log of
// every transition for audit). TokenisedFields records which fields the
// PSEUDONYMIZED transition has tokenised (registry input for the future
// per-domain `PII_Closure_Map.yaml` projection).
//
// Per ddd-enforcement aggregate invariant #10: AGIDs cannot own a closure
// saga (agents do not have lifecycle).
package closure

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// -----------------------------------------------------------------------------
// PII classification — used for `PII_Closure_Map.yaml` registry input.
// -----------------------------------------------------------------------------

// PIIClass tags the sensitivity of a tokenised field. Aligned with the
// crypto package's PIIClass for shared vocabulary (low / medium / high /
// critical) per Tier 3 D11.
type PIIClass string

const (
	PIIClassLow      PIIClass = "low"
	PIIClassMedium   PIIClass = "medium"
	PIIClassHigh     PIIClass = "high"
	PIIClassCritical PIIClass = "critical"
)

// TokenisedField records that a particular field has been tokenised (replaced
// with a deterministic pseudonym) during the PSEUDONYMIZED transition.
type TokenisedField struct {
	Name  string   `json:"name"`
	Class PIIClass `json:"class"`
}

// -----------------------------------------------------------------------------
// History entry — append-only audit of every state transition.
// -----------------------------------------------------------------------------

// HistoryEntry records a single saga transition. Append-only; never mutated.
type HistoryEntry struct {
	PriorState     State     `json:"prior_state"`
	NewState       State     `json:"new_state"`
	Reason         string    `json:"reason"`
	ActorGcid      string    `json:"actor_gcid"`
	TransitionedAt time.Time `json:"transitioned_at"`
}

// -----------------------------------------------------------------------------
// Saga aggregate root
// -----------------------------------------------------------------------------

// Saga is the closure saga aggregate root. One per (gcid, request lifecycle).
// New requests after a CRYPTO_SHREDDED terminal state would require fresh
// account registration (new GCID), but that is out-of-scope for this MVP.
type Saga struct {
	SagaID          string           `json:"saga_id"`
	Gcid            string           `json:"gcid"`
	TenantID        string           `json:"tenant_id"`
	State           State            `json:"state"`
	Reason          string           `json:"reason"`
	RequestedByGcid string           `json:"requested_by_gcid"`
	GracePeriodDays int              `json:"grace_period_days"`
	RequestedAt     time.Time        `json:"requested_at"`
	GraceEndsAt     time.Time        `json:"grace_ends_at"`
	CancelledAt     time.Time        `json:"cancelled_at,omitempty"`
	UpdatedAt       time.Time        `json:"updated_at"`
	History         []HistoryEntry   `json:"history"`
	TokenisedFields []TokenisedField `json:"tokenised_fields,omitempty"`
}

// NewSagaParams is the constructor input.
type NewSagaParams struct {
	Gcid            string
	TenantID        string
	GracePeriodDays int
	Reason          string
	RequestedByGcid string
}

// NewSaga constructs a Saga in the CLOSING state with the requested grace
// window. Returns an error if invariants are violated:
//
//   - Gcid empty or AGID-shaped (per ddd-enforcement aggregate invariant #10).
//   - TenantID empty.
//   - GracePeriodDays not in [1, 365].
func NewSaga(p NewSagaParams) (*Saga, error) {
	gcid := strings.TrimSpace(p.Gcid)
	if gcid == "" {
		return nil, errors.New("gcid is required")
	}
	if isAGID(gcid) {
		return nil, errors.New("AGID cannot own a closure saga (agents have no lifecycle)")
	}
	tenant := strings.TrimSpace(p.TenantID)
	if tenant == "" {
		return nil, errors.New("tenant_id is required")
	}
	if p.GracePeriodDays < 1 {
		return nil, fmt.Errorf("grace_period_days must be >= 1; got %d", p.GracePeriodDays)
	}
	if p.GracePeriodDays > 365 {
		return nil, fmt.Errorf("grace_period_days must be <= 365; got %d", p.GracePeriodDays)
	}
	requestedBy := strings.TrimSpace(p.RequestedByGcid)
	if requestedBy == "" {
		return nil, errors.New("requested_by_gcid is required")
	}

	id, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("uuidv7: %w", err)
	}
	now := time.Now().UTC()
	graceEnds := now.Add(time.Duration(p.GracePeriodDays) * 24 * time.Hour)

	s := &Saga{
		SagaID:          id.String(),
		Gcid:            gcid,
		TenantID:        tenant,
		State:           StateClosing,
		Reason:          strings.TrimSpace(p.Reason),
		RequestedByGcid: requestedBy,
		GracePeriodDays: p.GracePeriodDays,
		RequestedAt:     now,
		GraceEndsAt:     graceEnds,
		UpdatedAt:       now,
		History: []HistoryEntry{
			{
				PriorState:     StateActive,
				NewState:       StateClosing,
				Reason:         strings.TrimSpace(p.Reason),
				ActorGcid:      requestedBy,
				TransitionedAt: now,
			},
		},
		TokenisedFields: []TokenisedField{},
	}
	return s, nil
}

// Advance transitions the saga to `to`, validating the transition through
// the state machine table. Returns ErrInvalidTransition for forbidden moves.
//
// Cancel-during-grace (CLOSING -> ACTIVE) goes through Cancel(), not Advance().
func (s *Saga) Advance(to State, reason, actorGcid string) error {
	if !to.Valid() {
		return fmt.Errorf("%w: unknown state %q", ErrInvalidTransition, string(to))
	}
	if !CanTransition(s.State, to) {
		return fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, s.State, to)
	}
	now := time.Now().UTC()
	s.History = append(s.History, HistoryEntry{
		PriorState:     s.State,
		NewState:       to,
		Reason:         strings.TrimSpace(reason),
		ActorGcid:      strings.TrimSpace(actorGcid),
		TransitionedAt: now,
	})
	s.State = to
	s.UpdatedAt = now
	return nil
}

// Cancel reverts a saga in CLOSING back to ACTIVE. Returns ErrCancelTooLate
// if the saga has progressed past CLOSING.
func (s *Saga) Cancel(reason, actorGcid string) error {
	if !IsCancellable(s.State) {
		return fmt.Errorf("%w: state=%s", ErrCancelTooLate, s.State)
	}
	now := time.Now().UTC()
	s.History = append(s.History, HistoryEntry{
		PriorState:     s.State,
		NewState:       StateActive,
		Reason:         strings.TrimSpace(reason),
		ActorGcid:      strings.TrimSpace(actorGcid),
		TransitionedAt: now,
	})
	s.State = StateActive
	s.CancelledAt = now
	s.UpdatedAt = now
	return nil
}

// IsTerminal reports whether the saga has reached a terminal state.
func (s *Saga) IsTerminal() bool {
	return IsTerminalState(s.State)
}

// GraceExpiredAt reports whether the grace window has elapsed at the given
// instant. Pure function on the saga's clock fields — caller controls the
// "now" instant for testability.
func (s *Saga) GraceExpiredAt(now time.Time) bool {
	return now.After(s.GraceEndsAt)
}

// RecordTokenisedField appends a tokenisation marker to the saga audit. Used
// by the PSEUDONYMIZED transition to log which fields the per-domain
// PII_Closure_Map subscribers tokenised.
func (s *Saga) RecordTokenisedField(name string, class PIIClass) {
	s.TokenisedFields = append(s.TokenisedFields, TokenisedField{
		Name:  strings.TrimSpace(name),
		Class: class,
	})
}

// -----------------------------------------------------------------------------
// AGID detection — duplicated from identity package to keep this package
// dependency-free. Production wiring will swap to a single source.
// -----------------------------------------------------------------------------

func isAGID(id string) bool {
	if id == "" {
		return false
	}
	return strings.HasPrefix(strings.ToLower(id), "0197a")
}
