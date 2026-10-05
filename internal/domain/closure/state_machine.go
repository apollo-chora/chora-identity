// Package closure is the federated account closure saga domain.
//
// Per ddd-enforcement (Account Closure section) + Tier 3 D11:
// 5-state machine `ACTIVE -> CLOSING (grace) -> SUSPENDED -> PSEUDONYMIZED ->
// COLD_ARCHIVED -> CRYPTO_SHREDDED`. Pseudonymise + crypto-shred — NEVER
// hard-delete (preserves FK integrity + audit trail + GDPR Art. 17).
//
// CLOSING -> ACTIVE is the ONLY backward transition (cancellation during
// grace). Once SUSPENDED is reached the saga is no longer cancellable; the
// path to CRYPTO_SHREDDED is one-way and per-step (each Pub/Sub event
// signalling a federated domain has acknowledged its pseudonymisation duty).
//
// CMEK per-tenant master key + per-user DEK; deleting the DEK = crypto-shred
// (data unrecoverable). Per-domain `PII_Closure_Map.yaml` declares
// fields-to-tokenize / retention / on-creator-closure behaviour.
//
// Hexagonal: this package is dependency-free w.r.t. infrastructure.
package closure

import "errors"

// -----------------------------------------------------------------------------
// State enum
// -----------------------------------------------------------------------------

// State is the closure saga's lifecycle state. Values match the protobuf
// `chora.identity.account.AccountState` wire enum (ACCOUNT_STATE_*) modulo
// the prefix; the protobuf is the canonical wire shape, this package's
// `State` is the Go-side typed enum.
type State string

const (
	StateActive         State = "active"
	StateClosing        State = "closing"
	StateSuspended      State = "suspended"
	StatePseudonymized  State = "pseudonymized"
	StateColdArchived   State = "cold_archived"
	StateCryptoShredded State = "crypto_shredded"
)

// AllStates returns the canonical ordered list (used for table-driven tests
// + admin UI dropdowns + observability dashboards).
func AllStates() []State {
	return []State{
		StateActive,
		StateClosing,
		StateSuspended,
		StatePseudonymized,
		StateColdArchived,
		StateCryptoShredded,
	}
}

// Valid reports whether s is one of the six known states.
func (s State) Valid() bool {
	switch s {
	case StateActive, StateClosing, StateSuspended, StatePseudonymized,
		StateColdArchived, StateCryptoShredded:
		return true
	}
	return false
}

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

var (
	// ErrInvalidTransition is returned by Saga.Advance for a transition that
	// the state machine forbids.
	ErrInvalidTransition = errors.New("invalid closure state transition")

	// ErrCancelTooLate is returned by Saga.Cancel once the saga has progressed
	// past CLOSING (i.e. SUSPENDED or beyond — pseudonymisation has begun).
	ErrCancelTooLate = errors.New("closure cannot be cancelled after SUSPENDED")

	// ErrTerminalState is returned by NextState when called on a terminal state.
	ErrTerminalState = errors.New("state has no successor (terminal)")
)

// -----------------------------------------------------------------------------
// Transition table
// -----------------------------------------------------------------------------

// allowed lists the valid (from -> to) state transitions.
//
// Forward progressions are one-step-at-a-time. CLOSING -> ACTIVE is the ONE
// permitted backward transition — used for cancel-during-grace.
var allowed = map[State]map[State]struct{}{
	StateActive: {
		StateClosing: {},
	},
	StateClosing: {
		StateSuspended: {},
		StateActive:    {}, // cancel during grace
	},
	StateSuspended: {
		StatePseudonymized: {},
	},
	StatePseudonymized: {
		StateColdArchived: {},
	},
	StateColdArchived: {
		StateCryptoShredded: {},
	},
	StateCryptoShredded: {}, // terminal
}

// CanTransition reports whether from -> to is a permitted transition. Same-
// state transitions (from == to) always return false.
func CanTransition(from, to State) bool {
	if from == to {
		return false
	}
	successors, ok := allowed[from]
	if !ok {
		return false
	}
	_, ok = successors[to]
	return ok
}

// IsCancellable reports whether a saga in state s may still be cancelled by
// the learner (or admin on the learner's behalf). Only StateClosing qualifies
// — once SUSPENDED, federated domains may have begun tokenisation, and the
// saga is no longer reversible.
func IsCancellable(s State) bool {
	return s == StateClosing
}

// IsTerminalState reports whether s is a terminal state (no successor).
func IsTerminalState(s State) bool {
	successors, ok := allowed[s]
	if !ok {
		return true
	}
	return len(successors) == 0
}

// NextState returns the canonical successor state for the linear closure
// progression. Used by the manual-advance admin endpoint (real implementation
// is event-driven). For StateClosing the canonical successor is StateSuspended
// (NOT the cancel branch back to StateActive).
func NextState(from State) (State, error) {
	switch from {
	case StateActive:
		return StateClosing, nil
	case StateClosing:
		return StateSuspended, nil
	case StateSuspended:
		return StatePseudonymized, nil
	case StatePseudonymized:
		return StateColdArchived, nil
	case StateColdArchived:
		return StateCryptoShredded, nil
	}
	return "", ErrTerminalState
}
