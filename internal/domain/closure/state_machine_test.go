// Package closure_test exercises the federated account closure 5-state machine.
//
// State machine per ddd-enforcement (Account Closure section) + Tier 3 D11:
//
//	ACTIVE -> CLOSING (grace) -> SUSPENDED -> PSEUDONYMIZED ->
//	  COLD_ARCHIVED -> CRYPTO_SHREDDED
//
// CLOSING -> ACTIVE is the ONLY backward transition (cancellation during grace).
// All other backward transitions are FORBIDDEN. Once SUSPENDED, the saga is
// no longer cancellable.
//
// TDD RED: these tests assume the state machine does NOT yet exist.
package closure_test

import (
	"testing"

	"github.com/apollo-chora/chora-identity/internal/domain/closure"
)

// -----------------------------------------------------------------------------
// Valid forward transitions
// -----------------------------------------------------------------------------

func TestStateMachine_ValidForwardTransitions(t *testing.T) {
	t.Parallel()

	cases := []struct {
		from closure.State
		to   closure.State
	}{
		{closure.StateActive, closure.StateClosing},
		{closure.StateClosing, closure.StateSuspended},
		{closure.StateSuspended, closure.StatePseudonymized},
		{closure.StatePseudonymized, closure.StateColdArchived},
		{closure.StateColdArchived, closure.StateCryptoShredded},
	}
	for _, c := range cases {
		c := c
		t.Run(string(c.from)+"->"+string(c.to), func(t *testing.T) {
			t.Parallel()
			if !closure.CanTransition(c.from, c.to) {
				t.Errorf("CanTransition(%q,%q)=false; want true", c.from, c.to)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Cancel transition CLOSING -> ACTIVE (only backward transition allowed).
// -----------------------------------------------------------------------------

func TestStateMachine_CancelDuringGrace_ClosingToActive_IsValid(t *testing.T) {
	t.Parallel()
	if !closure.CanTransition(closure.StateClosing, closure.StateActive) {
		t.Errorf("CLOSING->ACTIVE must be valid (cancel during grace)")
	}
}

// -----------------------------------------------------------------------------
// Forbidden transitions — cancel only valid before SUSPENDED, no skipping,
// no rolling back from SUSPENDED+.
// -----------------------------------------------------------------------------

func TestStateMachine_ForbiddenBackwardAfterSuspended(t *testing.T) {
	t.Parallel()
	bad := []struct {
		from closure.State
		to   closure.State
	}{
		// Cannot cancel after SUSPENDED.
		{closure.StateSuspended, closure.StateActive},
		{closure.StateSuspended, closure.StateClosing},
		// Cannot un-pseudonymise.
		{closure.StatePseudonymized, closure.StateSuspended},
		{closure.StatePseudonymized, closure.StateClosing},
		{closure.StatePseudonymized, closure.StateActive},
		// Terminal states can't transition.
		{closure.StateColdArchived, closure.StatePseudonymized},
		{closure.StateColdArchived, closure.StateActive},
		{closure.StateCryptoShredded, closure.StateColdArchived},
		{closure.StateCryptoShredded, closure.StateActive},
	}
	for _, c := range bad {
		if closure.CanTransition(c.from, c.to) {
			t.Errorf("CanTransition(%q,%q)=true; want false (forbidden backward)", c.from, c.to)
		}
	}
}

func TestStateMachine_ForbiddenSkippingAhead(t *testing.T) {
	t.Parallel()
	// All non-adjacent forward transitions must be rejected.
	bad := []struct {
		from closure.State
		to   closure.State
	}{
		{closure.StateActive, closure.StateSuspended},
		{closure.StateActive, closure.StatePseudonymized},
		{closure.StateActive, closure.StateColdArchived},
		{closure.StateActive, closure.StateCryptoShredded},
		{closure.StateClosing, closure.StatePseudonymized},
		{closure.StateClosing, closure.StateColdArchived},
		{closure.StateClosing, closure.StateCryptoShredded},
		{closure.StateSuspended, closure.StateColdArchived},
		{closure.StateSuspended, closure.StateCryptoShredded},
		{closure.StatePseudonymized, closure.StateCryptoShredded},
	}
	for _, c := range bad {
		if closure.CanTransition(c.from, c.to) {
			t.Errorf("CanTransition(%q,%q)=true; want false (cannot skip ahead)", c.from, c.to)
		}
	}
}

func TestStateMachine_SameStateTransitionRejected(t *testing.T) {
	t.Parallel()
	for _, s := range closure.AllStates() {
		if closure.CanTransition(s, s) {
			t.Errorf("CanTransition(%q,%q)=true; same-state transition should be rejected", s, s)
		}
	}
}

// -----------------------------------------------------------------------------
// Cancel-eligibility window — only valid pre-SUSPENDED.
// -----------------------------------------------------------------------------

func TestIsCancellable_TrueBeforeSuspended(t *testing.T) {
	t.Parallel()
	cases := map[closure.State]bool{
		closure.StateActive:         false, // Cancel only meaningful after CLOSING starts.
		closure.StateClosing:        true,
		closure.StateSuspended:      false,
		closure.StatePseudonymized:  false,
		closure.StateColdArchived:   false,
		closure.StateCryptoShredded: false,
	}
	for s, want := range cases {
		got := closure.IsCancellable(s)
		if got != want {
			t.Errorf("IsCancellable(%q)=%v want %v", s, got, want)
		}
	}
}

// -----------------------------------------------------------------------------
// State validity / unknown rejection.
// -----------------------------------------------------------------------------

func TestState_ValidAcceptsAllKnownStates(t *testing.T) {
	t.Parallel()
	for _, s := range closure.AllStates() {
		if !s.Valid() {
			t.Errorf("State(%q).Valid()=false; want true", s)
		}
	}
	if closure.State("magic").Valid() {
		t.Errorf("State(magic).Valid()=true; want false")
	}
}

func TestNextState_ReturnsExpectedSuccessor(t *testing.T) {
	t.Parallel()
	cases := map[closure.State]closure.State{
		closure.StateActive:        closure.StateClosing,
		closure.StateClosing:       closure.StateSuspended,
		closure.StateSuspended:     closure.StatePseudonymized,
		closure.StatePseudonymized: closure.StateColdArchived,
		closure.StateColdArchived:  closure.StateCryptoShredded,
	}
	for from, want := range cases {
		got, err := closure.NextState(from)
		if err != nil {
			t.Errorf("NextState(%q) unexpected err=%v", from, err)
			continue
		}
		if got != want {
			t.Errorf("NextState(%q)=%q want %q", from, got, want)
		}
	}
}

func TestNextState_TerminalReturnsError(t *testing.T) {
	t.Parallel()
	if _, err := closure.NextState(closure.StateCryptoShredded); err == nil {
		t.Errorf("expected error for terminal state; got nil")
	}
}
