// saga_internal_test.go — internal-package tests for unexported helper +
// state-machine leaf logic (isAGID detection, terminal-state resolution).
//
// The external closure_test package exercises the saga through its public
// API; these target the small unexported helpers directly.
package closure

import "testing"

func TestIsAGID_DetectsChoraAuditGcids(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"0197a000-0000-7000-9000-000000000001", true}, // lowercase prefix
		{"0197A000-0000-7000-9000-000000000001", true}, // uppercase prefix (case-insensitive)
		{"0197abc123", true},                           // 0197a prefix, short tail
		{"0198a000-0000-7000-9000-000000000001", false},
		{"not-a-gcid", false},
	}
	for _, c := range cases {
		if got := isAGID(c.in); got != c.want {
			t.Errorf("isAGID(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestIsTerminalState_LeavesAndUnknown(t *testing.T) {
	t.Parallel()
	// The final state of the linear chain has no successors → terminal.
	if !IsTerminalState(StateCryptoShredded) {
		t.Error("StateCryptoShredded should be terminal")
	}
	// Unknown states are fail-safe terminal.
	if !IsTerminalState(State("nonexistent")) {
		t.Error("unknown state should be treated as terminal")
	}
	// Interior states of the chain are NOT terminal.
	for _, s := range []State{StateActive, StateClosing, StateSuspended, StatePseudonymized, StateColdArchived} {
		if IsTerminalState(s) {
			t.Errorf("State %q should not be terminal", s)
		}
	}
}
func TestCanTransition_PermittedAndForbidden(t *testing.T) {
	t.Parallel()
	cases := []struct {
		from, to State
		want     bool
	}{
		{StateActive, StateActive, false},         // same state never allowed
		{StateActive, StateClosing, true},         // forward
		{StateClosing, StateActive, true},         // backward cancel during grace
		{StateActive, StateSuspended, false},      // skipping a step
		{State("bogus"), StateActive, false},      // unknown source
		{StateCryptoShredded, StateActive, false}, // terminal → nothing
	}
	for _, c := range cases {
		if got := CanTransition(c.from, c.to); got != c.want {
			t.Errorf("CanTransition(%q, %q) = %v, want %v", c.from, c.to, got, c.want)
		}
	}
}
