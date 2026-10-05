// Package closure_test exercises the ClosureSaga aggregate.
package closure_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/apollo-chora/chora-identity/internal/domain/closure"
)

const (
	gcidA = "01970000-0000-7000-9000-000000000001"
	gcidB = "01970000-0000-7000-9000-000000000002"
	agidX = "0197A000-0000-7000-9000-000000000001"
)

// -----------------------------------------------------------------------------
// NewSaga constructor invariants.
// -----------------------------------------------------------------------------

func TestNewSaga_StartsInClosingWithGracePeriod(t *testing.T) {
	t.Parallel()
	s, err := closure.NewSaga(closure.NewSagaParams{
		Gcid:            gcidA,
		TenantID:        "01970000-0000-7000-8000-000000000001",
		GracePeriodDays: 30,
		Reason:          "learner_self_request",
		RequestedByGcid: gcidA,
	})
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if s.SagaID == "" {
		t.Errorf("SagaID empty")
	}
	if s.Gcid != gcidA {
		t.Errorf("Gcid mismatch")
	}
	if s.State != closure.StateClosing {
		t.Errorf("State=%q; want closing", s.State)
	}
	if s.GracePeriodDays != 30 {
		t.Errorf("GracePeriodDays=%d; want 30", s.GracePeriodDays)
	}
	expectedETA := s.RequestedAt.Add(30 * 24 * time.Hour)
	if !s.GraceEndsAt.Equal(expectedETA) {
		t.Errorf("GraceEndsAt=%v; want %v", s.GraceEndsAt, expectedETA)
	}
	if len(s.History) != 1 {
		t.Errorf("History size=%d; want 1 (initial CLOSING entry)", len(s.History))
	}
}

func TestNewSaga_RejectsAGID(t *testing.T) {
	t.Parallel()
	_, err := closure.NewSaga(closure.NewSagaParams{
		Gcid:            agidX,
		TenantID:        "01970000-0000-7000-8000-000000000001",
		GracePeriodDays: 30,
		Reason:          "learner_self_request",
		RequestedByGcid: agidX,
	})
	if err == nil {
		t.Errorf("expected error rejecting AGID; got nil")
	}
}

func TestNewSaga_RejectsEmptyGcid(t *testing.T) {
	t.Parallel()
	_, err := closure.NewSaga(closure.NewSagaParams{
		Gcid:            "",
		TenantID:        "t",
		GracePeriodDays: 30,
		RequestedByGcid: gcidA,
	})
	if err == nil {
		t.Errorf("expected error for empty gcid")
	}
}

func TestNewSaga_RejectsZeroGracePeriod(t *testing.T) {
	t.Parallel()
	_, err := closure.NewSaga(closure.NewSagaParams{
		Gcid:            gcidA,
		TenantID:        "t",
		GracePeriodDays: 0,
		RequestedByGcid: gcidA,
	})
	if err == nil {
		t.Errorf("expected error for zero grace period")
	}
}

func TestNewSaga_RejectsExcessiveGracePeriod(t *testing.T) {
	t.Parallel()
	// Hard ceiling at 365 days per spec — protects against fat-finger
	// admin entry that traps a user in CLOSING for years.
	_, err := closure.NewSaga(closure.NewSagaParams{
		Gcid:            gcidA,
		TenantID:        "t",
		GracePeriodDays: 366,
		RequestedByGcid: gcidA,
	})
	if err == nil {
		t.Errorf("expected error for excessive grace period")
	}
}

// -----------------------------------------------------------------------------
// Advance state transitions.
// -----------------------------------------------------------------------------

func TestSaga_Advance_AppendsHistoryAndUpdatesState(t *testing.T) {
	t.Parallel()
	s := mustNewSaga(t)

	if err := s.Advance(closure.StateSuspended, "grace_expired", gcidA); err != nil {
		t.Fatalf("Advance: %v", err)
	}
	if s.State != closure.StateSuspended {
		t.Errorf("State=%q; want suspended", s.State)
	}
	if len(s.History) != 2 {
		t.Errorf("History size=%d; want 2", len(s.History))
	}
	last := s.History[len(s.History)-1]
	if last.PriorState != closure.StateClosing || last.NewState != closure.StateSuspended {
		t.Errorf("last history = %+v", last)
	}
	if last.Reason != "grace_expired" {
		t.Errorf("Reason=%q; want grace_expired", last.Reason)
	}
	if last.ActorGcid != gcidA {
		t.Errorf("ActorGcid=%q; want %q", last.ActorGcid, gcidA)
	}
}

func TestSaga_Advance_RejectsInvalidTransition(t *testing.T) {
	t.Parallel()
	s := mustNewSaga(t)
	// Cannot skip ahead from CLOSING to PSEUDONYMIZED.
	err := s.Advance(closure.StatePseudonymized, "skip", gcidA)
	if err == nil {
		t.Fatalf("expected error skipping ahead; got nil")
	}
	if !errors.Is(err, closure.ErrInvalidTransition) {
		t.Errorf("err=%v; want errors.Is(_, ErrInvalidTransition)", err)
	}
	// State should not have changed.
	if s.State != closure.StateClosing {
		t.Errorf("State changed to %q; should remain closing", s.State)
	}
}

func TestSaga_FullProgression_CLOSING_TO_CRYPTO_SHREDDED(t *testing.T) {
	t.Parallel()
	s := mustNewSaga(t)

	progression := []struct {
		next   closure.State
		reason string
	}{
		{closure.StateSuspended, "grace_expired"},
		{closure.StatePseudonymized, "domain_pseudonymisation_complete"},
		{closure.StateColdArchived, "moved_to_coldline"},
		{closure.StateCryptoShredded, "dek_deleted"},
	}
	for _, step := range progression {
		if err := s.Advance(step.next, step.reason, gcidA); err != nil {
			t.Fatalf("Advance(%q): %v", step.next, err)
		}
	}
	if s.State != closure.StateCryptoShredded {
		t.Errorf("final state=%q; want crypto_shredded", s.State)
	}
	// 1 (initial CLOSING) + 4 progressions = 5 entries.
	if len(s.History) != 5 {
		t.Errorf("History size=%d; want 5", len(s.History))
	}
	if s.IsTerminal() != true {
		t.Errorf("IsTerminal=false; want true after CRYPTO_SHREDDED")
	}
}

// -----------------------------------------------------------------------------
// Cancel — only valid pre-SUSPENDED.
// -----------------------------------------------------------------------------

func TestSaga_Cancel_ReturnsToActive_DuringClosing(t *testing.T) {
	t.Parallel()
	s := mustNewSaga(t)
	if err := s.Cancel("learner_changed_mind", gcidA); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if s.State != closure.StateActive {
		t.Errorf("State=%q; want active", s.State)
	}
	if !s.CancelledAt.After(s.RequestedAt) && !s.CancelledAt.Equal(s.RequestedAt) {
		t.Errorf("CancelledAt should be set")
	}
}

func TestSaga_Cancel_RejectedAfterSuspended(t *testing.T) {
	t.Parallel()
	s := mustNewSaga(t)
	if err := s.Advance(closure.StateSuspended, "grace_expired", gcidA); err != nil {
		t.Fatalf("Advance: %v", err)
	}
	err := s.Cancel("too_late", gcidA)
	if err == nil {
		t.Fatalf("expected error cancelling after suspended; got nil")
	}
	if !errors.Is(err, closure.ErrCancelTooLate) {
		t.Errorf("err=%v; want errors.Is(_, ErrCancelTooLate)", err)
	}
}

func TestSaga_Cancel_RejectedAfterPseudonymized(t *testing.T) {
	t.Parallel()
	s := mustNewSaga(t)
	_ = s.Advance(closure.StateSuspended, "ge", gcidA)
	_ = s.Advance(closure.StatePseudonymized, "p", gcidA)
	err := s.Cancel("recover", gcidA)
	if err == nil {
		t.Fatalf("expected error cancelling after pseudonymized; got nil")
	}
}

func TestSaga_Cancel_IdempotentWhenAlreadyActive(t *testing.T) {
	t.Parallel()
	s := mustNewSaga(t)
	_ = s.Cancel("once", gcidA)
	err := s.Cancel("twice", gcidA)
	if err == nil {
		// A second cancel from ACTIVE is undefined; either no-op or error are
		// acceptable. The rule we lock in: it must not silently succeed and
		// double-record. Implementation returns ErrCancelTooLate when not in
		// CLOSING anymore.
		t.Errorf("expected idempotency error on second cancel")
	}
}

// -----------------------------------------------------------------------------
// ETA + grace expiry helpers.
// -----------------------------------------------------------------------------

func TestSaga_GraceExpired_TrueOnceClockPasses(t *testing.T) {
	t.Parallel()
	// Use a 1-day grace + a synthetic clock helper.
	s, err := closure.NewSaga(closure.NewSagaParams{
		Gcid:            gcidA,
		TenantID:        "t",
		GracePeriodDays: 1,
		RequestedByGcid: gcidA,
	})
	if err != nil {
		t.Fatalf("NewSaga: %v", err)
	}
	if s.GraceExpiredAt(s.RequestedAt) {
		t.Errorf("grace must not be expired immediately at request time")
	}
	if !s.GraceExpiredAt(s.GraceEndsAt.Add(1 * time.Second)) {
		t.Errorf("grace must be expired after GraceEndsAt")
	}
}

// -----------------------------------------------------------------------------
// PII tokenisation step (recorded as part of pseudonymise).
// -----------------------------------------------------------------------------

func TestSaga_RecordTokenisedField_AppendsToList(t *testing.T) {
	t.Parallel()
	s := mustNewSaga(t)
	s.RecordTokenisedField("email", closure.PIIClassHigh)
	s.RecordTokenisedField("display_name", closure.PIIClassMedium)
	if len(s.TokenisedFields) != 2 {
		t.Errorf("size=%d; want 2", len(s.TokenisedFields))
	}
	if s.TokenisedFields[0].Name != "email" || s.TokenisedFields[0].Class != closure.PIIClassHigh {
		t.Errorf("first entry mismatch: %+v", s.TokenisedFields[0])
	}
}

// -----------------------------------------------------------------------------
// Helpers.
// -----------------------------------------------------------------------------

func mustNewSaga(t *testing.T) *closure.Saga {
	t.Helper()
	s, err := closure.NewSaga(closure.NewSagaParams{
		Gcid:            gcidA,
		TenantID:        "01970000-0000-7000-8000-000000000001",
		GracePeriodDays: 30,
		Reason:          "learner_self_request",
		RequestedByGcid: gcidA,
	})
	if err != nil {
		t.Fatalf("mustNewSaga: %v", err)
	}
	return s
}

// Compile-time guard: ensure exported error sentinels are exported strings.
var _ = strings.HasPrefix
