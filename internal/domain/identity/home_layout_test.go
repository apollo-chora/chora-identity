// home_layout_test.go - RED-phase specs for the shell /home launcher layout
// value object (ADR-240 Track B). Written BEFORE the impl per strict TDD.
//
// The home layout is the SECOND users.ui_preferences key (after dashboard_layout)
// and the FIRST one whose id vocabulary is OPEN and FE-owned. Per ADR-240 D11 the
// domain validates STRUCTURE ONLY - a bounded pin count, and every pin id a
// non-empty bounded string with no duplicates - and NEVER the id VOCABULARY
// (doing so would recreate the hand-mirrored closed-enum drift that broke
// dashboard_layout twice, CHO-2274). An empty pin list is a legitimate persisted
// state (D7), unlike the dashboard order (which must be non-empty).
package identity_test

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// homePin builds a minimal valid pin object with just an id.
func homePin(id string) identity.HomePin {
	return identity.HomePin{ID: id, Raw: []byte(`{"id":"` + id + `"}`)}
}

func TestValidateHomePins_EmptyIsValid_D7(t *testing.T) {
	t.Parallel()
	// ADR-240 D7: an intentionally empty home (the learner removed every pin) is
	// a legitimate persisted state - NOT an error, NOT silently defaulted.
	if err := identity.ValidateHomePins(nil); err != nil {
		t.Errorf("ValidateHomePins(nil) = %v; want nil (empty home is valid, D7)", err)
	}
	if err := identity.ValidateHomePins([]identity.HomePin{}); err != nil {
		t.Errorf("ValidateHomePins([]) = %v; want nil (empty home is valid, D7)", err)
	}
}

func TestValidateHomePins_UnknownIdsAccepted_D11(t *testing.T) {
	t.Parallel()
	// ADR-240 D11: the domain validates STRUCTURE only, NEVER the id vocabulary.
	// Ids the backend has never heard of MUST pass - an unknown id is inert in a
	// GCID-scoped blob and grants nothing; the reconcile drops it at render.
	pins := []identity.HomePin{homePin("a-plus-dashboard"), homePin("totally-made-up-id"), homePin("wallet")}
	if err := identity.ValidateHomePins(pins); err != nil {
		t.Errorf("ValidateHomePins(unknown ids) = %v; want nil (no vocabulary check, D11)", err)
	}
}

func TestValidateHomePins_DuplicateId_Rejected(t *testing.T) {
	t.Parallel()
	pins := []identity.HomePin{homePin("map"), homePin("map")}
	if err := identity.ValidateHomePins(pins); !errors.Is(err, identity.ErrHomePinDuplicate) {
		t.Errorf("duplicate id = %v; want ErrHomePinDuplicate", err)
	}
}

func TestValidateHomePins_EmptyId_Rejected(t *testing.T) {
	t.Parallel()
	pins := []identity.HomePin{homePin("ok"), {ID: "", Raw: []byte(`{}`)}}
	if err := identity.ValidateHomePins(pins); !errors.Is(err, identity.ErrHomePinIDEmpty) {
		t.Errorf("empty id = %v; want ErrHomePinIDEmpty", err)
	}
}

func TestValidateHomePins_TooLongId_Rejected(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("x", identity.MaxHomePinIDLen+1)
	if err := identity.ValidateHomePins([]identity.HomePin{homePin(long)}); !errors.Is(err, identity.ErrHomePinIDTooLong) {
		t.Errorf("over-length id = %v; want ErrHomePinIDTooLong", err)
	}
}

func TestValidateHomePins_MaxLenId_OK(t *testing.T) {
	t.Parallel()
	// Boundary: an id of exactly MaxHomePinIDLen is allowed.
	ok := strings.Repeat("x", identity.MaxHomePinIDLen)
	if err := identity.ValidateHomePins([]identity.HomePin{homePin(ok)}); err != nil {
		t.Errorf("id at the max length must be valid; got %v", err)
	}
}

func TestValidateHomePins_TooManyPins_Rejected(t *testing.T) {
	t.Parallel()
	pins := make([]identity.HomePin, identity.MaxHomePins+1)
	for i := range pins {
		pins[i] = homePin("pin-" + strconv.Itoa(i))
	}
	if err := identity.ValidateHomePins(pins); !errors.Is(err, identity.ErrHomeLayoutTooManyPins) {
		t.Errorf("over-count pins = %v; want ErrHomeLayoutTooManyPins", err)
	}
}

func TestValidateHomePins_MaxPins_OK(t *testing.T) {
	t.Parallel()
	// Boundary: exactly MaxHomePins is allowed.
	pins := make([]identity.HomePin, identity.MaxHomePins)
	for i := range pins {
		pins[i] = homePin("pin-" + strconv.Itoa(i))
	}
	if err := identity.ValidateHomePins(pins); err != nil {
		t.Errorf("exactly MaxHomePins must be valid; got %v", err)
	}
}
