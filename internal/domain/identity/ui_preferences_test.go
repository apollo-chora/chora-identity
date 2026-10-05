// ui_preferences_test.go — RED-phase specs for the GCID-scoped UI-preference
// value objects (SP2.9 A+ dashboard-as-hub layout persistence). Written
// BEFORE ui_preferences.go per strict TDD.
package identity_test

import (
	"errors"
	"testing"

	"github.com/apollo-chora/chora-common/uiprefs"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

func TestValidateDashboardOrder_FullPermutationOK(t *testing.T) {
	t.Parallel()
	orders := [][]identity.DashboardWrapperKey{
		{identity.DashboardWrapperMap, identity.DashboardWrapperCast, identity.DashboardWrapperCourses},
		{identity.DashboardWrapperCast, identity.DashboardWrapperMap, identity.DashboardWrapperCourses},
		{identity.DashboardWrapperCourses, identity.DashboardWrapperCast, identity.DashboardWrapperMap},
	}
	for _, o := range orders {
		if err := identity.ValidateDashboardOrder(o); err != nil {
			t.Errorf("ValidateDashboardOrder(%v) = %v; want nil (permutation of known keys)", o, err)
		}
	}
}

func TestValidateDashboardOrder_SubsetOK(t *testing.T) {
	t.Parallel()
	// A wrapper may be removed → a strict subset of the known keys is valid.
	subsets := [][]identity.DashboardWrapperKey{
		{identity.DashboardWrapperMap},
		{identity.DashboardWrapperMap, identity.DashboardWrapperCourses},
	}
	for _, o := range subsets {
		if err := identity.ValidateDashboardOrder(o); err != nil {
			t.Errorf("ValidateDashboardOrder(%v) = %v; want nil (subset of known keys)", o, err)
		}
	}
}

func TestValidateDashboardOrder_Empty_Rejected(t *testing.T) {
	t.Parallel()
	err := identity.ValidateDashboardOrder(nil)
	if !errors.Is(err, identity.ErrDashboardOrderEmpty) {
		t.Errorf("ValidateDashboardOrder(nil) = %v; want ErrDashboardOrderEmpty", err)
	}
	if !errors.Is(identity.ValidateDashboardOrder([]identity.DashboardWrapperKey{}), identity.ErrDashboardOrderEmpty) {
		t.Errorf("empty slice must be ErrDashboardOrderEmpty")
	}
}

func TestValidateDashboardOrder_UnknownKey_Rejected(t *testing.T) {
	t.Parallel()
	o := []identity.DashboardWrapperKey{identity.DashboardWrapperMap, "atlas"}
	err := identity.ValidateDashboardOrder(o)
	if !errors.Is(err, identity.ErrDashboardOrderUnknown) {
		t.Errorf("ValidateDashboardOrder(%v) = %v; want ErrDashboardOrderUnknown", o, err)
	}
}

func TestValidateDashboardOrder_Duplicate_Rejected(t *testing.T) {
	t.Parallel()
	o := []identity.DashboardWrapperKey{identity.DashboardWrapperMap, identity.DashboardWrapperMap}
	err := identity.ValidateDashboardOrder(o)
	if !errors.Is(err, identity.ErrDashboardOrderDuplicate) {
		t.Errorf("ValidateDashboardOrder(%v) = %v; want ErrDashboardOrderDuplicate", o, err)
	}
}

func TestIsKnownDashboardWrapperKey(t *testing.T) {
	t.Parallel()
	for _, k := range identity.KnownDashboardWrapperKeys {
		if !identity.IsKnownDashboardWrapperKey(k) {
			t.Errorf("IsKnownDashboardWrapperKey(%q) = false; want true", k)
		}
	}
	if identity.IsKnownDashboardWrapperKey("nope") {
		t.Error("IsKnownDashboardWrapperKey(\"nope\") = true; want false")
	}
}

// TestKnownDashboardWrapperKeys_MatchCanonicalSource is the CHO-2274 drift
// guard: the identity known set must equal the single canonical source
// (uiprefs), so it can never fall behind the FE-owned vocabulary by hand.
// Before the fix identity knew only {map,cast,courses} while the FE and the
// canonical source also carry "study" and "transcript", so every save 422'd.
func TestKnownDashboardWrapperKeys_MatchCanonicalSource(t *testing.T) {
	t.Parallel()
	canonical := uiprefs.DashboardWrapperKeys()
	if len(identity.KnownDashboardWrapperKeys) != len(canonical) {
		t.Fatalf("identity KnownDashboardWrapperKeys = %v; want the canonical %v", identity.KnownDashboardWrapperKeys, canonical)
	}
	for i, k := range canonical {
		if string(identity.KnownDashboardWrapperKeys[i]) != k {
			t.Fatalf("identity known[%d] = %q; want canonical %q (derive from uiprefs, never hand-list)", i, identity.KnownDashboardWrapperKeys[i], k)
		}
	}
}

// TestValidateDashboardOrder_AcceptsStudyAndTranscript pins the specific
// CHO-2274 regression: the two keys the FE added (study CHO-2226, transcript
// CHO-2237) must validate authoritatively.
func TestValidateDashboardOrder_AcceptsStudyAndTranscript(t *testing.T) {
	t.Parallel()
	o := []identity.DashboardWrapperKey{"map", "cast", "courses", "study", "transcript"}
	if err := identity.ValidateDashboardOrder(o); err != nil {
		t.Errorf("ValidateDashboardOrder(full canonical) = %v; want nil", err)
	}
}

// The wrapper keys are PERSISTED — a rename silently orphans every stored
// layout. Pin the wire values so a rename fails this test loudly.
func TestDashboardWrapperKey_StableWireValues(t *testing.T) {
	t.Parallel()
	if string(identity.DashboardWrapperMap) != "map" {
		t.Errorf("DashboardWrapperMap = %q; want \"map\" (persisted — never rename)", identity.DashboardWrapperMap)
	}
	if string(identity.DashboardWrapperCast) != "cast" {
		t.Errorf("DashboardWrapperCast = %q; want \"cast\" (persisted — never rename)", identity.DashboardWrapperCast)
	}
	if string(identity.DashboardWrapperCourses) != "courses" {
		t.Errorf("DashboardWrapperCourses = %q; want \"courses\" (persisted — never rename)", identity.DashboardWrapperCourses)
	}
}
