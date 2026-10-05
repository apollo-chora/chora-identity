// ui_preferences.go — GCID-scoped UI-preference value objects for the Identity
// domain. Persisted as the users.ui_preferences JSONB slice (migration 0034).
//
// The first UI preference is the A+ dashboard-as-hub layout (SP2): an ordered
// set of draggable card-group "wrapper" keys the learner reorders. The layout
// is a GCID-scoped account preference (portable across tenants, like the GCID
// itself) — it lives on the User profile aggregate, NOT a tenant-scoped table,
// so no tenant RLS axis applies. The store filters by gcid = the authenticated
// caller (never the request body) per project_gateway_bff_tenant_from_authctx.
package identity

import (
	"errors"
	"fmt"
	"time"

	"github.com/apollo-chora/chora-common/uiprefs"
)

// DashboardWrapperKey identifies a draggable card group on the A+ dashboard.
//
// HARD INVARIANT: these values are PERSISTED inside users.ui_preferences —
// renaming one silently orphans every stored layout. The set mirrors the FE
// wrapper registry (SP2 shared contract); the two MUST stay in lockstep.
type DashboardWrapperKey string

const (
	DashboardWrapperMap     DashboardWrapperKey = "map"     // MapPreviewCard (default position 0)
	DashboardWrapperCast    DashboardWrapperKey = "cast"    // CastCard (default position 1)
	DashboardWrapperCourses DashboardWrapperKey = "courses" // ContinueLearningCard (default position 2)
)

// KnownDashboardWrapperKeys is the closed set the persisted order must be a
// subset/permutation of. It DERIVES from the single canonical source
// (uiprefs.DashboardWrapperKeys) that the chora-gateway edge validator also
// derives from, so the domain and the edge can never drift apart by hand.
// Before CHO-2274 this was a hand-maintained slice that fell behind the FE when
// "study" (CHO-2226) and "transcript" (CHO-2237) shipped, so every save 422'd.
// The order is the canonical DEFAULT order (map-dominant) used to reconcile
// added wrappers. The named constants above remain the stable persisted values
// (never rename); adding a card means appending the key to uiprefs (the one
// backend source) and to the FE wrapper registry.
var KnownDashboardWrapperKeys = func() []DashboardWrapperKey {
	src := uiprefs.DashboardWrapperKeys()
	keys := make([]DashboardWrapperKey, len(src))
	for i, k := range src {
		keys[i] = DashboardWrapperKey(k)
	}
	return keys
}()

// Validation sentinels — exported so handlers can errors.Is() them onto a 422.
var (
	ErrDashboardOrderEmpty     = errors.New("dashboard layout order must be non-empty")
	ErrDashboardOrderUnknown   = errors.New("dashboard layout order contains an unknown wrapper key")
	ErrDashboardOrderDuplicate = errors.New("dashboard layout order contains a duplicate wrapper key")
)

// DashboardLayout is the persisted UI-preference value object: the learner's
// ordered wrapper keys + the FE-supplied Last-Write-Wins conflict key.
type DashboardLayout struct {
	// Order is a subset/permutation of KnownDashboardWrapperKeys.
	Order []DashboardWrapperKey
	// UpdatedAt is the FE clock at the moment of the reorder — the LWW key the
	// FE compares against its local copy on load. Stored + returned verbatim.
	UpdatedAt time.Time
}

// UIPreferences is the GCID-scoped UI-preference aggregate slice materialised
// from users.ui_preferences JSONB. Each field is nil when its key was never set
// (the FE treats an absent value as "no server value yet"). New UI preferences
// append a key here (and a JSONB key in the store) - migration 0034 chose JSONB
// precisely so this needs no DB migration.
type UIPreferences struct {
	DashboardLayout *DashboardLayout
	// HomeLayout is the shell /home launcher layout (ADR-240 Track B). A NEW
	// key, never an overload of DashboardLayout (D2): the dashboard order is a
	// closed WrapperKey enum; the home pin list is an OPEN, user-curated set.
	HomeLayout *HomeLayout
}

// IsKnownDashboardWrapperKey reports whether k is in the closed registry.
func IsKnownDashboardWrapperKey(k DashboardWrapperKey) bool {
	for _, known := range KnownDashboardWrapperKeys {
		if k == known {
			return true
		}
	}
	return false
}

// ValidateDashboardOrder enforces the layout invariants: non-empty, every key
// in the known registry, no duplicates. Returns a wrapped sentinel (errors.Is-
// friendly) on the first violation so both the gateway edge guard and the
// authoritative identity handler can map it to a 422.
func ValidateDashboardOrder(order []DashboardWrapperKey) error {
	if len(order) == 0 {
		return ErrDashboardOrderEmpty
	}
	seen := make(map[DashboardWrapperKey]struct{}, len(order))
	for _, k := range order {
		if !IsKnownDashboardWrapperKey(k) {
			return fmt.Errorf("%w: %q", ErrDashboardOrderUnknown, k)
		}
		if _, dup := seen[k]; dup {
			return fmt.Errorf("%w: %q", ErrDashboardOrderDuplicate, k)
		}
		seen[k] = struct{}{}
	}
	return nil
}

// -----------------------------------------------------------------------------
// Home layout - the shell /home launcher preference (ADR-240 Track B)
// -----------------------------------------------------------------------------

// Home-launcher STRUCTURAL bounds (ADR-240 D11). These cap the JSONB blob only -
// they are NOT a vocabulary. The pin id set is OPEN and FE-owned (D4): the domain
// NEVER validates an id against a known set, because a hand-mirrored id set is
// exactly the drift class that broke dashboard_layout twice (CHO-2274). The
// bounds are deliberately generous - the whole pinnable registry across the five
// surfaces will not approach MaxHomePins.
const (
	// MaxHomePins caps the number of pinned entry-points a single home layout may
	// carry (anti-abuse guard on the JSONB size).
	MaxHomePins = 128
	// MaxHomePinIDLen caps a single pin id's length (bytes).
	MaxHomePinIDLen = 128
)

// Home-layout structural sentinels - exported so the handler can errors.Is()
// them onto a 422/400. NONE of these is an id-vocabulary check (D11).
var (
	ErrHomePinNotObject      = errors.New("home layout pin must be a JSON object with a string id")
	ErrHomePinIDEmpty        = errors.New("home layout pin id must be a non-empty string")
	ErrHomePinIDTooLong      = errors.New("home layout pin id exceeds the maximum length")
	ErrHomePinDuplicate      = errors.New("home layout contains a duplicate pin id")
	ErrHomeLayoutTooManyPins = errors.New("home layout exceeds the maximum pin count")
)

// HomePin is one pinned entry-point on the shell /home launcher (ADR-240). The
// id is an OPEN, FE-owned vocabulary - validated only as a bounded non-empty
// string, NEVER against a known-id set (D4/D11). Raw is the verbatim pin object
// as received (its id plus the FE-owned position fields per D10); the domain
// stores and returns Raw unchanged and never interprets the position fields, so
// a new position field (e.g. the H5 2D grid) needs NO backend change. Raw is
// opaque bytes here so the domain stays free of any JSON/infrastructure import.
type HomePin struct {
	ID  string
	Raw []byte
}

// HomeLayout is the persisted shell /home launcher preference: an ordered, OPEN
// list of pinned entry-points plus the FE-supplied Last-Write-Wins key. Unlike
// the A+ dashboard order (total over a closed set), the pin list is a
// user-curated SUBSET, and an empty list is a legitimate persisted state (D7).
type HomeLayout struct {
	// Pins is the ordered pin list; ordering IS the 1D placement for v1 (D10).
	Pins []HomePin
	// UpdatedAt is the FE clock at the moment of the edit - the LWW key the FE
	// compares against its local copy on load (D8). Stored + returned verbatim.
	UpdatedAt time.Time
}

// ValidateHomePins enforces the STRUCTURAL invariants only (ADR-240 D11): a
// bounded pin count, and every pin id a non-empty bounded string with no
// duplicates. It does NOT validate the id vocabulary - an unknown id is inert
// (D4). An empty pin list is valid (D7). Returns a wrapped sentinel
// (errors.Is-friendly) on the first violation so the handler can map it to a 422.
func ValidateHomePins(pins []HomePin) error {
	if len(pins) > MaxHomePins {
		return fmt.Errorf("%w: %d > %d", ErrHomeLayoutTooManyPins, len(pins), MaxHomePins)
	}
	seen := make(map[string]struct{}, len(pins))
	for _, p := range pins {
		if p.ID == "" {
			return ErrHomePinIDEmpty
		}
		if len(p.ID) > MaxHomePinIDLen {
			return fmt.Errorf("%w: %q", ErrHomePinIDTooLong, p.ID)
		}
		if _, dup := seen[p.ID]; dup {
			return fmt.Errorf("%w: %q", ErrHomePinDuplicate, p.ID)
		}
		seen[p.ID] = struct{}{}
	}
	return nil
}
