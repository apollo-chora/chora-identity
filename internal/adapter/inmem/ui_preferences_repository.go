// ui_preferences_repository.go — in-memory identity.UIPreferencesRepository
// (SP2.9). Backs the dev wiring when the chora_identity pool is absent and the
// handler unit tests. Production uses the pgx-backed adapter (users.ui_preferences
// JSONB, migration 0034).
package inmem

import (
	"context"
	"strings"
	"sync"

	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// UIPreferencesRepository is the in-memory store, keyed by gcid.
type UIPreferencesRepository struct {
	mu     sync.RWMutex
	byGcid map[string]identity.DashboardLayout
	// homeByGcid holds the shell /home launcher layout per gcid (ADR-240 D2),
	// independent of the dashboard layout so both keys coexist as in the JSONB.
	homeByGcid map[string]identity.HomeLayout
	// knownGcid, when non-empty, restricts writes to a set of seeded gcids so
	// the dev/test store can mimic the pg ErrUserNotFound path. Empty = accept
	// any gcid (the common dev case — the user row is assumed to exist).
	knownGcid map[string]struct{}
}

// NewUIPreferencesRepository builds an empty store that accepts any gcid.
func NewUIPreferencesRepository() *UIPreferencesRepository {
	return &UIPreferencesRepository{
		byGcid:     make(map[string]identity.DashboardLayout),
		homeByGcid: make(map[string]identity.HomeLayout),
	}
}

// SeedKnownGcids restricts UpsertDashboardLayout to the given gcids (returning
// identity.ErrUserNotFound otherwise) so tests can exercise the not-found path.
func (r *UIPreferencesRepository) SeedKnownGcids(gcids ...string) *UIPreferencesRepository {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.knownGcid = make(map[string]struct{}, len(gcids))
	for _, g := range gcids {
		r.knownGcid[g] = struct{}{}
	}
	return r
}

// GetUIPreferences returns the caller's preferences; an unset store yields a
// zero-value UIPreferences (DashboardLayout nil), never an error.
func (r *UIPreferencesRepository) GetUIPreferences(_ context.Context, gcid string) (*identity.UIPreferences, error) {
	if strings.TrimSpace(gcid) == "" {
		return nil, identity.ErrUserNotFound
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := &identity.UIPreferences{}
	if layout, ok := r.byGcid[gcid]; ok {
		clone := layout
		clone.Order = append([]identity.DashboardWrapperKey(nil), layout.Order...)
		out.DashboardLayout = &clone
	}
	if home, ok := r.homeByGcid[gcid]; ok {
		out.HomeLayout = cloneHomeLayout(home)
	}
	return out, nil
}

// cloneHomeLayout deep-copies a HomeLayout (including each pin's Raw bytes) so
// the stored state cannot be mutated through a returned reference.
func cloneHomeLayout(h identity.HomeLayout) *identity.HomeLayout {
	pins := make([]identity.HomePin, len(h.Pins))
	for i, p := range h.Pins {
		buf := make([]byte, len(p.Raw))
		copy(buf, p.Raw)
		pins[i] = identity.HomePin{ID: p.ID, Raw: buf}
	}
	return &identity.HomeLayout{Pins: pins, UpdatedAt: h.UpdatedAt}
}

// UpsertDashboardLayout replaces the caller's dashboard layout.
func (r *UIPreferencesRepository) UpsertDashboardLayout(_ context.Context, gcid string, layout identity.DashboardLayout) error {
	if strings.TrimSpace(gcid) == "" {
		return identity.ErrUserNotFound
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.knownGcid != nil {
		if _, ok := r.knownGcid[gcid]; !ok {
			return identity.ErrUserNotFound
		}
	}
	clone := layout
	clone.Order = append([]identity.DashboardWrapperKey(nil), layout.Order...)
	r.byGcid[gcid] = clone
	return nil
}

// UpsertHomeLayout replaces the caller's home layout (ADR-240 D2).
func (r *UIPreferencesRepository) UpsertHomeLayout(_ context.Context, gcid string, layout identity.HomeLayout) error {
	if strings.TrimSpace(gcid) == "" {
		return identity.ErrUserNotFound
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.knownGcid != nil {
		if _, ok := r.knownGcid[gcid]; !ok {
			return identity.ErrUserNotFound
		}
	}
	r.homeByGcid[gcid] = *cloneHomeLayout(layout)
	return nil
}

// Compile-time check.
var _ identity.UIPreferencesRepository = (*UIPreferencesRepository)(nil)
