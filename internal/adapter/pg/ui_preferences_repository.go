// ui_preferences_repository.go — pgx-backed implementation of
// identity.UIPreferencesRepository (SP2.9). Stores the GCID-scoped A+ dashboard
// layout as the users.ui_preferences JSONB slice (migration 0034).
//
// SQL contract:
//
//   - GetUIPreferences: SELECT ui_preferences FROM users WHERE gcid=$1 AND
//     deleted_at IS NULL. Returns identity.ErrUserNotFound when missing; an
//     empty '{}' column yields UIPreferences{DashboardLayout:nil} (no error).
//   - UpsertDashboardLayout: jsonb_set the '{dashboard_layout}' key only, so
//     future ui_preferences keys are preserved. RETURNING 1 detects the
//     not-found case (→ identity.ErrUserNotFound).
//
// RLS: users is identity-scoped (no tenant_id column, no policy) — these
// queries take no SET LOCAL wrapping. Scoping is by gcid = the authenticated
// caller (passed by the handler from AuthCtx, NEVER the request body).
//
// Cross-DB queries forbidden — chora-identity reads only chora_identity.
package pg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// UIPreferencesRepository is the pgx-backed identity.UIPreferencesRepository.
type UIPreferencesRepository struct {
	q Querier
}

// NewUIPreferencesRepository wraps a *PgxPoolQuerier.
func NewUIPreferencesRepository(querier *PgxPoolQuerier) *UIPreferencesRepository {
	return &UIPreferencesRepository{q: querier}
}

// NewUIPreferencesRepositoryWithQuerier accepts the lower-level Querier; used by
// unit tests that stub the SQL surface.
func NewUIPreferencesRepositoryWithQuerier(q Querier) *UIPreferencesRepository {
	return &UIPreferencesRepository{q: q}
}

// dashboardLayoutWire is the JSONB representation of a DashboardLayout stored
// under the ui_preferences.dashboard_layout key. snake_case + RFC3339 to match
// the FE adapter wire shape (SP2 shared contract) exactly — the gateway proxies
// the body verbatim, so this casing reaches the FE unchanged.
type dashboardLayoutWire struct {
	Order     []string `json:"order"`
	UpdatedAt string   `json:"updated_at"`
}

// homeLayoutWire is the JSONB representation of a HomeLayout stored under the
// ui_preferences.home_layout key (ADR-240 D2). Pins are carried as raw JSON
// objects so the FE-owned position fields (D10) round-trip verbatim - the
// backend never interprets them (D11). snake_case + RFC3339 to match the FE.
type homeLayoutWire struct {
	Pins      []json.RawMessage `json:"pins"`
	UpdatedAt string            `json:"updated_at"`
}

// uiPreferencesWire is the whole ui_preferences JSONB column shape.
type uiPreferencesWire struct {
	DashboardLayout *dashboardLayoutWire `json:"dashboard_layout,omitempty"`
	HomeLayout      *homeLayoutWire      `json:"home_layout,omitempty"`
}

// GetUIPreferences returns the caller's UI preferences.
func (r *UIPreferencesRepository) GetUIPreferences(ctx context.Context, gcid string) (*identity.UIPreferences, error) {
	if strings.TrimSpace(gcid) == "" {
		return nil, errors.New("pg.UIPreferencesRepository.GetUIPreferences: gcid required")
	}
	const q = `
        SELECT ui_preferences
        FROM   users
        WHERE  gcid = $1::uuid AND deleted_at IS NULL
    `
	var raw []byte
	if err := r.q.QueryRow(ctx, q, gcid).Scan(&raw); err != nil {
		if errors.Is(err, ErrNoRows) {
			return nil, identity.ErrUserNotFound
		}
		return nil, fmt.Errorf("pg.UIPreferencesRepository.GetUIPreferences: %w", err)
	}
	return decodeUIPreferences(raw)
}

// decodeUIPreferences maps the raw ui_preferences JSONB to the domain slice. A
// nil/empty column or an absent dashboard_layout key yields a zero-value
// UIPreferences (DashboardLayout nil) — never an error.
func decodeUIPreferences(raw []byte) (*identity.UIPreferences, error) {
	out := &identity.UIPreferences{}
	if len(raw) == 0 {
		return out, nil
	}
	var wire uiPreferencesWire
	if err := json.Unmarshal(raw, &wire); err != nil {
		return nil, fmt.Errorf("pg.UIPreferencesRepository: decode ui_preferences: %w", err)
	}
	if wire.DashboardLayout != nil {
		ts, err := time.Parse(time.RFC3339, wire.DashboardLayout.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("pg.UIPreferencesRepository: decode dashboard_layout.updated_at %q: %w",
				wire.DashboardLayout.UpdatedAt, err)
		}
		order := make([]identity.DashboardWrapperKey, 0, len(wire.DashboardLayout.Order))
		for _, k := range wire.DashboardLayout.Order {
			order = append(order, identity.DashboardWrapperKey(k))
		}
		out.DashboardLayout = &identity.DashboardLayout{Order: order, UpdatedAt: ts.UTC()}
	}
	if wire.HomeLayout != nil {
		hl, err := decodeHomeLayout(wire.HomeLayout)
		if err != nil {
			return nil, err
		}
		out.HomeLayout = hl
	}
	return out, nil
}

// decodeHomeLayout maps the home_layout JSONB fragment to the domain value
// object. Each pin's raw bytes are preserved verbatim (position fields, D10);
// the id is extracted for the domain value object (the stored blob was validated
// on write, so the id is present).
func decodeHomeLayout(wire *homeLayoutWire) (*identity.HomeLayout, error) {
	ts, err := time.Parse(time.RFC3339, wire.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("pg.UIPreferencesRepository: decode home_layout.updated_at %q: %w",
			wire.UpdatedAt, err)
	}
	pins := make([]identity.HomePin, 0, len(wire.Pins))
	for _, raw := range wire.Pins {
		var probe struct {
			ID string `json:"id"`
		}
		// Best-effort id extraction - the write path is the validation gate; Raw
		// is what round-trips to the FE regardless.
		_ = json.Unmarshal(raw, &probe)
		buf := make([]byte, len(raw))
		copy(buf, raw)
		pins = append(pins, identity.HomePin{ID: probe.ID, Raw: buf})
	}
	return &identity.HomeLayout{Pins: pins, UpdatedAt: ts.UTC()}, nil
}

// UpsertDashboardLayout jsonb_sets the dashboard_layout key, preserving any
// other ui_preferences keys.
func (r *UIPreferencesRepository) UpsertDashboardLayout(ctx context.Context, gcid string, layout identity.DashboardLayout) error {
	if strings.TrimSpace(gcid) == "" {
		return errors.New("pg.UIPreferencesRepository.UpsertDashboardLayout: gcid required")
	}
	frag, err := encodeDashboardLayout(layout)
	if err != nil {
		return err
	}
	const q = `
        UPDATE users
        SET    ui_preferences = jsonb_set(
                   COALESCE(ui_preferences, '{}'::jsonb),
                   '{dashboard_layout}',
                   $2::jsonb,
                   true),
               updated_at = now()
        WHERE  gcid = $1::uuid AND deleted_at IS NULL
        RETURNING 1
    `
	var hit int
	if err := r.q.QueryRow(ctx, q, gcid, frag).Scan(&hit); err != nil {
		if errors.Is(err, ErrNoRows) {
			return identity.ErrUserNotFound
		}
		return fmt.Errorf("pg.UIPreferencesRepository.UpsertDashboardLayout: %w", err)
	}
	return nil
}

// UpsertHomeLayout jsonb_sets the home_layout key, preserving any other
// ui_preferences keys (incl dashboard_layout) - ADR-240 D2.
func (r *UIPreferencesRepository) UpsertHomeLayout(ctx context.Context, gcid string, layout identity.HomeLayout) error {
	if strings.TrimSpace(gcid) == "" {
		return errors.New("pg.UIPreferencesRepository.UpsertHomeLayout: gcid required")
	}
	frag, err := encodeHomeLayout(layout)
	if err != nil {
		return err
	}
	const q = `
        UPDATE users
        SET    ui_preferences = jsonb_set(
                   COALESCE(ui_preferences, '{}'::jsonb),
                   '{home_layout}',
                   $2::jsonb,
                   true),
               updated_at = now()
        WHERE  gcid = $1::uuid AND deleted_at IS NULL
        RETURNING 1
    `
	var hit int
	if err := r.q.QueryRow(ctx, q, gcid, frag).Scan(&hit); err != nil {
		if errors.Is(err, ErrNoRows) {
			return identity.ErrUserNotFound
		}
		return fmt.Errorf("pg.UIPreferencesRepository.UpsertHomeLayout: %w", err)
	}
	return nil
}

// encodeHomeLayout marshals a HomeLayout to its JSONB fragment. Pins are emitted
// verbatim (each pin's Raw bytes, preserving the FE-owned position fields, D10);
// an empty layout serialises pins as [] (never null) so the empty home (D7)
// round-trips unambiguously.
func encodeHomeLayout(layout identity.HomeLayout) (string, error) {
	pins := make([]json.RawMessage, 0, len(layout.Pins))
	for _, p := range layout.Pins {
		pins = append(pins, json.RawMessage(p.Raw))
	}
	b, err := json.Marshal(homeLayoutWire{
		Pins:      pins,
		UpdatedAt: layout.UpdatedAt.UTC().Format(time.RFC3339),
	})
	if err != nil {
		return "", fmt.Errorf("pg.UIPreferencesRepository: encode home_layout: %w", err)
	}
	return string(b), nil
}

// encodeDashboardLayout marshals a DashboardLayout to its JSONB fragment
// (snake_case, RFC3339 UTC updated_at).
func encodeDashboardLayout(layout identity.DashboardLayout) (string, error) {
	order := make([]string, 0, len(layout.Order))
	for _, k := range layout.Order {
		order = append(order, string(k))
	}
	b, err := json.Marshal(dashboardLayoutWire{
		Order:     order,
		UpdatedAt: layout.UpdatedAt.UTC().Format(time.RFC3339),
	})
	if err != nil {
		return "", fmt.Errorf("pg.UIPreferencesRepository: encode dashboard_layout: %w", err)
	}
	return string(b), nil
}

// Compile-time check.
var _ identity.UIPreferencesRepository = (*UIPreferencesRepository)(nil)
