// me_preferences_handler.go — chora-identity GCID-scoped UI-preference endpoints
// (SP2.9, A+ dashboard-as-hub layout persistence):
//
//	GET /api/v1/me/preferences                    read the caller's UI prefs
//	PUT /api/v1/me/preferences/dashboard-layout   upsert the dashboard layout
//
// The dashboard layout is a GCID-scoped account preference stored on the User
// profile aggregate (users.ui_preferences JSONB, migration 0034). The gcid is
// resolved from the bearer/mesh auth context (bearerAuth → gcidFromContext),
// NEVER the request body (project_gateway_bff_tenant_from_authctx) — a
// body-supplied gcid is a cross-account write and is ignored.
//
// Auth shape mirrors the economy handlers: bearerAuth verifies the gcid exists
// (unknown gcid → 401) then injects it into the request context.
package httpadapter

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// MePreferencesHandler serves the /api/v1/me/preferences[...] routes.
type MePreferencesHandler struct {
	users identity.UserRepository
	prefs identity.UIPreferencesRepository
}

// NewMePreferencesHandler wires the user repo (bearer auth) + the UI-preference
// store.
func NewMePreferencesHandler(users identity.UserRepository, prefs identity.UIPreferencesRepository) *MePreferencesHandler {
	return &MePreferencesHandler{users: users, prefs: prefs}
}

// RegisterRoutes mounts the preference routes on a mux, each behind bearerAuth.
func (h *MePreferencesHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.Handle("/api/v1/me/preferences", bearerAuth(h.users, http.HandlerFunc(h.getPreferences)))
	mux.Handle("/api/v1/me/preferences/dashboard-layout", bearerAuth(h.users, http.HandlerFunc(h.putDashboardLayout)))
	mux.Handle("/api/v1/me/preferences/home-layout", bearerAuth(h.users, http.HandlerFunc(h.putHomeLayout)))
}

// -----------------------------------------------------------------------------
// Wire DTOs — snake_case + RFC3339 to match the FE adapter (SP2 shared
// contract). The gateway proxies the body verbatim, so this casing is what the
// FE receives.
// -----------------------------------------------------------------------------

type dashboardLayoutDTO struct {
	Order     []string `json:"order"`
	UpdatedAt string   `json:"updated_at"`
}

// homeLayoutRequest is the inbound PUT body (ADR-240). Pins is a POINTER so the
// handler distinguishes an absent/null pins (a structural violation - "pins must
// be an array") from an empty pins list (a legitimate empty home, D7). Each pin
// is a raw JSON object forwarded verbatim except for its id, which is validated.
type homeLayoutRequest struct {
	Pins      *[]json.RawMessage `json:"pins"`
	UpdatedAt string             `json:"updated_at"`
}

// homeLayoutDTO is the outbound home_layout shape - pins echoed verbatim (the
// FE-owned position fields, D10) + the RFC3339 LWW key.
type homeLayoutDTO struct {
	Pins      []json.RawMessage `json:"pins"`
	UpdatedAt string            `json:"updated_at"`
}

type mePreferencesResponse struct {
	DashboardLayout *dashboardLayoutDTO `json:"dashboard_layout,omitempty"`
	HomeLayout      *homeLayoutDTO      `json:"home_layout,omitempty"`
}

// -----------------------------------------------------------------------------
// GET /api/v1/me/preferences
// -----------------------------------------------------------------------------

func (h *MePreferencesHandler) getPreferences(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET only")
		return
	}
	gcid := gcidFromContext(r.Context())
	prefs, err := h.prefs.GetUIPreferences(r.Context(), gcid)
	if err != nil {
		if errors.Is(err, identity.ErrUserNotFound) {
			writeError(w, http.StatusUnauthorized, "IDENTITY_UNKNOWN_GCID", "unknown bearer gcid")
			return
		}
		log.Printf("me/preferences get error: %v", err)
		writeError(w, http.StatusInternalServerError, "IDENTITY_REPO_ERROR", "internal error")
		return
	}
	writeJSON(w, http.StatusOK, toPreferencesResponse(prefs))
}

// -----------------------------------------------------------------------------
// PUT /api/v1/me/preferences/dashboard-layout
// -----------------------------------------------------------------------------

func (h *MePreferencesHandler) putDashboardLayout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "PUT only")
		return
	}
	gcid := gcidFromContext(r.Context())

	var req dashboardLayoutDTO
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "IDENTITY_BAD_JSON", "request body must be JSON {order,updated_at}")
		return
	}

	order := make([]identity.DashboardWrapperKey, 0, len(req.Order))
	for _, k := range req.Order {
		order = append(order, identity.DashboardWrapperKey(k))
	}
	// Authoritative validation — the gateway edge-guards too, but a caller
	// bypassing the gateway must still be rejected (fail-loud, DDD).
	if err := identity.ValidateDashboardOrder(order); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "IDENTITY_INVALID_DASHBOARD_ORDER", err.Error())
		return
	}
	updatedAt, err := time.Parse(time.RFC3339, req.UpdatedAt)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "IDENTITY_INVALID_DASHBOARD_UPDATED_AT",
			"updated_at must be an RFC3339 timestamp")
		return
	}

	layout := identity.DashboardLayout{Order: order, UpdatedAt: updatedAt.UTC()}
	if err := h.prefs.UpsertDashboardLayout(r.Context(), gcid, layout); err != nil {
		if errors.Is(err, identity.ErrUserNotFound) {
			writeError(w, http.StatusUnauthorized, "IDENTITY_UNKNOWN_GCID", "unknown bearer gcid")
			return
		}
		log.Printf("me/preferences dashboard-layout upsert error: %v", err)
		writeError(w, http.StatusInternalServerError, "IDENTITY_REPO_ERROR", "internal error")
		return
	}
	// Echo the canonical stored layout so the FE can confirm the persisted value.
	writeJSON(w, http.StatusOK, mePreferencesResponse{DashboardLayout: layoutToDTO(&layout)})
}

// -----------------------------------------------------------------------------
// PUT /api/v1/me/preferences/home-layout  (ADR-240 Track B)
// -----------------------------------------------------------------------------

func (h *MePreferencesHandler) putHomeLayout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "PUT only")
		return
	}
	gcid := gcidFromContext(r.Context())

	var req homeLayoutRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "IDENTITY_BAD_JSON", "request body must be JSON {pins,updated_at}")
		return
	}
	// "pins is an array" is a STRUCTURAL rule (ADR-240 D11): an absent/null pins
	// is not an array. An empty array is a legitimate empty home (D7).
	if req.Pins == nil {
		writeError(w, http.StatusUnprocessableEntity, "IDENTITY_INVALID_HOME_LAYOUT", "pins must be an array")
		return
	}
	pins, err := toDomainHomePins(*req.Pins)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "IDENTITY_INVALID_HOME_LAYOUT", err.Error())
		return
	}
	// Authoritative STRUCTURAL validation - bounded count, non-empty bounded ids,
	// no duplicates. NEVER the id vocabulary (D11); an unknown id is inert (D4).
	if err := identity.ValidateHomePins(pins); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "IDENTITY_INVALID_HOME_LAYOUT", err.Error())
		return
	}
	updatedAt, err := time.Parse(time.RFC3339, req.UpdatedAt)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "IDENTITY_INVALID_HOME_UPDATED_AT",
			"updated_at must be an RFC3339 timestamp")
		return
	}

	layout := identity.HomeLayout{Pins: pins, UpdatedAt: updatedAt.UTC()}
	if err := h.prefs.UpsertHomeLayout(r.Context(), gcid, layout); err != nil {
		if errors.Is(err, identity.ErrUserNotFound) {
			writeError(w, http.StatusUnauthorized, "IDENTITY_UNKNOWN_GCID", "unknown bearer gcid")
			return
		}
		log.Printf("me/preferences home-layout upsert error: %v", err)
		writeError(w, http.StatusInternalServerError, "IDENTITY_REPO_ERROR", "internal error")
		return
	}
	// Echo the canonical stored layout so the FE can confirm the persisted value.
	writeJSON(w, http.StatusOK, mePreferencesResponse{HomeLayout: homeLayoutToDTO(&layout)})
}

// toDomainHomePins converts the raw inbound pin objects to domain HomePins. Each
// pin MUST be a JSON object with a string id (extracted for validation); the raw
// bytes are copied and preserved verbatim (position fields, D10 - the backend
// never interprets them, D11). A non-object pin (or a non-string id) is a
// structural violation.
func toDomainHomePins(raws []json.RawMessage) ([]identity.HomePin, error) {
	pins := make([]identity.HomePin, 0, len(raws))
	for _, raw := range raws {
		var probe struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(raw, &probe); err != nil {
			return nil, identity.ErrHomePinNotObject
		}
		buf := make([]byte, len(raw))
		copy(buf, raw)
		pins = append(pins, identity.HomePin{ID: probe.ID, Raw: buf})
	}
	return pins, nil
}

// -----------------------------------------------------------------------------
// Mapping
// -----------------------------------------------------------------------------

func toPreferencesResponse(p *identity.UIPreferences) mePreferencesResponse {
	if p == nil {
		return mePreferencesResponse{}
	}
	return mePreferencesResponse{
		DashboardLayout: layoutToDTO(p.DashboardLayout),
		HomeLayout:      homeLayoutToDTO(p.HomeLayout),
	}
}

func homeLayoutToDTO(l *identity.HomeLayout) *homeLayoutDTO {
	if l == nil {
		return nil
	}
	pins := make([]json.RawMessage, 0, len(l.Pins))
	for _, p := range l.Pins {
		pins = append(pins, json.RawMessage(p.Raw))
	}
	return &homeLayoutDTO{
		Pins:      pins,
		UpdatedAt: l.UpdatedAt.UTC().Format(time.RFC3339),
	}
}

func layoutToDTO(l *identity.DashboardLayout) *dashboardLayoutDTO {
	if l == nil {
		return nil
	}
	order := make([]string, 0, len(l.Order))
	for _, k := range l.Order {
		order = append(order, string(k))
	}
	return &dashboardLayoutDTO{
		Order:     order,
		UpdatedAt: l.UpdatedAt.UTC().Format(time.RFC3339),
	}
}
