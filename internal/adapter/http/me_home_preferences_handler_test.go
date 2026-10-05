// me_home_preferences_handler_test.go - RED-phase specs for the chora-identity
// home_layout endpoint (ADR-240 Track B):
//
//	PUT /api/v1/me/preferences/home-layout   upsert the shell /home launcher layout
//
// The READ is the existing GET /api/v1/me/preferences (which now also returns
// home_layout). Reuses the httpadapter_test helpers newPrefsMux /
// newPrefsMuxWithStore / doPrefs / prefsTestGCID / faultPrefsRepo from
// me_preferences_handler_test.go. Per ADR-240 D11 the handler validates STRUCTURE
// only (object, pins array, bounded non-empty string ids, no dups, bounded count,
// parseable updated_at) and NEVER the id vocabulary.
package httpadapter_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

func TestMeHomePreferences_PUT_then_GET_RoundTrip_SnakeCase(t *testing.T) {
	mux, _ := newPrefsMux(t)
	put := doPrefs(t, mux, http.MethodPut, "/api/v1/me/preferences/home-layout",
		`{"pins":[{"id":"a-plus-dashboard","x":0,"y":0},{"id":"wallet","x":1,"y":0}],"updated_at":"2026-07-18T12:00:00Z"}`)
	if put.Code != http.StatusOK {
		t.Fatalf("PUT status = %d; want 200 (body=%s)", put.Code, put.Body.String())
	}
	if !strings.Contains(put.Body.String(), `"home_layout"`) {
		t.Errorf("PUT must echo {home_layout:{pins,updated_at}} snake_case; got %s", put.Body.String())
	}

	get := doPrefs(t, mux, http.MethodGet, "/api/v1/me/preferences", "")
	if get.Code != http.StatusOK {
		t.Fatalf("GET status = %d; want 200", get.Code)
	}
	var resp struct {
		HomeLayout *struct {
			Pins      []map[string]any `json:"pins"`
			UpdatedAt string           `json:"updated_at"`
		} `json:"home_layout"`
	}
	if err := json.Unmarshal(get.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v (%s)", err, get.Body.String())
	}
	if resp.HomeLayout == nil || len(resp.HomeLayout.Pins) != 2 {
		t.Fatalf("home_layout absent/short after PUT: %s", get.Body.String())
	}
	if resp.HomeLayout.Pins[0]["id"] != "a-plus-dashboard" {
		t.Errorf("pin[0].id = %v; want a-plus-dashboard (order preserved)", resp.HomeLayout.Pins[0]["id"])
	}
	// Position fields (D10) preserved verbatim through the round-trip.
	if resp.HomeLayout.Pins[1]["x"] != float64(1) {
		t.Errorf("pin[1].x = %v; want 1 (position fields preserved verbatim)", resp.HomeLayout.Pins[1]["x"])
	}
	if resp.HomeLayout.UpdatedAt != "2026-07-18T12:00:00Z" {
		t.Errorf("updated_at = %q; want the LWW key persisted verbatim (RFC3339)", resp.HomeLayout.UpdatedAt)
	}
}

func TestMeHomePreferences_GET_EmptyStore_OmitsHomeLayout(t *testing.T) {
	mux, _ := newPrefsMux(t)
	w := doPrefs(t, mux, http.MethodGet, "/api/v1/me/preferences", "")
	if strings.Contains(w.Body.String(), "home_layout") {
		t.Errorf("home_layout must be OMITTED when unset; got %s", w.Body.String())
	}
}

// ADR-240 D11: chora-identity NEVER validates the id vocabulary. An id it has
// never heard of must be accepted (the structure is fine); recreating a known-id
// set here would be the exact hand-mirror anti-pattern that broke dashboard_layout.
func TestMeHomePreferences_PUT_UnknownPinId_200_D11(t *testing.T) {
	mux, _ := newPrefsMux(t)
	w := doPrefs(t, mux, http.MethodPut, "/api/v1/me/preferences/home-layout",
		`{"pins":[{"id":"a-totally-unknown-pin-id-9000"}],"updated_at":"2026-07-18T12:00:00Z"}`)
	if w.Code != http.StatusOK {
		t.Errorf("unknown pin id must be accepted (D11); got %d (%s)", w.Code, w.Body.String())
	}
}

func TestMeHomePreferences_PUT_EmptyPins_200_D7(t *testing.T) {
	mux, _ := newPrefsMux(t)
	w := doPrefs(t, mux, http.MethodPut, "/api/v1/me/preferences/home-layout",
		`{"pins":[],"updated_at":"2026-07-18T12:00:00Z"}`)
	if w.Code != http.StatusOK {
		t.Errorf("empty pins is a legitimate empty home (D7); got %d (%s)", w.Code, w.Body.String())
	}
}

func TestMeHomePreferences_PUT_DuplicateId_422(t *testing.T) {
	mux, _ := newPrefsMux(t)
	w := doPrefs(t, mux, http.MethodPut, "/api/v1/me/preferences/home-layout",
		`{"pins":[{"id":"map"},{"id":"map"}],"updated_at":"2026-07-18T12:00:00Z"}`)
	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("duplicate id must be 422; got %d", w.Code)
	}
}

func TestMeHomePreferences_PUT_EmptyId_422(t *testing.T) {
	mux, _ := newPrefsMux(t)
	w := doPrefs(t, mux, http.MethodPut, "/api/v1/me/preferences/home-layout",
		`{"pins":[{"id":""}],"updated_at":"2026-07-18T12:00:00Z"}`)
	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("empty id must be 422; got %d", w.Code)
	}
}

func TestMeHomePreferences_PUT_PinNotObject_422(t *testing.T) {
	mux, _ := newPrefsMux(t)
	w := doPrefs(t, mux, http.MethodPut, "/api/v1/me/preferences/home-layout",
		`{"pins":["not-an-object"],"updated_at":"2026-07-18T12:00:00Z"}`)
	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("a non-object pin must be 422; got %d (%s)", w.Code, w.Body.String())
	}
}

func TestMeHomePreferences_PUT_PinsNotArray_Rejected(t *testing.T) {
	mux, _ := newPrefsMux(t)
	// pins present but not an array - a structural violation (400 bad JSON is fine).
	w := doPrefs(t, mux, http.MethodPut, "/api/v1/me/preferences/home-layout",
		`{"pins":"nope","updated_at":"2026-07-18T12:00:00Z"}`)
	if w.Code != http.StatusBadRequest && w.Code != http.StatusUnprocessableEntity {
		t.Errorf("pins-not-array must be 400/422; got %d", w.Code)
	}
}

func TestMeHomePreferences_PUT_PinsMissing_422(t *testing.T) {
	mux, _ := newPrefsMux(t)
	// pins absent/null - "pins must be an array" structural violation.
	w := doPrefs(t, mux, http.MethodPut, "/api/v1/me/preferences/home-layout",
		`{"updated_at":"2026-07-18T12:00:00Z"}`)
	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("absent pins must be 422 (pins must be an array); got %d", w.Code)
	}
}

func TestMeHomePreferences_PUT_TooManyPins_422(t *testing.T) {
	mux, _ := newPrefsMux(t)
	var b strings.Builder
	b.WriteString(`{"pins":[`)
	for i := 0; i <= identity.MaxHomePins; i++ { // MaxHomePins+1 unique pins
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"id":"pin-` + strconv.Itoa(i) + `"}`)
	}
	b.WriteString(`],"updated_at":"2026-07-18T12:00:00Z"}`)
	w := doPrefs(t, mux, http.MethodPut, "/api/v1/me/preferences/home-layout", b.String())
	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("over-count pins must be 422; got %d", w.Code)
	}
}

func TestMeHomePreferences_PUT_BadTimestamp_422(t *testing.T) {
	mux, _ := newPrefsMux(t)
	w := doPrefs(t, mux, http.MethodPut, "/api/v1/me/preferences/home-layout",
		`{"pins":[{"id":"wallet"}],"updated_at":"not-a-timestamp"}`)
	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("unparseable updated_at must be 422; got %d", w.Code)
	}
}

func TestMeHomePreferences_PUT_BadJSON_400(t *testing.T) {
	mux, _ := newPrefsMux(t)
	w := doPrefs(t, mux, http.MethodPut, "/api/v1/me/preferences/home-layout", `{not json`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("malformed JSON must be 400; got %d", w.Code)
	}
}

func TestMeHomePreferences_HomeLayout_MethodNotAllowed(t *testing.T) {
	mux, _ := newPrefsMux(t)
	w := doPrefs(t, mux, http.MethodGet, "/api/v1/me/preferences/home-layout", "")
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /preferences/home-layout must be 405 (PUT only); got %d", w.Code)
	}
}

func TestMeHomePreferences_PUT_RepoError_500(t *testing.T) {
	mux := newPrefsMuxWithStore(t, faultPrefsRepo{putErr: errors.New("db down")})
	w := doPrefs(t, mux, http.MethodPut, "/api/v1/me/preferences/home-layout",
		`{"pins":[{"id":"wallet"}],"updated_at":"2026-07-18T12:00:00Z"}`)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("upsert repo error must surface as 500; got %d", w.Code)
	}
}

func TestMeHomePreferences_PUT_UnknownGcid_401(t *testing.T) {
	mux := newPrefsMuxWithStore(t, faultPrefsRepo{putErr: identity.ErrUserNotFound})
	w := doPrefs(t, mux, http.MethodPut, "/api/v1/me/preferences/home-layout",
		`{"pins":[{"id":"wallet"}],"updated_at":"2026-07-18T12:00:00Z"}`)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("upsert ErrUserNotFound must be 401; got %d", w.Code)
	}
}

// The gcid is the authenticated caller's - a body-supplied gcid MUST be ignored
// (project_gateway_bff_tenant_from_authctx).
func TestMeHomePreferences_PUT_IgnoresBodyGcid(t *testing.T) {
	mux, prefs := newPrefsMux(t)
	w := doPrefs(t, mux, http.MethodPut, "/api/v1/me/preferences/home-layout",
		`{"gcid":"01970000-0000-7000-8000-0000000000ff","pins":[{"id":"wallet"}],"updated_at":"2026-07-18T12:00:00Z"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200 (body=%s)", w.Code, w.Body.String())
	}
	got, _ := prefs.GetUIPreferences(context.Background(), prefsTestGCID)
	if got.HomeLayout == nil {
		t.Error("home layout must be stored under the authenticated gcid, not the body gcid")
	}
	other, _ := prefs.GetUIPreferences(context.Background(), "01970000-0000-7000-8000-0000000000ff")
	if other.HomeLayout != nil {
		t.Error("home layout must NOT be stored under the body-supplied gcid")
	}
}
