// me_preferences_handler_test.go — RED-phase specs for the chora-identity
// GCID-scoped UI-preference endpoints (SP2.9):
//
//	GET /api/v1/me/preferences                    read the caller's prefs
//	PUT /api/v1/me/preferences/dashboard-layout   upsert the dashboard layout
//
// Auth: bearer GCID (mesh chora-gcid / gcid header), same convention as the
// economy handlers. The gcid is taken from the auth context, NEVER the body.
package httpadapter_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	httpadapter "github.com/apollo-chora/chora-identity/internal/adapter/http"
	"github.com/apollo-chora/chora-identity/internal/adapter/inmem"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

const prefsTestGCID = "01970000-0000-7000-8000-0000000000aa"

// faultPrefsRepo injects errors on the store surface to exercise the handler's
// fail-loud branches (500 repo error / 401 unknown gcid).
type faultPrefsRepo struct{ getErr, putErr error }

func (f faultPrefsRepo) GetUIPreferences(context.Context, string) (*identity.UIPreferences, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return &identity.UIPreferences{}, nil
}

func (f faultPrefsRepo) UpsertDashboardLayout(context.Context, string, identity.DashboardLayout) error {
	return f.putErr
}

func (f faultPrefsRepo) UpsertHomeLayout(context.Context, string, identity.HomeLayout) error {
	return f.putErr
}

func newPrefsMuxWithStore(t *testing.T, store identity.UIPreferencesRepository) *http.ServeMux {
	t.Helper()
	users := inmem.NewUserRepository()
	if err := users.Save(context.Background(), &identity.User{
		Gcid: prefsTestGCID, Email: "learner@chora.dev",
		IdentityProvider: identity.ProviderOIDC, FederatedSubject: "sub-learner",
		Status: identity.UserStatusActive,
	}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	mux := http.NewServeMux()
	httpadapter.NewMePreferencesHandler(users, store).RegisterRoutes(mux)
	return mux
}

func newPrefsMux(t *testing.T) (*http.ServeMux, *inmem.UIPreferencesRepository) {
	t.Helper()
	users := inmem.NewUserRepository()
	if err := users.Save(context.Background(), &identity.User{
		Gcid:             prefsTestGCID,
		Email:            "learner@chora.dev",
		IdentityProvider: identity.ProviderOIDC,
		FederatedSubject: "sub-learner",
		Status:           identity.UserStatusActive,
	}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	prefs := inmem.NewUIPreferencesRepository().SeedKnownGcids(prefsTestGCID)
	h := httpadapter.NewMePreferencesHandler(users, prefs)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	return mux, prefs
}

func doPrefs(t *testing.T, mux *http.ServeMux, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	r.Header.Set("Authorization", "Bearer x")
	r.Header.Set("gcid", prefsTestGCID) // mesh gcid stamp the gateway forwards
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func TestMePreferences_GET_EmptyStore_OmitsDashboardLayout(t *testing.T) {
	mux, _ := newPrefsMux(t)
	w := doPrefs(t, mux, http.MethodGet, "/api/v1/me/preferences", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200 (body=%s)", w.Code, w.Body.String())
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v (%s)", err, w.Body.String())
	}
	if _, present := got["dashboard_layout"]; present {
		t.Errorf("dashboard_layout must be OMITTED when unset; got %s", w.Body.String())
	}
}

func TestMePreferences_PUT_then_GET_RoundTrip_SnakeCase(t *testing.T) {
	mux, _ := newPrefsMux(t)
	put := doPrefs(t, mux, http.MethodPut, "/api/v1/me/preferences/dashboard-layout",
		`{"order":["cast","map","courses"],"updated_at":"2026-07-06T12:00:00Z"}`)
	if put.Code != http.StatusOK {
		t.Fatalf("PUT status = %d; want 200 (body=%s)", put.Code, put.Body.String())
	}
	// PUT echoes the canonical stored layout under dashboard_layout.
	if !strings.Contains(put.Body.String(), `"dashboard_layout"`) ||
		!strings.Contains(put.Body.String(), `"updated_at"`) {
		t.Errorf("PUT body must echo {dashboard_layout:{order,updated_at}} snake_case; got %s", put.Body.String())
	}

	get := doPrefs(t, mux, http.MethodGet, "/api/v1/me/preferences", "")
	if get.Code != http.StatusOK {
		t.Fatalf("GET status = %d; want 200", get.Code)
	}
	var resp struct {
		DashboardLayout *struct {
			Order     []string `json:"order"`
			UpdatedAt string   `json:"updated_at"`
		} `json:"dashboard_layout"`
	}
	if err := json.Unmarshal(get.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v (%s)", err, get.Body.String())
	}
	if resp.DashboardLayout == nil {
		t.Fatal("dashboard_layout absent after PUT")
	}
	if strings.Join(resp.DashboardLayout.Order, ",") != "cast,map,courses" {
		t.Errorf("order = %v; want [cast map courses] (persisted)", resp.DashboardLayout.Order)
	}
	if resp.DashboardLayout.UpdatedAt != "2026-07-06T12:00:00Z" {
		t.Errorf("updated_at = %q; want the LWW key persisted verbatim (RFC3339)", resp.DashboardLayout.UpdatedAt)
	}
}

func TestMePreferences_PUT_SubsetOK(t *testing.T) {
	mux, _ := newPrefsMux(t)
	w := doPrefs(t, mux, http.MethodPut, "/api/v1/me/preferences/dashboard-layout",
		`{"order":["map"],"updated_at":"2026-07-06T12:00:00Z"}`)
	if w.Code != http.StatusOK {
		t.Errorf("subset order must be accepted; status = %d (body=%s)", w.Code, w.Body.String())
	}
}

func TestMePreferences_PUT_UnknownKey_422(t *testing.T) {
	mux, _ := newPrefsMux(t)
	w := doPrefs(t, mux, http.MethodPut, "/api/v1/me/preferences/dashboard-layout",
		`{"order":["map","atlas"],"updated_at":"2026-07-06T12:00:00Z"}`)
	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("unknown wrapper key must be 422; got %d (body=%s)", w.Code, w.Body.String())
	}
}

func TestMePreferences_PUT_EmptyOrder_422(t *testing.T) {
	mux, _ := newPrefsMux(t)
	w := doPrefs(t, mux, http.MethodPut, "/api/v1/me/preferences/dashboard-layout",
		`{"order":[],"updated_at":"2026-07-06T12:00:00Z"}`)
	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("empty order must be 422; got %d", w.Code)
	}
}

func TestMePreferences_PUT_DuplicateKey_422(t *testing.T) {
	mux, _ := newPrefsMux(t)
	w := doPrefs(t, mux, http.MethodPut, "/api/v1/me/preferences/dashboard-layout",
		`{"order":["map","map"],"updated_at":"2026-07-06T12:00:00Z"}`)
	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("duplicate key must be 422; got %d", w.Code)
	}
}

func TestMePreferences_PUT_BadTimestamp_422(t *testing.T) {
	mux, _ := newPrefsMux(t)
	w := doPrefs(t, mux, http.MethodPut, "/api/v1/me/preferences/dashboard-layout",
		`{"order":["map"],"updated_at":"not-a-timestamp"}`)
	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("unparseable updated_at must be 422; got %d", w.Code)
	}
}

func TestMePreferences_PUT_BadJSON_400(t *testing.T) {
	mux, _ := newPrefsMux(t)
	w := doPrefs(t, mux, http.MethodPut, "/api/v1/me/preferences/dashboard-layout", `{not json`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("malformed JSON must be 400; got %d", w.Code)
	}
}

func TestMePreferences_GET_MethodNotAllowed(t *testing.T) {
	mux, _ := newPrefsMux(t)
	w := doPrefs(t, mux, http.MethodPost, "/api/v1/me/preferences", "")
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /preferences must be 405; got %d", w.Code)
	}
}

func TestMePreferences_DashboardLayout_MethodNotAllowed(t *testing.T) {
	mux, _ := newPrefsMux(t)
	w := doPrefs(t, mux, http.MethodGet, "/api/v1/me/preferences/dashboard-layout", "")
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /preferences/dashboard-layout must be 405 (PUT only); got %d", w.Code)
	}
}

func TestMePreferences_GET_RepoError_500(t *testing.T) {
	mux := newPrefsMuxWithStore(t, faultPrefsRepo{getErr: errors.New("db down")})
	w := doPrefs(t, mux, http.MethodGet, "/api/v1/me/preferences", "")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("repo error must surface as 500 (fail-loud); got %d", w.Code)
	}
}

func TestMePreferences_GET_UnknownGcid_401(t *testing.T) {
	mux := newPrefsMuxWithStore(t, faultPrefsRepo{getErr: identity.ErrUserNotFound})
	w := doPrefs(t, mux, http.MethodGet, "/api/v1/me/preferences", "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("ErrUserNotFound must be 401; got %d", w.Code)
	}
}

func TestMePreferences_PUT_RepoError_500(t *testing.T) {
	mux := newPrefsMuxWithStore(t, faultPrefsRepo{putErr: errors.New("db down")})
	w := doPrefs(t, mux, http.MethodPut, "/api/v1/me/preferences/dashboard-layout",
		`{"order":["map"],"updated_at":"2026-07-06T12:00:00Z"}`)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("upsert repo error must surface as 500; got %d", w.Code)
	}
}

func TestMePreferences_PUT_UnknownGcid_401(t *testing.T) {
	mux := newPrefsMuxWithStore(t, faultPrefsRepo{putErr: identity.ErrUserNotFound})
	w := doPrefs(t, mux, http.MethodPut, "/api/v1/me/preferences/dashboard-layout",
		`{"order":["map"],"updated_at":"2026-07-06T12:00:00Z"}`)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("upsert ErrUserNotFound must be 401; got %d", w.Code)
	}
}

// The gcid is the authenticated caller's — a body-supplied gcid MUST be ignored
// (project_gateway_bff_tenant_from_authctx). Persisting under a body gcid would
// be a cross-account write.
func TestMePreferences_PUT_IgnoresBodyGcid(t *testing.T) {
	mux, prefs := newPrefsMux(t)
	w := doPrefs(t, mux, http.MethodPut, "/api/v1/me/preferences/dashboard-layout",
		`{"gcid":"01970000-0000-7000-8000-0000000000ff","order":["map"],"updated_at":"2026-07-06T12:00:00Z"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200", w.Code)
	}
	// Written under the AUTH gcid, not the body gcid.
	got, _ := prefs.GetUIPreferences(context.Background(), prefsTestGCID)
	if got.DashboardLayout == nil {
		t.Error("layout must be stored under the authenticated gcid, not the body gcid")
	}
	other, _ := prefs.GetUIPreferences(context.Background(), "01970000-0000-7000-8000-0000000000ff")
	if other.DashboardLayout != nil {
		t.Error("layout must NOT be stored under the body-supplied gcid")
	}
}
