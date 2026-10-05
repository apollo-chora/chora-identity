// Package httpadapter_test — coverage extras for handler.go weak functions.
//
// All tests here are additive: they exercise error paths / router fallthroughs
// of handler.go that handler_test.go / me_handler_test.go do not reach.
// Helpers defined below carry the hx_ prefix per the package convention.
package httpadapter_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	httpadapter "github.com/apollo-chora/chora-identity/internal/adapter/http"
	"github.com/apollo-chora/chora-identity/internal/adapter/inmem"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// hx_rawAuthedReq is authedReq but with a raw string body (for malformed-JSON
// cases that json.Marshal cannot produce).
func hx_rawAuthedReq(method, path, rawBody string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(rawBody))
	r.Header.Set("X-Tenant-Id", tenantA)
	r.Header.Set("gcid", gcidA)
	r.Header.Set("Content-Type", "application/json")
	return r
}

// hx_createUser seeds a user via POST /api/users and returns the minted gcid.
func hx_createUser(t *testing.T, srv http.Handler) string {
	t.Helper()
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedReq(http.MethodPost, "/api/users", map[string]any{
		"email":             "hx-user@chora.dev",
		"identity_provider": "oidc",
		"federated_subject": "hx-sub",
	}))
	if w.Code != http.StatusCreated {
		t.Fatalf("seed user status = %d body=%s", w.Code, w.Body.String())
	}
	var u map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &u); err != nil {
		t.Fatalf("seed user invalid json: %v", err)
	}
	gcid, _ := u["gcid"].(string)
	if gcid == "" {
		t.Fatalf("seed user response missing gcid: %v", u)
	}
	return gcid
}

// hx_serverWithClosedUser returns a router whose user repo contains one
// pre-closed user (seeded directly — no HTTP close endpoint exists), plus the
// user's gcid.
func hx_serverWithClosedUser(t *testing.T, email string) (http.Handler, string) {
	t.Helper()
	users := inmem.NewUserRepository()
	u, err := identity.NewUser(identity.NewUserParams{
		Email:            email,
		IdentityProvider: identity.ProviderOIDC,
		FederatedSubject: "hx-closed-sub-" + email,
	})
	if err != nil {
		t.Fatalf("new user: %v", err)
	}
	u.Close()
	if err := users.Save(context.Background(), u); err != nil {
		t.Fatalf("save closed user: %v", err)
	}
	srv := httpadapter.NewRouter(users, inmem.NewMembershipRepository(), inmem.NewSnapshotRepository())
	return srv, u.Gcid
}

// -----------------------------------------------------------------------------
// emptyCourseRoleRepo.GetAssignment (legacy NewRouter) + readyz + index
// -----------------------------------------------------------------------------

func TestGetAssignment_EmptyCourseRoleRepo_ReturnsRoleNone(t *testing.T) {
	t.Parallel()
	// newServer uses NewRouter → wires emptyCourseRoleRepo; any course lookup
	// must resolve to role=none / perms=[] (mirrors me_handler_test.go's
	// no-assignment assertions).
	srv := newServer(t)
	gcid := hx_createUser(t, srv) // bearer auth requires an existing user
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerReq(http.MethodGet, "/me/roles?course_id="+courseCSPO, gcid))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s; want 200", w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if got["role"] != "none" {
		t.Errorf("role=%v want none", got["role"])
	}
	perms, _ := got["permissions"].([]any)
	if len(perms) != 0 {
		t.Errorf("permissions size=%d; want 0", len(perms))
	}
	if got["gcid"] != gcid {
		t.Errorf("gcid=%v want %s", got["gcid"], gcid)
	}
}

func TestReadyz_Returns503WhenReposUninitialised(t *testing.T) {
	t.Parallel()
	srv := httpadapter.NewRouter(nil, nil, nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status=%d; want 503", w.Code)
	}
	if !strings.Contains(w.Body.String(), "repos-uninitialised") {
		t.Errorf("body missing repos-uninitialised: %s", w.Body.String())
	}
}

func TestIndexHandler_ReturnsServiceInfoOnRoot(t *testing.T) {
	t.Parallel()
	srv := newServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d; want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "chora-identity") || !strings.Contains(body, "Identity (supporting)") {
		t.Errorf("index body missing service info: %s", body)
	}
}

func TestIndexHandler_404OnUnknownPath(t *testing.T) {
	t.Parallel()
	srv := newServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedReq(http.MethodGet, "/some/unknown/path", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("status=%d; want 404", w.Code)
	}
}

// -----------------------------------------------------------------------------
// /api/users  (collection + item dispatchers + createUser decode paths)
// -----------------------------------------------------------------------------

func TestUsersCollection_PutReturns405(t *testing.T) {
	t.Parallel()
	srv := newServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedReq(http.MethodPut, "/api/users", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status=%d; want 405", w.Code)
	}
	if !strings.Contains(w.Body.String(), "METHOD_NOT_ALLOWED") {
		t.Errorf("body missing METHOD_NOT_ALLOWED: %s", w.Body.String())
	}
}

func TestCreateUser_MalformedJSON_Returns400(t *testing.T) {
	t.Parallel()
	srv := newServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, hx_rawAuthedReq(http.MethodPost, "/api/users", `{"email":`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d; want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "IDENTITY_INVALID_BODY") {
		t.Errorf("body missing IDENTITY_INVALID_BODY: %s", w.Body.String())
	}
}

func TestCreateUser_EmptyBody_Returns400(t *testing.T) {
	t.Parallel()
	srv := newServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedReq(http.MethodPost, "/api/users", nil))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status=%d; want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "IDENTITY_INVALID_BODY") {
		t.Errorf("body missing IDENTITY_INVALID_BODY: %s", w.Body.String())
	}
}

func TestCreateUser_NilBody_Returns400(t *testing.T) {
	t.Parallel()
	srv := newServer(t)
	// decodeJSON's `r.Body == nil` guard — reachable only by constructing a
	// request with an explicitly nil body (httptest otherwise uses http.NoBody).
	r := httptest.NewRequest(http.MethodPost, "/api/users", nil)
	r.Body = nil
	r.Header.Set("X-Tenant-Id", tenantA)
	r.Header.Set("gcid", gcidA)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status=%d; want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "IDENTITY_INVALID_BODY") {
		t.Errorf("body missing IDENTITY_INVALID_BODY: %s", w.Body.String())
	}
}

func TestCreateUser_UnknownField_Returns400(t *testing.T) {
	t.Parallel()
	srv := newServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, hx_rawAuthedReq(http.MethodPost, "/api/users", `{"nope":1}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d; want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "IDENTITY_INVALID_BODY") {
		t.Errorf("body missing IDENTITY_INVALID_BODY: %s", w.Body.String())
	}
}

func TestCreateUser_TrailingGarbageAfterJSONObject_IsIgnoredByDecoder(t *testing.T) {
	t.Parallel()
	// decodeJSON uses a single json.Decoder.Decode call, which reads only the
	// FIRST JSON value and ignores trailing bytes — the object below decodes
	// cleanly. It is then rejected by the User constructor (missing
	// identity_provider) with 400 IDENTITY_INVALID_USER, NOT a decode error.
	srv := newServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, hx_rawAuthedReq(http.MethodPost, "/api/users", `{"email":"garbage@chora.dev"}x`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d; want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "IDENTITY_INVALID_USER") {
		t.Errorf("body missing IDENTITY_INVALID_USER: %s", w.Body.String())
	}
}

// -----------------------------------------------------------------------------
// /api/users/{gcid}  (item dispatcher branches)
// -----------------------------------------------------------------------------

func TestUsersItem_MissingGcid_Returns404(t *testing.T) {
	t.Parallel()
	srv := newServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedReq(http.MethodGet, "/api/users/", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("status=%d; want 404", w.Code)
	}
	if !strings.Contains(w.Body.String(), "missing gcid") {
		t.Errorf("body missing 'missing gcid': %s", w.Body.String())
	}
}

func TestUsersItem_UnknownSubResource_Returns404(t *testing.T) {
	t.Parallel()
	srv := newServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedReq(http.MethodGet, "/api/users/"+gcidA+"/bogus", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("status=%d; want 404", w.Code)
	}
	if !strings.Contains(w.Body.String(), "unknown sub-resource") {
		t.Errorf("body missing 'unknown sub-resource': %s", w.Body.String())
	}
}

func TestUsersItem_PutReturns405(t *testing.T) {
	t.Parallel()
	srv := newServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedReq(http.MethodPut, "/api/users/"+gcidA, nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status=%d; want 405", w.Code)
	}
	if !strings.Contains(w.Body.String(), "METHOD_NOT_ALLOWED") {
		t.Errorf("body missing METHOD_NOT_ALLOWED: %s", w.Body.String())
	}
}

func TestUsersItem_ExportWrongMethod_Returns405(t *testing.T) {
	t.Parallel()
	srv := newServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedReq(http.MethodGet, "/api/users/"+gcidA+"/portability/export", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status=%d; want 405", w.Code)
	}
	if !strings.Contains(w.Body.String(), "only POST") {
		t.Errorf("body missing 'only POST': %s", w.Body.String())
	}
}

func TestUsersItem_SnapshotsWrongMethod_Returns405(t *testing.T) {
	t.Parallel()
	srv := newServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedReq(http.MethodPost, "/api/users/"+gcidA+"/portability/snapshots", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status=%d; want 405", w.Code)
	}
	if !strings.Contains(w.Body.String(), "only GET") {
		t.Errorf("body missing 'only GET': %s", w.Body.String())
	}
}

func TestUsersItem_UnknownPortabilitySubResource_Returns404(t *testing.T) {
	t.Parallel()
	srv := newServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedReq(http.MethodGet, "/api/users/"+gcidA+"/portability/whatever", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("status=%d; want 404", w.Code)
	}
	if !strings.Contains(w.Body.String(), "unknown sub-resource") {
		t.Errorf("body missing 'unknown sub-resource': %s", w.Body.String())
	}
}

// -----------------------------------------------------------------------------
// /api/memberships  (collection + item dispatchers + createMembership paths)
// -----------------------------------------------------------------------------

func TestMembershipsCollection_PutReturns405(t *testing.T) {
	t.Parallel()
	srv := newServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedReq(http.MethodPut, "/api/memberships", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status=%d; want 405", w.Code)
	}
	if !strings.Contains(w.Body.String(), "METHOD_NOT_ALLOWED") {
		t.Errorf("body missing METHOD_NOT_ALLOWED: %s", w.Body.String())
	}
}

func TestCreateMembership_MalformedJSON_Returns400(t *testing.T) {
	t.Parallel()
	srv := newServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, hx_rawAuthedReq(http.MethodPost, "/api/memberships", `{"gcid":`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d; want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "IDENTITY_INVALID_BODY") {
		t.Errorf("body missing IDENTITY_INVALID_BODY: %s", w.Body.String())
	}
}

func TestCreateMembership_InvalidRole_Returns400(t *testing.T) {
	t.Parallel()
	srv := newServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedReq(http.MethodPost, "/api/memberships", map[string]any{
		"gcid": gcidB, "tenant_id": tenantA, "role": "godmode",
	}))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d; want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "IDENTITY_INVALID_MEMBERSHIP") {
		t.Errorf("body missing IDENTITY_INVALID_MEMBERSHIP: %s", w.Body.String())
	}
}

func TestCreateMembership_MissingFields_Returns400(t *testing.T) {
	t.Parallel()
	srv := newServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedReq(http.MethodPost, "/api/memberships", map[string]any{
		"tenant_id": tenantA, "role": "learner",
	}))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d; want 400 (missing gcid)", w.Code)
	}
	if !strings.Contains(w.Body.String(), "IDENTITY_INVALID_MEMBERSHIP") {
		t.Errorf("body missing IDENTITY_INVALID_MEMBERSHIP: %s", w.Body.String())
	}
}

func TestMembershipsItem_MissingID_Returns404(t *testing.T) {
	t.Parallel()
	srv := newServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedReq(http.MethodGet, "/api/memberships/", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("status=%d; want 404", w.Code)
	}
	if !strings.Contains(w.Body.String(), "missing membership id") {
		t.Errorf("body missing 'missing membership id': %s", w.Body.String())
	}
}

func TestMembershipsItem_UnknownSubResource_Returns404(t *testing.T) {
	t.Parallel()
	srv := newServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedReq(http.MethodGet, "/api/memberships/"+gcidA+"/bogus", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("status=%d; want 404", w.Code)
	}
	if !strings.Contains(w.Body.String(), "unknown sub-resource") {
		t.Errorf("body missing 'unknown sub-resource': %s", w.Body.String())
	}
}

func TestMembershipsItem_RoleWrongMethod_Returns405(t *testing.T) {
	t.Parallel()
	srv := newServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedReq(http.MethodGet, "/api/memberships/"+gcidA+"/role", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status=%d; want 405", w.Code)
	}
	if !strings.Contains(w.Body.String(), "only PATCH") {
		t.Errorf("body missing 'only PATCH': %s", w.Body.String())
	}
}

func TestChangeRole_MalformedJSON_Returns400(t *testing.T) {
	t.Parallel()
	srv := newServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, hx_rawAuthedReq(http.MethodPatch, "/api/memberships/"+gcidA+"/role", `{"role":`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d; want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "IDENTITY_INVALID_BODY") {
		t.Errorf("body missing IDENTITY_INVALID_BODY: %s", w.Body.String())
	}
}

// -----------------------------------------------------------------------------
// Portability — closed users cannot export
// -----------------------------------------------------------------------------

func TestExportSnapshot_ClosedUser_Returns403(t *testing.T) {
	t.Parallel()
	srv, gcid := hx_serverWithClosedUser(t, "closed@chora.dev")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedReq(http.MethodPost, "/api/users/"+gcid+"/portability/export", nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s; want 403", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "IDENTITY_USER_CLOSED") {
		t.Errorf("body missing IDENTITY_USER_CLOSED: %s", w.Body.String())
	}
}
