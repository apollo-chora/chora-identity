// Package httpadapter_test exercises GET /me + GET /me/roles per Comic
// Ch4 P8 "I Am Two People" → "One Identity to Rule Them All".
//
// Header convention: `Authorization: Bearer <gcid>` (skeleton — no real OIDC
// validation; that lands at M12+). User must exist in the in-memory user repo
// or 401.
package httpadapter_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	httpadapter "github.com/apollo-chora/chora-identity/internal/adapter/http"
	"github.com/apollo-chora/chora-identity/internal/adapter/inmem"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// Comic seed values (also exposed by inmem.SeedComicFixtures).
const (
	phyllisGcid    = "01935b5a-9bcf-7000-8000-000000000001"
	chenGcid       = "01935b5a-9bcf-7000-8000-000000000002"
	courseCSPO     = "01935b5a-9bcf-7000-8000-000000000099"
	courseCSM      = "01935b5a-9bcf-7000-8000-000000000098"
	tenantMightyMS = "01935b5a-9bcf-7000-8000-000000000010"
)

// newSeededServer returns a router with Comic Ch4 P8 fixtures loaded into the
// in-memory repos (Phyllis = instructor on CSPO, learner on CSM; Chen =
// instructor on CSM).
func newSeededServer(t *testing.T) http.Handler {
	t.Helper()
	users := inmem.NewUserRepository()
	memberships := inmem.NewMembershipRepository()
	snapshots := inmem.NewSnapshotRepository()
	courseRoles := inmem.NewCourseRoleRepository()
	if err := inmem.SeedComicFixtures(users, courseRoles); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return httpadapter.NewRouterWithCourseRoles(users, memberships, snapshots, courseRoles)
}

func bearerReq(method, path, gcid string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	if gcid != "" {
		r.Header.Set("Authorization", "Bearer "+gcid)
	}
	r.Header.Set("Content-Type", "application/json")
	return r
}

// -----------------------------------------------------------------------------
// GET /me
// -----------------------------------------------------------------------------

func TestGetMe_HappyPath_Returns200WithProfile(t *testing.T) {
	t.Parallel()
	srv := newSeededServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerReq(http.MethodGet, "/me", phyllisGcid))

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s; want 200", w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if got["gcid"] != phyllisGcid {
		t.Errorf("gcid=%v want %s", got["gcid"], phyllisGcid)
	}
	if got["email"] != "phyllis@mightymind.sg" {
		t.Errorf("email=%v want phyllis@mightymind.sg", got["email"])
	}
	if got["display_name"] != "Phyllis Tan" {
		t.Errorf("display_name=%v want Phyllis Tan", got["display_name"])
	}
	if got["created_at"] == nil || got["created_at"] == "" {
		t.Errorf("created_at missing")
	}
	authMethods, ok := got["auth_methods"].([]any)
	if !ok || len(authMethods) == 0 {
		t.Errorf("auth_methods missing or empty: %v", got["auth_methods"])
	}
	linkedIdps, ok := got["linked_idps"].([]any)
	if !ok || len(linkedIdps) == 0 {
		t.Errorf("linked_idps missing or empty: %v", got["linked_idps"])
	}
}

func TestGetMe_NoBearerHeader_Returns401(t *testing.T) {
	t.Parallel()
	srv := newSeededServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerReq(http.MethodGet, "/me", ""))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status=%d body=%s; want 401", w.Code, w.Body.String())
	}
}

func TestGetMe_UnknownGcid_Returns401(t *testing.T) {
	t.Parallel()
	srv := newSeededServer(t)
	w := httptest.NewRecorder()
	// Valid UUIDv7 shape but not in the seeded repo.
	srv.ServeHTTP(w, bearerReq(http.MethodGet, "/me",
		"01935b5a-9bcf-7000-8000-0000000000ff"))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status=%d; want 401", w.Code)
	}
}

func TestGetMe_MalformedAuthorization_Returns401(t *testing.T) {
	t.Parallel()
	srv := newSeededServer(t)
	r := httptest.NewRequest(http.MethodGet, "/me", nil)
	r.Header.Set("Authorization", "NotBearer xxx")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status=%d; want 401", w.Code)
	}
}

// -----------------------------------------------------------------------------
// GET /me/roles?course_id=X
// -----------------------------------------------------------------------------

func TestGetMeRoles_PhyllisInstructorOnCSPO(t *testing.T) {
	t.Parallel()
	srv := newSeededServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerReq(http.MethodGet, "/me/roles?course_id="+courseCSPO, phyllisGcid))

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s; want 200", w.Code, w.Body.String())
	}
	var got map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got["gcid"] != phyllisGcid {
		t.Errorf("gcid=%v want %s", got["gcid"], phyllisGcid)
	}
	if got["course_id"] != courseCSPO {
		t.Errorf("course_id=%v want %s", got["course_id"], courseCSPO)
	}
	if got["tenant_id"] != tenantMightyMS {
		t.Errorf("tenant_id=%v want %s", got["tenant_id"], tenantMightyMS)
	}
	if got["role"] != "instructor" {
		t.Errorf("role=%v want instructor", got["role"])
	}
	perms, ok := got["permissions"].([]any)
	if !ok {
		t.Fatalf("permissions not an array: %v", got["permissions"])
	}
	if !containsAll(perms, "author", "grade", "publish", "moderate") {
		t.Errorf("permissions=%v; want author/grade/publish/moderate", perms)
	}
}

func TestGetMeRoles_PhyllisLearnerOnCSM(t *testing.T) {
	t.Parallel()
	srv := newSeededServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerReq(http.MethodGet, "/me/roles?course_id="+courseCSM, phyllisGcid))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var got map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got["role"] != "learner" {
		t.Errorf("role=%v want learner", got["role"])
	}
	perms, _ := got["permissions"].([]any)
	if !containsAll(perms, "read", "submit") {
		t.Errorf("permissions=%v; want read/submit", perms)
	}
}

func TestGetMeRoles_ComicCh4P8_SameGcid_TwoCoursesTwoRoles(t *testing.T) {
	t.Parallel()
	srv := newSeededServer(t)

	w1 := httptest.NewRecorder()
	srv.ServeHTTP(w1, bearerReq(http.MethodGet, "/me/roles?course_id="+courseCSPO, phyllisGcid))
	w2 := httptest.NewRecorder()
	srv.ServeHTTP(w2, bearerReq(http.MethodGet, "/me/roles?course_id="+courseCSM, phyllisGcid))

	var a, b map[string]any
	_ = json.Unmarshal(w1.Body.Bytes(), &a)
	_ = json.Unmarshal(w2.Body.Bytes(), &b)

	// Comic invariant: SAME gcid in BOTH responses.
	if a["gcid"] != b["gcid"] {
		t.Errorf("comic Ch4 P8 invariant violated: a.gcid=%v b.gcid=%v", a["gcid"], b["gcid"])
	}
	if a["gcid"] != phyllisGcid {
		t.Errorf("a.gcid=%v want %s", a["gcid"], phyllisGcid)
	}
	// Different roles per course.
	if a["role"] == b["role"] {
		t.Errorf("expected different roles per course; got %v / %v", a["role"], b["role"])
	}
}

func TestGetMeRoles_PhyllisHasNoRoleOnRandomCourse_ReturnsRoleNone(t *testing.T) {
	t.Parallel()
	srv := newSeededServer(t)
	courseC := "01935b5a-9bcf-7000-8000-0000000000aa"
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerReq(http.MethodGet, "/me/roles?course_id="+courseC, phyllisGcid))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s; want 200", w.Code, w.Body.String())
	}
	var got map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got["role"] != "none" {
		t.Errorf("role=%v want none", got["role"])
	}
	perms, _ := got["permissions"].([]any)
	if len(perms) != 0 {
		t.Errorf("permissions size=%d; want 0", len(perms))
	}
	if got["course_id"] != courseC {
		t.Errorf("course_id=%v want %s", got["course_id"], courseC)
	}
}

func TestGetMeRoles_InvalidCourseIDUUID_Returns400(t *testing.T) {
	t.Parallel()
	srv := newSeededServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerReq(http.MethodGet, "/me/roles?course_id=not-a-uuid", phyllisGcid))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status=%d body=%s; want 400", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "course_id") {
		t.Errorf("error envelope should mention course_id; got %s", w.Body.String())
	}
}

func TestGetMeRoles_MissingCourseIDQuery_Returns400(t *testing.T) {
	t.Parallel()
	srv := newSeededServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerReq(http.MethodGet, "/me/roles", phyllisGcid))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status=%d; want 400", w.Code)
	}
}

func TestGetMeRoles_NoBearer_Returns401(t *testing.T) {
	t.Parallel()
	srv := newSeededServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerReq(http.MethodGet, "/me/roles?course_id="+courseCSPO, ""))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status=%d; want 401", w.Code)
	}
}

func TestGetMeRoles_UnknownGcid_Returns401(t *testing.T) {
	t.Parallel()
	srv := newSeededServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, bearerReq(http.MethodGet,
		"/me/roles?course_id="+courseCSPO,
		"01935b5a-9bcf-7000-8000-0000000000ff"))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status=%d; want 401", w.Code)
	}
}

// -----------------------------------------------------------------------------
// helpers — keep identity import live and assertions terse.
// -----------------------------------------------------------------------------

func containsAll(arr []any, want ...string) bool {
	have := make(map[string]bool, len(arr))
	for _, v := range arr {
		if s, ok := v.(string); ok {
			have[s] = true
		}
	}
	for _, w := range want {
		if !have[w] {
			return false
		}
	}
	return true
}

var _ identity.CourseRole = identity.CourseRoleInstructor
