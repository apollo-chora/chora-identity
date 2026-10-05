// Package httpadapter_test exercises the HTTP adapter end-to-end against
// in-memory repositories.
package httpadapter_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	httpadapter "github.com/apollo-chora/chora-identity/internal/adapter/http"
	"github.com/apollo-chora/chora-identity/internal/adapter/inmem"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

const (
	tenantA = "01970000-0000-7000-8000-000000000001"
	tenantB = "01970000-0000-7000-8000-000000000002"
	gcidA   = "01970000-0000-7000-9000-000000000001"
	gcidB   = "01970000-0000-7000-9000-000000000002"
	// AGID shape per CLAUDE.md §1 §3 heuristic: starts with "0197A".
	agidX = "0197A000-0000-7000-9000-000000000001"
)

func newServer(t *testing.T) http.Handler {
	t.Helper()
	users := inmem.NewUserRepository()
	memberships := inmem.NewMembershipRepository()
	snapshots := inmem.NewSnapshotRepository()
	return httpadapter.NewRouter(users, memberships, snapshots)
}

func authedReq(method, path string, body any) *http.Request {
	var buf *bytes.Buffer
	if body != nil {
		b, _ := json.Marshal(body)
		buf = bytes.NewBuffer(b)
	} else {
		buf = bytes.NewBuffer(nil)
	}
	r := httptest.NewRequest(method, path, buf)
	r.Header.Set("X-Tenant-Id", tenantA)
	r.Header.Set("gcid", gcidA)
	r.Header.Set("Content-Type", "application/json")
	return r
}

// -----------------------------------------------------------------------------
// Health + readiness
// -----------------------------------------------------------------------------

func TestHealthz_ReturnsOK(t *testing.T) {
	t.Parallel()
	srv := newServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz/", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d; want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"status":"ok"`) {
		t.Errorf("body missing status:ok: %s", w.Body.String())
	}
}

func TestReadyz_ReturnsOK_WhenReposInitialised(t *testing.T) {
	t.Parallel()
	srv := newServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d; want 200", w.Code)
	}
}

// -----------------------------------------------------------------------------
// POST /api/users
// -----------------------------------------------------------------------------

func TestCreateUser_Returns201AndIssuesGcid(t *testing.T) {
	t.Parallel()
	srv := newServer(t)
	w := httptest.NewRecorder()
	body := map[string]any{
		"email":             "alice@chora.dev",
		"identity_provider": "oidc",
		"federated_subject": "sub-001",
		"display_name":      "Alice",
	}
	srv.ServeHTTP(w, authedReq(http.MethodPost, "/api/users", body))

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s; want 201", w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if got["gcid"] == nil || got["gcid"] == "" {
		t.Errorf("gcid missing in response: %v", got)
	}
	if got["status"] != "active" {
		t.Errorf("status = %v; want active", got["status"])
	}
	if got["email"] != "alice@chora.dev" {
		t.Errorf("email = %v", got["email"])
	}
}

func TestCreateUser_RejectsMissingHeaders(t *testing.T) {
	t.Parallel()
	srv := newServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/users",
		bytes.NewBufferString(`{"email":"a@b.com","identity_provider":"oidc","federated_subject":"x"}`))
	r.Header.Set("Content-Type", "application/json")
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400 when headers missing", w.Code)
	}
}

func TestCreateUser_RejectsInvalidEmail(t *testing.T) {
	t.Parallel()
	srv := newServer(t)
	w := httptest.NewRecorder()
	body := map[string]any{
		"email": "not-an-email", "identity_provider": "oidc", "federated_subject": "x",
	}
	srv.ServeHTTP(w, authedReq(http.MethodPost, "/api/users", body))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", w.Code)
	}
}

func TestCreateUser_RejectsInvalidProvider(t *testing.T) {
	t.Parallel()
	srv := newServer(t)
	w := httptest.NewRecorder()
	body := map[string]any{
		"email": "a@b.com", "identity_provider": "weird", "federated_subject": "x",
	}
	srv.ServeHTTP(w, authedReq(http.MethodPost, "/api/users", body))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", w.Code)
	}
}

// -----------------------------------------------------------------------------
// GET /api/users/{gcid}
// -----------------------------------------------------------------------------

func TestGetUser_ReturnsUser(t *testing.T) {
	t.Parallel()
	srv := newServer(t)

	// Create
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedReq(http.MethodPost, "/api/users", map[string]any{
		"email": "x@y.dev", "identity_provider": "oidc", "federated_subject": "sub-x",
	}))
	var created map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	gcid := created["gcid"].(string)

	// Get
	w2 := httptest.NewRecorder()
	srv.ServeHTTP(w2, authedReq(http.MethodGet, "/api/users/"+gcid, nil))
	if w2.Code != http.StatusOK {
		t.Fatalf("status = %d", w2.Code)
	}
	var got map[string]any
	_ = json.Unmarshal(w2.Body.Bytes(), &got)
	if got["gcid"] != gcid {
		t.Errorf("gcid roundtrip mismatch")
	}
}

func TestGetUser_404OnUnknown(t *testing.T) {
	t.Parallel()
	srv := newServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedReq(http.MethodGet, "/api/users/01970000-0000-7000-aaaa-bbbbbbbbbbbb", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d; want 404", w.Code)
	}
}

// -----------------------------------------------------------------------------
// POST /api/memberships
// -----------------------------------------------------------------------------

func TestCreateMembership_Returns201(t *testing.T) {
	t.Parallel()
	srv := newServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedReq(http.MethodPost, "/api/memberships", map[string]any{
		"gcid":      gcidB,
		"tenant_id": tenantA,
		"role":      "learner",
	}))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	var m map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	if m["membership_id"] == nil {
		t.Errorf("membership_id missing")
	}
	if m["role"] != "learner" {
		t.Errorf("role = %v", m["role"])
	}
}

func TestCreateMembership_RejectsAGIDWith400(t *testing.T) {
	t.Parallel()
	srv := newServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedReq(http.MethodPost, "/api/memberships", map[string]any{
		"gcid":      agidX,
		"tenant_id": tenantA,
		"role":      "learner",
	}))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400 (AGID rejection)", w.Code)
	}
	if !strings.Contains(w.Body.String(), "AGID") {
		t.Errorf("error envelope should mention AGID; got %s", w.Body.String())
	}
}

func TestCreateMembership_RejectsDuplicateWith409(t *testing.T) {
	t.Parallel()
	srv := newServer(t)
	w1 := httptest.NewRecorder()
	srv.ServeHTTP(w1, authedReq(http.MethodPost, "/api/memberships", map[string]any{
		"gcid": gcidB, "tenant_id": tenantA, "role": "learner",
	}))
	if w1.Code != http.StatusCreated {
		t.Fatalf("first status = %d", w1.Code)
	}
	w2 := httptest.NewRecorder()
	srv.ServeHTTP(w2, authedReq(http.MethodPost, "/api/memberships", map[string]any{
		"gcid": gcidB, "tenant_id": tenantA, "role": "instructor",
	}))
	if w2.Code != http.StatusConflict {
		t.Errorf("second status = %d; want 409 (duplicate)", w2.Code)
	}
}

func TestCreateMembership_AllowsSameGcidAcrossTenants(t *testing.T) {
	t.Parallel()
	srv := newServer(t)
	w1 := httptest.NewRecorder()
	srv.ServeHTTP(w1, authedReq(http.MethodPost, "/api/memberships", map[string]any{
		"gcid": gcidB, "tenant_id": tenantA, "role": "learner",
	}))
	w2 := httptest.NewRecorder()
	srv.ServeHTTP(w2, authedReq(http.MethodPost, "/api/memberships", map[string]any{
		"gcid": gcidB, "tenant_id": tenantB, "role": "admin",
	}))
	if w1.Code != http.StatusCreated || w2.Code != http.StatusCreated {
		t.Errorf("expected both 201; got %d / %d", w1.Code, w2.Code)
	}
}

// -----------------------------------------------------------------------------
// GET /api/memberships
// -----------------------------------------------------------------------------

func TestListMemberships_FiltersByTenantAndGcid(t *testing.T) {
	t.Parallel()
	srv := newServer(t)
	for _, body := range []map[string]any{
		{"gcid": gcidA, "tenant_id": tenantA, "role": "admin"},
		{"gcid": gcidB, "tenant_id": tenantA, "role": "learner"},
		{"gcid": gcidA, "tenant_id": tenantB, "role": "auditor"},
	} {
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, authedReq(http.MethodPost, "/api/memberships", body))
		if w.Code != http.StatusCreated {
			t.Fatalf("seed status = %d body=%s", w.Code, w.Body.String())
		}
	}

	// Filter by tenant
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedReq(http.MethodGet, "/api/memberships?tenant_id="+tenantA, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp struct {
		Items []map[string]any `json:"items"`
		Total int              `json:"total"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Total != 2 {
		t.Errorf("size = %d; want 2", resp.Total)
	}

	// Filter by both
	w2 := httptest.NewRecorder()
	srv.ServeHTTP(w2, authedReq(http.MethodGet, "/api/memberships?tenant_id="+tenantA+"&gcid="+gcidA, nil))
	var resp2 struct {
		Items []map[string]any `json:"items"`
		Total int              `json:"total"`
	}
	_ = json.Unmarshal(w2.Body.Bytes(), &resp2)
	if resp2.Total != 1 {
		t.Errorf("size = %d; want 1", resp2.Total)
	}
}

// -----------------------------------------------------------------------------
// PATCH /api/memberships/{id}/role  — audit trail
// -----------------------------------------------------------------------------

func TestPatchRole_AppendsAuditTrailEntry(t *testing.T) {
	t.Parallel()
	srv := newServer(t)
	// Create
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedReq(http.MethodPost, "/api/memberships", map[string]any{
		"gcid": gcidB, "tenant_id": tenantA, "role": "learner",
	}))
	var created map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	mid := created["membership_id"].(string)

	// PATCH role
	w2 := httptest.NewRecorder()
	srv.ServeHTTP(w2, authedReq(http.MethodPatch, "/api/memberships/"+mid+"/role", map[string]any{
		"role": "instructor",
	}))
	if w2.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w2.Code, w2.Body.String())
	}
	var updated map[string]any
	_ = json.Unmarshal(w2.Body.Bytes(), &updated)
	if updated["role"] != "instructor" {
		t.Errorf("role = %v", updated["role"])
	}
	auditTrail, ok := updated["audit_trail"].([]any)
	if !ok || len(auditTrail) != 1 {
		t.Errorf("audit_trail = %v; want 1 entry", updated["audit_trail"])
	}
	entry := auditTrail[0].(map[string]any)
	if entry["prior_role"] != "learner" || entry["new_role"] != "instructor" {
		t.Errorf("audit entry = %v", entry)
	}
	if entry["changed_by_gcid"] != gcidA {
		t.Errorf("changed_by_gcid = %v; want %s", entry["changed_by_gcid"], gcidA)
	}
}

func TestPatchRole_404OnUnknownMembership(t *testing.T) {
	t.Parallel()
	srv := newServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedReq(http.MethodPatch, "/api/memberships/01970000-0000-7000-aaaa-bbbbbbbbbbbb/role",
		map[string]any{"role": "instructor"}))
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d; want 404", w.Code)
	}
}

func TestPatchRole_RejectsInvalidRole(t *testing.T) {
	t.Parallel()
	srv := newServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedReq(http.MethodPost, "/api/memberships", map[string]any{
		"gcid": gcidB, "tenant_id": tenantA, "role": "learner",
	}))
	var created map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	mid := created["membership_id"].(string)

	w2 := httptest.NewRecorder()
	srv.ServeHTTP(w2, authedReq(http.MethodPatch, "/api/memberships/"+mid+"/role",
		map[string]any{"role": "godmode"}))
	if w2.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", w2.Code)
	}
}

// -----------------------------------------------------------------------------
// Portability — append-only snapshots
// -----------------------------------------------------------------------------

func TestExportSnapshot_CreatesNewSnapshotAndIncrementsSequence(t *testing.T) {
	t.Parallel()
	srv := newServer(t)
	// Create user
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedReq(http.MethodPost, "/api/users", map[string]any{
		"email": "p@chora.dev", "identity_provider": "oidc", "federated_subject": "sub-p",
	}))
	var u map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &u)
	gcid := u["gcid"].(string)

	// First export
	w1 := httptest.NewRecorder()
	srv.ServeHTTP(w1, authedReq(http.MethodPost, "/api/users/"+gcid+"/portability/export", nil))
	if w1.Code != http.StatusCreated {
		t.Fatalf("first export status = %d body=%s", w1.Code, w1.Body.String())
	}
	var s1 map[string]any
	_ = json.Unmarshal(w1.Body.Bytes(), &s1)
	if seq1, _ := s1["sequence"].(float64); seq1 != 1 {
		t.Errorf("first sequence = %v; want 1", s1["sequence"])
	}

	// Second export
	w2 := httptest.NewRecorder()
	srv.ServeHTTP(w2, authedReq(http.MethodPost, "/api/users/"+gcid+"/portability/export", nil))
	var s2 map[string]any
	_ = json.Unmarshal(w2.Body.Bytes(), &s2)
	if seq2, _ := s2["sequence"].(float64); seq2 != 2 {
		t.Errorf("second sequence = %v; want 2", s2["sequence"])
	}

	// List
	w3 := httptest.NewRecorder()
	srv.ServeHTTP(w3, authedReq(http.MethodGet, "/api/users/"+gcid+"/portability/snapshots", nil))
	if w3.Code != http.StatusOK {
		t.Fatalf("list status = %d", w3.Code)
	}
	var list struct {
		Items []map[string]any `json:"items"`
		Total int              `json:"total"`
	}
	_ = json.Unmarshal(w3.Body.Bytes(), &list)
	if list.Total != 2 {
		t.Errorf("snapshots size = %d; want 2", list.Total)
	}
}

func TestExportSnapshot_404OnUnknownUser(t *testing.T) {
	t.Parallel()
	srv := newServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedReq(http.MethodPost,
		"/api/users/01970000-0000-7000-aaaa-bbbbbbbbbbbb/portability/export", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d; want 404", w.Code)
	}
}

// _ keeps identity import live for tests.
var _ identity.IdentityProvider = identity.ProviderOIDC
