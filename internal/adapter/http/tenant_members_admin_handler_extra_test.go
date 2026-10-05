// tenant_members_admin_handler_extra_test.go — supplemental coverage for the
// weakly-covered functions of tenant_members_admin_handler.go:
//
//   - memberMultiRoleSummary (CHO-1809 multi-role REPLACE summary mapper) —
//     driven directly (unexported pure function).
//   - setRoles — PUT /api/v1/admin/tenant-members/{gcid}/roles (multi-role
//     REPLACE editor): happy path with case drift + dedup, authoritative-first
//     order, and every error branch (400/404/409/500/502).
//   - setDisplayName — PATCH /api/v1/admin/tenant-members/{gcid}/display-name
//     (CHO-1817): happy path, empty/too-long 400, 404, 500, enrich-read 500.
//   - serveItem — the remaining dispatch gaps: over-long path segments 404,
//     wrong methods 405 on /roles and /display-name.
//   - removeMember — authoritative 502/404 branches + mirror-drift tolerance.
//   - changeRole — authoritative best-effort sync (error logged, still 200).
//   - addByEmail — the last outstanding authoritative branch (tenancy reports
//     the target tenant as unknown/not active → 404).
//
// Reuses the existing fakes/helpers from tenant_members_admin_handler_test.go
// (fakeAdminUserFinder, fakeAdminMembershipWriter, fakeAuthoritativeUpserter,
// tmRequest, newTMHandler, newTMHandlerWithTenancy, tmTestTenant, ...). All new
// helpers/types are prefixed adm_.
package httpadapter

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// -----------------------------------------------------------------------------
// memberMultiRoleSummary — pure mapper (CHO-1809); called directly because it
// is unexported and needs no HTTP plumbing.
// -----------------------------------------------------------------------------

func TestAdmMemberMultiRoleSummary_nilRoles_emptyRolesSlice(t *testing.T) {
	u := tmTestUser()
	got := memberMultiRoleSummary(u, nil)
	if got.Gcid != u.Gcid || got.Email != u.Email || got.DisplayName != u.DisplayName {
		t.Errorf("core fields: got %+v want gcid=%s email=%s display_name=%s",
			got, u.Gcid, u.Email, u.DisplayName)
	}
	if len(got.Roles) != 0 {
		t.Errorf("roles: got %v want empty", got.Roles)
	}
	if got.LastActiveAt.IsZero() {
		t.Error("LastActiveAt must be set (now.UTC())")
	}
}

func TestAdmMemberMultiRoleSummary_singleRole_uppercased(t *testing.T) {
	u := tmTestUser()
	got := memberMultiRoleSummary(u, []identity.Role{identity.RoleInstructor})
	if len(got.Roles) != 1 || got.Roles[0] != "INSTRUCTOR" {
		t.Errorf("roles: got %v want [INSTRUCTOR]", got.Roles)
	}
}

func TestAdmMemberMultiRoleSummary_multipleRoles_uppercasedAndRecent(t *testing.T) {
	u := tmTestUser()
	before := time.Now().Add(-time.Minute)
	got := memberMultiRoleSummary(u, []identity.Role{identity.RoleLearner, identity.RoleAdmin})
	want := []string{"LEARNER", "ADMIN"}
	if len(got.Roles) != len(want) {
		t.Fatalf("roles: got %v want %v", got.Roles, want)
	}
	for i := range want {
		if got.Roles[i] != want[i] {
			t.Errorf("roles[%d]: got %q want %q", i, got.Roles[i], want[i])
		}
	}
	after := time.Now().Add(time.Minute)
	if got.LastActiveAt.Before(before) || got.LastActiveAt.After(after) {
		t.Errorf("LastActiveAt: got %v want within [%v, %v]", got.LastActiveAt, before, after)
	}
}

// -----------------------------------------------------------------------------
// serveItem dispatch gaps
// -----------------------------------------------------------------------------

func TestAdmServeItem_tooManyPathSegments_404(t *testing.T) {
	h := newTMHandler(&fakeAdminUserFinder{}, &fakeAdminMembershipWriter{}, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPut,
		tenantMembersBasePath+"/"+tmTestGcid+"/roles/extra", `{"roles":["LEARNER"]}`, true, tmTestTenant))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status: got %d want 404 (body=%s)", rec.Code, rec.Body.String())
	}
	if code := decodeErrCode(t, rec); code != "IDENTITY_NOT_FOUND" {
		t.Errorf("code: got %s", code)
	}
}

func TestAdmServeItem_rolesWrongMethod_405(t *testing.T) {
	h := newTMHandler(&fakeAdminUserFinder{}, &fakeAdminMembershipWriter{}, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodGet,
		tenantMembersBasePath+"/"+tmTestGcid+"/roles", "", true, tmTestTenant))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status: got %d want 405 (body=%s)", rec.Code, rec.Body.String())
	}
	if code := decodeErrCode(t, rec); code != "METHOD_NOT_ALLOWED" {
		t.Errorf("code: got %s", code)
	}
	if !strings.Contains(rec.Body.String(), "PUT only") {
		t.Errorf("message must say PUT only, body=%s", rec.Body.String())
	}
}

func TestAdmServeItem_displayNameWrongMethod_405(t *testing.T) {
	h := newTMHandler(&fakeAdminUserFinder{}, &fakeAdminMembershipWriter{}, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodGet,
		tenantMembersBasePath+"/"+tmTestGcid+"/display-name", "", true, tmTestTenant))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status: got %d want 405 (body=%s)", rec.Code, rec.Body.String())
	}
	if code := decodeErrCode(t, rec); code != "METHOD_NOT_ALLOWED" {
		t.Errorf("code: got %s", code)
	}
}

func TestAdmServeItem_bareGcidWrongMethod_405(t *testing.T) {
	h := newTMHandler(&fakeAdminUserFinder{}, &fakeAdminMembershipWriter{}, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPut, tenantMembersBasePath+"/"+tmTestGcid, "", true, tmTestTenant))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status: got %d want 405 (body=%s)", rec.Code, rec.Body.String())
	}
	if code := decodeErrCode(t, rec); code != "METHOD_NOT_ALLOWED" {
		t.Errorf("code: got %s", code)
	}
}

// -----------------------------------------------------------------------------
// PUT /api/v1/admin/tenant-members/{gcid}/roles — multi-role REPLACE editor
// (CHO-1809).
// -----------------------------------------------------------------------------

func admRolesPutPath(gcid string) string { return tenantMembersBasePath + "/" + gcid + "/roles" }

func TestAdmSetRoles_happyPath_caseDriftDedup_200(t *testing.T) {
	finder := &fakeAdminUserFinder{byGcid: map[string]*identity.User{tmTestGcid: tmTestUser()}}
	writer := &fakeAdminMembershipWriter{}
	h := newTMHandler(finder, writer, nil) // dev: mirror-only
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPut, admRolesPutPath(tmTestGcid),
		`{"roles":["LEARNER","admin","ADMIN"]}`, true, tmTestTenant))

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if len(writer.changes) != 1 {
		t.Fatalf("SetRoles calls: got %d want 1", len(writer.changes))
	}
	got := writer.changes[0]
	if got.gcid != tmTestGcid || got.tenantID != tmTestTenant || got.role != identity.RoleLearner {
		t.Errorf("SetRoles args: got %+v want first canonical role learner", got)
	}
	var body struct {
		Gcid  string   `json:"gcid"`
		Roles []string `json:"roles"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Gcid != tmTestGcid {
		t.Errorf("gcid: got %s", body.Gcid)
	}
	// Case drift + duplicate "ADMIN" de-duplicated; canonical order preserved.
	if len(body.Roles) != 2 || body.Roles[0] != "LEARNER" || body.Roles[1] != "ADMIN" {
		t.Errorf("roles: got %v want [LEARNER ADMIN]", body.Roles)
	}
}

func TestAdmSetRoles_happyPath_authoritativeReplaceFirst(t *testing.T) {
	finder := &fakeAdminUserFinder{byGcid: map[string]*identity.User{tmTestGcid: tmTestUser()}}
	writer := &fakeAdminMembershipWriter{}
	auth := &fakeAuthoritativeUpserter{created: true}
	h := newTMHandlerWithTenancy(finder, writer, auth)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPut, admRolesPutPath(tmTestGcid),
		`{"roles":["LEARNER","ADMIN"]}`, true, tmTestTenant))

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if auth.gotGcid != tmTestGcid || auth.gotTID != tmTestTenant {
		t.Errorf("authoritative args: gcid=%s tid=%s", auth.gotGcid, auth.gotTID)
	}
	if len(auth.gotRoles) != 2 || auth.gotRoles[0] != "LEARNER" || auth.gotRoles[1] != "ADMIN" {
		t.Errorf("authoritative roles: got %v want [LEARNER ADMIN]", auth.gotRoles)
	}
	if len(writer.changes) != 1 {
		t.Errorf("mirror SetRoles must also run; got %+v", writer.changes)
	}
}

func TestAdmSetRoles_invalidRole_400(t *testing.T) {
	h := newTMHandler(&fakeAdminUserFinder{}, &fakeAdminMembershipWriter{}, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPut, admRolesPutPath(tmTestGcid),
		`{"roles":["LEARNER","SUPERUSER"]}`, true, tmTestTenant))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400 (body=%s)", rec.Code, rec.Body.String())
	}
	if code := decodeErrCode(t, rec); code != "IDENTITY_INVALID_ROLE" {
		t.Errorf("code: got %s", code)
	}
}

func TestAdmSetRoles_emptyRoles_400(t *testing.T) {
	h := newTMHandler(&fakeAdminUserFinder{}, &fakeAdminMembershipWriter{}, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPut, admRolesPutPath(tmTestGcid),
		`{"roles":[]}`, true, tmTestTenant))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400 (body=%s)", rec.Code, rec.Body.String())
	}
	if code := decodeErrCode(t, rec); code != "IDENTITY_INVALID_ROLE" {
		t.Errorf("code: got %s", code)
	}
	if !strings.Contains(rec.Body.String(), "at least one role required") {
		t.Errorf("message must point at the revoke route, body=%s", rec.Body.String())
	}
}

func TestAdmSetRoles_gates_401And403(t *testing.T) {
	h := newTMHandler(&fakeAdminUserFinder{}, &fakeAdminMembershipWriter{}, nil)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPut, admRolesPutPath(tmTestGcid),
		`{"roles":["LEARNER"]}`, true, ""))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no tenant: got %d want 401 (body=%s)", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPut, admRolesPutPath(tmTestGcid),
		`{"roles":["LEARNER"]}`, false, tmTestTenant))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin: got %d want 403 (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestAdmSetRoles_malformedJSON_400(t *testing.T) {
	h := newTMHandler(&fakeAdminUserFinder{}, &fakeAdminMembershipWriter{}, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPut, admRolesPutPath(tmTestGcid),
		`{"roles": nope`, true, tmTestTenant))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400 (body=%s)", rec.Code, rec.Body.String())
	}
	if code := decodeErrCode(t, rec); code != "IDENTITY_INVALID_BODY" {
		t.Errorf("code: got %s", code)
	}
}

func TestAdmSetRoles_membershipNotFound_404(t *testing.T) {
	finder := &fakeAdminUserFinder{byGcid: map[string]*identity.User{tmTestGcid: tmTestUser()}}
	writer := &fakeAdminMembershipWriter{changeErr: identity.ErrMembershipNotFound}
	h := newTMHandler(finder, writer, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPut, admRolesPutPath(tmTestGcid),
		`{"roles":["LEARNER"]}`, true, tmTestTenant))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status: got %d want 404 (body=%s)", rec.Code, rec.Body.String())
	}
	if code := decodeErrCode(t, rec); code != "IDENTITY_MEMBERSHIP_NOT_FOUND" {
		t.Errorf("code: got %s", code)
	}
}

func TestAdmSetRoles_mirrorError_500(t *testing.T) {
	finder := &fakeAdminUserFinder{byGcid: map[string]*identity.User{tmTestGcid: tmTestUser()}}
	writer := &fakeAdminMembershipWriter{changeErr: errors.New("pg down")}
	h := newTMHandler(finder, writer, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPut, admRolesPutPath(tmTestGcid),
		`{"roles":["LEARNER"]}`, true, tmTestTenant))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d want 500 (body=%s)", rec.Code, rec.Body.String())
	}
	if code := decodeErrCode(t, rec); code != "IDENTITY_REPO_ERROR" {
		t.Errorf("code: got %s", code)
	}
}

func TestAdmSetRoles_enrichReadFails_500(t *testing.T) {
	// SetRoles persisted but the post-replace GetByGcid read fails.
	finder := &fakeAdminUserFinder{byGcid: map[string]*identity.User{}, err: errors.New("read fail")}
	writer := &fakeAdminMembershipWriter{}
	h := newTMHandler(finder, writer, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPut, admRolesPutPath(tmTestGcid),
		`{"roles":["LEARNER"]}`, true, tmTestTenant))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d want 500 (body=%s)", rec.Code, rec.Body.String())
	}
	if code := decodeErrCode(t, rec); code != "IDENTITY_REPO_ERROR" {
		t.Errorf("code: got %s", code)
	}
	if len(writer.changes) != 1 {
		t.Errorf("SetRoles should have been attempted before the read")
	}
}

func TestAdmSetRoles_authoritativeSuspended_409(t *testing.T) {
	finder := &fakeAdminUserFinder{byGcid: map[string]*identity.User{tmTestGcid: tmTestUser()}}
	auth := &fakeAuthoritativeUpserter{err: ErrUpstreamMembershipSuspended}
	h := newTMHandlerWithTenancy(finder, &fakeAdminMembershipWriter{}, auth)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPut, admRolesPutPath(tmTestGcid),
		`{"roles":["LEARNER"]}`, true, tmTestTenant))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status: got %d want 409 (body=%s)", rec.Code, rec.Body.String())
	}
	if code := decodeErrCode(t, rec); code != "IDENTITY_MEMBERSHIP_SUSPENDED" {
		t.Errorf("code: got %s", code)
	}
}

func TestAdmSetRoles_authoritativeTenantNotFound_404(t *testing.T) {
	finder := &fakeAdminUserFinder{byGcid: map[string]*identity.User{tmTestGcid: tmTestUser()}}
	auth := &fakeAuthoritativeUpserter{err: ErrUpstreamTenantNotFound}
	h := newTMHandlerWithTenancy(finder, &fakeAdminMembershipWriter{}, auth)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPut, admRolesPutPath(tmTestGcid),
		`{"roles":["LEARNER"]}`, true, tmTestTenant))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status: got %d want 404 (body=%s)", rec.Code, rec.Body.String())
	}
	if code := decodeErrCode(t, rec); code != "IDENTITY_TENANT_NOT_FOUND" {
		t.Errorf("code: got %s", code)
	}
}

func TestAdmSetRoles_authoritativeUnavailable_502(t *testing.T) {
	finder := &fakeAdminUserFinder{byGcid: map[string]*identity.User{tmTestGcid: tmTestUser()}}
	auth := &fakeAuthoritativeUpserter{err: errors.New("tenancy grpc down")}
	h := newTMHandlerWithTenancy(finder, &fakeAdminMembershipWriter{}, auth)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPut, admRolesPutPath(tmTestGcid),
		`{"roles":["LEARNER"]}`, true, tmTestTenant))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status: got %d want 502 (body=%s)", rec.Code, rec.Body.String())
	}
	if code := decodeErrCode(t, rec); code != "IDENTITY_TENANCY_ERROR" {
		t.Errorf("code: got %s", code)
	}
}

// -----------------------------------------------------------------------------
// PATCH /api/v1/admin/tenant-members/{gcid}/display-name (CHO-1817).
// -----------------------------------------------------------------------------

func admDisplayNamePatchPath(gcid string) string {
	return tenantMembersBasePath + "/" + gcid + "/display-name"
}

func TestAdmSetDisplayName_happyPath_200(t *testing.T) {
	finder := &fakeAdminUserFinder{byGcid: map[string]*identity.User{tmTestGcid: tmTestUser()}}
	h := newTMHandler(finder, &fakeAdminMembershipWriter{}, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPatch, admDisplayNamePatchPath(tmTestGcid),
		`{"display_name":"  Anika Lim  "}`, true, tmTestTenant))

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	// Trimmed name landed in the repo AND is echoed back.
	if finder.byGcid[tmTestGcid].DisplayName != "Anika Lim" {
		t.Errorf("repo display_name: got %q want %q", finder.byGcid[tmTestGcid].DisplayName, "Anika Lim")
	}
	if finder.lastDisplayNameTenant != tmTestTenant {
		t.Errorf("acting tenant provenance: got %q want %q", finder.lastDisplayNameTenant, tmTestTenant)
	}
	var body struct {
		DisplayName string `json:"display_name"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.DisplayName != "Anika Lim" {
		t.Errorf("body display_name: got %q want %q", body.DisplayName, "Anika Lim")
	}
}

func TestAdmSetDisplayName_empty_400(t *testing.T) {
	h := newTMHandler(&fakeAdminUserFinder{}, &fakeAdminMembershipWriter{}, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPatch, admDisplayNamePatchPath(tmTestGcid),
		`{"display_name":"   "}`, true, tmTestTenant))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400 (body=%s)", rec.Code, rec.Body.String())
	}
	if code := decodeErrCode(t, rec); code != "IDENTITY_INVALID_DISPLAY_NAME" {
		t.Errorf("code: got %s", code)
	}
}

func TestAdmSetDisplayName_tooLong_400(t *testing.T) {
	h := newTMHandler(&fakeAdminUserFinder{}, &fakeAdminMembershipWriter{}, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPatch, admDisplayNamePatchPath(tmTestGcid),
		`{"display_name":"`+strings.Repeat("x", maxDisplayNameLength+1)+`"}`, true, tmTestTenant))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400 (body=%s)", rec.Code, rec.Body.String())
	}
	if code := decodeErrCode(t, rec); code != "IDENTITY_INVALID_DISPLAY_NAME" {
		t.Errorf("code: got %s", code)
	}
	if !strings.Contains(rec.Body.String(), "128") {
		t.Errorf("message must cite the length cap, body=%s", rec.Body.String())
	}
}

func TestAdmSetDisplayName_gates_401And403(t *testing.T) {
	h := newTMHandler(&fakeAdminUserFinder{}, &fakeAdminMembershipWriter{}, nil)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPatch, admDisplayNamePatchPath(tmTestGcid),
		`{"display_name":"Anika Lim"}`, true, ""))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no tenant: got %d want 401 (body=%s)", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPatch, admDisplayNamePatchPath(tmTestGcid),
		`{"display_name":"Anika Lim"}`, false, tmTestTenant))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin: got %d want 403 (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestAdmSetDisplayName_malformedJSON_400(t *testing.T) {
	h := newTMHandler(&fakeAdminUserFinder{}, &fakeAdminMembershipWriter{}, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPatch, admDisplayNamePatchPath(tmTestGcid),
		`{"display_name": nope`, true, tmTestTenant))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400 (body=%s)", rec.Code, rec.Body.String())
	}
	if code := decodeErrCode(t, rec); code != "IDENTITY_INVALID_BODY" {
		t.Errorf("code: got %s", code)
	}
}

func TestAdmSetDisplayName_userNotFound_404(t *testing.T) {
	h := newTMHandler(&fakeAdminUserFinder{}, &fakeAdminMembershipWriter{}, nil) // empty finder
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPatch, admDisplayNamePatchPath(tmTestGcid),
		`{"display_name":"Anika Lim"}`, true, tmTestTenant))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status: got %d want 404 (body=%s)", rec.Code, rec.Body.String())
	}
	if code := decodeErrCode(t, rec); code != "IDENTITY_USER_NOT_FOUND" {
		t.Errorf("code: got %s", code)
	}
}

func TestAdmSetDisplayName_repoError_500(t *testing.T) {
	finder := &fakeAdminUserFinder{byGcid: map[string]*identity.User{tmTestGcid: tmTestUser()},
		err: errors.New("pg down")}
	h := newTMHandler(finder, &fakeAdminMembershipWriter{}, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPatch, admDisplayNamePatchPath(tmTestGcid),
		`{"display_name":"Anika Lim"}`, true, tmTestTenant))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d want 500 (body=%s)", rec.Code, rec.Body.String())
	}
	if code := decodeErrCode(t, rec); code != "IDENTITY_REPO_ERROR" {
		t.Errorf("code: got %s", code)
	}
}

// adm_displayNameEnrichFailFinder — wraps fakeAdminUserFinder so that
// UpdateDisplayName succeeds (embedded) but the post-update GetByGcid
// enrichment read fails, covering setDisplayName's "display name updated but
// member read failed" branch.
type adm_displayNameEnrichFailFinder struct {
	*fakeAdminUserFinder
}

func (f *adm_displayNameEnrichFailFinder) GetByGcid(context.Context, string) (*identity.User, error) {
	return nil, errors.New("enrichment read failed")
}

func TestAdmSetDisplayName_enrichReadFails_500(t *testing.T) {
	finder := &adm_displayNameEnrichFailFinder{&fakeAdminUserFinder{
		byGcid: map[string]*identity.User{tmTestGcid: tmTestUser()},
	}}
	search := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := NewTenantMembersAdminHandler(search, finder, &fakeAdminMembershipWriter{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPatch, admDisplayNamePatchPath(tmTestGcid),
		`{"display_name":"Anika Lim"}`, true, tmTestTenant))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d want 500 (body=%s)", rec.Code, rec.Body.String())
	}
	if code := decodeErrCode(t, rec); code != "IDENTITY_REPO_ERROR" {
		t.Errorf("code: got %s", code)
	}
}

// -----------------------------------------------------------------------------
// removeMember — remaining error/drift branches (WS2b / CHO-1869).
// -----------------------------------------------------------------------------

func TestAdmRemoveMember_authoritativeUnavailable_502(t *testing.T) {
	auth := &fakeAuthoritativeUpserter{removeErr: errors.New("tenancy grpc down")}
	h := newTMHandlerWithTenancy(&fakeAdminUserFinder{}, &fakeAdminMembershipWriter{}, auth)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodDelete, tmRemovePath(tmTestGcid), "", true, tmTestTenant))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status: got %d want 502 (body=%s)", rec.Code, rec.Body.String())
	}
	if code := decodeErrCode(t, rec); code != "IDENTITY_TENANCY_ERROR" {
		t.Errorf("code: got %s", code)
	}
}

func TestAdmRemoveMember_authoritativeTenantNotFound_404(t *testing.T) {
	auth := &fakeAuthoritativeUpserter{removeErr: ErrUpstreamTenantNotFound}
	h := newTMHandlerWithTenancy(&fakeAdminUserFinder{}, &fakeAdminMembershipWriter{}, auth)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodDelete, tmRemovePath(tmTestGcid), "", true, tmTestTenant))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status: got %d want 404 (body=%s)", rec.Code, rec.Body.String())
	}
	if code := decodeErrCode(t, rec); code != "IDENTITY_TENANT_NOT_FOUND" {
		t.Errorf("code: got %s", code)
	}
}

func TestAdmRemoveMember_authoritativeRemoved_mirrorError_204(t *testing.T) {
	// Authoritative removal succeeded but the mirror write failed — the
	// security boundary held (member cannot log in); roster self-heals, 204.
	auth := &fakeAuthoritativeUpserter{}
	writer := &fakeAdminMembershipWriter{removeErr: errors.New("mirror down")}
	h := newTMHandlerWithTenancy(&fakeAdminUserFinder{}, writer, auth)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodDelete, tmRemovePath(tmTestGcid), "", true, tmTestTenant))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status: got %d want 204 (drift tolerated, body=%s)", rec.Code, rec.Body.String())
	}
	if !auth.removed {
		t.Error("authoritative removal must have been attempted first")
	}
}

func TestAdmRemoveMember_devMirrorError_500(t *testing.T) {
	writer := &fakeAdminMembershipWriter{removeErr: errors.New("pg down")}
	h := newTMHandler(&fakeAdminUserFinder{}, writer, nil) // no authoritative (dev)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodDelete, tmRemovePath(tmTestGcid), "", true, tmTestTenant))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d want 500 (body=%s)", rec.Code, rec.Body.String())
	}
	if code := decodeErrCode(t, rec); code != "IDENTITY_REPO_ERROR" {
		t.Errorf("code: got %s", code)
	}
}

// -----------------------------------------------------------------------------
// addByEmail — the one remaining authoritative-error branch: tenancy reports
// the target tenant as unknown/not active (ERR-351-353).
// -----------------------------------------------------------------------------

func TestAdmAddTenantMember_authoritativeTenantNotFound_404(t *testing.T) {
	finder := &fakeAdminUserFinder{byEmail: map[string]*identity.User{"anika@mtm.sg": tmTestUser()}}
	auth := &fakeAuthoritativeUpserter{err: ErrUpstreamTenantNotFound}
	h := newTMHandlerWithTenancy(finder, &fakeAdminMembershipWriter{}, auth)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPost, "/api/v1/admin/tenant-members",
		`{"email":"anika@mtm.sg","role":"LEARNER"}`, true, tmTestTenant))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status: got %d want 404 (body=%s)", rec.Code, rec.Body.String())
	}
	if code := decodeErrCode(t, rec); code != "IDENTITY_TENANT_NOT_FOUND" {
		t.Errorf("code: got %s", code)
	}
}

// -----------------------------------------------------------------------------
// changeRole — authoritative parity is best-effort: an upstream failure is
// logged but the mirror write is authoritative for the response (still 200).
// -----------------------------------------------------------------------------

func TestAdmChangeRole_authoritativeBestEffortError_still200(t *testing.T) {
	finder := &fakeAdminUserFinder{byGcid: map[string]*identity.User{tmTestGcid: tmTestUser()}}
	writer := &fakeAdminMembershipWriter{}
	auth := &fakeAuthoritativeUpserter{err: errors.New("tenancy grpc down")}
	h := newTMHandlerWithTenancy(finder, writer, auth)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPatch, tenantMembersBasePath+"/"+tmTestGcid+"/role",
		`{"role":"ADMIN"}`, true, tmTestTenant))
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200 (mirror updated; JWT-side stale, body=%s)", rec.Code, rec.Body.String())
	}
	if len(writer.changes) != 1 || writer.changes[0].role != identity.RoleAdmin {
		t.Errorf("ChangeRole must have run before the best-effort sync: %+v", writer.changes)
	}
	if auth.gotRoles == nil || len(auth.gotRoles) != 1 || auth.gotRoles[0] != "admin" {
		t.Errorf("authoritative upsert args: got %v want [admin]", auth.gotRoles)
	}
}

func TestAdmChangeRole_authoritativeSuccess_200(t *testing.T) {
	finder := &fakeAdminUserFinder{byGcid: map[string]*identity.User{tmTestGcid: tmTestUser()}}
	writer := &fakeAdminMembershipWriter{}
	auth := &fakeAuthoritativeUpserter{created: true}
	h := newTMHandlerWithTenancy(finder, writer, auth)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPatch, tenantMembersBasePath+"/"+tmTestGcid+"/role",
		`{"role":"AUDITOR"}`, true, tmTestTenant))
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if len(auth.gotRoles) != 1 || auth.gotRoles[0] != "auditor" {
		t.Errorf("authoritative roles: got %v want [auditor]", auth.gotRoles)
	}
}
