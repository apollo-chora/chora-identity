// tenant_members_admin_handler_test.go — TDD RED for the L1 Tenant lane
// (CHO-1707): POST /api/v1/admin/tenant-members (add-member-by-email) +
// PATCH /api/v1/admin/tenant-members/{gcid}/role (tenant-scoped role
// change). Contract: identity-admin.yaml v1.4.0.
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

	"github.com/apollo-chora/chora-common/auth/servicemesh"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// -----------------------------------------------------------------------------
// fakes
// -----------------------------------------------------------------------------

type fakeAdminUserFinder struct {
	byEmail map[string]*identity.User
	byGcid  map[string]*identity.User
	err     error

	// lastDisplayNameTenant records the acting tenant passed to the most
	// recent UpdateDisplayName call (Q3 profile_updated provenance).
	lastDisplayNameTenant string
}

func (f *fakeAdminUserFinder) FindByEmail(_ context.Context, email string) (*identity.User, bool, error) {
	if f.err != nil {
		return nil, false, f.err
	}
	u, ok := f.byEmail[strings.ToLower(email)]
	return u, ok, nil
}

func (f *fakeAdminUserFinder) GetByGcid(_ context.Context, gcid string) (*identity.User, error) {
	if f.err != nil {
		return nil, f.err
	}
	if u, ok := f.byGcid[gcid]; ok {
		return u, nil
	}
	return nil, identity.ErrUserNotFound
}

func (f *fakeAdminUserFinder) UpdateDisplayName(_ context.Context, gcid, displayName, actingTenantID string) error {
	f.lastDisplayNameTenant = actingTenantID
	if f.err != nil {
		return f.err
	}
	if u, ok := f.byGcid[gcid]; ok {
		u.DisplayName = displayName
		return nil
	}
	return identity.ErrUserNotFound
}

type addCall struct {
	gcid, tenantID string
	role           identity.Role
}

type fakeAdminMembershipWriter struct {
	addErr    error
	changeErr error
	removeErr error
	adds      []addCall
	changes   []addCall
	removes   []addCall
}

func (f *fakeAdminMembershipWriter) AddMembership(_ context.Context, gcid, tenantID string, role identity.Role) error {
	f.adds = append(f.adds, addCall{gcid, tenantID, role})
	return f.addErr
}

func (f *fakeAdminMembershipWriter) ChangeRole(_ context.Context, gcid, tenantID string, role identity.Role) error {
	f.changes = append(f.changes, addCall{gcid, tenantID, role})
	return f.changeErr
}

func (f *fakeAdminMembershipWriter) SetRoles(_ context.Context, gcid, tenantID string, roles []identity.Role) error {
	// Record by collapsing to the first role for legacy fixture compat;
	// SetRoles-specific assertions belong in a focused test.
	if len(roles) > 0 {
		f.changes = append(f.changes, addCall{gcid, tenantID, roles[0]})
	}
	return f.changeErr
}

func (f *fakeAdminMembershipWriter) RemoveMember(_ context.Context, gcid, tenantID string) error {
	f.removes = append(f.removes, addCall{gcid: gcid, tenantID: tenantID})
	return f.removeErr
}

// recordingSearch proves GET delegates to the existing search handler.
type recordingSearch struct{ hits int }

func (r *recordingSearch) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	r.hits++
	w.WriteHeader(http.StatusOK)
}

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

const (
	tmTestTenant = "11111111-1111-7111-8111-111111111111"
	tmTestGcid   = "00000000-0000-7000-8000-000000001999"
	tmAgidGcid   = "0197a000-0000-7000-8000-000000000001"
)

func tmTestUser() *identity.User {
	return &identity.User{
		Gcid:        tmTestGcid,
		Email:       "anika@mtm.sg",
		DisplayName: "Anika",
		UpdatedAt:   time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC),
	}
}

func newTMHandler(finder *fakeAdminUserFinder, writer *fakeAdminMembershipWriter, search http.Handler) *TenantMembersAdminHandler {
	if search == nil {
		search = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	}
	return NewTenantMembersAdminHandler(search, finder, writer)
}

func tmRequest(method, path, body string, admin bool, tenant string) *http.Request {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	if tenant != "" {
		r.Header.Set(servicemesh.HeaderTenantID, tenant)
	}
	if admin {
		r.Header.Set(servicemesh.HeaderUserRoles, "TENANT_ADMIN")
	} else {
		r.Header.Set(servicemesh.HeaderUserRoles, "LEARNER")
	}
	return r
}

// decodeErrCode reads the identity service's FLAT error envelope
// {code, message} (handler.go errEnvelope — every identity handler uses it;
// the identity-admin.yaml nested ErrorResponse shape is a pre-existing
// spec/impl drift outside this lane).
func decodeErrCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var env struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode error envelope: %v (body=%s)", err, rec.Body.String())
	}
	return env.Code
}

// -----------------------------------------------------------------------------
// POST /api/v1/admin/tenant-members — add by email
// -----------------------------------------------------------------------------

func TestAddTenantMember_happyPath_creates201WithSummary(t *testing.T) {
	finder := &fakeAdminUserFinder{byEmail: map[string]*identity.User{"anika@mtm.sg": tmTestUser()}}
	writer := &fakeAdminMembershipWriter{}
	h := newTMHandler(finder, writer, nil)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPost, "/api/v1/admin/tenant-members",
		`{"email":"Anika@MTM.sg","role":"INSTRUCTOR"}`, true, tmTestTenant))

	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d want 201 (body=%s)", rec.Code, rec.Body.String())
	}
	if len(writer.adds) != 1 {
		t.Fatalf("AddMembership calls: got %d want 1", len(writer.adds))
	}
	got := writer.adds[0]
	if got.gcid != tmTestGcid || got.tenantID != tmTestTenant || got.role != identity.RoleInstructor {
		t.Errorf("AddMembership args: got %+v", got)
	}
	var body struct {
		Gcid        string   `json:"gcid"`
		Email       string   `json:"email"`
		DisplayName string   `json:"display_name"`
		Roles       []string `json:"roles"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Gcid != tmTestGcid || body.Email != "anika@mtm.sg" || body.DisplayName != "Anika" {
		t.Errorf("summary: got %+v", body)
	}
	if len(body.Roles) != 1 || body.Roles[0] != "INSTRUCTOR" {
		t.Errorf("roles: got %v want [INSTRUCTOR]", body.Roles)
	}
}

func TestAddTenantMember_unknownEmail_404(t *testing.T) {
	h := newTMHandler(&fakeAdminUserFinder{}, &fakeAdminMembershipWriter{}, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPost, "/api/v1/admin/tenant-members",
		`{"email":"ghost@mtm.sg","role":"LEARNER"}`, true, tmTestTenant))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status: got %d want 404", rec.Code)
	}
	if code := decodeErrCode(t, rec); code != "IDENTITY_USER_NOT_FOUND" {
		t.Errorf("code: got %s", code)
	}
}

func TestAddTenantMember_duplicate_409(t *testing.T) {
	finder := &fakeAdminUserFinder{byEmail: map[string]*identity.User{"anika@mtm.sg": tmTestUser()}}
	writer := &fakeAdminMembershipWriter{addErr: identity.ErrMembershipExists}
	h := newTMHandler(finder, writer, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPost, "/api/v1/admin/tenant-members",
		`{"email":"anika@mtm.sg","role":"ADMIN"}`, true, tmTestTenant))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status: got %d want 409", rec.Code)
	}
	if code := decodeErrCode(t, rec); code != "IDENTITY_MEMBERSHIP_DUPLICATE" {
		t.Errorf("code: got %s", code)
	}
}

func TestAddTenantMember_agidShapedGcid_400(t *testing.T) {
	agid := tmTestUser()
	agid.Gcid = tmAgidGcid
	finder := &fakeAdminUserFinder{byEmail: map[string]*identity.User{"agent@mtm.sg": agid}}
	writer := &fakeAdminMembershipWriter{}
	h := newTMHandler(finder, writer, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPost, "/api/v1/admin/tenant-members",
		`{"email":"agent@mtm.sg","role":"LEARNER"}`, true, tmTestTenant))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400", rec.Code)
	}
	if code := decodeErrCode(t, rec); code != "IDENTITY_AGID_REJECTED" {
		t.Errorf("code: got %s", code)
	}
	if len(writer.adds) != 0 {
		t.Errorf("AddMembership must not be called for AGID")
	}
}

func TestAddTenantMember_invalidRole_400(t *testing.T) {
	finder := &fakeAdminUserFinder{byEmail: map[string]*identity.User{"anika@mtm.sg": tmTestUser()}}
	h := newTMHandler(finder, &fakeAdminMembershipWriter{}, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPost, "/api/v1/admin/tenant-members",
		`{"email":"anika@mtm.sg","role":"OWNER"}`, true, tmTestTenant))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400 (OWNER is JWT-only, not a membership role)", rec.Code)
	}
}

func TestAddTenantMember_missingTenantHeader_401(t *testing.T) {
	h := newTMHandler(&fakeAdminUserFinder{}, &fakeAdminMembershipWriter{}, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPost, "/api/v1/admin/tenant-members",
		`{"email":"a@b.c","role":"LEARNER"}`, true, ""))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d want 401", rec.Code)
	}
}

func TestAddTenantMember_nonAdminCaller_403(t *testing.T) {
	h := newTMHandler(&fakeAdminUserFinder{}, &fakeAdminMembershipWriter{}, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPost, "/api/v1/admin/tenant-members",
		`{"email":"a@b.c","role":"LEARNER"}`, false, tmTestTenant))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status: got %d want 403", rec.Code)
	}
}

func TestAddTenantMember_malformedJSON_400(t *testing.T) {
	h := newTMHandler(&fakeAdminUserFinder{}, &fakeAdminMembershipWriter{}, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPost, "/api/v1/admin/tenant-members",
		`{"email": nope`, true, tmTestTenant))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400", rec.Code)
	}
}

func TestAddTenantMember_repoError_500(t *testing.T) {
	finder := &fakeAdminUserFinder{byEmail: map[string]*identity.User{"anika@mtm.sg": tmTestUser()}}
	writer := &fakeAdminMembershipWriter{addErr: errors.New("pg down")}
	h := newTMHandler(finder, writer, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPost, "/api/v1/admin/tenant-members",
		`{"email":"anika@mtm.sg","role":"LEARNER"}`, true, tmTestTenant))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d want 500", rec.Code)
	}
}

func TestTenantMembersCollection_getDelegatesToSearch(t *testing.T) {
	search := &recordingSearch{}
	h := newTMHandler(&fakeAdminUserFinder{}, &fakeAdminMembershipWriter{}, search)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodGet, "/api/v1/admin/tenant-members", "", true, tmTestTenant))
	if search.hits != 1 {
		t.Fatalf("search delegate hits: got %d want 1", search.hits)
	}
}

func TestTenantMembersCollection_methodNotAllowed_405(t *testing.T) {
	h := newTMHandler(&fakeAdminUserFinder{}, &fakeAdminMembershipWriter{}, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodDelete, "/api/v1/admin/tenant-members", "", true, tmTestTenant))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status: got %d want 405", rec.Code)
	}
}

// -----------------------------------------------------------------------------
// PATCH /api/v1/admin/tenant-members/{gcid}/role
// -----------------------------------------------------------------------------

func TestChangeTenantMemberRole_happyPath_200(t *testing.T) {
	finder := &fakeAdminUserFinder{byGcid: map[string]*identity.User{tmTestGcid: tmTestUser()}}
	writer := &fakeAdminMembershipWriter{}
	h := newTMHandler(finder, writer, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPatch,
		"/api/v1/admin/tenant-members/"+tmTestGcid+"/role",
		`{"role":"ADMIN"}`, true, tmTestTenant))

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if len(writer.changes) != 1 {
		t.Fatalf("ChangeRole calls: got %d want 1", len(writer.changes))
	}
	got := writer.changes[0]
	if got.gcid != tmTestGcid || got.tenantID != tmTestTenant || got.role != identity.RoleAdmin {
		t.Errorf("ChangeRole args: got %+v", got)
	}
	var body struct {
		Roles []string `json:"roles"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Roles) != 1 || body.Roles[0] != "ADMIN" {
		t.Errorf("roles: got %v want [ADMIN]", body.Roles)
	}
}

func TestChangeTenantMemberRole_membershipNotFound_404(t *testing.T) {
	finder := &fakeAdminUserFinder{byGcid: map[string]*identity.User{tmTestGcid: tmTestUser()}}
	writer := &fakeAdminMembershipWriter{changeErr: identity.ErrMembershipNotFound}
	h := newTMHandler(finder, writer, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPatch,
		"/api/v1/admin/tenant-members/"+tmTestGcid+"/role",
		`{"role":"ADMIN"}`, true, tmTestTenant))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status: got %d want 404", rec.Code)
	}
	if code := decodeErrCode(t, rec); code != "IDENTITY_MEMBERSHIP_NOT_FOUND" {
		t.Errorf("code: got %s", code)
	}
}

func TestChangeTenantMemberRole_invalidRole_400(t *testing.T) {
	h := newTMHandler(&fakeAdminUserFinder{}, &fakeAdminMembershipWriter{}, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPatch,
		"/api/v1/admin/tenant-members/"+tmTestGcid+"/role",
		`{"role":"PLATFORM_OPERATOR"}`, true, tmTestTenant))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400", rec.Code)
	}
}

func TestChangeTenantMemberRole_gates_401And403(t *testing.T) {
	h := newTMHandler(&fakeAdminUserFinder{}, &fakeAdminMembershipWriter{}, nil)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPatch,
		"/api/v1/admin/tenant-members/"+tmTestGcid+"/role", `{"role":"ADMIN"}`, true, ""))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no tenant: got %d want 401", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPatch,
		"/api/v1/admin/tenant-members/"+tmTestGcid+"/role", `{"role":"ADMIN"}`, false, tmTestTenant))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin: got %d want 403", rec.Code)
	}
}

func TestChangeTenantMemberRole_unknownSubResource_404(t *testing.T) {
	h := newTMHandler(&fakeAdminUserFinder{}, &fakeAdminMembershipWriter{}, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPatch,
		"/api/v1/admin/tenant-members/"+tmTestGcid+"/banana", `{"role":"ADMIN"}`, true, tmTestTenant))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status: got %d want 404", rec.Code)
	}
}

func TestChangeTenantMemberRole_wrongMethodOnItem_405(t *testing.T) {
	h := newTMHandler(&fakeAdminUserFinder{}, &fakeAdminMembershipWriter{}, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodGet,
		"/api/v1/admin/tenant-members/"+tmTestGcid+"/role", "", true, tmTestTenant))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status: got %d want 405", rec.Code)
	}
}

// -----------------------------------------------------------------------------
// error-path coverage (≥90% gate)
// -----------------------------------------------------------------------------

func TestAddTenantMember_emptyEmail_400(t *testing.T) {
	h := newTMHandler(&fakeAdminUserFinder{}, &fakeAdminMembershipWriter{}, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPost, "/api/v1/admin/tenant-members",
		`{"email":"  ","role":"LEARNER"}`, true, tmTestTenant))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400", rec.Code)
	}
}

func TestAddTenantMember_finderError_500(t *testing.T) {
	h := newTMHandler(&fakeAdminUserFinder{err: errors.New("pg down")}, &fakeAdminMembershipWriter{}, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPost, "/api/v1/admin/tenant-members",
		`{"email":"anika@mtm.sg","role":"LEARNER"}`, true, tmTestTenant))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d want 500", rec.Code)
	}
}

func TestChangeTenantMemberRole_malformedJSON_400(t *testing.T) {
	h := newTMHandler(&fakeAdminUserFinder{}, &fakeAdminMembershipWriter{}, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPatch,
		"/api/v1/admin/tenant-members/"+tmTestGcid+"/role", `{nope`, true, tmTestTenant))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400", rec.Code)
	}
}

func TestChangeTenantMemberRole_repoError_500(t *testing.T) {
	finder := &fakeAdminUserFinder{byGcid: map[string]*identity.User{tmTestGcid: tmTestUser()}}
	writer := &fakeAdminMembershipWriter{changeErr: errors.New("pg down")}
	h := newTMHandler(finder, writer, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPatch,
		"/api/v1/admin/tenant-members/"+tmTestGcid+"/role", `{"role":"ADMIN"}`, true, tmTestTenant))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d want 500", rec.Code)
	}
}

func TestChangeTenantMemberRole_enrichReadFails_500(t *testing.T) {
	// ChangeRole persisted but the post-change GetByGcid read fails — the
	// handler reports 500 and the FE retries the roster read.
	finder := &fakeAdminUserFinder{byGcid: map[string]*identity.User{}}
	writer := &fakeAdminMembershipWriter{}
	h := newTMHandler(finder, writer, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPatch,
		"/api/v1/admin/tenant-members/"+tmTestGcid+"/role", `{"role":"ADMIN"}`, true, tmTestTenant))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d want 500", rec.Code)
	}
	if len(writer.changes) != 1 {
		t.Fatalf("ChangeRole should have been attempted before the read")
	}
}

// -----------------------------------------------------------------------------
// ADR-182 authoritative write — addByEmail writes chora_tenancy.members
// via UpsertMembership BEFORE the identity mirror. Fixes the CHO-1707
// pre-existing bug where the added member could never actually log in to
// the tenant (mint reads the authoritative store).
// -----------------------------------------------------------------------------

type fakeAuthoritativeUpserter struct {
	created bool
	err     error
	// replaceErr, when set, overrides err for the REPLACE flavour only, so a
	// test can refuse a role replace while leaving the additive upsert alone
	// (S7-B1: the two carry different refusals).
	replaceErr error
	removeErr  error
	gotGcid    string
	gotTID     string
	gotRoles   []string
	order      *[]string
	removed    bool
	// upserted records that the additive authoritative write actually ran,
	// which is how a test proves a refused mirror write did not leak through
	// to the authoritative store.
	upserted bool
}

func (f *fakeAuthoritativeUpserter) UpsertMembershipByTenantID(_ context.Context, gcid, tenantID string, roles []string) (bool, error) {
	f.gotGcid, f.gotTID, f.gotRoles = gcid, tenantID, roles
	if f.order != nil {
		*f.order = append(*f.order, "authoritative")
	}
	if f.err == nil {
		f.upserted = true
	}
	return f.created, f.err
}

func (f *fakeAuthoritativeUpserter) ReplaceMembershipByTenantID(_ context.Context, gcid, tenantID string, roles []string) (bool, error) {
	f.gotGcid, f.gotTID, f.gotRoles = gcid, tenantID, roles
	if f.order != nil {
		*f.order = append(*f.order, "authoritative-replace")
	}
	if f.replaceErr != nil {
		return false, f.replaceErr
	}
	return f.created, f.err
}

func (f *fakeAuthoritativeUpserter) RemoveMembershipByTenantID(_ context.Context, gcid, tenantID string) error {
	f.gotGcid, f.gotTID = gcid, tenantID
	if f.order != nil {
		*f.order = append(*f.order, "authoritative-remove")
	}
	if f.removeErr != nil {
		return f.removeErr
	}
	f.removed = true
	return nil
}

// orderTrackingWriter wraps fakeAdminMembershipWriter to record call order.
type orderTrackingWriter struct {
	fakeAdminMembershipWriter
	order *[]string
}

func (f *orderTrackingWriter) AddMembership(ctx context.Context, gcid, tenantID string, role identity.Role) error {
	if f.order != nil {
		*f.order = append(*f.order, "mirror")
	}
	return f.fakeAdminMembershipWriter.AddMembership(ctx, gcid, tenantID, role)
}

func newTMHandlerWithTenancy(finder *fakeAdminUserFinder, writer AdminMembershipWriter, authoritative AuthoritativeMembershipUpserter) *TenantMembersAdminHandler {
	search := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	return NewTenantMembersAdminHandlerWithTenancy(search, finder, writer, authoritative)
}

// -----------------------------------------------------------------------------
// DELETE /api/v1/admin/tenant-members/{gcid} — member-centric remove (WS2b).
// -----------------------------------------------------------------------------

func tmRemovePath(gcid string) string { return tenantMembersBasePath + "/" + gcid }

func TestRemoveMember_authoritativeThenMirror_204(t *testing.T) {
	finder := &fakeAdminUserFinder{byGcid: map[string]*identity.User{tmTestGcid: tmTestUser()}}
	writer := &fakeAdminMembershipWriter{}
	auth := &fakeAuthoritativeUpserter{}
	h := newTMHandlerWithTenancy(finder, writer, auth)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodDelete, tmRemovePath(tmTestGcid), "", true, tmTestTenant))

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status: got %d want 204 (body=%s)", rec.Code, rec.Body.String())
	}
	if !auth.removed || auth.gotGcid != tmTestGcid || auth.gotTID != tmTestTenant {
		t.Errorf("authoritative remove not called for (%q,%q); removed=%v", auth.gotGcid, auth.gotTID, auth.removed)
	}
	if len(writer.removes) != 1 || writer.removes[0].gcid != tmTestGcid || writer.removes[0].tenantID != tmTestTenant {
		t.Errorf("mirror RemoveMember not called correctly: %+v", writer.removes)
	}
}

func TestRemoveMember_devMirrorOnly_204(t *testing.T) {
	writer := &fakeAdminMembershipWriter{}
	h := newTMHandler(&fakeAdminUserFinder{}, writer, nil) // no authoritative (dev)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodDelete, tmRemovePath(tmTestGcid), "", true, tmTestTenant))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status: got %d want 204 (body=%s)", rec.Code, rec.Body.String())
	}
	if len(writer.removes) != 1 {
		t.Errorf("mirror RemoveMember must be called in dev mode; got %+v", writer.removes)
	}
}

func TestRemoveMember_devNotFound_404(t *testing.T) {
	writer := &fakeAdminMembershipWriter{removeErr: identity.ErrMembershipNotFound}
	h := newTMHandler(&fakeAdminUserFinder{}, writer, nil) // no authoritative
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodDelete, tmRemovePath(tmTestGcid), "", true, tmTestTenant))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status: got %d want 404 (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestRemoveMember_authoritativeNotFound_404(t *testing.T) {
	auth := &fakeAuthoritativeUpserter{removeErr: ErrUpstreamMembershipNotFound}
	h := newTMHandlerWithTenancy(&fakeAdminUserFinder{}, &fakeAdminMembershipWriter{}, auth)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodDelete, tmRemovePath(tmTestGcid), "", true, tmTestTenant))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status: got %d want 404 (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestRemoveMember_authoritativeSuspended_409(t *testing.T) {
	auth := &fakeAuthoritativeUpserter{removeErr: ErrUpstreamMembershipSuspended}
	h := newTMHandlerWithTenancy(&fakeAdminUserFinder{}, &fakeAdminMembershipWriter{}, auth)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodDelete, tmRemovePath(tmTestGcid), "", true, tmTestTenant))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status: got %d want 409 (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestRemoveMember_authoritativeRemoved_mirrorDrift_204(t *testing.T) {
	// Authoritative removed but the mirror had no live row — drift, tolerated.
	auth := &fakeAuthoritativeUpserter{}
	writer := &fakeAdminMembershipWriter{removeErr: identity.ErrMembershipNotFound}
	h := newTMHandlerWithTenancy(&fakeAdminUserFinder{}, writer, auth)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodDelete, tmRemovePath(tmTestGcid), "", true, tmTestTenant))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status: got %d want 204 (drift tolerated, body=%s)", rec.Code, rec.Body.String())
	}
}

func TestRemoveMember_nonAdmin_403(t *testing.T) {
	h := newTMHandler(&fakeAdminUserFinder{}, &fakeAdminMembershipWriter{}, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodDelete, tmRemovePath(tmTestGcid), "", false, tmTestTenant)) // LEARNER
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status: got %d want 403 (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestRemoveMember_methodNotAllowed_405(t *testing.T) {
	h := newTMHandler(&fakeAdminUserFinder{}, &fakeAdminMembershipWriter{}, nil)
	rec := httptest.NewRecorder()
	// POST on the bare /{gcid} item path is not allowed (DELETE only).
	h.ServeHTTP(rec, tmRequest(http.MethodPost, tmRemovePath(tmTestGcid), "{}", true, tmTestTenant))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status: got %d want 405 (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestAddTenantMember_authoritativeBeforeMirror_201(t *testing.T) {
	var order []string
	finder := &fakeAdminUserFinder{byEmail: map[string]*identity.User{"anika@mtm.sg": tmTestUser()}}
	writer := &orderTrackingWriter{order: &order}
	auth := &fakeAuthoritativeUpserter{created: true, order: &order}
	h := newTMHandlerWithTenancy(finder, writer, auth)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPost, "/api/v1/admin/tenant-members",
		`{"email":"anika@mtm.sg","role":"INSTRUCTOR"}`, true, tmTestTenant))

	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d want 201 (body=%s)", rec.Code, rec.Body.String())
	}
	if len(order) != 2 || order[0] != "authoritative" || order[1] != "mirror" {
		t.Fatalf("write order: got %v want [authoritative mirror]", order)
	}
	if auth.gotGcid != tmTestGcid || auth.gotTID != tmTestTenant {
		t.Errorf("authoritative args: gcid=%s tid=%s", auth.gotGcid, auth.gotTID)
	}
	if len(auth.gotRoles) != 1 || auth.gotRoles[0] != "instructor" {
		t.Errorf("authoritative roles: got %v want [instructor]", auth.gotRoles)
	}
}

func TestAddTenantMember_authoritativeDuplicate_409_noMirrorWrite(t *testing.T) {
	finder := &fakeAdminUserFinder{byEmail: map[string]*identity.User{"anika@mtm.sg": tmTestUser()}}
	writer := &fakeAdminMembershipWriter{}
	auth := &fakeAuthoritativeUpserter{created: false}
	h := newTMHandlerWithTenancy(finder, writer, auth)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPost, "/api/v1/admin/tenant-members",
		`{"email":"anika@mtm.sg","role":"ADMIN"}`, true, tmTestTenant))

	if rec.Code != http.StatusConflict {
		t.Fatalf("status: got %d want 409", rec.Code)
	}
	if code := decodeErrCode(t, rec); code != "IDENTITY_MEMBERSHIP_DUPLICATE" {
		t.Errorf("code: got %s", code)
	}
	if len(writer.adds) != 0 {
		t.Errorf("mirror must not be written on authoritative duplicate")
	}
}

func TestAddTenantMember_authoritativeSuspended_409(t *testing.T) {
	finder := &fakeAdminUserFinder{byEmail: map[string]*identity.User{"anika@mtm.sg": tmTestUser()}}
	auth := &fakeAuthoritativeUpserter{err: ErrUpstreamMembershipSuspended}
	h := newTMHandlerWithTenancy(finder, &fakeAdminMembershipWriter{}, auth)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPost, "/api/v1/admin/tenant-members",
		`{"email":"anika@mtm.sg","role":"LEARNER"}`, true, tmTestTenant))

	if rec.Code != http.StatusConflict {
		t.Fatalf("status: got %d want 409", rec.Code)
	}
	if code := decodeErrCode(t, rec); code != "IDENTITY_MEMBERSHIP_SUSPENDED" {
		t.Errorf("code: got %s", code)
	}
}

func TestAddTenantMember_authoritativeUnavailable_502(t *testing.T) {
	finder := &fakeAdminUserFinder{byEmail: map[string]*identity.User{"anika@mtm.sg": tmTestUser()}}
	writer := &fakeAdminMembershipWriter{}
	auth := &fakeAuthoritativeUpserter{err: errors.New("tenancy grpc down")}
	h := newTMHandlerWithTenancy(finder, writer, auth)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPost, "/api/v1/admin/tenant-members",
		`{"email":"anika@mtm.sg","role":"LEARNER"}`, true, tmTestTenant))

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status: got %d want 502", rec.Code)
	}
	if code := decodeErrCode(t, rec); code != "IDENTITY_TENANCY_ERROR" {
		t.Errorf("code: got %s", code)
	}
	if len(writer.adds) != 0 {
		t.Errorf("mirror must not be written when authoritative write fails")
	}
}

func TestAddTenantMember_mirrorDrift_exists_still201(t *testing.T) {
	// Authoritative store created the row but the mirror already has it
	// (drift) — the add still succeeds; the mirror upsert self-heals.
	finder := &fakeAdminUserFinder{byEmail: map[string]*identity.User{"anika@mtm.sg": tmTestUser()}}
	writer := &fakeAdminMembershipWriter{addErr: identity.ErrMembershipExists}
	auth := &fakeAuthoritativeUpserter{created: true}
	h := newTMHandlerWithTenancy(finder, writer, auth)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPost, "/api/v1/admin/tenant-members",
		`{"email":"anika@mtm.sg","role":"LEARNER"}`, true, tmTestTenant))

	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d want 201 (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestAddTenantMember_authorRole_accepted(t *testing.T) {
	finder := &fakeAdminUserFinder{byEmail: map[string]*identity.User{"anika@mtm.sg": tmTestUser()}}
	writer := &fakeAdminMembershipWriter{}
	auth := &fakeAuthoritativeUpserter{created: true}
	h := newTMHandlerWithTenancy(finder, writer, auth)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPost, "/api/v1/admin/tenant-members",
		`{"email":"anika@mtm.sg","role":"AUTHOR"}`, true, tmTestTenant))

	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d want 201 (body=%s)", rec.Code, rec.Body.String())
	}
	if len(auth.gotRoles) != 1 || auth.gotRoles[0] != "author" {
		t.Errorf("authoritative roles: got %v want [author]", auth.gotRoles)
	}
	var body struct {
		Roles []string `json:"roles"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if len(body.Roles) != 1 || body.Roles[0] != "AUTHOR" {
		t.Errorf("summary roles: got %v want [AUTHOR]", body.Roles)
	}
}

func TestAddTenantMember_invalidRoleMessage_listsAuthor(t *testing.T) {
	finder := &fakeAdminUserFinder{byEmail: map[string]*identity.User{"anika@mtm.sg": tmTestUser()}}
	h := newTMHandler(finder, &fakeAdminMembershipWriter{}, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPost, "/api/v1/admin/tenant-members",
		`{"email":"anika@mtm.sg","role":"OWNER"}`, true, tmTestTenant))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "AUTHOR") {
		t.Errorf("error message must list AUTHOR as grantable, body=%s", rec.Body.String())
	}
}

// -----------------------------------------------------------------------------
// WS1 (CHO-1870) — TRAINING_ADMIN role-label exposure.
//
// TRAINING_ADMIN is a UI label over membership_role `instructor`
// (role_catalog mig 0014 documents it but nothing JWT-stamps it; an
// instructor membership already passes every downstream gate). The admin
// member-grant API therefore accepts TRAINING_ADMIN as a canonical ALIAS for
// instructor. TENANT_ADMIN -> admin is a defensive synonym (TENANT_ADMIN is
// the JWT-canonical token for the tenant admin, == ADMIN membership). OWNER /
// PLATFORM_OPERATOR / SUPPORT_AGENT stay non-grantable (JWT-only roles with no
// membership_role representation).
// -----------------------------------------------------------------------------

func TestGrantableRole_canonicalAliases(t *testing.T) {
	cases := []struct {
		in     string
		want   identity.Role
		wantOK bool
	}{
		{"TRAINING_ADMIN", identity.RoleInstructor, true},
		{"training_admin", identity.RoleInstructor, true},   // case-insensitive
		{" TRAINING_ADMIN ", identity.RoleInstructor, true}, // trimmed
		{"TENANT_ADMIN", identity.RoleAdmin, true},
		{"AUTHOR", identity.RoleAuthor, true},
		{"INSTRUCTOR", identity.RoleInstructor, true},
		{"LEARNER", identity.RoleLearner, true},
		{"ADMIN", identity.RoleAdmin, true},
		{"AUDITOR", identity.RoleAuditor, true},
		{"OWNER", identity.Role(""), false},
		{"PLATFORM_OPERATOR", identity.Role(""), false},
		{"SUPPORT_AGENT", identity.Role(""), false},
		{"", identity.Role(""), false},
	}
	for _, c := range cases {
		got, ok := grantableRole(c.in)
		if ok != c.wantOK || got != c.want {
			t.Errorf("grantableRole(%q) = (%q, %v); want (%q, %v)", c.in, got, ok, c.want, c.wantOK)
		}
	}
}

func TestAddTenantMember_trainingAdminRole_mapsToInstructor(t *testing.T) {
	finder := &fakeAdminUserFinder{byEmail: map[string]*identity.User{"anika@mtm.sg": tmTestUser()}}
	writer := &fakeAdminMembershipWriter{}
	auth := &fakeAuthoritativeUpserter{created: true}
	h := newTMHandlerWithTenancy(finder, writer, auth)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPost, "/api/v1/admin/tenant-members",
		`{"email":"anika@mtm.sg","role":"TRAINING_ADMIN"}`, true, tmTestTenant))

	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d want 201 (body=%s)", rec.Code, rec.Body.String())
	}
	// TRAINING_ADMIN persists as the underlying membership_role `instructor`.
	if len(auth.gotRoles) != 1 || auth.gotRoles[0] != "instructor" {
		t.Errorf("authoritative roles: got %v want [instructor]", auth.gotRoles)
	}
	if len(writer.adds) != 1 || writer.adds[0].role != identity.RoleInstructor {
		t.Errorf("mirror role: got %v want [instructor]", writer.adds)
	}
	var body struct {
		Roles []string `json:"roles"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if len(body.Roles) != 1 || body.Roles[0] != "INSTRUCTOR" {
		t.Errorf("summary roles: got %v want [INSTRUCTOR]", body.Roles)
	}
}

func TestChangeTenantMemberRole_trainingAdmin_mapsToInstructor(t *testing.T) {
	finder := &fakeAdminUserFinder{byGcid: map[string]*identity.User{tmTestGcid: tmTestUser()}}
	writer := &fakeAdminMembershipWriter{}
	h := newTMHandler(finder, writer, nil)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPatch, "/api/v1/admin/tenant-members/"+tmTestGcid+"/role",
		`{"role":"TRAINING_ADMIN"}`, true, tmTestTenant))

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if len(writer.changes) != 1 || writer.changes[0].role != identity.RoleInstructor {
		t.Errorf("changed role: got %v want [instructor]", writer.changes)
	}
}

func TestAddTenantMember_invalidRoleMessage_listsTrainingAdmin(t *testing.T) {
	finder := &fakeAdminUserFinder{byEmail: map[string]*identity.User{"anika@mtm.sg": tmTestUser()}}
	h := newTMHandler(finder, &fakeAdminMembershipWriter{}, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPost, "/api/v1/admin/tenant-members",
		`{"email":"anika@mtm.sg","role":"PLATFORM_OPERATOR"}`, true, tmTestTenant))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "TRAINING_ADMIN") {
		t.Errorf("error message must list TRAINING_ADMIN as grantable, body=%s", rec.Body.String())
	}
}
