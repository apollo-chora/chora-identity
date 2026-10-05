// tenant_invites_handler_test.go — TDD RED for WS3 / CHO-1873 (ADR-194 D2):
// the cold-invite admin API.
//
//	POST   /api/v1/admin/tenant-invites              createTenantInvite
//	GET    /api/v1/admin/tenant-invites              listTenantInvites
//	DELETE /api/v1/admin/tenant-invites/{inviteId}   revokeTenantInvite
//
// POST unifies add-by-email with cold-invite: an EXISTING user is granted the
// membership NOW (retiring the addTenantMemberByEmail 404 dead-end); a
// never-registered email persists a `pending` invite that the resolve seam
// auto-applies at first login. The target tenant is the BODY tenant_id on the
// operator (PLATFORM_OPERATOR) cross-tenant path, else the mesh-header tenant on
// the tenant-scoped admin path. Reuses the WS1/WS2 fakes (fakeAdminUserFinder,
// fakeGrantWriter, fakeAuthoritativeUpserter, fakeAuditEmitter) + a new
// fakePendingInviteStore.
package httpadapter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/apollo-chora/chora-common/auth/servicemesh"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// fakePendingInviteStore records the pending-invite CRUD the handler drives.
type fakePendingInviteStore struct {
	inserted   []*identity.PendingInvite
	insertErr  error
	listResult []identity.PendingInvite
	listErr    error
	revokeErr  error

	gotListTenant string
	revokedTenant string
	revokedID     string
}

func (f *fakePendingInviteStore) Insert(_ context.Context, pi *identity.PendingInvite) error {
	if f.insertErr != nil {
		return f.insertErr
	}
	f.inserted = append(f.inserted, pi)
	return nil
}

func (f *fakePendingInviteStore) ListByTenant(_ context.Context, tenantID string) ([]identity.PendingInvite, error) {
	f.gotListTenant = tenantID
	return f.listResult, f.listErr
}

func (f *fakePendingInviteStore) Revoke(_ context.Context, tenantID, inviteID string) error {
	f.revokedTenant, f.revokedID = tenantID, inviteID
	return f.revokeErr
}

const tiInvitesBase = "/api/v1/admin/tenant-invites"

// tiRequest builds a tenant-invites request with explicit mesh headers so each
// test can pick the operator vs admin gate independently.
func tiRequest(method, path, body, roles, gcid, tenantHdr string) *http.Request {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	if roles != "" {
		r.Header.Set(servicemesh.HeaderUserRoles, roles)
	}
	if gcid != "" {
		r.Header.Set(servicemesh.HeaderGCID, gcid)
	}
	if tenantHdr != "" {
		r.Header.Set(servicemesh.HeaderTenantID, tenantHdr)
	}
	return r
}

func tiCreateBody(email, tenant string, roles ...string) string {
	quoted := make([]string, len(roles))
	for i, rr := range roles {
		quoted[i] = `"` + rr + `"`
	}
	rolesJSON := "[" + strings.Join(quoted, ",") + "]"
	if tenant == "" {
		return `{"email":"` + email + `","roles":` + rolesJSON + `}`
	}
	return `{"email":"` + email + `","tenant_id":"` + tenant + `","roles":` + rolesJSON + `}`
}

func newTIHandler(users *fakeAdminUserFinder, grant *fakeGrantWriter, auth *fakeAuthoritativeUpserter, invites *fakePendingInviteStore, audit *fakeAuditEmitter) *TenantInvitesHandler {
	return NewTenantInvitesHandler(users, grant, auth, invites, audit)
}

// --- POST create: cold email → pending invite -------------------------------

func TestTenantInvites_coldEmail_201Invited(t *testing.T) {
	users := &fakeAdminUserFinder{byEmail: map[string]*identity.User{}} // email not found
	invites := &fakePendingInviteStore{}
	h := newTIHandler(users, &fakeGrantWriter{}, &fakeAuthoritativeUpserter{}, invites, &fakeAuditEmitter{})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tiRequest(http.MethodPost, tiInvitesBase,
		tiCreateBody("newcomer@studio.sg", "", "TRAINING_ADMIN"),
		"TENANT_ADMIN", gtmOperatorGcid, tmTestTenant))

	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d want 201 (body=%s)", rec.Code, rec.Body.String())
	}
	if len(invites.inserted) != 1 {
		t.Fatalf("invites inserted: got %d want 1", len(invites.inserted))
	}
	pi := invites.inserted[0]
	if pi.Email != "newcomer@studio.sg" || pi.TenantID != tmTestTenant {
		t.Errorf("persisted invite: got email=%q tenant=%q", pi.Email, pi.TenantID)
	}
	// TRAINING_ADMIN canonicalises to the instructor membership role.
	if len(pi.Roles) != 1 || pi.Roles[0] != identity.RoleInstructor {
		t.Errorf("persisted roles: got %v want [instructor]", pi.Roles)
	}
	if pi.InvitedByGcid != gtmOperatorGcid {
		t.Errorf("invited_by_gcid: got %q want caller %q", pi.InvitedByGcid, gtmOperatorGcid)
	}
	var resp struct {
		Kind     string   `json:"kind"`
		InviteID string   `json:"invite_id"`
		Email    string   `json:"email"`
		Roles    []string `json:"roles"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Kind != "invited" || resp.InviteID == "" {
		t.Errorf("response: got kind=%q invite_id=%q want invited/non-empty", resp.Kind, resp.InviteID)
	}
	if len(resp.Roles) != 1 || resp.Roles[0] != "INSTRUCTOR" {
		t.Errorf("response roles: got %v want [INSTRUCTOR]", resp.Roles)
	}
}

// --- POST create: existing user → grant now ---------------------------------

func TestTenantInvites_existingUser_201Granted(t *testing.T) {
	users := &fakeAdminUserFinder{byEmail: map[string]*identity.User{"anika@mtm.sg": tmTestUser()}}
	grant := &fakeGrantWriter{membershipID: "01990000-0000-7000-8000-000000000abc"}
	auth := &fakeAuthoritativeUpserter{created: true}
	invites := &fakePendingInviteStore{}
	h := newTIHandler(users, grant, auth, invites, &fakeAuditEmitter{})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tiRequest(http.MethodPost, tiInvitesBase,
		tiCreateBody("anika@mtm.sg", "", "INSTRUCTOR"),
		"TENANT_ADMIN", gtmOperatorGcid, tmTestTenant))

	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d want 201 (body=%s)", rec.Code, rec.Body.String())
	}
	if len(invites.inserted) != 0 {
		t.Errorf("existing user must NOT persist a pending invite; inserted %d", len(invites.inserted))
	}
	if grant.gotGcid != tmTestGcid || grant.gotTID != tmTestTenant {
		t.Errorf("grant: got gcid=%q tenant=%q want %q/%q", grant.gotGcid, grant.gotTID, tmTestGcid, tmTestTenant)
	}
	if auth.gotTID != tmTestTenant || len(auth.gotRoles) != 1 || auth.gotRoles[0] != "instructor" {
		t.Errorf("authoritative: got tenant=%q roles=%v", auth.gotTID, auth.gotRoles)
	}
	var resp struct {
		Kind         string `json:"kind"`
		MembershipID string `json:"membership_id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Kind != "granted" || resp.MembershipID != grant.membershipID {
		t.Errorf("response: got kind=%q membership_id=%q", resp.Kind, resp.MembershipID)
	}
}

// --- operator cross-tenant: tenant from BODY --------------------------------

func TestTenantInvites_operatorBodyTenant_usesBodyTenant(t *testing.T) {
	users := &fakeAdminUserFinder{byEmail: map[string]*identity.User{"anika@mtm.sg": tmTestUser()}}
	grant := &fakeGrantWriter{}
	auth := &fakeAuthoritativeUpserter{created: true}
	h := newTIHandler(users, grant, auth, &fakePendingInviteStore{}, &fakeAuditEmitter{})

	rec := httptest.NewRecorder()
	// PLATFORM_OPERATOR + body tenant != header tenant (none set) → body wins.
	h.ServeHTTP(rec, tiRequest(http.MethodPost, tiInvitesBase,
		tiCreateBody("anika@mtm.sg", gtmBodyTenant, "INSTRUCTOR"),
		"PLATFORM_OPERATOR", gtmOperatorGcid, ""))

	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d want 201 (body=%s)", rec.Code, rec.Body.String())
	}
	if grant.gotTID != gtmBodyTenant || auth.gotTID != gtmBodyTenant {
		t.Errorf("tenant: grant=%q auth=%q want body tenant %q", grant.gotTID, auth.gotTID, gtmBodyTenant)
	}
}

// --- admin path: tenant from HEADER, cold email -----------------------------

func TestTenantInvites_adminHeaderTenant_usesHeaderTenant(t *testing.T) {
	users := &fakeAdminUserFinder{byEmail: map[string]*identity.User{}}
	invites := &fakePendingInviteStore{}
	h := newTIHandler(users, &fakeGrantWriter{}, &fakeAuthoritativeUpserter{}, invites, &fakeAuditEmitter{})

	rec := httptest.NewRecorder()
	// No body tenant_id → adminGate → tenant from the mesh header.
	h.ServeHTTP(rec, tiRequest(http.MethodPost, tiInvitesBase,
		tiCreateBody("newcomer@studio.sg", "", "INSTRUCTOR"),
		"TENANT_ADMIN", gtmOperatorGcid, tmTestTenant))

	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d want 201 (body=%s)", rec.Code, rec.Body.String())
	}
	if len(invites.inserted) != 1 || invites.inserted[0].TenantID != tmTestTenant {
		t.Fatalf("invite tenant: must come from the header %q; inserted=%v", tmTestTenant, invites.inserted)
	}
}

// --- gates ------------------------------------------------------------------

func TestTenantInvites_nonOperatorBodyTenant_403(t *testing.T) {
	users := &fakeAdminUserFinder{byEmail: map[string]*identity.User{}}
	h := newTIHandler(users, &fakeGrantWriter{}, &fakeAuthoritativeUpserter{}, &fakePendingInviteStore{}, &fakeAuditEmitter{})
	rec := httptest.NewRecorder()
	// A body tenant_id forces the operator gate; TENANT_ADMIN is not operator.
	h.ServeHTTP(rec, tiRequest(http.MethodPost, tiInvitesBase,
		tiCreateBody("newcomer@studio.sg", gtmBodyTenant, "INSTRUCTOR"),
		"TENANT_ADMIN", gtmOperatorGcid, tmTestTenant))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status: got %d want 403 (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestTenantInvites_adminMissingRole_403(t *testing.T) {
	users := &fakeAdminUserFinder{byEmail: map[string]*identity.User{}}
	h := newTIHandler(users, &fakeGrantWriter{}, &fakeAuthoritativeUpserter{}, &fakePendingInviteStore{}, &fakeAuditEmitter{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tiRequest(http.MethodPost, tiInvitesBase,
		tiCreateBody("newcomer@studio.sg", "", "INSTRUCTOR"),
		"LEARNER", gtmOperatorGcid, tmTestTenant))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status: got %d want 403 (body=%s)", rec.Code, rec.Body.String())
	}
}

// --- role validation --------------------------------------------------------

func TestTenantInvites_ownerRole_422(t *testing.T) {
	users := &fakeAdminUserFinder{byEmail: map[string]*identity.User{}}
	h := newTIHandler(users, &fakeGrantWriter{}, &fakeAuthoritativeUpserter{}, &fakePendingInviteStore{}, &fakeAuditEmitter{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tiRequest(http.MethodPost, tiInvitesBase,
		tiCreateBody("newcomer@studio.sg", "", "OWNER"),
		"TENANT_ADMIN", gtmOperatorGcid, tmTestTenant))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status: got %d want 422 (OWNER not grantable, body=%s)", rec.Code, rec.Body.String())
	}
}

func TestTenantInvites_missingEmail_400(t *testing.T) {
	users := &fakeAdminUserFinder{byEmail: map[string]*identity.User{}}
	h := newTIHandler(users, &fakeGrantWriter{}, &fakeAuthoritativeUpserter{}, &fakePendingInviteStore{}, &fakeAuditEmitter{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tiRequest(http.MethodPost, tiInvitesBase,
		tiCreateBody("", "", "INSTRUCTOR"),
		"TENANT_ADMIN", gtmOperatorGcid, tmTestTenant))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400 (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestTenantInvites_existingAgid_400(t *testing.T) {
	agidUser := &identity.User{Gcid: tmAgidGcid, Email: "agent@bot.sg"}
	users := &fakeAdminUserFinder{byEmail: map[string]*identity.User{"agent@bot.sg": agidUser}}
	h := newTIHandler(users, &fakeGrantWriter{}, &fakeAuthoritativeUpserter{}, &fakePendingInviteStore{}, &fakeAuditEmitter{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tiRequest(http.MethodPost, tiInvitesBase,
		tiCreateBody("agent@bot.sg", "", "INSTRUCTOR"),
		"TENANT_ADMIN", gtmOperatorGcid, tmTestTenant))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400 (AGID rejected, body=%s)", rec.Code, rec.Body.String())
	}
}

// --- duplicate pending invite -----------------------------------------------

func TestTenantInvites_duplicate_409(t *testing.T) {
	users := &fakeAdminUserFinder{byEmail: map[string]*identity.User{}}
	invites := &fakePendingInviteStore{insertErr: identity.ErrPendingInviteExists}
	h := newTIHandler(users, &fakeGrantWriter{}, &fakeAuthoritativeUpserter{}, invites, &fakeAuditEmitter{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tiRequest(http.MethodPost, tiInvitesBase,
		tiCreateBody("newcomer@studio.sg", "", "INSTRUCTOR"),
		"TENANT_ADMIN", gtmOperatorGcid, tmTestTenant))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status: got %d want 409 (body=%s)", rec.Code, rec.Body.String())
	}
}

// --- GET list ---------------------------------------------------------------

func TestTenantInvites_list_200(t *testing.T) {
	pi, err := identity.NewPendingInvite(identity.NewPendingInviteParams{
		TenantID: tmTestTenant, Email: "newcomer@studio.sg",
		Roles: []identity.Role{identity.RoleInstructor}, InvitedByGcid: gtmOperatorGcid,
	})
	if err != nil {
		t.Fatalf("seed invite: %v", err)
	}
	invites := &fakePendingInviteStore{listResult: []identity.PendingInvite{*pi}}
	h := newTIHandler(&fakeAdminUserFinder{}, &fakeGrantWriter{}, &fakeAuthoritativeUpserter{}, invites, &fakeAuditEmitter{})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tiRequest(http.MethodGet, tiInvitesBase, "", "TENANT_ADMIN", gtmOperatorGcid, tmTestTenant))

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if invites.gotListTenant != tmTestTenant {
		t.Errorf("list tenant: got %q want header tenant %q", invites.gotListTenant, tmTestTenant)
	}
	var resp struct {
		Items []struct {
			InviteID string   `json:"invite_id"`
			Email    string   `json:"email"`
			Roles    []string `json:"roles"`
			Status   string   `json:"status"`
		} `json:"items"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Items) != 1 || resp.Items[0].Email != "newcomer@studio.sg" {
		t.Fatalf("items: got %+v", resp.Items)
	}
	if len(resp.Items[0].Roles) != 1 || resp.Items[0].Roles[0] != "INSTRUCTOR" || resp.Items[0].Status != "pending" {
		t.Errorf("item shape: got roles=%v status=%q", resp.Items[0].Roles, resp.Items[0].Status)
	}
}

func TestTenantInvites_list_nonAdmin_403(t *testing.T) {
	h := newTIHandler(&fakeAdminUserFinder{}, &fakeGrantWriter{}, &fakeAuthoritativeUpserter{}, &fakePendingInviteStore{}, &fakeAuditEmitter{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tiRequest(http.MethodGet, tiInvitesBase, "", "LEARNER", gtmOperatorGcid, tmTestTenant))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status: got %d want 403 (body=%s)", rec.Code, rec.Body.String())
	}
}

// --- DELETE revoke ----------------------------------------------------------

func TestTenantInvites_revoke_204(t *testing.T) {
	invites := &fakePendingInviteStore{}
	h := newTIHandler(&fakeAdminUserFinder{}, &fakeGrantWriter{}, &fakeAuthoritativeUpserter{}, invites, &fakeAuditEmitter{})
	rec := httptest.NewRecorder()
	const inviteID = "0199aaaa-0000-7000-8000-00000000bbbb"
	h.ServeHTTP(rec, tiRequest(http.MethodDelete, tiInvitesBase+"/"+inviteID, "", "TENANT_ADMIN", gtmOperatorGcid, tmTestTenant))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status: got %d want 204 (body=%s)", rec.Code, rec.Body.String())
	}
	if invites.revokedTenant != tmTestTenant || invites.revokedID != inviteID {
		t.Errorf("revoke: got tenant=%q id=%q want %q/%q", invites.revokedTenant, invites.revokedID, tmTestTenant, inviteID)
	}
}

func TestTenantInvites_revoke_404(t *testing.T) {
	invites := &fakePendingInviteStore{revokeErr: identity.ErrPendingInviteNotFound}
	h := newTIHandler(&fakeAdminUserFinder{}, &fakeGrantWriter{}, &fakeAuthoritativeUpserter{}, invites, &fakeAuditEmitter{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tiRequest(http.MethodDelete, tiInvitesBase+"/0199aaaa-0000-7000-8000-00000000bbbb", "", "TENANT_ADMIN", gtmOperatorGcid, tmTestTenant))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status: got %d want 404 (body=%s)", rec.Code, rec.Body.String())
	}
}

// --- method routing ---------------------------------------------------------

func TestTenantInvites_methodNotAllowed_405(t *testing.T) {
	h := newTIHandler(&fakeAdminUserFinder{}, &fakeGrantWriter{}, &fakeAuthoritativeUpserter{}, &fakePendingInviteStore{}, &fakeAuditEmitter{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tiRequest(http.MethodPut, tiInvitesBase, "{}", "TENANT_ADMIN", gtmOperatorGcid, tmTestTenant))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status: got %d want 405 (body=%s)", rec.Code, rec.Body.String())
	}
}

// --- IMDA-D1 evidence: operator grant-now emits; admin grant-now does not ----

func TestTenantInvites_operatorGrantNow_emitsEvidence(t *testing.T) {
	users := &fakeAdminUserFinder{byEmail: map[string]*identity.User{"anika@mtm.sg": tmTestUser()}}
	audit := &fakeAuditEmitter{}
	h := newTIHandler(users, &fakeGrantWriter{}, &fakeAuthoritativeUpserter{created: true}, &fakePendingInviteStore{}, audit)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tiRequest(http.MethodPost, tiInvitesBase,
		tiCreateBody("anika@mtm.sg", gtmBodyTenant, "INSTRUCTOR"),
		"PLATFORM_OPERATOR", gtmOperatorGcid, ""))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d want 201 (body=%s)", rec.Code, rec.Body.String())
	}
	if len(audit.calls) != 1 {
		t.Fatalf("operator grant-now must emit 1 evidence; got %d", len(audit.calls))
	}
	ev := audit.calls[0]
	if ev.EvidenceType != "tenant_membership_granted" || ev.Dimension != "accountability" {
		t.Errorf("evidence: got type=%q dim=%q", ev.EvidenceType, ev.Dimension)
	}
	if ev.AdditionalFields["target_tenant_id"] != gtmBodyTenant {
		t.Errorf("evidence target tenant: got %v want %q", ev.AdditionalFields["target_tenant_id"], gtmBodyTenant)
	}
}

func TestTenantInvites_adminGrantNow_noEvidence(t *testing.T) {
	users := &fakeAdminUserFinder{byEmail: map[string]*identity.User{"anika@mtm.sg": tmTestUser()}}
	audit := &fakeAuditEmitter{}
	h := newTIHandler(users, &fakeGrantWriter{}, &fakeAuthoritativeUpserter{created: true}, &fakePendingInviteStore{}, audit)
	rec := httptest.NewRecorder()
	// Same-tenant admin add (no body tenant) matches addByEmail — not audited.
	h.ServeHTTP(rec, tiRequest(http.MethodPost, tiInvitesBase,
		tiCreateBody("anika@mtm.sg", "", "INSTRUCTOR"),
		"TENANT_ADMIN", gtmOperatorGcid, tmTestTenant))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d want 201 (body=%s)", rec.Code, rec.Body.String())
	}
	if len(audit.calls) != 0 {
		t.Errorf("same-tenant admin grant must NOT emit evidence; got %d", len(audit.calls))
	}
}
