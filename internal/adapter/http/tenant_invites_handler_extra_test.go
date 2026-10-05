// tenant_invites_handler_extra_test.go — coverage additions for
// TenantInvitesHandler (see tenant_invites_handler_test.go for the RED→GREEN
// suite). Focused on branches the main suite leaves hot:
//
//   - ServeHTTP routing: unknown item paths → 404, wrong method on item → 405,
//     missing tenant context → 401
//   - create: malformed body → 400, empty roles → 422, email lookup error → 500
//   - grantNow: suspended / missing / failing authoritative upsert →
//     409 / 404 / 502, mirror grant error → 500, dev mode (nil
//     authoritative), audit-nil + audit-failure tolerance
//   - persistPending: invalid cold email → 422, generic insert error → 500
//   - list / revoke: repo errors → 500, gate failures → 401/403
//   - canonicaliseGrantRoles: de-dupe + case-fold
package httpadapter

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// tixItemID is the /{inviteId} item path fixture for the routing + revoke
// tests below (distinct from the ti-suite fixture ids).
const tixItemID = "0199bbbb-0000-7000-8000-00000000cccc"

// --- ServeHTTP routing -------------------------------------------------------

func TestTix_unknownItemPath_404(t *testing.T) {
	t.Parallel()
	h := newTIHandler(&fakeAdminUserFinder{}, &fakeGrantWriter{}, &fakeAuthoritativeUpserter{}, &fakePendingInviteStore{}, &fakeAuditEmitter{})

	rec := httptest.NewRecorder()
	// Two segments after the base → not /{inviteId} → 404 before any verb logic.
	h.ServeHTTP(rec, tiRequest(http.MethodGet, tiInvitesBase+"/a/b", "", "TENANT_ADMIN", gtmOperatorGcid, tmTestTenant))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status: got %d want 404 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "IDENTITY_NOT_FOUND") {
		t.Errorf("body lacks IDENTITY_NOT_FOUND: %s", rec.Body.String())
	}
}

func TestTix_itemPathWrongMethod_405(t *testing.T) {
	t.Parallel()
	h := newTIHandler(&fakeAdminUserFinder{}, &fakeGrantWriter{}, &fakeAuthoritativeUpserter{}, &fakePendingInviteStore{}, &fakeAuditEmitter{})

	rec := httptest.NewRecorder()
	// /{inviteId} accepts DELETE only; PUT must be 405.
	h.ServeHTTP(rec, tiRequest(http.MethodPut, tiInvitesBase+"/"+tixItemID, "{}", "TENANT_ADMIN", gtmOperatorGcid, tmTestTenant))

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status: got %d want 405 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "DELETE only") {
		t.Errorf("body lacks DELETE-only message: %s", rec.Body.String())
	}
}

func TestTix_missingTenantContext_401(t *testing.T) {
	t.Parallel()
	h := newTIHandler(&fakeAdminUserFinder{}, &fakeGrantWriter{}, &fakeAuthoritativeUpserter{}, &fakePendingInviteStore{}, &fakeAuditEmitter{})

	// No mesh tenant header → adminGate 401 on every tenant-scoped verb.
	for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
		path := tiInvitesBase
		if m == http.MethodDelete {
			path = tiInvitesBase + "/" + tixItemID
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, tiRequest(m, path, "{}", "TENANT_ADMIN", gtmOperatorGcid, ""))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: got %d want 401 (body=%s)", m, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "AUTH_TENANT_CONTEXT_MISSING") {
			t.Errorf("%s: body lacks AUTH_TENANT_CONTEXT_MISSING: %s", m, rec.Body.String())
		}
	}
}

// --- create: body + role + lookup errors -------------------------------------

func TestTix_create_invalidBody_400(t *testing.T) {
	t.Parallel()
	h := newTIHandler(&fakeAdminUserFinder{}, &fakeGrantWriter{}, &fakeAuthoritativeUpserter{}, &fakePendingInviteStore{}, &fakeAuditEmitter{})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tiRequest(http.MethodPost, tiInvitesBase, `{"email":`,
		"TENANT_ADMIN", gtmOperatorGcid, tmTestTenant))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "IDENTITY_INVALID_BODY") {
		t.Errorf("body lacks IDENTITY_INVALID_BODY: %s", rec.Body.String())
	}
}

func TestTix_create_emptyRoles_422(t *testing.T) {
	t.Parallel()
	h := newTIHandler(&fakeAdminUserFinder{}, &fakeGrantWriter{}, &fakeAuthoritativeUpserter{}, &fakePendingInviteStore{}, &fakeAuditEmitter{})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tiRequest(http.MethodPost, tiInvitesBase,
		`{"email":"newcomer@studio.sg","roles":[]}`,
		"TENANT_ADMIN", gtmOperatorGcid, tmTestTenant))

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status: got %d want 422 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "at least one role") {
		t.Errorf("body lacks role-required message: %s", rec.Body.String())
	}
}

func TestTix_create_lookupError_500(t *testing.T) {
	t.Parallel()
	users := &fakeAdminUserFinder{err: errors.New("db unreachable")}
	h := newTIHandler(users, &fakeGrantWriter{}, &fakeAuthoritativeUpserter{}, &fakePendingInviteStore{}, &fakeAuditEmitter{})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tiRequest(http.MethodPost, tiInvitesBase,
		tiCreateBody("newcomer@studio.sg", "", "INSTRUCTOR"),
		"TENANT_ADMIN", gtmOperatorGcid, tmTestTenant))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d want 500 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "IDENTITY_REPO_ERROR") {
		t.Errorf("body lacks IDENTITY_REPO_ERROR: %s", rec.Body.String())
	}
}

// --- persistPending: constructor + store failures -----------------------------

func TestTix_create_invalidColdEmail_422(t *testing.T) {
	t.Parallel()
	users := &fakeAdminUserFinder{byEmail: map[string]*identity.User{}}
	h := newTIHandler(users, &fakeGrantWriter{}, &fakeAuthoritativeUpserter{}, &fakePendingInviteStore{}, &fakeAuditEmitter{})

	rec := httptest.NewRecorder()
	// The handler only validates the cold email via NewPendingInvite — no '@'
	// ⇒ the domain constructor rejects the invite with 422.
	h.ServeHTTP(rec, tiRequest(http.MethodPost, tiInvitesBase,
		tiCreateBody("not-an-email", "", "INSTRUCTOR"),
		"TENANT_ADMIN", gtmOperatorGcid, tmTestTenant))

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status: got %d want 422 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "IDENTITY_INVALID_INVITE") {
		t.Errorf("body lacks IDENTITY_INVALID_INVITE: %s", rec.Body.String())
	}
}

func TestTix_create_insertError_500(t *testing.T) {
	t.Parallel()
	users := &fakeAdminUserFinder{byEmail: map[string]*identity.User{}}
	invites := &fakePendingInviteStore{insertErr: errors.New("db down")}
	h := newTIHandler(users, &fakeGrantWriter{}, &fakeAuthoritativeUpserter{}, invites, &fakeAuditEmitter{})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tiRequest(http.MethodPost, tiInvitesBase,
		tiCreateBody("newcomer@studio.sg", "", "INSTRUCTOR"),
		"TENANT_ADMIN", gtmOperatorGcid, tmTestTenant))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d want 500 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "IDENTITY_REPO_ERROR") {
		t.Errorf("body lacks IDENTITY_REPO_ERROR: %s", rec.Body.String())
	}
}

// --- grantNow: authoritative upsert error branches ----------------------------

func TestTix_grantNow_authoritativeSuspended_409(t *testing.T) {
	t.Parallel()
	users := &fakeAdminUserFinder{byEmail: map[string]*identity.User{"anika@mtm.sg": tmTestUser()}}
	auth := &fakeAuthoritativeUpserter{err: ErrUpstreamMembershipSuspended}
	h := newTIHandler(users, &fakeGrantWriter{}, auth, &fakePendingInviteStore{}, &fakeAuditEmitter{})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tiRequest(http.MethodPost, tiInvitesBase,
		tiCreateBody("anika@mtm.sg", "", "INSTRUCTOR"),
		"TENANT_ADMIN", gtmOperatorGcid, tmTestTenant))

	if rec.Code != http.StatusConflict {
		t.Fatalf("status: got %d want 409 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "IDENTITY_MEMBERSHIP_SUSPENDED") {
		t.Errorf("body lacks IDENTITY_MEMBERSHIP_SUSPENDED: %s", rec.Body.String())
	}
}

func TestTix_grantNow_authoritativeTenantNotFound_404(t *testing.T) {
	t.Parallel()
	users := &fakeAdminUserFinder{byEmail: map[string]*identity.User{"anika@mtm.sg": tmTestUser()}}
	auth := &fakeAuthoritativeUpserter{err: ErrUpstreamTenantNotFound}
	h := newTIHandler(users, &fakeGrantWriter{}, auth, &fakePendingInviteStore{}, &fakeAuditEmitter{})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tiRequest(http.MethodPost, tiInvitesBase,
		tiCreateBody("anika@mtm.sg", "", "INSTRUCTOR"),
		"TENANT_ADMIN", gtmOperatorGcid, tmTestTenant))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status: got %d want 404 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "IDENTITY_TENANT_NOT_FOUND") {
		t.Errorf("body lacks IDENTITY_TENANT_NOT_FOUND: %s", rec.Body.String())
	}
}

func TestTix_grantNow_authoritativeError_502(t *testing.T) {
	t.Parallel()
	users := &fakeAdminUserFinder{byEmail: map[string]*identity.User{"anika@mtm.sg": tmTestUser()}}
	auth := &fakeAuthoritativeUpserter{err: errors.New("rpc unavailable")}
	h := newTIHandler(users, &fakeGrantWriter{}, auth, &fakePendingInviteStore{}, &fakeAuditEmitter{})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tiRequest(http.MethodPost, tiInvitesBase,
		tiCreateBody("anika@mtm.sg", "", "INSTRUCTOR"),
		"TENANT_ADMIN", gtmOperatorGcid, tmTestTenant))

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status: got %d want 502 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "IDENTITY_TENANCY_ERROR") {
		t.Errorf("body lacks IDENTITY_TENANCY_ERROR: %s", rec.Body.String())
	}
}

func TestTix_grantNow_grantError_500(t *testing.T) {
	t.Parallel()
	users := &fakeAdminUserFinder{byEmail: map[string]*identity.User{"anika@mtm.sg": tmTestUser()}}
	grant := &fakeGrantWriter{err: errors.New("pg down")}
	h := newTIHandler(users, grant, &fakeAuthoritativeUpserter{created: true}, &fakePendingInviteStore{}, &fakeAuditEmitter{})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tiRequest(http.MethodPost, tiInvitesBase,
		tiCreateBody("anika@mtm.sg", "", "INSTRUCTOR"),
		"TENANT_ADMIN", gtmOperatorGcid, tmTestTenant))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d want 500 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "IDENTITY_REPO_ERROR") {
		t.Errorf("body lacks IDENTITY_REPO_ERROR: %s", rec.Body.String())
	}
}

func TestTix_grantNow_devNoAuthoritative_201(t *testing.T) {
	t.Parallel()
	users := &fakeAdminUserFinder{byEmail: map[string]*identity.User{"anika@mtm.sg": tmTestUser()}}
	grant := &fakeGrantWriter{}
	// nil authoritative = dev-mode wiring (no tenancy conn): the mirror-only
	// grant must still succeed. Built via the constructor so `nil` reaches the
	// AUTHORITATIVE interface as a true nil (newTIHandler's typed param would
	// wrap it as a typed-nil pointer).
	h := NewTenantInvitesHandler(users, grant, nil, &fakePendingInviteStore{}, &fakeAuditEmitter{})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tiRequest(http.MethodPost, tiInvitesBase,
		tiCreateBody("anika@mtm.sg", "", "INSTRUCTOR"),
		"TENANT_ADMIN", gtmOperatorGcid, tmTestTenant))

	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d want 201 (body=%s)", rec.Code, rec.Body.String())
	}
	if grant.gotGcid != tmTestGcid || grant.gotTID != tmTestTenant {
		t.Errorf("grant: got gcid=%q tenant=%q want %q/%q", grant.gotGcid, grant.gotTID, tmTestGcid, tmTestTenant)
	}
}

func TestTix_grantNow_auditNil_201(t *testing.T) {
	t.Parallel()
	users := &fakeAdminUserFinder{byEmail: map[string]*identity.User{"anika@mtm.sg": tmTestUser()}}
	// Cross-tenant (operator) grant with NO audit emitter — the evidence
	// emission is skipped, the grant still succeeds. Built via the constructor
	// so `nil` reaches the audit interface as a true nil.
	h := NewTenantInvitesHandler(users, &fakeGrantWriter{}, &fakeAuthoritativeUpserter{created: true}, &fakePendingInviteStore{}, nil)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tiRequest(http.MethodPost, tiInvitesBase,
		tiCreateBody("anika@mtm.sg", gtmBodyTenant, "INSTRUCTOR"),
		"PLATFORM_OPERATOR", gtmOperatorGcid, ""))

	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d want 201 (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestTix_grantNow_auditError_tolerated(t *testing.T) {
	t.Parallel()
	users := &fakeAdminUserFinder{byEmail: map[string]*identity.User{"anika@mtm.sg": tmTestUser()}}
	audit := &fakeAuditEmitter{err: errors.New("pubsub down")}
	h := newTIHandler(users, &fakeGrantWriter{}, &fakeAuthoritativeUpserter{created: true}, &fakePendingInviteStore{}, audit)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tiRequest(http.MethodPost, tiInvitesBase,
		tiCreateBody("anika@mtm.sg", gtmBodyTenant, "INSTRUCTOR"),
		"PLATFORM_OPERATOR", gtmOperatorGcid, ""))

	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d want 201 — audit failure must NOT roll back a persisted grant (body=%s)", rec.Code, rec.Body.String())
	}
	if len(audit.calls) != 1 {
		t.Errorf("audit must still be attempted: got %d calls want 1", len(audit.calls))
	}
}

// --- canonicaliseGrantRoles: de-dupe + case-fold ------------------------------

func TestTix_grantNow_roleDedupe_201(t *testing.T) {
	t.Parallel()
	users := &fakeAdminUserFinder{byEmail: map[string]*identity.User{"anika@mtm.sg": tmTestUser()}}
	grant := &fakeGrantWriter{membershipID: "01990000-0000-7000-8000-000000000abc"}
	auth := &fakeAuthoritativeUpserter{created: true}
	h := newTIHandler(users, grant, auth, &fakePendingInviteStore{}, &fakeAuditEmitter{})

	rec := httptest.NewRecorder()
	// TRAINING_ADMIN aliases instructor; "instructor" + "INSTRUCTOR" collapse
	// to the same Role — the de-dupe branch must leave exactly one role.
	h.ServeHTTP(rec, tiRequest(http.MethodPost, tiInvitesBase,
		tiCreateBody("anika@mtm.sg", "", "INSTRUCTOR", "instructor", "TRAINING_ADMIN"),
		"TENANT_ADMIN", gtmOperatorGcid, tmTestTenant))

	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d want 201 (body=%s)", rec.Code, rec.Body.String())
	}
	if len(grant.gotRoles) != 1 || grant.gotRoles[0] != identity.RoleInstructor {
		t.Errorf("grant roles: got %v want [instructor] (de-duped)", grant.gotRoles)
	}
	if len(auth.gotRoles) != 1 || auth.gotRoles[0] != "instructor" {
		t.Errorf("authoritative roles: got %v want [instructor]", auth.gotRoles)
	}
	var resp struct {
		Roles []string `json:"roles"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Roles) != 1 || resp.Roles[0] != "INSTRUCTOR" {
		t.Errorf("response roles: got %v want [INSTRUCTOR]", resp.Roles)
	}
}

// --- GET list: repo error -----------------------------------------------------

func TestTix_list_repoError_500(t *testing.T) {
	t.Parallel()
	invites := &fakePendingInviteStore{listErr: errors.New("db down")}
	h := newTIHandler(&fakeAdminUserFinder{}, &fakeGrantWriter{}, &fakeAuthoritativeUpserter{}, invites, &fakeAuditEmitter{})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tiRequest(http.MethodGet, tiInvitesBase, "", "TENANT_ADMIN", gtmOperatorGcid, tmTestTenant))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d want 500 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "IDENTITY_REPO_ERROR") {
		t.Errorf("body lacks IDENTITY_REPO_ERROR: %s", rec.Body.String())
	}
}

// --- DELETE revoke: generic repo error + gate rejection ------------------------

func TestTix_revoke_repoError_500(t *testing.T) {
	t.Parallel()
	invites := &fakePendingInviteStore{revokeErr: errors.New("db down")}
	h := newTIHandler(&fakeAdminUserFinder{}, &fakeGrantWriter{}, &fakeAuthoritativeUpserter{}, invites, &fakeAuditEmitter{})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tiRequest(http.MethodDelete, tiInvitesBase+"/"+tixItemID, "", "TENANT_ADMIN", gtmOperatorGcid, tmTestTenant))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d want 500 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "IDENTITY_REPO_ERROR") {
		t.Errorf("body lacks IDENTITY_REPO_ERROR: %s", rec.Body.String())
	}
}

func TestTix_revoke_nonAdmin_403(t *testing.T) {
	t.Parallel()
	h := newTIHandler(&fakeAdminUserFinder{}, &fakeGrantWriter{}, &fakeAuthoritativeUpserter{}, &fakePendingInviteStore{}, &fakeAuditEmitter{})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tiRequest(http.MethodDelete, tiInvitesBase+"/"+tixItemID, "", "LEARNER", gtmOperatorGcid, tmTestTenant))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status: got %d want 403 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "AUTH_INSUFFICIENT_ROLE") {
		t.Errorf("body lacks AUTH_INSUFFICIENT_ROLE: %s", rec.Body.String())
	}
}
