// grant_tenant_membership_handler_extra_test.go — coverage additions for
// GrantTenantMembershipHandler (see grant_tenant_membership_handler_test.go
// for the RED→GREEN suite). Focused on the error branches the main suite
// leaves hot:
//
//   - ServeHTTP: malformed body → 400, missing gcid/tenant → 400, empty
//     roles → 422, role de-dupe, grantee not-found → 404, grantee lookup
//     error → 500, dev mode (nil authoritative), authoritative failures →
//     409 / 404 / 502, mirror grant error → 500, audit-nil +
//     audit-failure tolerance
//   - callerHoldsOperatorRole: empty header, non-operator role, lowercase +
//     multi-role forms
package httpadapter

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/apollo-chora/chora-common/auth/servicemesh"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// --- ServeHTTP: body validation ----------------------------------------------

func TestGrx_invalidBody_400(t *testing.T) {
	t.Parallel()
	h := NewGrantTenantMembershipHandler(&fakeAdminUserFinder{}, &fakeGrantWriter{}, &fakeAuthoritativeUpserter{}, &fakeAuditEmitter{})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, gtmRequest(http.MethodPost, `{"gcid":`,
		"PLATFORM_OPERATOR", gtmOperatorGcid))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "IDENTITY_INVALID_BODY") {
		t.Errorf("body lacks IDENTITY_INVALID_BODY: %s", rec.Body.String())
	}
}

func TestGrx_missingGcidOrTenant_400(t *testing.T) {
	t.Parallel()
	h := NewGrantTenantMembershipHandler(&fakeAdminUserFinder{}, &fakeGrantWriter{}, &fakeAuthoritativeUpserter{}, &fakeAuditEmitter{})

	for _, body := range []string{
		`{"gcid":"","tenant_id":"` + gtmBodyTenant + `","roles":["INSTRUCTOR"]}`,
		`{"gcid":"` + tmTestGcid + `","tenant_id":"","roles":["INSTRUCTOR"]}`,
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, gtmRequest(http.MethodPost, body, "PLATFORM_OPERATOR", gtmOperatorGcid))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %s: got %d want 400 (body=%s)", body, rec.Code, rec.Body.String())
		}
	}
}

func TestGrx_emptyRoles_422(t *testing.T) {
	t.Parallel()
	h := NewGrantTenantMembershipHandler(&fakeAdminUserFinder{}, &fakeGrantWriter{}, &fakeAuthoritativeUpserter{}, &fakeAuditEmitter{})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, gtmRequest(http.MethodPost,
		`{"gcid":"`+tmTestGcid+`","tenant_id":"`+gtmBodyTenant+`","roles":[]}`,
		"PLATFORM_OPERATOR", gtmOperatorGcid))

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status: got %d want 422 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "at least one role") {
		t.Errorf("body lacks role-required message: %s", rec.Body.String())
	}
}

func TestGrx_roleDedupe_201(t *testing.T) {
	t.Parallel()
	grant := &fakeGrantWriter{}
	h := NewGrantTenantMembershipHandler(
		&fakeAdminUserFinder{byGcid: map[string]*identity.User{tmTestGcid: tmTestUser()}},
		grant, &fakeAuthoritativeUpserter{created: true}, &fakeAuditEmitter{})

	rec := httptest.NewRecorder()
	// TRAINING_ADMIN aliases instructor; the case-folded duplicate must collapse.
	h.ServeHTTP(rec, gtmRequest(http.MethodPost,
		grantBody(tmTestGcid, gtmBodyTenant, "INSTRUCTOR", "instructor", "TRAINING_ADMIN"),
		"PLATFORM_OPERATOR", gtmOperatorGcid))

	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d want 201 (body=%s)", rec.Code, rec.Body.String())
	}
	if len(grant.gotRoles) != 1 || grant.gotRoles[0] != identity.RoleInstructor {
		t.Errorf("grant roles: got %v want [instructor] (de-duped)", grant.gotRoles)
	}
	// Wire response uses the UPPERCASE form of the single surviving role.
	if !strings.Contains(rec.Body.String(), `"roles":["INSTRUCTOR"]`) {
		t.Errorf("response roles: body=%s", rec.Body.String())
	}
}

// --- ServeHTTP: grantee resolution -------------------------------------------

func TestGrx_granteeNotFound_404(t *testing.T) {
	t.Parallel()
	h := NewGrantTenantMembershipHandler(
		&fakeAdminUserFinder{byGcid: map[string]*identity.User{}},
		&fakeGrantWriter{}, &fakeAuthoritativeUpserter{created: true}, &fakeAuditEmitter{})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, gtmRequest(http.MethodPost,
		grantBody(tmTestGcid, gtmBodyTenant, "INSTRUCTOR"), "PLATFORM_OPERATOR", gtmOperatorGcid))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status: got %d want 404 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "IDENTITY_USER_NOT_FOUND") {
		t.Errorf("body lacks IDENTITY_USER_NOT_FOUND: %s", rec.Body.String())
	}
}

func TestGrx_granteeResolveError_500(t *testing.T) {
	t.Parallel()
	users := &fakeAdminUserFinder{err: errors.New("db unreachable")}
	h := NewGrantTenantMembershipHandler(users, &fakeGrantWriter{}, &fakeAuthoritativeUpserter{created: true}, &fakeAuditEmitter{})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, gtmRequest(http.MethodPost,
		grantBody(tmTestGcid, gtmBodyTenant, "INSTRUCTOR"), "PLATFORM_OPERATOR", gtmOperatorGcid))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d want 500 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "IDENTITY_REPO_ERROR") {
		t.Errorf("body lacks IDENTITY_REPO_ERROR: %s", rec.Body.String())
	}
}

// --- ServeHTTP: authoritative + mirror write failures -------------------------

func TestGrx_authoritativeSuspended_409(t *testing.T) {
	t.Parallel()
	auth := &fakeAuthoritativeUpserter{err: ErrUpstreamMembershipSuspended}
	h := NewGrantTenantMembershipHandler(
		&fakeAdminUserFinder{byGcid: map[string]*identity.User{tmTestGcid: tmTestUser()}},
		&fakeGrantWriter{}, auth, &fakeAuditEmitter{})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, gtmRequest(http.MethodPost,
		grantBody(tmTestGcid, gtmBodyTenant, "INSTRUCTOR"), "PLATFORM_OPERATOR", gtmOperatorGcid))

	if rec.Code != http.StatusConflict {
		t.Fatalf("status: got %d want 409 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "IDENTITY_MEMBERSHIP_SUSPENDED") {
		t.Errorf("body lacks IDENTITY_MEMBERSHIP_SUSPENDED: %s", rec.Body.String())
	}
}

func TestGrx_authoritativeTenantNotFound_404(t *testing.T) {
	t.Parallel()
	auth := &fakeAuthoritativeUpserter{err: ErrUpstreamTenantNotFound}
	h := NewGrantTenantMembershipHandler(
		&fakeAdminUserFinder{byGcid: map[string]*identity.User{tmTestGcid: tmTestUser()}},
		&fakeGrantWriter{}, auth, &fakeAuditEmitter{})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, gtmRequest(http.MethodPost,
		grantBody(tmTestGcid, gtmBodyTenant, "INSTRUCTOR"), "PLATFORM_OPERATOR", gtmOperatorGcid))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status: got %d want 404 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "IDENTITY_TENANT_NOT_FOUND") {
		t.Errorf("body lacks IDENTITY_TENANT_NOT_FOUND: %s", rec.Body.String())
	}
}

func TestGrx_authoritativeError_502(t *testing.T) {
	t.Parallel()
	auth := &fakeAuthoritativeUpserter{err: errors.New("rpc unavailable")}
	h := NewGrantTenantMembershipHandler(
		&fakeAdminUserFinder{byGcid: map[string]*identity.User{tmTestGcid: tmTestUser()}},
		&fakeGrantWriter{}, auth, &fakeAuditEmitter{})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, gtmRequest(http.MethodPost,
		grantBody(tmTestGcid, gtmBodyTenant, "INSTRUCTOR"), "PLATFORM_OPERATOR", gtmOperatorGcid))

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status: got %d want 502 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "IDENTITY_TENANCY_ERROR") {
		t.Errorf("body lacks IDENTITY_TENANCY_ERROR: %s", rec.Body.String())
	}
}

func TestGrx_devNoAuthoritative_201(t *testing.T) {
	t.Parallel()
	grant := &fakeGrantWriter{}
	// nil authoritative = dev-mode wiring: the mirror-only grant must succeed.
	h := NewGrantTenantMembershipHandler(
		&fakeAdminUserFinder{byGcid: map[string]*identity.User{tmTestGcid: tmTestUser()}},
		grant, nil, &fakeAuditEmitter{})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, gtmRequest(http.MethodPost,
		grantBody(tmTestGcid, gtmBodyTenant, "INSTRUCTOR"), "PLATFORM_OPERATOR", gtmOperatorGcid))

	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d want 201 (body=%s)", rec.Code, rec.Body.String())
	}
	if grant.gotGcid != tmTestGcid || grant.gotTID != gtmBodyTenant {
		t.Errorf("grant: got gcid=%q tenant=%q want %q/%q", grant.gotGcid, grant.gotTID, tmTestGcid, gtmBodyTenant)
	}
}

func TestGrx_grantError_500(t *testing.T) {
	t.Parallel()
	grant := &fakeGrantWriter{err: errors.New("pg down")}
	h := NewGrantTenantMembershipHandler(
		&fakeAdminUserFinder{byGcid: map[string]*identity.User{tmTestGcid: tmTestUser()}},
		grant, &fakeAuthoritativeUpserter{created: true}, &fakeAuditEmitter{})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, gtmRequest(http.MethodPost,
		grantBody(tmTestGcid, gtmBodyTenant, "INSTRUCTOR"), "PLATFORM_OPERATOR", gtmOperatorGcid))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d want 500 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "IDENTITY_REPO_ERROR") {
		t.Errorf("body lacks IDENTITY_REPO_ERROR: %s", rec.Body.String())
	}
}

// --- ServeHTTP: audit tolerance (best-effort after the write) -----------------

func TestGrx_auditNil_201(t *testing.T) {
	t.Parallel()
	h := NewGrantTenantMembershipHandler(
		&fakeAdminUserFinder{byGcid: map[string]*identity.User{tmTestGcid: tmTestUser()}},
		&fakeGrantWriter{}, &fakeAuthoritativeUpserter{created: true}, nil)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, gtmRequest(http.MethodPost,
		grantBody(tmTestGcid, gtmBodyTenant, "INSTRUCTOR"), "PLATFORM_OPERATOR", gtmOperatorGcid))

	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d want 201 (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestGrx_auditError_tolerated_201(t *testing.T) {
	t.Parallel()
	audit := &fakeAuditEmitter{err: errors.New("pubsub down")}
	h := NewGrantTenantMembershipHandler(
		&fakeAdminUserFinder{byGcid: map[string]*identity.User{tmTestGcid: tmTestUser()}},
		&fakeGrantWriter{}, &fakeAuthoritativeUpserter{created: true}, audit)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, gtmRequest(http.MethodPost,
		grantBody(tmTestGcid, gtmBodyTenant, "INSTRUCTOR"), "PLATFORM_OPERATOR", gtmOperatorGcid))

	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d want 201 — audit failure must NOT roll back a persisted grant (body=%s)", rec.Code, rec.Body.String())
	}
	if len(audit.calls) != 1 {
		t.Errorf("audit must still be attempted: got %d calls want 1", len(audit.calls))
	}
}

// --- callerHoldsOperatorRole --------------------------------------------------

func TestGrx_callerHoldsOperatorRole(t *testing.T) {
	t.Parallel()

	empty := httptest.NewRequest(http.MethodPost, "/api/v1/admin/tenant-memberships", nil)
	if callerHoldsOperatorRole(empty) {
		t.Error("empty roles header must NOT pass the operator gate")
	}

	tenantAdmin := httptest.NewRequest(http.MethodPost, "/api/v1/admin/tenant-memberships", nil)
	tenantAdmin.Header.Set(servicemesh.HeaderUserRoles, "TENANT_ADMIN")
	if callerHoldsOperatorRole(tenantAdmin) {
		t.Error("TENANT_ADMIN must NOT pass the operator gate")
	}

	lower := httptest.NewRequest(http.MethodPost, "/api/v1/admin/tenant-memberships", nil)
	lower.Header.Set(servicemesh.HeaderUserRoles, "platform_operator")
	if !callerHoldsOperatorRole(lower) {
		t.Error("lowercase 'platform_operator' must pass (case-insensitive)")
	}

	mixed := httptest.NewRequest(http.MethodPost, "/api/v1/admin/tenant-memberships", nil)
	mixed.Header.Set(servicemesh.HeaderUserRoles, "LEARNER, PLATFORM_OPERATOR ")
	if !callerHoldsOperatorRole(mixed) {
		t.Error("operator amid other roles must pass")
	}
}
