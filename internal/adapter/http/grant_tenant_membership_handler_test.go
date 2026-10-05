// grant_tenant_membership_handler_test.go — TDD RED for WS2 / CHO-1872
// (ADR-194 D1): POST /api/v1/admin/tenant-memberships, the operator
// cross-tenant membership grant.
//
// Distinct from tenant_members_admin_handler_test.go: PLATFORM_OPERATOR-only
// gate, tenant from the BODY (not the header), multi-role, IMDA-D1 evidence.
package httpadapter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/apollo-chora/chora-common/auth/servicemesh"
	"github.com/apollo-chora/chora-identity/internal/adapter/events"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

const (
	gtmOperatorGcid = "00000000-0000-7000-8000-0000000000aa"
	// Deliberately != tmTestTenant — proves the write uses the BODY tenant,
	// never the caller's header tenant.
	gtmBodyTenant = "22222222-2222-7222-8222-222222222222"
)

// fakeGrantWriter records the (gcid, tenant, roles) of a GrantMembership call.
type fakeGrantWriter struct {
	membershipID string
	gotGcid      string
	gotTID       string
	gotRoles     []identity.Role
	err          error
}

func (f *fakeGrantWriter) GrantMembership(_ context.Context, gcid, tenantID string, roles []identity.Role) (string, error) {
	f.gotGcid, f.gotTID, f.gotRoles = gcid, tenantID, roles
	if f.err != nil {
		return "", f.err
	}
	if f.membershipID == "" {
		return "01990000-0000-7000-8000-0000000000ff", nil
	}
	return f.membershipID, nil
}

// fakeAuditEmitter captures the IMDA evidence the handler records.
type fakeAuditEmitter struct {
	calls []events.EvidenceInput
	envs  []events.Envelope
	err   error
}

func (f *fakeAuditEmitter) RecordEvidence(env events.Envelope, in events.EvidenceInput) error {
	f.envs = append(f.envs, env)
	f.calls = append(f.calls, in)
	return f.err
}

func gtmRequest(method, body, roles, gcid string) *http.Request {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, "/api/v1/admin/tenant-memberships", nil)
	} else {
		r = httptest.NewRequest(method, "/api/v1/admin/tenant-memberships", strings.NewReader(body))
	}
	if roles != "" {
		r.Header.Set(servicemesh.HeaderUserRoles, roles)
	}
	if gcid != "" {
		r.Header.Set(servicemesh.HeaderGCID, gcid)
	}
	return r
}

func grantBody(gcid, tenant string, roles ...string) string {
	quoted := make([]string, len(roles))
	for i, r := range roles {
		quoted[i] = `"` + r + `"`
	}
	return `{"gcid":"` + gcid + `","tenant_id":"` + tenant + `","roles":[` + strings.Join(quoted, ",") + `]}`
}

func TestGrantMembership_happyPath_201(t *testing.T) {
	users := &fakeAdminUserFinder{byGcid: map[string]*identity.User{tmTestGcid: tmTestUser()}}
	grant := &fakeGrantWriter{membershipID: "01990000-0000-7000-8000-000000000abc"}
	auth := &fakeAuthoritativeUpserter{created: true}
	audit := &fakeAuditEmitter{}
	h := NewGrantTenantMembershipHandler(users, grant, auth, audit)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, gtmRequest(http.MethodPost,
		grantBody(tmTestGcid, gtmBodyTenant, "INSTRUCTOR"),
		"PLATFORM_OPERATOR", gtmOperatorGcid))

	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d want 201 (body=%s)", rec.Code, rec.Body.String())
	}
	// BODY tenant, not the (absent) header tenant.
	if grant.gotTID != gtmBodyTenant {
		t.Errorf("grant tenant: got %q want body tenant %q", grant.gotTID, gtmBodyTenant)
	}
	if auth.gotTID != gtmBodyTenant {
		t.Errorf("authoritative tenant: got %q want body tenant %q", auth.gotTID, gtmBodyTenant)
	}
	// Authoritative gets lowercase membership roles (WS1 parity).
	if len(auth.gotRoles) != 1 || auth.gotRoles[0] != "instructor" {
		t.Errorf("authoritative roles: got %v want [instructor]", auth.gotRoles)
	}
	if len(grant.gotRoles) != 1 || grant.gotRoles[0] != identity.RoleInstructor {
		t.Errorf("grant roles: got %v want [instructor]", grant.gotRoles)
	}
	// IMDA-D1 accountability evidence.
	if len(audit.calls) != 1 {
		t.Fatalf("audit: got %d evidence calls want 1", len(audit.calls))
	}
	ev := audit.calls[0]
	if ev.EvidenceType != "tenant_membership_granted" || ev.Dimension != "accountability" {
		t.Errorf("audit evidence: got type=%q dim=%q", ev.EvidenceType, ev.Dimension)
	}
	if ev.AdditionalFields["operator_gcid"] != gtmOperatorGcid ||
		ev.AdditionalFields["grantee_gcid"] != tmTestGcid ||
		ev.AdditionalFields["target_tenant_id"] != gtmBodyTenant {
		t.Errorf("audit additional_fields: got %v", ev.AdditionalFields)
	}
	// Response shape: uppercase roles + the real membership_id.
	var resp struct {
		MembershipID string   `json:"membership_id"`
		Gcid         string   `json:"gcid"`
		TenantID     string   `json:"tenant_id"`
		Roles        []string `json:"roles"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.MembershipID != grant.membershipID {
		t.Errorf("response membership_id: got %q want %q", resp.MembershipID, grant.membershipID)
	}
	if resp.TenantID != gtmBodyTenant || len(resp.Roles) != 1 || resp.Roles[0] != "INSTRUCTOR" {
		t.Errorf("response: got tenant=%q roles=%v", resp.TenantID, resp.Roles)
	}
}

func TestGrantMembership_nonOperator_403(t *testing.T) {
	users := &fakeAdminUserFinder{byGcid: map[string]*identity.User{tmTestGcid: tmTestUser()}}
	h := NewGrantTenantMembershipHandler(users, &fakeGrantWriter{}, &fakeAuthoritativeUpserter{created: true}, &fakeAuditEmitter{})
	rec := httptest.NewRecorder()
	// TENANT_ADMIN is an admin role but NOT the operator — must be rejected.
	h.ServeHTTP(rec, gtmRequest(http.MethodPost,
		grantBody(tmTestGcid, gtmBodyTenant, "INSTRUCTOR"), "TENANT_ADMIN", gtmOperatorGcid))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status: got %d want 403 (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestGrantMembership_trainingAdminAlias_mapsInstructor(t *testing.T) {
	users := &fakeAdminUserFinder{byGcid: map[string]*identity.User{tmTestGcid: tmTestUser()}}
	grant := &fakeGrantWriter{}
	auth := &fakeAuthoritativeUpserter{created: true}
	h := NewGrantTenantMembershipHandler(users, grant, auth, &fakeAuditEmitter{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, gtmRequest(http.MethodPost,
		grantBody(tmTestGcid, gtmBodyTenant, "TRAINING_ADMIN"), "PLATFORM_OPERATOR", gtmOperatorGcid))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d want 201 (body=%s)", rec.Code, rec.Body.String())
	}
	if len(grant.gotRoles) != 1 || grant.gotRoles[0] != identity.RoleInstructor {
		t.Errorf("TRAINING_ADMIN must map to instructor; got %v", grant.gotRoles)
	}
}

func TestGrantMembership_ownerRole_422(t *testing.T) {
	users := &fakeAdminUserFinder{byGcid: map[string]*identity.User{tmTestGcid: tmTestUser()}}
	h := NewGrantTenantMembershipHandler(users, &fakeGrantWriter{}, &fakeAuthoritativeUpserter{created: true}, &fakeAuditEmitter{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, gtmRequest(http.MethodPost,
		grantBody(tmTestGcid, gtmBodyTenant, "OWNER"), "PLATFORM_OPERATOR", gtmOperatorGcid))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status: got %d want 422 (OWNER not grantable, body=%s)", rec.Code, rec.Body.String())
	}
}

func TestGrantMembership_agidGcid_400(t *testing.T) {
	users := &fakeAdminUserFinder{byGcid: map[string]*identity.User{}}
	h := NewGrantTenantMembershipHandler(users, &fakeGrantWriter{}, &fakeAuthoritativeUpserter{created: true}, &fakeAuditEmitter{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, gtmRequest(http.MethodPost,
		grantBody(tmAgidGcid, gtmBodyTenant, "INSTRUCTOR"), "PLATFORM_OPERATOR", gtmOperatorGcid))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400 (AGID rejected, body=%s)", rec.Code, rec.Body.String())
	}
}

func TestGrantMembership_methodNotAllowed_405(t *testing.T) {
	h := NewGrantTenantMembershipHandler(&fakeAdminUserFinder{}, &fakeGrantWriter{}, &fakeAuthoritativeUpserter{}, &fakeAuditEmitter{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, gtmRequest(http.MethodGet, "", "PLATFORM_OPERATOR", gtmOperatorGcid))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status: got %d want 405", rec.Code)
	}
}
