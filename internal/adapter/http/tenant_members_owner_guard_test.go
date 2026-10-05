// tenant_members_owner_guard_test.go: S7-B1 at the HTTP boundary.
//
// The three admin routes that could erase ownership must each answer with a
// 409 carrying a NAMED code, so the H+ roster can say the right sentence
// rather than "role change failed":
//
//	DELETE /api/v1/admin/tenant-members/{gcid}         last owner
//	PUT    /api/v1/admin/tenant-members/{gcid}/roles   owner strip (authoritative)
//	PATCH  /api/v1/admin/tenant-members/{gcid}/role    owner strip (mirror)
//
// The third is the one that is easy to miss. PATCH /role writes the MIRROR
// first and only then makes a best-effort additive call to the authoritative
// store, so the chora-tenancy guard never sees it and the refusal arrives as
// the mirror's own identity.ErrOwnerRoleProtected rather than as an upstream
// sentinel. Both origins must land on the same status and the same code: an
// admin should not be able to tell which store refused, only what to do next.
//
// 409 rather than 403: this is a state conflict the caller can resolve by
// handing ownership over, not a permission the caller lacks. It matches the
// suspended-membership refusal already on these routes and the closure block
// the spec specifies at 13.7.2.
package httpadapter

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// assertOwnerRefusal pins status, code and the absence of leakage.
func assertOwnerRefusal(t *testing.T, rec *httptest.ResponseRecorder, wantCode string) {
	t.Helper()
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 (body=%s)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, wantCode) {
		t.Fatalf("body must carry the named code %q, got: %s", wantCode, body)
	}
	if strings.Contains(body, "IDENTITY_MEMBERSHIP_SUSPENDED") {
		t.Errorf("an ownership refusal must not be reported as a suspension: %s", body)
	}
}

func TestRemoveMember_lastOwner_409NamedCode(t *testing.T) {
	auth := &fakeAuthoritativeUpserter{removeErr: ErrUpstreamLastOwnerProtected}
	writer := &fakeAdminMembershipWriter{}
	h := newTMHandlerWithTenancy(&fakeAdminUserFinder{}, writer, auth)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodDelete, tmRemovePath(tmTestGcid), "", true, tmTestTenant))

	assertOwnerRefusal(t, rec, "IDENTITY_LAST_OWNER_PROTECTED")
	if len(writer.removes) != 0 {
		t.Errorf("the mirror must not be touched after an authoritative refusal; got %+v", writer.removes)
	}
}

func TestRemoveMember_devMirrorLastOwner_409NamedCode(t *testing.T) {
	// No tenancy client wired: the mirror guard is the only guard, and its
	// sentinel must reach the wire as the same 409.
	writer := &fakeAdminMembershipWriter{removeErr: identity.ErrLastOwnerProtected}
	h := newTMHandler(&fakeAdminUserFinder{}, writer, nil)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodDelete, tmRemovePath(tmTestGcid), "", true, tmTestTenant))

	assertOwnerRefusal(t, rec, "IDENTITY_LAST_OWNER_PROTECTED")
}

func TestSetRoles_ownerStrip_409NamedCode(t *testing.T) {
	auth := &fakeAuthoritativeUpserter{replaceErr: ErrUpstreamOwnerRoleProtected}
	writer := &fakeAdminMembershipWriter{}
	h := newTMHandlerWithTenancy(&fakeAdminUserFinder{}, writer, auth)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPut,
		tenantMembersBasePath+"/"+tmTestGcid+"/roles",
		`{"roles":["INSTRUCTOR"]}`, true, tmTestTenant))

	assertOwnerRefusal(t, rec, "IDENTITY_OWNER_ROLE_PROTECTED")
	if len(writer.changes) != 0 {
		t.Errorf("the mirror must not be replaced after an authoritative refusal; got %+v", writer.changes)
	}
}

// The H+ inline role select. Mirror-first, so the refusal originates in the
// identity mirror repository, not upstream.
func TestChangeRole_mirrorOwnerStrip_409NamedCode(t *testing.T) {
	writer := &fakeAdminMembershipWriter{changeErr: identity.ErrOwnerRoleProtected}
	auth := &fakeAuthoritativeUpserter{}
	h := newTMHandlerWithTenancy(&fakeAdminUserFinder{}, writer, auth)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPatch,
		tenantMembersBasePath+"/"+tmTestGcid+"/role",
		`{"role":"INSTRUCTOR"}`, true, tmTestTenant))

	assertOwnerRefusal(t, rec, "IDENTITY_OWNER_ROLE_PROTECTED")
	if auth.upserted {
		t.Errorf("a refused role change must not reach the authoritative store either")
	}
}

// The mirror's owner-strip sentinel can also surface from the multi-role
// editor when the authoritative store is absent (dev) or when the two stores
// have drifted. Same code, so the roster's message does not depend on which
// store noticed.
func TestSetRoles_mirrorOwnerStrip_409NamedCode(t *testing.T) {
	writer := &fakeAdminMembershipWriter{changeErr: identity.ErrOwnerRoleProtected}
	h := newTMHandler(&fakeAdminUserFinder{}, writer, nil)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tmRequest(http.MethodPut,
		tenantMembersBasePath+"/"+tmTestGcid+"/roles",
		`{"roles":["ADMIN"]}`, true, tmTestTenant))

	assertOwnerRefusal(t, rec, "IDENTITY_OWNER_ROLE_PROTECTED")
}

// OWNER stays ungrantable at the boundary, on every route that takes a role.
// The guards above stop ownership being destroyed; this stops it being handed
// out, which is the other half of the same invariant.
func TestTenantMembers_OwnerIsNotGrantableOnAnyRoute(t *testing.T) {
	for _, tc := range []struct {
		name, method, path, body string
	}{
		{"add by email", http.MethodPost, tenantMembersBasePath, `{"email":"x@example.com","role":"OWNER"}`},
		{"change role", http.MethodPatch, tenantMembersBasePath + "/" + tmTestGcid + "/role", `{"role":"OWNER"}`},
		{"set roles", http.MethodPut, tenantMembersBasePath + "/" + tmTestGcid + "/roles", `{"roles":["OWNER"]}`},
		{"set roles alongside admin", http.MethodPut, tenantMembersBasePath + "/" + tmTestGcid + "/roles", `{"roles":["ADMIN","OWNER"]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writer := &fakeAdminMembershipWriter{}
			h := newTMHandlerWithTenancy(&fakeAdminUserFinder{}, writer, &fakeAuthoritativeUpserter{})
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, tmRequest(tc.method, tc.path, tc.body, true, tmTestTenant))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
			}
			if len(writer.adds)+len(writer.changes) != 0 {
				t.Errorf("a rejected OWNER grant must not reach any store")
			}
		})
	}
}
