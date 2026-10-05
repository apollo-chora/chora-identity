// me_handler_mesh_test.go — gateway-style auth shape tests for /me (B2 fix).
//
// Production traffic to chora-identity comes via chora-gateway, which:
//
//  1. Validates the Identity Platform / ChoraSession JWT at the edge.
//
//  2. Marshals the canonical gcid + tenant_id + roles into mesh-metadata
//     headers via libs/chora-go-common/auth/servicemesh:
//
//     chora-gcid: 00000000-0000-7000-8000-000000001999
//     chora-tenant-id: 11111111-1111-7111-8111-111111111111
//     gcid: 00000000-0000-7000-8000-000000001999      (lowercase legacy)
//
//  3. Forwards the original `Authorization: Bearer <JWT>` header as-is so
//     backend services can opt-in to additional verification.
//
// The legacy `bearerAuth` middleware (per the M10 MVP comment block in
// me_handler.go lines 8-12) treated the WHOLE bearer token string as the
// raw GCID — i.e. `Authorization: Bearer <gcid>` (literal UUID). That works
// for unit tests and the comic seed but FAILS LIVE — the gateway sends a
// JWT, not a raw UUID, so the pg.GetByGcid query hit:
//
//	ERROR: invalid input syntax for type uuid: "eyJhbGciOiJIUzI1NiI..."
//	(SQLSTATE 22P02)
//
// And surfaced as 401 IDENTITY_UNKNOWN_GCID at the gateway (the B2 demo-
// rehearsal residual).
//
// Fix: bearerAuth now prefers the mesh-stamped gcid (chora-gcid header)
// when present, falling back to the lowercase `gcid` header, and only
// then to the legacy bearer-as-gcid MVP shape. Per servicemesh.go trust
// model — the gateway is the ONLY entry point + mTLS at the mesh layer
// makes the chora-gcid header trusted. Bearer-as-gcid retained for
// backwards-compat with the comic-seed tests + dev-curl shape.
package httpadapter_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	httpadapter "github.com/apollo-chora/chora-identity/internal/adapter/http"
	"github.com/apollo-chora/chora-identity/internal/adapter/inmem"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// gatewayStyleReq simulates the exact header shape chora-gateway stamps on
// outbound calls to chora-identity (see services/chora-gateway/internal/
// aggregator/phyllis/phyllis.go `call` method).
//
//   - Authorization: Bearer <opaque-JWT>  (full ChoraSession JWT)
//   - chora-gcid: <gcid>                  (mesh metadata, mTLS-trusted)
//   - chora-tenant-id: <tenant>           (mesh metadata)
//   - gcid: <gcid>                        (legacy lowercase header, D1.5)
//
// The bearer value here is INTENTIONALLY a JWT-shaped string (3 dot-
// separated segments) so the test asserts the handler does NOT crash trying
// to UUID-parse it.
func gatewayStyleReq(method, path, gcid, tenantID string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	// JWT-shaped stand-in. The exact contents don't matter — the test only
	// asserts the handler does NOT try to treat this as the GCID.
	jwtStandin := "eyJhbGciOiJIUzI1NiJ9.eyJnY2lkIjoiZ2NpZCJ9.signature-placeholder"
	r.Header.Set("Authorization", "Bearer "+jwtStandin)
	r.Header.Set("Content-Type", "application/json")
	if gcid != "" {
		r.Header.Set("chora-gcid", gcid)
		r.Header.Set("gcid", gcid) // legacy lowercase (D1.5)
	}
	if tenantID != "" {
		r.Header.Set("chora-tenant-id", tenantID)
	}
	return r
}

// TestGetMe_GatewayMeshHeader_LookupSucceeds — the B2 canonical case.
// The gateway forwards a JWT bearer + the canonical gcid in mesh metadata.
// /me must resolve the user from the mesh header, NOT from the bearer
// token string (which is opaque JWT, not a UUID).
func TestGetMe_GatewayMeshHeader_LookupSucceeds(t *testing.T) {
	t.Parallel()

	users := inmem.NewUserRepository()
	memberships := inmem.NewMembershipRepository()
	snapshots := inmem.NewSnapshotRepository()
	courseRoles := inmem.NewCourseRoleRepository()

	// Seed a user with the canonical Phyllis gcid the gateway forwards.
	const phyllisCanonicalGcid = "00000000-0000-7000-8000-000000001999"
	u := &identity.User{
		Gcid:             phyllisCanonicalGcid,
		Email:            "phyllis@mightymind.sg",
		DisplayName:      "Phyllis Tan",
		IdentityProvider: identity.ProviderOIDC,
		FederatedSubject: "google-oauth2|999",
	}
	if err := users.Save(t.Context(), u); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	srv := httpadapter.NewRouterWithCourseRoles(users, memberships, snapshots, courseRoles)
	w := httptest.NewRecorder()
	const phyllisTenant = "11111111-1111-7111-8111-111111111111"
	srv.ServeHTTP(w, gatewayStyleReq(http.MethodGet, "/me", phyllisCanonicalGcid, phyllisTenant))

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s; want 200 (B2 fix: bearer is JWT, gcid is in mesh header)",
			w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if got["gcid"] != phyllisCanonicalGcid {
		t.Errorf("gcid=%v want %s", got["gcid"], phyllisCanonicalGcid)
	}
	if got["email"] != "phyllis@mightymind.sg" {
		t.Errorf("email=%v want phyllis@mightymind.sg", got["email"])
	}
}

// TestGetMe_LegacyBearerAsGcid_StillWorks — backwards-compat: tests that
// embed the gcid directly in Authorization: Bearer (the M10 MVP shape +
// the existing me_handler_test.go convention) MUST still succeed. Without
// mesh headers the bearer falls back to the legacy interpretation.
func TestGetMe_LegacyBearerAsGcid_StillWorks(t *testing.T) {
	t.Parallel()

	users := inmem.NewUserRepository()
	memberships := inmem.NewMembershipRepository()
	snapshots := inmem.NewSnapshotRepository()
	courseRoles := inmem.NewCourseRoleRepository()
	if err := inmem.SeedComicFixtures(users, courseRoles); err != nil {
		t.Fatalf("seed: %v", err)
	}
	srv := httpadapter.NewRouterWithCourseRoles(users, memberships, snapshots, courseRoles)
	w := httptest.NewRecorder()
	// Legacy shape — bearer IS the gcid (comic-seed Phyllis fixture).
	const comicPhyllisGcid = "01935b5a-9bcf-7000-8000-000000000001"
	r := httptest.NewRequest(http.MethodGet, "/me", nil)
	r.Header.Set("Authorization", "Bearer "+comicPhyllisGcid)
	srv.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s; want 200 (legacy bearer-as-gcid back-compat)",
			w.Code, w.Body.String())
	}
}

// TestGetMe_MeshGcidUnknown_Returns401 — mesh header carrying a gcid that
// is NOT in the user repo (e.g. cold tenant, deleted user) must still
// produce 401 IDENTITY_UNKNOWN_GCID (the right verdict — just NOT for the
// canonical Phyllis case).
func TestGetMe_MeshGcidUnknown_Returns401(t *testing.T) {
	t.Parallel()

	users := inmem.NewUserRepository()
	memberships := inmem.NewMembershipRepository()
	snapshots := inmem.NewSnapshotRepository()
	courseRoles := inmem.NewCourseRoleRepository()
	srv := httpadapter.NewRouterWithCourseRoles(users, memberships, snapshots, courseRoles)

	w := httptest.NewRecorder()
	const unknownGcid = "99999999-9999-7999-8999-999999999999"
	srv.ServeHTTP(w, gatewayStyleReq(http.MethodGet, "/me", unknownGcid, ""))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status=%d; want 401 for unknown gcid in mesh header", w.Code)
	}
	if !contains(w.Body.String(), "IDENTITY_UNKNOWN_GCID") {
		t.Errorf("body=%s; want IDENTITY_UNKNOWN_GCID code", w.Body.String())
	}
}

// TestGetMe_LowercaseGcidHeaderOnly_Succeeds — the gateway stamps BOTH
// chora-gcid (mesh) AND gcid (lowercase, D1.5). In dev / test some
// callers stamp only the lowercase header. Both should work.
func TestGetMe_LowercaseGcidHeaderOnly_Succeeds(t *testing.T) {
	t.Parallel()

	users := inmem.NewUserRepository()
	memberships := inmem.NewMembershipRepository()
	snapshots := inmem.NewSnapshotRepository()
	courseRoles := inmem.NewCourseRoleRepository()

	const canonicalGcid = "00000000-0000-7000-8000-000000001999"
	if err := users.Save(t.Context(), &identity.User{
		Gcid:             canonicalGcid,
		Email:            "phyllis@mightymind.sg",
		DisplayName:      "Phyllis Tan",
		IdentityProvider: identity.ProviderOIDC,
		FederatedSubject: "google-oauth2|999",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	srv := httpadapter.NewRouterWithCourseRoles(users, memberships, snapshots, courseRoles)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/me", nil)
	r.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig")
	r.Header.Set("gcid", canonicalGcid)
	srv.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s; want 200 (lowercase gcid header only)",
			w.Code, w.Body.String())
	}
}

// contains is a strings.Contains helper to keep the test self-contained.
func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) &&
		(haystack == needle ||
			len(haystack) > 0 && len(needle) > 0 &&
				indexOf(haystack, needle) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
