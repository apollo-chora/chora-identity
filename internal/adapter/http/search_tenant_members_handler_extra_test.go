// search_tenant_members_handler_extra_test.go — coverage additions for
// SearchTenantMembersHandler (see search_tenant_members_handler_test.go for
// the RED→GREEN suite). Focused on the branches the main suite leaves hot:
//
//   - ServeHTTP: cross-tenant read with a NIL audit emitter → 500
//     (fail-closed), legacy X-Tenant-Id header fallback
//   - parsePageSize: non-integer / negative / whitespace forms
//   - decodePageToken: over-long token, wrong payload prefix, malformed
//     offset, negative offset (direct unit tests)
//   - looksLikeTenantUUID: wrong length, wrong dash positions, uppercase hex
//   - callerHoldsAdminRole: empty header, legacy lowercase aliases, OWNER
package httpadapter

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/apollo-chora/chora-common/auth/servicemesh"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// --- ServeHTTP: fail-closed audit + legacy tenant header ----------------------

func TestSrx_operatorRead_nilAudit_500(t *testing.T) {
	t.Parallel()
	repo := &stubSearchRepo{}
	// Cross-tenant read with NO wired audit — the read must be aborted
	// (fail-closed IMDA-D1), the repo never called.
	h := NewSearchTenantMembersHandler(repo, nil)

	rec := httptest.NewRecorder()
	req := operatorRequest(http.MethodGet, "/api/v1/admin/tenant-members?managed_tenant_id="+managedTenantID)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d want 500 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "IDENTITY_AUDIT_NOT_WIRED") {
		t.Errorf("body lacks IDENTITY_AUDIT_NOT_WIRED: %s", rec.Body.String())
	}
	if repo.gotQuery.TenantID != "" {
		t.Error("repo invoked despite a nil cross-tenant audit emitter")
	}
}

func TestSrx_legacyTenantHeaderFallback_200(t *testing.T) {
	t.Parallel()
	repo := &stubSearchRepo{result: identity.TenantMemberSearchResult{}}
	h := newTestSearchHandler(repo)

	// Production traffic stamps chora-tenant-id; local/curl probes may use the
	// legacy X-Tenant-Id fallback — it MUST scope the read.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/tenant-members", nil)
	req.Header.Set(servicemesh.HeaderGCID, testGCID)
	req.Header.Set("X-Tenant-Id", testTenantID)
	req.Header.Set(servicemesh.HeaderUserRoles, "TENANT_ADMIN")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if repo.gotQuery.TenantID != testTenantID {
		t.Errorf("repo tenant: got %q want legacy header %q", repo.gotQuery.TenantID, testTenantID)
	}
}

// --- parsePageSize ------------------------------------------------------------

func TestSrx_parsePageSize(t *testing.T) {
	t.Parallel()

	if n, err := parsePageSize(""); err != nil || n != 20 {
		t.Errorf("empty: got %d, %v want 20, nil", n, err)
	}
	if n, err := parsePageSize("   "); err != nil || n != 20 {
		t.Errorf("whitespace: got %d, %v want 20, nil", n, err)
	}
	if _, err := parsePageSize("abc"); err == nil {
		t.Error("non-integer page_size must error")
	}
	if _, err := parsePageSize("7"); err == nil {
		t.Error("non-enum page_size must error")
	}
	if _, err := parsePageSize("-1"); err == nil {
		t.Error("negative page_size must error")
	}
	for _, want := range []int{10, 20, 50, 100} {
		if n, err := parsePageSize(strconv.Itoa(want)); err != nil || n != want {
			t.Errorf("page_size=%d: got %d, %v want %d, nil", want, n, err, want)
		}
	}
}

// --- decodePageToken ----------------------------------------------------------

func TestSrx_decodePageToken(t *testing.T) {
	t.Parallel()

	if n, err := decodePageToken(""); err != nil || n != 0 {
		t.Errorf("empty: got %d, %v want 0, nil", n, err)
	}
	if _, err := decodePageToken(strings.Repeat("a", 513)); err == nil || !strings.Contains(err.Error(), "512") {
		t.Error("over-long page_token must error")
	}
	if _, err := decodePageToken("$$$"); err == nil {
		t.Error("invalid base64-url page_token must error")
	}
	// Base64-valid JSON-ish payload that lacks the "offset:" prefix.
	if _, err := decodePageToken(base64.RawURLEncoding.EncodeToString([]byte("not-an-offset"))); err == nil {
		t.Error("payload without the offset: prefix must error")
	}
	if _, err := decodePageToken(base64.RawURLEncoding.EncodeToString([]byte("offset:abc"))); err == nil {
		t.Error("non-numeric offset must error")
	}
	if _, err := decodePageToken(base64.RawURLEncoding.EncodeToString([]byte("offset:-7"))); err == nil {
		t.Error("negative offset must error")
	}
	if n, err := decodePageToken(base64.RawURLEncoding.EncodeToString([]byte("offset:42"))); err != nil || n != 42 {
		t.Errorf("round-trip: got %d, %v want 42, nil", n, err)
	}
}

// --- looksLikeTenantUUID ------------------------------------------------------

func TestSrx_looksLikeTenantUUID(t *testing.T) {
	t.Parallel()

	if looksLikeTenantUUID("") {
		t.Error("empty string must not look like a UUID")
	}
	if looksLikeTenantUUID("not-a-uuid") {
		t.Error("short garbage must not look like a UUID")
	}
	// 36 chars, all-hyphen-plus-hex shape but a dash at the wrong position.
	if looksLikeTenantUUID("01970000-00-07000-8000-0000000000bb") {
		t.Error("dash at a non-standard position must fail")
	}
	// 36 chars with a non-dash character in a must-be-dash slot (i==8).
	if looksLikeTenantUUID("01970000V0000-7000-8000-0000000000bb") {
		t.Error("non-dash at a dash position must fail")
	}
	// 36 chars with a non-hex tail character.
	if looksLikeTenantUUID("01970000-0000-7000-8000-0000000000bG") {
		t.Error("non-hex character must fail")
	}
	if !looksLikeTenantUUID(managedTenantID) {
		t.Error("valid tenant UUID must pass")
	}
	if !looksLikeTenantUUID(strings.ToUpper(managedTenantID)) {
		t.Error("uppercase hex must pass (case-insensitive)")
	}
}

// --- callerHoldsAdminRole -----------------------------------------------------

func TestSrx_callerHoldsAdminRole(t *testing.T) {
	t.Parallel()

	empty := httptest.NewRequest(http.MethodGet, "/api/v1/admin/tenant-members", nil)
	if callerHoldsAdminRole(empty) {
		t.Error("empty roles header must NOT pass the admin gate")
	}

	learner := httptest.NewRequest(http.MethodGet, "/api/v1/admin/tenant-members", nil)
	learner.Header.Set(servicemesh.HeaderUserRoles, "LEARNER")
	if callerHoldsAdminRole(learner) {
		t.Error("LEARNER must NOT pass the admin gate")
	}

	legacy := httptest.NewRequest(http.MethodGet, "/api/v1/admin/tenant-members", nil)
	legacy.Header.Set(servicemesh.HeaderUserRoles, "admin") // legacy lowercase mint alias
	if !callerHoldsAdminRole(legacy) {
		t.Error("lowercase 'admin' must pass (legacy mint alias)")
	}

	owner := httptest.NewRequest(http.MethodGet, "/api/v1/admin/tenant-members", nil)
	owner.Header.Set(servicemesh.HeaderUserRoles, "OWNER") // L1 bootstrap owner
	if !callerHoldsAdminRole(owner) {
		t.Error("OWNER must pass the admin gate (bootstrap)")
	}
}
