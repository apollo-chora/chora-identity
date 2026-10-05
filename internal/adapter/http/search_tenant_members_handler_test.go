// search_tenant_members_handler_test.go — RED→GREEN tests for the
// searchTenantMembers handler (operationId per
// chora-contracts/openapi/identity-admin.yaml).
//
// Tests cover:
//   - happy path returns canonical envelope
//   - empty page_token decodes to offset 0
//   - 422 on q < 2 / q > 64 chars
//   - 422 on bad page_size (not in enum)
//   - 403 on missing TRAINING_ADMIN / TENANT_ADMIN role
//   - 401 on missing/empty tenant context
//   - encode/decode of next_page_token (HasMore propagates)
package httpadapter

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/apollo-chora/chora-common/auth/servicemesh"
	"github.com/apollo-chora/chora-identity/internal/adapter/events"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// -----------------------------------------------------------------------------
// stubSearchRepo — captures the search query + returns canned result.
// -----------------------------------------------------------------------------

type stubSearchRepo struct {
	gotQuery identity.TenantMemberSearchQuery
	result   identity.TenantMemberSearchResult
	err      error
}

func (s *stubSearchRepo) Search(ctx context.Context, q identity.TenantMemberSearchQuery) (identity.TenantMemberSearchResult, error) {
	s.gotQuery = q
	if s.err != nil {
		return identity.TenantMemberSearchResult{}, s.err
	}
	return s.result, nil
}

// -----------------------------------------------------------------------------
// recordingAudit — captures IMDA-D1 evidence emits; err forces the fail-closed
// path (a failed emit MUST abort the cross-tenant read).
// -----------------------------------------------------------------------------

type recordingAudit struct {
	calls []events.EvidenceInput
	envs  []events.Envelope
	err   error
}

func (a *recordingAudit) RecordEvidence(env events.Envelope, in events.EvidenceInput) error {
	a.envs = append(a.envs, env)
	a.calls = append(a.calls, in)
	return a.err
}

// newTestSearchHandler wires the handler with a throwaway audit stub for the
// tenant-scoped tests (which never reach the operator audit path).
func newTestSearchHandler(repo identity.TenantMemberSearchRepo) *SearchTenantMembersHandler {
	return NewSearchTenantMembersHandler(repo, &recordingAudit{})
}

// managedTenantID is a DIFFERENT tenant than testTenantID — the operator's
// cross-tenant target for the S4 learner-directory read.
const managedTenantID = "01970000-0000-7000-8000-0000000000bb"

// operatorRequest builds a PLATFORM_OPERATOR request. A mesh tenant header is
// deliberately set to testTenantID so tests can prove the managed_tenant_id
// query param — not the header — drives the target-tenant read.
func operatorRequest(method, path string) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set(servicemesh.HeaderGCID, testGCID)
	req.Header.Set(servicemesh.HeaderTenantID, testTenantID)
	req.Header.Set(servicemesh.HeaderUserRoles, string(identity.CanonicalRolePlatformOperator))
	return req
}

// -----------------------------------------------------------------------------
// Fixture helpers
// -----------------------------------------------------------------------------

const (
	testTenantID = "01970000-0000-7000-8000-0000000000aa"
	testGCID     = "00000000-0000-7000-8000-000000001999"
)

func phyllisSummary(t *testing.T) identity.TenantMemberSummary {
	t.Helper()
	email := "daleleung76@gmail.com"
	name := "Dale (multi-role test)"
	ts, _ := time.Parse(time.RFC3339, "2026-05-16T01:32:00Z")
	return identity.TenantMemberSummary{
		GCID:         testGCID,
		Email:        &email,
		DisplayName:  &name,
		Roles:        []string{"ADMIN", "INSTRUCTOR"},
		LastActiveAt: &ts,
	}
}

// authedRequest builds a request with mesh-trust headers (chora-gcid,
// chora-tenant-id, role-summary) so the handler's auth gate sees a caller
// that holds TENANT_ADMIN.
func authedRequest(method, path string, roles []string) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set(servicemesh.HeaderGCID, testGCID)
	req.Header.Set(servicemesh.HeaderTenantID, testTenantID)
	if len(roles) > 0 {
		req.Header.Set(servicemesh.HeaderUserRoles, strings.Join(roles, ","))
	}
	return req
}

// -----------------------------------------------------------------------------
// Happy path
// -----------------------------------------------------------------------------

func TestSearchTenantMembers_HappyPath(t *testing.T) {
	repo := &stubSearchRepo{
		result: identity.TenantMemberSearchResult{
			Items: []identity.TenantMemberSummary{phyllisSummary(t)},
		},
	}
	h := newTestSearchHandler(repo)

	rr := httptest.NewRecorder()
	req := authedRequest(http.MethodGet,
		"/api/v1/admin/tenant-members?q=dale",
		[]string{"TENANT_ADMIN"})
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	items, _ := got["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("items: got %d want 1; body=%s", len(items), rr.Body.String())
	}
	first := items[0].(map[string]any)
	if first["gcid"] != testGCID {
		t.Errorf("gcid: got %v", first["gcid"])
	}
	if first["email"] != "daleleung76@gmail.com" {
		t.Errorf("email: got %v", first["email"])
	}
	if first["display_name"] != "Dale (multi-role test)" {
		t.Errorf("display_name: got %v", first["display_name"])
	}
	roles, _ := first["roles"].([]any)
	if len(roles) != 2 {
		t.Errorf("roles: got %v want 2 entries", roles)
	}

	// Repo MUST have been called with the q substring + the tenant from mesh
	// claims.
	if repo.gotQuery.Q != "dale" {
		t.Errorf("repo q: got %q want %q", repo.gotQuery.Q, "dale")
	}
	if repo.gotQuery.TenantID != testTenantID {
		t.Errorf("repo tenant: got %q want %q", repo.gotQuery.TenantID, testTenantID)
	}
	if repo.gotQuery.PageSize != 20 {
		t.Errorf("default page_size: got %d want 20", repo.gotQuery.PageSize)
	}
}

// -----------------------------------------------------------------------------
// 403 when caller lacks TRAINING_ADMIN/TENANT_ADMIN
// -----------------------------------------------------------------------------

func TestSearchTenantMembers_403_InsufficientRole(t *testing.T) {
	repo := &stubSearchRepo{}
	h := newTestSearchHandler(repo)

	rr := httptest.NewRecorder()
	req := authedRequest(http.MethodGet, "/api/v1/admin/tenant-members", []string{"LEARNER"})
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status: got %d want 403", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "AUTH_INSUFFICIENT_ROLE") {
		t.Errorf("body lacks AUTH_INSUFFICIENT_ROLE: %s", body)
	}
}

func TestSearchTenantMembers_AcceptsTrainingAdmin(t *testing.T) {
	repo := &stubSearchRepo{result: identity.TenantMemberSearchResult{}}
	h := newTestSearchHandler(repo)

	rr := httptest.NewRecorder()
	req := authedRequest(http.MethodGet, "/api/v1/admin/tenant-members", []string{"TRAINING_ADMIN"})
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200 (TRAINING_ADMIN must pass gate)", rr.Code)
	}
}

// TestSearchTenantMembers_AcceptsLegacyLowercaseRoles — the current mint
// handler stamps the schema-form lowercase roles (`instructor` / `admin`)
// onto the JWT; the role gate MUST accept these as the legacy aliases of
// TRAINING_ADMIN / TENANT_ADMIN per the doc comment on adminRoles.
func TestSearchTenantMembers_AcceptsLegacyLowercaseRoles(t *testing.T) {
	repo := &stubSearchRepo{result: identity.TenantMemberSearchResult{}}
	h := newTestSearchHandler(repo)

	for _, role := range []string{"instructor", "admin", "Instructor", "Admin"} {
		rr := httptest.NewRecorder()
		req := authedRequest(http.MethodGet, "/api/v1/admin/tenant-members", []string{role})
		h.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("role=%q: got %d want 200 (legacy lowercase MUST pass gate)", role, rr.Code)
		}
	}
}

// -----------------------------------------------------------------------------
// 422 — q too short (< 2) or too long (> 64)
// -----------------------------------------------------------------------------

func TestSearchTenantMembers_422_QTooShort(t *testing.T) {
	repo := &stubSearchRepo{}
	h := newTestSearchHandler(repo)

	rr := httptest.NewRecorder()
	req := authedRequest(http.MethodGet, "/api/v1/admin/tenant-members?q=a", []string{"TENANT_ADMIN"})
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status: got %d want 422", rr.Code)
	}
}

func TestSearchTenantMembers_422_QTooLong(t *testing.T) {
	repo := &stubSearchRepo{}
	h := newTestSearchHandler(repo)

	rr := httptest.NewRecorder()
	long := strings.Repeat("a", 65)
	req := authedRequest(http.MethodGet, "/api/v1/admin/tenant-members?q="+long, []string{"TENANT_ADMIN"})
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status: got %d want 422", rr.Code)
	}
}

// -----------------------------------------------------------------------------
// 422 — bad page_size (must be in {10,20,50,100})
// -----------------------------------------------------------------------------

func TestSearchTenantMembers_422_BadPageSize(t *testing.T) {
	repo := &stubSearchRepo{}
	h := newTestSearchHandler(repo)

	rr := httptest.NewRecorder()
	req := authedRequest(http.MethodGet, "/api/v1/admin/tenant-members?page_size=7", []string{"TENANT_ADMIN"})
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status: got %d want 422", rr.Code)
	}
}

// -----------------------------------------------------------------------------
// 422 — bad role enum
// -----------------------------------------------------------------------------

func TestSearchTenantMembers_422_BadRole(t *testing.T) {
	repo := &stubSearchRepo{}
	h := newTestSearchHandler(repo)

	rr := httptest.NewRecorder()
	req := authedRequest(http.MethodGet, "/api/v1/admin/tenant-members?role=GODKING", []string{"TENANT_ADMIN"})
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status: got %d want 422", rr.Code)
	}
}

// -----------------------------------------------------------------------------
// 401 — no tenant context (no mesh header AND no fallback bearer claim).
// -----------------------------------------------------------------------------

func TestSearchTenantMembers_401_MissingTenantContext(t *testing.T) {
	repo := &stubSearchRepo{}
	h := newTestSearchHandler(repo)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/tenant-members", nil)
	// No mesh headers, no bearer. The handler MUST reject 401 (or 400 —
	// either is fine; we just verify auth-context-required is enforced).
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized && rr.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 401 or 400 (no tenant context)", rr.Code)
	}
	if repo.gotQuery.TenantID != "" {
		t.Error("repo invoked despite missing tenant context")
	}
}

// -----------------------------------------------------------------------------
// 405 — non-GET methods
// -----------------------------------------------------------------------------

func TestSearchTenantMembers_405_NonGET(t *testing.T) {
	repo := &stubSearchRepo{}
	h := newTestSearchHandler(repo)

	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		rr := httptest.NewRecorder()
		req := authedRequest(m, "/api/v1/admin/tenant-members", []string{"TENANT_ADMIN"})
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: got %d want 405", m, rr.Code)
		}
	}
}

// -----------------------------------------------------------------------------
// Pagination — HasMore propagates to next_page_token; absent at end of list.
// -----------------------------------------------------------------------------

func TestSearchTenantMembers_NextPageToken_PresentWhenHasMore(t *testing.T) {
	repo := &stubSearchRepo{
		result: identity.TenantMemberSearchResult{
			Items:      []identity.TenantMemberSummary{phyllisSummary(t)},
			HasMore:    true,
			NextOffset: 20,
		},
	}
	h := newTestSearchHandler(repo)

	rr := httptest.NewRecorder()
	req := authedRequest(http.MethodGet, "/api/v1/admin/tenant-members", []string{"TENANT_ADMIN"})
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}

	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	tok, ok := body["next_page_token"].(string)
	if !ok || tok == "" {
		t.Fatalf("next_page_token: got %v want non-empty", body["next_page_token"])
	}
	// Decode to verify the offset round-trips.
	decoded, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	if !strings.Contains(string(decoded), "20") {
		t.Errorf("token offset: got %q want contains '20'", string(decoded))
	}
}

func TestSearchTenantMembers_NextPageToken_NilAtEndOfList(t *testing.T) {
	repo := &stubSearchRepo{
		result: identity.TenantMemberSearchResult{
			Items:   []identity.TenantMemberSummary{phyllisSummary(t)},
			HasMore: false,
		},
	}
	h := newTestSearchHandler(repo)

	rr := httptest.NewRecorder()
	req := authedRequest(http.MethodGet, "/api/v1/admin/tenant-members", []string{"TENANT_ADMIN"})
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status: %d", rr.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	// next_page_token MUST be nil (JSON null) at end of list per contract.
	tok, exists := body["next_page_token"]
	if exists && tok != nil {
		t.Errorf("next_page_token: got %v want nil", tok)
	}
}

// -----------------------------------------------------------------------------
// Pagination — caller-supplied page_token decodes into offset
// -----------------------------------------------------------------------------

func TestSearchTenantMembers_PageTokenDecodes(t *testing.T) {
	repo := &stubSearchRepo{}
	h := newTestSearchHandler(repo)

	// Pre-encode an offset=20 token using the same scheme the handler emits.
	tok := base64.RawURLEncoding.EncodeToString([]byte("offset:20"))
	url := fmt.Sprintf("/api/v1/admin/tenant-members?page_token=%s", tok)

	rr := httptest.NewRecorder()
	req := authedRequest(http.MethodGet, url, []string{"TENANT_ADMIN"})
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status: %d", rr.Code)
	}
	if repo.gotQuery.Offset != 20 {
		t.Errorf("offset: got %d want 20", repo.gotQuery.Offset)
	}
}

func TestSearchTenantMembers_BadPageToken_422(t *testing.T) {
	repo := &stubSearchRepo{}
	h := newTestSearchHandler(repo)

	rr := httptest.NewRecorder()
	req := authedRequest(http.MethodGet, "/api/v1/admin/tenant-members?page_token=$$$", []string{"TENANT_ADMIN"})
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("status: got %d want 422 (malformed page_token)", rr.Code)
	}
}

// -----------------------------------------------------------------------------
// Repo errors → 500
// -----------------------------------------------------------------------------

func TestSearchTenantMembers_RepoError_500(t *testing.T) {
	repo := &stubSearchRepo{err: errors.New("db unreachable")}
	h := newTestSearchHandler(repo)

	rr := httptest.NewRecorder()
	req := authedRequest(http.MethodGet, "/api/v1/admin/tenant-members", []string{"TENANT_ADMIN"})
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status: got %d want 500", rr.Code)
	}
}

// -----------------------------------------------------------------------------
// PageSize valid enums — explicit accept-list (10, 20, 50, 100)
// -----------------------------------------------------------------------------

func TestSearchTenantMembers_AcceptsAllValidPageSizes(t *testing.T) {
	repo := &stubSearchRepo{result: identity.TenantMemberSearchResult{}}
	h := newTestSearchHandler(repo)
	for _, ps := range []int{10, 20, 50, 100} {
		rr := httptest.NewRecorder()
		url := fmt.Sprintf("/api/v1/admin/tenant-members?page_size=%d", ps)
		req := authedRequest(http.MethodGet, url, []string{"TENANT_ADMIN"})
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("page_size=%d: got %d want 200", ps, rr.Code)
		}
		if repo.gotQuery.PageSize != ps {
			t.Errorf("page_size=%d propagated as %d", ps, repo.gotQuery.PageSize)
		}
	}
}

// -----------------------------------------------------------------------------
// Valid role enums — all 6 per contract
// -----------------------------------------------------------------------------

func TestSearchTenantMembers_AcceptsAllValidRoles(t *testing.T) {
	repo := &stubSearchRepo{result: identity.TenantMemberSearchResult{}}
	h := newTestSearchHandler(repo)
	for _, role := range []string{"LEARNER", "INSTRUCTOR", "ADMIN", "AUDITOR", "OWNER", "SUPPORT_AGENT"} {
		rr := httptest.NewRecorder()
		url := "/api/v1/admin/tenant-members?role=" + role
		req := authedRequest(http.MethodGet, url, []string{"TENANT_ADMIN"})
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("role=%s: got %d want 200", role, rr.Code)
		}
	}
}

// -----------------------------------------------------------------------------
// OWNER administers members (L1 CHO-1705 walk-caught)
// -----------------------------------------------------------------------------

// The bootstrap owner's minted JWT carries roles=["owner"] only (OWNER is
// JWT-only; the membership mirror row lags via Pub/Sub). The tenant owner
// MUST clear the members admin gate or a fresh tenant cannot be
// administered at all.
func TestSearchTenantMembers_OwnerRoleAllowed(t *testing.T) {
	for _, roles := range [][]string{{"OWNER"}, {"owner"}} {
		repo := &stubSearchRepo{}
		h := newTestSearchHandler(repo)

		rr := httptest.NewRecorder()
		req := authedRequest(http.MethodGet, "/api/v1/admin/tenant-members", roles)
		h.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("roles %v: got %d want 200 (owner must administer members)", roles, rr.Code)
		}
	}
}

// -----------------------------------------------------------------------------
// S4 (CHO-2000 / CHO-1930) — operator cross-tenant learner-directory read.
// A PLATFORM_OPERATOR targeting ?managed_tenant_id=<uuid> reads THAT
// franchisee's members (RLS enforced via RunInTenantTx(target)), audited
// fail-closed BEFORE the read. Design A per the recon (reuses the blessed
// grant-handler authorization pattern; NOT a new RLS-bypass surface).
// -----------------------------------------------------------------------------

// Operator + managed_tenant_id → the read is scoped to the TARGET tenant
// (the param wins over the operator's mesh tenant header), and the IMDA-D1
// cross-tenant evidence fires exactly once carrying operator + target context.
func TestSearchTenantMembers_Operator_TargetsFranchisee(t *testing.T) {
	repo := &stubSearchRepo{result: identity.TenantMemberSearchResult{
		Items: []identity.TenantMemberSummary{phyllisSummary(t)},
	}}
	audit := &recordingAudit{}
	h := NewSearchTenantMembersHandler(repo, audit)

	rr := httptest.NewRecorder()
	req := operatorRequest(http.MethodGet,
		"/api/v1/admin/tenant-members?role=learner&q=dale&managed_tenant_id="+managedTenantID)
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	// The read MUST target the franchisee param, NOT the operator's mesh tenant.
	if repo.gotQuery.TenantID != managedTenantID {
		t.Errorf("repo tenant: got %q want franchisee %q (param must win over mesh header %q)",
			repo.gotQuery.TenantID, managedTenantID, testTenantID)
	}
	if repo.gotQuery.Role != "learner" {
		t.Errorf("repo role: got %q want learner", repo.gotQuery.Role)
	}
	if repo.gotQuery.Q != "dale" {
		t.Errorf("repo q: got %q want dale", repo.gotQuery.Q)
	}
	// IMDA-D1 cross-tenant evidence MUST have fired exactly once.
	if len(audit.calls) != 1 {
		t.Fatalf("audit calls: got %d want 1", len(audit.calls))
	}
	in := audit.calls[0]
	if in.EvidenceType == "" {
		t.Error("audit evidence_type is empty")
	}
	if in.AdditionalFields["target_tenant_id"] != managedTenantID {
		t.Errorf("audit target_tenant_id: got %v want %q", in.AdditionalFields["target_tenant_id"], managedTenantID)
	}
	if in.AdditionalFields["operator_gcid"] != testGCID {
		t.Errorf("audit operator_gcid: got %v want %q", in.AdditionalFields["operator_gcid"], testGCID)
	}
	if in.AdditionalFields["cross_tenant"] != true {
		t.Errorf("audit cross_tenant: got %v want true", in.AdditionalFields["cross_tenant"])
	}
	// Evidence is attributed to the tenant being VIEWED + the operator actor.
	if len(audit.envs) != 1 || audit.envs[0].TenantID != managedTenantID || audit.envs[0].GCID != testGCID {
		t.Errorf("audit envelope: got %+v want tenant=%q gcid=%q", audit.envs, managedTenantID, testGCID)
	}
}

// Fail-closed: if the pre-read audit emit fails, the cross-tenant read MUST be
// aborted (500) — no un-audited PII access. The repo is never called.
func TestSearchTenantMembers_Operator_AuditFailClosed_500(t *testing.T) {
	repo := &stubSearchRepo{result: identity.TenantMemberSearchResult{
		Items: []identity.TenantMemberSummary{phyllisSummary(t)},
	}}
	audit := &recordingAudit{err: errors.New("pubsub down")}
	h := NewSearchTenantMembersHandler(repo, audit)

	rr := httptest.NewRecorder()
	req := operatorRequest(http.MethodGet,
		"/api/v1/admin/tenant-members?managed_tenant_id="+managedTenantID)
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d want 500 (audit failure must abort the read)", rr.Code)
	}
	if repo.gotQuery.TenantID != "" {
		t.Error("repo invoked despite audit failure — cross-tenant read NOT fail-closed")
	}
}

// A non-operator (tenant admin) MUST NOT be able to target another tenant via
// managed_tenant_id — 403, and the repo is never called.
func TestSearchTenantMembers_NonOperator_FranchiseeParam_403(t *testing.T) {
	repo := &stubSearchRepo{}
	h := newTestSearchHandler(repo)

	rr := httptest.NewRecorder()
	req := authedRequest(http.MethodGet,
		"/api/v1/admin/tenant-members?managed_tenant_id="+managedTenantID,
		[]string{"TENANT_ADMIN"})
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status: got %d want 403 (non-operator cannot target a franchisee)", rr.Code)
	}
	if repo.gotQuery.TenantID != "" {
		t.Error("repo invoked for a non-operator cross-tenant attempt")
	}
}

// Operator + malformed managed_tenant_id → 422; the read + audit never run.
func TestSearchTenantMembers_Operator_InvalidFranchiseeUUID_422(t *testing.T) {
	repo := &stubSearchRepo{}
	audit := &recordingAudit{}
	h := NewSearchTenantMembersHandler(repo, audit)

	rr := httptest.NewRecorder()
	req := operatorRequest(http.MethodGet,
		"/api/v1/admin/tenant-members?managed_tenant_id=not-a-uuid")
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status: got %d want 422 (malformed managed_tenant_id)", rr.Code)
	}
	if repo.gotQuery.TenantID != "" {
		t.Error("repo invoked despite invalid managed_tenant_id")
	}
	if len(audit.calls) != 0 {
		t.Error("audit fired despite invalid managed_tenant_id (must validate first)")
	}
}
