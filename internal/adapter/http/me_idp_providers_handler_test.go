// me_idp_providers_handler_test.go — RED-phase tests for the Setup Wizard
// Phase C HTTP handler (CHO-1682) exposing
// POST /api/v1/tenants/me/idp-providers.
//
// Strict TDD per .claude/rules/development-execution.md: this file is
// written BEFORE me_idp_providers_handler.go exists. Compile must fail
// with "undefined: httpadapter.NewMeIdpProvidersHandler" — that's the
// observed RED.
//
// Drives the handler through `httptest` against fake Repository +
// SecretManager + EventPublisher implementations of the domain ports.
// The handler stays out of domain plumbing; it's the thin HTTP shell on
// top of `tenant_idp_provider.Service`.
package httpadapter_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	httpadapter "github.com/apollo-chora/chora-identity/internal/adapter/http"
	tip "github.com/apollo-chora/chora-identity/internal/domain/tenant_idp_provider"
)

// ---------------------------------------------------------------------------
// Fakes — minimal in-memory implementations of the domain ports.
// ---------------------------------------------------------------------------

type fakeRepo struct {
	mu        sync.Mutex
	rows      map[string]*tip.TenantIdpProvider // (tenant|type) → row
	upsertErr error
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{rows: map[string]*tip.TenantIdpProvider{}}
}

func (r *fakeRepo) Upsert(_ context.Context, p *tip.TenantIdpProvider) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.upsertErr != nil {
		return r.upsertErr
	}
	r.rows[p.TenantID+"|"+string(p.ProviderType)] = p
	return nil
}

func (r *fakeRepo) Get(_ context.Context, tenantID string, pt tip.ProviderType) (*tip.TenantIdpProvider, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.rows[tenantID+"|"+string(pt)]
	if !ok || v.DeletedAt != nil {
		return nil, tip.ErrNotFound
	}
	clone := *v
	return &clone, nil
}

func (r *fakeRepo) ListByTenant(_ context.Context, tenantID string) ([]tip.TenantIdpProvider, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]tip.TenantIdpProvider, 0)
	for _, v := range r.rows {
		if v.TenantID == tenantID && v.DeletedAt == nil {
			out = append(out, *v)
		}
	}
	return out, nil
}

func (r *fakeRepo) SoftDelete(_ context.Context, tenantID string, pt tip.ProviderType, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.rows[tenantID+"|"+string(pt)]
	if !ok {
		return tip.ErrNotFound
	}
	t := now
	v.DeletedAt = &t
	return nil
}

func (r *fakeRepo) rowCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.rows)
}

type fakeSecretManager struct {
	mu       sync.Mutex
	storeErr error
	calls    int
}

func (s *fakeSecretManager) Store(_ context.Context, tenantID, idpID, _ string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.storeErr != nil {
		return "", s.storeErr
	}
	return "projects/chora-local/secrets/idp-client-secret-" + tenantID + "-" + idpID, nil
}

type fakePublisher struct {
	mu     sync.Mutex
	events []tip.PublishedEvent
	err    error
}

func (p *fakePublisher) Publish(_ context.Context, evt tip.PublishedEvent) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return p.err
	}
	p.events = append(p.events, evt)
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newHandler(t *testing.T) (http.Handler, *fakeRepo, *fakeSecretManager, *fakePublisher) {
	t.Helper()
	repo := newFakeRepo()
	sm := &fakeSecretManager{}
	pub := &fakePublisher{}
	svc := tip.NewService(repo, sm, pub)
	h := httpadapter.NewMeIdpProvidersHandler(svc)
	return h, repo, sm, pub
}

func doPost(t *testing.T, h http.Handler, headers map[string]string, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/me/idp-providers", strings.NewReader(body))
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

const (
	tipTenantA = "01970000-0000-7000-8000-00000000000a"
	tipGcidA   = "01935f12-0000-7000-8000-0000000000ff"
)

// ---------------------------------------------------------------------------
// Happy path — OIDC
// ---------------------------------------------------------------------------

func TestMeIdp_POST_OIDC_HappyPath(t *testing.T) {
	t.Parallel()
	h, repo, sm, pub := newHandler(t)
	w := doPost(t, h, map[string]string{
		"X-Tenant-Id": tenantA,
		"gcid":        gcidA,
	}, `{"provider_type":"oidc","client_id":"client-acme","client_secret":"shhh","discovery_url":"https://issuer.example.com/.well-known/openid-configuration"}`)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200; body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		ID               string `json:"id"`
		TenantID         string `json:"tenant_id"`
		ProviderType     string `json:"provider_type"`
		ClientID         string `json:"client_id"`
		ClientSecret     string `json:"client_secret"`
		ClientSecretName string `json:"client_secret_name"`
		DiscoveryURL     string `json:"discovery_url"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v; body=%s", err, w.Body.String())
	}
	if resp.ID == "" {
		t.Error("missing id")
	}
	if resp.TenantID != tenantA {
		t.Errorf("tenant_id = %q; want %q", resp.TenantID, tenantA)
	}
	if resp.ProviderType != "oidc" {
		t.Errorf("provider_type = %q; want oidc", resp.ProviderType)
	}
	if resp.ClientID != "client-acme" {
		t.Errorf("client_id = %q", resp.ClientID)
	}
	if resp.ClientSecret != "" {
		t.Errorf("client_secret leaked in response: %q", resp.ClientSecret)
	}
	if !strings.HasPrefix(resp.ClientSecretName, "projects/") {
		t.Errorf("client_secret_name = %q; want Secret Manager resource name", resp.ClientSecretName)
	}
	if sm.calls != 1 {
		t.Errorf("SecretManager calls = %d; want 1", sm.calls)
	}
	if repo.rowCount() != 1 {
		t.Errorf("repo rows = %d; want 1", repo.rowCount())
	}
	if len(pub.events) != 1 {
		t.Errorf("publisher events = %d; want 1", len(pub.events))
	}
}

// ---------------------------------------------------------------------------
// Happy path — Singpass
// ---------------------------------------------------------------------------

func TestMeIdp_POST_Singpass_HappyPath(t *testing.T) {
	t.Parallel()
	h, _, sm, pub := newHandler(t)
	w := doPost(t, h, map[string]string{"X-Tenant-Id": tenantA, "gcid": gcidA},
		`{"provider_type":"singpass","singpass_enabled":true}`)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
	if sm.calls != 0 {
		t.Errorf("SecretManager called %d times; want 0 for singpass", sm.calls)
	}
	if len(pub.events) != 1 {
		t.Errorf("publisher events = %d; want 1", len(pub.events))
	}
}

// ---------------------------------------------------------------------------
// 400 — validation failures map to domain ErrInvalidInput
// ---------------------------------------------------------------------------

func TestMeIdp_POST_UnknownProviderType_400(t *testing.T) {
	t.Parallel()
	h, _, _, _ := newHandler(t)
	w := doPost(t, h, map[string]string{"X-Tenant-Id": tenantA, "gcid": gcidA},
		`{"provider_type":"definitely-not-a-real-type"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestMeIdp_POST_OIDCMissingClientID_400(t *testing.T) {
	t.Parallel()
	h, _, _, _ := newHandler(t)
	w := doPost(t, h, map[string]string{"X-Tenant-Id": tenantA, "gcid": gcidA},
		`{"provider_type":"oidc","client_secret":"s","discovery_url":"https://x.example/openid"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestMeIdp_POST_SingpassWithClientSecret_400(t *testing.T) {
	t.Parallel()
	h, _, _, _ := newHandler(t)
	w := doPost(t, h, map[string]string{"X-Tenant-Id": tenantA, "gcid": gcidA},
		`{"provider_type":"singpass","client_secret":"should-be-rejected","singpass_enabled":true}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestMeIdp_POST_MalformedJSON_400(t *testing.T) {
	t.Parallel()
	h, _, _, _ := newHandler(t)
	w := doPost(t, h, map[string]string{"X-Tenant-Id": tenantA, "gcid": gcidA},
		`{"provider_type":`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// 401 — missing X-Tenant-Id or gcid
// ---------------------------------------------------------------------------

func TestMeIdp_POST_MissingTenantHeader_401(t *testing.T) {
	t.Parallel()
	h, _, _, _ := newHandler(t)
	w := doPost(t, h, map[string]string{"gcid": gcidA}, `{"provider_type":"singpass"}`)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401; body=%s", w.Code, w.Body.String())
	}
}

func TestMeIdp_POST_MissingGcidHeader_401(t *testing.T) {
	t.Parallel()
	h, _, _, _ := newHandler(t)
	w := doPost(t, h, map[string]string{"X-Tenant-Id": tenantA}, `{"provider_type":"singpass"}`)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401; body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// 502 — Secret Manager failure
// ---------------------------------------------------------------------------

func TestMeIdp_POST_SecretManagerFailure_502_NoDbRow(t *testing.T) {
	t.Parallel()
	h, repo, sm, pub := newHandler(t)
	sm.storeErr = errors.New("kaboom — Secret Manager unreachable")
	w := doPost(t, h, map[string]string{"X-Tenant-Id": tenantA, "gcid": gcidA},
		`{"provider_type":"oidc","client_id":"c","client_secret":"s","discovery_url":"https://x.example/openid"}`)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d; want 502; body=%s", w.Code, w.Body.String())
	}
	if repo.rowCount() != 0 {
		t.Errorf("DB row leaked on SM failure; rows=%d", repo.rowCount())
	}
	if len(pub.events) != 0 {
		t.Errorf("event leaked on SM failure; events=%d", len(pub.events))
	}
}

// ---------------------------------------------------------------------------
// GET — list active rows for the calling tenant (CHO-1692)
//
// The same path /api/v1/tenants/me/idp-providers serves BOTH:
//   - POST (CHO-1682): upsert one provider
//   - GET  (CHO-1692): list active providers (for wizard re-entry
//                       hydration; client_secret never returned)
//
// Hydration consumers MUST see an empty array (not 404) for tenants
// that haven't configured an IdP yet — a fresh wizard run is a normal
// state, not a missing resource.
// ---------------------------------------------------------------------------

func TestMeIdp_GET_HappyPath_ReturnsListWithoutClientSecret(t *testing.T) {
	t.Parallel()
	h, _, _, _ := newHandler(t)

	// Seed via the POST path so the row goes through the real Service +
	// SecretManager; the wire shape we'll read back must NOT include the
	// plaintext client_secret.
	seedW := doPost(t, h, map[string]string{"X-Tenant-Id": tenantA, "gcid": gcidA},
		`{"provider_type":"oidc","client_id":"acme","client_secret":"shhh","discovery_url":"https://issuer.example.com/.well-known/openid-configuration"}`)
	if seedW.Code != http.StatusOK {
		t.Fatalf("seed POST: status=%d body=%s", seedW.Code, seedW.Body.String())
	}

	// Now GET the list.
	r := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/me/idp-providers", nil)
	r.Header.Set("X-Tenant-Id", tenantA)
	r.Header.Set("gcid", gcidA)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d; want 200; body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Items []struct {
			ID               string `json:"id"`
			ProviderType     string `json:"provider_type"`
			ClientID         string `json:"client_id"`
			ClientSecret     string `json:"client_secret"` // MUST be absent
			ClientSecretName string `json:"client_secret_name"`
		} `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v; body=%s", err, w.Body.String())
	}
	if len(resp.Items) != 1 {
		t.Fatalf("items len = %d; want 1", len(resp.Items))
	}
	it := resp.Items[0]
	if it.ProviderType != "oidc" {
		t.Errorf("provider_type = %q; want oidc", it.ProviderType)
	}
	if it.ClientID != "acme" {
		t.Errorf("client_id = %q", it.ClientID)
	}
	if it.ClientSecret != "" {
		t.Errorf("client_secret leaked in response: %q", it.ClientSecret)
	}
	if !strings.HasPrefix(it.ClientSecretName, "projects/") {
		t.Errorf("client_secret_name not Secret Manager resource: %q", it.ClientSecretName)
	}
}

func TestMeIdp_GET_NoRows_ReturnsEmptyArray_Not404(t *testing.T) {
	t.Parallel()
	h, _, _, _ := newHandler(t)

	r := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/me/idp-providers", nil)
	r.Header.Set("X-Tenant-Id", "01970000-0000-7000-8000-no-rows-yet")
	r.Header.Set("gcid", gcidA)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	// A fresh tenant with NO IdP rows must return 200 + empty list, not 404.
	// Wizard hydration relies on this: an empty IdP list is a normal pre-
	// configuration state, not a missing resource.
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d; want 200 on empty tenant; body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Items) != 0 {
		t.Errorf("items = %d; want 0", len(resp.Items))
	}
}

func TestMeIdp_GET_MissingTenantHeader_401(t *testing.T) {
	t.Parallel()
	h, _, _, _ := newHandler(t)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/me/idp-providers", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d; want 401", w.Code)
	}
}

// ---------------------------------------------------------------------------
// Method gate — anything other than GET or POST is 405
// ---------------------------------------------------------------------------

func TestMeIdp_PATCH_405(t *testing.T) {
	t.Parallel()
	h, _, _, _ := newHandler(t)
	r := httptest.NewRequest(http.MethodPatch, "/api/v1/tenants/me/idp-providers", nil)
	r.Header.Set("X-Tenant-Id", tenantA)
	r.Header.Set("gcid", gcidA)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d; want 405", w.Code)
	}
}

// ---------------------------------------------------------------------------
// CHO-1694 — DELETE /api/v1/tenants/me/idp-providers/{providerType}
// Soft-deletes the row for the calling tenant + provider_type. Backs
// the H+ IdP Federation page's Disconnect CTA.
// ---------------------------------------------------------------------------

// Helper: POST a seed row, then DELETE it, then GET to assert the soft-delete
// removed it from the active list.
func TestMeIdp_DELETE_HappyPath_SoftDeletesRow(t *testing.T) {
	t.Parallel()
	h, repo, _, _ := newHandler(t)

	// Seed: POST an OIDC config.
	w := doPost(t, h, map[string]string{
		"X-Tenant-Id": tenantA,
		"gcid":        gcidA,
	}, `{"provider_type":"oidc","client_id":"acme","client_secret":"shhh","discovery_url":"https://issuer.example.com/.well-known/openid-configuration"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("seed POST status=%d; want 200; body=%s", w.Code, w.Body.String())
	}
	if repo.rowCount() != 1 {
		t.Fatalf("seed: repo rows = %d; want 1", repo.rowCount())
	}

	// DELETE the row.
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/tenants/me/idp-providers/oidc", nil)
	r.Header.Set("X-Tenant-Id", tenantA)
	r.Header.Set("gcid", gcidA)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE status=%d; want 204; body=%s", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() != 0 {
		t.Errorf("DELETE response should have empty body; got %q", rec.Body.String())
	}

	// Subsequent GET must show the row gone.
	rGet := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/me/idp-providers", nil)
	rGet.Header.Set("X-Tenant-Id", tenantA)
	rGet.Header.Set("gcid", gcidA)
	wGet := httptest.NewRecorder()
	h.ServeHTTP(wGet, rGet)
	if wGet.Code != http.StatusOK {
		t.Fatalf("GET after DELETE: status=%d; want 200; body=%s", wGet.Code, wGet.Body.String())
	}
	if !strings.Contains(wGet.Body.String(), `"items":[]`) {
		t.Errorf("GET after DELETE: body=%s; want items:[]", wGet.Body.String())
	}
}

// 404 when no row exists for the (tenant, provider_type) pair.
func TestMeIdp_DELETE_NoRow_404(t *testing.T) {
	t.Parallel()
	h, _, _, _ := newHandler(t)

	r := httptest.NewRequest(http.MethodDelete, "/api/v1/tenants/me/idp-providers/oidc", nil)
	r.Header.Set("X-Tenant-Id", tenantA)
	r.Header.Set("gcid", gcidA)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status=%d; want 404 on missing row; body=%s", w.Code, w.Body.String())
	}
}

// 401 when X-Tenant-Id is missing.
func TestMeIdp_DELETE_MissingTenantHeader_401(t *testing.T) {
	t.Parallel()
	h, _, _, _ := newHandler(t)

	r := httptest.NewRequest(http.MethodDelete, "/api/v1/tenants/me/idp-providers/oidc", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d; want 401; body=%s", w.Code, w.Body.String())
	}
}

// 400 when the provider_type segment is empty or unknown.
func TestMeIdp_DELETE_UnknownProviderType_400(t *testing.T) {
	t.Parallel()
	h, _, _, _ := newHandler(t)

	r := httptest.NewRequest(http.MethodDelete, "/api/v1/tenants/me/idp-providers/bogus", nil)
	r.Header.Set("X-Tenant-Id", tenantA)
	r.Header.Set("gcid", gcidA)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d; want 400; body=%s", w.Code, w.Body.String())
	}
}

// 400 when provider_type segment is missing (path ends with /idp-providers/).
func TestMeIdp_DELETE_MissingProviderType_400(t *testing.T) {
	t.Parallel()
	h, _, _, _ := newHandler(t)

	r := httptest.NewRequest(http.MethodDelete, "/api/v1/tenants/me/idp-providers/", nil)
	r.Header.Set("X-Tenant-Id", tenantA)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d; want 400 on missing provider_type segment; body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Constructor safety
// ---------------------------------------------------------------------------

func TestNewMeIdpProvidersHandler_NilSvc_Panics(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on nil service")
		}
	}()
	_ = httpadapter.NewMeIdpProvidersHandler(nil)
}
