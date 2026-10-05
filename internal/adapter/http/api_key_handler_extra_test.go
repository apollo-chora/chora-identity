// api_key_handler_extra_test.go — coverage completion for api_key_handler.go:
// error branches (invalid JSON, missing name, repo save/revoke/list errors),
// dispatch routing (405/400), and the requireTenantAndGcid missing-gcid path.
package httpadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/apollo-chora/chora-identity/internal/adapter/apikey_events"
	"github.com/apollo-chora/chora-identity/internal/adapter/events"
	"github.com/apollo-chora/chora-identity/internal/domain/apikey"
)

const (
	akxTenant = "01970000-0000-7000-8000-0000000000ee"
	akxGcid   = "01975555-0000-7000-8000-0000000000ee"
)

// akxStubRepo is an apikey.Repository fake with injectable per-operation
// errors + a nil-list mode (to exercise the handler's empty-slice fallback).
type akxStubRepo struct {
	listErr    error
	saveErr    error
	revokeErr  error
	listNil    bool
	listActive int // when > 0, ListByGcid yields that many active APIKeys
}

func (r *akxStubRepo) ListByGcid(_ context.Context, _ string) ([]apikey.APIKey, error) {
	if r.listErr != nil {
		return nil, r.listErr
	}
	if r.listNil {
		return nil, nil
	}
	if r.listActive > 0 {
		out := make([]apikey.APIKey, r.listActive)
		for i := range out {
			out[i] = apikey.APIKey{ID: "01975555-0000-7000-8000-0000000000f" + string(rune('0'+i))}
		}
		return out, nil
	}
	return []apikey.APIKey{}, nil
}

func (r *akxStubRepo) Save(_ context.Context, _ *apikey.APIKey) error { return r.saveErr }

func (r *akxStubRepo) Revoke(_ context.Context, _ string) error { return r.revokeErr }

// akxRouter builds the api-key router on a caller-supplied repository (reuses
// the shared fixedHasher + an events.Recorder-bound publisher).
func akxRouter(repo apikey.Repository) http.Handler {
	rec := events.NewRecorder()
	pub := apikey_events.NewPublisher(rec, "00-00000000000000000000000000000000-0000000000000000-01", "")
	svc := apikey.NewService(repo, fixedHasher{}, pub)
	return NewAPIKeyRouter(svc)
}

// akxReq is the standard create/list/revoke request with tenant + gcid headers.
func akxReq(method, path string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	r.Header.Set("X-Tenant-Id", akxTenant)
	r.Header.Set("gcid", akxGcid)
	return r
}

func TestAPIKeyHandlerCreate_MalformedJSON_400(t *testing.T) {
	t.Parallel()
	srv := akxRouter(&akxStubRepo{})

	req := httptest.NewRequest(http.MethodPost, "/api/identity/api-keys", strings.NewReader(`{"name":`))
	req.Header.Set("X-Tenant-Id", akxTenant)
	req.Header.Set("gcid", akxGcid)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400 (body %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "invalid_json") {
		t.Fatalf("body %q lacks invalid_json code", w.Body.String())
	}
}

func TestAPIKeyHandlerCreate_MissingName_400(t *testing.T) {
	t.Parallel()
	srv := akxRouter(&akxStubRepo{})

	buf, _ := json.Marshal(map[string]any{"scopes": []string{"read"}})
	req := httptest.NewRequest(http.MethodPost, "/api/identity/api-keys", bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-Id", akxTenant)
	req.Header.Set("gcid", akxGcid)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400 (body %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "missing_name") {
		t.Fatalf("body %q lacks missing_name code", w.Body.String())
	}
}

func TestAPIKeyHandlerCreate_SaveError_500(t *testing.T) {
	t.Parallel()
	srv := akxRouter(&akxStubRepo{saveErr: errors.New("save boom")})

	buf, _ := json.Marshal(map[string]any{"name": "doomed"})
	req := httptest.NewRequest(http.MethodPost, "/api/identity/api-keys", bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-Id", akxTenant)
	req.Header.Set("gcid", akxGcid)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d; want 500 (body %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "internal_error") {
		t.Fatalf("body %q lacks internal_error code", w.Body.String())
	}
}

func TestAPIKeyHandlerCreate_MissingGcid_400(t *testing.T) {
	t.Parallel()
	srv := akxRouter(&akxStubRepo{})

	buf, _ := json.Marshal(map[string]any{"name": "x"})
	req := httptest.NewRequest(http.MethodPost, "/api/identity/api-keys", bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-Id", akxTenant) // tenant present, gcid absent
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400 (body %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "missing_gcid") {
		t.Fatalf("body %q lacks missing_gcid code", w.Body.String())
	}
}

func TestAPIKeyHandlerCreate_MissingTenant_400(t *testing.T) {
	t.Parallel()
	srv := akxRouter(&akxStubRepo{})

	buf, _ := json.Marshal(map[string]any{"name": "x"})
	req := httptest.NewRequest(http.MethodPost, "/api/identity/api-keys", bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("gcid", akxGcid) // gcid present, tenant absent
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400 (body %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "missing_tenant") {
		t.Fatalf("body %q lacks missing_tenant code", w.Body.String())
	}
}

func TestAPIKeyHandlerList_RepoError_500(t *testing.T) {
	t.Parallel()
	srv := akxRouter(&akxStubRepo{listErr: errors.New("list boom")})

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, akxReq(http.MethodGet, "/api/identity/api-keys"))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d; want 500 (body %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "internal_error") {
		t.Fatalf("body %q lacks internal_error code", w.Body.String())
	}
}

func TestAPIKeyHandlerList_EmptyNilList_200(t *testing.T) {
	t.Parallel()
	srv := akxRouter(&akxStubRepo{listNil: true})

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, akxReq(http.MethodGet, "/api/identity/api-keys"))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200 (body %s)", w.Code, w.Body.String())
	}
	var got struct {
		APIKeys []map[string]any `json:"api_keys"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("body parse: %v (%s)", err, w.Body.String())
	}
	if got.APIKeys == nil || len(got.APIKeys) != 0 {
		t.Fatalf("expected empty non-nil api_keys slice; got %#v", got.APIKeys)
	}
}

func TestAPIKeyHandlerCollection_WrongMethod_405(t *testing.T) {
	t.Parallel()
	srv := akxRouter(&akxStubRepo{})

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, akxReq(http.MethodPut, "/api/identity/api-keys"))

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d; want 405 (body %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "method_not_allowed") {
		t.Fatalf("body %q lacks method_not_allowed code", w.Body.String())
	}
}

func TestAPIKeyHandlerItem_MissingID_400(t *testing.T) {
	t.Parallel()
	srv := akxRouter(&akxStubRepo{})

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, akxReq(http.MethodDelete, "/api/identity/api-keys/"))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400 (body %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "missing_id") {
		t.Fatalf("body %q lacks missing_id code", w.Body.String())
	}
}

func TestAPIKeyHandlerItem_WrongMethod_405(t *testing.T) {
	t.Parallel()
	srv := akxRouter(&akxStubRepo{})

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, akxReq(http.MethodGet, "/api/identity/api-keys/01975555-0000-7000-8000-0000000000ff"))

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d; want 405 (body %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "method_not_allowed") {
		t.Fatalf("body %q lacks method_not_allowed code", w.Body.String())
	}
}

func TestAPIKeyHandlerRevoke_RepoError_500(t *testing.T) {
	t.Parallel()
	srv := akxRouter(&akxStubRepo{revokeErr: errors.New("revoke boom")})

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, akxReq(http.MethodDelete, "/api/identity/api-keys/01975555-0000-7000-8000-0000000000ff"))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d; want 500 (body %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "internal_error") {
		t.Fatalf("body %q lacks internal_error code", w.Body.String())
	}
}

func TestAPIKeyHandlerCreate_LimitExceeded_429(t *testing.T) {
	t.Parallel()
	// The GCID already holds MaxActivePerGcid active keys → 429.
	srv := akxRouter(&akxStubRepo{listActive: apikey.MaxActivePerGcid})

	buf, _ := json.Marshal(map[string]any{"name": "overflow"})
	req := httptest.NewRequest(http.MethodPost, "/api/identity/api-keys", bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-Id", akxTenant)
	req.Header.Set("gcid", akxGcid)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d; want 429 (body %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "limit_exceeded") {
		t.Fatalf("body %q lacks limit_exceeded code", w.Body.String())
	}
}

func TestAPIKeyHandlerList_MissingHeaders_400(t *testing.T) {
	t.Parallel()
	srv := akxRouter(&akxStubRepo{})

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/identity/api-keys", nil))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400 (body %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "missing_tenant") {
		t.Fatalf("body %q lacks missing_tenant code", w.Body.String())
	}
}

func TestAPIKeyHandlerRevoke_MissingGcid_400(t *testing.T) {
	t.Parallel()
	srv := akxRouter(&akxStubRepo{})

	req := httptest.NewRequest(http.MethodDelete, "/api/identity/api-keys/01975555-0000-7000-8000-0000000000ff", nil)
	req.Header.Set("X-Tenant-Id", akxTenant) // gcid absent
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400 (body %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "missing_gcid") {
		t.Fatalf("body %q lacks missing_gcid code", w.Body.String())
	}
}
