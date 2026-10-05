package httpadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/apollo-chora/chora-identity/internal/adapter/apikey_events"
	"github.com/apollo-chora/chora-identity/internal/adapter/apikey_inmem"
	"github.com/apollo-chora/chora-identity/internal/adapter/events"
	"github.com/apollo-chora/chora-identity/internal/domain/apikey"
)

// fixedHasher returns a deterministic plaintext + hash for handler tests.
type fixedHasher struct{}

func (fixedHasher) Generate() (string, error) {
	return "sk_" + "live_test1234567890abcdef1234567890ab", nil
}
func (fixedHasher) Hash(_ string) string { return "hashed-key" }

func newAPIKeyTestServer(t *testing.T) (http.Handler, *events.Recorder, *apikey_inmem.Repository) {
	t.Helper()
	repo := apikey_inmem.NewRepository()
	rec := events.NewRecorder()
	pub := apikey_events.NewPublisher(rec, "00-00000000000000000000000000000000-0000000000000000-01", "")
	svc := apikey.NewService(repo, fixedHasher{}, pub)
	return NewAPIKeyRouter(svc), rec, repo
}

func TestAPIKeyHandler_Create_201(t *testing.T) {
	t.Parallel()
	srv, rec, _ := newAPIKeyTestServer(t)

	body := map[string]any{
		"name":   "My CLI Key",
		"scopes": []string{"read", "write"},
	}
	buf, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/identity/api-keys", bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-Id", "01970000-0000-7000-8000-000000000001")
	req.Header.Set("gcid", "01975555-0000-7000-8000-000000000001")

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d (%s)", w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("body parse: %v (%s)", err, w.Body.String())
	}
	if got["plaintext"] != "sk_"+"live_test1234567890abcdef1234567890ab" {
		t.Fatalf("plaintext missing/changed: %v", got["plaintext"])
	}
	keyObj, ok := got["api_key"].(map[string]any)
	if !ok {
		t.Fatalf("api_key obj missing: %+v", got)
	}
	if keyObj["name"] != "My CLI Key" {
		t.Fatalf("name = %v", keyObj["name"])
	}
	if _, ok := keyObj["id"].(string); !ok {
		t.Fatalf("id missing")
	}
	// Event emitted on chora.identity.api_key.created.v1.
	if len(rec.RecordedByTopic(apikey.TopicCreated)) != 1 {
		t.Fatalf("expected 1 created event; got %d", len(rec.RecordedByTopic(apikey.TopicCreated)))
	}
}

func TestAPIKeyHandler_Create_RejectsAGID_400(t *testing.T) {
	t.Parallel()
	srv, _, _ := newAPIKeyTestServer(t)

	buf, _ := json.Marshal(map[string]any{"name": "agent-key"})
	req := httptest.NewRequest(http.MethodPost, "/api/identity/api-keys", bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-Id", "01970000-0000-7000-8000-000000000001")
	req.Header.Set("gcid", "0197a000-0000-7000-8000-000000000001") // AGID-shape

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400 (body %s)", w.Code, w.Body.String())
	}
}

func TestAPIKeyHandler_Create_MissingHeaders_400(t *testing.T) {
	t.Parallel()
	srv, _, _ := newAPIKeyTestServer(t)

	buf, _ := json.Marshal(map[string]any{"name": "x"})
	req := httptest.NewRequest(http.MethodPost, "/api/identity/api-keys", bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	// No X-Tenant-Id, no gcid.

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400", w.Code)
	}
}

func TestAPIKeyHandler_List_200(t *testing.T) {
	t.Parallel()
	srv, _, repo := newAPIKeyTestServer(t)

	// Seed two keys for the same gcid.
	gcid := "01975555-0000-7000-8000-000000000001"
	tenant := "01970000-0000-7000-8000-000000000001"
	for i := 0; i < 2; i++ {
		buf, _ := json.Marshal(map[string]any{"name": "Key"})
		req := httptest.NewRequest(http.MethodPost, "/api/identity/api-keys", bytes.NewReader(buf))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Tenant-Id", tenant)
		req.Header.Set("gcid", gcid)
		srv.ServeHTTP(httptest.NewRecorder(), req)
	}

	// Sanity — repo holds 2 keys for the gcid.
	got, err := repo.ListByGcid(context.Background(), gcid)
	if err != nil || len(got) != 2 {
		t.Fatalf("seed failed: err=%v len=%d", err, len(got))
	}

	req := httptest.NewRequest(http.MethodGet, "/api/identity/api-keys", nil)
	req.Header.Set("X-Tenant-Id", tenant)
	req.Header.Set("gcid", gcid)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", w.Code, w.Body.String())
	}
	var listResp struct {
		APIKeys []map[string]any `json:"api_keys"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("body parse: %v", err)
	}
	if len(listResp.APIKeys) != 2 {
		t.Fatalf("expected 2 api_keys; got %d", len(listResp.APIKeys))
	}
}

func TestAPIKeyHandler_Revoke_204(t *testing.T) {
	t.Parallel()
	srv, rec, _ := newAPIKeyTestServer(t)

	// Create the key.
	buf, _ := json.Marshal(map[string]any{"name": "Doomed"})
	req := httptest.NewRequest(http.MethodPost, "/api/identity/api-keys", bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-Id", "01970000-0000-7000-8000-000000000001")
	req.Header.Set("gcid", "01975555-0000-7000-8000-000000000001")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	var createResp struct {
		APIKey struct {
			ID string `json:"id"`
		} `json:"api_key"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("create body: %v", err)
	}
	if createResp.APIKey.ID == "" {
		t.Fatalf("missing id in create response")
	}

	// Revoke.
	revReq := httptest.NewRequest(http.MethodDelete, "/api/identity/api-keys/"+createResp.APIKey.ID, nil)
	revReq.Header.Set("X-Tenant-Id", "01970000-0000-7000-8000-000000000001")
	revReq.Header.Set("gcid", "01975555-0000-7000-8000-000000000001")
	revW := httptest.NewRecorder()
	srv.ServeHTTP(revW, revReq)
	if revW.Code != http.StatusNoContent {
		t.Fatalf("revoke status = %d (%s)", revW.Code, revW.Body.String())
	}
	// Event on chora.identity.api_key.revoked.v1.
	if len(rec.RecordedByTopic(apikey.TopicRevoked)) != 1 {
		t.Fatalf("expected 1 revoked event; got %d", len(rec.RecordedByTopic(apikey.TopicRevoked)))
	}
}

func TestAPIKeyHandler_Revoke_NotFound_404(t *testing.T) {
	t.Parallel()
	srv, _, _ := newAPIKeyTestServer(t)

	req := httptest.NewRequest(http.MethodDelete, "/api/identity/api-keys/01975555-0000-7000-9000-000000000099", nil)
	req.Header.Set("X-Tenant-Id", "01970000-0000-7000-8000-000000000001")
	req.Header.Set("gcid", "01975555-0000-7000-8000-000000000001")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d (%s)", w.Code, w.Body.String())
	}
}

func TestAPIKeyHandler_ContentType_AlwaysJSON(t *testing.T) {
	t.Parallel()
	srv, _, _ := newAPIKeyTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/identity/api-keys", nil)
	req.Header.Set("X-Tenant-Id", "01970000-0000-7000-8000-000000000001")
	req.Header.Set("gcid", "01975555-0000-7000-8000-000000000001")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("expected JSON content-type; got %q", w.Header().Get("Content-Type"))
	}
}
