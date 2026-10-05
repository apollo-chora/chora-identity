// API Key HTTP handler — exposes /api/identity/api-keys endpoints per M12.2.E.1.
//
// Route table:
//
//	POST   /api/identity/api-keys           -> Generate a new key (returns plaintext once)
//	GET    /api/identity/api-keys           -> List the caller's keys
//	DELETE /api/identity/api-keys/{id}      -> Revoke a key
//
// All endpoints require:
//   - X-Tenant-Id  : UUIDv7 tenant identifier
//   - gcid         : Global Chora ID of the requester (CLAUDE.md §1)
//
// Tracing: the existing chora-identity HTTPMiddleware (internal/observability)
// emits a span per request with attributes chora.tenant.id + chora.gcid. The
// API key handler does not add domain-specific span attributes here — span
// enrichment is mux-wide. Per-request publisher injection picks up the
// inbound traceparent so the emitted chora.identity.api_key.* events carry
// W3C trace context per ddd-enforcement.
package httpadapter

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/apollo-chora/chora-identity/internal/domain/apikey"
)

// APIKeyHandler is the apikey-domain HTTP adapter. The dependency-injected
// Service owns the in-memory (or pg) repository + the events.Publisher-bound
// outbox publisher.
type APIKeyHandler struct {
	svc *apikey.Service
}

// NewAPIKeyRouter wires the api-key sub-router. Compose into the main mux at
// cmd/server/main.go alongside the existing IdentityHandler.
func NewAPIKeyRouter(svc *apikey.Service) http.Handler {
	h := &APIKeyHandler{svc: svc}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/identity/api-keys", h.dispatchCollection)
	mux.HandleFunc("/api/identity/api-keys/", h.dispatchItem)
	return mux
}

// dispatchCollection routes POST / GET on the collection.
func (h *APIKeyHandler) dispatchCollection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.create(w, r)
	case http.MethodGet:
		h.list(w, r)
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	}
}

// dispatchItem routes DELETE on the item.
func (h *APIKeyHandler) dispatchItem(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/identity/api-keys/")
	id = strings.TrimSuffix(id, "/")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "missing_id", "api key id required")
		return
	}
	switch r.Method {
	case http.MethodDelete:
		h.revoke(w, r, id)
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	}
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

type createReq struct {
	Name      string     `json:"name"`
	Scopes    []string   `json:"scopes,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

func (h *APIKeyHandler) create(w http.ResponseWriter, r *http.Request) {
	tenant, gcid, ok := requireTenantAndGcid(w, r)
	if !ok {
		return
	}
	var body createReq
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil && !errors.Is(err, errEmptyBody) {
		writeJSONError(w, http.StatusBadRequest, "invalid_json", "invalid JSON body")
		return
	}
	if strings.TrimSpace(body.Name) == "" {
		writeJSONError(w, http.StatusBadRequest, "missing_name", "name required")
		return
	}

	key, plaintext, err := h.svc.Generate(r.Context(), apikey.GenerateInput{
		Gcid:      gcid,
		TenantID:  tenant,
		Name:      body.Name,
		Scopes:    body.Scopes,
		ExpiresAt: body.ExpiresAt,
	})
	if err != nil {
		switch {
		case errors.Is(err, apikey.ErrAGIDForbidden):
			writeJSONError(w, http.StatusBadRequest, "agid_forbidden", err.Error())
		case errors.Is(err, apikey.ErrLimitExceeded):
			writeJSONError(w, http.StatusTooManyRequests, "limit_exceeded", err.Error())
		case errors.Is(err, apikey.ErrInvalidInput):
			writeJSONError(w, http.StatusBadRequest, "invalid_input", err.Error())
		default:
			writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		}
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"api_key":   key,
		"plaintext": plaintext,
	})
}

func (h *APIKeyHandler) list(w http.ResponseWriter, r *http.Request) {
	_, gcid, ok := requireTenantAndGcid(w, r)
	if !ok {
		return
	}
	keys, err := h.svc.List(r.Context(), gcid)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	if keys == nil {
		keys = []apikey.APIKey{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"api_keys": keys})
}

func (h *APIKeyHandler) revoke(w http.ResponseWriter, r *http.Request, id string) {
	tenant, gcid, ok := requireTenantAndGcid(w, r)
	if !ok {
		return
	}
	err := h.svc.Revoke(r.Context(), apikey.RevokeInput{
		ID:       id,
		Gcid:     gcid,
		TenantID: tenant,
	})
	if err != nil {
		switch {
		case errors.Is(err, apikey.ErrNotFound):
			writeJSONError(w, http.StatusNotFound, "not_found", "api key not found")
		case errors.Is(err, apikey.ErrInvalidInput):
			writeJSONError(w, http.StatusBadRequest, "invalid_input", err.Error())
		default:
			writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Helpers (local to this file). Reuses writeJSON + writeError from handler.go.
// ---------------------------------------------------------------------------

var errEmptyBody = errors.New("apikey: empty body")

// writeJSONError is a tiny alias around writeError so the apikey handler keeps
// its descriptive naming while still using the canonical error envelope from
// handler.go.
func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	writeError(w, status, code, message)
}

func requireTenantAndGcid(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	tenant := strings.TrimSpace(r.Header.Get("X-Tenant-Id"))
	gcid := strings.TrimSpace(r.Header.Get("gcid"))
	if gcid == "" {
		gcid = strings.TrimSpace(r.Header.Get("X-Chora-GCID"))
	}
	if tenant == "" {
		writeJSONError(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-Id header required")
		return "", "", false
	}
	if gcid == "" {
		writeJSONError(w, http.StatusBadRequest, "missing_gcid", "gcid header required")
		return "", "", false
	}
	return tenant, gcid, true
}
