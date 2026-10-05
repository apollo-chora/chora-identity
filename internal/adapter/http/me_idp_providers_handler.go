// me_idp_providers_handler.go — Setup Wizard Phase C HTTP handler
// (CHO-1682).
//
// Implements POST /api/v1/tenants/me/idp-providers, the chora-identity
// half of the BFF aggregator's fan-out. Reads X-Tenant-Id + gcid stamped
// by the BFF after JWT validation, decodes the request body, calls the
// `tenant_idp_provider.Service`, and returns the persisted aggregate as
// JSON. `client_secret` is consumed (forwarded to the SecretManager
// adapter inside the Service) but NEVER echoed back in the response.
//
// Domain → HTTP status mapping:
//
//	tenant_idp_provider.ErrInvalidInput → 400 invalid_input
//	tenant_idp_provider.ErrNotFound      → 404 not_found  (theoretical;
//	                                       this handler is a single
//	                                       upsert path, so it doesn't
//	                                       actually fire today)
//	Secret Manager port failure          → 502 secret_manager_failed
//	missing X-Tenant-Id / gcid           → 401 gateway_unauthenticated
//	default                              → 500 internal_error
package httpadapter

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	tip "github.com/apollo-chora/chora-identity/internal/domain/tenant_idp_provider"
)

// MeIdpProvidersHandler serves POST /api/v1/tenants/me/idp-providers.
type MeIdpProvidersHandler struct {
	svc *tip.Service
}

// NewMeIdpProvidersHandler constructs the handler. Panics on nil service
// so wiring bugs fail loud at boot.
func NewMeIdpProvidersHandler(svc *tip.Service) *MeIdpProvidersHandler {
	if svc == nil {
		panic("httpadapter.NewMeIdpProvidersHandler: nil Service")
	}
	return &MeIdpProvidersHandler{svc: svc}
}

// meIdpUpsertRequest is the wire shape — mirrors
// chora-contracts/openapi/identity-admin.yaml::UpsertTenantIdpProviderRequest.
// `client_secret` is `writeOnly` on the contract.
type meIdpUpsertRequest struct {
	ProviderType    string `json:"provider_type"`
	ClientID        string `json:"client_id,omitempty"`
	ClientSecret    string `json:"client_secret,omitempty"`
	DiscoveryURL    string `json:"discovery_url,omitempty"`
	SingpassEnabled bool   `json:"singpass_enabled,omitempty"`
}

// meIdpProviderResponse mirrors
// chora-contracts/openapi/identity-admin.yaml::TenantIdpProviderResponse.
// NO `client_secret` field — the value lives in Secret Manager, referenced
// only by `client_secret_name`.
type meIdpProviderResponse struct {
	ID               string `json:"id"`
	TenantID         string `json:"tenant_id"`
	ProviderType     string `json:"provider_type"`
	ClientID         string `json:"client_id,omitempty"`
	ClientSecretName string `json:"client_secret_name,omitempty"`
	DiscoveryURL     string `json:"discovery_url,omitempty"`
	SingpassEnabled  bool   `json:"singpass_enabled"`
	CreatedAt        string `json:"created_at"`
	UpdatedAt        string `json:"updated_at"`
}

// meIdpProviderListResponse is the GET response envelope — mirrors
// chora-contracts/openapi/identity-admin.yaml::TenantIdpProviderListResponse.
// `items` is ALWAYS a non-nil array even when empty so the FE hydration
// path (CHO-1692) can iterate it without null-checks (a fresh tenant
// with no IdP rows is a normal pre-configuration state, not a missing
// resource).
type meIdpProviderListResponse struct {
	Items []meIdpProviderResponse `json:"items"`
}

// ServeHTTP dispatches:
//   - GET    /api/v1/tenants/me/idp-providers              (CHO-1692 list)
//   - POST   /api/v1/tenants/me/idp-providers              (CHO-1682 upsert)
//   - DELETE /api/v1/tenants/me/idp-providers/{providerType} (CHO-1694 soft-delete)
//
// The handler is mounted on BOTH the exact path AND the trailing-slash
// prefix path (see cmd/server/main.go) so a single ServeHTTP can route
// based on the URL plus method. Everything else returns 405.
const meIdpProvidersBasePath = "/api/v1/tenants/me/idp-providers"

func (h *MeIdpProvidersHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Sub-path requests (anything after the base path) are DELETE-only;
	// the {providerType} segment is parsed inside handleDelete.
	if strings.HasPrefix(r.URL.Path, meIdpProvidersBasePath+"/") {
		if r.Method != http.MethodDelete {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		h.handleDelete(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		h.handleGet(w, r)
	case http.MethodPost:
		h.handlePost(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	}
}

// handleDelete serves DELETE /api/v1/tenants/me/idp-providers/{providerType}
// (CHO-1694). Soft-deletes the row for the calling tenant + provider_type.
// 204 on success; 404 if no active row exists; 400 on missing/unknown
// provider_type segment; 401 on missing X-Tenant-Id.
func (h *MeIdpProvidersHandler) handleDelete(w http.ResponseWriter, r *http.Request) {
	tenantID := strings.TrimSpace(r.Header.Get("X-Tenant-Id"))
	if tenantID == "" {
		writeError(w, http.StatusUnauthorized, "gateway_unauthenticated",
			"caller tenant required (X-Tenant-Id header — chora-gateway stamps after JWT verify)")
		return
	}
	// Parse {providerType} from the URL — everything after the base path's
	// trailing slash, trimming any trailing slash for forgiveness on a
	// curl-style "/oidc/" call.
	segment := strings.TrimSuffix(
		strings.TrimPrefix(r.URL.Path, meIdpProvidersBasePath+"/"),
		"/",
	)
	if segment == "" || strings.Contains(segment, "/") {
		writeError(w, http.StatusBadRequest, "invalid_provider_type",
			"path must be /api/v1/tenants/me/idp-providers/{providerType}")
		return
	}
	if err := h.svc.SoftDelete(r.Context(), tenantID, tip.ProviderType(segment)); err != nil {
		switch {
		case errors.Is(err, tip.ErrInvalidInput):
			writeError(w, http.StatusBadRequest, "invalid_input", err.Error())
		case errors.Is(err, tip.ErrNotFound):
			writeError(w, http.StatusNotFound, "not_found",
				"no active idp-provider for the calling tenant + provider_type")
		default:
			writeError(w, http.StatusInternalServerError, "internal_error", err.Error())
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleGet serves GET /api/v1/tenants/me/idp-providers (CHO-1692).
// Returns 200 + an `items` array (possibly empty) for the calling
// tenant. `client_secret` is never on the aggregate; the wire is the
// same shape as POST's response minus the secret value.
func (h *MeIdpProvidersHandler) handleGet(w http.ResponseWriter, r *http.Request) {
	tenantID := strings.TrimSpace(r.Header.Get("X-Tenant-Id"))
	if tenantID == "" {
		writeError(w, http.StatusUnauthorized, "gateway_unauthenticated",
			"caller tenant required (X-Tenant-Id header — chora-gateway stamps after JWT verify)")
		return
	}
	// GET is read-only — no gcid required (production traffic always
	// carries it via the JWT gate; dev curl skips it).
	rows, err := h.svc.ListByTenant(r.Context(), tenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	items := make([]meIdpProviderResponse, 0, len(rows))
	for i := range rows {
		p := &rows[i]
		items = append(items, meIdpProviderResponse{
			ID:               p.ID,
			TenantID:         p.TenantID,
			ProviderType:     string(p.ProviderType),
			ClientID:         p.ClientID,
			ClientSecretName: p.ClientSecretName,
			DiscoveryURL:     p.DiscoveryURL,
			SingpassEnabled:  p.SingpassEnabled,
			CreatedAt:        p.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
			UpdatedAt:        p.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		})
	}
	writeJSON(w, http.StatusOK, meIdpProviderListResponse{Items: items})
}

// handlePost serves POST /api/v1/tenants/me/idp-providers (CHO-1682).
func (h *MeIdpProvidersHandler) handlePost(w http.ResponseWriter, r *http.Request) {
	tenantID := strings.TrimSpace(r.Header.Get("X-Tenant-Id"))
	if tenantID == "" {
		writeError(w, http.StatusUnauthorized, "gateway_unauthenticated",
			"caller tenant required (X-Tenant-Id header — chora-gateway stamps after JWT verify)")
		return
	}
	gcid := strings.TrimSpace(r.Header.Get("gcid"))
	if gcid == "" {
		gcid = strings.TrimSpace(r.Header.Get("X-Chora-GCID"))
	}
	if gcid == "" {
		writeError(w, http.StatusUnauthorized, "gateway_unauthenticated",
			"caller gcid required (gcid / X-Chora-GCID header — chora-gateway stamps after JWT verify)")
		return
	}

	var req meIdpUpsertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}

	p, err := h.svc.Upsert(r.Context(), tip.UpsertInput{
		TenantID:        tenantID,
		ProviderType:    tip.ProviderType(req.ProviderType),
		ClientID:        req.ClientID,
		ClientSecret:    req.ClientSecret,
		DiscoveryURL:    req.DiscoveryURL,
		SingpassEnabled: req.SingpassEnabled,
		ActorGCID:       gcid,
		// W3C trace context from the inbound request — flows through to
		// the outbox envelope so the emitted event stitches to the
		// calling span in Cloud Trace.
		Traceparent: strings.TrimSpace(r.Header.Get("traceparent")),
		Tracestate:  strings.TrimSpace(r.Header.Get("tracestate")),
	})
	if err != nil {
		switch {
		case errors.Is(err, tip.ErrInvalidInput):
			writeError(w, http.StatusBadRequest, "invalid_input", err.Error())
		case strings.Contains(err.Error(), "secret manager"):
			writeError(w, http.StatusBadGateway, "secret_manager_failed", err.Error())
		default:
			writeError(w, http.StatusInternalServerError, "internal_error", err.Error())
		}
		return
	}

	writeJSON(w, http.StatusOK, meIdpProviderResponse{
		ID:               p.ID,
		TenantID:         p.TenantID,
		ProviderType:     string(p.ProviderType),
		ClientID:         p.ClientID,
		ClientSecretName: p.ClientSecretName,
		DiscoveryURL:     p.DiscoveryURL,
		SingpassEnabled:  p.SingpassEnabled,
		CreatedAt:        p.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:        p.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
	})
}
