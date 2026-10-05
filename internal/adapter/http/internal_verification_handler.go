// internal_verification_handler.go — INTERNAL service-to-service by-GCID
// verification-claim read (ADR-190 D2).
//
// Route (mounted on the top-level `composed` mux in cmd/server/main.go, next to
// the existing /api/internal/pubsub/* internal routes):
//
//	GET /internal/v1/identity/verification-status?gcid=<uuid>
//	  → 200 {"gcid":"…","verified":true|false,"status":"…"}
//	  → 400 when gcid is missing
//
// Unlike GET /v1/me/kyc/status (self/"me"-scoped to the bearer-token GCID), this
// endpoint reads the verification claim for an ARBITRARY gcid. It is the
// service-to-service seam ADR-190 D2 requires: "candidate admission is gated by
// an Identity-owned verification claim". chora-delivery's Exam BC admission gate
// (verify + admit) consults it over the mesh via the exam.VerificationClaimReader
// port. It reuses the SAME kyc.Repository as the self-scoped handler — NO new
// migration, NO new store.
//
// SECURITY (fail-closed, defence-in-depth):
//   - NOT bearer-authenticated. Access is gated at the mesh: the Istio
//     AuthorizationPolicy chora-infra/k8s/services/chora-identity/
//     authz-allow-delivery-internal.yaml permits ONLY the chora-delivery SA
//     principal on /internal/v1/identity/*. The sidecar default-deny (already
//     active via authz-allow-gateway.yaml) keeps the gateway/BFF — and thus
//     learners — out of the /internal/* subtree.
//   - Person-scoped, NOT tenant-scoped: a KYC/Singpass verification claim is a
//     property of the GCID (cross-tenant portable), so the lookup keys off gcid
//     only (mirrors kyc.Repository.GetLatestByGcid). No RLS tenant context is
//     needed or applied here.
package httpadapter

import (
	"errors"
	"net/http"
	"strings"

	"github.com/apollo-chora/chora-identity/internal/domain/kyc"
)

// InternalVerificationHandler serves the internal by-GCID verification-status
// read. It depends only on the kyc.Repository port (hexagonal — no infra).
type InternalVerificationHandler struct {
	kycRepo kyc.Repository
}

// NewInternalVerificationHandler wires the handler to the kyc repository.
func NewInternalVerificationHandler(kycRepo kyc.Repository) *InternalVerificationHandler {
	return &InternalVerificationHandler{kycRepo: kycRepo}
}

// RegisterRoutes mounts the endpoint on the supplied mux.
func (h *InternalVerificationHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.Handle("/internal/v1/identity/verification-status", h)
}

// ServeHTTP makes the handler an http.Handler so it can be mounted directly on
// the top-level `composed` mux (mirrors identityPaymentsInboxHandler).
func (h *InternalVerificationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET only")
		return
	}
	if h.kycRepo == nil {
		// Fail loud — a nil repo is a wiring bug, never a silent "unverified".
		writeError(w, http.StatusInternalServerError, "KYC_REPO_UNAVAILABLE", "verification store not wired")
		return
	}

	gcid := strings.TrimSpace(r.URL.Query().Get("gcid"))
	if gcid == "" {
		writeError(w, http.StatusBadRequest, "GCID_REQUIRED", "gcid query parameter required")
		return
	}

	v, err := h.kycRepo.GetLatestByGcid(r.Context(), gcid)
	if err != nil {
		if errors.Is(err, kyc.ErrNotFound) {
			// No claim on record — an honest, non-error "unverified".
			writeJSON(w, http.StatusOK, map[string]any{
				"gcid":     gcid,
				"verified": false,
				"status":   "unverified",
			})
			return
		}
		// Infra error — fail loud so the delivery adapter surfaces a 502, never
		// a false-negative admission.
		writeError(w, http.StatusInternalServerError, "KYC_REPO_ERROR", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"gcid":     gcid,
		"verified": v.Status == kyc.StatusVerified,
		"status":   string(v.Status),
	})
}
