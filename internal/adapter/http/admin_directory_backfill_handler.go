// admin_directory_backfill_handler.go — admin-gated directory-projection
// backfill (CHO-2327).
//
// Route (mounted on the composed mux in cmd/server/main.go):
//
//	POST /api/v1/admin/directory/backfill → re-emit chora.identity.user.profile_updated.v1
//	                                        for every live user with a non-empty display_name
//
// WHY: identity is the sole owner of the (gcid → display_name) mapping and emits
// chora.identity.user.profile_updated.v1 ONLY on UpdateDisplayName. Downstream
// directories (chora-delivery.user_directory, which feeds the R+ Offering Roster
// + Transcript) therefore never learned the names of members whose display_name
// predates the projection being wired — those rows render raw GCIDs. This
// endpoint replays the projection for the whole directory so it catches up,
// using identity's OWN DB + transactional outbox (no external DB credentials).
// Idempotent + safe to re-run: the consumer dedups on event_id + is
// last-writer-wins on updated_at, so a replay can never regress a newer name.
//
// AUTHZ (fail-closed): adminGate — the mesh x-mesh-user-roles header must carry
// an admin role (TENANT_ADMIN / TRAINING_ADMIN / INSTRUCTOR / ADMIN / OWNER) AND
// a tenant context must be present. Reachable only via the bearer-authed
// gateway/BFF admin surface (the sidecar default-deny + authz-allow-gateway.yaml
// keep learners out; the in-handler role gate is the second layer).
//
// KNOWN SIMPLIFICATION (flagged, not hidden): display_name is a property of the
// GCID (cross-tenant portable — carries no tenant), so any tenant admin passing
// adminGate triggers a platform-wide re-emit. The blast radius is bounded — it
// only re-projects names that are ALREADY public in every consuming directory,
// and the emit is idempotent — but PLATFORM_OPERATOR is the stricter future gate
// (mirrors the admin_kyc_verify_handler.go GCID-portability note). The acting
// admin's tenant is carried as envelope provenance only; the consumer keys its
// directory by the global gcid and ignores tenant_id.
package httpadapter

import (
	"context"
	"log"
	"net/http"
)

const adminDirectoryBackfillPath = "/api/v1/admin/directory/backfill"

// ProfileDirectoryBackfiller — consumer-side port over the pg UserRepository's
// directory-projection replay. Returns (scanned, emitted, err): scanned = users
// with a projectable display_name considered; emitted = profile_updated.v1
// outbox rows enqueued.
type ProfileDirectoryBackfiller interface {
	BackfillProfileDirectory(ctx context.Context, actingTenantID string) (scanned, emitted int, err error)
}

// AdminDirectoryBackfillHandler serves POST /api/v1/admin/directory/backfill.
// It depends only on the ProfileDirectoryBackfiller port — hexagonal, no infra.
type AdminDirectoryBackfillHandler struct {
	backfiller ProfileDirectoryBackfiller
}

// NewAdminDirectoryBackfillHandler wires the handler.
func NewAdminDirectoryBackfillHandler(backfiller ProfileDirectoryBackfiller) *AdminDirectoryBackfillHandler {
	return &AdminDirectoryBackfillHandler{backfiller: backfiller}
}

// RegisterRoutes mounts the handler at the exact backfill path.
func (h *AdminDirectoryBackfillHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.Handle(adminDirectoryBackfillPath, h)
}

// Compile-time guard.
var _ http.Handler = (*AdminDirectoryBackfillHandler)(nil)

func (h *AdminDirectoryBackfillHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED",
			"POST only on /api/v1/admin/directory/backfill")
		return
	}
	// Fail-closed authz FIRST — a non-admin / no-tenant caller never reaches the
	// store. adminGate writes the 401/403 response itself.
	actingTenantID, ok := adminGate(w, r)
	if !ok {
		return
	}
	if h.backfiller == nil {
		// Fail loud — a nil backfiller is a wiring bug, never a silent success.
		writeError(w, http.StatusInternalServerError, "DIRECTORY_BACKFILLER_UNAVAILABLE",
			"directory backfill store not wired")
		return
	}

	scanned, emitted, err := h.backfiller.BackfillProfileDirectory(r.Context(), actingTenantID)
	if err != nil {
		log.Printf("admin-directory-backfill: BackfillProfileDirectory error (scanned=%d emitted=%d, acting_tenant=%s): %v",
			scanned, emitted, actingTenantID, err)
		writeError(w, http.StatusInternalServerError, "DIRECTORY_BACKFILL_FAILED", err.Error())
		return
	}
	log.Printf("admin-directory-backfill: re-emitted profile_updated.v1 for %d/%d users (acting_tenant=%s)",
		emitted, scanned, actingTenantID)
	writeJSON(w, http.StatusOK, map[string]any{
		"scanned": scanned,
		"emitted": emitted,
	})
}
