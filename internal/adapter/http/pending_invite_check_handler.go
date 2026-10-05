// pending_invite_check_handler.go — GET /api/v1/internal/pending-invite?email=X
//
// CHO-2205 (ADR-194 D2) + CHO-2207. The gateway mint allowlist reads through
// this endpoint to authorize an email that is NOT in the static
// idp-email-allowlist secret. An email is authorized to mint if it either:
//   - carries a live PENDING tenant invite (CHO-2205 — first sign-in), or
//   - is an already-KNOWN identity user (CHO-2207 — re-authentication). A user
//     row exists only after a prior AUTHORIZED mint (allowlist or accepted
//     invite), so re-authorizing an existing user is safe; this fixes the
//     lockout where an accepted invite (consumed at first sign-in) no longer
//     matches as pending.
//
// Returns {"has_pending_invite": bool, "is_known_user": bool}; the gateway
// authorizes if EITHER is true.
//
// PURE READ — MatchByEmail (SECURITY DEFINER match_pending_invites_by_email) +
// FindByEmail (users table, case-insensitive, excludes soft-deleted). Mints NO
// GCID and writes NO membership; the actual cold-invite apply still happens at
// /v1/identity/resolve (ADR-194 D2).
//
// Trust model: internal mesh endpoint (chora-gateway → chora-identity). The
// gateway is the upstream trust boundary, same model as /v1/identity/resolve —
// NO Authorization check here. The mesh path allow-list entry lives in
// chora-infra/k8s/services/chora-identity/authz-allow-gateway.yaml (an unlisted
// path is a sidecar default-deny 403).
package httpadapter

import (
	"context"
	"log"
	"net/http"
	"strings"

	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// PendingInviteLookup is the read-only cross-tenant email matcher the check
// handler needs — the SAME MatchByEmail the resolve-time applier uses (the pg
// PendingInviteRepository satisfies it). NO MarkAccepted: the check is a PURE
// READ, so a write is structurally impossible on this port.
type PendingInviteLookup interface {
	MatchByEmail(ctx context.Context, email string) ([]identity.PendingInviteMatch, error)
}

// KnownUserLookup reports whether an email already maps to an existing
// (non-soft-deleted) identity user (CHO-2207). A user row exists only after a
// prior AUTHORIZED mint, so an existing user was vetted once and the mint may
// safely re-authorize them. The pg UserRepository.FindByEmail satisfies this.
// Read-only. Optional: a nil lookup disables the member-authorization arm
// (endpoint behaves exactly as CHO-2205).
type KnownUserLookup interface {
	FindByEmail(ctx context.Context, email string) (*identity.User, bool, error)
}

// PendingInviteCheckHandler implements GET /api/v1/internal/pending-invite.
type PendingInviteCheckHandler struct {
	lookup    PendingInviteLookup
	knownUser KnownUserLookup // optional — nil disables the CHO-2207 member arm
}

// NewPendingInviteCheckHandler constructs the handler. Returns nil when the
// pending-invite lookup is missing — the caller leaves the route unmounted
// rather than binding a fake (per `feedback_no_stubs_real_wiring`; the gateway
// then fails closed). knownUser is optional.
func NewPendingInviteCheckHandler(lookup PendingInviteLookup, knownUser KnownUserLookup) *PendingInviteCheckHandler {
	if lookup == nil {
		return nil
	}
	return &PendingInviteCheckHandler{lookup: lookup, knownUser: knownUser}
}

type pendingInviteCheckResponse struct {
	HasPendingInvite bool `json:"has_pending_invite"`
	IsKnownUser      bool `json:"is_known_user"`
}

// ServeHTTP dispatches GET /api/v1/internal/pending-invite?email=X. Other
// methods get 405; a missing email is 400; a store error is 503 (the gateway
// treats any non-200 as NOT authorized, so the mint gate fails closed).
func (h *PendingInviteCheckHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeError(w, http.StatusMethodNotAllowed, "IDENTITY_METHOD_NOT_ALLOWED",
			"only GET supported on /api/v1/internal/pending-invite")
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("email")))
	if email == "" {
		writeError(w, http.StatusBadRequest, "IDENTITY_BAD_REQUEST", "email query param required")
		return
	}
	matches, err := h.lookup.MatchByEmail(r.Context(), email)
	if err != nil {
		log.Printf("pending_invite_check: MatchByEmail(%q): %v", email, err)
		writeError(w, http.StatusServiceUnavailable, "IDENTITY_PENDING_INVITE_LOOKUP_FAILED",
			"pending-invite lookup failed")
		return
	}
	hasPendingInvite := len(matches) > 0

	// CHO-2207: only consult the user lookup when a pending invite hasn't
	// already authorized — this both saves a query and prevents a user-lookup
	// error from masking a valid pending invite.
	isKnownUser := false
	if !hasPendingInvite && h.knownUser != nil {
		_, found, uerr := h.knownUser.FindByEmail(r.Context(), email)
		if uerr != nil {
			log.Printf("pending_invite_check: FindByEmail(%q): %v", email, uerr)
			writeError(w, http.StatusServiceUnavailable, "IDENTITY_KNOWN_USER_LOOKUP_FAILED",
				"user lookup failed")
			return
		}
		isKnownUser = found
	}

	writeJSON(w, http.StatusOK, pendingInviteCheckResponse{
		HasPendingInvite: hasPendingInvite,
		IsKnownUser:      isKnownUser,
	})
}
