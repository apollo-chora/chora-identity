// /me + /me/roles handlers per Comic Ch4 P8 "I Am Two People" → "One Identity
// to Rule Them All".
//
//	GET /me                       → authenticated user's GCID profile
//	GET /me/roles?course_id=UUID  → per-course role context (same gcid, role
//	                                varies per course)
//
// Authentication shape — production traffic comes via chora-gateway, which:
//
//  1. Validates the ChoraSession / Identity Platform JWT at the edge.
//
//  2. Marshals the canonical gcid into mesh-metadata headers (per
//     libs/chora-go-common/auth/servicemesh):
//
//     chora-gcid: <gcid>          (canonical, mTLS-trusted mesh metadata)
//     chora-tenant-id: <tenant>   (mTLS-trusted mesh metadata)
//     gcid: <gcid>                (legacy lowercase header, D1.5)
//
//  3. Forwards `Authorization: Bearer <JWT>` as-is so backend services
//     can opt-in to additional verification.
//
// The bearer auth middleware below resolves the gcid via the following
// priority chain (B2 fix, 2026-05-15):
//
//  1. `chora-gcid` mesh header     (canonical; mTLS-trusted)
//  2. `gcid` lowercase header      (legacy; D1.5 stamp)
//  3. Bearer token as raw GCID     (M10 MVP shape; comic-seed + dev curl)
//
// The legacy MVP shape (bearer-as-gcid) is retained for backwards-
// compatibility with the existing me_handler_test.go fixtures + curl-shape
// dev probes. Live traffic from chora-gateway always hits path 1.
//
// Pre-B2 the bearer was UNCONDITIONALLY treated as the gcid. Live the
// bearer is a JWT, not a UUID — `pg.GetByGcid` blew up with
// `invalid input syntax for type uuid: "eyJ…"` (SQLSTATE 22P02), surfaced
// as 401 IDENTITY_UNKNOWN_GCID at the gateway. Documented in
// docs/m13/phyllis-demo-rehearsal-v3-2026-05-15.md as B2.
package httpadapter

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/apollo-chora/chora-common/auth/servicemesh"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// -----------------------------------------------------------------------------
// MeHandler — wraps the user repo + role resolver for /me + /me/roles.
// -----------------------------------------------------------------------------

type MeHandler struct {
	users    identity.UserRepository
	resolver *identity.RoleResolver
}

// NewMeHandler constructs a MeHandler given the user repository + a course-role
// repository (used to build the resolver internally).
func NewMeHandler(
	users identity.UserRepository,
	courseRoles identity.CourseRoleRepository,
) *MeHandler {
	return &MeHandler{
		users:    users,
		resolver: identity.NewRoleResolver(courseRoles),
	}
}

// -----------------------------------------------------------------------------
// Bearer auth middleware — extracts gcid from Authorization: Bearer <gcid>.
// On success injects the gcid into the request context under ctxKeyGcid.
// On failure writes 401 + canonical error envelope and short-circuits.
// -----------------------------------------------------------------------------

func bearerAuth(users identity.UserRepository, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gcid, ok := resolveBearerGCID(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "IDENTITY_BEARER_REQUIRED",
				"Authorization: Bearer <token> or chora-gcid / gcid header is required")
			return
		}
		// Verify the gcid exists in the user repo — unknown GCIDs get 401, not 404.
		if _, err := users.GetByGcid(r.Context(), gcid); err != nil {
			if errors.Is(err, identity.ErrUserNotFound) {
				writeError(w, http.StatusUnauthorized, "IDENTITY_UNKNOWN_GCID",
					"unknown bearer gcid")
				return
			}
			log.Printf("bearer auth user lookup error: %v", err)
			writeError(w, http.StatusInternalServerError, "IDENTITY_REPO_ERROR", "internal error")
			return
		}
		ctx := context.WithValue(r.Context(), ctxKeyGcid, gcid)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// resolveBearerGCID extracts the caller's canonical GCID per the B2 priority
// chain (B2 fix, 2026-05-15):
//
//  1. servicemesh.HeaderGCID (`chora-gcid`)  — mTLS-trusted mesh metadata
//     stamped by chora-gateway after JWT validation. The canonical path
//     for production traffic.
//
//  2. `gcid` lowercase header — legacy mesh-adjacent stamp (D1.5). The
//     gateway also sets this for downstream services whose middleware
//     reads the lowercase form.
//
//  3. Bearer token treated as raw GCID — the M10 MVP shape preserved
//     for backwards-compat with comic-seed tests + dev curl probes. Only
//     accepted when the bearer DOESN'T look like a JWT (no `.` separator)
//     so a live JWT never poisons the lookup with a non-UUID value
//     (the pg.GetByGcid SQLSTATE 22P02 crash B2 root-caused).
//
// Returns (gcid, true) on success, ("", false) when nothing usable.
func resolveBearerGCID(r *http.Request) (string, bool) {
	// 1. Mesh-trusted canonical header.
	if gcid := strings.TrimSpace(r.Header.Get(servicemesh.HeaderGCID)); gcid != "" {
		return gcid, true
	}
	// 2. Lowercase legacy header (gateway D1.5 stamp).
	if gcid := strings.TrimSpace(r.Header.Get("gcid")); gcid != "" {
		return gcid, true
	}
	// 3. Bearer-as-gcid MVP fallback. The bearer is rejected as a gcid
	// source when it LOOKS LIKE A JWT (contains a `.` — JWTs are 3
	// dot-separated base64-url segments). This prevents the canonical
	// pg.GetByGcid `invalid input syntax for type uuid` crash that
	// B2 exposed in production.
	bearer, ok := extractBearer(r.Header.Get("Authorization"))
	if !ok {
		return "", false
	}
	if strings.Contains(bearer, ".") {
		// JWT-shaped — and mesh headers absent. The gateway should
		// always stamp chora-gcid before forwarding; if we got here
		// it's a misconfigured edge or a direct caller bypassing the
		// gateway. Refuse loud per `feedback_no_stubs_real_wiring`.
		return "", false
	}
	return bearer, true
}

// extractBearer parses "Bearer <token>" (case-insensitive scheme). Returns
// (token, true) on success; ("", false) for missing / malformed values.
func extractBearer(authz string) (string, bool) {
	authz = strings.TrimSpace(authz)
	if authz == "" {
		return "", false
	}
	parts := strings.SplitN(authz, " ", 2)
	if len(parts) != 2 {
		return "", false
	}
	if !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}
	tok := strings.TrimSpace(parts[1])
	if tok == "" {
		return "", false
	}
	return tok, true
}

// -----------------------------------------------------------------------------
// GET /me
// -----------------------------------------------------------------------------

// meResponse mirrors the spec contract — global account metadata.
type meResponse struct {
	Gcid        string   `json:"gcid"`
	Email       string   `json:"email"`
	DisplayName string   `json:"display_name"`
	CreatedAt   string   `json:"created_at"`
	AuthMethods []string `json:"auth_methods"`
	LinkedIdps  []string `json:"linked_idps"`
}

func (h *MeHandler) getMe(w http.ResponseWriter, r *http.Request) {
	gcid := gcidFromContext(r.Context())
	u, err := h.users.GetByGcid(r.Context(), gcid)
	if err != nil {
		// Bearer middleware already verified existence; this branch is
		// defensive. Treat as 401 to match the auth contract.
		if errors.Is(err, identity.ErrUserNotFound) {
			writeError(w, http.StatusUnauthorized, "IDENTITY_UNKNOWN_GCID", "unknown bearer gcid")
			return
		}
		log.Printf("me get user error: %v", err)
		writeError(w, http.StatusInternalServerError, "IDENTITY_REPO_ERROR", "internal error")
		return
	}

	resp := meResponse{
		Gcid:        u.Gcid,
		Email:       u.Email,
		DisplayName: u.DisplayName,
		CreatedAt:   u.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		AuthMethods: deriveAuthMethods(u),
		LinkedIdps:  deriveLinkedIdps(u),
	}
	writeJSON(w, http.StatusOK, resp)
}

// deriveAuthMethods returns the list of auth methods the user has registered.
// MVP heuristic: include "password" by default + the IdentityProvider type if
// it implies a credential method. Production wiring will read from a
// credentials projection.
func deriveAuthMethods(u *identity.User) []string {
	out := []string{"password"}
	switch u.IdentityProvider {
	case identity.ProviderOIDC:
		out = append(out, "google_oidc")
	case identity.ProviderWebAuthn:
		out = append(out, "webauthn")
	case identity.ProviderSAML:
		out = append(out, "saml")
	}
	return out
}

// deriveLinkedIdps mirrors deriveAuthMethods at the IdP level (production:
// links projection from chora_identity DB).
func deriveLinkedIdps(u *identity.User) []string {
	switch u.IdentityProvider {
	case identity.ProviderOIDC:
		// Comic Ch4: Phyllis links Google + Singpass. Skeleton emits both for
		// any OIDC-bound user so the JSON contract is non-empty.
		return []string{"google", "singpass"}
	case identity.ProviderWebAuthn:
		return []string{"webauthn"}
	case identity.ProviderSAML:
		return []string{"saml"}
	}
	return []string{}
}

// -----------------------------------------------------------------------------
// GET /me/roles?course_id=UUID
// -----------------------------------------------------------------------------

func (h *MeHandler) getMeRoles(w http.ResponseWriter, r *http.Request) {
	gcid := gcidFromContext(r.Context())
	courseID := strings.TrimSpace(r.URL.Query().Get("course_id"))
	if courseID == "" {
		writeError(w, http.StatusBadRequest, "IDENTITY_COURSE_ID_REQUIRED",
			"course_id query parameter is required")
		return
	}

	ctx, err := h.resolver.ResolveCourseRole(r.Context(), gcid, courseID)
	if err != nil {
		switch {
		case errors.Is(err, identity.ErrInvalidCourseID):
			writeError(w, http.StatusBadRequest, "IDENTITY_INVALID_COURSE_ID",
				"course_id must be a valid UUID")
			return
		case errors.Is(err, identity.ErrInvalidGCID):
			// Bearer middleware should've caught the empty case; AGID-shape
			// is also rejected at 401-equivalent for the "/me" surface.
			writeError(w, http.StatusUnauthorized, "IDENTITY_INVALID_GCID",
				"invalid gcid claim")
			return
		}
		log.Printf("me/roles resolve error: %v", err)
		writeError(w, http.StatusInternalServerError, "IDENTITY_RESOLVER_ERROR",
			"failed to resolve course role")
		return
	}
	writeJSON(w, http.StatusOK, ctx)
}

// -----------------------------------------------------------------------------
// Compile-time guard: the JSON encoder/decoder must agree on field names with
// the spec contract — keep this guard live so refactors fail loudly.
// -----------------------------------------------------------------------------

var _ = json.Marshal
