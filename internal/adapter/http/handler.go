// Package httpadapter wires the Identity domain to REST endpoints.
//
// 8 endpoints per spec:
//
//	GET  /healthz, /healthz/
//	GET  /readyz
//	POST /api/users
//	GET  /api/users/{gcid}
//	POST /api/memberships
//	GET  /api/memberships?tenant_id=&gcid=
//	PATCH /api/memberships/{id}/role
//	POST /api/users/{gcid}/portability/export
//	GET  /api/users/{gcid}/portability/snapshots
package httpadapter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// IdentityHandler exposes the /api/* HTTP routes.
type IdentityHandler struct {
	users       identity.UserRepository
	memberships identity.MembershipRepository
	snapshots   identity.SnapshotRepository
}

// NewRouter wires the public mux. Returns an http.Handler ready for
// ListenAndServe or ServeMux embedding. Backwards-compatible entrypoint
// without the per-course role repository — /me/roles will return the
// "no assignments seeded" path until the broader caller migrates to
// NewRouterWithCourseRoles.
func NewRouter(
	users identity.UserRepository,
	memberships identity.MembershipRepository,
	snapshots identity.SnapshotRepository,
) http.Handler {
	return NewRouterWithCourseRoles(users, memberships, snapshots, emptyCourseRoleRepo{})
}

// NewRouterWithCourseRoles is the M11+ entrypoint — it takes a
// CourseRoleRepository so the /me/roles handler can resolve per-course role
// context per Comic Ch4 P8.
func NewRouterWithCourseRoles(
	users identity.UserRepository,
	memberships identity.MembershipRepository,
	snapshots identity.SnapshotRepository,
	courseRoles identity.CourseRoleRepository,
) http.Handler {
	h := &IdentityHandler{
		users:       users,
		memberships: memberships,
		snapshots:   snapshots,
	}
	me := NewMeHandler(users, courseRoles)

	mux := http.NewServeMux()
	// Health + readiness — public, no tenant context required.
	mux.HandleFunc("/healthz", healthz)
	mux.HandleFunc("/healthz/", healthz)
	mux.HandleFunc("/health", healthz)
	mux.HandleFunc("/readyz", h.readyz)

	// /me + /me/roles — bearer-auth (no tenant header). Comic Ch4 P8:
	// "Same account, different role — per course."
	mux.Handle("/me", bearerAuth(users, http.HandlerFunc(me.getMe)))
	mux.Handle("/me/roles", bearerAuth(users, http.HandlerFunc(me.getMeRoles)))

	// Protected /api/users[/...]  + /api/memberships[/...] dispatchers.
	mux.HandleFunc("/api/users", h.usersCollection)
	mux.HandleFunc("/api/users/", h.usersItem)
	mux.HandleFunc("/api/memberships", h.membershipsCollection)
	mux.HandleFunc("/api/memberships/", h.membershipsItem)

	// Index ('/') registered last so explicit mounts above take precedence.
	mux.HandleFunc("/", h.indexHandler)

	// Compose middleware: logging -> tenantContext -> mux. Note: the
	// tenantContext middleware bypasses /me + /healthz (see isPublicPath).
	return logging(tenantContext(mux))
}

// emptyCourseRoleRepo is a degenerate CourseRoleRepository used when the
// legacy NewRouter is called without a per-course role store. Every lookup
// returns ErrCourseRoleNotFound so /me/roles yields role=none / perms=[].
type emptyCourseRoleRepo struct{}

func (emptyCourseRoleRepo) GetAssignment(_ context.Context, _, _ string) (*identity.CourseRoleAssignment, error) {
	return nil, identity.ErrCourseRoleNotFound
}

// -----------------------------------------------------------------------------
// Health + readiness + index
// -----------------------------------------------------------------------------

func healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}

func (h *IdentityHandler) readyz(w http.ResponseWriter, _ *http.Request) {
	if h.users == nil || h.memberships == nil || h.snapshots == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "repos-uninitialised"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ready"})
}

func (h *IdentityHandler) indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"service":         "chora-identity",
		"domain":          "Identity (supporting)",
		"project":         resolveProject(),
		"owning_team":     "Team 3 (Platform)",
		"aggregate_roots": []string{"User", "TenantMembership", "PortableSnapshot"},
	})
}

// -----------------------------------------------------------------------------
// /api/users  (collection: POST + GET-by-gcid via /api/users/{gcid})
// -----------------------------------------------------------------------------

func (h *IdentityHandler) usersCollection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.createUser(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED",
			"only POST is supported on /api/users")
	}
}

type createUserRequest struct {
	Email            string `json:"email"`
	IdentityProvider string `json:"identity_provider"`
	FederatedSubject string `json:"federated_subject"`
	DisplayName      string `json:"display_name"`
}

func (h *IdentityHandler) createUser(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "IDENTITY_INVALID_BODY", err.Error())
		return
	}
	u, err := identity.NewUser(identity.NewUserParams{
		Email:            req.Email,
		DisplayName:      req.DisplayName,
		IdentityProvider: identity.IdentityProvider(req.IdentityProvider),
		FederatedSubject: req.FederatedSubject,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, "IDENTITY_INVALID_USER", err.Error())
		return
	}
	if err := h.users.Save(r.Context(), u); err != nil {
		log.Printf("user save error: %v", err)
		writeError(w, http.StatusInternalServerError, "IDENTITY_REPO_ERROR", "failed to persist user")
		return
	}
	writeJSON(w, http.StatusCreated, u)
}

// usersItem dispatches /api/users/{gcid}[...] sub-paths.
func (h *IdentityHandler) usersItem(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/users/")
	rest = strings.TrimSuffix(rest, "/")
	if rest == "" {
		writeError(w, http.StatusNotFound, "IDENTITY_NOT_FOUND", "missing gcid")
		return
	}
	parts := strings.Split(rest, "/")
	gcid := parts[0]

	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			h.getUser(w, r, gcid)
		default:
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED",
				"only GET is supported on /api/users/{gcid}")
		}
		return
	}

	// Sub-resource: /api/users/{gcid}/portability/{export|snapshots}
	if len(parts) == 3 && parts[1] == "portability" {
		switch parts[2] {
		case "export":
			if r.Method != http.MethodPost {
				writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED",
					"only POST is supported on /api/users/{gcid}/portability/export")
				return
			}
			h.exportSnapshot(w, r, gcid)
			return
		case "snapshots":
			if r.Method != http.MethodGet {
				writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED",
					"only GET is supported on /api/users/{gcid}/portability/snapshots")
				return
			}
			h.listSnapshots(w, r, gcid)
			return
		}
	}

	writeError(w, http.StatusNotFound, "IDENTITY_NOT_FOUND", "unknown sub-resource")
}

func (h *IdentityHandler) getUser(w http.ResponseWriter, r *http.Request, gcid string) {
	u, err := h.users.GetByGcid(r.Context(), gcid)
	if err != nil {
		if errors.Is(err, identity.ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "IDENTITY_USER_NOT_FOUND", "user not found")
			return
		}
		log.Printf("user get error: %v", err)
		writeError(w, http.StatusInternalServerError, "IDENTITY_REPO_ERROR", "internal error")
		return
	}
	writeJSON(w, http.StatusOK, u)
}

// -----------------------------------------------------------------------------
// /api/memberships
// -----------------------------------------------------------------------------

func (h *IdentityHandler) membershipsCollection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.listMemberships(w, r)
	case http.MethodPost:
		h.createMembership(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED",
			"only GET and POST are supported on /api/memberships")
	}
}

type createMembershipRequest struct {
	Gcid     string `json:"gcid"`
	TenantID string `json:"tenant_id"`
	Role     string `json:"role"`
}

func (h *IdentityHandler) createMembership(w http.ResponseWriter, r *http.Request) {
	var req createMembershipRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "IDENTITY_INVALID_BODY", err.Error())
		return
	}
	// AGID-shape rejection at the API boundary — must produce 400 even before
	// the constructor (test contract).
	if identity.IsAGID(req.Gcid) {
		writeError(w, http.StatusBadRequest, "IDENTITY_AGID_REJECTED",
			"agent identifiers (AGID) cannot hold a TenantMembership")
		return
	}

	m, err := identity.NewTenantMembership(identity.NewMembershipParams{
		Gcid:     req.Gcid,
		TenantID: req.TenantID,
		Role:     identity.Role(req.Role),
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, "IDENTITY_INVALID_MEMBERSHIP", err.Error())
		return
	}
	if err := h.memberships.AddMembership(r.Context(), m); err != nil {
		if errors.Is(err, identity.ErrMembershipExists) {
			writeError(w, http.StatusConflict, "IDENTITY_MEMBERSHIP_DUPLICATE",
				"membership already exists for (gcid, tenant_id)")
			return
		}
		log.Printf("membership add error: %v", err)
		writeError(w, http.StatusInternalServerError, "IDENTITY_REPO_ERROR", "failed to persist membership")
		return
	}
	writeJSON(w, http.StatusCreated, m)
}

type listMembershipsResponse struct {
	Items []*identity.TenantMembership `json:"items"`
	Total int                          `json:"total"`
}

func (h *IdentityHandler) listMemberships(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := identity.MembershipFilter{
		TenantID: strings.TrimSpace(q.Get("tenant_id")),
		Gcid:     strings.TrimSpace(q.Get("gcid")),
	}
	items, err := h.memberships.List(r.Context(), filter)
	if err != nil {
		log.Printf("membership list error: %v", err)
		writeError(w, http.StatusInternalServerError, "IDENTITY_REPO_ERROR", "failed to list memberships")
		return
	}
	writeJSON(w, http.StatusOK, listMembershipsResponse{Items: items, Total: len(items)})
}

// membershipsItem dispatches /api/memberships/{id}/role.
func (h *IdentityHandler) membershipsItem(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/memberships/")
	rest = strings.TrimSuffix(rest, "/")
	if rest == "" {
		writeError(w, http.StatusNotFound, "IDENTITY_NOT_FOUND", "missing membership id")
		return
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 2 || parts[1] != "role" {
		writeError(w, http.StatusNotFound, "IDENTITY_NOT_FOUND", "unknown sub-resource")
		return
	}
	if r.Method != http.MethodPatch {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED",
			"only PATCH is supported on /api/memberships/{id}/role")
		return
	}
	h.changeRole(w, r, parts[0])
}

type changeRoleRequest struct {
	Role string `json:"role"`
}

func (h *IdentityHandler) changeRole(w http.ResponseWriter, r *http.Request, membershipID string) {
	var req changeRoleRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "IDENTITY_INVALID_BODY", err.Error())
		return
	}
	m, err := h.memberships.GetByID(r.Context(), membershipID)
	if err != nil {
		if errors.Is(err, identity.ErrMembershipNotFound) {
			writeError(w, http.StatusNotFound, "IDENTITY_MEMBERSHIP_NOT_FOUND",
				"membership not found")
			return
		}
		log.Printf("membership get error: %v", err)
		writeError(w, http.StatusInternalServerError, "IDENTITY_REPO_ERROR", "internal error")
		return
	}
	actor := gcidFromContext(r.Context())
	if err := m.ChangeRole(identity.Role(req.Role), actor); err != nil {
		writeError(w, http.StatusBadRequest, "IDENTITY_INVALID_ROLE", err.Error())
		return
	}
	if err := h.memberships.UpdateRole(r.Context(), m); err != nil {
		log.Printf("membership update error: %v", err)
		writeError(w, http.StatusInternalServerError, "IDENTITY_REPO_ERROR", "failed to save role change")
		return
	}
	writeJSON(w, http.StatusOK, m)
}

// -----------------------------------------------------------------------------
// /api/users/{gcid}/portability — append-only snapshots
// -----------------------------------------------------------------------------

func (h *IdentityHandler) exportSnapshot(w http.ResponseWriter, r *http.Request, gcid string) {
	// Verify the user exists first — closed users cannot export.
	u, err := h.users.GetByGcid(r.Context(), gcid)
	if err != nil {
		if errors.Is(err, identity.ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "IDENTITY_USER_NOT_FOUND", "user not found")
			return
		}
		log.Printf("portability user get error: %v", err)
		writeError(w, http.StatusInternalServerError, "IDENTITY_REPO_ERROR", "internal error")
		return
	}
	if u.Status == identity.UserStatusClosed {
		writeError(w, http.StatusForbidden, "IDENTITY_USER_CLOSED",
			"closed users cannot export snapshots")
		return
	}

	seq, err := h.snapshots.NextSequence(r.Context(), gcid)
	if err != nil {
		log.Printf("portability next-seq error: %v", err)
		writeError(w, http.StatusInternalServerError, "IDENTITY_REPO_ERROR", "failed to compute sequence")
		return
	}

	// Skeleton: payload hash is a deterministic placeholder over (gcid, seq, time).
	// Tier 2 will replace this with the actual GCS object hash from the export job.
	payload := gcid + ":" + time.Now().UTC().Format(time.RFC3339Nano)
	hash := sha256.Sum256([]byte(payload))

	s, err := identity.NewPortableSnapshot(identity.NewPortableSnapshotParams{
		Gcid:        gcid,
		Sequence:    seq,
		PayloadHash: "sha256:" + hex.EncodeToString(hash[:]),
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, "IDENTITY_INVALID_SNAPSHOT", err.Error())
		return
	}
	if err := h.snapshots.Append(r.Context(), s); err != nil {
		log.Printf("portability append error: %v", err)
		writeError(w, http.StatusInternalServerError, "IDENTITY_REPO_ERROR", "failed to append snapshot")
		return
	}
	writeJSON(w, http.StatusCreated, s)
}

type listSnapshotsResponse struct {
	Items []*identity.PortableSnapshot `json:"items"`
	Total int                          `json:"total"`
}

func (h *IdentityHandler) listSnapshots(w http.ResponseWriter, r *http.Request, gcid string) {
	items, err := h.snapshots.List(r.Context(), gcid)
	if err != nil {
		log.Printf("portability list error: %v", err)
		writeError(w, http.StatusInternalServerError, "IDENTITY_REPO_ERROR", "failed to list snapshots")
		return
	}
	writeJSON(w, http.StatusOK, listSnapshotsResponse{Items: items, Total: len(items)})
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func decodeJSON(r *http.Request, v any) error {
	if r.Body == nil {
		return errors.New("empty body")
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// errEnvelope mirrors the canonical error schema across Chora services.
type errEnvelope struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, errEnvelope{Code: code, Message: msg})
}
