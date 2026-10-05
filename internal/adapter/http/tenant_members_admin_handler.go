// tenant_members_admin_handler.go — L1 Tenant lane (CHO-1707).
//
// Contract: chora-contracts/openapi/identity-admin.yaml v1.4.0
//
//	POST  /api/v1/admin/tenant-members              addTenantMemberByEmail
//	GET   /api/v1/admin/tenant-members              (delegates to the existing
//	                                                 SearchTenantMembersHandler)
//	PATCH /api/v1/admin/tenant-members/{gcid}/role  changeTenantMemberRole
//
// Auth contract (same as searchTenantMembers):
//   - tenant id from servicemesh.HeaderTenantID (`chora-tenant-id`),
//     legacy `X-Tenant-Id` fallback for dev curl + tests — NEVER from the
//     request body (contrast the platform-operator grantTenantMembership).
//   - caller MUST hold TRAINING_ADMIN or TENANT_ADMIN
//     (servicemesh.HeaderUserRoles).
//
// The API speaks the canonical UPPERCASE subset
// LEARNER|AUTHOR|INSTRUCTOR|ADMIN|AUDITOR (AUTHOR per ADR-182 / migration
// 0020) plus the label aliases TRAINING_ADMIN (-> instructor) and TENANT_ADMIN
// (-> admin) resolved by grantableRole (CHO-1870 / WS1). OWNER is JWT-only
// (bootstrap) and PLATFORM_OPERATOR is cross-tenant-only (ADR-165) — neither is
// grantable here.
//
// Write topology (ADR-182 fix for the CHO-1707 bug where the added member
// could never log in to the tenant): the AUTHORITATIVE store is
// chora_tenancy.members — addByEmail writes it FIRST via the tenancy
// UpsertMembership gRPC, then upserts the identity-side tenant_memberships
// MIRROR. Duplicate detection comes from the authoritative store's
// `created` flag; a mirror row that already exists is drift and is
// tolerated (self-heals). When no tenancy client is wired (dev), the
// legacy mirror-only path remains.
//
// Email-invite-with-acceptance (pending membership + email delivery) is a
// named follow-up; this endpoint adds EXISTING users directly.
package httpadapter

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/apollo-chora/chora-common/auth/servicemesh"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// AdminUserFinder — consumer-side port (resolve_handler precedent): the
// slice of UserRepository this handler needs.
type AdminUserFinder interface {
	FindByEmail(ctx context.Context, email string) (*identity.User, bool, error)
	GetByGcid(ctx context.Context, gcid string) (*identity.User, error)
	// UpdateDisplayName patches users.display_name for a live GCID AND
	// atomically enqueues chora.identity.user.profile_updated.v1 (Q3
	// projection). actingTenantID is the acting admin's tenant, carried as
	// envelope provenance. Returns identity.ErrUserNotFound when no live
	// user exists.
	UpdateDisplayName(ctx context.Context, gcid, displayName, actingTenantID string) error
}

// AdminMembershipWriter — consumer-side port over the pg-backed
// tenant_memberships writes, keyed by (gcid, tenant_id).
type AdminMembershipWriter interface {
	AddMembership(ctx context.Context, gcid, tenantID string, role identity.Role) error
	ChangeRole(ctx context.Context, gcid, tenantID string, role identity.Role) error
	// SetRoles (CHO-1809 follow-up): deactivates every existing live row
	// for (gcid, tenant_id) whose role is NOT in `roles`, then upserts
	// the rows that ARE in `roles`. Returns ErrMembershipNotFound when
	// no live row exists for (gcid, tenant_id).
	SetRoles(ctx context.Context, gcid, tenantID string, roles []identity.Role) error
	// RemoveMember (WS2b / CHO-1869): soft-deletes EVERY live mirror row for
	// (gcid, tenant_id). Returns ErrMembershipNotFound when no live row exists.
	RemoveMember(ctx context.Context, gcid, tenantID string) error
}

// AuthoritativeMembershipUpserter — consumer-side port over chora-tenancy's
// UpsertMembership gRPC (the authoritative chora_tenancy.members store).
// created=false means every requested role row already existed.
//
// ReplaceMembershipByTenantID is the REPLACE flavour (CHO-1809 follow-up):
// chora-tenancy soft-deletes existing live roles NOT in the request set
// before upserting the request set. Used by the multi-role PUT
// /tenant-members/{gcid}/roles editor where the admin picks the full role
// set; `UpsertMembershipByTenantID` keeps the additive semantics for the
// per-role grant path (add-by-email + single-role PATCH).
type AuthoritativeMembershipUpserter interface {
	UpsertMembershipByTenantID(ctx context.Context, gcid, tenantID string, roles []string) (created bool, err error)
	ReplaceMembershipByTenantID(ctx context.Context, gcid, tenantID string, roles []string) (created bool, err error)
	// RemoveMembershipByTenantID soft-deletes EVERY authoritative role row for
	// (gcid, tenantID) — the member-centric revoke (WS2b / CHO-1869). Maps the
	// tenancy RemoveMembership RPC; returns ErrUpstreamMembershipSuspended when
	// the membership is suspended and ErrUpstreamMembershipNotFound when there
	// is no live membership to remove.
	RemoveMembershipByTenantID(ctx context.Context, gcid, tenantID string) error
}

// Upstream-tenancy sentinel errors the gRPC adapter maps status codes onto
// so this handler can translate them without importing grpc/codes.
var (
	// ErrUpstreamMembershipSuspended — tenancy FAILED_PRECONDITION: a
	// suspended/soft-deleted membership is never resurrected by an upsert.
	ErrUpstreamMembershipSuspended = errors.New("tenancy: membership suspended")
	// ErrUpstreamTenantNotFound — tenancy NOT_FOUND for the target tenant.
	ErrUpstreamTenantNotFound = errors.New("tenancy: tenant not found")
	// ErrUpstreamMembershipNotFound — tenancy NOT_FOUND for RemoveMembership:
	// no live membership for (gcid, tenant) to remove (WS2b).
	ErrUpstreamMembershipNotFound = errors.New("tenancy: membership not found")
	// ErrUpstreamLastOwnerProtected is a tenancy FAILED_PRECONDITION carrying
	// the errdetails reason LAST_OWNER_PROTECTED (S7-B1 guard D1): the removal
	// would leave the tenant with no owner.
	ErrUpstreamLastOwnerProtected = errors.New("tenancy: last owner protected")
	// ErrUpstreamOwnerRoleProtected is a tenancy FAILED_PRECONDITION carrying
	// the errdetails reason OWNER_ROLE_PROTECTED (S7-B1 guard D2): the replace
	// would strip a live owner row.
	ErrUpstreamOwnerRoleProtected = errors.New("tenancy: owner role protected")
)

// Copy shared by every ownership refusal, whichever store noticed it. An admin
// should not have to know that ownership lives in two tables, only what to do
// next, so the authoritative and mirror refusals produce identical responses.
const (
	codeLastOwnerProtected = "IDENTITY_LAST_OWNER_PROTECTED"
	msgLastOwnerProtected  = "this member is the organisation's owner; hand ownership over before removing them"
	codeOwnerRoleProtected = "IDENTITY_OWNER_ROLE_PROTECTED"
	msgOwnerRoleProtected  = "this member owns the organisation; ownership cannot be changed from the roster"
)

// writeOwnerRefusal answers the two ownership guards with 409 and a named
// code. 409 rather than 403: this is a state conflict the caller resolves by
// handing ownership over, not a permission they lack, which is the same
// register as the suspended-membership refusal on these routes.
// Returns false when err is not an ownership refusal, so callers can fall
// through to their existing error mapping.
func writeOwnerRefusal(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, ErrUpstreamLastOwnerProtected), errors.Is(err, identity.ErrLastOwnerProtected):
		writeError(w, http.StatusConflict, codeLastOwnerProtected, msgLastOwnerProtected)
		return true
	case errors.Is(err, ErrUpstreamOwnerRoleProtected), errors.Is(err, identity.ErrOwnerRoleProtected):
		writeError(w, http.StatusConflict, codeOwnerRoleProtected, msgOwnerRoleProtected)
		return true
	}
	return false
}

// TenantMembersAdminHandler dispatches the /api/v1/admin/tenant-members
// collection + item routes. GET delegates to the existing search handler
// (B6.1) so the roster read path stays single-sourced.
type TenantMembersAdminHandler struct {
	search        http.Handler
	users         AdminUserFinder
	members       AdminMembershipWriter
	authoritative AuthoritativeMembershipUpserter // nil in dev (no tenancy conn)
}

// NewTenantMembersAdminHandler constructs the legacy mirror-only handler
// (dev mode / no tenancy conn). search MUST be the existing
// SearchTenantMembersHandler (or a test stub).
func NewTenantMembersAdminHandler(search http.Handler, users AdminUserFinder, members AdminMembershipWriter) *TenantMembersAdminHandler {
	return &TenantMembersAdminHandler{search: search, users: users, members: members}
}

// NewTenantMembersAdminHandlerWithTenancy constructs the production
// handler: authoritative chora_tenancy.members write first, mirror second.
func NewTenantMembersAdminHandlerWithTenancy(search http.Handler, users AdminUserFinder, members AdminMembershipWriter, authoritative AuthoritativeMembershipUpserter) *TenantMembersAdminHandler {
	return &TenantMembersAdminHandler{search: search, users: users, members: members, authoritative: authoritative}
}

const tenantMembersBasePath = "/api/v1/admin/tenant-members"

// ServeHTTP routes both the collection path and the /{gcid}/role item path
// (mount the handler at the base path AND the base path + "/").
func (h *TenantMembersAdminHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, tenantMembersBasePath)
	rest = strings.Trim(rest, "/")
	if rest == "" {
		h.serveCollection(w, r)
		return
	}
	h.serveItem(w, r, rest)
}

func (h *TenantMembersAdminHandler) serveCollection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.search.ServeHTTP(w, r)
	case http.MethodPost:
		h.addByEmail(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED",
			"GET or POST only on /api/v1/admin/tenant-members")
	}
}

func (h *TenantMembersAdminHandler) serveItem(w http.ResponseWriter, r *http.Request, rest string) {
	parts := strings.Split(rest, "/")
	if len(parts) == 1 {
		// Bare /{gcid} — member-centric remove (WS2b / CHO-1869). DELETE only.
		if r.Method != http.MethodDelete {
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED",
				"DELETE only on /api/v1/admin/tenant-members/{gcid}")
			return
		}
		h.removeMember(w, r, parts[0])
		return
	}
	if len(parts) != 2 {
		writeError(w, http.StatusNotFound, "IDENTITY_NOT_FOUND",
			"path must be /api/v1/admin/tenant-members/{gcid} or /{gcid}/role|roles|display-name")
		return
	}
	switch parts[1] {
	case "role":
		if r.Method != http.MethodPatch {
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED",
				"PATCH only on /api/v1/admin/tenant-members/{gcid}/role")
			return
		}
		h.changeRole(w, r, parts[0])
	case "roles":
		// CHO-1809 follow-up — multi-role REPLACE editor. PUT with a
		// full role-set body; chora-tenancy soft-deletes the diff.
		if r.Method != http.MethodPut {
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED",
				"PUT only on /api/v1/admin/tenant-members/{gcid}/roles")
			return
		}
		h.setRoles(w, r, parts[0])
	case "display-name":
		// CHO-1817 follow-up — admin patches a member's display name.
		if r.Method != http.MethodPatch {
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED",
				"PATCH only on /api/v1/admin/tenant-members/{gcid}/display-name")
			return
		}
		h.setDisplayName(w, r, parts[0])
	default:
		writeError(w, http.StatusNotFound, "IDENTITY_NOT_FOUND",
			"path must be /api/v1/admin/tenant-members/{gcid}/role, /roles or /display-name")
	}
}

// adminGate resolves the caller's tenant + enforces the admin role gate.
// Returns ("", false) after writing the error response when the gate fails.
func adminGate(w http.ResponseWriter, r *http.Request) (string, bool) {
	tenantID := strings.TrimSpace(r.Header.Get(servicemesh.HeaderTenantID))
	if tenantID == "" {
		tenantID = strings.TrimSpace(r.Header.Get("X-Tenant-Id"))
	}
	if tenantID == "" {
		writeError(w, http.StatusUnauthorized, "AUTH_TENANT_CONTEXT_MISSING",
			"tenant context not propagated (gateway must stamp chora-tenant-id)")
		return "", false
	}
	if !callerHoldsAdminRole(r) {
		writeError(w, http.StatusForbidden, "AUTH_INSUFFICIENT_ROLE",
			"caller must hold TRAINING_ADMIN or TENANT_ADMIN to manage tenant members")
		return "", false
	}
	return tenantID, true
}

// canonicalRoleAliases maps JWT-canonical role TOKENS that are not themselves
// membership_role values onto the membership_role they grant (CHO-1870 / WS1):
//   - TRAINING_ADMIN is a UI label over `instructor` (role_catalog mig 0014
//     documents it but nothing JWT-stamps it; an instructor membership already
//     passes every downstream gate — hasOfferingAdminRole, the member-admin
//     adminGate, the FE canManage).
//   - TENANT_ADMIN is the canonical token for the tenant admin and grants
//     `admin` (defensive synonym; the FE picker only surfaces TRAINING_ADMIN).
//
// OWNER / PLATFORM_OPERATOR / SUPPORT_AGENT are intentionally ABSENT — they are
// JWT-only roles with no membership_role representation and stay non-grantable.
var canonicalRoleAliases = map[string]identity.Role{
	"TRAINING_ADMIN": identity.RoleInstructor,
	"TENANT_ADMIN":   identity.RoleAdmin,
}

// grantableRole maps the canonical UPPERCASE API role onto the lowercase
// single-role membership ENUM, resolving the TRAINING_ADMIN / TENANT_ADMIN
// label aliases first. OWNER / PLATFORM_OPERATOR / SUPPORT_AGENT are not
// membership_role values and are rejected.
func grantableRole(canonical string) (identity.Role, bool) {
	token := strings.ToUpper(strings.TrimSpace(canonical))
	if aliased, ok := canonicalRoleAliases[token]; ok {
		return aliased, true
	}
	role := identity.Role(strings.ToLower(token))
	if !role.Grantable() {
		return "", false
	}
	return role, true
}

type addTenantMemberRequest struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

type tenantMemberSummaryDTO struct {
	Gcid         string    `json:"gcid"`
	Email        string    `json:"email"`
	DisplayName  string    `json:"display_name"`
	Roles        []string  `json:"roles"`
	LastActiveAt time.Time `json:"last_active_at"`
}

// memberMultiRoleSummary builds the same tenantMemberSummaryDTO as
// memberSummary but with the FULL active role set (CHO-1809 multi-role).
// Roles are emitted UPPERCASE to match the wire contract.
func memberMultiRoleSummary(u *identity.User, roles []identity.Role) tenantMemberSummaryDTO {
	upper := make([]string, 0, len(roles))
	for _, r := range roles {
		upper = append(upper, strings.ToUpper(string(r)))
	}
	return tenantMemberSummaryDTO{
		Gcid:         u.Gcid,
		Email:        u.Email,
		DisplayName:  u.DisplayName,
		Roles:        upper,
		LastActiveAt: time.Now().UTC(),
	}
}

func memberSummary(u *identity.User, role identity.Role) tenantMemberSummaryDTO {
	return tenantMemberSummaryDTO{
		Gcid:         u.Gcid,
		Email:        u.Email,
		DisplayName:  u.DisplayName,
		Roles:        []string{strings.ToUpper(string(role))},
		LastActiveAt: u.UpdatedAt,
	}
}

func (h *TenantMembersAdminHandler) addByEmail(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := adminGate(w, r)
	if !ok {
		return
	}
	var req addTenantMemberRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "IDENTITY_INVALID_BODY", err.Error())
		return
	}
	if strings.TrimSpace(req.Email) == "" {
		writeError(w, http.StatusBadRequest, "IDENTITY_INVALID_BODY", "email is required")
		return
	}
	role, ok := grantableRole(req.Role)
	if !ok {
		writeError(w, http.StatusBadRequest, "IDENTITY_INVALID_ROLE",
			"role must be one of LEARNER, AUTHOR, INSTRUCTOR, ADMIN, AUDITOR, TRAINING_ADMIN")
		return
	}

	u, found, err := h.users.FindByEmail(r.Context(), req.Email)
	if err != nil {
		log.Printf("tenant-members add: FindByEmail error: %v", err)
		writeError(w, http.StatusInternalServerError, "IDENTITY_REPO_ERROR", "failed to resolve email")
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "IDENTITY_USER_NOT_FOUND",
			"no user with that email — they must register before being added")
		return
	}
	if identity.IsAGID(u.Gcid) {
		writeError(w, http.StatusBadRequest, "IDENTITY_AGID_REJECTED",
			"agent identifiers (AGID) cannot hold a TenantMembership")
		return
	}

	// Authoritative write FIRST (ADR-182): chora_tenancy.members via the
	// tenancy UpsertMembership gRPC. The mint reads the authoritative
	// store, so skipping this write produced members who could never log
	// in to the tenant (the original CHO-1707 bug).
	if h.authoritative != nil {
		created, err := h.authoritative.UpsertMembershipByTenantID(
			r.Context(), u.Gcid, tenantID, []string{string(role)})
		if err != nil {
			switch {
			case errors.Is(err, ErrUpstreamMembershipSuspended):
				writeError(w, http.StatusConflict, "IDENTITY_MEMBERSHIP_SUSPENDED",
					"membership is suspended — un-suspend explicitly instead of re-adding")
			case errors.Is(err, ErrUpstreamTenantNotFound):
				writeError(w, http.StatusNotFound, "IDENTITY_TENANT_NOT_FOUND",
					"target tenant not found or not active")
			default:
				log.Printf("tenant-members add: tenancy UpsertMembership error: %v", err)
				writeError(w, http.StatusBadGateway, "IDENTITY_TENANCY_ERROR",
					"authoritative membership write failed")
			}
			return
		}
		if !created {
			writeError(w, http.StatusConflict, "IDENTITY_MEMBERSHIP_DUPLICATE",
				"membership already exists for (gcid, tenant_id, role)")
			return
		}
	}

	if err := h.members.AddMembership(r.Context(), u.Gcid, tenantID, role); err != nil {
		switch {
		case errors.Is(err, identity.ErrMembershipExists) && h.authoritative != nil:
			// Authoritative store created the row but the mirror already
			// has it — drift, tolerated; the upsert self-heals.
			log.Printf("tenant-members add: mirror drift for (gcid=%s, tenant=%s, role=%s) — tolerated", u.Gcid, tenantID, role)
		case errors.Is(err, identity.ErrMembershipExists):
			writeError(w, http.StatusConflict, "IDENTITY_MEMBERSHIP_DUPLICATE",
				"membership already exists for (gcid, tenant_id)")
			return
		default:
			log.Printf("tenant-members add: AddMembership error: %v", err)
			writeError(w, http.StatusInternalServerError, "IDENTITY_REPO_ERROR", "failed to persist membership")
			return
		}
	}
	writeJSON(w, http.StatusCreated, memberSummary(u, role))
}

// removeMember soft-deletes EVERY role for (gcid, caller-tenant) — the
// member-centric revoke (WS2b / CHO-1869, owner-decided gcid semantics).
// Authoritative-first (chora_tenancy, what the mint reads → revokes login),
// then the identity mirror (the roster source). NEVER hard-deletes. A member
// removed from a non-master tenant keeps their chora-master baseline (ADR-182);
// removing from chora-master itself just re-auto-enrols at next resolve.
func (h *TenantMembersAdminHandler) removeMember(w http.ResponseWriter, r *http.Request, gcid string) {
	tenantID, ok := adminGate(w, r)
	if !ok {
		return
	}

	// Authoritative removal first: the JWT mint reads chora_tenancy.members,
	// so this is what actually stops the member logging in to the tenant.
	authoritativeRemoved := false
	if h.authoritative != nil {
		if err := h.authoritative.RemoveMembershipByTenantID(r.Context(), gcid, tenantID); err != nil {
			// S7-B1: the last-owner refusal is its own 409, never the
			// suspension one; the two need different actions from the admin.
			if writeOwnerRefusal(w, err) {
				return
			}
			switch {
			case errors.Is(err, ErrUpstreamMembershipSuspended):
				writeError(w, http.StatusConflict, "IDENTITY_MEMBERSHIP_SUSPENDED",
					"membership is suspended — un-suspend before removing it")
			case errors.Is(err, ErrUpstreamMembershipNotFound):
				// Cross-tenant memberships are never confirmable — absent reads
				// the same as a member outside the caller's tenant.
				writeError(w, http.StatusNotFound, "IDENTITY_MEMBERSHIP_NOT_FOUND",
					"no membership for (gcid, caller tenant)")
			case errors.Is(err, ErrUpstreamTenantNotFound):
				writeError(w, http.StatusNotFound, "IDENTITY_TENANT_NOT_FOUND",
					"target tenant not found or not active")
			default:
				log.Printf("tenant-members remove: tenancy RemoveMembership error: %v", err)
				writeError(w, http.StatusBadGateway, "IDENTITY_TENANCY_ERROR",
					"authoritative membership removal failed")
			}
			return
		}
		authoritativeRemoved = true
	}

	// Identity mirror soft-delete (the roster read source).
	if err := h.members.RemoveMember(r.Context(), gcid, tenantID); err != nil {
		// The mirror carries the same guards, and in dev (no tenancy client)
		// it is the only one that ran.
		if writeOwnerRefusal(w, err) {
			return
		}
		if errors.Is(err, identity.ErrMembershipNotFound) {
			// Authoritative already removed but the mirror had no live row —
			// drift, tolerated (the removal is complete). Without an
			// authoritative store (dev) an absent mirror row is a genuine 404.
			if authoritativeRemoved {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			writeError(w, http.StatusNotFound, "IDENTITY_MEMBERSHIP_NOT_FOUND",
				"no membership for (gcid, caller tenant)")
			return
		}
		// Mirror write failed after the authoritative removal succeeded: the
		// member can no longer log in (the security boundary held); the roster
		// self-heals on the next sync. Log loudly, still 204.
		if authoritativeRemoved {
			log.Printf("tenant-members remove: mirror RemoveMember drift (authoritative removed): %v", err)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		log.Printf("tenant-members remove: RemoveMember error: %v", err)
		writeError(w, http.StatusInternalServerError, "IDENTITY_REPO_ERROR", "failed to remove member")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type changeTenantMemberRoleRequest struct {
	Role string `json:"role"`
}

func (h *TenantMembersAdminHandler) changeRole(w http.ResponseWriter, r *http.Request, gcid string) {
	tenantID, ok := adminGate(w, r)
	if !ok {
		return
	}
	var req changeTenantMemberRoleRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "IDENTITY_INVALID_BODY", err.Error())
		return
	}
	role, ok := grantableRole(req.Role)
	if !ok {
		writeError(w, http.StatusBadRequest, "IDENTITY_INVALID_ROLE",
			"role must be one of LEARNER, AUTHOR, INSTRUCTOR, ADMIN, AUDITOR, TRAINING_ADMIN")
		return
	}

	if err := h.members.ChangeRole(r.Context(), gcid, tenantID, role); err != nil {
		// S7-B1: this route writes the mirror FIRST and only then makes a
		// best-effort ADDITIVE authoritative call, so the chora-tenancy guard
		// never sees it. The mirror's refusal is the only one there is.
		if writeOwnerRefusal(w, err) {
			return
		}
		if errors.Is(err, identity.ErrMembershipNotFound) {
			// Cross-tenant membership ids are never confirmable — a
			// membership outside the caller's tenant reads as absent.
			writeError(w, http.StatusNotFound, "IDENTITY_MEMBERSHIP_NOT_FOUND",
				"no membership for (gcid, caller tenant)")
			return
		}
		log.Printf("tenant-members role: ChangeRole error: %v", err)
		writeError(w, http.StatusInternalServerError, "IDENTITY_REPO_ERROR", "failed to change role")
		return
	}

	// Authoritative-parity sync (additive). The mirror is now correct; the
	// JWT mint reads from chora_tenancy.members, so without this call the
	// new role would be invisible at sign-in. UpsertMembership is ADDITIVE
	// — old role rows in chora_tenancy stay active. With the FE multi-role
	// display the resulting JWT carries BOTH roles, which is the right
	// behaviour for a multi-role membership model (CHO-1809). A future
	// strict-replace flavour (deactivate other roles) would need a new RPC
	// — out of this PR's scope; tracked as a follow-up to the original
	// ADR-182 TODO above.
	//
	// Best-effort: if the authoritative upsert fails, log + still return
	// success (the identity mirror IS updated; an admin retry self-heals).
	// Not fatal because the FE roster reads from the mirror and would show
	// the new role even if the JWT-side write was momentarily down.
	if h.authoritative != nil {
		if _, err := h.authoritative.UpsertMembershipByTenantID(
			r.Context(), gcid, tenantID, []string{string(role)},
		); err != nil {
			log.Printf("tenant-members role: authoritative UpsertMembership error (mirror updated; JWT-side stale): %v", err)
		}
	}

	u, err := h.users.GetByGcid(r.Context(), gcid)
	if err != nil {
		// Role change persisted; the enrichment read failing is a 500 —
		// the FE retries the roster read.
		log.Printf("tenant-members role: GetByGcid after change: %v", err)
		writeError(w, http.StatusInternalServerError, "IDENTITY_REPO_ERROR", "role changed but member read failed")
		return
	}
	writeJSON(w, http.StatusOK, memberSummary(u, role))
}

// setTenantMemberRolesRequest is the wire shape for PUT
// /api/v1/admin/tenant-members/{gcid}/roles — CHO-1809 multi-role REPLACE
// editor. Roles arrive UPPERCASE (canonical, ADR-141); duplicates and case
// drift are tolerated and de-duplicated server-side.
type setTenantMemberRolesRequest struct {
	Roles []string `json:"roles"`
}

func (h *TenantMembersAdminHandler) setRoles(w http.ResponseWriter, r *http.Request, gcid string) {
	tenantID, ok := adminGate(w, r)
	if !ok {
		return
	}
	var req setTenantMemberRolesRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "IDENTITY_INVALID_BODY", err.Error())
		return
	}
	if len(req.Roles) == 0 {
		writeError(w, http.StatusBadRequest, "IDENTITY_INVALID_ROLE",
			"at least one role required (use DELETE /tenant-members/{gcid} to revoke)")
		return
	}
	// Validate + canonicalise + de-dupe. Order-insensitive on the wire.
	seen := make(map[identity.Role]bool, len(req.Roles))
	canonical := make([]identity.Role, 0, len(req.Roles))
	canonicalUpper := make([]string, 0, len(req.Roles))
	for _, raw := range req.Roles {
		role, ok := grantableRole(raw)
		if !ok {
			writeError(w, http.StatusBadRequest, "IDENTITY_INVALID_ROLE",
				"role must be one of LEARNER, AUTHOR, INSTRUCTOR, ADMIN, AUDITOR, TRAINING_ADMIN")
			return
		}
		if seen[role] {
			continue
		}
		seen[role] = true
		canonical = append(canonical, role)
		canonicalUpper = append(canonicalUpper, strings.ToUpper(string(role)))
	}

	// Authoritative-first (ADR-182 pattern): chora_tenancy.members REPLACE
	// via the tenancy UpsertMembership(replace_existing=true) RPC. The JWT
	// mint reads the authoritative store, so without this the new role set
	// would be invisible at sign-in.
	if h.authoritative != nil {
		if _, err := h.authoritative.ReplaceMembershipByTenantID(
			r.Context(), gcid, tenantID, canonicalUpper,
		); err != nil {
			if writeOwnerRefusal(w, err) {
				return
			}
			switch {
			case errors.Is(err, ErrUpstreamMembershipSuspended):
				writeError(w, http.StatusConflict, "IDENTITY_MEMBERSHIP_SUSPENDED",
					"membership is suspended — un-suspend explicitly instead of replacing roles")
			case errors.Is(err, ErrUpstreamTenantNotFound):
				writeError(w, http.StatusNotFound, "IDENTITY_TENANT_NOT_FOUND",
					"target tenant not found or not active")
			default:
				log.Printf("tenant-members roles: tenancy ReplaceMembership error: %v", err)
				writeError(w, http.StatusBadGateway, "IDENTITY_TENANCY_ERROR",
					"authoritative role-set write failed")
			}
			return
		}
	}

	// Identity mirror REPLACE — same set in the chora_identity table so
	// the Members roster reads agree with the authoritative store.
	if err := h.members.SetRoles(r.Context(), gcid, tenantID, canonical); err != nil {
		if writeOwnerRefusal(w, err) {
			return
		}
		if errors.Is(err, identity.ErrMembershipNotFound) {
			writeError(w, http.StatusNotFound, "IDENTITY_MEMBERSHIP_NOT_FOUND",
				"no membership for (gcid, caller tenant)")
			return
		}
		log.Printf("tenant-members roles: SetRoles error: %v", err)
		writeError(w, http.StatusInternalServerError, "IDENTITY_REPO_ERROR", "failed to replace roles")
		return
	}

	u, err := h.users.GetByGcid(r.Context(), gcid)
	if err != nil {
		log.Printf("tenant-members roles: GetByGcid after replace: %v", err)
		writeError(w, http.StatusInternalServerError, "IDENTITY_REPO_ERROR", "roles replaced but member read failed")
		return
	}
	writeJSON(w, http.StatusOK, memberMultiRoleSummary(u, canonical))
}

// setTenantMemberDisplayNameRequest is the wire shape for PATCH
// /api/v1/admin/tenant-members/{gcid}/display-name (CHO-1817 follow-up).
type setTenantMemberDisplayNameRequest struct {
	DisplayName string `json:"display_name"`
}

const maxDisplayNameLength = 128

func (h *TenantMembersAdminHandler) setDisplayName(w http.ResponseWriter, r *http.Request, gcid string) {
	actingTenantID, ok := adminGate(w, r)
	if !ok {
		return
	}
	var req setTenantMemberDisplayNameRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "IDENTITY_INVALID_BODY", err.Error())
		return
	}
	name := strings.TrimSpace(req.DisplayName)
	if name == "" {
		writeError(w, http.StatusBadRequest, "IDENTITY_INVALID_DISPLAY_NAME",
			"display_name must not be empty")
		return
	}
	if len(name) > maxDisplayNameLength {
		writeError(w, http.StatusBadRequest, "IDENTITY_INVALID_DISPLAY_NAME",
			fmt.Sprintf("display_name must be %d characters or fewer", maxDisplayNameLength))
		return
	}

	if err := h.users.UpdateDisplayName(r.Context(), gcid, name, actingTenantID); err != nil {
		if errors.Is(err, identity.ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "IDENTITY_USER_NOT_FOUND", "no user with that GCID")
			return
		}
		log.Printf("tenant-members display-name: UpdateDisplayName error: %v", err)
		writeError(w, http.StatusInternalServerError, "IDENTITY_REPO_ERROR", "failed to update display name")
		return
	}

	u, err := h.users.GetByGcid(r.Context(), gcid)
	if err != nil {
		log.Printf("tenant-members display-name: GetByGcid after update: %v", err)
		writeError(w, http.StatusInternalServerError, "IDENTITY_REPO_ERROR",
			"display name updated but member read failed")
		return
	}
	// Reply with the same shape as the role mutations — roles[] left
	// empty here on purpose; the FE refreshes its row from the new
	// display_name + leaves the existing role chips intact.
	writeJSON(w, http.StatusOK, tenantMemberSummaryDTO{
		Gcid:         u.Gcid,
		Email:        u.Email,
		DisplayName:  u.DisplayName,
		Roles:        nil,
		LastActiveAt: time.Now().UTC(),
	})
}
