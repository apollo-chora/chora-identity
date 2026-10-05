// tenant_invites_handler.go — WS3 / CHO-1873 (ADR-194 D2): the cold-invite
// admin API.
//
//	POST   /api/v1/admin/tenant-invites              createTenantInvite
//	GET    /api/v1/admin/tenant-invites              listTenantInvites
//	DELETE /api/v1/admin/tenant-invites/{inviteId}   revokeTenantInvite
//
// POST unifies add-by-email with cold-invite and RETIRES the
// addTenantMemberByEmail 404 IDENTITY_USER_NOT_FOUND dead-end:
//
//   - the email already maps to a GCID → grant the membership NOW (authoritative
//     chora_tenancy write + identity mirror, exactly like the WS2 grant), 201
//     {kind:"granted", ...};
//   - the email has never registered → persist a `pending` invite, 201
//     {kind:"invited", ...}. The resolve seam (pending_invite_applier.go)
//     auto-applies it at first login (ADR-194 D2).
//
// Gate selection follows the BODY shape (the WS2/WS1 split):
//
//   - body carries tenant_id → operator cross-tenant invite — operatorGate
//     (PLATFORM_OPERATOR only, ADR-165), target tenant = body.tenant_id. This is
//     the WS6 path (operator cold-invites into chora-master / any tenant);
//   - no body tenant_id → tenant-scoped admin — adminGate (TRAINING_ADMIN /
//     TENANT_ADMIN / …), target tenant = the mesh header.
//
// GET + DELETE are tenant-scoped admin only (adminGate; tenant from the header).
// RLS stays ENFORCED everywhere — the pg store wraps every write in
// RunInTenantTx(tenant); this is NOT a bypass surface (ADR-194 D2).
package httpadapter

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/apollo-chora/chora-common/auth/servicemesh"
	"github.com/apollo-chora/chora-identity/internal/adapter/events"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// PendingInviteStore is the admin-side cold-invite persistence port (the pg
// PendingInviteRepository satisfies it). The resolve-time matcher
// (PendingInviteMatcher) is a separate, read-mostly port.
type PendingInviteStore interface {
	Insert(ctx context.Context, pi *identity.PendingInvite) error
	ListByTenant(ctx context.Context, tenantID string) ([]identity.PendingInvite, error)
	Revoke(ctx context.Context, tenantID, inviteID string) error
}

// TenantInvitesHandler serves /api/v1/admin/tenant-invites (+ the /{inviteId}
// item path). Reuses the WS1/WS2 machinery: AdminUserFinder (email→gcid),
// AuthoritativeMembershipUpserter + GrantMembershipWriter (grant-now), and the
// optional GrantAuditEmitter (IMDA-D1 on the operator cross-tenant grant).
type TenantInvitesHandler struct {
	users         AdminUserFinder
	grant         GrantMembershipWriter
	authoritative AuthoritativeMembershipUpserter // nil in dev (no tenancy conn)
	invites       PendingInviteStore
	audit         GrantAuditEmitter // nil-tolerant (best-effort)
}

// NewTenantInvitesHandler constructs the handler.
func NewTenantInvitesHandler(users AdminUserFinder, grant GrantMembershipWriter, authoritative AuthoritativeMembershipUpserter, invites PendingInviteStore, audit GrantAuditEmitter) *TenantInvitesHandler {
	return &TenantInvitesHandler{users: users, grant: grant, authoritative: authoritative, invites: invites, audit: audit}
}

const tenantInvitesBasePath = "/api/v1/admin/tenant-invites"

// ServeHTTP routes the collection path (GET list / POST create) and the
// /{inviteId} item path (DELETE revoke). Mount the handler at the base path AND
// the base path + "/".
func (h *TenantInvitesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, tenantInvitesBasePath), "/")
	if rest == "" {
		switch r.Method {
		case http.MethodGet:
			h.list(w, r)
		case http.MethodPost:
			h.create(w, r)
		default:
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED",
				"GET or POST only on /api/v1/admin/tenant-invites")
		}
		return
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 1 {
		writeError(w, http.StatusNotFound, "IDENTITY_NOT_FOUND",
			"path must be /api/v1/admin/tenant-invites/{inviteId}")
		return
	}
	if r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED",
			"DELETE only on /api/v1/admin/tenant-invites/{inviteId}")
		return
	}
	h.revoke(w, r, parts[0])
}

type createTenantInviteRequest struct {
	Email    string   `json:"email"`
	TenantID string   `json:"tenant_id"`
	Roles    []string `json:"roles"`
}

type grantedInviteDTO struct {
	Kind         string    `json:"kind"` // "granted"
	MembershipID string    `json:"membership_id"`
	Gcid         string    `json:"gcid"`
	TenantID     string    `json:"tenant_id"`
	Roles        []string  `json:"roles"`
	GrantedAt    time.Time `json:"granted_at"`
}

type pendingInviteDTO struct {
	Kind      string    `json:"kind,omitempty"` // "invited" on create; omitted in list items
	InviteID  string    `json:"invite_id"`
	Email     string    `json:"email"`
	TenantID  string    `json:"tenant_id"`
	Roles     []string  `json:"roles"`
	Status    string    `json:"status"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

type listInvitesResponse struct {
	Items []pendingInviteDTO `json:"items"`
}

func (h *TenantInvitesHandler) create(w http.ResponseWriter, r *http.Request) {
	var req createTenantInviteRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "IDENTITY_INVALID_BODY", err.Error())
		return
	}
	req.Email = strings.TrimSpace(req.Email)
	bodyTenant := strings.TrimSpace(req.TenantID)

	// Gate by body shape: a body tenant_id ⇒ operator cross-tenant invite
	// (PLATFORM_OPERATOR only, tenant from body); else tenant-scoped admin
	// (tenant from the mesh header). A non-operator caller naming a body tenant
	// is rejected 403 by operatorGate (the WS3 cross-tenant escalation guard).
	var tenantID, callerGcid string
	crossTenant := bodyTenant != ""
	if crossTenant {
		gcid, ok := operatorGate(w, r)
		if !ok {
			return
		}
		callerGcid = gcid
		tenantID = bodyTenant
	} else {
		t, ok := adminGate(w, r)
		if !ok {
			return
		}
		tenantID = t
		callerGcid = strings.TrimSpace(r.Header.Get(servicemesh.HeaderGCID))
	}

	if req.Email == "" {
		writeError(w, http.StatusBadRequest, "IDENTITY_INVALID_BODY", "email is required")
		return
	}
	if len(req.Roles) == 0 {
		writeError(w, http.StatusUnprocessableEntity, "IDENTITY_INVALID_ROLE", "at least one role is required")
		return
	}
	canonical, lowerRoles, upperRoles, ok := canonicaliseGrantRoles(w, req.Roles)
	if !ok {
		return
	}

	u, found, err := h.users.FindByEmail(r.Context(), req.Email)
	if err != nil {
		log.Printf("tenant-invites create: FindByEmail error: %v", err)
		writeError(w, http.StatusInternalServerError, "IDENTITY_REPO_ERROR", "failed to resolve email")
		return
	}
	if found {
		h.grantNow(w, r, u, tenantID, canonical, lowerRoles, upperRoles, callerGcid, crossTenant)
		return
	}
	h.persistPending(w, r, req.Email, tenantID, canonical, callerGcid)
}

// grantNow applies an existing user's membership immediately (the retired-404
// path). Mirrors the WS2 grant: authoritative chora_tenancy write first, then
// the identity mirror; IMDA-D1 evidence only on the operator cross-tenant grant.
func (h *TenantInvitesHandler) grantNow(w http.ResponseWriter, r *http.Request, u *identity.User, tenantID string, canonical []identity.Role, lowerRoles, upperRoles []string, callerGcid string, crossTenant bool) {
	if identity.IsAGID(u.Gcid) {
		writeError(w, http.StatusBadRequest, "IDENTITY_AGID_REJECTED",
			"agent identifiers (AGID) cannot hold a TenantMembership")
		return
	}
	if h.authoritative != nil {
		if _, err := h.authoritative.UpsertMembershipByTenantID(r.Context(), u.Gcid, tenantID, lowerRoles); err != nil {
			switch {
			case errors.Is(err, ErrUpstreamMembershipSuspended):
				writeError(w, http.StatusConflict, "IDENTITY_MEMBERSHIP_SUSPENDED",
					"membership is suspended — un-suspend explicitly instead of re-granting")
			case errors.Is(err, ErrUpstreamTenantNotFound):
				writeError(w, http.StatusNotFound, "IDENTITY_TENANT_NOT_FOUND",
					"target tenant not found or not active")
			default:
				log.Printf("tenant-invites grant: tenancy UpsertMembership error: %v", err)
				writeError(w, http.StatusBadGateway, "IDENTITY_TENANCY_ERROR",
					"authoritative membership write failed")
			}
			return
		}
	}
	membershipID, err := h.grant.GrantMembership(r.Context(), u.Gcid, tenantID, canonical)
	if err != nil {
		log.Printf("tenant-invites grant: GrantMembership error: %v", err)
		writeError(w, http.StatusInternalServerError, "IDENTITY_REPO_ERROR", "failed to persist membership")
		return
	}
	// IMDA-D1 accountability evidence — only on the operator cross-tenant grant
	// (ADR-194 D1). The same-tenant admin add matches addByEmail, which does not
	// audit. Best-effort AFTER the write (a completed RLS-enforced write is not
	// rolled back over an audit hiccup; the failure is logged loudly).
	if h.audit != nil && crossTenant {
		env := events.NewEnvelope(tenantID, callerGcid, r.Header.Get("traceparent"), r.Header.Get("tracestate"))
		if err := h.audit.RecordEvidence(env, events.EvidenceInput{
			EvidenceType:    "tenant_membership_granted",
			SourceEventType: "chora.identity.tenant_membership.granted.v1",
			Dimension:       "accountability",
			LifecycleStage:  "runtime",
			PolicyReference: "ADR-194 D1+D2 (operator cold-invite grant-now)",
			AdditionalFields: map[string]any{
				"operator_gcid":    callerGcid,
				"grantee_gcid":     u.Gcid,
				"target_tenant_id": tenantID,
				"granted_roles":    upperRoles,
				"cross_tenant":     true,
				"via":              "tenant_invite",
			},
		}); err != nil {
			log.Printf("tenant-invites grant: audit RecordEvidence failed (grant persisted; best-effort): %v", err)
		}
	}
	writeJSON(w, http.StatusCreated, grantedInviteDTO{
		Kind:         "granted",
		MembershipID: membershipID,
		Gcid:         u.Gcid,
		TenantID:     tenantID,
		Roles:        upperRoles,
		GrantedAt:    time.Now().UTC(),
	})
}

// persistPending records a cold invite for a never-registered email. The
// resolve seam applies it at first login.
func (h *TenantInvitesHandler) persistPending(w http.ResponseWriter, r *http.Request, email, tenantID string, canonical []identity.Role, callerGcid string) {
	pi, err := identity.NewPendingInvite(identity.NewPendingInviteParams{
		TenantID:      tenantID,
		Email:         email,
		Roles:         canonical,
		InvitedByGcid: callerGcid,
	})
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "IDENTITY_INVALID_INVITE", err.Error())
		return
	}
	if err := h.invites.Insert(r.Context(), pi); err != nil {
		if errors.Is(err, identity.ErrPendingInviteExists) {
			writeError(w, http.StatusConflict, "IDENTITY_INVITE_DUPLICATE",
				"a pending invite already exists for this email in this tenant")
			return
		}
		log.Printf("tenant-invites create: Insert error: %v", err)
		writeError(w, http.StatusInternalServerError, "IDENTITY_REPO_ERROR", "failed to persist invite")
		return
	}
	dto := pendingInviteToDTO(pi)
	dto.Kind = "invited"
	writeJSON(w, http.StatusCreated, dto)
}

func (h *TenantInvitesHandler) list(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := adminGate(w, r)
	if !ok {
		return
	}
	invites, err := h.invites.ListByTenant(r.Context(), tenantID)
	if err != nil {
		log.Printf("tenant-invites list: %v", err)
		writeError(w, http.StatusInternalServerError, "IDENTITY_REPO_ERROR", "failed to list invites")
		return
	}
	items := make([]pendingInviteDTO, 0, len(invites))
	for i := range invites {
		items = append(items, pendingInviteToDTO(&invites[i]))
	}
	writeJSON(w, http.StatusOK, listInvitesResponse{Items: items})
}

func (h *TenantInvitesHandler) revoke(w http.ResponseWriter, r *http.Request, inviteID string) {
	tenantID, ok := adminGate(w, r)
	if !ok {
		return
	}
	if err := h.invites.Revoke(r.Context(), tenantID, inviteID); err != nil {
		if errors.Is(err, identity.ErrPendingInviteNotFound) {
			writeError(w, http.StatusNotFound, "IDENTITY_INVITE_NOT_FOUND",
				"no pending invite for (invite_id, caller tenant)")
			return
		}
		log.Printf("tenant-invites revoke: %v", err)
		writeError(w, http.StatusInternalServerError, "IDENTITY_REPO_ERROR", "failed to revoke invite")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// pendingInviteToDTO projects a PendingInvite for the wire (roles UPPERCASE per
// the canonical ADR-141 contract). Kind is left empty (omitted) — the create
// path stamps "invited" explicitly.
func pendingInviteToDTO(pi *identity.PendingInvite) pendingInviteDTO {
	upper := make([]string, 0, len(pi.Roles))
	for _, role := range pi.Roles {
		upper = append(upper, strings.ToUpper(string(role)))
	}
	return pendingInviteDTO{
		InviteID:  pi.InviteID,
		Email:     pi.Email,
		TenantID:  pi.TenantID,
		Roles:     upper,
		Status:    string(pi.Status),
		ExpiresAt: pi.ExpiresAt,
		CreatedAt: pi.CreatedAt,
	}
}

// canonicaliseGrantRoles validates + canonicalises the role set (TRAINING_ADMIN
// → instructor; OWNER / PLATFORM_OPERATOR are not grantable → 422). De-dupes,
// order-insensitive. Returns the domain Roles, the lowercase membership tokens
// (authoritative write), the UPPERCASE wire tokens, and ok=false after writing
// the 422 on an invalid role. Shared by create's grant-now + pending paths.
func canonicaliseGrantRoles(w http.ResponseWriter, raw []string) (canonical []identity.Role, lower, upper []string, ok bool) {
	seen := make(map[identity.Role]bool, len(raw))
	canonical = make([]identity.Role, 0, len(raw))
	lower = make([]string, 0, len(raw))
	upper = make([]string, 0, len(raw))
	for _, rr := range raw {
		role, valid := grantableRole(rr)
		if !valid {
			writeError(w, http.StatusUnprocessableEntity, "IDENTITY_INVALID_ROLE",
				"role must be one of LEARNER, AUTHOR, INSTRUCTOR, ADMIN, AUDITOR, TRAINING_ADMIN")
			return nil, nil, nil, false
		}
		if seen[role] {
			continue
		}
		seen[role] = true
		canonical = append(canonical, role)
		lower = append(lower, string(role))
		upper = append(upper, strings.ToUpper(string(role)))
	}
	return canonical, lower, upper, true
}
