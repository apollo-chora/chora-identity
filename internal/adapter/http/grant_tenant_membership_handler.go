// grant_tenant_membership_handler.go — WS2 / CHO-1872 (ADR-194 D1).
//
// POST /api/v1/admin/tenant-memberships — the operator cross-tenant
// membership grant. Contract: chora-contracts/openapi/identity-admin.yaml
// ::grantTenantMembership (body {gcid, tenant_id, roles[]}).
//
// Distinct from tenant_members_admin_handler.go (the tenant-scoped member
// admin):
//   - caller MUST hold PLATFORM_OPERATOR (ADR-165 — the sole cross-tenant
//     principal). The admin gate is NOT reused: it accepts
//     instructor/admin/training_admin/tenant_admin/owner, none of which may
//     write into an arbitrary tenant.
//   - the tenant comes from the BODY, never the mesh header.
//   - the mirror write runs inside RunInTenantTx(body.tenant_id) (automatic in
//     the pg GrantMembership repo) — RLS stays ENFORCED (the row's tenant_id
//     equals the chora.tenant_id GUC, so tenant_isolation passes). This is
//     operator cross-tenant AUTHORIZATION, NOT an RLS bypass: it never sets
//     row_security=off and is explicitly NOT a 4th surface on the
//     ADR-165/184/192 bypass chain (ADR-194 D1).
//   - grant is idempotent (re-granting an existing role set is 201, not 409);
//     emits IMDA-D1 accountability evidence per grant.
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

// GrantMembershipWriter upserts a multi-role membership for (gcid, tenant) and
// returns a representative active membership_id. Additive + idempotent (a role
// that already exists active is a no-op; an inactive role is reactivated). The
// pg implementation wraps the writes in RunInTenantTx(tenantID).
type GrantMembershipWriter interface {
	GrantMembership(ctx context.Context, gcid, tenantID string, roles []identity.Role) (membershipID string, err error)
}

// GrantAuditEmitter records the IMDA-D1 accountability evidence for a
// cross-tenant grant. Satisfied by *events.GovernancePublisher.
type GrantAuditEmitter interface {
	RecordEvidence(env events.Envelope, in events.EvidenceInput) error
}

// GrantTenantMembershipHandler serves POST /api/v1/admin/tenant-memberships.
type GrantTenantMembershipHandler struct {
	users         AdminUserFinder
	grant         GrantMembershipWriter
	authoritative AuthoritativeMembershipUpserter // nil in dev (no tenancy conn)
	audit         GrantAuditEmitter               // nil-tolerant (best-effort)
}

// NewGrantTenantMembershipHandler constructs the handler.
func NewGrantTenantMembershipHandler(users AdminUserFinder, grant GrantMembershipWriter, authoritative AuthoritativeMembershipUpserter, audit GrantAuditEmitter) *GrantTenantMembershipHandler {
	return &GrantTenantMembershipHandler{users: users, grant: grant, authoritative: authoritative, audit: audit}
}

// callerHoldsOperatorRole reports whether the mesh role header carries
// PLATFORM_OPERATOR (case-insensitive). Unlike callerHoldsAdminRole this
// accepts ONLY the operator role — the cross-tenant grant must never be
// reachable by a tenant-scoped admin.
func callerHoldsOperatorRole(r *http.Request) bool {
	hdr := strings.TrimSpace(r.Header.Get(servicemesh.HeaderUserRoles))
	if hdr == "" {
		return false
	}
	for _, part := range strings.Split(hdr, ",") {
		if strings.ToUpper(strings.TrimSpace(part)) == string(identity.CanonicalRolePlatformOperator) {
			return true
		}
	}
	return false
}

// operatorGate enforces PLATFORM_OPERATOR + returns the caller's gcid (for the
// accountability audit). Writes the 403 + returns ("", false) on failure.
func operatorGate(w http.ResponseWriter, r *http.Request) (string, bool) {
	if !callerHoldsOperatorRole(r) {
		writeError(w, http.StatusForbidden, "AUTH_INSUFFICIENT_ROLE",
			"caller must hold PLATFORM_OPERATOR to grant a cross-tenant membership")
		return "", false
	}
	return strings.TrimSpace(r.Header.Get(servicemesh.HeaderGCID)), true
}

type grantTenantMembershipRequest struct {
	Gcid     string   `json:"gcid"`
	TenantID string   `json:"tenant_id"`
	Roles    []string `json:"roles"`
}

type grantedMembershipDTO struct {
	MembershipID string    `json:"membership_id"`
	Gcid         string    `json:"gcid"`
	TenantID     string    `json:"tenant_id"`
	Roles        []string  `json:"roles"`
	GrantedAt    time.Time `json:"granted_at"`
}

func (h *GrantTenantMembershipHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED",
			"POST only on /api/v1/admin/tenant-memberships")
		return
	}
	operatorGcid, ok := operatorGate(w, r)
	if !ok {
		return
	}

	var req grantTenantMembershipRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "IDENTITY_INVALID_BODY", err.Error())
		return
	}
	req.Gcid = strings.TrimSpace(req.Gcid)
	req.TenantID = strings.TrimSpace(req.TenantID)
	if req.Gcid == "" || req.TenantID == "" {
		writeError(w, http.StatusBadRequest, "IDENTITY_INVALID_BODY", "gcid and tenant_id are required")
		return
	}
	if len(req.Roles) == 0 {
		writeError(w, http.StatusUnprocessableEntity, "IDENTITY_INVALID_ROLE", "at least one role is required")
		return
	}
	if identity.IsAGID(req.Gcid) {
		writeError(w, http.StatusBadRequest, "IDENTITY_AGID_REJECTED",
			"agent identifiers (AGID) cannot hold a TenantMembership")
		return
	}

	// Validate + canonicalise the role set (TRAINING_ADMIN -> instructor etc.;
	// OWNER / PLATFORM_OPERATOR are not grantable). De-dupe, order-insensitive.
	seen := make(map[identity.Role]bool, len(req.Roles))
	canonical := make([]identity.Role, 0, len(req.Roles))
	lowerRoles := make([]string, 0, len(req.Roles))
	upperRoles := make([]string, 0, len(req.Roles))
	for _, raw := range req.Roles {
		role, ok := grantableRole(raw)
		if !ok {
			writeError(w, http.StatusUnprocessableEntity, "IDENTITY_INVALID_ROLE",
				"role must be one of LEARNER, AUTHOR, INSTRUCTOR, ADMIN, AUDITOR, TRAINING_ADMIN")
			return
		}
		if seen[role] {
			continue
		}
		seen[role] = true
		canonical = append(canonical, role)
		lowerRoles = append(lowerRoles, string(role))
		upperRoles = append(upperRoles, strings.ToUpper(string(role)))
	}

	// Grantee must be a real GCID (not an orphan reference). Cross-tenant
	// portable — the users table is not tenant-scoped.
	if _, err := h.users.GetByGcid(r.Context(), req.Gcid); err != nil {
		if errors.Is(err, identity.ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "IDENTITY_USER_NOT_FOUND", "no user with that gcid")
			return
		}
		log.Printf("grant-membership: GetByGcid error: %v", err)
		writeError(w, http.StatusInternalServerError, "IDENTITY_REPO_ERROR", "failed to resolve grantee")
		return
	}

	// Authoritative write FIRST (ADR-182): chora_tenancy.members via the
	// tenancy UpsertMembership gRPC (additive). The mint reads the
	// authoritative store, so a mirror-only grant would produce a member who
	// can never log in to the tenant. Roles on the wire are lowercase
	// membership_role tokens (WS1 parity). `created` is ignored — the operator
	// grant is idempotent (re-granting is success, not a 409).
	if h.authoritative != nil {
		if _, err := h.authoritative.UpsertMembershipByTenantID(r.Context(), req.Gcid, req.TenantID, lowerRoles); err != nil {
			switch {
			case errors.Is(err, ErrUpstreamMembershipSuspended):
				writeError(w, http.StatusConflict, "IDENTITY_MEMBERSHIP_SUSPENDED",
					"membership is suspended — un-suspend explicitly instead of re-granting")
			case errors.Is(err, ErrUpstreamTenantNotFound):
				writeError(w, http.StatusNotFound, "IDENTITY_TENANT_NOT_FOUND",
					"target tenant not found or not active")
			default:
				log.Printf("grant-membership: tenancy UpsertMembership error: %v", err)
				writeError(w, http.StatusBadGateway, "IDENTITY_TENANCY_ERROR",
					"authoritative membership write failed")
			}
			return
		}
	}

	// Identity mirror — runs inside RunInTenantTx(req.TenantID) in the pg repo
	// (RLS-enforced; the row's tenant == the GUC). Returns a representative
	// active membership_id for the response.
	membershipID, err := h.grant.GrantMembership(r.Context(), req.Gcid, req.TenantID, canonical)
	if err != nil {
		log.Printf("grant-membership: GrantMembership error: %v", err)
		writeError(w, http.StatusInternalServerError, "IDENTITY_REPO_ERROR", "failed to persist membership")
		return
	}

	// IMDA-D1 accountability evidence (ADR-194 D1). Best-effort AFTER the
	// write: a completed RLS-enforced write is not rolled back over an
	// audit-publish hiccup, but the failure is logged loudly. Emitted before
	// the 201 response.
	if h.audit != nil {
		env := events.NewEnvelope(req.TenantID, operatorGcid,
			r.Header.Get("traceparent"), r.Header.Get("tracestate"))
		if err := h.audit.RecordEvidence(env, events.EvidenceInput{
			EvidenceType:    "tenant_membership_granted",
			SourceEventType: "chora.identity.tenant_membership.granted.v1",
			Dimension:       "accountability",
			LifecycleStage:  "runtime",
			PolicyReference: "ADR-194 D1 (operator cross-tenant grant)",
			AdditionalFields: map[string]any{
				"operator_gcid":    operatorGcid,
				"grantee_gcid":     req.Gcid,
				"target_tenant_id": req.TenantID,
				"granted_roles":    upperRoles,
				"cross_tenant":     true,
			},
		}); err != nil {
			log.Printf("grant-membership: audit RecordEvidence failed (grant persisted; best-effort): %v", err)
		}
	}

	writeJSON(w, http.StatusCreated, grantedMembershipDTO{
		MembershipID: membershipID,
		Gcid:         req.Gcid,
		TenantID:     req.TenantID,
		Roles:        upperRoles,
		GrantedAt:    time.Now().UTC(),
	})
}
