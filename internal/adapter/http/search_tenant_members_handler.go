// search_tenant_members_handler.go — HTTP handler for the
// `searchTenantMembers` operation (B6.1, 2026-05-16).
//
// Contract: chora-contracts/openapi/identity-admin.yaml::searchTenantMembers
//
//	GET /api/v1/admin/tenant-members
//	  ?q=<2..64 chars>
//	  &role=<LEARNER|INSTRUCTOR|ADMIN|AUDITOR|OWNER|SUPPORT_AGENT>
//	  &page_size=<10|20|50|100>      (default 20)
//	  &page_token=<base64 cursor>
//
//	→ 200 TenantMemberSearchResponse
//	→ 401 missing tenant context (caller bypassed gateway / no mesh stamp)
//	→ 403 caller lacks TRAINING_ADMIN or TENANT_ADMIN role
//	→ 405 non-GET
//	→ 422 q invalid length / page_size not in enum / page_token malformed / role not in enum
//	→ 500 repo error
//
// Auth contract:
//   - Caller's tenant_id is pulled from servicemesh.HeaderTenantID
//     (`chora-tenant-id`); falls back to the legacy `X-Tenant-Id` header for
//     local tests + dev curl probes (real production traffic ALWAYS stamps
//     the mesh header).
//   - Role gate reads servicemesh.HeaderUserRoles (`x-mesh-user-roles`) —
//     a comma-separated list of canonical UPPERCASE role tokens. Caller
//     MUST hold at least one of TRAINING_ADMIN / TENANT_ADMIN.
//
// Mapping note (TRAINING_ADMIN / TENANT_ADMIN vs the schema enum):
//   - The schema `tenant_memberships.role` enum is lowercase
//     {learner, instructor, admin, auditor}; the canonical gateway
//     stamps UPPERCASE roles for fast role-gate decisions per
//     ADR-141 / mesh role propagation (Bucket 4).
//   - TENANT_ADMIN here corresponds to the schema's `admin` role; the
//     gateway maps the canonical user role token to the mesh header.
//   - TRAINING_ADMIN is the "instructor-with-admin-on-courses" role
//     (per role_resolver) — distinct from TENANT_ADMIN but equally
//     authorised to run the picker UX in the assessment cohort flow.
package httpadapter

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/apollo-chora/chora-common/auth/servicemesh"
	"github.com/apollo-chora/chora-identity/internal/adapter/events"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// MemberSearchAuditEmitter records the IMDA-D1 accountability evidence for an
// operator cross-tenant member-directory read (S4 / CHO-2000 under CHO-1930).
// Satisfied by *events.GovernancePublisher — the same emitter the cross-tenant
// membership grant uses (grant_tenant_membership_handler.go).
type MemberSearchAuditEmitter interface {
	RecordEvidence(env events.Envelope, in events.EvidenceInput) error
}

// SearchTenantMembersHandler binds the search-tenant-members operation.
type SearchTenantMembersHandler struct {
	repo  identity.TenantMemberSearchRepo
	audit MemberSearchAuditEmitter // backs the S4 operator cross-tenant branch
}

// NewSearchTenantMembersHandler constructs the handler. audit backs the S4
// operator cross-tenant learner-directory read (fail-closed IMDA-D1 evidence
// emitted BEFORE the read); it is unused on the tenant-scoped path.
func NewSearchTenantMembersHandler(repo identity.TenantMemberSearchRepo, audit MemberSearchAuditEmitter) *SearchTenantMembersHandler {
	return &SearchTenantMembersHandler{repo: repo, audit: audit}
}

// ServeHTTP implements http.Handler. The handler is method-strict (GET only).
func (h *SearchTenantMembersHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "IDENTITY_METHOD_NOT_ALLOWED",
			"GET only on /api/v1/admin/tenant-members")
		return
	}

	qs := r.URL.Query()

	// 1. Resolve the scope + authorize. TWO paths:
	//
	//    (a) S4 operator cross-tenant branch (CHO-2000) — ?managed_tenant_id
	//        =<uuid> lets a PLATFORM_OPERATOR read a TARGET franchisee's member
	//        directory (RLS stays ENFORCED via the repo's RunInTenantTx(target);
	//        NOT a bypass — the ADR-194 D1 grant-handler authorization pattern).
	//        A fail-closed IMDA-D1 audit fires in step 3 BEFORE the read. The
	//        param — never the operator's mesh tenant header — is authoritative.
	//    (b) default tenant-scoped branch — the caller's OWN tenant (mesh
	//        header) + the TRAINING_ADMIN / TENANT_ADMIN gate (unchanged).
	targetTenant := strings.TrimSpace(qs.Get("managed_tenant_id"))
	isOperatorRead := targetTenant != ""
	var tenantID, operatorGCID string
	if isOperatorRead {
		if !callerHoldsOperatorRole(r) {
			writeError(w, http.StatusForbidden, "AUTH_INSUFFICIENT_ROLE",
				"caller must hold PLATFORM_OPERATOR to search another tenant's members")
			return
		}
		if !looksLikeTenantUUID(targetTenant) {
			writeError(w, http.StatusUnprocessableEntity, "IDENTITY_INVALID_TENANT",
				"managed_tenant_id must be a tenant UUID")
			return
		}
		operatorGCID = strings.TrimSpace(r.Header.Get(servicemesh.HeaderGCID))
		tenantID = targetTenant
	} else {
		// Resolve tenant id from mesh trust headers.
		tenantID = strings.TrimSpace(r.Header.Get(servicemesh.HeaderTenantID))
		if tenantID == "" {
			// Legacy fallback — dev curl + tests can stamp X-Tenant-Id directly.
			tenantID = strings.TrimSpace(r.Header.Get("X-Tenant-Id"))
		}
		if tenantID == "" {
			writeError(w, http.StatusUnauthorized, "AUTH_TENANT_CONTEXT_MISSING",
				"tenant context not propagated (gateway must stamp chora-tenant-id)")
			return
		}
		// Role gate — caller MUST hold TRAINING_ADMIN or TENANT_ADMIN.
		if !callerHoldsAdminRole(r) {
			writeError(w, http.StatusForbidden, "AUTH_INSUFFICIENT_ROLE",
				"caller must hold TRAINING_ADMIN or TENANT_ADMIN to search tenant members")
			return
		}
	}

	// 2. Validate + decode query params (shared across both scopes).
	q := strings.TrimSpace(qs.Get("q"))
	if q != "" {
		// length already trimmed; the contract bounds are 2..64 inclusive.
		if len(q) < 2 || len(q) > 64 {
			writeError(w, http.StatusUnprocessableEntity, "IDENTITY_INVALID_Q",
				"q must be 2..64 characters")
			return
		}
	}

	roleParam := strings.TrimSpace(qs.Get("role"))
	if roleParam != "" {
		if !isValidRoleEnum(roleParam) {
			writeError(w, http.StatusUnprocessableEntity, "IDENTITY_INVALID_ROLE",
				"role must be one of LEARNER, INSTRUCTOR, ADMIN, AUDITOR, OWNER, SUPPORT_AGENT")
			return
		}
	}

	pageSize, err := parsePageSize(qs.Get("page_size"))
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "IDENTITY_INVALID_PAGE_SIZE",
			err.Error())
		return
	}

	offset, err := decodePageToken(qs.Get("page_token"))
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "IDENTITY_INVALID_PAGE_TOKEN",
			err.Error())
		return
	}

	// 3. S4 fail-closed IMDA-D1 accountability evidence, emitted BEFORE the
	//    cross-tenant read. A failed emit ABORTS the read (500) — there is no
	//    un-audited operator cross-tenant PII access (mirrors the tx-history
	//    master audit; stricter than the grant handler's best-effort-after,
	//    because this is a READ that must not proceed unrecorded).
	if isOperatorRead {
		if h.audit == nil {
			writeError(w, http.StatusInternalServerError, "IDENTITY_AUDIT_NOT_WIRED",
				"cross-tenant audit emitter not wired")
			return
		}
		env := events.NewEnvelope(targetTenant, operatorGCID,
			r.Header.Get("traceparent"), r.Header.Get("tracestate"))
		if err := h.audit.RecordEvidence(env, events.EvidenceInput{
			EvidenceType:    "cross_tenant_members_viewed",
			SourceEventType: "chora.identity.cross_tenant_members_viewed.v1",
			Dimension:       "accountability",
			LifecycleStage:  "runtime",
			PolicyReference: "ADR-165/205 (operator cross-tenant learner-directory read for the tx-history filter)",
			AdditionalFields: map[string]any{
				"operator_gcid":    operatorGCID,
				"target_tenant_id": targetTenant,
				"q":                q,
				"role_filter":      strings.ToUpper(roleParam),
				"cross_tenant":     true,
			},
		}); err != nil {
			log.Printf("searchTenantMembers: cross-tenant audit emit failed (read aborted, IMDA D1): %v", err)
			writeError(w, http.StatusInternalServerError, "IDENTITY_AUDIT_EMIT_FAILED",
				"cross-tenant audit emit failed (read aborted, IMDA D1)")
			return
		}
	}

	// 4. Dispatch to the search repo. Role is canonicalised to the schema
	//    enum (lowercase) — the contract uses UPPERCASE for the picker UX,
	//    the schema (migration 0001) is lowercase.
	res, err := h.repo.Search(r.Context(), identity.TenantMemberSearchQuery{
		TenantID: tenantID,
		Q:        q,
		Role:     contractRoleToSchema(roleParam),
		PageSize: pageSize,
		Offset:   offset,
	})
	if err != nil {
		log.Printf("searchTenantMembers: repo error: %v", err)
		writeError(w, http.StatusInternalServerError, "IDENTITY_REPO_ERROR",
			"failed to search tenant members")
		return
	}

	// 5. Encode the response per the TenantMemberSearchResponse schema.
	writeJSON(w, http.StatusOK, buildSearchResponse(res))
}

// -----------------------------------------------------------------------------
// Response shape
// -----------------------------------------------------------------------------

// memberSummaryJSON mirrors the OpenAPI `TenantMemberSummary` schema. Pointer
// fields encode as JSON null when nil — required by the contract's
// `nullable: true` clauses.
type memberSummaryJSON struct {
	GCID         string     `json:"gcid"`
	Email        *string    `json:"email,omitempty"`
	DisplayName  *string    `json:"display_name,omitempty"`
	AvatarURL    *string    `json:"avatar_url,omitempty"`
	Roles        []string   `json:"roles"`
	LastActiveAt *time.Time `json:"last_active_at,omitempty"`
}

// searchResponseJSON mirrors the OpenAPI `TenantMemberSearchResponse` schema.
// `next_page_token` is a *string so the JSON encoder emits null at end-of-list
// (the contract requires null, not omit).
type searchResponseJSON struct {
	Items         []memberSummaryJSON `json:"items"`
	NextPageToken *string             `json:"next_page_token"`
	Total         int                 `json:"total,omitempty"`
}

func buildSearchResponse(res identity.TenantMemberSearchResult) searchResponseJSON {
	items := make([]memberSummaryJSON, 0, len(res.Items))
	for _, it := range res.Items {
		items = append(items, memberSummaryJSON{
			GCID:         it.GCID,
			Email:        it.Email,
			DisplayName:  it.DisplayName,
			AvatarURL:    it.AvatarURL,
			Roles:        it.Roles,
			LastActiveAt: it.LastActiveAt,
		})
	}
	resp := searchResponseJSON{Items: items}
	if res.HasMore && res.NextOffset > 0 {
		tok := encodePageToken(res.NextOffset)
		resp.NextPageToken = &tok
	}
	return resp
}

// -----------------------------------------------------------------------------
// Query-param parsing
// -----------------------------------------------------------------------------

// parsePageSize returns 20 when empty; rejects values outside the enum.
func parsePageSize(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 20, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("page_size must be an integer (10, 20, 50, or 100)")
	}
	switch n {
	case 10, 20, 50, 100:
		return n, nil
	}
	return 0, fmt.Errorf("page_size must be one of 10, 20, 50, 100; got %d", n)
}

// encodePageToken / decodePageToken use a base64-url-encoded "offset:N"
// payload. Opaque to the FE — the contract requires it be treated as a
// cursor and round-tripped verbatim.
func encodePageToken(offset int) string {
	return base64.RawURLEncoding.EncodeToString([]byte("offset:" + strconv.Itoa(offset)))
}

func decodePageToken(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	if len(raw) > 512 {
		// Match the OpenAPI maxLength clause.
		return 0, errors.New("page_token exceeds 512 chars")
	}
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return 0, errors.New("page_token: invalid base64-url payload")
	}
	const prefix = "offset:"
	s := string(b)
	if !strings.HasPrefix(s, prefix) {
		return 0, errors.New("page_token: malformed payload (expected 'offset:N')")
	}
	n, err := strconv.Atoi(s[len(prefix):])
	if err != nil || n < 0 {
		return 0, errors.New("page_token: malformed offset")
	}
	return n, nil
}

// looksLikeTenantUUID reports whether s is a canonical 8-4-4-4-12 hex UUID
// (case-insensitive). The operator's managed_tenant_id becomes the RLS GUC,
// so it MUST be validated before it reaches the repo (no injection of a
// non-uuid sentinel like 'platform' into the tenant scope).
func looksLikeTenantUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			return false
		}
	}
	return true
}

// -----------------------------------------------------------------------------
// Role gate
// -----------------------------------------------------------------------------

// adminRoles is the role-gate accept list per the contract description:
// "TRAINING_ADMIN or TENANT_ADMIN role required".
//
// The canonical contract enum is UPPERCASE per ADR-141; the existing schema
// (migration 0001's `membership_role` enum) is lowercase, and the mint
// handler currently propagates the lowercase form on the JWT. Both shapes
// are accepted here so the gate works regardless of which mint version
// stamped the caller's session (M14.x will normalise everywhere to the
// UPPERCASE form).
//
//   - TENANT_ADMIN ≡ `admin` (schema enum) — tenant-level admin.
//   - TRAINING_ADMIN ≡ `instructor` (schema enum) — instructors who
//     manage cohort assessments are the picker's primary callers.
var adminRoles = map[string]struct{}{
	// Contract / canonical uppercase form (ADR-141; future state).
	"TRAINING_ADMIN": {},
	"TENANT_ADMIN":   {},
	// Schema / legacy lowercase form (uppercased at parse time below).
	"INSTRUCTOR": {},
	"ADMIN":      {},
	// Bootstrap owner (L1 CHO-1705 walk-caught): the fresh tenant owner's
	// minted JWT carries roles=["owner"] ONLY (OWNER is JWT-stamped at
	// bootstrap; the role=admin membership mirror row lags via Pub/Sub).
	// Without OWNER here a brand-new tenant cannot manage its members.
	"OWNER": {},
}

// callerHoldsAdminRole returns true when the caller's mesh role-summary
// (HeaderUserRoles `x-mesh-user-roles`) contains TRAINING_ADMIN or
// TENANT_ADMIN. Roles are case-insensitive at parse time.
//
// chora-role-summary (the JSON envelope) is NOT consulted here — the
// canonical Bucket 4 mesh path stamps the typed roles into the simpler
// comma-separated header. Falling back to the JSON envelope would mask
// the simpler header's absence and is a smell.
func callerHoldsAdminRole(r *http.Request) bool {
	hdr := strings.TrimSpace(r.Header.Get(servicemesh.HeaderUserRoles))
	if hdr == "" {
		return false
	}
	for _, part := range strings.Split(hdr, ",") {
		role := strings.ToUpper(strings.TrimSpace(part))
		if _, ok := adminRoles[role]; ok {
			return true
		}
	}
	return false
}

// -----------------------------------------------------------------------------
// Role enum mapping
// -----------------------------------------------------------------------------

// contractRoleEnum is the canonical contract role enum (UPPERCASE).
var contractRoleEnum = map[string]struct{}{
	"LEARNER":       {},
	"INSTRUCTOR":    {},
	"ADMIN":         {},
	"AUDITOR":       {},
	"OWNER":         {},
	"SUPPORT_AGENT": {},
}

func isValidRoleEnum(r string) bool {
	_, ok := contractRoleEnum[strings.ToUpper(r)]
	return ok
}

// contractRoleToSchema maps the contract enum (UPPERCASE) to the schema
// enum (lowercase) the SQL layer uses. OWNER + SUPPORT_AGENT have no direct
// schema row — they're contract-forward-compat; map to the empty string so
// the SQL layer's `$2 IS NULL OR role = $2` predicate returns no rows
// (no membership of that role exists). This matches the contract semantics:
// filtering by a role that doesn't exist yields empty.
func contractRoleToSchema(r string) string {
	switch strings.ToUpper(strings.TrimSpace(r)) {
	case "":
		return ""
	case "LEARNER":
		return "learner"
	case "INSTRUCTOR":
		return "instructor"
	case "ADMIN":
		return "admin"
	case "AUDITOR":
		return "auditor"
	}
	// OWNER + SUPPORT_AGENT — forward-compat. Returning a non-matching
	// sentinel (uppercase) means the SQL `tm.role::text = $2` clause never
	// matches (the enum casts to lowercase) so the result is empty —
	// semantically correct.
	return strings.ToUpper(r)
}
