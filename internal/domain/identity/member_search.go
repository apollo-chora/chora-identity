// member_search.go — domain port + value objects for the tenant-member picker
// search (operationId `searchTenantMembers`, contract
// `chora-contracts/openapi/identity-admin.yaml`).
//
// Distinct from MembershipRepository.List (admin row-level view of
// tenant_memberships): this port returns an ENRICHED USER projection
// (gcid + email + display_name + roles + last_active_at) suitable for the
// picker UX driving the assessment-cohort `invited_gcids[]` field per
// ADR-155 §D9 (B6.1, 2026-05-16).
//
// Per hexagonal: the port lives here; the adapter (pgx-backed) lives in
// internal/adapter/pg/tenant_member_search.go. Per multi-tenant-rls:
// adapters MUST wrap their SQL in a tenant-scoped transaction
// (`SET LOCAL chora.tenant_id = $1`) so RLS scopes results to the caller's
// tenant — cross-tenant matches are blocked at the database layer.
package identity

import (
	"context"
	"time"
)

// TenantMemberSearchRepo is the domain port for searching active tenant
// members (picker UX). Implementations live in adapter packages
// (e.g. internal/adapter/pg.TenantMemberSearchRepository) and MUST honour:
//
//   - RLS scoping by `current_setting('chora.tenant_id', true)::uuid` — only
//     rows for the caller's tenant are returned.
//   - Exclusion of accounts in SUSPENDED / CLOSING / PSEUDONYMIZED /
//     CRYPTO_SHREDDED states (per closure saga state in
//     chora_identity.closure_sagas).
//   - Soft-delete filter on users.deleted_at IS NULL.
//   - Active-membership filter on tenant_memberships.status = 'active'.
//   - Deterministic ordering: best-effort recency DESC, display_name ASC.
//
// Implementations propagate `ctx`; the HTTP middleware stamps the tenant id
// into the ctx via tracing.WithTenantID so the adapter's RunInTenantTx pulls
// the tenant from the same source-of-truth.
type TenantMemberSearchRepo interface {
	Search(ctx context.Context, query TenantMemberSearchQuery) (TenantMemberSearchResult, error)
}

// TenantMemberSearchQuery is the search input. All fields are optional except
// PageSize (which the handler defaults to 20 when zero); TenantID is required
// for the adapter — the HTTP layer guarantees it via mesh-claim extraction.
type TenantMemberSearchQuery struct {
	// TenantID is the RLS-scoping tenant. The adapter applies it via
	// SET LOCAL chora.tenant_id inside the transaction; an empty value is
	// rejected at the adapter boundary because every tenant-scoped query
	// MUST have a tenant context (see multi-tenant-rls/SKILL.md).
	TenantID string

	// Q is the free-text substring matched against LOWER(email) and
	// LOWER(display_name). Empty means "no q filter — return recent members".
	// The handler validates 2..64 chars before calling.
	Q string

	// Role filters to members holding the supplied role. Empty means no
	// role filter. Canonical lowercase form ("learner" / "instructor" /
	// "admin" / "auditor") — the handler normalises the contract enum
	// (uppercase) before calling.
	Role string

	// PageSize caps the returned items. The handler validates the enum
	// {10, 20, 50, 100} before calling; zero means "use default 20".
	PageSize int

	// Offset is the decoded page_token offset. Zero = first page.
	// The handler is responsible for base64-decoding the opaque
	// `next_page_token` cursor into this integer offset.
	Offset int
}

// TenantMemberSummary is the per-row projection returned in the search
// response. Mirrors the OpenAPI `TenantMemberSummary` schema; ptr fields are
// nullable per the contract.
type TenantMemberSummary struct {
	GCID         string
	Email        *string
	DisplayName  *string
	AvatarURL    *string
	Roles        []string // canonical UPPERCASE form per the contract (e.g. ["ADMIN", "INSTRUCTOR"])
	LastActiveAt *time.Time
}

// TenantMemberSearchResult is the search output. NextOffset is non-zero when
// there is at least one more page; the handler encodes it into the opaque
// `next_page_token`.
type TenantMemberSearchResult struct {
	Items      []TenantMemberSummary
	NextOffset int  // 0 = end-of-list; >0 = caller may pass as Offset on next call
	HasMore    bool // explicit "more available" flag (decoupled from NextOffset == 0 vs unset)
}
