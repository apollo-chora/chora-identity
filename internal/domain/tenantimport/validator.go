// validator.go — the P1 mode-dependent validator (CHO-2021, ADR-221 D3;
// CR §5.2). The P0 parser (types.go:6-11) is deliberately mode-agnostic:
// context-free per-cell checks only. This layer adds the operator_existing_only
// rules on top of a ParseResult:
//
//   - tenant-existence: every distinct tenant_slug MUST resolve to an existing
//     tenant (unknown slug = block error — NEVER an implicit create, ADR-221 D3);
//   - email-union merge (GQ-8): in-file duplicate emails within one tenant block
//     collapse to a single execution unit with the UNION of their roles;
//   - parser row errors pass straight through into the report/error-CSV.
//
// A resolver failure is a WHOLE-JOB (system) failure, not a row error.
// tenant_name-per-slug consistency + tenant-column-forbidden are create/admin
// mode concerns (P2/P6) and are intentionally not enforced here.
package tenantimport

import (
	"context"
	"fmt"

	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// ErrCodeUnknownTenant — a tenant_slug did not resolve to an existing tenant in
// operator_existing_only mode (the slug-typo guard; block error).
const ErrCodeUnknownTenant = "unknown_tenant"

// TenantResolver resolves a tenant slug to its id. Implemented by a chora-tenancy
// gRPC adapter in the application layer; faked in tests. `exists` is false for an
// unknown slug; a non-nil error is a transport/system failure.
type TenantResolver interface {
	ResolveSlug(ctx context.Context, slug string) (tenantID string, exists bool, err error)
}

// ValidatedRow is one post-merge execution unit ready to seat: a distinct
// (tenant, email) with the unioned role set and its resolved target tenant id.
type ValidatedRow struct {
	Line           int // first physical line the (tenant,email) appeared on
	TenantSlug     string
	TargetTenantID string
	Email          string
	DisplayName    string
	Roles          []identity.Role
	ExternalRef    string
	SendInvite     *bool
}

// ValidationResult is the dry-run output: the execution units, every error
// (parser + validator) for the error CSV, and the roll-up summary.
type ValidationResult struct {
	Rows    []ValidatedRow
	Errors  []RowError
	Summary ValidationSummary
}

// Validate applies the operator_existing_only rules to a parsed CSV. It never
// writes; it produces the dry-run report the job settles on at awaiting_confirm.
func Validate(ctx context.Context, pr ParseResult, mode RunMode, resolver TenantResolver) (ValidationResult, error) {
	if mode != RunModeOperatorExistingOnly {
		// P1 ships exactly one mode; fail loud rather than silently mis-handle.
		return ValidationResult{}, fmt.Errorf("validator: run_mode %q not supported in P1 (operator_existing_only only)", string(mode))
	}

	res := ValidationResult{Summary: ValidationSummary{Delimiter: delimiterLabel(pr.Delimiter)}}

	// Parser row errors pass through verbatim; their lines are error lines.
	errorLines := map[int]bool{}
	for _, e := range pr.Errors {
		res.Errors = append(res.Errors, e)
		errorLines[e.Line] = true
	}

	// Resolve each distinct slug once (cache). A resolver error aborts the job.
	resolved := map[string]string{} // slug → tenant_id (only existing slugs)
	seenSlug := map[string]bool{}
	for _, r := range pr.Rows {
		if seenSlug[r.TenantSlug] {
			continue
		}
		seenSlug[r.TenantSlug] = true
		id, exists, err := resolver.ResolveSlug(ctx, r.TenantSlug)
		if err != nil {
			return ValidationResult{}, fmt.Errorf("validator: resolve tenant %q: %w", r.TenantSlug, err)
		}
		if exists {
			resolved[r.TenantSlug] = id
		}
	}

	// Merge known-tenant rows by (slug, normalized email); block unknown tenants.
	type mergeKey struct{ slug, email string }
	index := map[mergeKey]int{} // key → position in res.Rows
	roleSeen := map[mergeKey]map[identity.Role]bool{}
	validLines := map[int]bool{}
	tenants := map[string]bool{}

	for _, r := range pr.Rows {
		tenantID, ok := resolved[r.TenantSlug]
		if !ok {
			// Unknown tenant → block error on this row; not an execution unit.
			res.Errors = append(res.Errors, RowError{
				Line:   r.Line,
				Field:  ColTenantSlug,
				Code:   ErrCodeUnknownTenant,
				Reason: fmt.Sprintf("tenant %q does not exist (operator_existing_only never creates tenants)", r.TenantSlug),
			})
			errorLines[r.Line] = true
			continue
		}
		validLines[r.Line] = true
		tenants[tenantID] = true

		email := identity.NormalizeEmail(r.Email)
		k := mergeKey{slug: r.TenantSlug, email: email}
		if pos, seen := index[k]; seen {
			// Union additional roles into the existing execution unit (GQ-8).
			for _, role := range r.Roles {
				if !roleSeen[k][role] {
					roleSeen[k][role] = true
					res.Rows[pos].Roles = append(res.Rows[pos].Roles, role)
				}
			}
			continue
		}
		vr := ValidatedRow{
			Line:           r.Line,
			TenantSlug:     r.TenantSlug,
			TargetTenantID: tenantID,
			Email:          email,
			DisplayName:    r.DisplayName,
			ExternalRef:    r.ExternalRef,
			SendInvite:     r.SendInvite,
			Roles:          make([]identity.Role, 0, len(r.Roles)),
		}
		rs := make(map[identity.Role]bool, len(r.Roles))
		for _, role := range r.Roles {
			if rs[role] {
				continue
			}
			rs[role] = true
			vr.Roles = append(vr.Roles, role)
		}
		index[k] = len(res.Rows)
		roleSeen[k] = rs
		res.Rows = append(res.Rows, vr)
	}

	res.Summary.ValidRows = len(validLines)
	res.Summary.ErrorRows = len(errorLines)
	res.Summary.TotalRows = len(validLines) + len(errorLines)
	res.Summary.TenantCount = len(tenants)
	return res, nil
}

// delimiterLabel renders the sniffed delimiter for the M-1 report echo.
func delimiterLabel(d rune) string {
	switch d {
	case '\t':
		return "TAB"
	case 0:
		return ""
	default:
		return string(d)
	}
}
