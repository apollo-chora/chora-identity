// validator_test.go — RED spec for the P1 mode-dependent validator
// (CHO-2021). The parser (P0) does context-free per-cell checks; this adds the
// operator_existing_only layer: tenant-existence resolution + email-union merge
// (GQ-8) + parser-error passthrough. Written before validator.go.
package tenantimport

import (
	"context"
	"errors"
	"testing"

	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// fakeResolver maps existing slugs → tenant_id; a missing slug resolves absent.
type fakeResolver map[string]string

func (f fakeResolver) ResolveSlug(_ context.Context, slug string) (string, bool, error) {
	id, ok := f[slug]
	return id, ok, nil
}

type errResolver struct{}

func (errResolver) ResolveSlug(context.Context, string) (string, bool, error) {
	return "", false, errors.New("tenancy unavailable")
}

func TestValidate_existingOnly_mergeExistenceAndPassthrough(t *testing.T) {
	pr := ParseResult{
		Delimiter: ',',
		Rows: []Row{
			{Line: 2, TenantSlug: "acme", Email: "a@x.io", Roles: []identity.Role{"learner"}},
			{Line: 3, TenantSlug: "acme", Email: "a@x.io", Roles: []identity.Role{"author"}},     // dup email → union with line 2
			{Line: 4, TenantSlug: "acme", Email: "b@x.io", Roles: []identity.Role{"instructor"}}, // distinct user
			{Line: 5, TenantSlug: "ghost", Email: "c@x.io", Roles: []identity.Role{"learner"}},   // unknown tenant → block error
		},
		Errors: []RowError{
			{Line: 6, Field: ColEmail, Code: ErrCodeInvalidEmail, Reason: "bad email"}, // parser error — must pass through
		},
	}
	res, err := Validate(context.Background(), pr, RunModeOperatorExistingOnly, fakeResolver{"acme": "T-ACME"})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}

	// acme yields TWO execution units: a@x.io (learner+author unioned) + b@x.io.
	if len(res.Rows) != 2 {
		t.Fatalf("validated rows = %d, want 2 (%+v)", len(res.Rows), res.Rows)
	}
	byEmail := map[string]ValidatedRow{}
	for _, r := range res.Rows {
		byEmail[r.Email] = r
		if r.TargetTenantID != "T-ACME" {
			t.Errorf("%s target = %q, want T-ACME", r.Email, r.TargetTenantID)
		}
	}
	a, ok := byEmail["a@x.io"]
	if !ok {
		t.Fatal("missing merged row a@x.io")
	}
	if len(a.Roles) != 2 || a.Roles[0] != "learner" || a.Roles[1] != "author" {
		t.Errorf("a@x.io roles = %v, want [learner author] (union, first-seen)", a.Roles)
	}

	// errors: the ghost block (line 5) + the parser passthrough (line 6).
	if len(res.Errors) != 2 {
		t.Fatalf("errors = %d, want 2 (%+v)", len(res.Errors), res.Errors)
	}
	var gotUnknownTenant, gotPassthrough bool
	for _, e := range res.Errors {
		if e.Code == ErrCodeUnknownTenant && e.Line == 5 {
			gotUnknownTenant = true
		}
		if e.Code == ErrCodeInvalidEmail && e.Line == 6 {
			gotPassthrough = true
		}
	}
	if !gotUnknownTenant {
		t.Error("expected unknown_tenant error for the ghost block (line 5)")
	}
	if !gotPassthrough {
		t.Error("expected parser error (line 6) passed through")
	}

	// summary reconciles per INPUT row: 5 data lines (2-6), 2 error lines (5,6),
	// 3 valid input lines (2,3,4), 1 resolved tenant.
	s := res.Summary
	if s.TotalRows != 5 || s.ErrorRows != 2 || s.ValidRows != 3 || s.TenantCount != 1 {
		t.Errorf("summary = %+v, want total=5 error=2 valid=3 tenants=1", s)
	}
	if s.Delimiter != "," {
		t.Errorf("summary delimiter = %q, want ,", s.Delimiter)
	}
}

func TestValidate_existingOnly_resolverError_isSystemFailure(t *testing.T) {
	pr := ParseResult{Rows: []Row{{Line: 2, TenantSlug: "acme", Email: "a@x.io", Roles: []identity.Role{"learner"}}}}
	if _, err := Validate(context.Background(), pr, RunModeOperatorExistingOnly, errResolver{}); err == nil {
		t.Error("resolver error should surface as a system failure (whole-job), not a row error")
	}
}

func TestValidate_allRowsErrored_zeroValid(t *testing.T) {
	pr := ParseResult{
		Errors: []RowError{
			{Line: 2, Field: ColEmail, Code: ErrCodeMissingEmail, Reason: "no email"},
			{Line: 3, Field: ColRoles, Code: ErrCodeMissingRoles, Reason: "no roles"},
		},
	}
	res, err := Validate(context.Background(), pr, RunModeOperatorExistingOnly, fakeResolver{})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(res.Rows) != 0 {
		t.Errorf("validated rows = %d, want 0", len(res.Rows))
	}
	if res.Summary.TotalRows != 2 || res.Summary.ErrorRows != 2 || res.Summary.ValidRows != 0 {
		t.Errorf("summary = %+v, want total=2 error=2 valid=0", res.Summary)
	}
}
