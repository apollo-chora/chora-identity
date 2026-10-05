// helpers_internal_test.go — internal-package coverage for the tenant-import
// helpers that the external parser suite reaches only indirectly
// (delimiterLabel rendering, header-map diagnostics, NewImportJob branches).
package tenantimport

import (
	"testing"
)

func TestDelimiterLabel_Rendering(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   rune
		want string
	}{
		{'\t', "TAB"},
		{0, ""},
		{';', ";"},
		{',', ","},
	}
	for _, c := range cases {
		if got := delimiterLabel(c.in); got != c.want {
			t.Errorf("delimiterLabel(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestMapHeader_UnknownAndDuplicateColumns(t *testing.T) {
	t.Parallel()
	// "email,roles,tenant_name,bogus,email" — bogus is unknown, the second
	// email is a duplicate; both are reported as RowErrors and the first
	// occurrence of email wins.
	idx, errs := mapHeader([]string{"email", "roles", "tenant_name", "bogus", "email"})
	if idx["email"] != 0 {
		t.Errorf("email index = %d, want 0 (first occurrence wins)", idx["email"])
	}
	if len(errs) != 2 {
		t.Fatalf("got %d header errors, want 2 (unknown + duplicate)", len(errs))
	}
	codes := map[string]bool{}
	for _, e := range errs {
		codes[e.Code] = true
	}
	if !codes[ErrCodeUnknownHeader] || !codes[ErrCodeDuplicateHeader] {
		t.Errorf("expected both unknown-header and duplicate-header codes, got %v", codes)
	}
}

func TestMapHeader_EmptyCellSkipped(t *testing.T) {
	t.Parallel()
	idx, errs := mapHeader([]string{"email", "", "roles"})
	if len(errs) != 0 {
		t.Errorf("empty cells must be skipped silently; got %v", errs)
	}
	if idx["roles"] != 2 {
		t.Errorf("roles index = %d, want 2", idx["roles"])
	}
}

func TestNewImportJob_MissingOperator(t *testing.T) {
	t.Parallel()
	if _, err := NewImportJob(NewImportJobParams{}); err == nil {
		t.Error("NewImportJob without operator + no default must error")
	}
}
