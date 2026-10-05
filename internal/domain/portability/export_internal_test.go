// export_internal_test.go — internal-package tests for unexported helpers
// (AGID detection) in the portability aggregate.
//
// The external portability_test package covers the public API; this file
// exercises isAGID's branches directly.
package portability

import "testing"

func TestIsAGID_DetectsChoraAuditGcids(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"0197a000-0000-7000-9000-000000000001", true},
		{"0197A000-0000-7000-9000-000000000001", true},
		{"0198a000-0000-7000-9000-000000000001", false},
		{"plain-text", false},
	}
	for _, c := range cases {
		if got := isAGID(c.in); got != c.want {
			t.Errorf("isAGID(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
