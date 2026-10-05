// =============================================================================
// tenantimport parser — golden-file tests (P0, CHO-2020; ADR-221 D2, CR §5.1).
//
// TDD RED: written BEFORE parser.go exists. The fixtures under testdata/ are
// byte-exact Excel / Google-Sheets export shapes (UTF-8 BOM, CRLF, `;`/TSV
// delimiters, quoted commas, duplicate headers, trailing blanks). The LOCKED
// CSV contract being pinned here:
//
//   - one file, UTF-8 (BOM tolerated), comma default with `;`/TSV sniff (M-1/M-2)
//   - case-insensitive headers (M-3); emails normalized lower/trim (M-4)
//   - external_ref preserved as text — leading zeros safe (M-5)
//   - caps 20 MB / 50k rows (M-6)
//   - roles = pipe/semicolon list, aliases tenant_admin→admin,
//     training_admin→instructor; owner/platform_operator ⇒ row error (GQ-6)
//   - row-level partial failure with precise (line, field, reason) errors (GQ-7)
//
// =============================================================================
package tenantimport_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/apollo-chora/chora-identity/internal/domain/identity"
	"github.com/apollo-chora/chora-identity/internal/domain/tenantimport"
)

func boolPtr(b bool) *bool { return &b }

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

// errKey is the exact-match projection of a RowError used in golden asserts.
// Reason strings are asserted non-empty but not string-matched (they are
// human-facing; Code is the stable machine contract).
type errKey struct {
	Line  int
	Field string
	Code  string
}

func projectErrors(t *testing.T, errs []tenantimport.RowError) []errKey {
	t.Helper()
	out := make([]errKey, 0, len(errs))
	for _, e := range errs {
		if e.Reason == "" {
			t.Errorf("RowError %+v has empty Reason (must be human-readable)", e)
		}
		out = append(out, errKey{Line: e.Line, Field: e.Field, Code: e.Code})
	}
	return out
}

func assertRows(t *testing.T, got, want []tenantimport.Row) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("rows: got %d want %d\ngot: %+v", len(got), len(want), got)
	}
	for i := range want {
		g, w := got[i], want[i]
		if g.Line != w.Line || g.TenantSlug != w.TenantSlug || g.TenantName != w.TenantName ||
			g.HostingMode != w.HostingMode || g.Country != w.Country || g.Currency != w.Currency ||
			g.Email != w.Email || g.DisplayName != w.DisplayName || g.ExternalRef != w.ExternalRef ||
			g.Locale != w.Locale {
			t.Errorf("row %d scalar mismatch:\n got %+v\nwant %+v", i, g, w)
		}
		if (g.SendInvite == nil) != (w.SendInvite == nil) ||
			(g.SendInvite != nil && *g.SendInvite != *w.SendInvite) {
			t.Errorf("row %d SendInvite mismatch: got %v want %v", i, g.SendInvite, w.SendInvite)
		}
		if len(g.Roles) != len(w.Roles) {
			t.Errorf("row %d roles: got %v want %v", i, g.Roles, w.Roles)
			continue
		}
		for j := range w.Roles {
			if g.Roles[j] != w.Roles[j] {
				t.Errorf("row %d role[%d]: got %q want %q", i, j, g.Roles[j], w.Roles[j])
			}
		}
	}
}

func assertErrKeys(t *testing.T, got []tenantimport.RowError, want []errKey) {
	t.Helper()
	gk := projectErrors(t, got)
	if len(gk) != len(want) {
		t.Fatalf("errors: got %d want %d\ngot: %+v", len(gk), len(want), gk)
	}
	for i := range want {
		if gk[i] != want[i] {
			t.Errorf("error %d: got %+v want %+v", i, gk[i], want[i])
		}
	}
}

// -----------------------------------------------------------------------------
// M-6 caps are a locked public contract — pin the constants.
// -----------------------------------------------------------------------------
func TestDefaults_LockedCaps(t *testing.T) {
	if tenantimport.DefaultMaxFileBytes != 20*1024*1024 {
		t.Errorf("DefaultMaxFileBytes = %d, want 20 MiB", tenantimport.DefaultMaxFileBytes)
	}
	if tenantimport.DefaultMaxRows != 50_000 {
		t.Errorf("DefaultMaxRows = %d, want 50000", tenantimport.DefaultMaxRows)
	}
}

// -----------------------------------------------------------------------------
// Happy path: Excel "CSV UTF-8" export — BOM + CRLF + mixed-case headers +
// quoted commas + role aliases + duplicate-role dedupe + leading-zero
// external_ref + tolerated trailing blank line.
// -----------------------------------------------------------------------------
func TestParse_HappyExcelBOMCRLF(t *testing.T) {
	res, err := tenantimport.Parse(bytes.NewReader(loadFixture(t, "happy_excel_bom_crlf.csv")), tenantimport.Options{})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if res.Delimiter != ',' {
		t.Errorf("Delimiter = %q, want ','", res.Delimiter)
	}
	assertErrKeys(t, res.Errors, nil)
	assertRows(t, res.Rows, []tenantimport.Row{
		{
			Line: 2, TenantSlug: "acme-college", TenantName: "Acme College, Pte Ltd",
			HostingMode: "FRANCHISE", Country: "SG", Currency: "SGD",
			Email: "alice@acme.sg", DisplayName: "Tan, Alice",
			Roles:       []identity.Role{identity.RoleLearner, identity.RoleAuthor},
			ExternalRef: "00042", Locale: "en-SG", SendInvite: boolPtr(true),
		},
		{
			Line: 3, TenantSlug: "acme-college", TenantName: "Acme College, Pte Ltd",
			Email: "bob@acme.sg", DisplayName: "Bob Lim",
			Roles:       []identity.Role{identity.RoleAdmin, identity.RoleInstructor},
			ExternalRef: "00043", SendInvite: boolPtr(false),
		},
		{
			Line: 4, TenantSlug: "acme-college", TenantName: "Acme College, Pte Ltd",
			Email: "carol@acme.sg",
			Roles: []identity.Role{identity.RoleInstructor},
		},
		{
			Line: 5, TenantSlug: "acme-college", TenantName: "Acme College, Pte Ltd",
			Email: "dave@acme.sg",
			Roles: []identity.Role{identity.RoleAdmin},
		},
	})
}

// -----------------------------------------------------------------------------
// Delimiter sniffing (M-1): semicolon (EU Excel/GSheets) and TSV. The
// semicolon fixture also proves a QUOTED `;` role list splits as a role
// separator, not a cell separator, and email lowercasing.
// -----------------------------------------------------------------------------
func TestParse_SemicolonDelimiter(t *testing.T) {
	res, err := tenantimport.Parse(bytes.NewReader(loadFixture(t, "semicolon_gsheets.csv")), tenantimport.Options{})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if res.Delimiter != ';' {
		t.Errorf("Delimiter = %q, want ';'", res.Delimiter)
	}
	assertErrKeys(t, res.Errors, nil)
	assertRows(t, res.Rows, []tenantimport.Row{
		{
			Line: 2, TenantSlug: "beta-inst", TenantName: "Beta Institute",
			Email: "dora@beta.example",
			Roles: []identity.Role{identity.RoleLearner, identity.RoleAuthor},
		},
		{
			Line: 3, TenantSlug: "beta-inst", TenantName: "Beta Institute",
			Email: "evan@beta.example",
			Roles: []identity.Role{identity.RoleAdmin},
		},
	})
}

func TestParse_TabDelimiter(t *testing.T) {
	res, err := tenantimport.Parse(bytes.NewReader(loadFixture(t, "tabs_export.tsv")), tenantimport.Options{})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if res.Delimiter != '\t' {
		t.Errorf("Delimiter = %q, want tab", res.Delimiter)
	}
	assertErrKeys(t, res.Errors, nil)
	assertRows(t, res.Rows, []tenantimport.Row{
		{
			Line: 2, TenantSlug: "gamma-school", TenantName: "Gamma School",
			Email: "fern@gamma.example",
			Roles: []identity.Role{identity.RoleLearner, identity.RoleInstructor},
		},
	})
}

// -----------------------------------------------------------------------------
// Hazard zoo (GQ-7 row-level semantics): every bad row is pinpointed by
// (line, field, code); good rows survive; all-empty + blank rows skipped;
// duplicate KNOWN header → first occurrence wins + header error; unknown
// header → header error + column ignored.
// -----------------------------------------------------------------------------
func TestParse_HazardsMixed(t *testing.T) {
	res, err := tenantimport.Parse(bytes.NewReader(loadFixture(t, "hazards_mixed.csv")), tenantimport.Options{})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	assertErrKeys(t, res.Errors, []errKey{
		{Line: 1, Field: "email", Code: tenantimport.ErrCodeDuplicateHeader},
		{Line: 1, Field: "bogus_col", Code: tenantimport.ErrCodeUnknownHeader},
		// L2: slug "Acme-Corp " normalizes clean (trim+lower); the ONLY defect
		// is send_invite "maybe". Also proves the duplicate email column and
		// the unknown bogus_col value are ignored without further errors.
		{Line: 2, Field: "send_invite", Code: tenantimport.ErrCodeInvalidSendInvite},
		{Line: 3, Field: "tenant_slug", Code: tenantimport.ErrCodeInvalidTenantSlug},
		{Line: 4, Field: "email", Code: tenantimport.ErrCodeInvalidEmail},
		{Line: 5, Field: "roles", Code: tenantimport.ErrCodeForbiddenRole},
		{Line: 6, Field: "roles", Code: tenantimport.ErrCodeInvalidRole},
		{Line: 7, Field: "email", Code: tenantimport.ErrCodeMissingEmail},
		{Line: 8, Field: "", Code: tenantimport.ErrCodeRowTooWide},
		{Line: 9, Field: "roles", Code: tenantimport.ErrCodeForbiddenRole},
	})
	assertRows(t, res.Rows, []tenantimport.Row{
		{
			Line: 10, TenantSlug: "acme-corp", TenantName: "Acme Corp",
			Email: "liam@acme.example",
			Roles: []identity.Role{identity.RoleLearner},
		},
	})
}

// -----------------------------------------------------------------------------
// File-level rejections: missing required header, malformed quoting, empty
// file, non-UTF-8 header, caps (M-6).
// -----------------------------------------------------------------------------
func TestParse_FileErrors(t *testing.T) {
	cases := []struct {
		name     string
		input    []byte
		opts     tenantimport.Options
		wantCode string
	}{
		{
			name:     "missing roles header",
			input:    loadFixture(t, "missing_header.csv"),
			wantCode: tenantimport.FileErrCodeMissingHeader,
		},
		{
			name:     "unclosed quote",
			input:    loadFixture(t, "malformed_quote.csv"),
			wantCode: tenantimport.FileErrCodeMalformed,
		},
		{
			name:     "empty file",
			input:    loadFixture(t, "empty.csv"),
			wantCode: tenantimport.FileErrCodeEmpty,
		},
		{
			name:     "whitespace-only file",
			input:    []byte("\n\n"),
			wantCode: tenantimport.FileErrCodeEmpty,
		},
		{
			name:     "non-UTF-8 header",
			input:    []byte("tenant_slug,tenant_name,\xe9mail,roles\nacme,Acme,a@b.example,learner\n"),
			wantCode: tenantimport.FileErrCodeNotUTF8,
		},
		{
			name: "row cap",
			input: []byte("email,roles\n" +
				"a@x.example,learner\nb@x.example,learner\nc@x.example,learner\n"),
			opts:     tenantimport.Options{MaxRows: 2},
			wantCode: tenantimport.FileErrCodeTooManyRows,
		},
		{
			name:     "byte cap",
			input:    []byte("email,roles\n" + strings.Repeat("a@x.example,learner\n", 10)),
			opts:     tenantimport.Options{MaxFileBytes: 64},
			wantCode: tenantimport.FileErrCodeTooLarge,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tenantimport.Parse(bytes.NewReader(tc.input), tc.opts)
			var fe *tenantimport.FileError
			if !errors.As(err, &fe) {
				t.Fatalf("want *FileError, got %v", err)
			}
			if fe.Code != tc.wantCode {
				t.Errorf("FileError.Code = %q, want %q", fe.Code, tc.wantCode)
			}
			if fe.Error() == "" {
				t.Errorf("FileError message must be non-empty")
			}
		})
	}
}

// A data row carrying invalid UTF-8 is a ROW error (file continues) with the
// offending field named — Excel "plain CSV" on Windows emits CP-1252 bytes.
func TestParse_InvalidUTF8Row(t *testing.T) {
	in := []byte("tenant_slug,tenant_name,email,roles\n" +
		"acme,Acme,l\xe9a@acme.example,learner\n" +
		"acme,Acme,mia@acme.example,learner\n")
	res, err := tenantimport.Parse(bytes.NewReader(in), tenantimport.Options{})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	assertErrKeys(t, res.Errors, []errKey{
		{Line: 2, Field: "email", Code: tenantimport.ErrCodeInvalidUTF8},
	})
	assertRows(t, res.Rows, []tenantimport.Row{
		{
			Line: 3, TenantSlug: "acme", TenantName: "Acme",
			Email: "mia@acme.example",
			Roles: []identity.Role{identity.RoleLearner},
		},
	})
}

// Header-only file parses clean with zero rows (the P1 validator, not the
// parser, decides whether zero rows is a job-level problem).
func TestParse_HeaderOnly(t *testing.T) {
	res, err := tenantimport.Parse(bytes.NewReader([]byte("tenant_slug,tenant_name,email,roles\n")), tenantimport.Options{})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(res.Rows) != 0 || len(res.Errors) != 0 {
		t.Errorf("want 0 rows 0 errors, got %d/%d", len(res.Rows), len(res.Errors))
	}
}

// -----------------------------------------------------------------------------
// Slug boundary conditions (LOCKED regex ^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$:
// 3..64 chars, no leading/trailing hyphen) + hosting_mode / country / currency
// normalization and rejection.
// -----------------------------------------------------------------------------
func TestParse_FieldValidation(t *testing.T) {
	slug64 := "a" + strings.Repeat("b", 62) + "c" // 64 chars — valid ceiling
	slug65 := "a" + strings.Repeat("b", 63) + "c" // 65 chars — over
	header := "tenant_slug,tenant_name,hosting_mode,country,currency,email,roles\n"

	cases := []struct {
		name     string
		row      string
		wantErrs []errKey
		wantRow  *tenantimport.Row
	}{
		{
			name: "64-char slug + lowercase hosting mode + country/currency normalize",
			row:  slug64 + ",Edge Inst,white_label,my,myr,zoe@edge.example,learner\n",
			wantRow: &tenantimport.Row{
				Line: 2, TenantSlug: slug64, TenantName: "Edge Inst",
				HostingMode: "WHITE_LABEL", Country: "MY", Currency: "MYR",
				Email: "zoe@edge.example", Roles: []identity.Role{identity.RoleLearner},
			},
		},
		{
			name:     "65-char slug rejected",
			row:      slug65 + ",Edge Inst,,,,zoe@edge.example,learner\n",
			wantErrs: []errKey{{Line: 2, Field: "tenant_slug", Code: tenantimport.ErrCodeInvalidTenantSlug}},
		},
		{
			name:     "leading hyphen slug rejected",
			row:      "-bad-slug,Edge Inst,,,,zoe@edge.example,learner\n",
			wantErrs: []errKey{{Line: 2, Field: "tenant_slug", Code: tenantimport.ErrCodeInvalidTenantSlug}},
		},
		{
			name:     "unknown hosting mode rejected",
			row:      "edge-inst,Edge Inst,ON_PREM,,,zoe@edge.example,learner\n",
			wantErrs: []errKey{{Line: 2, Field: "hosting_mode", Code: tenantimport.ErrCodeInvalidHostingMode}},
		},
		{
			name:     "bad country rejected",
			row:      "edge-inst,Edge Inst,,Singapore,,zoe@edge.example,learner\n",
			wantErrs: []errKey{{Line: 2, Field: "country", Code: tenantimport.ErrCodeInvalidCountry}},
		},
		{
			name:     "bad currency rejected",
			row:      "edge-inst,Edge Inst,,,S$,zoe@edge.example,learner\n",
			wantErrs: []errKey{{Line: 2, Field: "currency", Code: tenantimport.ErrCodeInvalidCurrency}},
		},
		{
			name:     "empty roles cell rejected",
			row:      "edge-inst,Edge Inst,,,,zoe@edge.example,\n",
			wantErrs: []errKey{{Line: 2, Field: "roles", Code: tenantimport.ErrCodeMissingRoles}},
		},
		{
			name: "smart quotes + padding tolerated on tokens",
			row:  "edge-inst,Edge Inst,,,,zoe@edge.example,“learner”| admin \n",
			wantRow: &tenantimport.Row{
				Line: 2, TenantSlug: "edge-inst", TenantName: "Edge Inst",
				Email: "zoe@edge.example",
				Roles: []identity.Role{identity.RoleLearner, identity.RoleAdmin},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := tenantimport.Parse(bytes.NewReader([]byte(header+tc.row)), tenantimport.Options{})
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			assertErrKeys(t, res.Errors, tc.wantErrs)
			if tc.wantRow != nil {
				assertRows(t, res.Rows, []tenantimport.Row{*tc.wantRow})
			} else {
				assertRows(t, res.Rows, nil)
			}
		})
	}
}
