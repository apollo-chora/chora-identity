package tenantimport

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// LOCKED slug shape (CR §5.1): 3–64 chars, lowercase alnum + interior hyphens.
var slugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$`)

// Pragmatic CSV-grade email check (full RFC validation is not the parser's
// job; GCIP/invite layers re-validate at materialization).
var emailRe = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

const maxEmailLen = 320

var (
	countryRe  = regexp.MustCompile(`^[A-Z]{2}$`)
	currencyRe = regexp.MustCompile(`^[A-Z]{3}$`)
)

// hostingModes mirrors the tenancy wire enum (proto HostingMode / PG
// tenant_hosting_mode) as plain strings — the domain package stays free of
// proto imports; the P2 executor maps to the gRPC enum at the adapter.
var hostingModes = map[string]struct{}{
	"PLATFORM_HOSTED": {},
	"WHITE_LABEL":     {},
	"FRANCHISE":       {},
	"SELF_HOST":       {},
}

// Role aliases canonicalized at parse time (GQ-6). Values must stay inside
// identity's 5 grantable roles — the CSV layer NEVER invents vocabulary.
var roleAliases = map[string]identity.Role{
	"tenant_admin":   identity.RoleAdmin,
	"training_admin": identity.RoleInstructor,
}

// forbiddenRoles hard-reject at row level (GQ-6): owner is bootstrap-only,
// platform_operator is JWT-only (ADR-165) — neither is CSV-grantable.
var forbiddenRoles = map[string]struct{}{
	"owner":             {},
	"platform_operator": {},
}

// knownColumns is the full LOCKED header set.
var knownColumns = map[string]struct{}{
	ColTenantSlug: {}, ColTenantName: {}, ColHostingMode: {}, ColCountry: {},
	ColCurrency: {}, ColEmail: {}, ColDisplayName: {}, ColRoles: {},
	ColExternalRef: {}, ColLocale: {}, ColSendInvite: {},
}

// fieldOrder fixes deterministic per-row error ordering (column order of the
// published template).
var fieldOrder = []string{
	ColTenantSlug, ColTenantName, ColHostingMode, ColCountry, ColCurrency,
	ColEmail, ColDisplayName, ColRoles, ColExternalRef, ColLocale, ColSendInvite,
}

// Parse decodes one import CSV per the locked contract. Structural failures
// (caps, missing required header, malformed quoting, non-UTF-8 header, empty
// file) return *FileError; per-cell defects accumulate in ParseResult.Errors
// and exclude only their own row (GQ-7).
func Parse(r io.Reader, opts Options) (*ParseResult, error) {
	maxBytes := opts.MaxFileBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxFileBytes
	}
	maxRows := opts.MaxRows
	if maxRows <= 0 {
		maxRows = DefaultMaxRows
	}

	// M-6 byte cap. Read one byte past the cap so truncation is DETECTED,
	// never silent (an io.LimitReader-style clean EOF at the cap would let a
	// truncated file parse "successfully" — fail-loud forbids that).
	data, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("tenantimport: reading csv: %w", err)
	}
	if int64(len(data)) > maxBytes {
		return nil, &FileError{
			Code:    FileErrCodeTooLarge,
			Message: fmt.Sprintf("file exceeds the %d-byte cap (M-6)", maxBytes),
		}
	}

	// M-2: tolerate the Excel "CSV UTF-8" byte-order mark.
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})

	if len(bytes.TrimSpace(data)) == 0 {
		return nil, &FileError{Code: FileErrCodeEmpty, Message: "file contains no header row"}
	}

	delim := sniffDelimiter(firstLine(data))

	cr := csv.NewReader(bytes.NewReader(data))
	cr.Comma = delim
	cr.FieldsPerRecord = -1 // ragged rows handled ourselves (Excel pads/trims)

	header, err := cr.Read()
	if err != nil {
		return nil, malformedFileError(err)
	}
	for _, cell := range header {
		if !utf8.ValidString(cell) {
			return nil, &FileError{
				Code: FileErrCodeNotUTF8, Line: 1,
				Message: "header row is not valid UTF-8 — export as CSV UTF-8 (M-2)",
			}
		}
	}

	colIdx, headerErrs := mapHeader(header)
	for _, req := range []string{ColEmail, ColRoles} {
		if _, ok := colIdx[req]; !ok {
			return nil, &FileError{
				Code: FileErrCodeMissingHeader, Line: 1,
				Message: fmt.Sprintf("required column %q is missing from the header", req),
			}
		}
	}

	result := &ParseResult{Delimiter: delim, Errors: headerErrs}
	dataRows := 0
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// A structural mid-file failure poisons everything after it —
			// reject the file rather than silently dropping the remainder.
			return nil, malformedFileError(err)
		}
		line, _ := cr.FieldPos(0)

		if allEmpty(rec) {
			continue // Excel trailing/interstitial ",,,," artifact rows
		}

		dataRows++
		if dataRows > maxRows {
			return nil, &FileError{
				Code: FileErrCodeTooManyRows, Line: line,
				Message: fmt.Sprintf("file exceeds the %d-data-row cap (M-6)", maxRows),
			}
		}

		if wide := len(rec) > len(header) && !allEmpty(rec[len(header):]); wide {
			result.Errors = append(result.Errors, RowError{
				Line: line, Code: ErrCodeRowTooWide,
				Reason: fmt.Sprintf("row has %d cells but the header defines %d columns", len(rec), len(header)),
			})
			continue
		}

		row, rowErrs := parseRow(line, rec, colIdx)
		if len(rowErrs) > 0 {
			result.Errors = append(result.Errors, rowErrs...)
			continue
		}
		result.Rows = append(result.Rows, row)
	}
	return result, nil
}

// mapHeader resolves canonical column → cell index. First occurrence of a
// duplicated KNOWN column wins (subsequent ones error + are ignored); unknown
// columns error + are ignored; empty header cells (Excel trailing-comma
// artifact) are skipped silently.
func mapHeader(header []string) (map[string]int, []RowError) {
	colIdx := make(map[string]int, len(header))
	var errs []RowError
	for i, cell := range header {
		name := strings.ToLower(normalizeToken(cell))
		if name == "" {
			continue
		}
		if _, known := knownColumns[name]; !known {
			errs = append(errs, RowError{
				Line: 1, Field: name, Code: ErrCodeUnknownHeader,
				Reason: fmt.Sprintf("column %q is not part of the import template and was ignored", name),
			})
			continue
		}
		if _, dup := colIdx[name]; dup {
			errs = append(errs, RowError{
				Line: 1, Field: name, Code: ErrCodeDuplicateHeader,
				Reason: fmt.Sprintf("column %q appears more than once; only the first occurrence was used", name),
			})
			continue
		}
		colIdx[name] = i
	}
	return colIdx, errs
}

// parseRow normalizes + validates every mapped cell of one record. Any error
// invalidates the whole row (its errors are all reported; the row is
// excluded) — a row is applied fully or not at all.
func parseRow(line int, rec []string, colIdx map[string]int) (Row, []RowError) {
	row := Row{Line: line}
	var errs []RowError
	addErr := func(field, code, reason string) {
		errs = append(errs, RowError{Line: line, Field: field, Code: code, Reason: reason})
	}
	cell := func(col string) (string, bool) {
		idx, ok := colIdx[col]
		if !ok || idx >= len(rec) {
			return "", false
		}
		return rec[idx], true
	}

	for _, col := range fieldOrder {
		raw, present := cell(col)
		if !present {
			continue
		}
		if !utf8.ValidString(raw) {
			addErr(col, ErrCodeInvalidUTF8,
				"cell is not valid UTF-8 — export as CSV UTF-8 (M-2)")
			continue
		}
		switch col {
		case ColTenantSlug:
			slug := strings.ToLower(normalizeToken(raw))
			if slug != "" && !slugRe.MatchString(slug) {
				addErr(col, ErrCodeInvalidTenantSlug,
					fmt.Sprintf("%q must be 3-64 chars of a-z, 0-9 and interior hyphens", slug))
				continue
			}
			row.TenantSlug = slug
		case ColTenantName:
			row.TenantName = strings.TrimSpace(raw)
		case ColHostingMode:
			mode := strings.ToUpper(normalizeToken(raw))
			if mode != "" {
				if _, ok := hostingModes[mode]; !ok {
					addErr(col, ErrCodeInvalidHostingMode,
						fmt.Sprintf("%q is not one of PLATFORM_HOSTED, WHITE_LABEL, FRANCHISE, SELF_HOST", mode))
					continue
				}
			}
			row.HostingMode = mode
		case ColCountry:
			c := strings.ToUpper(normalizeToken(raw))
			if c != "" && !countryRe.MatchString(c) {
				addErr(col, ErrCodeInvalidCountry,
					fmt.Sprintf("%q must be an ISO 3166-1 alpha-2 code (e.g. SG)", c))
				continue
			}
			row.Country = c
		case ColCurrency:
			c := strings.ToUpper(normalizeToken(raw))
			if c != "" && !currencyRe.MatchString(c) {
				addErr(col, ErrCodeInvalidCurrency,
					fmt.Sprintf("%q must be an ISO 4217 alpha-3 code (e.g. SGD)", c))
				continue
			}
			row.Currency = c
		case ColEmail:
			email := strings.ToLower(normalizeToken(raw))
			switch {
			case email == "":
				addErr(col, ErrCodeMissingEmail, "email is required on every row")
			case len(email) > maxEmailLen || !emailRe.MatchString(email):
				addErr(col, ErrCodeInvalidEmail, fmt.Sprintf("%q is not a valid email address", email))
			default:
				row.Email = email
			}
		case ColDisplayName:
			row.DisplayName = strings.TrimSpace(raw)
		case ColRoles:
			roles, roleErrs := parseRolesCell(line, raw)
			if len(roleErrs) > 0 {
				errs = append(errs, roleErrs...)
				continue
			}
			row.Roles = roles
		case ColExternalRef:
			row.ExternalRef = strings.TrimSpace(raw) // text VERBATIM — never numeric (M-5)
		case ColLocale:
			row.Locale = strings.TrimSpace(raw)
		case ColSendInvite:
			v := strings.ToLower(normalizeToken(raw))
			switch v {
			case "":
				// leave nil — job-level toggle applies
			case "true", "yes", "1":
				t := true
				row.SendInvite = &t
			case "false", "no", "0":
				f := false
				row.SendInvite = &f
			default:
				addErr(col, ErrCodeInvalidSendInvite,
					fmt.Sprintf("%q is not a boolean (use true/false, yes/no or 1/0)", v))
			}
		}
	}
	if len(errs) > 0 {
		return Row{}, errs
	}
	return row, nil
}

// parseRolesCell splits the pipe/semicolon multi-role list (GQ-6),
// canonicalizes aliases, rejects forbidden/unknown roles, and dedupes
// preserving first-seen order.
func parseRolesCell(line int, raw string) ([]identity.Role, []RowError) {
	var errs []RowError
	var roles []identity.Role
	seen := map[identity.Role]struct{}{}
	tokens := strings.FieldsFunc(raw, func(r rune) bool { return r == '|' || r == ';' })
	for _, tok := range tokens {
		name := strings.ToLower(normalizeToken(tok))
		if name == "" {
			continue
		}
		if _, forbidden := forbiddenRoles[name]; forbidden {
			errs = append(errs, RowError{
				Line: line, Field: ColRoles, Code: ErrCodeForbiddenRole,
				Reason: fmt.Sprintf("role %q cannot be granted via import (owner is bootstrap-only; platform_operator is JWT-only per ADR-165)", name),
			})
			continue
		}
		role, aliased := roleAliases[name]
		if !aliased {
			role = identity.Role(name)
			if !role.Grantable() {
				errs = append(errs, RowError{
					Line: line, Field: ColRoles, Code: ErrCodeInvalidRole,
					Reason: fmt.Sprintf("role %q is not one of learner, author, instructor, admin, auditor (aliases: tenant_admin, training_admin)", name),
				})
				continue
			}
		}
		if _, dup := seen[role]; dup {
			continue
		}
		seen[role] = struct{}{}
		roles = append(roles, role)
	}
	if len(errs) > 0 {
		return nil, errs
	}
	if len(roles) == 0 {
		return nil, []RowError{{
			Line: line, Field: ColRoles, Code: ErrCodeMissingRoles,
			Reason: "at least one role is required (learner, author, instructor, admin, auditor)",
		}}
	}
	return roles, nil
}

// normalizeToken trims whitespace plus wrapping straight/curly quotes — the
// residue Excel + word-processor round-trips leave on enum-ish cells (M-1
// hazards). Cell CONTENT fields (names, refs) use plain TrimSpace instead.
func normalizeToken(s string) string {
	return strings.Trim(strings.TrimSpace(s), `"'`+"“”‘’")
}

// sniffDelimiter picks the M-1 cell separator by counting candidate runes
// OUTSIDE quoted regions of the header line; comma wins ties (the default).
func sniffDelimiter(line string) rune {
	counts := map[rune]int{',': 0, ';': 0, '\t': 0}
	inQuotes := false
	for _, r := range line {
		switch {
		case r == '"':
			inQuotes = !inQuotes
		case !inQuotes:
			if _, ok := counts[r]; ok {
				counts[r]++
			}
		}
	}
	best, bestN := ',', counts[',']
	if counts[';'] > bestN {
		best, bestN = ';', counts[';']
	}
	if counts['\t'] > bestN {
		best = '\t'
	}
	return best
}

func firstLine(data []byte) string {
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		data = data[:i]
	}
	return string(bytes.TrimSuffix(data, []byte{'\r'}))
}

func allEmpty(cells []string) bool {
	for _, c := range cells {
		if strings.TrimSpace(c) != "" {
			return false
		}
	}
	return true
}

// malformedFileError wraps an encoding/csv structural error with its line.
func malformedFileError(err error) *FileError {
	var pe *csv.ParseError
	line := 0
	if errors.As(err, &pe) {
		line = pe.Line
	}
	return &FileError{
		Code: FileErrCodeMalformed, Line: line,
		Message: fmt.Sprintf("malformed CSV: %v", err),
	}
}
