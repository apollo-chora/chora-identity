// Package tenantimport implements the LOCKED tenant + user CSV mass-import
// contract (ADR-221 D2; CR docs/TENANT-MASS-IMPORT-CR-2026-07-02.md §5.1,
// minor defaults M-1…M-6).
//
// P0 scope (CHO-2020): the pure-domain CSV parser — decode, header mapping,
// per-cell normalization + context-free validation, role canonicalization,
// and the M-6 caps. It is deliberately MODE-AGNOSTIC: rules that depend on
// the run mode (tenant columns forbidden in tenant-admin mode, tenant_name
// consistency per block, in-file duplicate-email union, email uniqueness
// after merge) belong to the P1 ImportJob validator, not the parser.
//
// Failure semantics (GQ-7): structural whole-file problems return *FileError;
// per-cell problems land in ParseResult.Errors as (line, field, code, reason)
// and EXCLUDE only that row — good rows always survive bad ones.
package tenantimport

import (
	"fmt"

	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// Canonical CSV column names (LOCKED header set, CR §5.1). Header matching is
// case-insensitive (M-3); these lowercase snake_case forms are canonical.
const (
	ColTenantSlug  = "tenant_slug"
	ColTenantName  = "tenant_name"
	ColHostingMode = "hosting_mode"
	ColCountry     = "country"
	ColCurrency    = "currency"
	ColEmail       = "email"
	ColDisplayName = "display_name"
	ColRoles       = "roles"
	ColExternalRef = "external_ref"
	ColLocale      = "locale"
	ColSendInvite  = "send_invite"
)

// M-6 caps — a public contract mirrored in the H+ wizard copy and ADR-221 D2.
const (
	DefaultMaxFileBytes int64 = 20 * 1024 * 1024 // 20 MiB per file
	DefaultMaxRows            = 50_000           // data rows per file
)

// Options tunes the M-6 caps; zero values mean the locked defaults. Tests use
// small caps — production callers pass Options{}.
type Options struct {
	MaxFileBytes int64
	MaxRows      int
}

// Row is one parsed, normalized user row. Line is the 1-based physical CSV
// line (header = line 1) so validation-report errors point at what the
// operator sees in Excel/GSheets.
type Row struct {
	Line        int
	TenantSlug  string // trimmed + lowercased; matches the locked slug regex when non-empty
	TenantName  string
	HostingMode string // canonical UPPERCASE enum value, or "" (default applied at execution)
	Country     string // ISO 3166-1 alpha-2, uppercased, or ""
	Currency    string // ISO 4217 alpha-3, uppercased, or ""
	Email       string // normalized lower/trim (M-4)
	DisplayName string
	Roles       []identity.Role // canonicalized, deduplicated, first-seen order
	ExternalRef string          // preserved VERBATIM as text — leading zeros safe (M-5)
	Locale      string          // reserved for the P3 invite-email locale
	SendInvite  *bool           // nil = column absent / cell empty (job-level toggle applies)
}

// RowError pinpoints one defective cell (or row) — the (row, field, reason)
// triple the CR's downloadable error CSV is built from (AC-5). Code is the
// stable machine-readable contract; Reason is the human-facing explanation.
type RowError struct {
	Line   int
	Field  string // canonical column name; "" for whole-row defects
	Code   string
	Reason string
}

// Stable RowError codes.
const (
	ErrCodeDuplicateHeader    = "duplicate_header"
	ErrCodeUnknownHeader      = "unknown_header"
	ErrCodeInvalidTenantSlug  = "invalid_tenant_slug"
	ErrCodeInvalidHostingMode = "invalid_hosting_mode"
	ErrCodeInvalidCountry     = "invalid_country"
	ErrCodeInvalidCurrency    = "invalid_currency"
	ErrCodeMissingEmail       = "missing_email"
	ErrCodeInvalidEmail       = "invalid_email"
	ErrCodeMissingRoles       = "missing_roles"
	ErrCodeInvalidRole        = "invalid_role"
	ErrCodeForbiddenRole      = "forbidden_role"
	ErrCodeInvalidSendInvite  = "invalid_send_invite"
	ErrCodeRowTooWide         = "row_too_wide"
	ErrCodeInvalidUTF8        = "invalid_utf8"
)

// FileError rejects the WHOLE file — structural problems no row-level report
// can recover from (fail-loud; the job flips to failed/validation-error).
type FileError struct {
	Code    string
	Line    int // 1-based line where detected; 0 when not line-specific
	Message string
}

// Stable FileError codes.
const (
	FileErrCodeEmpty         = "empty_file"
	FileErrCodeTooLarge      = "file_too_large"
	FileErrCodeTooManyRows   = "too_many_rows"
	FileErrCodeMissingHeader = "missing_required_header"
	FileErrCodeMalformed     = "malformed_csv"
	FileErrCodeNotUTF8       = "not_utf8"
)

func (e *FileError) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("csv import rejected (%s, line %d): %s", e.Code, e.Line, e.Message)
	}
	return fmt.Sprintf("csv import rejected (%s): %s", e.Code, e.Message)
}

// ParseResult carries every surviving row plus every per-cell defect.
// Delimiter is the sniffed cell separator (M-1) — surfaced so the P1
// validation report can echo what the parser detected.
type ParseResult struct {
	Rows      []Row
	Errors    []RowError
	Delimiter rune
}
