// Package authn is the local username/password authentication domain for
// chora-identity.
//
// It owns:
//
//   - the normalisation rule for usernames (case-insensitive, trimmed) and the
//     credential record (username + Argon2id PHC hash), and
//   - the Argon2id password hashing / verification helpers.
//
// Credentials are globally unique by username: login sends only
// username+password, so per-tenant uniqueness would be ambiguous. The username
// is stored in its normalised form and enforced by a UNIQUE constraint.
//
// Hexagonal: this package is dependency-free w.r.t. infrastructure. Adapters
// (pgx, in-memory) implement the repository ports.
package authn

import (
	"context"
	"errors"
	"strings"
	"time"
)

// ErrCredentialsNotFound is returned when no credential row matches the
// supplied normalised username.
var ErrCredentialsNotFound = errors.New("authn: credentials not found")

// NormalizeUsername returns the canonical, globally-unique form of a username:
// trimmed and lower-cased. The stored `username_norm` column and every lookup
// key use this form.
func NormalizeUsername(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

// Credentials is one local username/password credential, keyed 1:1 by GCID.
// PasswordHash is the PHC string produced by HashPassword.
type Credentials struct {
	Gcid         string
	Username     string
	UsernameNorm string
	PasswordHash string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// CredentialsRepository is the persistence port for local credentials.
type CredentialsRepository interface {
	// GetByUsernameNorm returns the credential for the normalised username, or
	// ErrCredentialsNotFound.
	GetByUsernameNorm(ctx context.Context, usernameNorm string) (*Credentials, error)
	// Upsert inserts or updates the credential for a GCID, keyed on the
	// normalised username. Idempotent.
	Upsert(ctx context.Context, c *Credentials) error
}

// Membership is one ACTIVE tenant membership row projected for login
// resolution. A single (tenant, role) pair per row; a user may hold several
// rows for the same tenant (multi-role) and several tenants.
type Membership struct {
	TenantID  string
	Role      string
	CreatedAt time.Time
}

// MembershipRepository is the persistence port for the login-time membership
// read (all active memberships for a GCID, across tenants).
type MembershipRepository interface {
	ListActiveByGCID(ctx context.Context, gcid string) ([]Membership, error)
}

// TenantRoles groups active roles by tenant, preserving a deterministic role
// order (ascending) for stable responses.
type TenantRoles struct {
	TenantID string
	Roles    []string
}

// GroupByTenant folds membership rows into per-tenant role sets, sorted by
// tenant_id then role so the response is deterministic.
func GroupByTenant(memberships []Membership) []TenantRoles {
	byTenant := map[string][]string{}
	order := []string{}
	for _, m := range memberships {
		if _, seen := byTenant[m.TenantID]; !seen {
			order = append(order, m.TenantID)
		}
		byTenant[m.TenantID] = append(byTenant[m.TenantID], m.Role)
	}
	out := make([]TenantRoles, 0, len(order))
	for _, tid := range order {
		roles := byTenant[tid]
		sortStrings(roles)
		out = append(out, TenantRoles{TenantID: tid, Roles: roles})
	}
	return out
}

// ResolveActiveTenant picks the authoritative active tenant from the grouped
// memberships. It returns ("", nil) when there is no active membership.
//
// Semantics: the service's active tenant is the tenant the user has belonged to
// LONGEST — the tenant of the earliest-created active membership — with
// tenant_id ascending as a deterministic tie-break. This mirrors the
// resolve-handler default-tenant precedence (an explicit hint, else the
// service-derived default) while remaining fully deterministic without an
// external hint. It deliberately does NOT take an unordered SQL row.
func ResolveActiveTenant(memberships []Membership, groups []TenantRoles) (string, []string) {
	if len(memberships) == 0 || len(groups) == 0 {
		return "", nil
	}
	earliest := make(map[string]time.Time, len(groups))
	for _, m := range memberships {
		if t, ok := earliest[m.TenantID]; !ok || m.CreatedAt.Before(t) {
			earliest[m.TenantID] = m.CreatedAt
		}
	}
	best := ""
	var bestAt time.Time
	for _, g := range groups {
		at := earliest[g.TenantID]
		switch {
		case best == "":
			best, bestAt = g.TenantID, at
		case at.Before(bestAt):
			best, bestAt = g.TenantID, at
		case at.Equal(bestAt) && g.TenantID < best:
			best = g.TenantID
		}
	}
	for _, g := range groups {
		if g.TenantID == best {
			return best, append([]string(nil), g.Roles...)
		}
	}
	return "", nil
}

// sortStrings is a tiny insertion sort — role slices are at most a handful of
// entries, so this avoids importing sort for one call site.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
