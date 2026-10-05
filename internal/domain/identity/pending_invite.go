// pending_invite.go — WS3 / CHO-1873 (ADR-194 D2): the PendingInvite
// aggregate for cold-invite / pending-membership.
//
// A PendingInvite is the COLD half of onboarding: an admin/operator invites an
// EMAIL (not a GCID — the person may never have logged in) into a tenant with
// a role set. The invite is keyed by (tenant_id, lower(email)); there is NO
// gcid until the person first authenticates, at which point the resolve seam
// matches the pending invite by email and applies the membership (Accept).
//
// Lifecycle: pending -> accepted | revoked | expired (terminal). The
// constructor refuses an AGID-shaped accepting identity (invariant #10 — agents
// hold no TenantMembership) at Accept time, and validates the role set up front.
package identity

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// PendingInviteStatus is the lifecycle state of a cold invite.
type PendingInviteStatus string

const (
	PendingInviteStatusPending  PendingInviteStatus = "pending"
	PendingInviteStatusAccepted PendingInviteStatus = "accepted"
	PendingInviteStatusRevoked  PendingInviteStatus = "revoked"
	PendingInviteStatusExpired  PendingInviteStatus = "expired"
)

// DefaultInviteTTL is the validity window applied when NewPendingInviteParams
// leaves TTL unset. Cold invites are long-lived (the invitee may take a while
// to first log in) but not indefinite.
const DefaultInviteTTL = 14 * 24 * time.Hour

// PendingInvite is the aggregate root for a cold tenant invite.
type PendingInvite struct {
	InviteID      string
	TenantID      string
	Email         string // normalised: trimmed + lowercased
	Roles         []Role // canonical lowercase membership roles
	InvitedByGcid string
	Token         string // opaque landing token (UX only; email-match is the authority)
	Status        PendingInviteStatus
	ExpiresAt     time.Time
	AcceptedAt    *time.Time
	AcceptedGcid  string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// NewPendingInviteParams is the constructor input.
type NewPendingInviteParams struct {
	TenantID      string
	Email         string
	Roles         []Role
	InvitedByGcid string
	TTL           time.Duration // <= 0 → DefaultInviteTTL
}

// NewPendingInvite constructs a fresh pending invite, normalising the email,
// de-duplicating + validating the role set, and minting an invite_id + token.
func NewPendingInvite(p NewPendingInviteParams) (*PendingInvite, error) {
	tenant := strings.TrimSpace(p.TenantID)
	if tenant == "" {
		return nil, errors.New("tenant_id is required")
	}
	email := NormalizeEmail(p.Email)
	if email == "" {
		return nil, errors.New("email is required")
	}
	if !looksLikeEmail(email) {
		return nil, fmt.Errorf("invalid email: %q", p.Email)
	}
	if len(p.Roles) == 0 {
		return nil, errors.New("at least one role is required")
	}
	seen := make(map[Role]bool, len(p.Roles))
	roles := make([]Role, 0, len(p.Roles))
	for _, r := range p.Roles {
		if !r.Grantable() {
			return nil, fmt.Errorf("invalid role: %q", string(r))
		}
		if seen[r] {
			continue
		}
		seen[r] = true
		roles = append(roles, r)
	}
	inviter := strings.TrimSpace(p.InvitedByGcid)
	if inviter == "" {
		return nil, errors.New("invited_by_gcid is required")
	}

	id, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("uuidv7 invite_id: %w", err)
	}
	tok, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("uuidv7 token: %w", err)
	}
	ttl := p.TTL
	if ttl <= 0 {
		ttl = DefaultInviteTTL
	}
	now := time.Now().UTC()
	return &PendingInvite{
		InviteID:      id.String(),
		TenantID:      tenant,
		Email:         email,
		Roles:         roles,
		InvitedByGcid: inviter,
		Token:         tok.String(),
		Status:        PendingInviteStatusPending,
		ExpiresAt:     now.Add(ttl),
		CreatedAt:     now,
		UpdatedAt:     now,
	}, nil
}

// Accept transitions a pending invite to accepted, binding the GCID that first
// resolved with the invited email. Refuses AGID-shaped identities (invariant
// #10) and non-pending invites.
func (pi *PendingInvite) Accept(gcid string) error {
	g := strings.TrimSpace(gcid)
	if g == "" {
		return errors.New("accepting gcid is required")
	}
	if IsAGID(g) {
		return errors.New("AGID cannot accept a tenant invite (agents hold no membership)")
	}
	if pi.Status != PendingInviteStatusPending {
		return fmt.Errorf("cannot accept invite in status %q", pi.Status)
	}
	now := time.Now().UTC()
	pi.Status = PendingInviteStatusAccepted
	pi.AcceptedGcid = g
	pi.AcceptedAt = &now
	pi.UpdatedAt = now
	return nil
}

// Revoke transitions a pending invite to revoked (admin cancels before accept).
func (pi *PendingInvite) Revoke() error {
	if pi.Status != PendingInviteStatusPending {
		return fmt.Errorf("cannot revoke invite in status %q", pi.Status)
	}
	pi.Status = PendingInviteStatusRevoked
	pi.UpdatedAt = time.Now().UTC()
	return nil
}

// IsExpired reports whether a still-pending invite has passed its window as of
// `now`. A terminal (accepted/revoked/expired) invite is never "expired".
func (pi *PendingInvite) IsExpired(now time.Time) bool {
	return pi.Status == PendingInviteStatusPending && now.After(pi.ExpiresAt)
}

// RoleStrings returns the role set as lowercase membership_role tokens (the
// shape the pg layer + the authoritative upsert consume).
func (pi *PendingInvite) RoleStrings() []string {
	out := make([]string, 0, len(pi.Roles))
	for _, r := range pi.Roles {
		out = append(out, string(r))
	}
	return out
}

// NormalizeEmail trims + lowercases an email for storage + matching.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// looksLikeEmail is a deliberately-minimal shape check (a single @ with a
// non-empty local part and a dotted domain). Full RFC validation is the IdP's
// job; this only guards against obviously-malformed invite targets.
func looksLikeEmail(email string) bool {
	at := strings.IndexByte(email, '@')
	if at <= 0 || at != strings.LastIndexByte(email, '@') {
		return false
	}
	domain := email[at+1:]
	if len(domain) < 3 || !strings.Contains(domain, ".") {
		return false
	}
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return false
	}
	return true
}

// Sentinel errors for the pending-invite repository.
var (
	// ErrPendingInviteExists — a live pending invite already exists for the
	// (tenant, email) pair (partial-unique violation).
	ErrPendingInviteExists = errors.New("pending invite already exists for (tenant, email)")
	// ErrPendingInviteNotFound — no pending invite matches (invite_id, tenant).
	ErrPendingInviteNotFound = errors.New("pending invite not found")
)

// PendingInviteMatch is the projection the cross-tenant SECURITY DEFINER email
// matcher returns — enough to apply the membership at resolve time.
type PendingInviteMatch struct {
	InviteID  string
	TenantID  string
	Roles     []string // lowercase membership_role tokens
	ExpiresAt time.Time
}
