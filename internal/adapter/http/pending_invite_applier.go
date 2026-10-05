// pending_invite_applier.go — WS3 / CHO-1873 (ADR-194 D2). The resolve-time
// cold-invite applier: at first login, match live pending invites for the
// resolved email and apply each (authoritative chora_tenancy write + identity
// mirror) + mark accepted. Invoked from resolve_handler AFTER the ADR-182 3b
// chora-master auto-enrol, so a cold-invited Training-Admin lands
// chora-master[learner,author] + the invited tenant[instructor].
package httpadapter

import (
	"context"
	"fmt"
	"log"

	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// PendingInviteMatcher is the cross-tenant email matcher + accept-marker the
// applier needs (the pg PendingInviteRepository satisfies it).
type PendingInviteMatcher interface {
	MatchByEmail(ctx context.Context, email string) ([]identity.PendingInviteMatch, error)
	MarkAccepted(ctx context.Context, tenantID, inviteID, gcid string) error
}

// PendingInviteApplier orchestrates ApplyByEmail. Reuses the WS2 grant
// machinery: authoritative-first (chora_tenancy) + identity mirror.
type PendingInviteApplier struct {
	matcher       PendingInviteMatcher
	authoritative AuthoritativeMembershipUpserter // nil in dev (no tenancy conn)
	grant         GrantMembershipWriter
}

// NewPendingInviteApplier constructs the applier.
func NewPendingInviteApplier(matcher PendingInviteMatcher, authoritative AuthoritativeMembershipUpserter, grant GrantMembershipWriter) *PendingInviteApplier {
	return &PendingInviteApplier{matcher: matcher, authoritative: authoritative, grant: grant}
}

// ApplyByEmail matches live pending invites for `email` and applies each to
// `gcid`, returning the tenant IDs successfully applied (the resolve handler
// prefers the first as the default active tenant). Best-effort + idempotent:
// a per-invite failure is logged and skipped — the invite stays pending and
// re-applies on the next resolve (GrantMembership + MarkAccepted are both
// idempotent). Returns an error only when the matcher itself fails.
func (a *PendingInviteApplier) ApplyByEmail(ctx context.Context, gcid, email string) ([]string, error) {
	if a == nil || a.matcher == nil {
		return nil, nil
	}
	matches, err := a.matcher.MatchByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("pending-invite match: %w", err)
	}
	var applied []string
	for _, m := range matches {
		roles := toGrantRoles(m.Roles)
		if len(roles) == 0 {
			log.Printf("invite-apply: invite %s carries no valid role — skipping", m.InviteID)
			continue
		}
		// Authoritative-first (chora_tenancy): the mint reads it, so a
		// mirror-only apply would produce a member who can't log in.
		if a.authoritative != nil {
			if _, err := a.authoritative.UpsertMembershipByTenantID(ctx, gcid, m.TenantID, m.Roles); err != nil {
				log.Printf("invite-apply: authoritative upsert tenant=%s: %v (invite stays pending; retries next login)", m.TenantID, err)
				continue
			}
		}
		// Identity mirror — RunInTenantTx(m.TenantID) in the pg repo.
		if _, err := a.grant.GrantMembership(ctx, gcid, m.TenantID, roles); err != nil {
			log.Printf("invite-apply: mirror grant tenant=%s: %v (invite stays pending)", m.TenantID, err)
			continue
		}
		// Mark accepted — idempotent; best-effort (the grant already landed).
		if err := a.matcher.MarkAccepted(ctx, m.TenantID, m.InviteID, gcid); err != nil {
			log.Printf("invite-apply: mark-accepted tenant=%s invite=%s: %v", m.TenantID, m.InviteID, err)
		}
		applied = append(applied, m.TenantID)
	}
	return applied, nil
}

// toGrantRoles converts lowercase membership_role tokens to domain Roles,
// dropping anything that is not a valid membership_role (defensive — the matcher
// reads stored roles, but a future token shouldn't crash a login).
func toGrantRoles(raw []string) []identity.Role {
	out := make([]identity.Role, 0, len(raw))
	for _, s := range raw {
		if r := identity.Role(s); r.Grantable() {
			out = append(out, r)
		}
	}
	return out
}
