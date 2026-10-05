// pending_invite_applier_test.go — WS3 / CHO-1873 (ADR-194 D2).
package httpadapter

import (
	"context"
	"errors"
	"testing"

	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

type fakeMatcher struct {
	matches   []identity.PendingInviteMatch
	err       error
	markedIDs []string
}

func (f *fakeMatcher) MatchByEmail(_ context.Context, _ string) ([]identity.PendingInviteMatch, error) {
	return f.matches, f.err
}

func (f *fakeMatcher) MarkAccepted(_ context.Context, _, inviteID, _ string) error {
	f.markedIDs = append(f.markedIDs, inviteID)
	return nil
}

func TestApplyByEmail_appliesAndMarksAccepted(t *testing.T) {
	matcher := &fakeMatcher{matches: []identity.PendingInviteMatch{
		{InviteID: "inv-1", TenantID: gtmBodyTenant, Roles: []string{"instructor"}},
	}}
	auth := &fakeAuthoritativeUpserter{created: true}
	grant := &fakeGrantWriter{}
	a := NewPendingInviteApplier(matcher, auth, grant)

	applied, err := a.ApplyByEmail(context.Background(), tmTestGcid, "anika@mtm.sg")
	if err != nil {
		t.Fatalf("ApplyByEmail: %v", err)
	}
	if len(applied) != 1 || applied[0] != gtmBodyTenant {
		t.Errorf("applied tenants: got %v want [%s]", applied, gtmBodyTenant)
	}
	if auth.gotTID != gtmBodyTenant || len(auth.gotRoles) != 1 || auth.gotRoles[0] != "instructor" {
		t.Errorf("authoritative: tenant=%s roles=%v", auth.gotTID, auth.gotRoles)
	}
	if grant.gotTID != gtmBodyTenant || len(grant.gotRoles) != 1 || grant.gotRoles[0] != identity.RoleInstructor {
		t.Errorf("mirror grant: tenant=%s roles=%v", grant.gotTID, grant.gotRoles)
	}
	if len(matcher.markedIDs) != 1 || matcher.markedIDs[0] != "inv-1" {
		t.Errorf("marked accepted: got %v want [inv-1]", matcher.markedIDs)
	}
}

func TestApplyByEmail_noMatches_noop(t *testing.T) {
	matcher := &fakeMatcher{} // no matches
	grant := &fakeGrantWriter{}
	a := NewPendingInviteApplier(matcher, &fakeAuthoritativeUpserter{}, grant)

	applied, err := a.ApplyByEmail(context.Background(), tmTestGcid, "nobody@x.sg")
	if err != nil || len(applied) != 0 {
		t.Fatalf("noop: applied=%v err=%v", applied, err)
	}
	if grant.gotGcid != "" {
		t.Error("grant must not be called when there are no matches")
	}
}

func TestApplyByEmail_matcherError(t *testing.T) {
	matcher := &fakeMatcher{err: errors.New("definer boom")}
	a := NewPendingInviteApplier(matcher, &fakeAuthoritativeUpserter{}, &fakeGrantWriter{})
	if _, err := a.ApplyByEmail(context.Background(), tmTestGcid, "x@y.sg"); err == nil {
		t.Error("matcher error must propagate")
	}
}

func TestApplyByEmail_dropsInvalidRoleInvite(t *testing.T) {
	matcher := &fakeMatcher{matches: []identity.PendingInviteMatch{
		{InviteID: "inv-bad", TenantID: gtmBodyTenant, Roles: []string{"ghost_role"}},
	}}
	grant := &fakeGrantWriter{}
	a := NewPendingInviteApplier(matcher, &fakeAuthoritativeUpserter{created: true}, grant)
	applied, err := a.ApplyByEmail(context.Background(), tmTestGcid, "a@b.sg")
	if err != nil {
		t.Fatalf("ApplyByEmail: %v", err)
	}
	if len(applied) != 0 || grant.gotGcid != "" {
		t.Error("an invite carrying only invalid roles must be skipped (no grant)")
	}
}
