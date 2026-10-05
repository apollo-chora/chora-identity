// pending_invite_applier_extra_test.go — coverage completion for
// pending_invite_applier.go: nil receiver/matcher, per-invite failure paths
// (authoritative error, grant error, mark-accepted error), the nil-authoritative
// variant, multi-role canonicalisation, and a mixed-invite partial success.
package httpadapter

import (
	"context"
	"errors"
	"testing"

	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

const (
	pixGcid   = "00000000-0000-7000-8000-000000001977"
	pixTenant = "22222222-2222-7222-8222-222222222299"
)

// pixMatcher is a PendingInviteMatcher fake whose MarkAccepted can fail
// (distinct from the shared fakeMatcher which always succeeds).
type pixMatcher struct {
	matches  []identity.PendingInviteMatch
	err      error
	markErr  error
	marked   []string
	markCall []string
}

func (f *pixMatcher) MatchByEmail(_ context.Context, _ string) ([]identity.PendingInviteMatch, error) {
	return f.matches, f.err
}

func (f *pixMatcher) MarkAccepted(_ context.Context, tenantID, inviteID, _ string) error {
	f.marked = append(f.marked, inviteID)
	f.markCall = append(f.markCall, tenantID)
	return f.markErr
}

func TestApplyByEmail_NilReceiver_Noop(t *testing.T) {
	var a *PendingInviteApplier
	applied, err := a.ApplyByEmail(context.Background(), pixGcid, "nobody@x.sg")
	if err != nil || applied != nil {
		t.Fatalf("nil receiver: applied=%v err=%v; want nil,nil", applied, err)
	}
}

func TestApplyByEmail_NilMatcher_Noop(t *testing.T) {
	a := NewPendingInviteApplier(nil, nil, nil)
	applied, err := a.ApplyByEmail(context.Background(), pixGcid, "nobody@x.sg")
	if err != nil || applied != nil {
		t.Fatalf("nil matcher: applied=%v err=%v; want nil,nil", applied, err)
	}
}

func TestApplyByEmail_AuthoritativeError_SkipsInvite(t *testing.T) {
	matcher := &fakeMatcher{matches: []identity.PendingInviteMatch{
		{InviteID: "inv-auth-err", TenantID: pixTenant, Roles: []string{"instructor"}},
	}}
	auth := &fakeAuthoritativeUpserter{err: errors.New("tenancy exploded")}
	grant := &fakeGrantWriter{}
	a := NewPendingInviteApplier(matcher, auth, grant)

	applied, err := a.ApplyByEmail(context.Background(), pixGcid, "anika@mtm.sg")
	if err != nil {
		t.Fatalf("ApplyByEmail: %v", err)
	}
	if len(applied) != 0 {
		t.Errorf("applied tenants: got %v want [] (authoritative failure must skip)", applied)
	}
	if grant.gotGcid != "" {
		t.Error("mirror grant must NOT run after an authoritative failure")
	}
	if len(matcher.markedIDs) != 0 {
		t.Errorf("invite must stay pending (unmarked); marked=%v", matcher.markedIDs)
	}
}

func TestApplyByEmail_GrantError_SkipsInvite(t *testing.T) {
	matcher := &fakeMatcher{matches: []identity.PendingInviteMatch{
		{InviteID: "inv-grant-err", TenantID: pixTenant, Roles: []string{"instructor"}},
	}}
	grant := &fakeGrantWriter{err: errors.New("mirror exploded")}
	a := NewPendingInviteApplier(matcher, &fakeAuthoritativeUpserter{created: true}, grant)

	applied, err := a.ApplyByEmail(context.Background(), pixGcid, "anika@mtm.sg")
	if err != nil {
		t.Fatalf("ApplyByEmail: %v", err)
	}
	if len(applied) != 0 {
		t.Errorf("applied tenants: got %v want [] (grant failure must skip)", applied)
	}
	if len(matcher.markedIDs) != 0 {
		t.Errorf("invite must stay pending (unmarked); marked=%v", matcher.markedIDs)
	}
}

func TestApplyByEmail_MarkAcceptedError_StillApplied(t *testing.T) {
	matcher := &pixMatcher{matches: []identity.PendingInviteMatch{
		{InviteID: "inv-mark-err", TenantID: pixTenant, Roles: []string{"author"}},
	}, markErr: errors.New("mark failed")}
	grant := &fakeGrantWriter{}
	a := NewPendingInviteApplier(matcher, &fakeAuthoritativeUpserter{created: true}, grant)

	applied, err := a.ApplyByEmail(context.Background(), pixGcid, "author@x.sg")
	if err != nil {
		t.Fatalf("ApplyByEmail: %v", err)
	}
	if len(applied) != 1 || applied[0] != pixTenant {
		t.Errorf("applied tenants: got %v want [%s] (grant landed despite mark failure)", applied, pixTenant)
	}
	if grant.gotTID != pixTenant {
		t.Errorf("mirror grant tenant: got %q want %q", grant.gotTID, pixTenant)
	}
}

func TestApplyByEmail_MultiRoles_AllCanonicalised(t *testing.T) {
	matcher := &fakeMatcher{matches: []identity.PendingInviteMatch{
		{InviteID: "inv-multi", TenantID: pixTenant, Roles: []string{"instructor", "author"}},
	}}
	grant := &fakeGrantWriter{}
	a := NewPendingInviteApplier(matcher, &fakeAuthoritativeUpserter{created: true}, grant)

	applied, err := a.ApplyByEmail(context.Background(), pixGcid, "multi@x.sg")
	if err != nil {
		t.Fatalf("ApplyByEmail: %v", err)
	}
	if len(applied) != 1 || applied[0] != pixTenant {
		t.Errorf("applied tenants: got %v want [%s]", applied, pixTenant)
	}
	if len(grant.gotRoles) != 2 ||
		grant.gotRoles[0] != identity.RoleInstructor || grant.gotRoles[1] != identity.RoleAuthor {
		t.Errorf("granted roles: got %v want [instructor author]", grant.gotRoles)
	}
}

func TestApplyByEmail_MixedRoles_FiltersInvalid(t *testing.T) {
	matcher := &fakeMatcher{matches: []identity.PendingInviteMatch{
		{InviteID: "inv-mixed", TenantID: pixTenant, Roles: []string{"instructor", "ghost_role", "author"}},
	}}
	grant := &fakeGrantWriter{}
	a := NewPendingInviteApplier(matcher, &fakeAuthoritativeUpserter{created: true}, grant)

	applied, err := a.ApplyByEmail(context.Background(), pixGcid, "mixed@x.sg")
	if err != nil {
		t.Fatalf("ApplyByEmail: %v", err)
	}
	if len(applied) != 1 {
		t.Errorf("applied tenants: got %v want [%s]", applied, pixTenant)
	}
	if len(grant.gotRoles) != 2 ||
		grant.gotRoles[0] != identity.RoleInstructor || grant.gotRoles[1] != identity.RoleAuthor {
		t.Errorf("granted roles: got %v want [instructor author] (invalid token dropped)", grant.gotRoles)
	}
}

func TestApplyByEmail_NilAuthoritative_MirrorOnly(t *testing.T) {
	matcher := &fakeMatcher{matches: []identity.PendingInviteMatch{
		{InviteID: "inv-noauth", TenantID: pixTenant, Roles: []string{"learner"}},
	}}
	grant := &fakeGrantWriter{}
	a := NewPendingInviteApplier(matcher, nil, grant) // no tenancy conn (dev)

	applied, err := a.ApplyByEmail(context.Background(), pixGcid, "learner@x.sg")
	if err != nil {
		t.Fatalf("ApplyByEmail: %v", err)
	}
	if len(applied) != 1 || applied[0] != pixTenant {
		t.Errorf("applied tenants: got %v want [%s]", applied, pixTenant)
	}
	if grant.gotTID != pixTenant || len(grant.gotRoles) != 1 || grant.gotRoles[0] != identity.RoleLearner {
		t.Errorf("mirror grant: tenant=%s roles=%v", grant.gotTID, grant.gotRoles)
	}
}

func TestApplyByEmail_PartialSuccess_SkipsInvalidSecond(t *testing.T) {
	matcher := &fakeMatcher{matches: []identity.PendingInviteMatch{
		{InviteID: "inv-ok", TenantID: pixTenant, Roles: []string{"instructor"}},
		{InviteID: "inv-bad", TenantID: "33333333-3333-7333-8333-333333333399", Roles: []string{"ghost_role"}},
	}}
	grant := &fakeGrantWriter{}
	a := NewPendingInviteApplier(matcher, &fakeAuthoritativeUpserter{created: true}, grant)

	applied, err := a.ApplyByEmail(context.Background(), pixGcid, "partial@x.sg")
	if err != nil {
		t.Fatalf("ApplyByEmail: %v", err)
	}
	if len(applied) != 1 || applied[0] != pixTenant {
		t.Errorf("applied tenants: got %v want [%s]", applied, pixTenant)
	}
	if len(matcher.markedIDs) != 1 || matcher.markedIDs[0] != "inv-ok" {
		t.Errorf("marked accepted: got %v want [inv-ok]", matcher.markedIDs)
	}
}
