// pending_invite_test.go — TDD RED for WS3 / CHO-1873 (ADR-194 D2): the
// PendingInvite aggregate (cold-invite / pending-membership lifecycle).
package identity

import (
	"testing"
	"time"
)

func validInviteParams() NewPendingInviteParams {
	return NewPendingInviteParams{
		TenantID:      "11111111-1111-7111-8111-111111111111",
		Email:         "  Anika@MTM.sg ",
		Roles:         []Role{RoleInstructor},
		InvitedByGcid: "00000000-0000-7000-8000-0000000000aa",
	}
}

func TestNewPendingInvite_happyPath(t *testing.T) {
	pi, err := NewPendingInvite(validInviteParams())
	if err != nil {
		t.Fatalf("NewPendingInvite: %v", err)
	}
	if pi.Status != PendingInviteStatusPending {
		t.Errorf("status: got %q want pending", pi.Status)
	}
	// Email normalised to lowercase + trimmed.
	if pi.Email != "anika@mtm.sg" {
		t.Errorf("email: got %q want anika@mtm.sg (normalised)", pi.Email)
	}
	if len(pi.Roles) != 1 || pi.Roles[0] != RoleInstructor {
		t.Errorf("roles: got %v", pi.Roles)
	}
	if pi.InviteID == "" || pi.Token == "" {
		t.Errorf("invite_id + token must be minted (id=%q token=%q)", pi.InviteID, pi.Token)
	}
	if pi.ExpiresAt.IsZero() || !pi.ExpiresAt.After(pi.CreatedAt) {
		t.Errorf("expires_at must be after created_at (exp=%v created=%v)", pi.ExpiresAt, pi.CreatedAt)
	}
	if pi.AcceptedAt != nil || pi.AcceptedGcid != "" {
		t.Errorf("a fresh invite must not be accepted")
	}
}

func TestNewPendingInvite_validation(t *testing.T) {
	cases := map[string]func(*NewPendingInviteParams){
		"empty tenant":  func(p *NewPendingInviteParams) { p.TenantID = "" },
		"empty email":   func(p *NewPendingInviteParams) { p.Email = "   " },
		"invalid email": func(p *NewPendingInviteParams) { p.Email = "not-an-email" },
		"no roles":      func(p *NewPendingInviteParams) { p.Roles = nil },
		"invalid role":  func(p *NewPendingInviteParams) { p.Roles = []Role{"bogus"} },
		"empty inviter": func(p *NewPendingInviteParams) { p.InvitedByGcid = "" },
	}
	for name, mutate := range cases {
		p := validInviteParams()
		mutate(&p)
		if _, err := NewPendingInvite(p); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestNewPendingInvite_defaultTTL(t *testing.T) {
	p := validInviteParams()
	p.TTL = 0
	pi, err := NewPendingInvite(p)
	if err != nil {
		t.Fatalf("NewPendingInvite: %v", err)
	}
	want := pi.CreatedAt.Add(DefaultInviteTTL)
	if pi.ExpiresAt.Sub(want).Abs() > time.Second {
		t.Errorf("expires_at: got %v want ~%v (default TTL)", pi.ExpiresAt, want)
	}
}

func TestPendingInvite_Accept(t *testing.T) {
	pi, _ := NewPendingInvite(validInviteParams())
	gcid := "00000000-0000-7000-8000-000000001999"
	if err := pi.Accept(gcid); err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if pi.Status != PendingInviteStatusAccepted || pi.AcceptedGcid != gcid || pi.AcceptedAt == nil {
		t.Errorf("after Accept: status=%q gcid=%q at=%v", pi.Status, pi.AcceptedGcid, pi.AcceptedAt)
	}
	// Double-accept is rejected.
	if err := pi.Accept(gcid); err == nil {
		t.Error("accepting an already-accepted invite must error")
	}
}

func TestPendingInvite_Accept_rejectsAgidAndEmpty(t *testing.T) {
	pi, _ := NewPendingInvite(validInviteParams())
	if err := pi.Accept("0197a000-0000-7000-8000-000000000001"); err == nil {
		t.Error("AGID must not accept an invite")
	}
	pi2, _ := NewPendingInvite(validInviteParams())
	if err := pi2.Accept("   "); err == nil {
		t.Error("empty gcid must error")
	}
}

func TestPendingInvite_Revoke(t *testing.T) {
	pi, _ := NewPendingInvite(validInviteParams())
	if err := pi.Revoke(); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if pi.Status != PendingInviteStatusRevoked {
		t.Errorf("status: got %q want revoked", pi.Status)
	}
	// Cannot revoke a non-pending invite, and cannot accept a revoked one.
	if err := pi.Revoke(); err == nil {
		t.Error("re-revoke must error")
	}
	if err := pi.Accept("00000000-0000-7000-8000-000000001999"); err == nil {
		t.Error("accepting a revoked invite must error")
	}
}

func TestPendingInvite_IsExpired(t *testing.T) {
	pi, _ := NewPendingInvite(validInviteParams())
	if pi.IsExpired(pi.CreatedAt) {
		t.Error("fresh invite must not be expired at creation")
	}
	if !pi.IsExpired(pi.ExpiresAt.Add(time.Second)) {
		t.Error("invite past expires_at must be expired")
	}
	// A non-pending invite is never "expired" (its terminal state stands).
	_ = pi.Revoke()
	if pi.IsExpired(pi.ExpiresAt.Add(time.Hour)) {
		t.Error("a revoked invite must not report expired")
	}
}
