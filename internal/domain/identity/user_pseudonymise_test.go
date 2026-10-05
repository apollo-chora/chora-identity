package identity_test

import (
	"strings"
	"testing"

	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

func newActiveUser(t *testing.T) *identity.User {
	t.Helper()
	u, err := identity.NewUser(identity.NewUserParams{
		Email:            "phyllis@mightymind.sg",
		DisplayName:      "Phyllis",
		IdentityProvider: identity.ProviderOIDC,
		FederatedSubject: "google|phyllis-001",
	})
	if err != nil {
		t.Fatalf("NewUser: %v", err)
	}
	return u
}

func TestUserPseudonymise_TombstonesPIIAndSoftDeletes(t *testing.T) {
	u := newActiveUser(t)
	originalGcid := u.Gcid

	u.Pseudonymise("user-abc123@redacted.invalid", "Former member")

	if u.Email != "user-abc123@redacted.invalid" {
		t.Errorf("email = %q", u.Email)
	}
	if u.DisplayName != "Former member" {
		t.Errorf("display name = %q", u.DisplayName)
	}
	if u.Status != identity.UserStatusClosed {
		t.Errorf("status = %v", u.Status)
	}
	if u.DeletedAt == nil {
		t.Error("DeletedAt must be set (soft delete frees the partial unique email index)")
	}
	// GCID is preserved — FK integrity across all domains depends on it.
	if u.Gcid != originalGcid {
		t.Errorf("gcid changed: %q", u.Gcid)
	}
	// The IdP subject is tombstoned so the (provider, subject) unique pair
	// can never resurrect the closed account.
	if !strings.HasPrefix(u.FederatedSubject, "shredded:") {
		t.Errorf("federated subject = %q", u.FederatedSubject)
	}
}

func TestUserPseudonymise_Idempotent(t *testing.T) {
	u := newActiveUser(t)
	u.Pseudonymise("user-abc@redacted.invalid", "Former member")
	first := *u.DeletedAt
	u.Pseudonymise("user-abc@redacted.invalid", "Former member")
	if !u.DeletedAt.Equal(first) {
		t.Error("second Pseudonymise must not move DeletedAt")
	}
}

func TestUserPseudonymise_FreesEmailForFreshGCID(t *testing.T) {
	// The re-registration invariant (CHO-1719 gap 7): after closure the
	// SAME email must mint a FRESH GCID while the old aggregate stays
	// pseudonymised.
	old := newActiveUser(t)
	originalEmail := old.Email
	old.Pseudonymise("user-abc@redacted.invalid", "Former member")

	if old.Email == originalEmail {
		t.Fatal("pseudonymised user must not retain the original email")
	}

	fresh, err := identity.NewUser(identity.NewUserParams{
		Email:            originalEmail,
		IdentityProvider: identity.ProviderOIDC,
		FederatedSubject: "google|phyllis-NEW",
	})
	if err != nil {
		t.Fatalf("re-registration NewUser: %v", err)
	}
	if fresh.Gcid == old.Gcid {
		t.Error("re-registration must mint a FRESH GCID")
	}
	if fresh.Status != identity.UserStatusActive {
		t.Errorf("fresh user status = %v", fresh.Status)
	}
	if old.Status != identity.UserStatusClosed || old.DeletedAt == nil {
		t.Error("old aggregate must stay pseudonymised")
	}
}
