// Tests for the KYC fast-path projection on the User aggregate (BE-USR-1, ADR-142).
package identity_test

import (
	"testing"
	"time"

	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

func TestNewUser_DefaultsVerificationStatusToUnverified(t *testing.T) {
	t.Parallel()
	u, err := identity.NewUser(identity.NewUserParams{
		Email: "x@y.com", IdentityProvider: identity.ProviderOIDC, FederatedSubject: "s",
	})
	if err != nil {
		t.Fatalf("NewUser: %v", err)
	}
	if u.VerificationStatus != identity.VerificationStatusUnverified {
		t.Errorf("VerificationStatus=%q want unverified", u.VerificationStatus)
	}
	if u.KycVerifiedAt != nil {
		t.Errorf("KycVerifiedAt should be nil")
	}
}

func TestUser_MarkKycVerified_SetsFieldsAndStatus(t *testing.T) {
	t.Parallel()
	u, _ := identity.NewUser(identity.NewUserParams{
		Email: "x@y.com", IdentityProvider: identity.ProviderOIDC, FederatedSubject: "s",
	})
	when := time.Now().UTC().Add(-time.Hour)
	u.MarkKycVerified(identity.KycMethod("singpass"), when)
	if u.VerificationStatus != identity.VerificationStatusVerified {
		t.Errorf("VerificationStatus=%q want verified", u.VerificationStatus)
	}
	if u.KycMethod != identity.KycMethod("singpass") {
		t.Errorf("KycMethod=%q", u.KycMethod)
	}
	if u.KycVerifiedAt == nil || !u.KycVerifiedAt.Equal(when) {
		t.Errorf("KycVerifiedAt mismatch")
	}
}

func TestUser_MarkKycVerified_IdempotentOnSameMethod(t *testing.T) {
	t.Parallel()
	u, _ := identity.NewUser(identity.NewUserParams{
		Email: "x@y.com", IdentityProvider: identity.ProviderOIDC, FederatedSubject: "s",
	})
	when := time.Now().UTC()
	u.MarkKycVerified(identity.KycMethod("singpass"), when)
	first := u.UpdatedAt
	u.MarkKycVerified(identity.KycMethod("singpass"), when.Add(time.Hour))
	if !u.UpdatedAt.Equal(first) {
		t.Errorf("MarkKycVerified should be idempotent on same method")
	}
}

func TestUser_MarkKycPending_SetsStatusAndMethod(t *testing.T) {
	t.Parallel()
	u, _ := identity.NewUser(identity.NewUserParams{
		Email: "x@y.com", IdentityProvider: identity.ProviderOIDC, FederatedSubject: "s",
	})
	u.MarkKycPending(identity.KycMethod("manual_doc"))
	if u.VerificationStatus != identity.VerificationStatusPending {
		t.Errorf("VerificationStatus=%q want pending", u.VerificationStatus)
	}
	if u.KycMethod != identity.KycMethod("manual_doc") {
		t.Errorf("KycMethod=%q", u.KycMethod)
	}
}

func TestUser_MarkKycRejected_SetsStatus(t *testing.T) {
	t.Parallel()
	u, _ := identity.NewUser(identity.NewUserParams{
		Email: "x@y.com", IdentityProvider: identity.ProviderOIDC, FederatedSubject: "s",
	})
	u.MarkKycRejected()
	if u.VerificationStatus != identity.VerificationStatusRejected {
		t.Errorf("VerificationStatus=%q want rejected", u.VerificationStatus)
	}
}

func TestVerificationStatus_Valid(t *testing.T) {
	t.Parallel()
	for _, s := range []identity.VerificationStatus{
		identity.VerificationStatusUnverified,
		identity.VerificationStatusPending,
		identity.VerificationStatusVerified,
		identity.VerificationStatusRejected,
		identity.VerificationStatusExpired,
	} {
		if !s.Valid() {
			t.Errorf("%q.Valid()=false", s)
		}
	}
	if identity.VerificationStatus("blue").Valid() {
		t.Errorf("invalid status accepted")
	}
}
