// Tests for the WebAuthn / Passkey domain primitives.
//
// Per audit-identity-fillgaps.md §3.1 (P0 passkey challenge + verify) +
// Phyllis MVP §3 Step 1: every Phyllis flow starts at
// `POST /v1/auth/passkey/{challenge,verify}` so this is the highest-priority
// gap to close.
//
// RED phase: these tests exercise the domain shape we WANT and currently fail
// to compile because the implementation doesn't exist yet.
//
// Hexagonal note: domain only. No infra imports.
package identity_test

import (
	"strings"
	"testing"
	"time"

	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// -----------------------------------------------------------------------------
// PasskeyChallenge constructor
// -----------------------------------------------------------------------------

func TestNewPasskeyChallenge_Valid(t *testing.T) {
	c, err := identity.NewPasskeyChallenge(identity.NewPasskeyChallengeParams{
		ChallengeBytes: []byte("32-bytes-of-entropy-12345678901234"),
		RPID:           "chora.site",
		UserHandle:     "phyllis@mightymind.sg",
		TTL:            5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.ChallengeID == "" {
		t.Fatalf("challenge_id must be set")
	}
	if c.RPID != "chora.site" {
		t.Fatalf("rp_id mismatch: got %q", c.RPID)
	}
	if c.UserHandle != "phyllis@mightymind.sg" {
		t.Fatalf("user_handle mismatch: got %q", c.UserHandle)
	}
	if c.Status != identity.PasskeyChallengeStatusPending {
		t.Fatalf("expected pending; got %v", c.Status)
	}
	if !time.Now().UTC().Before(c.ExpiresAt) {
		t.Fatalf("expires_at must be in the future: %v", c.ExpiresAt)
	}
	if len(c.ChallengeBytes) < 16 {
		t.Fatalf("challenge_bytes too short")
	}
}

func TestNewPasskeyChallenge_RejectsShortEntropy(t *testing.T) {
	_, err := identity.NewPasskeyChallenge(identity.NewPasskeyChallengeParams{
		ChallengeBytes: []byte("short"),
		RPID:           "chora.site",
		UserHandle:     "x@y.com",
		TTL:            time.Minute,
	})
	if err == nil {
		t.Fatalf("expected error for short challenge bytes")
	}
}

func TestNewPasskeyChallenge_RejectsEmptyRPID(t *testing.T) {
	_, err := identity.NewPasskeyChallenge(identity.NewPasskeyChallengeParams{
		ChallengeBytes: []byte("32-bytes-of-entropy-12345678901234"),
		RPID:           "",
		UserHandle:     "x@y.com",
		TTL:            time.Minute,
	})
	if err == nil {
		t.Fatalf("expected error for empty rp_id")
	}
}

func TestNewPasskeyChallenge_RejectsZeroTTL(t *testing.T) {
	_, err := identity.NewPasskeyChallenge(identity.NewPasskeyChallengeParams{
		ChallengeBytes: []byte("32-bytes-of-entropy-12345678901234"),
		RPID:           "chora.site",
		UserHandle:     "x@y.com",
		TTL:            0,
	})
	if err == nil {
		t.Fatalf("expected error for zero TTL")
	}
}

// -----------------------------------------------------------------------------
// Challenge expiry
// -----------------------------------------------------------------------------

func TestPasskeyChallenge_Expired(t *testing.T) {
	c, err := identity.NewPasskeyChallenge(identity.NewPasskeyChallengeParams{
		ChallengeBytes: []byte("32-bytes-of-entropy-12345678901234"),
		RPID:           "chora.site",
		UserHandle:     "x@y.com",
		TTL:            time.Millisecond, // already-expired by the time we check
	})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	if !c.Expired(time.Now().UTC()) {
		t.Fatalf("expected expired challenge")
	}
}

func TestPasskeyChallenge_NotExpired(t *testing.T) {
	c, err := identity.NewPasskeyChallenge(identity.NewPasskeyChallengeParams{
		ChallengeBytes: []byte("32-bytes-of-entropy-12345678901234"),
		RPID:           "chora.site",
		UserHandle:     "x@y.com",
		TTL:            time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.Expired(time.Now().UTC()) {
		t.Fatalf("did not expect expired challenge")
	}
}

// -----------------------------------------------------------------------------
// Verify state-transitions
// -----------------------------------------------------------------------------

func TestPasskeyChallenge_MarkVerified(t *testing.T) {
	c, _ := identity.NewPasskeyChallenge(identity.NewPasskeyChallengeParams{
		ChallengeBytes: []byte("32-bytes-of-entropy-12345678901234"),
		RPID:           "chora.site",
		UserHandle:     "x@y.com",
		TTL:            time.Hour,
	})
	if err := c.MarkVerified("01935b5a-9bcf-7000-8000-000000000001"); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if c.Status != identity.PasskeyChallengeStatusVerified {
		t.Fatalf("expected verified; got %v", c.Status)
	}
	if c.VerifiedGCID == "" {
		t.Fatalf("verified_gcid must be set")
	}
	// Idempotent re-verify with same gcid is fine.
	if err := c.MarkVerified("01935b5a-9bcf-7000-8000-000000000001"); err != nil {
		t.Fatalf("idempotent re-verify should be fine; got %v", err)
	}
	// Re-verify with DIFFERENT gcid must error.
	if err := c.MarkVerified("01935b5a-9bcf-7000-8000-000000000002"); err == nil {
		t.Fatalf("expected error on re-verify with different gcid")
	}
}

func TestPasskeyChallenge_MarkVerified_RejectsAGID(t *testing.T) {
	c, _ := identity.NewPasskeyChallenge(identity.NewPasskeyChallengeParams{
		ChallengeBytes: []byte("32-bytes-of-entropy-12345678901234"),
		RPID:           "chora.site",
		UserHandle:     "x@y.com",
		TTL:            time.Hour,
	})
	// AGID heuristic = "0197a..." (case-insensitive) — see user.go:IsAGID.
	if err := c.MarkVerified("0197a000-0000-0000-0000-000000000001"); err == nil {
		t.Fatalf("expected AGID rejection")
	}
}

func TestPasskeyChallenge_MarkConsumed(t *testing.T) {
	c, _ := identity.NewPasskeyChallenge(identity.NewPasskeyChallengeParams{
		ChallengeBytes: []byte("32-bytes-of-entropy-12345678901234"),
		RPID:           "chora.site",
		UserHandle:     "x@y.com",
		TTL:            time.Hour,
	})
	if err := c.MarkConsumed(); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if c.Status != identity.PasskeyChallengeStatusConsumed {
		t.Fatalf("expected consumed; got %v", c.Status)
	}
	// Once consumed, MarkVerified must reject (replay protection).
	if err := c.MarkVerified("01935b5a-9bcf-7000-8000-000000000001"); err == nil {
		t.Fatalf("expected error on verify after consume")
	}
}

// -----------------------------------------------------------------------------
// Passkey credential aggregate
// -----------------------------------------------------------------------------

func TestNewPasskeyCredential_Valid(t *testing.T) {
	cred, err := identity.NewPasskeyCredential(identity.NewPasskeyCredentialParams{
		Gcid:            "01935b5a-9bcf-7000-8000-000000000001",
		CredentialID:    []byte("cred-id-bytes"),
		PublicKeyCOSE:   []byte("cose-public-key"),
		AttestationType: "none",
		RPID:            "chora.site",
	})
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if cred.Gcid != "01935b5a-9bcf-7000-8000-000000000001" {
		t.Fatalf("gcid mismatch")
	}
	if cred.SignCount != 0 {
		t.Fatalf("expected sign_count 0; got %d", cred.SignCount)
	}
	if cred.Status != identity.PasskeyCredentialStatusActive {
		t.Fatalf("expected active; got %v", cred.Status)
	}
}

func TestNewPasskeyCredential_RejectsAGID(t *testing.T) {
	_, err := identity.NewPasskeyCredential(identity.NewPasskeyCredentialParams{
		Gcid:            "0197a000-0000-0000-0000-000000000001",
		CredentialID:    []byte("cred-id-bytes"),
		PublicKeyCOSE:   []byte("cose-public-key"),
		AttestationType: "none",
		RPID:            "chora.site",
	})
	if err == nil {
		t.Fatalf("expected AGID rejection")
	}
}

func TestPasskeyCredential_RecordUse(t *testing.T) {
	cred, _ := identity.NewPasskeyCredential(identity.NewPasskeyCredentialParams{
		Gcid:            "01935b5a-9bcf-7000-8000-000000000001",
		CredentialID:    []byte("cred-id-bytes"),
		PublicKeyCOSE:   []byte("cose-public-key"),
		AttestationType: "none",
		RPID:            "chora.site",
	})
	// Sign-count must monotonically increase per WebAuthn spec.
	if err := cred.RecordUse(1); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if cred.SignCount != 1 {
		t.Fatalf("expected 1; got %d", cred.SignCount)
	}
	if err := cred.RecordUse(5); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if cred.SignCount != 5 {
		t.Fatalf("expected 5; got %d", cred.SignCount)
	}
	// Replay (sign-count went DOWN) must be rejected.
	if err := cred.RecordUse(3); err == nil {
		t.Fatalf("expected error on sign-count regression (replay attack)")
	}
}

func TestPasskeyCredential_Revoke(t *testing.T) {
	cred, _ := identity.NewPasskeyCredential(identity.NewPasskeyCredentialParams{
		Gcid:            "01935b5a-9bcf-7000-8000-000000000001",
		CredentialID:    []byte("cred-id-bytes"),
		PublicKeyCOSE:   []byte("cose-public-key"),
		AttestationType: "none",
		RPID:            "chora.site",
	})
	cred.Revoke()
	if cred.Status != identity.PasskeyCredentialStatusRevoked {
		t.Fatalf("expected revoked; got %v", cred.Status)
	}
	// RecordUse on revoked credential must error.
	if err := cred.RecordUse(1); err == nil {
		t.Fatalf("expected error on use of revoked credential")
	}
}

// -----------------------------------------------------------------------------
// Helper: confirm exported domain errors are present.
// -----------------------------------------------------------------------------

func TestPasskeyDomainErrors_Exported(t *testing.T) {
	for name, err := range map[string]error{
		"ErrPasskeyChallengeExpired":  identity.ErrPasskeyChallengeExpired,
		"ErrPasskeyChallengeConsumed": identity.ErrPasskeyChallengeConsumed,
		"ErrPasskeyCredentialReplay":  identity.ErrPasskeyCredentialReplay,
		"ErrPasskeyCredentialRevoked": identity.ErrPasskeyCredentialRevoked,
	} {
		if err == nil {
			t.Fatalf("%s sentinel must be exported", name)
		}
		if !strings.Contains(err.Error(), "passkey") {
			t.Fatalf("%s error message should mention 'passkey'; got %q", name, err.Error())
		}
	}
}
