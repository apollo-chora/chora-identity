// Package crypto_test exercises the per-user DEK stub used by the closure
// saga's crypto-shred step.
//
// MVP: HMAC-based stubs in-memory. Production wires Cloud KMS CMEK (per-tenant
// master key) + per-user DEK; deleting the DEK = crypto-shred (data
// unrecoverable) per ddd-enforcement Account Closure section.
//
// TDD RED: tests assume the package does NOT yet exist.
package crypto_test

import (
	"errors"
	"testing"

	"github.com/apollo-chora/chora-identity/internal/domain/crypto"
)

const (
	gcidA = "01970000-0000-7000-9000-000000000001"
	gcidB = "01970000-0000-7000-9000-000000000002"
)

// -----------------------------------------------------------------------------
// IssueDEK / Encrypt / Decrypt round trip.
// -----------------------------------------------------------------------------

func TestKeyManager_RoundTrip_EncryptDecrypt(t *testing.T) {
	t.Parallel()
	km := crypto.NewInMemoryKeyManager([]byte("master-key-stub-do-not-use-in-prod"))
	if _, err := km.IssueDEK(gcidA); err != nil {
		t.Fatalf("IssueDEK: %v", err)
	}

	plain := []byte("alice@chora.dev")
	ct, err := km.Encrypt(gcidA, plain)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if string(ct) == string(plain) {
		t.Errorf("ciphertext equals plaintext (encryption no-op?)")
	}

	got, err := km.Decrypt(gcidA, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != string(plain) {
		t.Errorf("decrypt mismatch: %q want %q", got, plain)
	}
}

// -----------------------------------------------------------------------------
// Crypto-shred semantics: deleting the DEK = data unrecoverable.
// -----------------------------------------------------------------------------

func TestKeyManager_Shred_FailsAllSubsequentDecrypts(t *testing.T) {
	t.Parallel()
	km := crypto.NewInMemoryKeyManager([]byte("master"))
	if _, err := km.IssueDEK(gcidA); err != nil {
		t.Fatalf("IssueDEK: %v", err)
	}
	ct, err := km.Encrypt(gcidA, []byte("phyllis@mightymind.sg"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if err := km.ShredDEK(gcidA); err != nil {
		t.Fatalf("ShredDEK: %v", err)
	}
	// After shred, decrypt must fail.
	_, err = km.Decrypt(gcidA, ct)
	if err == nil {
		t.Errorf("expected error decrypting after shred; got nil")
	}
	if !errors.Is(err, crypto.ErrDEKShredded) {
		t.Errorf("err=%v; want errors.Is(_, ErrDEKShredded)", err)
	}
}

func TestKeyManager_Shred_IsolatesPerUser(t *testing.T) {
	t.Parallel()
	// Crypto-shredding gcidA must NOT affect gcidB's data.
	km := crypto.NewInMemoryKeyManager([]byte("master"))
	_, _ = km.IssueDEK(gcidA)
	_, _ = km.IssueDEK(gcidB)

	ctA, _ := km.Encrypt(gcidA, []byte("a-data"))
	ctB, _ := km.Encrypt(gcidB, []byte("b-data"))

	if err := km.ShredDEK(gcidA); err != nil {
		t.Fatalf("ShredDEK: %v", err)
	}

	if _, err := km.Decrypt(gcidA, ctA); err == nil {
		t.Errorf("decrypt after shred should fail for gcidA")
	}
	got, err := km.Decrypt(gcidB, ctB)
	if err != nil {
		t.Errorf("gcidB decrypt failed unexpectedly: %v", err)
	}
	if string(got) != "b-data" {
		t.Errorf("gcidB plaintext mismatch: %q", got)
	}
}

func TestKeyManager_Shred_Idempotent(t *testing.T) {
	t.Parallel()
	km := crypto.NewInMemoryKeyManager([]byte("master"))
	_, _ = km.IssueDEK(gcidA)
	if err := km.ShredDEK(gcidA); err != nil {
		t.Fatalf("first ShredDEK: %v", err)
	}
	if err := km.ShredDEK(gcidA); err != nil {
		t.Errorf("second ShredDEK should be idempotent; got %v", err)
	}
}

// -----------------------------------------------------------------------------
// Pseudonymisation tokens — deterministic per gcid+field.
// -----------------------------------------------------------------------------

func TestKeyManager_Tokenise_DeterministicForSameInput(t *testing.T) {
	t.Parallel()
	km := crypto.NewInMemoryKeyManager([]byte("master"))
	_, _ = km.IssueDEK(gcidA)
	tok1, err := km.Tokenise(gcidA, "email", "alice@chora.dev")
	if err != nil {
		t.Fatalf("Tokenise: %v", err)
	}
	tok2, _ := km.Tokenise(gcidA, "email", "alice@chora.dev")
	if tok1 != tok2 {
		t.Errorf("tokens differ for same input: %q vs %q", tok1, tok2)
	}
	if tok1 == "" {
		t.Errorf("token empty")
	}
}

func TestKeyManager_Tokenise_DiffersAcrossFields(t *testing.T) {
	t.Parallel()
	km := crypto.NewInMemoryKeyManager([]byte("master"))
	_, _ = km.IssueDEK(gcidA)
	tEmail, _ := km.Tokenise(gcidA, "email", "alice@chora.dev")
	tName, _ := km.Tokenise(gcidA, "display_name", "alice@chora.dev")
	if tEmail == tName {
		t.Errorf("tokens for different fields collided: %q == %q", tEmail, tName)
	}
}

func TestKeyManager_Tokenise_DiffersAcrossGcids(t *testing.T) {
	t.Parallel()
	km := crypto.NewInMemoryKeyManager([]byte("master"))
	_, _ = km.IssueDEK(gcidA)
	_, _ = km.IssueDEK(gcidB)
	tA, _ := km.Tokenise(gcidA, "email", "shared@chora.dev")
	tB, _ := km.Tokenise(gcidB, "email", "shared@chora.dev")
	if tA == tB {
		t.Errorf("tokens for different gcids collided")
	}
}

// -----------------------------------------------------------------------------
// Edges.
// -----------------------------------------------------------------------------

func TestKeyManager_EncryptUnknownGcid_ReturnsError(t *testing.T) {
	t.Parallel()
	km := crypto.NewInMemoryKeyManager([]byte("master"))
	_, err := km.Encrypt(gcidA, []byte("data"))
	if err == nil {
		t.Errorf("expected error for unknown gcid")
	}
	if !errors.Is(err, crypto.ErrDEKNotFound) {
		t.Errorf("err=%v; want errors.Is(_, ErrDEKNotFound)", err)
	}
}

func TestKeyManager_DecryptCorruptedCiphertext_ReturnsError(t *testing.T) {
	t.Parallel()
	km := crypto.NewInMemoryKeyManager([]byte("master"))
	_, _ = km.IssueDEK(gcidA)
	if _, err := km.Decrypt(gcidA, []byte("garbage")); err == nil {
		t.Errorf("expected error for corrupted ciphertext")
	}
}

func TestPIIClass_String(t *testing.T) {
	t.Parallel()
	if string(crypto.PIIClassLow) == "" || string(crypto.PIIClassCritical) == "" {
		t.Errorf("PII class enum should expose string values")
	}
}
