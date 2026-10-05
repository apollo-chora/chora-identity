package authn_test

import (
	"strings"
	"testing"

	"github.com/apollo-chora/chora-identity/internal/domain/authn"
)

func TestHashPassword_ProducesCanonicalPHC(t *testing.T) {
	phc, err := authn.HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	// $argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>
	parts := strings.Split(phc, "$")
	if len(parts) != 6 {
		t.Fatalf("PHC field count = %d, want 6 (%q)", len(parts), phc)
	}
	if parts[1] != "argon2id" {
		t.Errorf("algorithm = %q, want argon2id", parts[1])
	}
	if parts[2] != "v=19" {
		t.Errorf("version = %q, want v=19", parts[2])
	}
	if parts[3] != "m=65536,t=3,p=2" {
		t.Errorf("params = %q, want m=65536,t=3,p=2", parts[3])
	}
}

func TestHashPassword_SaltIsRandom(t *testing.T) {
	a, err := authn.HashPassword("same-password")
	if err != nil {
		t.Fatalf("HashPassword a: %v", err)
	}
	b, err := authn.HashPassword("same-password")
	if err != nil {
		t.Fatalf("HashPassword b: %v", err)
	}
	if a == b {
		t.Fatal("two hashes of the same password are identical — salt is not random")
	}
}

func TestVerifyPassword_RoundTrip(t *testing.T) {
	phc, err := authn.HashPassword("s3cret-p@ss")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	ok, err := authn.VerifyPassword("s3cret-p@ss", phc)
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if !ok {
		t.Error("correct password did not verify")
	}
	ok, err = authn.VerifyPassword("wrong-password", phc)
	if err != nil {
		t.Fatalf("VerifyPassword (wrong): %v", err)
	}
	if ok {
		t.Error("wrong password verified")
	}
}

func TestVerifyPassword_MalformedPHC(t *testing.T) {
	for _, phc := range []string{
		"",
		"not-a-phc",
		"$argon2i$v=19$m=65536,t=3,p=2$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=0,t=3,p=2$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=65536,t=3,p=2$!!!$aGFzaA",
	} {
		if _, err := authn.VerifyPassword("x", phc); err == nil {
			t.Errorf("VerifyPassword(%q) = nil error, want ErrInvalidPHC", phc)
		}
	}
}

func TestHashPassword_RejectsOversizedPassword(t *testing.T) {
	tooLong := strings.Repeat("a", authn.MaxPasswordBytes+1)
	if _, err := authn.HashPassword(tooLong); err == nil {
		t.Fatal("oversized password must be rejected")
	}
}

func TestVerifyPassword_AcceptsParsedParamsNotCompiledDefaults(t *testing.T) {
	// A hash produced with different (weaker, test-only) parameters must still
	// parse — the parameters travel with the hash rather than being assumed.
	phc := "$argon2id$v=19$m=8192,t=1,p=1$c29tZXNhbHQxMjM0NTY3OA$" +
		"Y8sQm5Q0M5mY2n8xqg4Y7p6kZ1v3s2d9f0a1b2c3d4e"
	ok, err := authn.VerifyPassword("x", phc)
	if err != nil {
		t.Fatalf("well-formed foreign-params PHC should parse: %v", err)
	}
	if ok {
		t.Error("unexpected match for a foreign-params hash")
	}
}
