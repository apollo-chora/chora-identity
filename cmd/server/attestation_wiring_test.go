// attestation_wiring_test.go — FIDO MDS attestation env-parsing helpers
// (ADR-187 WebAuthn attestation verification).
//
// configureAttestation itself wires a PasskeyHandler + starts a background
// MDS refresh goroutine (fidomds), so it is covered indirectly here through
// its pure parsing helpers; the full handler wiring is exercised by the
// http package's attestation tests.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// selfSignedCertPEM returns a freshly-minted self-signed certificate in PEM
// form so the PEM-root parser never depends on a static fixture.
func selfSignedCertPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "chora-test-root"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestAttParsePEMRoots_ParsesCertificates(t *testing.T) {
	t.Parallel()
	certPEM := selfSignedCertPEM(t)
	roots := attParsePEMRoots(certPEM)
	if len(roots) != 1 {
		t.Fatalf("parsed %d roots, want 1", len(roots))
	}
	if roots[0].Subject.CommonName != "chora-test-root" {
		t.Errorf("root CN = %q, want chora-test-root", roots[0].Subject.CommonName)
	}
}

func TestAttParsePEMRoots_EmptyAndForeignBlocks(t *testing.T) {
	t.Parallel()
	if got := attParsePEMRoots(""); len(got) != 0 {
		t.Errorf("empty input parsed %d roots, want 0", len(got))
	}
	// A non-CERTIFICATE PEM block (e.g. an RSA public key) must be skipped,
	// and garbage after it must terminate parsing without error.
	pubPEM := "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEc1x0Zg==\n-----END PUBLIC KEY-----\n"
	if got := attParsePEMRoots(pubPEM); len(got) != 0 {
		t.Errorf("public-key block parsed %d roots, want 0", len(got))
	}
	if got := attParsePEMRoots("not pem at all"); len(got) != 0 {
		t.Errorf("garbage parsed %d roots, want 0", len(got))
	}
}

func TestAttParsePEMRoots_SkipsMalformedCertificates(t *testing.T) {
	t.Parallel()
	// A CERTIFICATE block whose DER payload is not a parseable certificate
	// must be skipped rather than failing the whole parse.
	bad := "-----BEGIN CERTIFICATE-----\ndGVzdGluZy1ub3QtYS1jZXJ0\n-----END CERTIFICATE-----\n"
	if got := attParsePEMRoots(bad); len(got) != 0 {
		t.Errorf("malformed cert parsed %d roots, want 0", len(got))
	}
}

func TestAttParseAllowList_NormalisesAAGUIDs(t *testing.T) {
	t.Parallel()
	got := attParseAllowList("A1B2C3D4-0000-4000-8000-000000000001, a1b2c3d4000040008000000000000002,  A3B4C5D6")
	if len(got) != 3 {
		t.Fatalf("parsed %d keys, want 3 (%v)", len(got), got)
	}
	if !got["a1b2c3d4000040008000000000000001"] {
		t.Error("dashed uppercase AAGUID missing as lowercase dashless key")
	}
	if !got["a1b2c3d4000040008000000000000002"] {
		t.Error("comma-separated lowercase AAGUID missing")
	}
	if !got["a3b4c5d6"] {
		t.Error("short AAGUID missing")
	}
}

func TestAttParseAllowList_EmptyAndSeparators(t *testing.T) {
	t.Parallel()
	if got := attParseAllowList(""); got != nil {
		t.Errorf("empty input returned %v, want nil", got)
	}
	if got := attParseAllowList("   \t\n  "); got != nil {
		t.Errorf("whitespace-only input returned %v, want nil", got)
	}
	// Newline + tab separators and empty tokens are tolerated; each token
	// becomes a lowercase dashless key.
	got := attParseAllowList("aa-bb,\ncc\tdd  ee\n\ncc-dd")
	if len(got) != 5 {
		t.Errorf("separator mix parsed %d keys, want 5 (%v)", len(got), got)
	}
	for _, want := range []string{"aabb", "cc", "dd", "ee", "ccdd"} {
		if !got[want] {
			t.Errorf("key %q missing from %v", want, got)
		}
	}
}

func TestAttEnvDuration_ValidValue(t *testing.T) {
	t.Setenv("CHORA_ATTESTATION_TEST_DUR", "24h")
	if got := attEnvDuration("CHORA_ATTESTATION_TEST_DUR", time.Hour); got != 24*time.Hour {
		t.Errorf("attEnvDuration = %v, want 24h", got)
	}
}

func TestAttEnvDuration_FallsBackOnInvalid(t *testing.T) {
	t.Setenv("CHORA_ATTESTATION_TEST_DUR", "not-a-duration")
	t.Setenv("CHORA_ATTESTATION_TEST_NEG", "-5s")
	def := 90 * time.Minute
	if got := attEnvDuration("CHORA_ATTESTATION_TEST_DUR", def); got != def {
		t.Errorf("invalid duration = %v, want default %v", got, def)
	}
	if got := attEnvDuration("CHORA_ATTESTATION_TEST_NEG", def); got != def {
		t.Errorf("non-positive duration = %v, want default %v", got, def)
	}
}

func TestAttEnvDuration_FallsBackOnUnset(t *testing.T) {
	t.Setenv("CHORA_ATTESTATION_TEST_UNSET", "")
	def := time.Minute
	if got := attEnvDuration("CHORA_ATTESTATION_TEST_UNSET", def); got != def {
		t.Errorf("unset duration = %v, want default %v", got, def)
	}
}

func TestAttEnvDuration_TrimsWhitespace(t *testing.T) {
	t.Setenv("CHORA_ATTESTATION_TEST_DUR", " 45m ")
	if got := attEnvDuration("CHORA_ATTESTATION_TEST_DUR", time.Hour); got != 45*time.Minute {
		t.Errorf("whitespace-padded duration = %v, want 45m", got)
	}
}
