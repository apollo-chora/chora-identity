// jwks_test.go — domain tests for the chora-identity JWKS port. Exercises
// the AsJWK marshaller + helper bigEndianBytes / leftPadTo.
package jwks_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"testing"

	"github.com/apollo-chora/chora-identity/internal/domain/jwks"
)

func TestPublicKey_AsJWK_EC_P256(t *testing.T) {
	t.Parallel()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pk := jwks.PublicKey{KID: "ec-1", Alg: "ES256", EC: &priv.PublicKey}
	got := pk.AsJWK()
	if got["kty"] != "EC" || got["crv"] != "P-256" || got["alg"] != "ES256" {
		t.Errorf("base fields wrong: %+v", got)
	}
	if got["use"] != "sig" {
		t.Errorf("use=%v", got["use"])
	}
	if got["kid"] != "ec-1" {
		t.Errorf("kid=%v", got["kid"])
	}
	xb, err := base64.RawURLEncoding.DecodeString(got["x"].(string))
	if err != nil {
		t.Fatalf("x decode: %v", err)
	}
	yb, err := base64.RawURLEncoding.DecodeString(got["y"].(string))
	if err != nil {
		t.Fatalf("y decode: %v", err)
	}
	if len(xb) != 32 || len(yb) != 32 {
		t.Errorf("EC P-256 coordinates must be 32 bytes; got x=%d y=%d", len(xb), len(yb))
	}
	// Round-trip: reconstructed key matches original.
	if new(big.Int).SetBytes(xb).Cmp(priv.PublicKey.X) != 0 {
		t.Errorf("x roundtrip mismatch")
	}
	if new(big.Int).SetBytes(yb).Cmp(priv.PublicKey.Y) != 0 {
		t.Errorf("y roundtrip mismatch")
	}
}

func TestPublicKey_AsJWK_RSA(t *testing.T) {
	t.Parallel()
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pk := jwks.PublicKey{KID: "rsa-1", Alg: "RS256", RSA: &priv.PublicKey}
	got := pk.AsJWK()
	if got["kty"] != "RSA" || got["alg"] != "RS256" {
		t.Errorf("base fields wrong: %+v", got)
	}
	// e=65537 is the canonical RSA exponent → "AQAB".
	if got["e"] != "AQAB" {
		t.Errorf("e=%q want AQAB (RFC 7518 §6.3.1.2)", got["e"])
	}
	nb, err := base64.RawURLEncoding.DecodeString(got["n"].(string))
	if err != nil {
		t.Fatalf("n decode: %v", err)
	}
	if new(big.Int).SetBytes(nb).Cmp(priv.PublicKey.N) != 0 {
		t.Errorf("n roundtrip mismatch")
	}
	// Public-key only — no private parameters.
	for _, priv := range []string{"d", "p", "q", "dp", "dq", "qi"} {
		if _, has := got[priv]; has {
			t.Errorf("RSA JWK leaks private param %q", priv)
		}
	}
}

func TestPublicKey_AsJWK_BareKey_OmitsTypeFields(t *testing.T) {
	t.Parallel()
	// Both EC + RSA nil → no kty/x/y/n/e — only kid + use + alg.
	pk := jwks.PublicKey{KID: "bare", Alg: "ES256"}
	got := pk.AsJWK()
	if got["kid"] != "bare" || got["use"] != "sig" || got["alg"] != "ES256" {
		t.Errorf("base fields wrong: %+v", got)
	}
	for _, k := range []string{"kty", "crv", "x", "y", "n", "e"} {
		if _, has := got[k]; has {
			t.Errorf("bare key shouldn't expose %q", k)
		}
	}
}

// Custom RSA exponent (non-65537) — exercises the bigEndianBytes loop branch.
func TestPublicKey_AsJWK_RSA_CustomExponent(t *testing.T) {
	t.Parallel()
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	priv.PublicKey.E = 3 // toy exponent — single-byte
	pk := jwks.PublicKey{KID: "rsa-tiny", Alg: "RS256", RSA: &priv.PublicKey}
	got := pk.AsJWK()
	eDec, err := base64.RawURLEncoding.DecodeString(got["e"].(string))
	if err != nil {
		t.Fatalf("e decode: %v", err)
	}
	if len(eDec) != 1 || eDec[0] != 3 {
		t.Errorf("e bytes=%v want [3]", eDec)
	}
}

// Short EC X — pads to 32 bytes (exercises leftPadTo).
func TestPublicKey_AsJWK_EC_LeadingZeroX(t *testing.T) {
	t.Parallel()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// Force a synthetic short X by replacing the public-key big.Int with
	// a 1-byte value. We don't use this for cryptography — only for the
	// padding pathway.
	pk := jwks.PublicKey{
		KID: "ec-short",
		Alg: "ES256",
		EC: &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     big.NewInt(1),
			Y:     priv.PublicKey.Y,
		},
	}
	got := pk.AsJWK()
	xb, _ := base64.RawURLEncoding.DecodeString(got["x"].(string))
	if len(xb) != 32 {
		t.Errorf("x must be 32 bytes after pad; got %d", len(xb))
	}
	// The trailing byte should be 1.
	if xb[31] != 1 {
		t.Errorf("expected trailing byte 1; got %d", xb[31])
	}
	for i := 0; i < 31; i++ {
		if xb[i] != 0 {
			t.Errorf("expected zero pad at index %d; got %d", i, xb[i])
		}
	}
}
