// Package jwks is the domain port for the chora-identity signing key set.
//
// chora-identity exposes its public signing keys at /.well-known/jwks.json so
// external relying parties (notably Singpass NDI per SP-4 + SP-5) can verify
// JWTs Chora signs as the OIDC client (private_key_jwt grant).
//
// Hexagonal: this is DOMAIN. Production wires a Cloud KMS / Secret Manager
// adapter (S1.4 ADR-141 — A-Platform-Sec); dev tests wire an in-memory
// adapter that constructs keys at process startup.
//
// Companion docs:
//   - docs/design/ux_singpass_kyc.md
//   - .claude/skills/secrets-and-env/SKILL.md
//   - services/chora-identity/migrations/0004_singpass_sub_minimisation.sql
package jwks

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
)

// PublicKey is one entry in the JWKS — exactly one of (EC, RSA) must be set.
// AGID-shaped IDs are forbidden in KID (KIDs are non-PII labels).
type PublicKey struct {
	// KID is the key identifier (RFC 7517 §4.5). Stable across rotations
	// of the same logical key.
	KID string
	// Alg is the JWS algorithm (RFC 7518 §3.1). Must be one of:
	//   - "ES256" for EC P-256 keys
	//   - "RS256" for RSA keys
	Alg string
	// EC, if non-nil, is the ECDSA public key. Mutually exclusive with RSA.
	EC *ecdsa.PublicKey
	// RSA, if non-nil, is the RSA public key. Mutually exclusive with EC.
	RSA *rsa.PublicKey
}

// Provider is the port the HTTP handler depends on. The adapter — in-memory
// (dev) or Cloud KMS-backed (prod) — implements this.
type Provider interface {
	// PublicKeys returns all currently-active signing keys' public halves.
	// During key rotation this MAY return both old + new keys for the
	// overlap window so external verifiers can drain in-flight tokens.
	PublicKeys() []PublicKey
}

// AsJWK marshals the public key to a JWK map per RFC 7517. Only public-half
// fields are emitted — private parameters (d/p/q/dp/dq/qi) are NEVER set.
//
// Unsupported (Alg, EC, RSA all-nil) keys produce {"kid": ..., "use": "sig"}
// with no other fields — the handler still emits the entry but verifiers
// will reject it.
func (k PublicKey) AsJWK() map[string]any {
	out := map[string]any{
		"kid": k.KID,
		"use": "sig",
		"alg": k.Alg,
	}
	switch {
	case k.EC != nil:
		out["kty"] = "EC"
		// P-256 has 32-byte coordinates per SEC 1 §2.3.
		out["crv"] = "P-256"
		out["x"] = base64.RawURLEncoding.EncodeToString(leftPadTo(k.EC.X.Bytes(), 32))
		out["y"] = base64.RawURLEncoding.EncodeToString(leftPadTo(k.EC.Y.Bytes(), 32))
	case k.RSA != nil:
		out["kty"] = "RSA"
		// n is the modulus, big-endian.
		out["n"] = base64.RawURLEncoding.EncodeToString(k.RSA.N.Bytes())
		// e is the public exponent (typically 65537 → 0x010001 → "AQAB").
		eBytes := bigEndianBytes(k.RSA.E)
		out["e"] = base64.RawURLEncoding.EncodeToString(eBytes)
	}
	return out
}

// leftPadTo returns b left-padded with zero bytes to length n. If len(b) ≥ n,
// b is returned as-is (its high bits are already at the front).
func leftPadTo(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

// bigEndianBytes returns the minimum-length big-endian byte representation
// of e. Special-cased to {0x01, 0x00, 0x01} for the common 65537.
func bigEndianBytes(e int) []byte {
	if e == 0 {
		return []byte{0}
	}
	var buf []byte
	for v := e; v > 0; v >>= 8 {
		buf = append([]byte{byte(v & 0xff)}, buf...)
	}
	return buf
}
