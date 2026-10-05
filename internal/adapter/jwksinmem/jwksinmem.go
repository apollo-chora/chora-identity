// Package jwksinmem is the in-memory chora-identity JWKS provider for dev +
// test rigs. It generates one ES256 + one RS256 key pair at construction
// time and surfaces the public halves to the HTTP handler.
//
// Production wiring (deferred to S1.4 + Cloud KMS rollout per ADR-141)
// replaces this with a Cloud KMS-backed provider that:
//   - reads private key material via Workload Identity Federation (no SA key
//     files travel)
//   - rotates keys via Secret Manager versions
//   - exposes both old + new public keys during the rotation overlap window
//
// Hexagonal: this is an ADAPTER. It has no business logic; the JWK shape is
// defined in the domain port (internal/domain/jwks/jwks.go).
//
// Aligned with: .claude/skills/secrets-and-env/SKILL.md (no inline keys —
// even dev keys are produced via crypto/rand at boot, never literals).
package jwksinmem

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/apollo-chora/chora-identity/internal/domain/jwks"
)

// Provider is the in-memory implementation of jwks.Provider.
type Provider struct {
	keys []jwks.PublicKey
	// Private halves are retained for any future code path that wants to
	// sign tokens with the same key material (e.g. dev-only Singpass NDI
	// client-assertion sign). Production REPLACES this with Cloud KMS.
	ecPriv  *ecdsa.PrivateKey
	rsaPriv *rsa.PrivateKey
}

// New constructs a provider with one ES256 + one RS256 dev key pair.
func New() (*Provider, error) {
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("jwksinmem: ec keygen: %w", err)
	}
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("jwksinmem: rsa keygen: %w", err)
	}
	return &Provider{
		ecPriv:  ecPriv,
		rsaPriv: rsaPriv,
		keys: []jwks.PublicKey{
			{KID: "chora-identity-ec-dev-1", Alg: "ES256", EC: &ecPriv.PublicKey},
			{KID: "chora-identity-rsa-dev-1", Alg: "RS256", RSA: &rsaPriv.PublicKey},
		},
	}, nil
}

// PublicKeys implements jwks.Provider.
func (p *Provider) PublicKeys() []jwks.PublicKey {
	out := make([]jwks.PublicKey, len(p.keys))
	copy(out, p.keys)
	return out
}

// ECPrivate exposes the dev ES256 private key. Returns nil for non-dev wiring.
func (p *Provider) ECPrivate() *ecdsa.PrivateKey { return p.ecPriv }

// RSAPrivate exposes the dev RS256 private key. Returns nil for non-dev wiring.
func (p *Provider) RSAPrivate() *rsa.PrivateKey { return p.rsaPriv }
