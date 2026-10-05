// passkey_test_helpers_test.go — shared crypto helpers for the production
// WebAuthn signature tests in this package. Adapter-side helpers — no
// dependency on the domain crypto.
package httpadapter_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
	"testing"
)

// newES256COSEPair returns an ECDSA P-256 private key + the matching COSE_Key
// CBOR bytes (RFC 8152 §16) so a credential can be seeded with public key
// material the production verifier accepts.
func newES256COSEPair(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa keygen: %v", err)
	}
	cose := ec2COSE(pad32(priv.PublicKey.X.Bytes()), pad32(priv.PublicKey.Y.Bytes()))
	return priv, cose
}

// signES256ForTest signs the WebAuthn assertion message
// `signing_input = authData || sha256(clientDataJSON)` with the provided
// ES256 private key and returns the ASN.1 DER signature.
func signES256ForTest(t *testing.T, priv *ecdsa.PrivateKey, authData, clientDataJSON []byte) []byte {
	t.Helper()
	cdh := sha256.Sum256(clientDataJSON)
	signing := append([]byte{}, authData...)
	signing = append(signing, cdh[:]...)
	hashed := sha256.Sum256(signing)
	r, s, err := ecdsa.Sign(rand.Reader, priv, hashed[:])
	if err != nil {
		t.Fatalf("ecdsa sign: %v", err)
	}
	sig, err := asn1.Marshal(struct{ R, S *big.Int }{R: r, S: s})
	if err != nil {
		t.Fatalf("asn1 marshal: %v", err)
	}
	return sig
}
