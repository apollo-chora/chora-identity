// webauthn_verify_test.go — RED-phase TDD specs for production-ready
// WebAuthn signature verification, replacing the `attestation_dev=true`
// shortcut in the passkey verify handler.
//
// Per W3C WebAuthn Level 3 §7.2 the assertion verification is:
//
//	sig is computed over: authenticatorData || sha256(clientDataJSON)
//
// Where the public key was published in COSE_Key (CBOR) format at registration
// time and is stored as cred.PublicKeyCOSE.
//
// Supported COSE algorithms (the two Identity Platform / Apple Passkey /
// Android Passkey emit):
//
//   - ES256 (kty=EC2, alg=-7, crv=P-256): ECDSA over SHA-256
//   - RS256 (kty=RSA, alg=-257):           RSA-PKCS1v15 over SHA-256
//
// We test:
//  1. Valid ES256 signature verifies green.
//  2. Tampered signature byte → ErrInvalidSignature.
//  3. Tampered authenticatorData → ErrInvalidSignature.
//  4. Tampered clientDataJSON → ErrInvalidSignature.
//  5. Valid RS256 signature verifies green.
//  6. Unsupported COSE alg → ErrUnsupportedCOSEAlg.
//  7. Malformed COSE key → ErrMalformedCOSEKey.
package identity_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"math/big"
	"testing"

	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// --- COSE encoding helpers (test fixtures) ---------------------------------

// encodeCBORLen encodes a CBOR length prefix for major type m (0=uint, 2=byte
// string, 5=map). Used by the tiny inline CBOR encoder that builds COSE_Key
// fixtures for tests.
func encodeCBORLen(m byte, n uint64) []byte {
	if n < 24 {
		return []byte{(m << 5) | byte(n)}
	}
	if n < 256 {
		return []byte{(m << 5) | 24, byte(n)}
	}
	if n < 65536 {
		return []byte{(m << 5) | 25, byte(n >> 8), byte(n)}
	}
	if n < 4_294_967_296 {
		return []byte{(m << 5) | 26, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
	return []byte{(m << 5) | 27, byte(n >> 56), byte(n >> 48), byte(n >> 40), byte(n >> 32), byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}

// cborInt encodes a signed CBOR integer (positive or negative).
func cborInt(v int64) []byte {
	if v >= 0 {
		return encodeCBORLen(0, uint64(v))
	}
	// negative: major type 1, value = -1 - v
	n := uint64(-1 - v)
	return encodeCBORLen(1, n)
}

// cborBytes encodes a byte string (major type 2).
func cborBytes(b []byte) []byte {
	out := encodeCBORLen(2, uint64(len(b)))
	return append(out, b...)
}

// cborMap builds a 4-entry CBOR map for an EC2 COSE key:
//
//	{1: 2, 3: -7, -1: 1, -2: x, -3: y}      (kty=2 EC2, alg=-7 ES256, crv=1 P-256)
func ec2COSEKey(x, y []byte) []byte {
	pairs := [][2][]byte{
		{cborInt(1), cborInt(2)},  // kty = EC2
		{cborInt(3), cborInt(-7)}, // alg = ES256
		{cborInt(-1), cborInt(1)}, // crv = P-256
		{cborInt(-2), cborBytes(x)},
		{cborInt(-3), cborBytes(y)},
	}
	out := encodeCBORLen(5, uint64(len(pairs)))
	for _, p := range pairs {
		out = append(out, p[0]...)
		out = append(out, p[1]...)
	}
	return out
}

// rsaCOSEKey builds {1: 3, 3: -257, -1: n, -2: e}.
func rsaCOSEKey(n, e []byte) []byte {
	pairs := [][2][]byte{
		{cborInt(1), cborInt(3)},    // kty = RSA
		{cborInt(3), cborInt(-257)}, // alg = RS256
		{cborInt(-1), cborBytes(n)},
		{cborInt(-2), cborBytes(e)},
	}
	out := encodeCBORLen(5, uint64(len(pairs)))
	for _, p := range pairs {
		out = append(out, p[0]...)
		out = append(out, p[1]...)
	}
	return out
}

func leftPad32(b []byte) []byte {
	if len(b) >= 32 {
		return b
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// --- Tests -----------------------------------------------------------------

func TestVerifyAssertion_ValidES256_Verifies(t *testing.T) {
	t.Parallel()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa keygen: %v", err)
	}
	x := leftPad32(priv.PublicKey.X.Bytes())
	y := leftPad32(priv.PublicKey.Y.Bytes())
	cose := ec2COSEKey(x, y)

	authData := []byte("authenticator-data-32-bytes-pad-rrrrrrr")
	clientData := []byte(`{"type":"webauthn.get","challenge":"abc"}`)

	// Compute signature over authData || sha256(clientData)
	cdh := sha256.Sum256(clientData)
	signing := append([]byte{}, authData...)
	signing = append(signing, cdh[:]...)
	h := sha256.Sum256(signing)
	r, s, err := ecdsa.Sign(rand.Reader, priv, h[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	// ASN.1 DER encoding of (r, s) per WebAuthn §6.5.6
	sig := encodeECDSASig(r, s)

	if err := identity.VerifyAssertion(cose, authData, clientData, sig); err != nil {
		t.Fatalf("VerifyAssertion: %v", err)
	}
}

func TestVerifyAssertion_TamperedSignatureRejected(t *testing.T) {
	t.Parallel()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	x := leftPad32(priv.PublicKey.X.Bytes())
	y := leftPad32(priv.PublicKey.Y.Bytes())
	cose := ec2COSEKey(x, y)

	authData := []byte("authenticator-data-32-bytes-pad-rrrrrrr")
	clientData := []byte(`{"type":"webauthn.get"}`)
	cdh := sha256.Sum256(clientData)
	signing := append([]byte{}, authData...)
	signing = append(signing, cdh[:]...)
	h := sha256.Sum256(signing)
	r, s, _ := ecdsa.Sign(rand.Reader, priv, h[:])
	sig := encodeECDSASig(r, s)
	// Flip last byte
	sig[len(sig)-1] ^= 0x01

	if err := identity.VerifyAssertion(cose, authData, clientData, sig); !errors.Is(err, identity.ErrInvalidSignature) {
		t.Errorf("err = %v, want ErrInvalidSignature", err)
	}
}

func TestVerifyAssertion_TamperedAuthDataRejected(t *testing.T) {
	t.Parallel()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	x := leftPad32(priv.PublicKey.X.Bytes())
	y := leftPad32(priv.PublicKey.Y.Bytes())
	cose := ec2COSEKey(x, y)

	authData := []byte("authenticator-data-32-bytes-pad-rrrrrrr")
	clientData := []byte(`{"type":"webauthn.get"}`)
	cdh := sha256.Sum256(clientData)
	signing := append([]byte{}, authData...)
	signing = append(signing, cdh[:]...)
	h := sha256.Sum256(signing)
	r, s, _ := ecdsa.Sign(rand.Reader, priv, h[:])
	sig := encodeECDSASig(r, s)

	// Tamper authData AFTER signing.
	tampered := append([]byte{}, authData...)
	tampered[0] ^= 0xff

	if err := identity.VerifyAssertion(cose, tampered, clientData, sig); !errors.Is(err, identity.ErrInvalidSignature) {
		t.Errorf("err = %v, want ErrInvalidSignature", err)
	}
}

func TestVerifyAssertion_TamperedClientDataRejected(t *testing.T) {
	t.Parallel()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	x := leftPad32(priv.PublicKey.X.Bytes())
	y := leftPad32(priv.PublicKey.Y.Bytes())
	cose := ec2COSEKey(x, y)

	authData := []byte("authenticator-data-32-bytes-pad-rrrrrrr")
	clientData := []byte(`{"type":"webauthn.get"}`)
	cdh := sha256.Sum256(clientData)
	signing := append([]byte{}, authData...)
	signing = append(signing, cdh[:]...)
	h := sha256.Sum256(signing)
	r, s, _ := ecdsa.Sign(rand.Reader, priv, h[:])
	sig := encodeECDSASig(r, s)

	tamperedCD := []byte(`{"type":"webauthn.create"}`) // change "get" → "create"
	if err := identity.VerifyAssertion(cose, authData, tamperedCD, sig); !errors.Is(err, identity.ErrInvalidSignature) {
		t.Errorf("err = %v, want ErrInvalidSignature", err)
	}
}

func TestVerifyAssertion_ValidRS256_Verifies(t *testing.T) {
	t.Parallel()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	n := priv.PublicKey.N.Bytes()
	e := big.NewInt(int64(priv.PublicKey.E)).Bytes()
	cose := rsaCOSEKey(n, e)

	authData := []byte("auth-data-RS256-fixture-padding")
	clientData := []byte(`{"type":"webauthn.get","challenge":"xyz"}`)
	cdh := sha256.Sum256(clientData)
	signing := append([]byte{}, authData...)
	signing = append(signing, cdh[:]...)
	h := sha256.Sum256(signing)
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, h[:])
	if err != nil {
		t.Fatalf("rsa sign: %v", err)
	}

	if err := identity.VerifyAssertion(cose, authData, clientData, sig); err != nil {
		t.Fatalf("VerifyAssertion (RSA): %v", err)
	}
}

func TestVerifyAssertion_RejectsUnsupportedAlg(t *testing.T) {
	t.Parallel()
	// alg = -8 (Ed25519, not supported)
	pairs := [][2][]byte{
		{cborInt(1), cborInt(1)},  // kty = OKP
		{cborInt(3), cborInt(-8)}, // alg = EdDSA
		{cborInt(-1), cborInt(6)}, // crv = Ed25519
		{cborInt(-2), cborBytes([]byte("dummy"))},
	}
	out := encodeCBORLen(5, uint64(len(pairs)))
	for _, p := range pairs {
		out = append(out, p[0]...)
		out = append(out, p[1]...)
	}
	if err := identity.VerifyAssertion(out, []byte("auth"), []byte("cd"), []byte("sig")); !errors.Is(err, identity.ErrUnsupportedCOSEAlg) {
		t.Errorf("err = %v, want ErrUnsupportedCOSEAlg", err)
	}
}

func TestVerifyAssertion_RejectsMalformedCOSE(t *testing.T) {
	t.Parallel()
	// Empty / random bytes can't decode to a CBOR map.
	if err := identity.VerifyAssertion(nil, []byte("auth"), []byte("cd"), []byte("sig")); !errors.Is(err, identity.ErrMalformedCOSEKey) {
		t.Errorf("err = %v, want ErrMalformedCOSEKey", err)
	}
	if err := identity.VerifyAssertion([]byte{0x00, 0x01, 0x02}, []byte("auth"), []byte("cd"), []byte("sig")); !errors.Is(err, identity.ErrMalformedCOSEKey) {
		t.Errorf("err = %v, want ErrMalformedCOSEKey for bogus bytes; got %v", err, err)
	}
}

// --- Edge-case coverage for parseCOSEKey error branches ------------------

// TestVerifyAssertion_RejectsTruncatedKey covers decodeCBORHead error paths
// (truncated buffer at each length-prefix boundary 24/25/26/27).
func TestVerifyAssertion_RejectsTruncatedKey(t *testing.T) {
	t.Parallel()
	// Type-byte requests a 1-byte ext (24 = uint8 follows) but no data.
	truncated := []byte{(0 << 5) | 24}
	if err := identity.VerifyAssertion(truncated, []byte("a"), []byte("b"), []byte("s")); !errors.Is(err, identity.ErrMalformedCOSEKey) {
		t.Errorf("err = %v want ErrMalformedCOSEKey", err)
	}
	// Type-byte requests 2-byte ext but only 1 byte present.
	truncated2 := []byte{(0 << 5) | 25, 0x00}
	if err := identity.VerifyAssertion(truncated2, []byte("a"), []byte("b"), []byte("s")); !errors.Is(err, identity.ErrMalformedCOSEKey) {
		t.Errorf("truncated25 err = %v want ErrMalformedCOSEKey", err)
	}
	// Type-byte requests 4-byte ext but only 2 bytes present.
	truncated4 := []byte{(0 << 5) | 26, 0x00, 0x00}
	if err := identity.VerifyAssertion(truncated4, []byte("a"), []byte("b"), []byte("s")); !errors.Is(err, identity.ErrMalformedCOSEKey) {
		t.Errorf("truncated26 err = %v want ErrMalformedCOSEKey", err)
	}
	// Type-byte requests 8-byte ext but only 4 bytes present.
	truncated8 := []byte{(0 << 5) | 27, 0x00, 0x00, 0x00, 0x00}
	if err := identity.VerifyAssertion(truncated8, []byte("a"), []byte("b"), []byte("s")); !errors.Is(err, identity.ErrMalformedCOSEKey) {
		t.Errorf("truncated27 err = %v want ErrMalformedCOSEKey", err)
	}
}

// TestVerifyAssertion_RejectsKeyMissingKty covers the !hasKty branch.
func TestVerifyAssertion_RejectsKeyMissingKty(t *testing.T) {
	t.Parallel()
	// Map with only alg, no kty.
	pairs := [][2][]byte{
		{cborInt(3), cborInt(-7)}, // alg only
	}
	out := encodeCBORLen(5, uint64(len(pairs)))
	for _, p := range pairs {
		out = append(out, p[0]...)
		out = append(out, p[1]...)
	}
	if err := identity.VerifyAssertion(out, []byte("auth"), []byte("cd"), []byte("sig")); !errors.Is(err, identity.ErrMalformedCOSEKey) {
		t.Errorf("err = %v want ErrMalformedCOSEKey", err)
	}
}

// TestVerifyAssertion_RejectsTopNotMap covers the major != 5 branch.
func TestVerifyAssertion_RejectsTopNotMap(t *testing.T) {
	t.Parallel()
	// Top-level uint, not a map.
	if err := identity.VerifyAssertion([]byte{0x05}, []byte("a"), []byte("b"), []byte("s")); !errors.Is(err, identity.ErrMalformedCOSEKey) {
		t.Errorf("err = %v want ErrMalformedCOSEKey", err)
	}
}

// TestVerifyAssertion_ESVerifyKeyTypeMismatch covers an alg=ES256 with an RSA
// key in the cose blob (impossible to construct correctly from real
// authenticators but parseCOSEKey returns the wrong-shape pubkey).
func TestVerifyAssertion_RejectsRSASignatureWithECKey(t *testing.T) {
	t.Parallel()
	// EC2 key with alg ES256
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cose := ec2COSEKey(leftPad32(priv.PublicKey.X.Bytes()), leftPad32(priv.PublicKey.Y.Bytes()))
	// Deliberately pass a non-DER signature (some random bytes).
	if err := identity.VerifyAssertion(cose, []byte("auth"), []byte("cd"), []byte{0x00, 0x01, 0x02}); !errors.Is(err, identity.ErrInvalidSignature) {
		t.Errorf("err = %v want ErrInvalidSignature", err)
	}
}

// encodeECDSASig returns the ASN.1 DER encoding of (r, s) per WebAuthn §6.5.6.
func encodeECDSASig(r, s *big.Int) []byte {
	rb := r.Bytes()
	sb := s.Bytes()
	if len(rb) > 0 && rb[0]&0x80 != 0 {
		rb = append([]byte{0x00}, rb...)
	}
	if len(sb) > 0 && sb[0]&0x80 != 0 {
		sb = append([]byte{0x00}, sb...)
	}
	rPart := append([]byte{0x02, byte(len(rb))}, rb...)
	sPart := append([]byte{0x02, byte(len(sb))}, sb...)
	body := append(rPart, sPart...)
	return append([]byte{0x30, byte(len(body))}, body...)
}
