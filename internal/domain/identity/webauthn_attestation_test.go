// webauthn_attestation_test.go — RED-phase TDD specs for REGISTRATION-time
// attestationObject parsing (auth-hardening Phase A4, ADR-181 D2, CHO-1718).
//
// Per W3C WebAuthn Level 3 §7.1 the registration ceremony delivers an
// attestationObject:
//
//	CBOR map { "fmt": tstr, "attStmt": map, "authData": bstr }
//
// where authData is:
//
//	rpIdHash(32) || flags(1) || signCount(4 BE) ||
//	[attestedCredentialData when flags&AT:
//	    aaguid(16) || credIdLen(2 BE) || credentialId || COSE_Key(CBOR)]
//
// ParseAttestationObject must extract the credentialId + the REAL COSE
// public-key bytes (replacing the "dev-mode-public-key-placeholder" debt at
// passkey_handler.go) and accept ES256 (-7) + RS256 (-257) only, rejecting
// other algorithms cleanly.
//
// Fixture helpers (encodeCBORLen / cborInt / cborBytes / ec2COSEKey /
// rsaCOSEKey / leftPad32) come from webauthn_verify_test.go (same package).
package identity_test

import (
	"bytes"
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

// --- attestation fixture helpers -------------------------------------------

// cborText encodes a CBOR text string (major type 3).
func cborText(s string) []byte {
	out := encodeCBORLen(3, uint64(len(s)))
	return append(out, s...)
}

// cborEmptyMap is a zero-entry CBOR map.
func cborEmptyMap() []byte { return encodeCBORLen(5, 0) }

// buildAuthData assembles a WebAuthn authData blob. When credID+coseKey are
// nil the attestedCredentialData block is omitted entirely (pure assertion
// shape) — pair with flags that lack the AT bit.
func buildAuthData(rpID string, flags byte, signCount uint32, credID, coseKey []byte) []byte {
	rpHash := sha256.Sum256([]byte(rpID))
	out := append([]byte{}, rpHash[:]...)
	out = append(out, flags)
	out = append(out,
		byte(signCount>>24), byte(signCount>>16), byte(signCount>>8), byte(signCount))
	if credID == nil && coseKey == nil {
		return out
	}
	aaguid := make([]byte, 16) // zero AAGUID — "none" attestation
	out = append(out, aaguid...)
	out = append(out, byte(len(credID)>>8), byte(len(credID)))
	out = append(out, credID...)
	out = append(out, coseKey...)
	return out
}

// buildAttestationObject assembles the top-level CBOR map. attStmt is raw
// CBOR (typically cborEmptyMap()).
func buildAttestationObject(format string, attStmt, authData []byte) []byte {
	out := encodeCBORLen(5, 3)
	out = append(out, cborText("fmt")...)
	out = append(out, cborText(format)...)
	out = append(out, cborText("attStmt")...)
	out = append(out, attStmt...)
	out = append(out, cborText("authData")...)
	out = append(out, cborBytes(authData)...)
	return out
}

const (
	testRPID     = "chora.site"
	atFlagUPAT   = byte(0x41) // UP | AT
	atFlagUPOnly = byte(0x01) // UP only — no attested credential data
)

// --- happy paths -------------------------------------------------------------

func TestParseAttestationObject_ES256_HappyPath(t *testing.T) {
	t.Parallel()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	cose := ec2COSEKey(leftPad32(priv.PublicKey.X.Bytes()), leftPad32(priv.PublicKey.Y.Bytes()))
	credID := []byte("es256-credential-id-bytes")
	authData := buildAuthData(testRPID, atFlagUPAT, 7, credID, cose)
	attObj := buildAttestationObject("none", cborEmptyMap(), authData)

	got, err := identity.ParseAttestationObject(attObj)
	if err != nil {
		t.Fatalf("ParseAttestationObject: %v", err)
	}
	if !bytes.Equal(got.CredentialID, credID) {
		t.Errorf("CredentialID = %x want %x", got.CredentialID, credID)
	}
	if !bytes.Equal(got.PublicKeyCOSE, cose) {
		t.Errorf("PublicKeyCOSE bytes mismatch")
	}
	if got.SignCount != 7 {
		t.Errorf("SignCount = %d want 7", got.SignCount)
	}
	if got.Format != "none" {
		t.Errorf("Format = %q want none", got.Format)
	}
	wantHash := sha256.Sum256([]byte(testRPID))
	if !bytes.Equal(got.RPIDHash, wantHash[:]) {
		t.Errorf("RPIDHash mismatch")
	}
}

// TestParseAttestationObject_RoundTrip_VerifyAssertion proves the parsed COSE
// key bytes verify a real assertion — the registration→login bridge that the
// placeholder key could never satisfy.
func TestParseAttestationObject_RoundTrip_VerifyAssertion(t *testing.T) {
	t.Parallel()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cose := ec2COSEKey(leftPad32(priv.PublicKey.X.Bytes()), leftPad32(priv.PublicKey.Y.Bytes()))
	authData := buildAuthData(testRPID, atFlagUPAT, 1, []byte("rt-cred"), cose)
	attObj := buildAttestationObject("none", cborEmptyMap(), authData)

	parsed, err := identity.ParseAttestationObject(attObj)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Sign a fresh assertion with the SAME private key and verify it against
	// the PARSED public key bytes.
	assertAuthData := buildAuthData(testRPID, atFlagUPOnly, 2, nil, nil)
	clientData := []byte(`{"type":"webauthn.get","challenge":"roundtrip"}`)
	cdh := sha256.Sum256(clientData)
	signing := append(append([]byte{}, assertAuthData...), cdh[:]...)
	h := sha256.Sum256(signing)
	r, s, _ := ecdsa.Sign(rand.Reader, priv, h[:])
	sig := encodeECDSASig(r, s)

	if err := identity.VerifyAssertion(parsed.PublicKeyCOSE, assertAuthData, clientData, sig); err != nil {
		t.Fatalf("VerifyAssertion against parsed key: %v", err)
	}
}

func TestParseAttestationObject_RS256_HappyPath(t *testing.T) {
	t.Parallel()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	cose := rsaCOSEKey(priv.PublicKey.N.Bytes(), big.NewInt(int64(priv.PublicKey.E)).Bytes())
	credID := []byte("rs256-cred")
	authData := buildAuthData(testRPID, atFlagUPAT, 0, credID, cose)
	attObj := buildAttestationObject("packed", cborEmptyMap(), authData)

	got, err := identity.ParseAttestationObject(attObj)
	if err != nil {
		t.Fatalf("ParseAttestationObject: %v", err)
	}
	if !bytes.Equal(got.CredentialID, credID) {
		t.Errorf("CredentialID mismatch")
	}
	if !bytes.Equal(got.PublicKeyCOSE, cose) {
		t.Errorf("PublicKeyCOSE mismatch")
	}
	if got.Format != "packed" {
		t.Errorf("Format = %q want packed", got.Format)
	}
}

// TestParseAttestationObject_PackedAttStmtSkipped — a non-empty attStmt map
// (alg + sig, the "packed" shape) must be walked over without corrupting the
// authData extraction, regardless of key order.
func TestParseAttestationObject_PackedAttStmtSkipped(t *testing.T) {
	t.Parallel()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cose := ec2COSEKey(leftPad32(priv.PublicKey.X.Bytes()), leftPad32(priv.PublicKey.Y.Bytes()))
	credID := []byte("packed-cred-id")
	authData := buildAuthData(testRPID, atFlagUPAT, 3, credID, cose)

	// attStmt = {"alg": -7, "sig": <64 bytes>, "x5c": [<bytes>]}
	attStmt := encodeCBORLen(5, 3)
	attStmt = append(attStmt, cborText("alg")...)
	attStmt = append(attStmt, cborInt(-7)...)
	attStmt = append(attStmt, cborText("sig")...)
	attStmt = append(attStmt, cborBytes(make([]byte, 64))...)
	attStmt = append(attStmt, cborText("x5c")...)
	attStmt = append(attStmt, encodeCBORLen(4, 1)...) // array(1)
	attStmt = append(attStmt, cborBytes([]byte("fake-der-cert"))...)

	// Deliberately order keys attStmt → authData → fmt.
	attObj := encodeCBORLen(5, 3)
	attObj = append(attObj, cborText("attStmt")...)
	attObj = append(attObj, attStmt...)
	attObj = append(attObj, cborText("authData")...)
	attObj = append(attObj, cborBytes(authData)...)
	attObj = append(attObj, cborText("fmt")...)
	attObj = append(attObj, cborText("packed")...)

	got, err := identity.ParseAttestationObject(attObj)
	if err != nil {
		t.Fatalf("ParseAttestationObject: %v", err)
	}
	if !bytes.Equal(got.CredentialID, credID) {
		t.Errorf("CredentialID mismatch after attStmt skip")
	}
	if got.Format != "packed" {
		t.Errorf("Format = %q want packed", got.Format)
	}
}

// --- rejection paths ---------------------------------------------------------

func TestParseAttestationObject_UnsupportedAlg_EdDSA(t *testing.T) {
	t.Parallel()
	// OKP / EdDSA key: {1:1, 3:-8, -1:6, -2:bytes}
	pairs := [][2][]byte{
		{cborInt(1), cborInt(1)},
		{cborInt(3), cborInt(-8)},
		{cborInt(-1), cborInt(6)},
		{cborInt(-2), cborBytes(make([]byte, 32))},
	}
	cose := encodeCBORLen(5, uint64(len(pairs)))
	for _, p := range pairs {
		cose = append(cose, p[0]...)
		cose = append(cose, p[1]...)
	}
	authData := buildAuthData(testRPID, atFlagUPAT, 0, []byte("ed-cred"), cose)
	attObj := buildAttestationObject("none", cborEmptyMap(), authData)

	if _, err := identity.ParseAttestationObject(attObj); !errors.Is(err, identity.ErrUnsupportedCOSEAlg) {
		t.Errorf("err = %v want ErrUnsupportedCOSEAlg", err)
	}
}

func TestParseAttestationObject_MissingATFlag(t *testing.T) {
	t.Parallel()
	authData := buildAuthData(testRPID, atFlagUPOnly, 0, nil, nil)
	attObj := buildAttestationObject("none", cborEmptyMap(), authData)
	if _, err := identity.ParseAttestationObject(attObj); !errors.Is(err, identity.ErrMalformedAttestation) {
		t.Errorf("err = %v want ErrMalformedAttestation (no AT flag)", err)
	}
}

func TestParseAttestationObject_TruncatedAuthData(t *testing.T) {
	t.Parallel()
	attObj := buildAttestationObject("none", cborEmptyMap(), []byte("too-short"))
	if _, err := identity.ParseAttestationObject(attObj); !errors.Is(err, identity.ErrMalformedAttestation) {
		t.Errorf("err = %v want ErrMalformedAttestation (short authData)", err)
	}
}

func TestParseAttestationObject_TruncatedCredentialID(t *testing.T) {
	t.Parallel()
	// credIdLen says 200 bytes but only a handful follow.
	rpHash := sha256.Sum256([]byte(testRPID))
	authData := append([]byte{}, rpHash[:]...)
	authData = append(authData, atFlagUPAT, 0, 0, 0, 0)
	authData = append(authData, make([]byte, 16)...) // aaguid
	authData = append(authData, 0x00, 0xC8)          // credIdLen = 200
	authData = append(authData, []byte("short")...)
	attObj := buildAttestationObject("none", cborEmptyMap(), authData)
	if _, err := identity.ParseAttestationObject(attObj); !errors.Is(err, identity.ErrMalformedAttestation) {
		t.Errorf("err = %v want ErrMalformedAttestation (truncated credId)", err)
	}
}

func TestParseAttestationObject_TopLevelNotAMap(t *testing.T) {
	t.Parallel()
	if _, err := identity.ParseAttestationObject([]byte{0x05}); !errors.Is(err, identity.ErrMalformedAttestation) {
		t.Errorf("err = %v want ErrMalformedAttestation (uint top)", err)
	}
	if _, err := identity.ParseAttestationObject(nil); !errors.Is(err, identity.ErrMalformedAttestation) {
		t.Errorf("err = %v want ErrMalformedAttestation (nil)", err)
	}
}

func TestParseAttestationObject_MissingAuthDataKey(t *testing.T) {
	t.Parallel()
	attObj := encodeCBORLen(5, 2)
	attObj = append(attObj, cborText("fmt")...)
	attObj = append(attObj, cborText("none")...)
	attObj = append(attObj, cborText("attStmt")...)
	attObj = append(attObj, cborEmptyMap()...)
	if _, err := identity.ParseAttestationObject(attObj); !errors.Is(err, identity.ErrMalformedAttestation) {
		t.Errorf("err = %v want ErrMalformedAttestation (no authData)", err)
	}
}

func TestParseAttestationObject_MalformedCOSEKeyInAuthData(t *testing.T) {
	t.Parallel()
	// COSE region is garbage that cannot CBOR-decode.
	rpHash := sha256.Sum256([]byte(testRPID))
	authData := append([]byte{}, rpHash[:]...)
	authData = append(authData, atFlagUPAT, 0, 0, 0, 1)
	authData = append(authData, make([]byte, 16)...)
	authData = append(authData, 0x00, 0x04)
	authData = append(authData, []byte("cred")...)
	authData = append(authData, 0xFF, 0xFF) // invalid CBOR head (indefinite)
	attObj := buildAttestationObject("none", cborEmptyMap(), authData)
	if _, err := identity.ParseAttestationObject(attObj); err == nil {
		t.Errorf("expected error for malformed COSE region; got nil")
	}
}

// TestParseAttestationObject_AttStmtExoticValuesSkipped exercises the CBOR
// skip walker over tags, simple values (true/false/null), floats and nested
// arrays inside attStmt — everything CTAP2 could legally place there.
func TestParseAttestationObject_AttStmtExoticValuesSkipped(t *testing.T) {
	t.Parallel()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cose := ec2COSEKey(leftPad32(priv.PublicKey.X.Bytes()), leftPad32(priv.PublicKey.Y.Bytes()))
	credID := []byte("exotic-cred")
	authData := buildAuthData(testRPID, atFlagUPAT, 9, credID, cose)

	// attStmt = {"a": tag(1)(uint 42), "b": true, "c": null, "d": 1.5(f64),
	//            "e": [[1,2],"s"], "f": -42}
	attStmt := encodeCBORLen(5, 6)
	attStmt = append(attStmt, cborText("a")...)
	attStmt = append(attStmt, encodeCBORLen(6, 1)...) // tag(1)
	attStmt = append(attStmt, cborInt(42)...)
	attStmt = append(attStmt, cborText("b")...)
	attStmt = append(attStmt, 0xF5) // true
	attStmt = append(attStmt, cborText("c")...)
	attStmt = append(attStmt, 0xF6) // null
	attStmt = append(attStmt, cborText("d")...)
	attStmt = append(attStmt, 0xFB, 0x3F, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) // 1.5 f64
	attStmt = append(attStmt, cborText("e")...)
	attStmt = append(attStmt, encodeCBORLen(4, 2)...) // array(2)
	attStmt = append(attStmt, encodeCBORLen(4, 2)...) //   array(2)
	attStmt = append(attStmt, cborInt(1)...)
	attStmt = append(attStmt, cborInt(2)...)
	attStmt = append(attStmt, cborText("s")...)
	attStmt = append(attStmt, cborText("f")...)
	attStmt = append(attStmt, cborInt(-42)...)

	attObj := buildAttestationObject("packed", attStmt, authData)
	got, err := identity.ParseAttestationObject(attObj)
	if err != nil {
		t.Fatalf("ParseAttestationObject with exotic attStmt: %v", err)
	}
	if !bytes.Equal(got.CredentialID, credID) {
		t.Errorf("CredentialID corrupted by attStmt skip")
	}
	if got.SignCount != 9 {
		t.Errorf("SignCount = %d want 9", got.SignCount)
	}
}

// TestParseAttestationObject_TruncatedAttStmt — a byte string inside attStmt
// claiming more bytes than exist must fail loud, not over-read.
func TestParseAttestationObject_TruncatedAttStmt(t *testing.T) {
	t.Parallel()
	attObj := encodeCBORLen(5, 2)
	attObj = append(attObj, cborText("attStmt")...)
	// map(1) { "sig": bstr(claims 100, provides 2) }
	attObj = append(attObj, encodeCBORLen(5, 1)...)
	attObj = append(attObj, cborText("sig")...)
	attObj = append(attObj, encodeCBORLen(2, 100)...)
	attObj = append(attObj, 0x01, 0x02)
	// would-be authData key never reached
	attObj = append(attObj, cborText("authData")...)
	if _, err := identity.ParseAttestationObject(attObj); !errors.Is(err, identity.ErrMalformedAttestation) {
		t.Errorf("err = %v want ErrMalformedAttestation (truncated attStmt)", err)
	}
}

// --- SignCountFromAuthenticatorData ------------------------------------------

func TestSignCountFromAuthenticatorData(t *testing.T) {
	t.Parallel()
	authData := buildAuthData(testRPID, atFlagUPOnly, 0x01020304, nil, nil)
	got, err := identity.SignCountFromAuthenticatorData(authData)
	if err != nil {
		t.Fatalf("SignCountFromAuthenticatorData: %v", err)
	}
	if got != 0x01020304 {
		t.Errorf("signCount = %#x want 0x01020304", got)
	}
}

func TestSignCountFromAuthenticatorData_TooShort(t *testing.T) {
	t.Parallel()
	if _, err := identity.SignCountFromAuthenticatorData([]byte("short")); !errors.Is(err, identity.ErrMalformedAttestation) {
		t.Errorf("err = %v want ErrMalformedAttestation", err)
	}
}

// --- initial sign-count on the credential aggregate ---------------------------

func TestNewPasskeyCredential_InitialSignCount(t *testing.T) {
	t.Parallel()
	cred, err := identity.NewPasskeyCredential(identity.NewPasskeyCredentialParams{
		Gcid:             "01970000-0000-7000-8000-0000000000cc",
		CredentialID:     []byte("cred"),
		PublicKeyCOSE:    []byte("cose"),
		RPID:             testRPID,
		InitialSignCount: 41,
	})
	if err != nil {
		t.Fatalf("NewPasskeyCredential: %v", err)
	}
	if cred.SignCount != 41 {
		t.Errorf("SignCount = %d want 41", cred.SignCount)
	}
	// Monotonicity machinery must keep working from the seeded value.
	if err := cred.RecordUse(40); !errors.Is(err, identity.ErrPasskeyCredentialReplay) {
		t.Errorf("RecordUse(40) err = %v want ErrPasskeyCredentialReplay", err)
	}
	if err := cred.RecordUse(42); err != nil {
		t.Errorf("RecordUse(42) err = %v want nil", err)
	}
}

// --- x5c self-attestation posture (D9) ---------------------------------------

// TestParseAttestationObject_X5cChain_SelfAttestationPosture_D9 PINS the
// deliberate D9 (CHO-1790) security posture: the attestation statement —
// including a "packed" x5c CERTIFICATE CHAIN — is parsed-past, NOT validated.
//
// A "packed" attestationObject carrying an UNTRUSTED / bogus x5c chain (a
// cert that chains to no FIDO Metadata Service root, with a non-verifying
// attestation signature) is STILL accepted and the credential is extracted.
// This is intentional self-attestation: Chora does not maintain a FIDO MDS
// trust store and gates no entitlement on attested authenticator provenance.
// Full x5c chain validation is a tracked follow-up (needs the MDS trust
// anchors + its own ADR). If a future change wires chain validation, THIS
// test must flip (and the SECURITY POSTURE comment in webauthn_verify.go must
// be removed) — it is the tripwire that makes the posture an explicit,
// reviewed decision rather than a silent gap.
func TestParseAttestationObject_X5cChain_SelfAttestationPosture_D9(t *testing.T) {
	t.Parallel()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cose := ec2COSEKey(leftPad32(priv.PublicKey.X.Bytes()), leftPad32(priv.PublicKey.Y.Bytes()))
	credID := []byte("x5c-posture-cred-id")
	authData := buildAuthData(testRPID, atFlagUPAT, 11, credID, cose)

	// "packed" attStmt = {"alg": -7, "sig": <bogus 64B>, "x5c": [<untrusted
	// DER cert that chains to nothing>]}. None of this is verified.
	attStmt := encodeCBORLen(5, 3)
	attStmt = append(attStmt, cborText("alg")...)
	attStmt = append(attStmt, cborInt(-7)...)
	attStmt = append(attStmt, cborText("sig")...)
	attStmt = append(attStmt, cborBytes(bytes.Repeat([]byte{0xAB}, 64))...) // non-verifying sig
	attStmt = append(attStmt, cborText("x5c")...)
	attStmt = append(attStmt, encodeCBORLen(4, 1)...) // array(1)
	attStmt = append(attStmt, cborBytes([]byte("UNTRUSTED-DER-CERT-CHAINS-TO-NO-ROOT"))...)

	attObj := buildAttestationObject("packed", attStmt, authData)

	got, err := identity.ParseAttestationObject(attObj)
	if err != nil {
		t.Fatalf("self-attestation posture: a bogus x5c chain must STILL parse "+
			"(no chain validation by design); got err=%v", err)
	}
	if !bytes.Equal(got.CredentialID, credID) {
		t.Errorf("CredentialID mismatch under x5c skip")
	}
	if !bytes.Equal(got.PublicKeyCOSE, cose) {
		t.Errorf("PublicKeyCOSE mismatch under x5c skip")
	}
	if got.Format != "packed" {
		t.Errorf("Format = %q want packed", got.Format)
	}
}
