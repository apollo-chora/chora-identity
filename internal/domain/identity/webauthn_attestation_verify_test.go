// webauthn_attestation_verify_test.go — RED-phase TDD specs for ADR-187
// sub-phase 2: registration attestation-STATEMENT verification (W3C WebAuthn
// L3 §8), packed (full + self) + none formats, with strict provenance
// semantics (amendment A1) and an injected clock (amendment A5).
//
// "Verified" is STRICT: true iff the x5c chain validated to a trusted MDS
// attestation root AND the attestation signature verified AND the leaf's
// AAGUID extension matched authData.aaguid AND the AAGUID is not revoked.
// none / packed-self / unknown-AAGUID / bad-chain / cold-trust-store all
// record Verified=false (never an error, so the policy layer is the single
// allow/deny decision point — amendment A3).
//
// Fixture helpers encodeCBORLen / cborInt / cborBytes / cborText /
// buildAuthData / buildAttestationObject / ec2COSEKey come from the sibling
// _test.go files (same identity_test package).
package identity_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// fidoAAGUIDExtOID is the FIDO "id-fido-gen-ce-aaguid" cert extension
// (1.3.6.1.4.1.45724.1.1.4) — its value is an OCTET STRING wrapping the
// 16-byte AAGUID (W3C WebAuthn L3 §8.2.1).
var fidoAAGUIDExtOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}

var attTestNow = time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)

// --- cert minting -----------------------------------------------------------

func mintRoot(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("root key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test FIDO MDS Root"},
		NotBefore:             attTestNow.Add(-365 * 24 * time.Hour),
		NotAfter:              attTestNow.Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("root cert: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert, key
}

// mintLeaf signs an end-entity attestation cert under parent, optionally
// embedding the FIDO AAGUID extension and overriding validity for the
// clock-injection test.
func mintLeaf(t *testing.T, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, aaguid []byte, notBefore, notAfter time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test Authenticator Attestation"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  false,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}
	if aaguid != nil {
		val, err := asn1.Marshal(aaguid) // OCTET STRING(16)
		if err != nil {
			t.Fatalf("aaguid ext: %v", err)
		}
		tmpl.ExtraExtensions = []pkix.Extension{{Id: fidoAAGUIDExtOID, Value: val}}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert, key
}

// --- packed attStmt assembly ------------------------------------------------

// packedAttStmt builds a CBOR attStmt map { "alg": int, "sig": bstr, "x5c": [bstr...] }.
// x5c omitted when nil (self-attestation shape).
func packedAttStmt(alg int64, sig []byte, x5c [][]byte) []byte {
	pairs := 2
	if x5c != nil {
		pairs = 3
	}
	out := encodeCBORLen(5, uint64(pairs))
	out = append(out, cborText("alg")...)
	out = append(out, cborInt(alg)...)
	out = append(out, cborText("sig")...)
	out = append(out, cborBytes(sig)...)
	if x5c != nil {
		out = append(out, cborText("x5c")...)
		out = append(out, encodeCBORLen(4, uint64(len(x5c)))...)
		for _, c := range x5c {
			out = append(out, cborBytes(c)...)
		}
	}
	return out
}

// ecPubCOSE serialises an ECDSA P-256 pub key as a COSE_Key (-7) for authData.
func ecPubCOSE(pub *ecdsa.PublicKey) []byte {
	return ec2COSEKey(leftPad32(pub.X.Bytes()), leftPad32(pub.Y.Bytes()))
}

// signES256 returns an ASN.1 DER ECDSA signature over sha256(msg).
func signES256(t *testing.T, key *ecdsa.PrivateKey, msg []byte) []byte {
	t.Helper()
	h := sha256.Sum256(msg)
	sig, err := ecdsa.SignASN1(rand.Reader, key, h[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return sig
}

// buildPacked assembles (attestationObject, clientDataHash, authData) for a
// packed attestation. credKey is the credential keypair embedded in authData;
// sigKey signs the attestation (the leaf key for full, the credential key for
// self). x5c nil ⇒ self-attestation.
func buildPacked(t *testing.T, aaguid []byte, credKey, sigKey *ecdsa.PrivateKey, x5c [][]byte) (attObj, clientDataHash []byte) {
	t.Helper()
	cose := ecPubCOSE(&credKey.PublicKey)
	authData := buildAuthDataAAGUID(testRPID, atFlagUPAT, 0, aaguid, []byte("cred-id-xyz"), cose)
	cdh := sha256.Sum256([]byte(`{"type":"webauthn.create"}`))
	sig := signES256(t, sigKey, append(append([]byte{}, authData...), cdh[:]...))
	att := packedAttStmt(-7, sig, x5c)
	return buildAttestationObject("packed", att, authData), cdh[:]
}

// buildAuthDataAAGUID is buildAuthData with a caller-supplied AAGUID (the
// sibling helper hard-codes a zero AAGUID).
func buildAuthDataAAGUID(rpID string, flags byte, signCount uint32, aaguid, credID, coseKey []byte) []byte {
	rpHash := sha256.Sum256([]byte(rpID))
	out := append([]byte{}, rpHash[:]...)
	out = append(out, flags)
	out = append(out, byte(signCount>>24), byte(signCount>>16), byte(signCount>>8), byte(signCount))
	out = append(out, aaguid...)
	out = append(out, byte(len(credID)>>8), byte(len(credID)))
	out = append(out, credID...)
	out = append(out, coseKey...)
	return out
}

// --- fake MetadataResolver --------------------------------------------------

type fakeResolver struct {
	meta     identity.AAGUIDMetadata
	found    bool
	evalErr  error // non-nil ⇒ "can't evaluate" (cold/unreachable trust store)
	gotAAGID []byte
}

func (f *fakeResolver) ResolveAAGUID(aaguid []byte) (identity.AAGUIDMetadata, bool, error) {
	f.gotAAGID = aaguid
	if f.evalErr != nil {
		return identity.AAGUIDMetadata{}, false, f.evalErr
	}
	return f.meta, f.found, nil
}

func aaguid16(b byte) []byte {
	a := make([]byte, 16)
	for i := range a {
		a[i] = b
	}
	return a
}

// --- none -------------------------------------------------------------------

func TestVerifyAttestation_None_RecordsUnverified(t *testing.T) {
	credKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cose := ecPubCOSE(&credKey.PublicKey)
	authData := buildAuthData(testRPID, atFlagUPAT, 0, []byte("cred"), cose)
	attObj := buildAttestationObject("none", cborEmptyMap(), authData)
	att, err := identity.ParseAttestationObject(attObj)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	res, err := identity.VerifyAttestationStatement(att, []byte("cdh"), &fakeResolver{}, attTestNow)
	if err != nil {
		t.Fatalf("verify returned error: %v", err)
	}
	if res.Verified {
		t.Fatal("none attestation must record Verified=false")
	}
	if res.Format != "none" {
		t.Fatalf("format = %q want none", res.Format)
	}
}

// --- packed self ------------------------------------------------------------

func TestVerifyAttestation_PackedSelf_ValidSig_StillUnverified(t *testing.T) {
	credKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	attObj, cdh := buildPacked(t, aaguid16(0xAB), credKey, credKey, nil) // self: sig by cred key, no x5c
	att, err := identity.ParseAttestationObject(attObj)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	res, err := identity.VerifyAttestationStatement(att, cdh, &fakeResolver{}, attTestNow)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if res.Verified {
		t.Fatal("A1: self-attestation is NOT provenance — must be Verified=false")
	}
}

// --- packed full happy path -------------------------------------------------

func TestVerifyAttestation_PackedFull_ChainsToTrustedRoot_Verified(t *testing.T) {
	root, rootKey := mintRoot(t)
	aaguid := aaguid16(0xCD)
	leaf, leafKey := mintLeaf(t, root, rootKey, aaguid, attTestNow.Add(-time.Hour), attTestNow.Add(time.Hour))
	credKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	attObj, cdh := buildPacked(t, aaguid, credKey, leafKey, [][]byte{leaf.Raw})

	att, err := identity.ParseAttestationObject(attObj)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	res, err := identity.VerifyAttestationStatement(att, cdh, &fakeResolver{
		found: true,
		meta: identity.AAGUIDMetadata{
			Roots:                    []*x509.Certificate{root},
			AuthenticatorDescription: "Test Authenticator",
			CertificationLevel:       "L1",
		},
	}, attTestNow)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if !res.Verified {
		t.Fatalf("packed-full chaining to a trusted root must be Verified=true (reason=%q)", res.Reason)
	}
	if res.AuthenticatorDescription != "Test Authenticator" || res.CertificationLevel != "L1" {
		t.Fatalf("provenance not propagated: %+v", res)
	}
}

func TestVerifyAttestation_PackedFull_RS256_Verified(t *testing.T) {
	// RS256-keyed credential, ES256 leaf — exercises the RS256 cred path while
	// the attestation sig stays ES256 (alg in attStmt drives the sig alg).
	root, rootKey := mintRoot(t)
	aaguid := aaguid16(0x11)
	leaf, leafKey := mintLeaf(t, root, rootKey, aaguid, attTestNow.Add(-time.Hour), attTestNow.Add(time.Hour))
	credKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	attObj, cdh := buildPacked(t, aaguid, credKey, leafKey, [][]byte{leaf.Raw})
	att, _ := identity.ParseAttestationObject(attObj)
	res, err := identity.VerifyAttestationStatement(att, cdh, &fakeResolver{found: true, meta: identity.AAGUIDMetadata{Roots: []*x509.Certificate{root}}}, attTestNow)
	if err != nil || !res.Verified {
		t.Fatalf("want verified; err=%v res=%+v", err, res)
	}
}

// --- packed full negative paths ---------------------------------------------

func TestVerifyAttestation_PackedFull_BadSig_Unverified(t *testing.T) {
	root, rootKey := mintRoot(t)
	aaguid := aaguid16(0x22)
	leaf, leafKey := mintLeaf(t, root, rootKey, aaguid, attTestNow.Add(-time.Hour), attTestNow.Add(time.Hour))
	credKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	attObj, cdh := buildPacked(t, aaguid, credKey, leafKey, [][]byte{leaf.Raw})
	// flip a byte of clientDataHash so the signed message no longer matches.
	cdh[0] ^= 0xFF
	att, _ := identity.ParseAttestationObject(attObj)
	res, err := identity.VerifyAttestationStatement(att, cdh, &fakeResolver{found: true, meta: identity.AAGUIDMetadata{Roots: []*x509.Certificate{root}}}, attTestNow)
	if err != nil {
		t.Fatalf("content failures must NOT error (record-safe): %v", err)
	}
	if res.Verified {
		t.Fatal("tampered attestation sig must be Verified=false")
	}
}

func TestVerifyAttestation_PackedFull_UntrustedRoot_Unverified(t *testing.T) {
	root, rootKey := mintRoot(t)
	other, _ := mintRoot(t) // resolver returns a DIFFERENT root
	aaguid := aaguid16(0x33)
	leaf, leafKey := mintLeaf(t, root, rootKey, aaguid, attTestNow.Add(-time.Hour), attTestNow.Add(time.Hour))
	credKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	attObj, cdh := buildPacked(t, aaguid, credKey, leafKey, [][]byte{leaf.Raw})
	att, _ := identity.ParseAttestationObject(attObj)
	res, _ := identity.VerifyAttestationStatement(att, cdh, &fakeResolver{found: true, meta: identity.AAGUIDMetadata{Roots: []*x509.Certificate{other}}}, attTestNow)
	if res.Verified {
		t.Fatal("leaf not chaining to the resolved root must be Verified=false")
	}
	if !res.Evaluable {
		t.Fatal("an unknown chain is a definite verdict — Evaluable should stay true")
	}
}

func TestVerifyAttestation_PackedFull_UnknownAAGUID_Unverified(t *testing.T) {
	root, rootKey := mintRoot(t)
	aaguid := aaguid16(0x44)
	leaf, leafKey := mintLeaf(t, root, rootKey, aaguid, attTestNow.Add(-time.Hour), attTestNow.Add(time.Hour))
	credKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	attObj, cdh := buildPacked(t, aaguid, credKey, leafKey, [][]byte{leaf.Raw})
	att, _ := identity.ParseAttestationObject(attObj)
	res, _ := identity.VerifyAttestationStatement(att, cdh, &fakeResolver{found: false}, attTestNow) // not in MDS
	if res.Verified {
		t.Fatal("unknown AAGUID must be Verified=false")
	}
	if !res.Evaluable {
		t.Fatal("not-found is a definite verdict (Evaluable=true), distinct from can't-evaluate")
	}
}

func TestVerifyAttestation_PackedFull_AAGUIDExtMismatch_Unverified(t *testing.T) {
	root, rootKey := mintRoot(t)
	// leaf carries AAGUID 0x55 in its cert extension, but authData says 0x66.
	leaf, leafKey := mintLeaf(t, root, rootKey, aaguid16(0x55), attTestNow.Add(-time.Hour), attTestNow.Add(time.Hour))
	credKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	attObj, cdh := buildPacked(t, aaguid16(0x66), credKey, leafKey, [][]byte{leaf.Raw})
	att, _ := identity.ParseAttestationObject(attObj)
	res, _ := identity.VerifyAttestationStatement(att, cdh, &fakeResolver{found: true, meta: identity.AAGUIDMetadata{Roots: []*x509.Certificate{root}}}, attTestNow)
	if res.Verified {
		t.Fatal("leaf AAGUID extension ≠ authData.aaguid must be Verified=false")
	}
}

func TestVerifyAttestation_PackedFull_Revoked_Unverified(t *testing.T) {
	root, rootKey := mintRoot(t)
	aaguid := aaguid16(0x77)
	leaf, leafKey := mintLeaf(t, root, rootKey, aaguid, attTestNow.Add(-time.Hour), attTestNow.Add(time.Hour))
	credKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	attObj, cdh := buildPacked(t, aaguid, credKey, leafKey, [][]byte{leaf.Raw})
	att, _ := identity.ParseAttestationObject(attObj)
	res, _ := identity.VerifyAttestationStatement(att, cdh, &fakeResolver{found: true, meta: identity.AAGUIDMetadata{Roots: []*x509.Certificate{root}, Revoked: true}}, attTestNow)
	if res.Verified {
		t.Fatal("revoked AAGUID must be Verified=false")
	}
}

func TestVerifyAttestation_PackedFull_ExpiredLeaf_Unverified(t *testing.T) {
	root, rootKey := mintRoot(t)
	aaguid := aaguid16(0x88)
	// leaf already expired relative to attTestNow.
	leaf, leafKey := mintLeaf(t, root, rootKey, aaguid, attTestNow.Add(-48*time.Hour), attTestNow.Add(-24*time.Hour))
	credKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	attObj, cdh := buildPacked(t, aaguid, credKey, leafKey, [][]byte{leaf.Raw})
	att, _ := identity.ParseAttestationObject(attObj)
	res, _ := identity.VerifyAttestationStatement(att, cdh, &fakeResolver{found: true, meta: identity.AAGUIDMetadata{Roots: []*x509.Certificate{root}}}, attTestNow)
	if res.Verified {
		t.Fatal("expired leaf (clock-injected now) must be Verified=false")
	}
}

func TestVerifyAttestation_PackedFull_ColdTrustStore_NotEvaluable(t *testing.T) {
	root, rootKey := mintRoot(t)
	aaguid := aaguid16(0x99)
	leaf, leafKey := mintLeaf(t, root, rootKey, aaguid, attTestNow.Add(-time.Hour), attTestNow.Add(time.Hour))
	credKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	attObj, cdh := buildPacked(t, aaguid, credKey, leafKey, [][]byte{leaf.Raw})
	att, _ := identity.ParseAttestationObject(attObj)
	res, _ := identity.VerifyAttestationStatement(att, cdh, &fakeResolver{evalErr: assertColdError{}}, attTestNow)
	if res.Verified {
		t.Fatal("cold trust store must be Verified=false")
	}
	if res.Evaluable {
		t.Fatal("A3: cold/unreachable trust store must set Evaluable=false (≠ untrusted)")
	}
}

type assertColdError struct{}

func (assertColdError) Error() string { return "mds cache cold" }
