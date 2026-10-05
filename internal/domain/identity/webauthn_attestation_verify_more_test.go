// webauthn_attestation_verify_more_test.go — branch-coverage TDD for ADR-187
// sub-phase 2: RS256 attestation, alg/key-type mismatch, unsupported alg,
// empty-roots, malformed attStmt, unparseable leaf/intermediate, nil-input,
// unsupported format. Reuses the helpers from webauthn_attestation_verify_test.go.
package identity_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// assembleAuthDataCDH builds authData (with the given AAGUID + credKey) and a
// fixed clientDataHash, returning both so a test can sign authData‖cdh itself.
func assembleAuthDataCDH(aaguid []byte, credKey *ecdsa.PrivateKey) (authData, cdh []byte) {
	cose := ecPubCOSE(&credKey.PublicKey)
	authData = buildAuthDataAAGUID(testRPID, atFlagUPAT, 0, aaguid, []byte("cred-id-xyz"), cose)
	h := sha256.Sum256([]byte(`{"type":"webauthn.create"}`))
	return authData, h[:]
}

func signRS256(t *testing.T, key *rsa.PrivateKey, msg []byte) []byte {
	t.Helper()
	h := sha256.Sum256(msg)
	s, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	if err != nil {
		t.Fatalf("rs256 sign: %v", err)
	}
	return s
}

func mintRSALeaf(t *testing.T, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, aaguid []byte) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "Test RSA Attestation"},
		NotBefore:             attTestNow.Add(-time.Hour),
		NotAfter:              attTestNow.Add(time.Hour),
		IsCA:                  false,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}
	if aaguid != nil {
		val, _ := asn1.Marshal(aaguid)
		tmpl.ExtraExtensions = []pkix.Extension{{Id: fidoAAGUIDExtOID, Value: val}}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("rsa leaf cert: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert, key
}

func mustParse(t *testing.T, attObj []byte) *identity.AttestedCredential {
	t.Helper()
	att, err := identity.ParseAttestationObject(attObj)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return att
}

func trustedResolver(root *x509.Certificate) *fakeResolver {
	return &fakeResolver{found: true, meta: identity.AAGUIDMetadata{Roots: []*x509.Certificate{root}}}
}

// --- RS256 full attestation (covers verifyAttestationSig RS256 branch) ------

func TestVerifyAttestation_PackedFull_RS256Leaf_Verified(t *testing.T) {
	root, rootKey := mintRoot(t)
	aaguid := aaguid16(0xA1)
	leaf, leafKey := mintRSALeaf(t, root, rootKey, aaguid)
	credKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	authData, cdh := assembleAuthDataCDH(aaguid, credKey)
	sig := signRS256(t, leafKey, append(append([]byte{}, authData...), cdh...))
	attObj := buildAttestationObject("packed", packedAttStmt(-257, sig, [][]byte{leaf.Raw}), authData)

	res, err := identity.VerifyAttestationStatement(mustParse(t, attObj), cdh, trustedResolver(root), attTestNow)
	if err != nil || !res.Verified {
		t.Fatalf("RS256 packed-full must verify; err=%v res=%+v", err, res)
	}
}

// --- alg/key-type mismatch (covers verifyAttestationSig type-assert branches) ---

func TestVerifyAttestation_PackedFull_AlgKeyTypeMismatch_Unverified(t *testing.T) {
	root, rootKey := mintRoot(t)
	aaguid := aaguid16(0xA2)
	leaf, leafKey := mintLeaf(t, root, rootKey, aaguid, attTestNow.Add(-time.Hour), attTestNow.Add(time.Hour)) // EC leaf
	credKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	authData, cdh := assembleAuthDataCDH(aaguid, credKey)
	sig := signES256(t, leafKey, append(append([]byte{}, authData...), cdh...))
	// Claim RS256 in the attStmt while the leaf key is EC ⇒ type-assert fails.
	attObj := buildAttestationObject("packed", packedAttStmt(-257, sig, [][]byte{leaf.Raw}), authData)

	res, _ := identity.VerifyAttestationStatement(mustParse(t, attObj), cdh, trustedResolver(root), attTestNow)
	if res.Verified {
		t.Fatal("alg≠leaf-key-type must be Verified=false")
	}
}

// --- unsupported attestation alg --------------------------------------------

func TestVerifyAttestation_PackedFull_UnsupportedAlg_Unverified(t *testing.T) {
	root, rootKey := mintRoot(t)
	aaguid := aaguid16(0xA3)
	leaf, leafKey := mintLeaf(t, root, rootKey, aaguid, attTestNow.Add(-time.Hour), attTestNow.Add(time.Hour))
	credKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	authData, cdh := assembleAuthDataCDH(aaguid, credKey)
	sig := signES256(t, leafKey, append(append([]byte{}, authData...), cdh...))
	attObj := buildAttestationObject("packed", packedAttStmt(-8 /* EdDSA, unsupported */, sig, [][]byte{leaf.Raw}), authData)

	res, _ := identity.VerifyAttestationStatement(mustParse(t, attObj), cdh, trustedResolver(root), attTestNow)
	if res.Verified {
		t.Fatal("unsupported attestation alg must be Verified=false")
	}
}

// --- empty trusted roots (covers verifyX5CChain no-roots branch) ------------

func TestVerifyAttestation_PackedFull_EmptyRoots_Unverified(t *testing.T) {
	root, rootKey := mintRoot(t)
	aaguid := aaguid16(0xA4)
	leaf, leafKey := mintLeaf(t, root, rootKey, aaguid, attTestNow.Add(-time.Hour), attTestNow.Add(time.Hour))
	credKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	authData, cdh := assembleAuthDataCDH(aaguid, credKey)
	sig := signES256(t, leafKey, append(append([]byte{}, authData...), cdh...))
	attObj := buildAttestationObject("packed", packedAttStmt(-7, sig, [][]byte{leaf.Raw}), authData)
	// found=true but no roots provided.
	res, _ := identity.VerifyAttestationStatement(mustParse(t, attObj), cdh, &fakeResolver{found: true, meta: identity.AAGUIDMetadata{}}, attTestNow)
	if res.Verified {
		t.Fatal("found AAGUID with empty roots must be Verified=false")
	}
	if !res.Evaluable {
		t.Fatal("empty roots is a definite verdict, Evaluable=true")
	}
}

// --- malformed attStmt (covers parsePackedAttStmt error path) ---------------

func TestVerifyAttestation_PackedMalformedAttStmt_Unverified(t *testing.T) {
	credKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	authData, cdh := assembleAuthDataCDH(aaguid16(0xA5), credKey)
	// empty attStmt map ⇒ missing alg/sig.
	attObj := buildAttestationObject("packed", cborEmptyMap(), authData)
	res, err := identity.VerifyAttestationStatement(mustParse(t, attObj), cdh, &fakeResolver{}, attTestNow)
	if err != nil {
		t.Fatalf("malformed attStmt must NOT error (record-safe): %v", err)
	}
	if res.Verified {
		t.Fatal("malformed attStmt must be Verified=false")
	}
}

// --- unparseable leaf / intermediate ----------------------------------------

func TestVerifyAttestation_PackedBadLeafCert_Unverified(t *testing.T) {
	credKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	authData, cdh := assembleAuthDataCDH(aaguid16(0xA6), credKey)
	sig := signES256(t, credKey, append(append([]byte{}, authData...), cdh...))
	attObj := buildAttestationObject("packed", packedAttStmt(-7, sig, [][]byte{[]byte("not-a-cert")}), authData)
	res, _ := identity.VerifyAttestationStatement(mustParse(t, attObj), cdh, &fakeResolver{}, attTestNow)
	if res.Verified {
		t.Fatal("unparseable x5c leaf must be Verified=false")
	}
}

func TestVerifyAttestation_PackedBadIntermediate_Unverified(t *testing.T) {
	root, rootKey := mintRoot(t)
	aaguid := aaguid16(0xA7)
	leaf, leafKey := mintLeaf(t, root, rootKey, aaguid, attTestNow.Add(-time.Hour), attTestNow.Add(time.Hour))
	credKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	authData, cdh := assembleAuthDataCDH(aaguid, credKey)
	sig := signES256(t, leafKey, append(append([]byte{}, authData...), cdh...))
	// leaf valid, but a garbage intermediate makes chain building fail.
	attObj := buildAttestationObject("packed", packedAttStmt(-7, sig, [][]byte{leaf.Raw, []byte("garbage-intermediate")}), authData)
	res, _ := identity.VerifyAttestationStatement(mustParse(t, attObj), cdh, trustedResolver(root), attTestNow)
	if res.Verified {
		t.Fatal("garbage intermediate must be Verified=false")
	}
}

// --- nil input + unsupported format -----------------------------------------

func TestVerifyAttestation_NilInputs_Error(t *testing.T) {
	if _, err := identity.VerifyAttestationStatement(nil, nil, &fakeResolver{}, attTestNow); err == nil {
		t.Fatal("nil attested must error")
	}
	if _, err := identity.VerifyAttestationStatement(&identity.AttestedCredential{Format: "none"}, nil, nil, attTestNow); err == nil {
		t.Fatal("nil resolver must error")
	}
}

func TestVerifyAttestation_UnsupportedFormat_RecordsUnverified(t *testing.T) {
	credKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cose := ecPubCOSE(&credKey.PublicKey)
	authData := buildAuthData(testRPID, atFlagUPAT, 0, []byte("cred"), cose)
	attObj := buildAttestationObject("tpm", cborEmptyMap(), authData) // tpm verifier is a later sub-phase
	res, err := identity.VerifyAttestationStatement(mustParse(t, attObj), []byte("cdh"), &fakeResolver{}, attTestNow)
	if err != nil {
		t.Fatalf("unsupported format must NOT error: %v", err)
	}
	if res.Verified || res.Format != "tpm" {
		t.Fatalf("tpm must record Verified=false, Format=tpm; got %+v", res)
	}
}

func TestParseAttestationMode_Off(t *testing.T) {
	if identity.ParseAttestationMode("off") != identity.AttestationModeOff {
		t.Fatal("off")
	}
	if identity.ParseAttestationMode("OFF") != identity.AttestationModeOff {
		t.Fatal("case-insensitive off")
	}
}

// --- attStmt parsing robustness ---------------------------------------------

func TestVerifyAttestation_PackedAttStmtNotAMap_Unverified(t *testing.T) {
	credKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	authData, cdh := assembleAuthDataCDH(aaguid16(0xB1), credKey)
	// attStmt is a CBOR int, not a map.
	attObj := buildAttestationObject("packed", cborInt(42), authData)
	res, err := identity.VerifyAttestationStatement(mustParse(t, attObj), cdh, &fakeResolver{}, attTestNow)
	if err != nil {
		t.Fatalf("non-map attStmt must NOT error (record-safe): %v", err)
	}
	if res.Verified {
		t.Fatal("non-map attStmt must be Verified=false")
	}
}

func TestVerifyAttestation_PackedAttStmtExtraKey_Ignored(t *testing.T) {
	root, rootKey := mintRoot(t)
	aaguid := aaguid16(0xB2)
	leaf, leafKey := mintLeaf(t, root, rootKey, aaguid, attTestNow.Add(-time.Hour), attTestNow.Add(time.Hour))
	credKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	authData, cdh := assembleAuthDataCDH(aaguid, credKey)
	sig := signES256(t, leafKey, append(append([]byte{}, authData...), cdh...))
	// Hand-build an attStmt map with an extra "ver" key the parser must skip.
	att := encodeCBORLen(5, 4)
	att = append(att, cborText("ver")...)
	att = append(att, cborText("2.0")...)
	att = append(att, cborText("alg")...)
	att = append(att, cborInt(-7)...)
	att = append(att, cborText("sig")...)
	att = append(att, cborBytes(sig)...)
	att = append(att, cborText("x5c")...)
	att = append(att, encodeCBORLen(4, 1)...)
	att = append(att, cborBytes(leaf.Raw)...)
	attObj := buildAttestationObject("packed", att, authData)

	res, _ := identity.VerifyAttestationStatement(mustParse(t, attObj), cdh, trustedResolver(root), attTestNow)
	if !res.Verified {
		t.Fatalf("an extra attStmt key must be skipped, not break parsing (reason=%q)", res.Reason)
	}
}
