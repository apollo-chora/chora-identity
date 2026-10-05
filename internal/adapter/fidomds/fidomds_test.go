// fidomds_test.go — TDD for the FIDO MDS3 trust-store adapter (ADR-187 §D3).
// A synthetic BLOB is minted in-test: a fake FIDO root CA + MDS signing leaf,
// a JSON payload with entries, signed as a compact ES256/RS256 JWS.
package fidomds_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/apollo-chora/chora-identity/internal/adapter/fidomds"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

var mdsNow = time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)

// Compile-time: the Store satisfies the domain's resolver port.
var _ identity.MetadataResolver = (*fidomds.Store)(nil)

// --- cert + JWS fixtures ----------------------------------------------------

func mintCA(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             mdsNow.Add(-365 * 24 * time.Hour),
		NotAfter:              mdsNow.Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	c, _ := x509.ParseCertificate(der)
	return c, key
}

func mintECSigner(t *testing.T, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "MDS Signer"},
		NotBefore:             mdsNow.Add(-time.Hour),
		NotAfter:              mdsNow.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	c, _ := x509.ParseCertificate(der)
	return c, key
}

func leftPad(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

// makeES256JWS builds a compact ES256 JWS (raw R‖S signature, per JWS — NOT DER).
func makeES256JWS(t *testing.T, x5c [][]byte, payload []byte, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	x5cB64 := make([]string, len(x5c))
	for i, c := range x5c {
		x5cB64[i] = base64.StdEncoding.EncodeToString(c)
	}
	hj, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": "JWT", "x5c": x5cB64})
	h64 := base64.RawURLEncoding.EncodeToString(hj)
	p64 := base64.RawURLEncoding.EncodeToString(payload)
	sum := sha256.Sum256([]byte(h64 + "." + p64))
	r, s, _ := ecdsa.Sign(rand.Reader, key, sum[:])
	sig := append(leftPad(r.Bytes(), 32), leftPad(s.Bytes(), 32)...)
	return []byte(h64 + "." + p64 + "." + base64.RawURLEncoding.EncodeToString(sig))
}

type stubFetcher struct {
	blob []byte
	err  error
}

func (s stubFetcher) Fetch(context.Context) ([]byte, error) { return s.blob, s.err }

const testAAGUIDStr = "9c835346-796b-4c27-8898-d6032f515cc5"

func testAAGUIDBytes(t *testing.T) []byte {
	t.Helper()
	b, err := hex.DecodeString("9c835346796b4c278898d6032f515cc5")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// blobPayload builds an MDS payload JSON with one entry for testAAGUIDStr.
func blobPayload(attRootDER []byte, status, nextUpdate string) []byte {
	entry := map[string]any{
		"aaguid": testAAGUIDStr,
		"metadataStatement": map[string]any{
			"description":                 "Test Authenticator Model",
			"attestationRootCertificates": []string{base64.StdEncoding.EncodeToString(attRootDER)},
		},
		"statusReports": []map[string]any{{"status": status}},
	}
	b, _ := json.Marshal(map[string]any{"no": 7, "nextUpdate": nextUpdate, "entries": []any{entry}})
	return b
}

func newStore(t *testing.T, root *x509.Certificate, blob []byte) *fidomds.Store {
	return fidomds.New(fidomds.Config{
		Fetcher:    stubFetcher{blob: blob},
		RootBundle: []*x509.Certificate{root},
		Now:        func() time.Time { return mdsNow },
	})
}

// --- tests ------------------------------------------------------------------

func TestStore_Cold_ReturnsErr(t *testing.T) {
	s := fidomds.New(fidomds.Config{RootBundle: nil})
	if _, _, err := s.ResolveAAGUID(testAAGUIDBytes(t)); err == nil {
		t.Fatal("cold store must return an error (can't-evaluate)")
	}
}

func TestStore_Refresh_IndexesAndResolves(t *testing.T) {
	fidoRoot, fidoKey := mintCA(t, "FIDO Root")
	signer, signerKey := mintECSigner(t, fidoRoot, fidoKey)
	attRoot, _ := mintCA(t, "Attestation Root")
	blob := makeES256JWS(t, [][]byte{signer.Raw}, blobPayload(attRoot.Raw, "FIDO_CERTIFIED_L2", "2026-07-15"), signerKey)

	s := newStore(t, fidoRoot, blob)
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	meta, found, err := s.ResolveAAGUID(testAAGUIDBytes(t))
	if err != nil || !found {
		t.Fatalf("known AAGUID must resolve; found=%v err=%v", found, err)
	}
	if len(meta.Roots) != 1 || !meta.Roots[0].Equal(attRoot) {
		t.Fatalf("attestation root not indexed: %+v", meta.Roots)
	}
	if meta.AuthenticatorDescription != "Test Authenticator Model" {
		t.Fatalf("description = %q", meta.AuthenticatorDescription)
	}
	if meta.CertificationLevel != "L2" {
		t.Fatalf("cert level = %q want L2", meta.CertificationLevel)
	}
	if meta.Revoked {
		t.Fatal("L2-certified entry must not be Revoked")
	}
	if _, nextUpdate, no := s.Age(); no != 7 || nextUpdate.IsZero() {
		t.Fatalf("Age serial/nextUpdate = %d / %v", no, nextUpdate)
	}
}

func TestStore_UnknownAAGUID_NotFound(t *testing.T) {
	fidoRoot, fidoKey := mintCA(t, "FIDO Root")
	signer, signerKey := mintECSigner(t, fidoRoot, fidoKey)
	attRoot, _ := mintCA(t, "Attestation Root")
	blob := makeES256JWS(t, [][]byte{signer.Raw}, blobPayload(attRoot.Raw, "FIDO_CERTIFIED", "2026-07-15"), signerKey)
	s := newStore(t, fidoRoot, blob)
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	other := make([]byte, 16)
	other[0] = 0xFF
	_, found, err := s.ResolveAAGUID(other)
	if err != nil {
		t.Fatalf("loaded store must not error on lookup: %v", err)
	}
	if found {
		t.Fatal("unknown AAGUID must be found=false")
	}
}

func TestStore_Refresh_UntrustedBlobRoot_Rejected(t *testing.T) {
	fidoRoot, fidoKey := mintCA(t, "FIDO Root")
	signer, signerKey := mintECSigner(t, fidoRoot, fidoKey)
	attRoot, _ := mintCA(t, "Attestation Root")
	blob := makeES256JWS(t, [][]byte{signer.Raw}, blobPayload(attRoot.Raw, "FIDO_CERTIFIED", "2026-07-15"), signerKey)

	// Store trusts a DIFFERENT root than the BLOB chains to.
	otherRoot, _ := mintCA(t, "Other Root")
	s := fidomds.New(fidomds.Config{
		Fetcher:    stubFetcher{blob: blob},
		RootBundle: []*x509.Certificate{otherRoot},
		Now:        func() time.Time { return mdsNow },
	})
	if err := s.Refresh(context.Background()); err == nil {
		t.Fatal("BLOB not chaining to the trusted root must be rejected")
	}
	if _, _, err := s.ResolveAAGUID(testAAGUIDBytes(t)); err == nil {
		t.Fatal("store must stay cold after a rejected refresh")
	}
}

func TestStore_Refresh_TamperedSig_Rejected(t *testing.T) {
	fidoRoot, fidoKey := mintCA(t, "FIDO Root")
	signer, signerKey := mintECSigner(t, fidoRoot, fidoKey)
	attRoot, _ := mintCA(t, "Attestation Root")
	blob := makeES256JWS(t, [][]byte{signer.Raw}, blobPayload(attRoot.Raw, "FIDO_CERTIFIED", "2026-07-15"), signerKey)
	blob[len(blob)-2] ^= 0x01 // corrupt the signature segment
	s := newStore(t, fidoRoot, blob)
	if err := s.Refresh(context.Background()); err == nil {
		t.Fatal("tampered JWS signature must be rejected")
	}
}

func TestStore_Refresh_RevokedStatus(t *testing.T) {
	fidoRoot, fidoKey := mintCA(t, "FIDO Root")
	signer, signerKey := mintECSigner(t, fidoRoot, fidoKey)
	attRoot, _ := mintCA(t, "Attestation Root")
	blob := makeES256JWS(t, [][]byte{signer.Raw}, blobPayload(attRoot.Raw, "REVOKED", "2026-07-15"), signerKey)
	s := newStore(t, fidoRoot, blob)
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	meta, found, _ := s.ResolveAAGUID(testAAGUIDBytes(t))
	if !found || !meta.Revoked {
		t.Fatalf("REVOKED status must set meta.Revoked; found=%v meta=%+v", found, meta)
	}
}

func TestStore_Refresh_FetchError_Propagates(t *testing.T) {
	s := fidomds.New(fidomds.Config{Fetcher: stubFetcher{err: context.DeadlineExceeded}, RootBundle: []*x509.Certificate{{}}})
	if err := s.Refresh(context.Background()); err == nil {
		t.Fatal("fetch error must propagate")
	}
}

func TestStore_Refresh_RS256JWS(t *testing.T) {
	// RS256-signed BLOB exercises the RSA JWS branch.
	fidoRoot, fidoKey := mintCA(t, "FIDO Root")
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "RSA MDS Signer"},
		NotBefore: mdsNow.Add(-time.Hour), NotAfter: mdsNow.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, fidoRoot, &rsaKey.PublicKey, fidoKey)
	signer, _ := x509.ParseCertificate(der)
	attRoot, _ := mintCA(t, "Attestation Root")
	payload := blobPayload(attRoot.Raw, "FIDO_CERTIFIED_L1", "2026-08-01")

	x5cB64 := []string{base64.StdEncoding.EncodeToString(signer.Raw)}
	hj, _ := json.Marshal(map[string]any{"alg": "RS256", "x5c": x5cB64})
	h64 := base64.RawURLEncoding.EncodeToString(hj)
	p64 := base64.RawURLEncoding.EncodeToString(payload)
	sum := sha256.Sum256([]byte(h64 + "." + p64))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, sum[:])
	blob := []byte(h64 + "." + p64 + "." + base64.RawURLEncoding.EncodeToString(sig))

	s := newStore(t, fidoRoot, blob)
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatalf("RS256 BLOB refresh: %v", err)
	}
	meta, found, _ := s.ResolveAAGUID(testAAGUIDBytes(t))
	if !found || meta.CertificationLevel != "L1" {
		t.Fatalf("RS256 path: found=%v level=%q", found, meta.CertificationLevel)
	}
}

func TestStore_Refresh_NotAJWS_Rejected(t *testing.T) {
	fidoRoot, _ := mintCA(t, "FIDO Root")
	s := newStore(t, fidoRoot, []byte("not-a-jws"))
	if err := s.Refresh(context.Background()); err == nil {
		t.Fatal("non-JWS blob must be rejected")
	}
}
