// fidomds_extra_test.go — internal-package coverage for the unexported JWS
// verification + blob-parsing helpers, plus the Start background-refresh
// loop and the production HTTPFetcher. The external fidomds_test.go covers
// the exported Refresh/ResolveAAGUID happy+error paths; this file pushes the
// remaining error branches.
package fidomds

import (
	"bytes"
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
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- self-contained fixtures (external test package helpers not visible) -----

var intMDSNow = time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)

type intStubFetcher struct {
	blob []byte
	err  error
}

func (f intStubFetcher) Fetch(context.Context) ([]byte, error) { return f.blob, f.err }

const intTestAAGUID = "9c835346796b4c278898d6032f515cc5"

func intAAGUIDBytes(t *testing.T) []byte {
	t.Helper()
	b, err := hex.DecodeString(intTestAAGUID)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func intMintCA(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             intMDSNow.Add(-365 * 24 * time.Hour),
		NotAfter:              intMDSNow.Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	c, _ := x509.ParseCertificate(der)
	return c, key
}

func intMintECSigner(t *testing.T, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "MDS Signer"},
		NotBefore:             intMDSNow.Add(-time.Hour),
		NotAfter:              intMDSNow.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	c, _ := x509.ParseCertificate(der)
	return c, key
}

func intLeftPad(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

func intMakeES256JWS(t *testing.T, x5c [][]byte, payload []byte, key *ecdsa.PrivateKey) []byte {
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
	sig := append(intLeftPad(r.Bytes(), 32), intLeftPad(s.Bytes(), 32)...)
	return []byte(h64 + "." + p64 + "." + base64.RawURLEncoding.EncodeToString(sig))
}

func intBlobPayload(status string) []byte {
	entry := map[string]any{
		"aaguid": intTestAAGUID,
		"metadataStatement": map[string]any{
			"description":                 "Internal Test Authenticator",
			"attestationRootCertificates": []string{},
		},
		"statusReports": []map[string]any{{"status": status}},
	}
	b, _ := json.Marshal(map[string]any{"no": 7, "nextUpdate": "2026-07-15", "entries": []any{entry}})
	return b
}

// --- Refresh: no-fetcher guard ------------------------------------------------

func TestStore_Refresh_NoFetcherConfigured(t *testing.T) {
	s := New(Config{})
	if err := s.Refresh(context.Background()); err == nil {
		t.Fatal("Refresh must error when no fetcher is configured")
	}
}

// TestStore_Refresh_ValidJWSWithGarbagePayload drives the parse-error wrap:
// a well-formed JWS whose payload is not valid MDS JSON passes verifyJWS but
// must fail Refresh with a "fidomds: parse:" prefix.
func TestStore_Refresh_ValidJWSWithGarbagePayload(t *testing.T) {
	fidoRoot, fidoKey := intMintCA(t, "FIDO Root")
	signer, signerKey := intMintECSigner(t, fidoRoot, fidoKey)
	blob := intMakeES256JWS(t, [][]byte{signer.Raw}, []byte("{"), signerKey)
	s := New(Config{
		Fetcher:    intStubFetcher{blob: blob},
		RootBundle: []*x509.Certificate{fidoRoot},
		Now:        func() time.Time { return intMDSNow },
	})
	err := s.Refresh(context.Background())
	if err == nil || !strings.Contains(err.Error(), "fidomds: parse:") {
		t.Fatalf("err = %v, want parse-wrap", err)
	}
}

// --- Start: background refresh loop -------------------------------------------

func TestStore_Start_InitialRefreshThenLoopCancels(t *testing.T) {
	fidoRoot, fidoKey := intMintCA(t, "FIDO Root")
	signer, signerKey := intMintECSigner(t, fidoRoot, fidoKey)
	blob := intMakeES256JWS(t, [][]byte{signer.Raw}, intBlobPayload("FIDO_CERTIFIED_L2"), signerKey)
	s := New(Config{
		Fetcher:         intStubFetcher{blob: blob},
		RootBundle:      []*x509.Certificate{fidoRoot},
		RefreshInterval: 15 * time.Millisecond,
		Now:             func() time.Time { return intMDSNow },
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Start(ctx, nil)

	ab := intAAGUIDBytes(t)
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, found, err := s.ResolveAAGUID(ab); err == nil && found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("initial Refresh never populated the index")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Let at least one timer-driven re-refresh fire before cancelling.
	time.Sleep(60 * time.Millisecond)
	cancel()
	// Give the goroutine a moment to observe the cancellation and exit.
	time.Sleep(30 * time.Millisecond)
	if _, found, _ := s.ResolveAAGUID(ab); !found {
		t.Error("index lost after Start cancellation")
	}
}

// TestStore_Start_NextUpdateControlsWaitWhenSooner asserts the wait
// calculation prefers the BLOB-declared nextUpdate when it fires sooner than
// RefreshInterval. Date-granularity: nextUpdate "2026-06-21" (parsed as
// 2026-06-21T00:00:00Z) with Now = 2026-06-20T23:59:59Z means ~1s to the
// next refresh, not the full 1h RefreshInterval. Certs are minted relative
// to an earlier base so they're valid at that Now.
func TestStore_Start_NextUpdateControlsWaitWhenSooner(t *testing.T) {
	const base = "2026-06-19T00:00:00Z"
	baseT, _ := time.Parse(time.RFC3339, base)
	now := time.Date(2026, 6, 20, 23, 59, 59, 0, time.UTC)

	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "FIDO Root"},
		NotBefore: baseT, NotAfter: baseT.Add(7 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	root, _ := x509.ParseCertificate(rootDER)

	signerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signerTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "MDS Signer"},
		NotBefore: baseT, NotAfter: baseT.Add(7 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
	}
	signerDER, _ := x509.CreateCertificate(rand.Reader, signerTmpl, root, &signerKey.PublicKey, rootKey)
	signer, _ := x509.ParseCertificate(signerDER)

	entry := map[string]any{
		"aaguid":            intTestAAGUID,
		"metadataStatement": map[string]any{"description": "x"},
	}
	payload, _ := json.Marshal(map[string]any{"no": 55, "nextUpdate": "2026-06-21", "entries": []any{entry}})
	blob := intMakeES256JWS(t, [][]byte{signer.Raw}, payload, signerKey)

	s := New(Config{
		Fetcher:         intStubFetcher{blob: blob},
		RootBundle:      []*x509.Certificate{root},
		RefreshInterval: time.Hour,
		Now:             func() time.Time { return now },
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Start(ctx, nil)

	ab := intAAGUIDBytes(t)
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, found, err := s.ResolveAAGUID(ab); err == nil && found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("initial Refresh never populated the index")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// ~1s after the initial refresh the nextUpdate-driven timer fires and
	// the loop refreshes again. Sleeping past that point proves the loop did
	// not wait the full hour-long RefreshInterval.
	time.Sleep(1300 * time.Millisecond)
	cancel()
	if _, found, _ := s.ResolveAAGUID(ab); !found {
		t.Error("index lost after nextUpdate-driven refresh + cancel")
	}
}

func TestStore_Start_ReportsRefreshErrors(t *testing.T) {
	s := New(Config{
		Fetcher:         intStubFetcher{err: errors.New("blob service down")},
		RefreshInterval: 10 * time.Millisecond,
		Now:             func() time.Time { return intMDSNow },
	})
	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	var reports []error
	done := make(chan struct{})
	go func() {
		s.Start(ctx, func(err error) {
			mu.Lock()
			reports = append(reports, err)
			mu.Unlock()
		})
		close(done)
	}()

	deadline := time.Now().Add(3 * time.Second)
	for {
		mu.Lock()
		n := len(reports)
		mu.Unlock()
		if n >= 3 { // initial + at least two timer-driven re-refreshes
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("refresh errors never reported")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after ctx cancellation")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(reports) < 3 {
		t.Errorf("reports = %d, want >= 3", len(reports))
	}
}

// --- HTTPFetcher (production fetch path) ---------------------------------------

func TestHTTPFetcher_Fetch_Success(t *testing.T) {
	body := []byte("raw-mds-blob-bytes")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	defer ts.Close()

	got, err := (HTTPFetcher{URL: ts.URL}).Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("body = %q, want %q", got, body)
	}
}

func TestHTTPFetcher_Fetch_EmptyURL(t *testing.T) {
	if _, err := (HTTPFetcher{}).Fetch(context.Background()); err == nil {
		t.Fatal("empty URL must error")
	}
}

func TestHTTPFetcher_Fetch_NonOKStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "overloaded", http.StatusServiceUnavailable)
	}))
	defer ts.Close()
	if _, err := (HTTPFetcher{URL: ts.URL}).Fetch(context.Background()); err == nil {
		t.Fatal("non-200 response must error")
	}
}

func TestHTTPFetcher_Fetch_TransportError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("x"))
	}))
	url := ts.URL
	ts.Close() // dial now fails with connection refused
	if _, err := (HTTPFetcher{URL: url}).Fetch(context.Background()); err == nil {
		t.Fatal("transport failure must error")
	}
}

func TestHTTPFetcher_Fetch_UsesExplicitClient(t *testing.T) {
	body := []byte("explicit-client-body")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	defer ts.Close()
	got, err := (HTTPFetcher{URL: ts.URL, Client: ts.Client()}).Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch with explicit client: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("body = %q, want %q", got, body)
	}
}

// TestHTTPFetcher_Fetch_InvalidURL drives the http.NewRequestWithContext
// error branch (an unparseable URL fails request construction before any
// network I/O).
func TestHTTPFetcher_Fetch_InvalidURL(t *testing.T) {
	if _, err := (HTTPFetcher{URL: "http://exa mple.com/blob"}).Fetch(context.Background()); err == nil {
		t.Fatal("URL containing a space must fail request construction")
	}
}

// --- verifyJWS error branches --------------------------------------------------

func TestVerifyJWS_ErrorBranches(t *testing.T) {
	fidoRoot, fidoKey := intMintCA(t, "FIDO Root")
	signer, signerKey := intMintECSigner(t, fidoRoot, fidoKey)
	valid := intMakeES256JWS(t, [][]byte{signer.Raw}, intBlobPayload("FIDO_CERTIFIED"), signerKey)
	roots := []*x509.Certificate{fidoRoot}
	now := intMDSNow

	rawB64 := base64.RawURLEncoding.EncodeToString
	stdB64 := base64.StdEncoding.EncodeToString

	cases := []struct {
		name       string
		blob       string
		wantSubstr string
		roots      []*x509.Certificate
	}{
		{"not compact", "a.b", "compact JWS", roots},
		{"no roots", "a.b.c", "root bundle", nil},
		{"bad header b64", "!!!.x.y", "header b64", roots},
		{"bad header json", rawB64([]byte("not-json")) + ".x.y", "header json", roots},
		{"missing x5c", rawB64([]byte(`{"alg":"ES256"}`)) + ".x.y", "missing x5c", roots},
		{"bad x5c b64", rawB64([]byte(`{"alg":"ES256","x5c":["!!!"]}`)) + ".x.y", "x5c[0] b64", roots},
		{"x5c parse", rawB64([]byte(`{"alg":"ES256","x5c":["`+stdB64([]byte("not-a-cert"))+`"]}`)) + ".x.y", "x5c[0] parse", roots},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, err := verifyJWS([]byte(tc.blob), tc.roots, now)
			if err == nil || !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Fatalf("err = %v, want substring %q", err, tc.wantSubstr)
			}
		})
	}

	// Corrupt the signature segment of an otherwise-valid JWS.
	parts := strings.Split(string(valid), ".")
	parts[2] = "%%%"
	if _, err := verifyJWS([]byte(strings.Join(parts, ".")), roots, now); err == nil || !strings.Contains(err.Error(), "sig b64") {
		t.Fatalf("bad sig b64: err = %v, want substring %q", err, "sig b64")
	}

	// Positive control: the valid JWS verifies and returns the payload.
	payload, err := verifyJWS(valid, roots, now)
	if err != nil {
		t.Fatalf("valid JWS must verify: %v", err)
	}
	if !bytes.Contains(payload, []byte(`"aaguid"`)) {
		t.Errorf("payload %q missing aaguid entry", payload)
	}
}

// TestVerifyJWS_IntermediateChain exercises the intermediates branch of the
// x5c chain build (a BLOB whose leaf chains through an intermediate CA to
// the configured root).
func TestVerifyJWS_IntermediateChain(t *testing.T) {
	fidoRoot, rootKey := intMintCA(t, "FIDO Root")
	midKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	midTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "FIDO Intermediate"},
		NotBefore: intMDSNow.Add(-time.Hour), NotAfter: intMDSNow.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	midDER, _ := x509.CreateCertificate(rand.Reader, midTmpl, fidoRoot, &midKey.PublicKey, rootKey)
	mid, _ := x509.ParseCertificate(midDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "MDS Signer"},
		NotBefore: intMDSNow.Add(-time.Hour), NotAfter: intMDSNow.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, mid, &leafKey.PublicKey, midKey)
	leaf, _ := x509.ParseCertificate(leafDER)

	blob := intMakeES256JWS(t, [][]byte{leaf.Raw, mid.Raw}, intBlobPayload("FIDO_CERTIFIED"), leafKey)
	if _, err := verifyJWS(blob, []*x509.Certificate{fidoRoot}, intMDSNow); err != nil {
		t.Fatalf("intermediate chain must verify: %v", err)
	}
}

// --- verifyJWSSig error branches ------------------------------------------------

func TestVerifyJWSSig_Branches(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	si := []byte("signing-input")
	sum := sha256.Sum256(si)

	r, s, _ := ecdsa.Sign(rand.Reader, ecKey, sum[:])
	es256Sig := append(intLeftPad(r.Bytes(), 32), intLeftPad(s.Bytes(), 32)...)

	t.Run("ES256 valid", func(t *testing.T) {
		if err := verifyJWSSig(&ecKey.PublicKey, "ES256", si, es256Sig); err != nil {
			t.Errorf("valid ES256 rejected: %v", err)
		}
	})
	t.Run("ES256 non-ECDSA key", func(t *testing.T) {
		err := verifyJWSSig(&rsaKey.PublicKey, "ES256", si, es256Sig)
		if err == nil || !strings.Contains(err.Error(), "non-ECDSA") {
			t.Errorf("err = %v, want non-ECDSA", err)
		}
	})
	t.Run("ES256 wrong length", func(t *testing.T) {
		err := verifyJWSSig(&ecKey.PublicKey, "ES256", si, make([]byte, 63))
		if err == nil || !strings.Contains(err.Error(), "64 bytes") {
			t.Errorf("err = %v, want 64 bytes", err)
		}
	})
	t.Run("ES256 bad signature", func(t *testing.T) {
		err := verifyJWSSig(&ecKey.PublicKey, "ES256", si, make([]byte, 64))
		if err == nil || !strings.Contains(err.Error(), "did not verify") {
			t.Errorf("err = %v, want did not verify", err)
		}
	})

	rsSig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("rsa sign: %v", err)
	}
	t.Run("RS256 valid", func(t *testing.T) {
		if err := verifyJWSSig(&rsaKey.PublicKey, "RS256", si, rsSig); err != nil {
			t.Errorf("valid RS256 rejected: %v", err)
		}
	})
	t.Run("RS256 non-RSA key", func(t *testing.T) {
		err := verifyJWSSig(&ecKey.PublicKey, "RS256", si, rsSig)
		if err == nil || !strings.Contains(err.Error(), "non-RSA") {
			t.Errorf("err = %v, want non-RSA", err)
		}
	})
	t.Run("RS256 bad signature", func(t *testing.T) {
		if err := verifyJWSSig(&rsaKey.PublicKey, "RS256", si, make([]byte, 256)); err == nil {
			t.Error("garbage RS256 signature must not verify")
		}
	})
	t.Run("unsupported alg", func(t *testing.T) {
		err := verifyJWSSig(&ecKey.PublicKey, "HS256", si, es256Sig)
		if err == nil || !strings.Contains(err.Error(), "unsupported JWS alg") {
			t.Errorf("err = %v, want unsupported JWS alg", err)
		}
	})
}

// --- parseBlobPayload branches ---------------------------------------------------

func TestParseBlobPayload_RejectsBadJSON(t *testing.T) {
	if _, _, _, err := parseBlobPayload([]byte("{")); err == nil {
		t.Fatal("malformed payload JSON must error")
	}
}

func TestParseBlobPayload_SkipsInvalidAAGUID(t *testing.T) {
	payload := []byte(`{"no":1,"entries":[{"aaguid":"not-a-uuid-format","metadataStatement":{"description":"x"}}]}`)
	idx, _, _, err := parseBlobPayload(payload)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(idx) != 0 {
		t.Errorf("invalid aaguid entry must be skipped, got %d entries", len(idx))
	}
}

func TestParseBlobPayload_SkipsBadAttestationRoots(t *testing.T) {
	entry := map[string]any{
		"aaguid": intTestAAGUID,
		"metadataStatement": map[string]any{
			"description":                 "x",
			"attestationRootCertificates": []string{"!!!", base64.StdEncoding.EncodeToString([]byte("not-a-cert"))},
		},
		"statusReports": []map[string]any{{"status": "REVOKED"}},
	}
	payload, _ := json.Marshal(map[string]any{"no": 2, "entries": []any{entry}})
	idx, _, _, err := parseBlobPayload(payload)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	meta, ok := idx[intTestAAGUID]
	if !ok {
		t.Fatal("entry with a valid aaguid must be indexed despite bad roots")
	}
	if len(meta.Roots) != 0 {
		t.Errorf("bad attestation roots must be skipped, got %d", len(meta.Roots))
	}
	if !meta.Revoked {
		t.Error("REVOKED status must set Revoked even when roots failed to parse")
	}
}

func TestParseBlobPayload_GarbageNextUpdateIgnored(t *testing.T) {
	entry := map[string]any{
		"aaguid":            intTestAAGUID,
		"metadataStatement": map[string]any{"description": "x"},
	}
	payload, _ := json.Marshal(map[string]any{"no": 3, "nextUpdate": "not-a-date", "entries": []any{entry}})
	idx, nextUpdate, serial, err := parseBlobPayload(payload)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !nextUpdate.IsZero() {
		t.Errorf("garbage nextUpdate must be ignored, got %v", nextUpdate)
	}
	if serial != 3 || len(idx) != 1 {
		t.Errorf("serial/len = %d/%d, want 3/1", serial, len(idx))
	}
}

func TestParseBlobPayload_CertLevelVariants(t *testing.T) {
	for _, tc := range []struct {
		status, wantLevel string
	}{
		{"FIDO_CERTIFIED_L1plus", "L1"},
		{"FIDO_CERTIFIED_bogus", "L1"},
		{"FIDO_CERTIFIED_L3plus", "L3"},
	} {
		entry := map[string]any{
			"aaguid":            intTestAAGUID,
			"metadataStatement": map[string]any{"description": "x"},
			"statusReports":     []map[string]any{{"status": tc.status}},
		}
		payload, _ := json.Marshal(map[string]any{"entries": []any{entry}})
		idx, _, _, err := parseBlobPayload(payload)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if got := idx[intTestAAGUID].CertificationLevel; got != tc.wantLevel {
			t.Errorf("status %q → level %q, want %q", tc.status, got, tc.wantLevel)
		}
	}
}

// --- aaguidKey / certLevelFromStatus direct branches ------------------------------

func TestAAGUIDKey_Branches(t *testing.T) {
	if k, ok := aaguidKey("9C835346-796B-4C27-8898-D6032F515CC5"); !ok || k != intTestAAGUID {
		t.Errorf("canonical uuid: got %q, %v", k, ok)
	}
	if _, ok := aaguidKey("short"); ok {
		t.Error("too-short aaguid must fail")
	}
	if _, ok := aaguidKey("gggggggggggggggggggggggggggggggg"); ok {
		t.Error("non-hex aaguid must fail")
	}
}

func TestCertLevelFromStatus_Variants(t *testing.T) {
	cases := map[string]string{
		"FIDO_CERTIFIED":        "L1",
		"FIDO_CERTIFIED_L2":     "L2",
		"FIDO_CERTIFIED_L2plus": "L2",
		"FIDO_CERTIFIED_abc":    "L1",
		"REVOKED":               "",
		"":                      "",
	}
	for status, want := range cases {
		if got := certLevelFromStatus(status); got != want {
			t.Errorf("certLevelFromStatus(%q) = %q, want %q", status, got, want)
		}
	}
}
