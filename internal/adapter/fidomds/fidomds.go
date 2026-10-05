// Package fidomds implements identity.MetadataResolver against the FIDO
// Alliance Metadata Service v3 (MDS3) — ADR-187 sub-phase 3.
//
// The MDS3 BLOB is a JWS (compact serialization) whose x5c header chains to the
// FIDO Alliance Root CA. This adapter fetches the BLOB, verifies the JWS chain
// + signature against a CONFIG-SOURCED root bundle (ADR-187 A2 — never an
// in-repo pinned root, which would be a silent expiry bomb), parses the entries,
// and indexes them by AAGUID. The registration hot path is served from the
// in-memory index (Refresh runs in the background); a never-refreshed/cold index
// returns ErrTrustStoreCold so the domain records "can't-evaluate" (A3) rather
// than "untrusted".
//
// stdlib only — consistent with the hand-rolled CBOR/COSE in the domain.
package fidomds

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// ErrTrustStoreCold is returned by ResolveAAGUID before any successful Refresh.
// The domain maps a resolver error to Evaluable=false (can't-evaluate, A3).
var ErrTrustStoreCold = errors.New("fidomds: trust store not yet loaded")

// BlobFetcher returns the raw compact-JWS MDS BLOB bytes.
type BlobFetcher interface {
	Fetch(ctx context.Context) ([]byte, error)
}

// Config wires the trust store. All values are caller-supplied (env / Secret
// Manager resolved upstream — ADR-187 A6); the package hard-codes nothing.
type Config struct {
	// Fetcher retrieves the BLOB (HTTPFetcher in prod; a stub in tests).
	Fetcher BlobFetcher
	// RootBundle is the FIDO Alliance Root CA trust anchor(s) the BLOB's JWS
	// x5c chain must validate to (A2 — config-sourced, rotatable).
	RootBundle []*x509.Certificate
	// RefreshInterval bounds how often the background loop refreshes when the
	// BLOB carries no usable nextUpdate (default 24h).
	RefreshInterval time.Duration
	// Now is injected for deterministic cert-validity + staleness (A5).
	Now func() time.Time
}

// Store is the in-memory, refreshable FIDO MDS trust store.
type Store struct {
	cfg Config

	mu         sync.RWMutex
	index      map[string]identity.AAGUIDMetadata // keyed by identity.AAGUIDHex
	fetchedAt  time.Time
	nextUpdate time.Time
	serialNo   int
}

// New constructs a Store. The index is cold until the first successful Refresh.
func New(cfg Config) *Store {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.RefreshInterval <= 0 {
		cfg.RefreshInterval = 24 * time.Hour
	}
	return &Store{cfg: cfg}
}

// ResolveAAGUID implements identity.MetadataResolver. A cold index returns
// ErrTrustStoreCold (⇒ can't-evaluate); a loaded index returns (meta, found,nil).
func (s *Store) ResolveAAGUID(aaguid []byte) (identity.AAGUIDMetadata, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.index == nil {
		return identity.AAGUIDMetadata{}, false, ErrTrustStoreCold
	}
	m, ok := s.index[identity.AAGUIDHex(aaguid)]
	return m, ok, nil
}

// Refresh fetches, JWS-verifies, parses, and atomically swaps in a fresh index.
// On any failure the previous index is retained (a transient fetch/verify error
// must not blank the trust store).
func (s *Store) Refresh(ctx context.Context) error {
	if s.cfg.Fetcher == nil {
		return errors.New("fidomds: no fetcher configured")
	}
	blob, err := s.cfg.Fetcher.Fetch(ctx)
	if err != nil {
		return fmt.Errorf("fidomds: fetch: %w", err)
	}
	payload, err := verifyJWS(blob, s.cfg.RootBundle, s.cfg.Now())
	if err != nil {
		return fmt.Errorf("fidomds: jws verify: %w", err)
	}
	index, nextUpdate, serial, err := parseBlobPayload(payload)
	if err != nil {
		return fmt.Errorf("fidomds: parse: %w", err)
	}
	s.mu.Lock()
	s.index = index
	s.nextUpdate = nextUpdate
	s.serialNo = serial
	s.fetchedAt = s.cfg.Now()
	s.mu.Unlock()
	return nil
}

// Age reports how long since the last successful Refresh and the BLOB's declared
// nextUpdate — surfaced for the A2 blob-age/expiry observability.
func (s *Store) Age() (fetchedAt, nextUpdate time.Time, serial int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.fetchedAt, s.nextUpdate, s.serialNo
}

// Start runs an initial Refresh then loops until ctx is cancelled, re-refreshing
// at min(RefreshInterval, time-to-nextUpdate). refreshErr (nil-able) is invoked
// on each failed refresh for the caller's logging/metrics.
func (s *Store) Start(ctx context.Context, refreshErr func(error)) {
	report := func(err error) {
		if err != nil && refreshErr != nil {
			refreshErr(err)
		}
	}
	report(s.Refresh(ctx))
	for {
		s.mu.RLock()
		next := s.nextUpdate
		s.mu.RUnlock()
		wait := s.cfg.RefreshInterval
		if !next.IsZero() {
			if d := next.Sub(s.cfg.Now()); d > 0 && d < wait {
				wait = d
			}
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			report(s.Refresh(ctx))
		}
	}
}

// --- JWS verification -------------------------------------------------------

type jwsHeader struct {
	Alg string   `json:"alg"`
	X5c []string `json:"x5c"`
}

// verifyJWS validates the compact JWS: builds the header x5c chain to roots at
// time now, then verifies the signature over "<headerB64>.<payloadB64>".
// Returns the decoded payload bytes.
func verifyJWS(blob []byte, roots []*x509.Certificate, now time.Time) ([]byte, error) {
	s := strings.TrimSpace(string(blob))
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return nil, errors.New("not a compact JWS (need 3 parts)")
	}
	if len(roots) == 0 {
		return nil, errors.New("no trusted FIDO root bundle configured")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("header b64: %w", err)
	}
	var hdr jwsHeader
	if err := json.Unmarshal(headerJSON, &hdr); err != nil {
		return nil, fmt.Errorf("header json: %w", err)
	}
	if len(hdr.X5c) == 0 {
		return nil, errors.New("JWS header missing x5c")
	}
	chain := make([]*x509.Certificate, 0, len(hdr.X5c))
	for i, c := range hdr.X5c {
		der, err := base64.StdEncoding.DecodeString(c)
		if err != nil {
			return nil, fmt.Errorf("x5c[%d] b64: %w", i, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("x5c[%d] parse: %w", i, err)
		}
		chain = append(chain, cert)
	}
	leaf := chain[0]
	rootPool := x509.NewCertPool()
	for _, r := range roots {
		rootPool.AddCert(r)
	}
	interPool := x509.NewCertPool()
	for _, c := range chain[1:] {
		interPool.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: interPool,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("x5c chain: %w", err)
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("sig b64: %w", err)
	}
	signingInput := []byte(parts[0] + "." + parts[1])
	if err := verifyJWSSig(leaf.PublicKey, hdr.Alg, signingInput, sig); err != nil {
		return nil, err
	}
	return base64.RawURLEncoding.DecodeString(parts[1])
}

// verifyJWSSig verifies a JWS signature. NOTE: JWS ES256 uses raw R‖S (64 bytes),
// NOT the ASN.1 DER used by the WebAuthn attestation signature.
func verifyJWSSig(pub any, alg string, signingInput, sig []byte) error {
	h := sha256.Sum256(signingInput)
	switch alg {
	case "ES256":
		ec, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("ES256 header but non-ECDSA signing cert")
		}
		if len(sig) != 64 {
			return fmt.Errorf("ES256 sig must be 64 bytes, got %d", len(sig))
		}
		r := new(big.Int).SetBytes(sig[:32])
		ss := new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(ec, h[:], r, ss) {
			return errors.New("ES256 signature did not verify")
		}
		return nil
	case "RS256":
		rk, ok := pub.(*rsa.PublicKey)
		if !ok {
			return errors.New("RS256 header but non-RSA signing cert")
		}
		return rsa.VerifyPKCS1v15(rk, crypto.SHA256, h[:], sig)
	default:
		return fmt.Errorf("unsupported JWS alg %q", alg)
	}
}

// --- BLOB payload parsing ---------------------------------------------------

type mdsBlob struct {
	No         int        `json:"no"`
	NextUpdate string     `json:"nextUpdate"`
	Entries    []mdsEntry `json:"entries"`
}

type mdsEntry struct {
	AAGUID            string `json:"aaguid"`
	MetadataStatement struct {
		Description                 string   `json:"description"`
		AttestationRootCertificates []string `json:"attestationRootCertificates"`
	} `json:"metadataStatement"`
	StatusReports []struct {
		Status string `json:"status"`
	} `json:"statusReports"`
}

// disqualifyingStatuses mark an AAGUID as not-trustworthy (FIDO MDS3 §3.1.4).
var disqualifyingStatuses = map[string]bool{
	"REVOKED":                      true,
	"USER_VERIFICATION_BYPASS":     true,
	"ATTESTATION_KEY_COMPROMISE":   true,
	"USER_KEY_REMOTE_COMPROMISE":   true,
	"USER_KEY_PHYSICAL_COMPROMISE": true,
}

func parseBlobPayload(payload []byte) (index map[string]identity.AAGUIDMetadata, nextUpdate time.Time, serial int, err error) {
	var blob mdsBlob
	if err := json.Unmarshal(payload, &blob); err != nil {
		return nil, time.Time{}, 0, fmt.Errorf("payload json: %w", err)
	}
	index = make(map[string]identity.AAGUIDMetadata, len(blob.Entries))
	for _, e := range blob.Entries {
		key, ok := aaguidKey(e.AAGUID)
		if !ok {
			continue // U2F entries key on cert-id, not AAGUID — out of scope here
		}
		var roots []*x509.Certificate
		for _, b64 := range e.MetadataStatement.AttestationRootCertificates {
			der, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
			if derr != nil {
				continue
			}
			if cert, perr := x509.ParseCertificate(der); perr == nil {
				roots = append(roots, cert)
			}
		}
		meta := identity.AAGUIDMetadata{
			Roots:                    roots,
			AuthenticatorDescription: e.MetadataStatement.Description,
		}
		for _, sr := range e.StatusReports {
			if disqualifyingStatuses[sr.Status] {
				meta.Revoked = true
			}
			if lvl := certLevelFromStatus(sr.Status); lvl != "" {
				meta.CertificationLevel = lvl
			}
		}
		index[key] = meta
	}
	if blob.NextUpdate != "" {
		if t, perr := time.Parse("2006-01-02", blob.NextUpdate); perr == nil {
			nextUpdate = t
		}
	}
	return index, nextUpdate, blob.No, nil
}

// aaguidKey normalises a hyphenated UUID AAGUID to the lowercase-hex key used by
// identity.AAGUIDHex (hex of the 16 raw bytes).
func aaguidKey(uuid string) (string, bool) {
	h := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(uuid), "-", ""))
	if len(h) != 32 {
		return "", false
	}
	if _, err := hex.DecodeString(h); err != nil {
		return "", false
	}
	return h, true
}

// certLevelFromStatus maps a FIDO_CERTIFIED[_Ln[plus]] status to "Ln" ("L1" for
// the bare FIDO_CERTIFIED). Non-certification statuses return "".
func certLevelFromStatus(status string) string {
	if !strings.HasPrefix(status, "FIDO_CERTIFIED") {
		return ""
	}
	rest := strings.TrimPrefix(status, "FIDO_CERTIFIED")
	if rest == "" {
		return "L1"
	}
	rest = strings.TrimPrefix(rest, "_") // "L2", "L1plus", ...
	if strings.HasPrefix(rest, "L") {
		// keep the leading "L<digit>"; drop a "plus" suffix for ranking.
		lvl := strings.TrimSuffix(rest, "plus")
		return lvl
	}
	return "L1"
}

// HTTPFetcher fetches the BLOB over HTTPS (the production fetcher).
type HTTPFetcher struct {
	URL    string
	Client *http.Client
}

func (f HTTPFetcher) Fetch(ctx context.Context) ([]byte, error) {
	if f.URL == "" {
		return nil, errors.New("fidomds: empty blob URL")
	}
	client := f.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fidomds: blob HTTP %d", resp.StatusCode)
	}
	const maxBlob = 32 << 20 // 32 MiB ceiling
	return io.ReadAll(io.LimitReader(resp.Body, maxBlob))
}
