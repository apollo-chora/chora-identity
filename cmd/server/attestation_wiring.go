package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
	"strings"
	"time"

	"github.com/apollo-chora/chora-identity/internal/adapter/fidomds"
	httpadapter "github.com/apollo-chora/chora-identity/internal/adapter/http"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// configureAttestation wires ADR-187 WebAuthn attestation verification onto the
// passkey handler from env (per feedback_no_inline_config). Default (unset /
// "off") is a no-op — registration behaviour is unchanged. When enabled it
// constructs the FIDO MDS trust store + policy and starts the background refresh.
//
// Env (A6 — all config-sourced, FIDO root bundle from Secret Manager via the
// deployment's env-from-secret):
//   - CHORA_ATTESTATION_MODE            off | record (default when enabled) | enforce
//   - CHORA_ATTESTATION_FAIL_MODE       fail_closed (default) | fail_open_record
//   - CHORA_ATTESTATION_ALLOWED_AAGUIDS comma/space list (enforce allow-list; empty = any verified)
//   - CHORA_ATTESTATION_MIN_CERT_LEVEL  e.g. L2 (enforce bar; empty = none)
//   - FIDO_MDS_BLOB_URL                 MDS3 BLOB endpoint
//   - FIDO_MDS_ROOT_BUNDLE_PEM          FIDO Alliance Root CA PEM bundle (Secret Manager)
//   - FIDO_MDS_REFRESH_INTERVAL         e.g. 24h (default)
func configureAttestation(ctx context.Context, h *httpadapter.PasskeyHandler) {
	mode := identity.ParseAttestationMode(os.Getenv("CHORA_ATTESTATION_MODE"))
	if mode == identity.AttestationModeOff {
		return
	}
	blobURL := strings.TrimSpace(os.Getenv("FIDO_MDS_BLOB_URL"))
	roots := attParsePEMRoots(os.Getenv("FIDO_MDS_ROOT_BUNDLE_PEM"))
	refresh := attEnvDuration("FIDO_MDS_REFRESH_INTERVAL", 24*time.Hour)

	store := fidomds.New(fidomds.Config{
		Fetcher:         fidomds.HTTPFetcher{URL: blobURL},
		RootBundle:      roots,
		RefreshInterval: refresh,
		Now:             time.Now,
	})
	if blobURL != "" && len(roots) > 0 {
		go store.Start(ctx, func(err error) { log.Printf("identity: FIDO MDS refresh: %v", err) })
	} else {
		// Enabled but not fully configured: the store stays cold → record
		// records unverified, enforce applies its fail-mode (A3). Loud, not silent.
		log.Printf("identity: CHORA_ATTESTATION_MODE=%s but FIDO MDS not fully configured (roots=%d, url_set=%v) — trust store stays cold",
			os.Getenv("CHORA_ATTESTATION_MODE"), len(roots), blobURL != "")
	}

	policy := identity.AttestationPolicy{
		Mode:                  mode,
		FailMode:              identity.ParseAttestationFailMode(os.Getenv("CHORA_ATTESTATION_FAIL_MODE")),
		AllowedAAGUIDs:        attParseAllowList(os.Getenv("CHORA_ATTESTATION_ALLOWED_AAGUIDS")),
		MinCertificationLevel: strings.TrimSpace(os.Getenv("CHORA_ATTESTATION_MIN_CERT_LEVEL")),
	}
	// NOTE: this wires a GLOBAL policy from env. Per-tenant `enforce` resolution
	// (tenant_entitlements.config_overrides, ADR-187 §D1) is a documented
	// follow-up; the safe global default is `record`.
	h.EnableAttestation(store, policy, time.Now)
	log.Printf("identity: WebAuthn attestation verification ENABLED (mode=%s, roots=%d, mds_url_set=%v)",
		os.Getenv("CHORA_ATTESTATION_MODE"), len(roots), blobURL != "")
}

// attParsePEMRoots parses a PEM bundle into CERTIFICATE blocks (ignores others).
func attParsePEMRoots(pemStr string) []*x509.Certificate {
	var out []*x509.Certificate
	rest := []byte(pemStr)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if c, err := x509.ParseCertificate(block.Bytes); err == nil {
			out = append(out, c)
		}
	}
	return out
}

// attParseAllowList normalises a comma/space-separated AAGUID list to the
// lowercase-hex (dashless) keys the policy compares against.
func attParseAllowList(s string) map[string]bool {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	out := map[string]bool{}
	for _, tok := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' }) {
		k := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(tok), "-", ""))
		if k != "" {
			out[k] = true
		}
	}
	return out
}

func attEnvDuration(key string, def time.Duration) time.Duration {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return def
}
