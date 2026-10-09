// demo_mana_config.go — environment assembly for the demo mana grant
// (POST /api/v1/me/mana/demo-grant).
//
// Extracted from main() so the STARTUP GATE is testable. The endpoint is
// restricted to an explicit allowlist of demo GCIDs
// (CHORA_DEMO_MANA_ALLOWED_GCIDS); a configuration that would enable the
// endpoint without a usable allowlist must fail the boot rather than serve free
// mana to an unintended account.
package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/apollo-chora/chora-common/auth/chorasession"
	httpadapter "github.com/apollo-chora/chora-identity/internal/adapter/http"
)

// Chora session env vars. These are the SAME values chora-gateway mints and
// validates Chora session JWTs with — the demo grant reuses that validator
// rather than inventing a second session mechanism.
const (
	envDemoSessionSigner   = "CHORA_SESSION_SIGNER"
	envDemoSessionIssuer   = "CHORA_SESSION_ISSUER"
	envDemoSessionAudience = "CHORA_SESSION_AUDIENCE"
)

// demoManaConfigFromEnv assembles httpadapter.DemoManaConfig from the
// environment. demoModeOn / demoTopupOn are the two explicit enable flags; the
// endpoint is additionally refused outright when choraEnv is prod/production.
//
// Allowlist contract (CHORA_DEMO_MANA_ALLOWED_GCIDS — comma-separated GCIDs):
//   - entries are parsed into a set of CANONICAL (lowercase) UUID strings;
//   - when the endpoint ends up ENABLED, a malformed entry, an EMPTY entry (a
//     trailing comma or a blank slot between commas) or an empty allowlist
//     returns an error, which main() turns into a startup failure;
//   - when the endpoint is disabled the allowlist is still parsed but never
//     enforced, and bad entries are only reported — a stale value must not
//     take down a deployment that does not expose the endpoint at all.
func demoManaConfigFromEnv(choraEnv string, demoModeOn, demoTopupOn bool) (httpadapter.DemoManaConfig, error) {
	cfg := httpadapter.DemoManaConfig{
		GrantUnits:       1_000_000,
		MaxPerGcid:       10,
		TotalBudgetUnits: 1_000_000_000,
	}
	if v, err := strconv.ParseInt(strings.TrimSpace(os.Getenv("CHORA_DEMO_MANA_GRANT_UNITS")), 10, 64); err == nil && v > 0 {
		cfg.GrantUnits = v
	}
	if v, err := strconv.ParseInt(strings.TrimSpace(os.Getenv("CHORA_DEMO_MANA_GRANT_MAX_PER_GCID")), 10, 64); err == nil && v > 0 {
		cfg.MaxPerGcid = v
	}
	if v, err := strconv.ParseInt(strings.TrimSpace(os.Getenv("CHORA_DEMO_MANA_GRANT_TOTAL_BUDGET")), 10, 64); err == nil && v > 0 {
		cfg.TotalBudgetUnits = v
	}

	demoInProd := strings.EqualFold(choraEnv, "prod") || strings.EqualFold(choraEnv, "production")
	cfg.Enabled = demoModeOn && demoTopupOn && !demoInProd

	allowed, malformed, empty := httpadapter.ParseDemoManaAllowedGcids(os.Getenv("CHORA_DEMO_MANA_ALLOWED_GCIDS"))
	cfg.AllowedGcids = allowed

	if len(malformed) > 0 || len(empty) > 0 {
		if cfg.Enabled {
			return httpadapter.DemoManaConfig{}, fmt.Errorf(
				"CHORA_DEMO_MANA_ALLOWED_GCIDS has %d malformed entry(ies) %q and %d empty slot(s) — every entry must be a non-empty GCID (UUID)",
				len(malformed), malformed, len(empty))
		}
		log.Printf("identity: demo mana grant allowlist has %d malformed entry(ies) %q and %d empty slot(s) (endpoint disabled — not enforced)",
			len(malformed), malformed, len(empty))
	}
	if cfg.Enabled && len(allowed) == 0 {
		return httpadapter.DemoManaConfig{}, errors.New(
			"CHORA_DEMO_MANA_ALLOWED_GCIDS must list at least one GCID when the demo mana grant is enabled")
	}
	return cfg, nil
}

// demoSessionValidatorFromEnv builds the chorasession.Validator the demo grant
// authenticates callers with, from the same env vars chora-gateway mints and
// validates Chora session JWTs with.
//
// Returns (nil, nil) when the endpoint is disabled — the session boundary is
// then not enforced, so a missing or half-configured value is logged and
// ignored rather than taking down a deployment that does not expose the
// endpoint. An ENABLED endpoint with no validator is a startup error: it must
// never boot able to authenticate nobody, which is precisely the
// unauthenticated-identity defect the session boundary exists to close.
func demoSessionValidatorFromEnv(enabled bool) (*chorasession.Validator, error) {
	signer := strings.TrimSpace(os.Getenv(envDemoSessionSigner))
	issuer := strings.TrimSpace(os.Getenv(envDemoSessionIssuer))
	audience := strings.TrimSpace(os.Getenv(envDemoSessionAudience))

	if !enabled {
		set := 0
		for _, v := range []string{signer, issuer, audience} {
			if v != "" {
				set++
			}
		}
		if set > 0 && set < 3 {
			log.Printf("identity: demo mana grant disabled — ignoring partially configured session env (%s/%s/%s)",
				envDemoSessionSigner, envDemoSessionIssuer, envDemoSessionAudience)
		}
		return nil, nil
	}

	if signer == "" || issuer == "" || audience == "" {
		return nil, fmt.Errorf(
			"the demo mana grant is ENABLED but Chora session validation is not configured: %s, %s and %s must all be set",
			envDemoSessionSigner, envDemoSessionIssuer, envDemoSessionAudience)
	}
	v, err := chorasession.NewValidator([]byte(signer), issuer, audience)
	if err != nil {
		return nil, fmt.Errorf("build the demo grant session validator: %w", err)
	}
	return v, nil
}
