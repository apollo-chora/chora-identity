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

	httpadapter "github.com/apollo-chora/chora-identity/internal/adapter/http"
)

// demoManaConfigFromEnv assembles httpadapter.DemoManaConfig from the
// environment. demoModeOn / demoTopupOn are the two explicit enable flags; the
// endpoint is additionally refused outright when choraEnv is prod/production.
//
// Allowlist contract (CHORA_DEMO_MANA_ALLOWED_GCIDS — comma-separated GCIDs):
//   - entries are parsed into a set of CANONICAL (lowercase) UUID strings;
//   - when the endpoint ends up ENABLED, a malformed entry or an empty
//     allowlist returns an error, which main() turns into a startup failure;
//   - when the endpoint is disabled the allowlist is still parsed but never
//     enforced, and malformed entries are only reported — a stale value must
//     not take down a deployment that does not expose the endpoint at all.
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

	allowed, malformed := httpadapter.ParseDemoManaAllowedGcids(os.Getenv("CHORA_DEMO_MANA_ALLOWED_GCIDS"))
	cfg.AllowedGcids = allowed

	if len(malformed) > 0 {
		if cfg.Enabled {
			return httpadapter.DemoManaConfig{}, fmt.Errorf(
				"CHORA_DEMO_MANA_ALLOWED_GCIDS has %d malformed entry(ies) %q — every entry must be a GCID (UUID)",
				len(malformed), malformed)
		}
		log.Printf("identity: demo mana grant allowlist has %d malformed entry(ies) %q (endpoint disabled — not enforced)",
			len(malformed), malformed)
	}
	if cfg.Enabled && len(allowed) == 0 {
		return httpadapter.DemoManaConfig{}, errors.New(
			"CHORA_DEMO_MANA_ALLOWED_GCIDS must list at least one GCID when the demo mana grant is enabled")
	}
	return cfg, nil
}
