// demo_mana_config_test.go — STARTUP GATE coverage for the demo mana grant
// allowlist (CHORA_DEMO_MANA_ALLOWED_GCIDS).
//
// The endpoint must never come up enabled with an unusable allowlist: a
// malformed entry or an empty list is a boot failure, not a warning. These
// specs drive the same demoManaConfigFromEnv helper main() calls, so the
// failure they assert is the failure that stops the process.
package main

import (
	"strings"
	"testing"
)

const (
	demoCfgGcidA = "01970000-0000-7000-8000-00000000da01"
	demoCfgGcidB = "01970000-0000-7000-8000-00000000da02"
)

// clearDemoManaEnv pins every demo-mana env var to empty so a spec sees only
// what it sets itself.
func clearDemoManaEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"CHORA_DEMO_MODE",
		"CHORA_DEMO_MANA_TOPUP_ENABLED",
		"CHORA_DEMO_MANA_ALLOWED_GCIDS",
		"CHORA_DEMO_MANA_GRANT_UNITS",
		"CHORA_DEMO_MANA_GRANT_MAX_PER_GCID",
		"CHORA_DEMO_MANA_GRANT_TOTAL_BUDGET",
	} {
		t.Setenv(k, "")
	}
}

func TestDemoManaConfigFromEnv_DefaultsWhenOff(t *testing.T) {
	clearDemoManaEnv(t)

	cfg, err := demoManaConfigFromEnv("local", false, false)
	if err != nil {
		t.Fatalf("err = %v, want nil — a disabled endpoint needs no allowlist", err)
	}
	if cfg.Enabled {
		t.Error("Enabled = true, want false by default")
	}
	if cfg.GrantUnits != 1_000_000 || cfg.MaxPerGcid != 10 || cfg.TotalBudgetUnits != 1_000_000_000 {
		t.Errorf("defaults = %d/%d/%d, want 1000000/10/1000000000",
			cfg.GrantUnits, cfg.MaxPerGcid, cfg.TotalBudgetUnits)
	}
	if len(cfg.AllowedGcids) != 0 {
		t.Errorf("AllowedGcids = %v, want empty", cfg.AllowedGcids)
	}
}

func TestDemoManaConfigFromEnv_EnabledWithoutAllowlist_FailsStartup(t *testing.T) {
	clearDemoManaEnv(t)

	cfg, err := demoManaConfigFromEnv("local", true, true)
	if err == nil {
		t.Fatalf("err = nil, want a startup failure — an enabled endpoint requires an allowlist (cfg=%+v)", cfg)
	}
	if !strings.Contains(err.Error(), "CHORA_DEMO_MANA_ALLOWED_GCIDS") {
		t.Errorf("err = %v, want it to name CHORA_DEMO_MANA_ALLOWED_GCIDS", err)
	}
}

func TestDemoManaConfigFromEnv_EnabledWithBlankAllowlist_FailsStartup(t *testing.T) {
	clearDemoManaEnv(t)
	t.Setenv("CHORA_DEMO_MANA_ALLOWED_GCIDS", " , ,, ")

	if _, err := demoManaConfigFromEnv("local", true, true); err == nil {
		t.Fatal("err = nil, want a startup failure — separators alone are not an allowlist")
	}
}

func TestDemoManaConfigFromEnv_MalformedGcid_FailsStartup(t *testing.T) {
	for _, bad := range []string{"not-a-uuid", demoCfgGcidA + ",oops", "12345"} {
		t.Run(bad, func(t *testing.T) {
			clearDemoManaEnv(t)
			t.Setenv("CHORA_DEMO_MANA_ALLOWED_GCIDS", bad)

			_, err := demoManaConfigFromEnv("local", true, true)
			if err == nil {
				t.Fatal("err = nil, want a startup failure on a malformed allowlist entry")
			}
			if !strings.Contains(err.Error(), "malformed") {
				t.Errorf("err = %v, want it to report the malformed entry", err)
			}
		})
	}
}

func TestDemoManaConfigFromEnv_MalformedGcid_DisabledDoesNotFail(t *testing.T) {
	// A stale allowlist value must not take down a deployment that does not
	// expose the endpoint at all.
	clearDemoManaEnv(t)
	t.Setenv("CHORA_DEMO_MANA_ALLOWED_GCIDS", "not-a-uuid")

	cfg, err := demoManaConfigFromEnv("local", false, false)
	if err != nil {
		t.Fatalf("err = %v, want nil while the endpoint is disabled", err)
	}
	if cfg.Enabled {
		t.Error("Enabled = true, want false")
	}
	if len(cfg.AllowedGcids) != 0 {
		t.Errorf("AllowedGcids = %v, want the unparseable entry dropped", cfg.AllowedGcids)
	}
}

func TestDemoManaConfigFromEnv_EnabledWithAllowlist_OK(t *testing.T) {
	clearDemoManaEnv(t)
	// Canonicalised: uppercase entry, extra whitespace, trailing comma.
	t.Setenv("CHORA_DEMO_MANA_ALLOWED_GCIDS",
		" "+strings.ToUpper(demoCfgGcidA)+" , "+demoCfgGcidB+", ")

	cfg, err := demoManaConfigFromEnv("local", true, true)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if !cfg.Enabled {
		t.Fatal("Enabled = false, want true")
	}
	if len(cfg.AllowedGcids) != 2 {
		t.Fatalf("AllowedGcids = %v, want 2 entries", cfg.AllowedGcids)
	}
	for _, want := range []string{demoCfgGcidA, demoCfgGcidB} {
		if _, ok := cfg.AllowedGcids[want]; !ok {
			t.Errorf("AllowedGcids = %v, want the canonical key %s", cfg.AllowedGcids, want)
		}
		if !cfg.AllowsGcid(want) {
			t.Errorf("AllowsGcid(%s) = false, want true", want)
		}
	}
}

func TestDemoManaConfigFromEnv_ProdNeverEnables(t *testing.T) {
	for _, env := range []string{"prod", "production", "PROD"} {
		t.Run(env, func(t *testing.T) {
			clearDemoManaEnv(t)
			t.Setenv("CHORA_DEMO_MANA_ALLOWED_GCIDS", demoCfgGcidA)

			cfg, err := demoManaConfigFromEnv(env, true, true)
			if err != nil {
				t.Fatalf("err = %v, want nil — prod must simply disable, not fail", err)
			}
			if cfg.Enabled {
				t.Errorf("Enabled = true in %s, want false — CHORA_ENV alone can never turn it on", env)
			}
		})
	}
}

func TestDemoManaConfigFromEnv_UnitsOverrides(t *testing.T) {
	clearDemoManaEnv(t)
	t.Setenv("CHORA_DEMO_MANA_ALLOWED_GCIDS", demoCfgGcidA)
	t.Setenv("CHORA_DEMO_MANA_GRANT_UNITS", "2000000")
	t.Setenv("CHORA_DEMO_MANA_GRANT_MAX_PER_GCID", "3")
	t.Setenv("CHORA_DEMO_MANA_GRANT_TOTAL_BUDGET", "5000000")

	cfg, err := demoManaConfigFromEnv("local", true, true)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if cfg.GrantUnits != 2_000_000 || cfg.MaxPerGcid != 3 || cfg.TotalBudgetUnits != 5_000_000 {
		t.Errorf("cfg = %d/%d/%d, want 2000000/3/5000000",
			cfg.GrantUnits, cfg.MaxPerGcid, cfg.TotalBudgetUnits)
	}
}
