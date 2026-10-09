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
// what it sets itself. The session vars are included because they gate the
// same endpoint's authentication boundary.
func clearDemoManaEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"CHORA_DEMO_MODE",
		"CHORA_DEMO_MANA_TOPUP_ENABLED",
		"CHORA_DEMO_MANA_ALLOWED_GCIDS",
		"CHORA_DEMO_MANA_GRANT_UNITS",
		"CHORA_DEMO_MANA_GRANT_MAX_PER_GCID",
		"CHORA_DEMO_MANA_GRANT_TOTAL_BUDGET",
		"CHORA_SESSION_SIGNER",
		"CHORA_SESSION_ISSUER",
		"CHORA_SESSION_AUDIENCE",
	} {
		t.Setenv(k, "")
	}
}

// setSessionEnv pins the three Chora session vars the demo grant's
// authentication boundary is configured from.
func setSessionEnv(t *testing.T) {
	t.Helper()
	t.Setenv("CHORA_SESSION_SIGNER", "test-demo-session-signer-key-0123456789abcdef")
	t.Setenv("CHORA_SESSION_ISSUER", "https://auth.chora.dev")
	t.Setenv("CHORA_SESSION_AUDIENCE", "chora-identity")
}

// --- session validator boot gate ---------------------------------------------
//
// The demo grant is the one identity route that must not trust client-supplied
// identity headers, so it is the one that requires a validated Chora session
// JWT. An enabled endpoint with no session validator must fail the boot rather
// than come up able to authenticate nobody.

func TestDemoSessionValidatorFromEnv_NotConfiguredWhileDisabled(t *testing.T) {
	clearDemoManaEnv(t)

	v, err := demoSessionValidatorFromEnv(false)
	if err != nil {
		t.Fatalf("err = %v, want nil — a disabled endpoint needs no session validator", err)
	}
	if v != nil {
		t.Error("validator != nil, want nil while the endpoint is disabled")
	}
}

func TestDemoSessionValidatorFromEnv_EnabledWithoutSessionEnv_FailsStartup(t *testing.T) {
	clearDemoManaEnv(t)

	_, err := demoSessionValidatorFromEnv(true)
	if err == nil {
		t.Fatal("err = nil, want a startup failure — an enabled endpoint cannot authenticate callers without a session validator")
	}
	for _, want := range []string{"CHORA_SESSION_SIGNER", "CHORA_SESSION_ISSUER", "CHORA_SESSION_AUDIENCE"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to name %s", err, want)
		}
	}
}

func TestDemoSessionValidatorFromEnv_EnabledWithPartialSessionEnv_FailsStartup(t *testing.T) {
	// A half-configured session env is a misconfiguration, not a weaker one.
	clearDemoManaEnv(t)
	t.Setenv("CHORA_SESSION_SIGNER", "test-demo-session-signer-key-0123456789abcdef")

	if _, err := demoSessionValidatorFromEnv(true); err == nil {
		t.Fatal("err = nil, want a startup failure on a partially configured session env")
	}
}

func TestDemoSessionValidatorFromEnv_EnabledWithSessionEnv_Builds(t *testing.T) {
	clearDemoManaEnv(t)
	setSessionEnv(t)

	v, err := demoSessionValidatorFromEnv(true)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if v == nil {
		t.Fatal("validator == nil, want a built validator")
	}
}

func TestDemoSessionValidatorFromEnv_UndersizedSigner_FailsStartup(t *testing.T) {
	clearDemoManaEnv(t)
	t.Setenv("CHORA_SESSION_SIGNER", "too-short")
	t.Setenv("CHORA_SESSION_ISSUER", "https://auth.chora.dev")
	t.Setenv("CHORA_SESSION_AUDIENCE", "chora-identity")

	// chorasession.NewValidator enforces the RFC 7518 §3.2 32-byte HS256
	// minimum; an enabled demo grant must not boot with a weaker key.
	if _, err := demoSessionValidatorFromEnv(true); err == nil {
		t.Fatal("err = nil, want a startup failure on an undersized session signer")
	}
}

func TestDemoSessionValidatorFromEnv_PartialSessionEnvWhileDisabled_DoesNotFail(t *testing.T) {
	clearDemoManaEnv(t)
	t.Setenv("CHORA_SESSION_SIGNER", "test-demo-session-signer-key-0123456789abcdef")

	v, err := demoSessionValidatorFromEnv(false)
	if err != nil {
		t.Fatalf("err = %v, want nil while the endpoint is disabled", err)
	}
	if v != nil {
		t.Error("validator != nil, want nil while the endpoint is disabled")
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
	// Canonicalised: uppercase entry, extra whitespace, a blank slot BETWEEN
	// entries is still rejected — see the empty-slot spec below.
	t.Setenv("CHORA_DEMO_MANA_ALLOWED_GCIDS",
		" "+strings.ToUpper(demoCfgGcidA)+" , "+demoCfgGcidB)

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

func TestDemoManaConfigFromEnv_EnabledWithEmptySlot_FailsStartup(t *testing.T) {
	// A trailing comma (or any blank slot) is an allowlist the operator never
	// wrote. Silently skipping it is how "gcid-a, gcid-b," becomes a
	// two-account list, so an enabled endpoint must refuse to boot.
	for _, bad := range []string{
		demoCfgGcidA + ",",
		"," + demoCfgGcidA,
		demoCfgGcidA + ", ," + demoCfgGcidB,
		demoCfgGcidA + ",\t,",
	} {
		t.Run(bad, func(t *testing.T) {
			clearDemoManaEnv(t)
			t.Setenv("CHORA_DEMO_MANA_ALLOWED_GCIDS", bad)

			_, err := demoManaConfigFromEnv("local", true, true)
			if err == nil {
				t.Fatalf("err = nil, want a startup failure on the empty slot in %q", bad)
			}
			if !strings.Contains(err.Error(), "empty slot") {
				t.Errorf("err = %v, want it to report the empty slot", err)
			}
		})
	}
}

func TestDemoManaConfigFromEnv_EmptySlot_DisabledDoesNotFail(t *testing.T) {
	// A stale allowlist value must not take down a deployment that does not
	// expose the endpoint at all.
	clearDemoManaEnv(t)
	t.Setenv("CHORA_DEMO_MANA_ALLOWED_GCIDS", demoCfgGcidA+",")

	cfg, err := demoManaConfigFromEnv("local", false, false)
	if err != nil {
		t.Fatalf("err = %v, want nil while the endpoint is disabled", err)
	}
	if cfg.Enabled {
		t.Error("Enabled = true, want false")
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
