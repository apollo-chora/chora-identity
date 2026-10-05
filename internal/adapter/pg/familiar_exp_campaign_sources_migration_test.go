package pg

// familiar_exp_campaign_sources_migration_test.go
//
// Static guard for migration 0036 — the ADR-227 D10 / WS-C5 (CHO-2084)
// campaign conquest EXP sources. The Familiar Campaign awards XP off four NEW
// verified sources (rung first-clear / reduced refresher re-clear / node won /
// goal sealed), resolver-priced through the ADR-201 ExpRuleResolver with the
// values parity-pinned on the consumption side
// (internal/domain/growth/exp_rules_test.go identityParitySeed — ADR-218 D6
// parity contract; DO NOT edit one side alone).
//
// The seal's additional ~1/week spacing (D10 "tier-S ~1/week") is a code
// semantic in consumption's campaign XP subscriber — exp_source_def carries
// daily caps only, so the catalogue row pins value 120 / daily cap 120
// (max one seal award per day) and the subscriber enforces the 7-day window.
//
// This migration is a pure additive seed: 4 INSERTs, no UPDATE, no
// deprecation — the L16 invariant holds (registers verified sources only;
// can never mint a self-declare source).
//
// Why a SQL-content test (not live-DB): same rationale as the 0027/0030
// guards — the deliverable IS the migration; the shared Cloud SQL is
// routinely cost-paused. Reuses the package migration-content helpers
// (readMigrationFile / stripSQLComments / insertRegion / mustAtoi).

import (
	"regexp"
	"strings"
	"testing"
)

const (
	expCampaignUpFile   = "0036_familiar_exp_campaign_sources.up.sql"
	expCampaignDownFile = "0036_familiar_exp_campaign_sources.down.sql"
)

// expCampaignRows — the WS-C5 campaign vocabulary (tier, value, daily cap).
// Mirror of consumption's identityParitySeed campaign block.
var expCampaignRows = []expParityRow{
	{"campaign_rung_cleared", "B", 8, 32, true},
	{"campaign_rung_refreshed", "C", 3, 12, true},
	{"campaign_node_won", "B", 25, 75, true},
	{"campaign_goal_sealed", "S", 120, 120, true},
}

// TestMigration0036_FamiliarExpCampaignSources is the RED→GREEN guard for
// the campaign conquest EXP seed.
func TestMigration0036_FamiliarExpCampaignSources(t *testing.T) {
	up := readMigrationFile(t, expCampaignUpFile)
	upX := stripSQLComments(up)

	// --- 4 campaign INSERT rows with EXACT tier/value/cap literals ---------
	t.Run("inserts_4_campaign_sources_verbatim", func(t *testing.T) {
		region := insertRegion(t, upX, "exp_source_def")
		for _, r := range expCampaignRows {
			re := regexp.MustCompile(`'` + regexp.QuoteMeta(r.code) +
				`'\s*,\s*'[^']*'\s*,\s*'([SABCDEF])'\s*,\s*(\d+)\s*,\s*(\d+)`)
			m := re.FindStringSubmatch(region)
			if m == nil {
				t.Errorf("%s: no INSERT row matched (code, display, tier, value, cap) in exp_source_def INSERT", r.code)
				continue
			}
			if m[1] != r.tier {
				t.Errorf("%s: tier = %q, want %q", r.code, m[1], r.tier)
			}
			if v := mustAtoi(t, m[2]); v != r.value {
				t.Errorf("%s: default_exp_value = %d, want %d (parity — consumption identityParitySeed)", r.code, v, r.value)
			}
			if c := mustAtoi(t, m[3]); c != r.cap {
				t.Errorf("%s: default_daily_cap = %d, want %d (parity — consumption identityParitySeed)", r.code, c, r.cap)
			}
		}
	})

	// --- idempotent (ON CONFLICT (source_code) DO NOTHING) -----------------
	t.Run("insert_idempotent_on_conflict", func(t *testing.T) {
		if !regexp.MustCompile(`(?is)INSERT INTO\s+exp_source_def[^;]*ON CONFLICT\s*\(\s*source_code\s*\)\s*DO NOTHING`).MatchString(upX) {
			t.Errorf("exp_source_def INSERT must be idempotent: ON CONFLICT (source_code) DO NOTHING")
		}
	})

	// --- purely additive: no UPDATE, no deprecation of existing rows -------
	t.Run("purely_additive_no_update_no_deprecation", func(t *testing.T) {
		if regexp.MustCompile(`(?is)UPDATE\s+exp_source_def`).MatchString(upX) {
			t.Errorf("0036 must not UPDATE existing exp_source_def rows (pure additive campaign seed)")
		}
		if strings.Contains(strings.ToLower(upX), "deprecated_at") {
			t.Errorf("0036 must not touch deprecated_at (no supersessions in the campaign seed)")
		}
	})

	// --- down reverts exactly the 4 campaign rows --------------------------
	t.Run("down_deletes_exactly_the_campaign_rows", func(t *testing.T) {
		down := stripSQLComments(readMigrationFile(t, expCampaignDownFile))
		if !regexp.MustCompile(`(?is)DELETE FROM\s+exp_source_def`).MatchString(down) {
			t.Fatalf("down must DELETE the seeded campaign rows from exp_source_def")
		}
		for _, r := range expCampaignRows {
			if !strings.Contains(down, "'"+r.code+"'") {
				t.Errorf("down does not remove %q", r.code)
			}
		}
		// Guard the blast radius: the down must not name any pre-0036 source.
		for _, keep := range []string{"atom_session", "hex_expand", "atom_authored", "admin_grant"} {
			if strings.Contains(down, "'"+keep+"'") {
				t.Errorf("down names pre-0036 source %q — blast radius too wide", keep)
			}
		}
	})
}
