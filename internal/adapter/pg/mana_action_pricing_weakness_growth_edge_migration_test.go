package pg

// mana_action_pricing_weakness_growth_edge_migration_test.go
//
// Static guard for migration 0028 — the ADDITIVE Growth-Edge (ADR-205) mana
// pricing model. The upload-driven PREMIUM weakness flow reserves mana on
// accept at the chora-consumption upload door (WS-4 / CHO-1956); the crew
// settles on success and refunds on any fail-loud node. Three new action codes,
// all consumption-metered + refundable (the crew owns the refund), tenant-
// overridable via the ADR-178 price-plan layer:
//
//	weakness_analysis        → 50  (one premium multimodal weakness analysis)
//	study_aid_generate       → 20  (advice / glossary / cheat-sheet output)
//	practice_test_generate   → 30  (a generated practice-test output)
//
// Why a SQL-content test (not a live-DB or stubbed-resolver test): identical
// rationale to the 0024 sibling (mana_action_pricing_question_generate_migration_test.go).
// The deliverable IS the migration; migrations auto-apply at deploy and are not
// applied from these tests, and the shared Cloud SQL is routinely cost-paused.
// End-to-end resolution against a live chora_identity is covered by the
// `integration` build-tag suite when a DB is present.
//
// ADR-178 configurable price-plan layer (tenant > plan-default > flat catalogue).

import (
	"regexp"
	"strings"
	"testing"
)

const (
	weakAnalysisCode = "weakness_analysis"
	studyAidCode     = "study_aid_generate"
	practiceTestCode = "practice_test_generate"

	weakAnalysisPrice = 50
	studyAidPrice     = 20
	practiceTestPrice = 30
)

// weakUpFile / weakDownFile are the expected migration filenames. NEXT free
// number after the highest existing (0027_familiar_exp_rules_layer). RED until
// both exist.
const (
	weakUpFile   = "0028_mana_action_pricing_weakness_growth_edge.up.sql"
	weakDownFile = "0028_mana_action_pricing_weakness_growth_edge.down.sql"
)

// weakNewCodes are the three codes the migration registers.
var weakNewCodes = []string{weakAnalysisCode, studyAidCode, practiceTestCode}

// weakExistingCodes are pre-existing action codes the additive 0028 migration
// MUST NOT mention, re-price, or otherwise touch.
var weakExistingCodes = []string{
	"daily_dose_coach",
	"question_generation",
	"question_authoring_generate",
	"familiar_chat_turn_premium",
	"atom_authoring_assist",
}

// TestMigration0028_WeaknessGrowthEdgePricing is the RED→GREEN guard for the
// additive Growth-Edge premium pricing migration.
func TestMigration0028_WeaknessGrowthEdgePricing(t *testing.T) {
	up := readMigrationFile(t, weakUpFile)
	upX := stripSQLComments(up)

	wantPrice := map[string]int{
		weakAnalysisCode: weakAnalysisPrice,
		studyAidCode:     studyAidPrice,
		practiceTestCode: practiceTestPrice,
	}

	// --- flat catalogue (mana_action_pricing) --------------------------------
	t.Run("catalogue_prices", func(t *testing.T) {
		region := insertRegion(t, upX, "mana_action_pricing")
		for _, code := range weakNewCodes {
			// '<code>', <int>,   (exact closing quote ⇒ no prefix collision)
			got := priceFor(t, region, code, `'CODE'\s*,\s*(\d+)`, "catalogue")
			if got != wantPrice[code] {
				t.Errorf("catalogue %s = %d, want %d", code, got, wantPrice[code])
			}
		}
	})

	// --- action registry (mana_action_def): consumption + refundable ---------
	t.Run("action_def_flags", func(t *testing.T) {
		region := insertRegion(t, upX, "mana_action_def")
		for _, code := range weakNewCodes {
			re := regexp.MustCompile(`\(\s*'` + regexp.QuoteMeta(code) + `'\s*,([^)]*)\)`)
			m := re.FindStringSubmatch(region)
			if m == nil {
				t.Fatalf("mana_action_def: no row for %q in:\n%s", code, strings.TrimSpace(region))
			}
			row := m[1]
			if !strings.Contains(row, "'consumption'") {
				t.Errorf("%s: category not 'consumption' (row: %s)", code, row)
			}
			// refundable is column 4 → TRUE (the crew refunds on every fail-loud node).
			if !regexp.MustCompile(`TRUE\s*,`).MatchString(row) {
				t.Errorf("%s: refundable not TRUE (row: %s)", code, row)
			}
			// meter_home 'consumption' — the upload door (chora-consumption) debits.
			if strings.Count(row, "'consumption'") < 2 {
				t.Errorf("%s: meter_home not 'consumption' (row: %s)", code, row)
			}
		}
	})

	// --- platform-default price rule (mana_price_rule): on the default plan ---
	t.Run("platform_default_rule_prices", func(t *testing.T) {
		region := insertRegion(t, upX, "mana_price_rule")
		for _, must := range []string{"plan_code", "'default'", "'platform'", "'active'"} {
			if !strings.Contains(region, must) {
				t.Errorf("mana_price_rule region missing %q (must attach to the platform default plan)", must)
			}
		}
		for _, code := range weakNewCodes {
			got := priceFor(t, region, code, `'CODE'\s+AS\s+action_code\s*,\s*(\d+)\s+AS\s+mana_cost`, "rule")
			if got != wantPrice[code] {
				t.Errorf("rule %s = %d, want %d", code, got, wantPrice[code])
			}
		}
	})

	// --- ADDITIVE-ONLY: no destructive DML, no mention of existing codes ------
	t.Run("up_is_additive_only", func(t *testing.T) {
		if re := regexp.MustCompile(`(?i)\b(update|delete|alter|drop|truncate)\b`); re.MatchString(upX) {
			t.Errorf("up migration contains destructive DML %q — must be INSERT-only (billing-sensitive: additive only)", re.FindString(upX))
		}
		for _, code := range weakExistingCodes {
			if strings.Contains(upX, code) {
				t.Errorf("up migration references existing code %q — must NOT touch existing codes", code)
			}
		}
		// Each of the 3 inserts (one per table) is idempotent.
		if n := strings.Count(upX, "DO NOTHING"); n < 3 {
			t.Errorf("up has %d `DO NOTHING` clauses, want >=3 (idempotent per-table insert)", n)
		}
	})

	// --- down reverses ONLY the three new codes, across all three tables ------
	t.Run("down_reverts_only_new_codes", func(t *testing.T) {
		down := stripSQLComments(readMigrationFile(t, weakDownFile))
		for _, code := range weakNewCodes {
			if !strings.Contains(down, code) {
				t.Errorf("down migration does not remove %q", code)
			}
		}
		for _, tbl := range []string{"mana_price_rule", "mana_action_def", "mana_action_pricing"} {
			if !strings.Contains(down, tbl) {
				t.Errorf("down migration does not clean table %q", tbl)
			}
		}
		// FK safety: price rules must be deleted before the action_def rows.
		if iRule, iDef := strings.Index(down, "mana_price_rule"), strings.Index(down, "mana_action_def"); iRule < 0 || iDef < 0 || iRule > iDef {
			t.Errorf("down must delete mana_price_rule BEFORE mana_action_def (FK order): rule@%d def@%d", iRule, iDef)
		}
		for _, code := range weakExistingCodes {
			if strings.Contains(down, code) {
				t.Errorf("down migration references existing code %q — must remove ONLY the three new codes", code)
			}
		}
	})
}
