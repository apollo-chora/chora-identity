package pg

// familiar_skill_action_pricing_migration_test.go
//
// Static guard for migration 0030 — the per-Skill mana action-code pricing seed
// (ADR-218 / ADR-219 Familiar Skill & Grimoire catalogue). Seeds the flat
// mana_action_pricing catalogue floor with 26 familiar_skill_* / familiar_ritual_run
// action codes (spec docs/FAMILIAR-SKILL-SPECS-2026-07-03.md §7). Each code is
// editor-tunable via the ADR-178 PricePlanResolver later; 0030 registers only the
// flat catalogue floor (same single-table shape as 0010's familiar-chat tiers).
//
// Why a SQL-content test: same rationale as the 0024 / 0028 mana guards — the
// deliverable IS the migration; migrations auto-apply at deploy and are NOT run
// from tests, and the shared Cloud SQL is routinely cost-paused. This test pins
// the billing-sensitive per-Skill costs of the migration text.
//
// Reuses the package migration-content helpers (readMigrationFile /
// stripSQLComments / insertRegion / priceFor) defined in the 0024 + 0027 guards.

import (
	"regexp"
	"strings"
	"testing"
)

const (
	skillPriceUpFile   = "0031_familiar_skill_action_pricing.up.sql"
	skillPriceDownFile = "0031_familiar_skill_action_pricing.down.sql"
)

// skillActionPrice is one (action_code, mana_cost) row.
type skillActionPrice struct {
	code string
	cost int
}

// skillActionPrices is the full ADR-218/219 §7 per-Skill pricing table — the
// billing-sensitive numbers 0030 must register verbatim into mana_action_pricing.
// 26 codes: 25 familiar_skill_* + familiar_ritual_run (base 20; actual Ritual runs
// charge the published_price_units composed at publish).
var skillActionPrices = []skillActionPrice{
	{"familiar_skill_explain_anew", 10},
	{"familiar_skill_quiz_me", 0},
	{"familiar_skill_quiz_me_gen", 25},
	{"familiar_skill_worked_example", 10},
	{"familiar_skill_socratic_drill", 15},
	{"familiar_skill_flashcard_forge", 25},
	{"familiar_skill_step_checker", 15},
	{"familiar_skill_polyglot", 10},
	{"familiar_skill_map_sight", 0},
	{"familiar_skill_weakness_sight", 15},
	{"familiar_skill_progress_mirror", 0},
	{"familiar_skill_recap_scribe", 5},
	{"familiar_skill_photo_sight", 60},
	{"familiar_skill_reminder_bell", 0},
	{"familiar_skill_path_weaver", 25},
	{"familiar_skill_fog_scout", 20},
	{"familiar_skill_goal_scribe", 10},
	{"familiar_skill_atom_forge", 200},
	{"familiar_skill_study_calendar", 0},
	{"familiar_skill_web_research", 80},
	{"familiar_skill_source_reader", 40},
	{"familiar_skill_fact_check", 40},
	{"familiar_skill_duel_second", 10},
	{"familiar_skill_dawn_briefing", 15},
	{"familiar_skill_watchful_eye", 10},
	{"familiar_ritual_run", 20},
}

// TestMigration0030_FamiliarSkillActionPricing is the RED→GREEN guard for the
// additive per-Skill pricing migration.
func TestMigration0030_FamiliarSkillActionPricing(t *testing.T) {
	up := readMigrationFile(t, skillPriceUpFile)
	upX := stripSQLComments(up)

	// --- all 26 skill prices seeded verbatim into mana_action_pricing -----------
	//     The exact closing quote in the pattern keeps 'familiar_skill_quiz_me'
	//     from matching inside 'familiar_skill_quiz_me_gen' (0024 collision note).
	t.Run("seeds_26_skill_prices_verbatim", func(t *testing.T) {
		region := insertRegion(t, upX, "mana_action_pricing")
		if len(skillActionPrices) != 26 {
			t.Fatalf("fixture drift: expected 26 skill codes, have %d", len(skillActionPrices))
		}
		for _, r := range skillActionPrices {
			got := priceFor(t, region, r.code, `'CODE'\s*,\s*(\d+)`, "skill catalogue")
			if got != r.cost {
				t.Errorf("%s: mana_cost = %d, want %d (ADR-218/219 §7)", r.code, got, r.cost)
			}
		}
	})

	// --- purely additive + idempotent (single INSERT, ON CONFLICT DO NOTHING) ----
	t.Run("up_is_additive_and_idempotent", func(t *testing.T) {
		if re := regexp.MustCompile(`(?i)\b(update|delete|alter|drop|truncate)\b`); re.MatchString(upX) {
			t.Errorf("up contains destructive DML %q — must be INSERT-only (billing-sensitive: additive only)", re.FindString(upX))
		}
		if !regexp.MustCompile(`(?is)INSERT INTO\s+mana_action_pricing[^;]*ON CONFLICT\s*\(\s*action_code\s*,\s*effective_from\s*\)\s*DO NOTHING`).MatchString(upX) {
			t.Errorf("mana_action_pricing INSERT must be idempotent: ON CONFLICT (action_code, effective_from) DO NOTHING (per 0010)")
		}
	})

	// --- no hand-written GRANTs (delegated to 9999_grant_app_roles.sql) ----------
	t.Run("no_hand_written_grants", func(t *testing.T) {
		if regexp.MustCompile(`(?i)\bGRANT\b`).MatchString(upX) {
			t.Errorf("migration must NOT hand-write GRANTs — delegated to 9999_grant_app_roles.sql")
		}
	})

	// --- down removes ONLY the 26 new codes -------------------------------------
	t.Run("down_removes_only_the_26_codes", func(t *testing.T) {
		down := stripSQLComments(readMigrationFile(t, skillPriceDownFile))
		if !regexp.MustCompile(`(?is)DELETE FROM\s+mana_action_pricing`).MatchString(down) {
			t.Errorf("down must DELETE FROM mana_action_pricing")
		}
		for _, r := range skillActionPrices {
			if !strings.Contains(down, "'"+r.code+"'") {
				t.Errorf("down must remove %q", r.code)
			}
		}
	})
}
