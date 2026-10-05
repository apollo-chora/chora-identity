package pg

// familiar_exp_live_source_parity_migration_test.go
//
// Static guard for migration 0029 — the LIVE-source parity seed for the
// configurable familiar-EXP rules layer (ADR-218 D6). Migration 0027 seeded the
// ADR-203 §12 *aspirational* EXP catalogue; chora-consumption's LIVE award path
// (internal/domain/growth/curve.go) awards EXP off a DIFFERENT, smaller source
// vocabulary with different values. ADR-218 D6 unifies the two: consumption will
// call identity's ExpRuleService.ResolveExpRule, and this migration parity-seeds
// exp_source_def with the LIVE vocabulary + values so resolution returns EXACTLY
// today's live behaviour (the in-code map remains only as the fail-loud fallback).
//
// This migration:
//   (a) INSERTs 10 NEW live-token source rows (ON CONFLICT (source_code) DO NOTHING).
//   (b) UPDATEs the shared atom_authored row from ADR-203's aspirational 30/150
//       to the LIVE 20/40 (idempotent — a SET to a fixed value).
//   (c) DEPRECATEs the 7 ADR-203 rows superseded by a live token (idempotent —
//       deprecated_at = COALESCE(deprecated_at, now())), leaving ONE live registry
//       row per real source. Deprecated rows resolve to ErrUnknownSource; nothing
//       feeds them today. The other 15 aspirational rows stay for future wiring.
//
// Why a SQL-content test (not a live-DB or stubbed-resolver test): same rationale
// as the 0027 guard — the deliverable IS the migration; migrations auto-apply at
// deploy and are NOT run from tests, and the shared Cloud SQL is routinely
// cost-paused. This test pins the EXP-economy-sensitive parity literals of the
// migration text.
//
// Reuses the package migration-content helpers (readMigrationFile /
// stripSQLComments / insertRegion / mustAtoi) defined in the 0024 + 0027 guards.

import (
	"regexp"
	"strings"
	"testing"
)

const (
	expParityUpFile   = "0030_familiar_exp_live_source_parity.up.sql"
	expParityDownFile = "0030_familiar_exp_live_source_parity.down.sql"
)

// expParityRow is one LIVE parity source (tier + value + daily cap), keyed by the
// canonical live-token source_code.
type expParityRow struct {
	code  string
	tier  string
	value int
	cap   int  // 0 = uncapped
	isNew bool // true = one of the 10 NEW INSERT rows; false = the atom_authored UPDATE
}

// expLiveParityRows is the LIVE EXP source vocabulary + values — a documented
// mirror of chora-consumption internal/domain/growth/curve.go — the parity
// contract of ADR-218 D6; consumption pins the same literals in its own parity
// test. If these two drift, resolution stops matching the live in-code fallback
// and the D6 unification is broken. Eleven live parity values: the 10 new inserts
// plus the shared atom_authored row updated in place to the live 20/40.
var expLiveParityRows = []expParityRow{
	// 10 NEW live-token INSERT rows (source_code, tier, value, daily_cap).
	{"atom_session", "B", 3, 30, true},
	{"ebbinghaus_review", "B", 5, 15, true},
	{"hex_expand", "C", 4, 12, true},
	{"conv_turn", "D", 2, 10, true},
	{"daily_dose_open", "B", 2, 2, true},
	{"social_share", "E", 8, 16, true},
	{"social_reaction", "E", 1, 10, true},
	{"junction_accepted", "C", 15, 15, true},
	{"admin_grant", "S", 0, 0, true},
	{"hatch_roll", "D", 0, 0, true},
	// the shared atom_authored row, UPDATEd in place from 30/150 → LIVE 20/40.
	{"atom_authored", "F", 20, 40, false},
}

// expDeprecatedCodes are the 7 ADR-203 §12 rows superseded by a live token — each
// deprecated (not deleted) so the catalogue keeps ONE live registry row per real
// source. The → live-token mapping is documented in the migration SQL comments.
var expDeprecatedCodes = []string{
	"atom_correct",         // → atom_session
	"atom_attempt",         // → atom_session (incorrect)
	"on_time_review",       // → ebbinghaus_review
	"chat_turn",            // → conv_turn
	"kg_hexagon_expanded",  // → hex_expand
	"daily_dose_completed", // → daily_dose_open
	"post_shared",          // → social_share
}

// expUntouchedAspirational is a sample of the 15 ADR-203 rows NOT superseded by a
// live token — 0029 must not insert, update, or deprecate any of them.
var expUntouchedAspirational = []string{
	"certification_issued", "course_completed", "assessment_passed",
	"cluster_mastered", "duel_won", "referral_converted", "streak_day",
}

// setBodyOf returns the SET-clause body of an `UPDATE exp_source_def SET ... WHERE
// source_code = '<code>'` statement in sql, confined to a single statement
// (`[^;]*?` cannot cross the terminating semicolon), or "" if none.
func setBodyOf(sql, code string) (string, bool) {
	re := regexp.MustCompile(`(?is)UPDATE\s+exp_source_def\s+SET\b([^;]*?)WHERE\s+source_code\s*=\s*'` + regexp.QuoteMeta(code) + `'`)
	m := re.FindStringSubmatch(sql)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// TestMigration0029_FamiliarExpLiveSourceParity is the RED→GREEN guard for the
// live-source parity seed.
func TestMigration0029_FamiliarExpLiveSourceParity(t *testing.T) {
	up := readMigrationFile(t, expParityUpFile)
	upX := stripSQLComments(up)

	// --- (a) 10 new live-token INSERT rows with EXACT tier/value/cap literals.
	//     Anchored on the tier literal (a single quoted letter after display_name),
	//     mirroring the 0027 seed guard. -------------------------------------------
	t.Run("inserts_10_live_tokens_verbatim", func(t *testing.T) {
		region := insertRegion(t, upX, "exp_source_def")
		for _, r := range expLiveParityRows {
			if !r.isNew {
				continue
			}
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
				t.Errorf("%s: default_exp_value = %d, want %d (LIVE parity — curve.go)", r.code, v, r.value)
			}
			if c := mustAtoi(t, m[3]); c != r.cap {
				t.Errorf("%s: default_daily_cap = %d, want %d (LIVE parity — curve.go)", r.code, c, r.cap)
			}
		}
	})

	// --- the INSERT is idempotent (ON CONFLICT (source_code) DO NOTHING) ---------
	t.Run("insert_idempotent_on_conflict", func(t *testing.T) {
		if !regexp.MustCompile(`(?is)INSERT INTO\s+exp_source_def[^;]*ON CONFLICT\s*\(\s*source_code\s*\)\s*DO NOTHING`).MatchString(upX) {
			t.Errorf("exp_source_def INSERT must be idempotent: ON CONFLICT (source_code) DO NOTHING")
		}
	})

	// --- (b) atom_authored UPDATE 30/150 → LIVE 20/40, idempotent + bumps updated_at.
	t.Run("updates_atom_authored_to_live_20_40", func(t *testing.T) {
		set, ok := setBodyOf(upX, "atom_authored")
		if !ok {
			t.Fatalf("no UPDATE exp_source_def ... WHERE source_code='atom_authored' found")
		}
		if !regexp.MustCompile(`default_exp_value\s*=\s*20\b`).MatchString(set) {
			t.Errorf("atom_authored update must SET default_exp_value = 20 (LIVE parity); SET body: %s", strings.TrimSpace(set))
		}
		if !regexp.MustCompile(`default_daily_cap\s*=\s*40\b`).MatchString(set) {
			t.Errorf("atom_authored update must SET default_daily_cap = 40 (LIVE parity); SET body: %s", strings.TrimSpace(set))
		}
		if !regexp.MustCompile(`updated_at\s*=\s*now\(\)`).MatchString(set) {
			t.Errorf("atom_authored update must bump updated_at = now(); SET body: %s", strings.TrimSpace(set))
		}
	})

	// --- (c) all 7 superseded ADR-203 rows deprecated, idempotently (COALESCE) ---
	t.Run("deprecates_7_superseded_rows_idempotent", func(t *testing.T) {
		for _, code := range expDeprecatedCodes {
			set, ok := setBodyOf(upX, code)
			if !ok {
				t.Errorf("%s: no deprecation UPDATE ... WHERE source_code='%s' found", code, code)
				continue
			}
			if !regexp.MustCompile(`deprecated_at\s*=\s*COALESCE\(\s*deprecated_at\s*,\s*now\(\)\s*\)`).MatchString(set) {
				t.Errorf("%s: deprecation must SET deprecated_at = COALESCE(deprecated_at, now()) (idempotent); SET body: %s", code, strings.TrimSpace(set))
			}
		}
	})

	// --- the other 15 aspirational rows are left untouched (not inserted / updated
	//     / deprecated by 0029) -----------------------------------------------------
	t.Run("leaves_other_aspirational_rows_untouched", func(t *testing.T) {
		for _, code := range expUntouchedAspirational {
			if strings.Contains(upX, "'"+code+"'") {
				t.Errorf("0029 must NOT touch the aspirational row %q — only the 7 live-superseded rows are deprecated", code)
			}
		}
	})

	// --- no hand-written GRANTs (delegated to 9999_grant_app_roles.sql). Anchored
	//     to a statement-leading GRANT (^\s*GRANT) rather than the bare word, since
	//     the admin_grant row's display label legitimately reads "Operator EXP
	//     grant" — a real GRANT DDL statement always starts a line here. ----------
	t.Run("no_hand_written_grants", func(t *testing.T) {
		if regexp.MustCompile(`(?im)^\s*GRANT\b`).MatchString(upX) {
			t.Errorf("migration must NOT hand-write GRANTs — delegated to 9999_grant_app_roles.sql")
		}
	})

	// --- down reverses the parity seed: delete the 10, restore atom_authored to
	//     30/150, clear deprecated_at on the 7 -------------------------------------
	t.Run("down_reverses_parity_seed", func(t *testing.T) {
		down := stripSQLComments(readMigrationFile(t, expParityDownFile))

		// (a) the 10 inserted codes are DELETEd from exp_source_def.
		if !regexp.MustCompile(`(?is)DELETE FROM\s+exp_source_def`).MatchString(down) {
			t.Errorf("down must DELETE the 10 inserted live-token rows from exp_source_def")
		}
		for _, r := range expLiveParityRows {
			if !r.isNew {
				continue
			}
			if !strings.Contains(down, "'"+r.code+"'") {
				t.Errorf("down must remove inserted code %q", r.code)
			}
		}
		// down must NOT delete atom_authored (only restore its values).
		if regexp.MustCompile(`(?is)DELETE FROM\s+exp_source_def[^;]*'atom_authored'`).MatchString(down) {
			t.Errorf("down must NOT delete atom_authored — it pre-dates 0029 and is only restored")
		}

		// (b) atom_authored restored to its ADR-203 30/150 default.
		set, ok := setBodyOf(down, "atom_authored")
		if !ok {
			t.Fatalf("down must UPDATE atom_authored back to its ADR-203 default")
		}
		if !regexp.MustCompile(`default_exp_value\s*=\s*30\b`).MatchString(set) ||
			!regexp.MustCompile(`default_daily_cap\s*=\s*150\b`).MatchString(set) {
			t.Errorf("down must restore atom_authored to 30/150; SET body: %s", strings.TrimSpace(set))
		}

		// (c) deprecated_at cleared for the 7 superseded rows.
		for _, code := range expDeprecatedCodes {
			set, ok := setBodyOf(down, code)
			if !ok {
				t.Errorf("down must UPDATE %q to clear deprecated_at", code)
				continue
			}
			if !regexp.MustCompile(`deprecated_at\s*=\s*NULL`).MatchString(set) {
				t.Errorf("down must clear deprecated_at = NULL for %q; SET body: %s", code, strings.TrimSpace(set))
			}
		}
	})
}
