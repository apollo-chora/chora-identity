package pg

// familiar_exp_wave1_sources_migration_test.go
//
// Static guard for migration 0037 — the ADR-228 D4 Wave 1 / F-I3 (CHO-2090)
// familiar-EXP source seed: three NEW verified sources ("the power of a
// little bit") join the live vocabulary, resolver-priced through the ADR-201
// ExpRuleResolver with the values parity-pinned on the consumption side
// (internal/domain/growth/exp_rules_test.go identityParitySeed — ADR-218 D6
// parity contract; DO NOT edit one side alone):
//
//	weakness_grown     B  10 / 30  — chora.consumption.weakness.grown.v1
//	submission_graded  A  30 / 60  — chora.delivery.submission.graded.v1 (binary)
//	module_completed   B  15 / 45  — chora.delivery.module_progress.completed.v1
//
// Follows the 0030 seed idiom (not 0036's pure-additive): the INSERTs ride
// with the dedup-deprecation of the ADR-203 aspirational rows each live
// token supersedes, keeping ONE live registry row per real source:
//
//	weakness_recovered (B 100/0)  → weakness_grown
//	assessment_passed  (A 200/0)  → submission_graded
//
// (assessment_attempted stays — it describes the SUBMITTED moment, not the
// graded one, and is not superseded by a Wave-1 token.)
//
// INVARIANT (ADR-203 L16): every source is a Chora-verified system event
// with flat per-event pricing — this migration only registers / retires
// catalogue rows; it can never mint a self-declare source or a difficulty-
// scaled value.
//
// Why a SQL-content test (not live-DB): same rationale as the 0027/0030/0036
// guards — the deliverable IS the migration; the shared Cloud SQL is
// routinely cost-paused. Reuses the package migration-content helpers
// (readMigrationFile / stripSQLComments / insertRegion / mustAtoi /
// setBodyOf / expParityRow).

import (
	"regexp"
	"strings"
	"testing"
)

const (
	expWave1UpFile   = "0037_familiar_exp_wave1_sources.up.sql"
	expWave1DownFile = "0037_familiar_exp_wave1_sources.down.sql"
)

// expWave1Rows — the F-I3 Wave-1 vocabulary (tier, value, daily cap). Mirror
// of consumption's identityParitySeed Wave-1 block.
var expWave1Rows = []expParityRow{
	{"weakness_grown", "B", 10, 30, true},
	{"submission_graded", "A", 30, 60, true},
	{"module_completed", "B", 15, 45, true},
}

// expWave1DeprecatedCodes — the ADR-203 aspirational rows superseded by a
// Wave-1 live token (0030(c) idiom: deprecated, never deleted).
var expWave1DeprecatedCodes = []string{
	"weakness_recovered", // → weakness_grown
	"assessment_passed",  // → submission_graded
}

// TestMigration0037_FamiliarExpWave1Sources is the RED→GREEN guard for the
// ADR-228 D4 Wave-1 EXP seed.
func TestMigration0037_FamiliarExpWave1Sources(t *testing.T) {
	up := readMigrationFile(t, expWave1UpFile)
	upX := stripSQLComments(up)

	// --- 3 Wave-1 INSERT rows with EXACT tier/value/cap literals -----------
	t.Run("inserts_3_wave1_sources_verbatim", func(t *testing.T) {
		region := insertRegion(t, upX, "exp_source_def")
		for _, r := range expWave1Rows {
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

	// --- the 2 superseded aspirational rows deprecated, idempotently -------
	t.Run("deprecates_2_superseded_rows_idempotent", func(t *testing.T) {
		for _, code := range expWave1DeprecatedCodes {
			set, ok := setBodyOf(upX, code)
			if !ok {
				t.Errorf("%s: no deprecation UPDATE ... WHERE source_code='%s' found", code, code)
				continue
			}
			if !regexp.MustCompile(`deprecated_at\s*=\s*COALESCE\(\s*deprecated_at\s*,\s*now\(\)\s*\)`).MatchString(set) {
				t.Errorf("%s: deprecation must SET deprecated_at = COALESCE(deprecated_at, now()); SET body: %s", code, strings.TrimSpace(set))
			}
		}
	})

	// --- no value UPDATE of any pre-existing row; assessment_attempted +
	//     first_attempt_mastery stay untouched --------------------------------
	t.Run("leaves_non_superseded_rows_untouched", func(t *testing.T) {
		for _, keep := range []string{"assessment_attempted", "first_attempt_mastery", "atom_session", "campaign_node_won"} {
			if strings.Contains(upX, "'"+keep+"'") {
				t.Errorf("0037 must NOT touch %q — only the 3 inserts + the 2 superseded deprecations", keep)
			}
		}
	})

	// --- no hand-written GRANTs (delegated to 9999_grant_app_roles.sql) ----
	t.Run("no_hand_written_grants", func(t *testing.T) {
		if regexp.MustCompile(`(?im)^\s*GRANT\b`).MatchString(upX) {
			t.Errorf("migration must NOT hand-write GRANTs — delegated to 9999_grant_app_roles.sql")
		}
	})

	// --- down: delete exactly the 3 Wave-1 rows + un-deprecate the 2 -------
	t.Run("down_reverses_wave1_seed", func(t *testing.T) {
		down := stripSQLComments(readMigrationFile(t, expWave1DownFile))
		if !regexp.MustCompile(`(?is)DELETE FROM\s+exp_source_def`).MatchString(down) {
			t.Fatalf("down must DELETE the 3 seeded Wave-1 rows from exp_source_def")
		}
		for _, r := range expWave1Rows {
			if !strings.Contains(down, "'"+r.code+"'") {
				t.Errorf("down does not remove %q", r.code)
			}
		}
		for _, code := range expWave1DeprecatedCodes {
			set, ok := setBodyOf(down, code)
			if !ok {
				t.Errorf("down must UPDATE %q to clear deprecated_at", code)
				continue
			}
			if !regexp.MustCompile(`deprecated_at\s*=\s*NULL`).MatchString(set) {
				t.Errorf("down must clear deprecated_at = NULL for %q; SET body: %s", code, strings.TrimSpace(set))
			}
		}
		// Blast radius: the down must not delete any pre-0037 source.
		for _, keep := range []string{"atom_session", "campaign_goal_sealed", "assessment_attempted"} {
			if regexp.MustCompile(`(?is)DELETE FROM\s+exp_source_def[^;]*'` + keep + `'`).MatchString(down) {
				t.Errorf("down deletes pre-0037 source %q — blast radius too wide", keep)
			}
		}
	})
}
