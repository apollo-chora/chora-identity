package pg

// familiar_exp_rules_layer_migration_test.go
//
// Static guard for migration 0027 — the configurable familiar-EXP rules layer
// (ADR-201 §5 / WS4). Three new tables in chora_identity:
//
//	exp_source_def   — catalogue of verified EXP sources + default value/cap/tier
//	                   (global, NO RLS — like mana_action_def)
//	exp_rule_plan    — named, versioned, platform-or-tenant-scoped plans (RLS)
//	exp_rule         — the actual per-(plan, source) value/cap/eligibility (RLS)
//
// Why a SQL-content test (not a live-DB or stubbed-resolver test):
//   - The deliverable IS the migration. Migrations auto-apply at deploy; they
//     are NOT applied from these tests, and the shared Cloud SQL is routinely
//     cost-paused — so a live-DB assertion is not reliably runnable here. The
//     stubbed adapter unit tests (exp_rule_repository_test.go) prove the
//     resolution PLUMBING with canned rows; they cannot prove the migration
//     seeds the ADR-203 §12 catalogue defaults.
//   - This test pins the EXP-economy-sensitive invariants of the migration text:
//     the seed default values + tiers + caps (ADR-203 §12), the RLS posture
//     (ENABLE + FORCE on the two tenant-axis tables, NONE on the global
//     catalogue), the source-non-configurable invariant (exp_rule.source_code FK
//     to exp_source_def), idempotency, and behaviour-neutral rollout (NO plan
//     rows seeded — resolution falls to the catalogue default).
//
// ADR-201 configurable EXP-rule layer (tenant > plan > catalogue), mirroring
// ADR-178's PricePlanResolver.

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const (
	expUpFile   = "0027_familiar_exp_rules_layer.up.sql"
	expDownFile = "0027_familiar_exp_rules_layer.down.sql"
)

// expSeedRow is one expected exp_source_def catalogue default (ADR-203 §12).
type expSeedRow struct {
	code  string
	tier  string
	value int
	cap   int // 0 = uncapped
}

// expSeedRows is the full ADR-203 §12 EXP-gain list as seeded catalogue
// defaults. Values are single picks from the table's ranges; caps are the
// max-EXP-per-day ceiling (0 = uncapped). These are the economy-sensitive
// numbers the migration must register verbatim.
var expSeedRows = []expSeedRow{
	// S — goals / milestones (high EXP, uncapped)
	{"certification_issued", "S", 2000, 0},
	{"course_completed", "S", 1000, 0},
	{"path_completed", "S", 1000, 0},
	{"familiar_goal_achieved", "S", 500, 0},
	{"path_milestone", "S", 100, 0},
	// A — assessment
	{"assessment_passed", "A", 200, 0},
	{"first_attempt_mastery", "A", 100, 0},
	{"assessment_attempted", "A", 20, 60},
	// B — core loop
	{"concept_mastered", "B", 50, 0},
	{"weakness_recovered", "B", 100, 0},
	{"atom_correct", "B", 3, 30},
	{"atom_attempt", "B", 1, 20},
	{"daily_dose_completed", "B", 10, 10},
	{"on_time_review", "B", 2, 40},
	// C — discovery / KG
	{"kg_hexagon_expanded", "C", 4, 40},
	{"cluster_mastered", "C", 50, 0},
	// D — engagement (small, capped)
	{"streak_day", "D", 5, 5},
	{"streak_milestone", "D", 50, 0},
	{"chat_turn", "D", 1, 10},
	// E — social (capped)
	{"duel_won", "E", 30, 90},
	{"referral_converted", "E", 100, 0},
	{"post_shared", "E", 1, 5},
	// F — creation (capped)
	{"atom_authored", "F", 30, 150},
}

// TestMigration0027_FamiliarExpRulesLayer is the RED→GREEN guard for the
// configurable EXP-rule layer migration.
func TestMigration0027_FamiliarExpRulesLayer(t *testing.T) {
	up := readMigrationFile(t, expUpFile)
	upX := stripSQLComments(up)

	// --- three tables created, idempotently ----------------------------------
	t.Run("creates_three_tables_idempotent", func(t *testing.T) {
		for _, tbl := range []string{"exp_source_def", "exp_rule_plan", "exp_rule"} {
			re := regexp.MustCompile(`(?i)CREATE TABLE IF NOT EXISTS\s+` + tbl + `\b`)
			if !re.MatchString(upX) {
				t.Errorf("missing idempotent `CREATE TABLE IF NOT EXISTS %s`", tbl)
			}
		}
	})

	// --- source-non-configurable invariant (ADR-203 L16): exp_rule.source_code
	//     FK to exp_source_def, so no rule can exist for an unknown source ------
	t.Run("exp_rule_source_code_fk_to_catalogue", func(t *testing.T) {
		region := tableRegion(t, upX, "exp_rule")
		if !regexp.MustCompile(`(?is)source_code[^,]*REFERENCES\s+exp_source_def\s*\(\s*source_code\s*\)`).MatchString(region) {
			t.Errorf("exp_rule.source_code must REFERENCES exp_source_def(source_code) — the non-configurable-source invariant (ADR-203 L16)")
		}
		// plan_id FK to exp_rule_plan with ON DELETE CASCADE (rules die with plan).
		if !regexp.MustCompile(`(?is)plan_id[^,]*REFERENCES\s+exp_rule_plan\s*\(\s*plan_id\s*\)[^,]*ON DELETE CASCADE`).MatchString(region) {
			t.Errorf("exp_rule.plan_id must REFERENCES exp_rule_plan(plan_id) ON DELETE CASCADE")
		}
		// one rule per (plan, source).
		if !regexp.MustCompile(`(?is)UNIQUE[^;]*\(\s*plan_id\s*,\s*source_code\s*\)`).MatchString(upX) {
			t.Errorf("exp_rule must be UNIQUE(plan_id, source_code)")
		}
	})

	// --- RLS posture: ENABLE + FORCE on the two tenant-axis tables; the global
	//     catalogue (exp_source_def) carries NO RLS ----------------------------
	t.Run("rls_enable_force_on_tenant_axis_tables", func(t *testing.T) {
		for _, tbl := range []string{"exp_rule_plan", "exp_rule"} {
			if !regexp.MustCompile(`(?i)ALTER TABLE\s+` + tbl + `\s+ENABLE ROW LEVEL SECURITY`).MatchString(upX) {
				t.Errorf("%s: missing ENABLE ROW LEVEL SECURITY", tbl)
			}
			if !regexp.MustCompile(`(?i)ALTER TABLE\s+` + tbl + `\s+FORCE ROW LEVEL SECURITY`).MatchString(upX) {
				t.Errorf("%s: missing FORCE ROW LEVEL SECURITY", tbl)
			}
		}
		// exp_source_def is global config — must NOT enable RLS.
		if regexp.MustCompile(`(?i)ALTER TABLE\s+exp_source_def\s+ENABLE ROW LEVEL SECURITY`).MatchString(upX) {
			t.Errorf("exp_source_def must NOT enable RLS (global catalogue, like mana_action_def)")
		}
		// Policies are idempotent (DO $$ ... duplicate_object) like 0017.
		if n := strings.Count(upX, "duplicate_object"); n < 2 {
			t.Errorf("RLS policies must be idempotent (DO $$ ... EXCEPTION WHEN duplicate_object) — found %d, want >=2", n)
		}
	})

	// --- RLS policy shape: scope='platform' OR tenant_id = GUC (NULLIF-safe) OR
	//     admin role — mirrors 0017 plan_scope_isolation + the 0019 fix --------
	t.Run("rls_policy_scope_and_nullif_safe", func(t *testing.T) {
		if !strings.Contains(upX, "scope = 'platform'") {
			t.Errorf("plan RLS policy must allow scope='platform' (world-readable platform plan)")
		}
		if !regexp.MustCompile(`NULLIF\s*\(\s*current_setting\(\s*'chora\.tenant_id'\s*,\s*true\s*\)\s*,\s*''\s*\)::uuid`).MatchString(upX) {
			t.Errorf("tenant cast must be NULLIF-safe: NULLIF(current_setting('chora.tenant_id', true), '')::uuid (per migration 0019)")
		}
		if !strings.Contains(upX, "current_setting('chora.role', true) = 'admin'") {
			t.Errorf("plan RLS policy must include the admin-role read escape (like 0017)")
		}
		// The locked GUC is chora.tenant_id, NOT the generic app.current_tenant_id.
		if strings.Contains(upX, "app.current_tenant_id") {
			t.Errorf("must use the LOCKED chora.tenant_id GUC, not app.current_tenant_id")
		}
	})

	// --- exactly-one-active-plan unique indexes (mirror 0017) -----------------
	t.Run("active_plan_unique_indexes", func(t *testing.T) {
		if !regexp.MustCompile(`(?is)CREATE UNIQUE INDEX[^;]*ON exp_rule_plan[^;]*WHERE[^;]*status\s*=\s*'active'[^;]*scope\s*=\s*'platform'`).MatchString(upX) {
			t.Errorf("missing partial UNIQUE INDEX for exactly one ACTIVE platform plan (status='active' AND scope='platform')")
		}
		if !regexp.MustCompile(`(?is)CREATE UNIQUE INDEX[^;]*ON exp_rule_plan\s*\(\s*tenant_id\s*\)[^;]*WHERE[^;]*status\s*=\s*'active'`).MatchString(upX) {
			t.Errorf("missing partial UNIQUE INDEX for at most one ACTIVE tenant plan (on tenant_id WHERE status='active')")
		}
	})

	// --- seed catalogue defaults (ADR-203 §12) — value + cap + tier verbatim.
	//     Anchored on the tier literal (a single quoted letter that follows
	//     display_name), so digits/parens in display_name never confuse it. ----
	t.Run("seeds_adr203_catalogue_defaults", func(t *testing.T) {
		region := insertRegion(t, upX, "exp_source_def")
		for _, r := range expSeedRows {
			// '<code>', '<display>', '<tier>', <value>, <cap>, ...
			re := regexp.MustCompile(`'` + regexp.QuoteMeta(r.code) +
				`'\s*,\s*'[^']*'\s*,\s*'([SABCDEF])'\s*,\s*(\d+)\s*,\s*(\d+)`)
			m := re.FindStringSubmatch(region)
			if m == nil {
				t.Errorf("%s: no seed row matched (code, display, tier, value, cap) in exp_source_def INSERT", r.code)
				continue
			}
			if m[1] != r.tier {
				t.Errorf("%s: tier = %q, want %q (ADR-203 §12)", r.code, m[1], r.tier)
			}
			if v := mustAtoi(t, m[2]); v != r.value {
				t.Errorf("%s: default_exp_value = %d, want %d (ADR-203 §12)", r.code, v, r.value)
			}
			if c := mustAtoi(t, m[3]); c != r.cap {
				t.Errorf("%s: default_daily_cap = %d, want %d", r.code, c, r.cap)
			}
		}
	})

	// --- behaviour-neutral rollout: NO plan rows seeded (resolution falls to the
	//     catalogue default until an admin authors a plan) ---------------------
	t.Run("no_plan_rows_seeded_behaviour_neutral", func(t *testing.T) {
		if regexp.MustCompile(`(?i)INSERT INTO\s+exp_rule_plan`).MatchString(upX) {
			t.Errorf("migration must NOT seed exp_rule_plan rows (behaviour-neutral rollout — resolution falls to the catalogue default)")
		}
		if regexp.MustCompile(`(?i)INSERT INTO\s+exp_rule\b`).MatchString(upX) {
			t.Errorf("migration must NOT seed exp_rule rows (behaviour-neutral rollout)")
		}
		// The only seeded INSERT is exp_source_def, and it is idempotent.
		if !regexp.MustCompile(`(?is)INSERT INTO\s+exp_source_def[^;]*ON CONFLICT[^;]*DO NOTHING`).MatchString(upX) {
			t.Errorf("exp_source_def seed must be idempotent (ON CONFLICT ... DO NOTHING)")
		}
	})

	// --- no hand-written GRANTs (delegated to 9999_grant_app_roles.sql) -------
	t.Run("no_hand_written_grants", func(t *testing.T) {
		if regexp.MustCompile(`(?i)\bGRANT\b`).MatchString(upX) {
			t.Errorf("migration must NOT hand-write GRANTs — app_rw/app_ro privileges are delegated to 9999_grant_app_roles.sql (ALTER DEFAULT PRIVILEGES)")
		}
	})

	// --- down reverses ONLY the three new tables, child-first (FK order) ------
	t.Run("down_drops_three_tables_child_first", func(t *testing.T) {
		down := stripSQLComments(readMigrationFile(t, expDownFile))
		for _, tbl := range []string{"exp_rule", "exp_rule_plan", "exp_source_def"} {
			if !regexp.MustCompile(`(?i)DROP TABLE IF EXISTS\s+` + tbl + `\b`).MatchString(down) {
				t.Errorf("down migration must idempotently DROP TABLE IF EXISTS %s", tbl)
			}
		}
		// FK order: exp_rule (child) dropped before exp_rule_plan + exp_source_def.
		iRule := indexDropOf(down, "exp_rule")
		iPlan := indexDropOf(down, "exp_rule_plan")
		iDef := indexDropOf(down, "exp_source_def")
		if iRule < 0 || iPlan < 0 || iDef < 0 {
			t.Fatalf("down missing a DROP (rule@%d plan@%d def@%d)", iRule, iPlan, iDef)
		}
		if !(iRule < iPlan && iRule < iDef) {
			t.Errorf("down must DROP exp_rule (child) BEFORE exp_rule_plan + exp_source_def (FK order): rule@%d plan@%d def@%d", iRule, iPlan, iDef)
		}
	})
}

// tableRegion returns the body of a `CREATE TABLE IF NOT EXISTS <tbl> ( ... )`
// statement (balanced to the matching close-paren).
func tableRegion(t *testing.T, sql, tbl string) string {
	t.Helper()
	loc := regexp.MustCompile(`(?i)CREATE TABLE IF NOT EXISTS\s+` + tbl + `\s*\(`).FindStringIndex(sql)
	if loc == nil {
		t.Fatalf("no CREATE TABLE for %q", tbl)
	}
	rest := sql[loc[1]:]
	depth := 1
	for i, r := range rest {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return rest[:i]
			}
		}
	}
	t.Fatalf("unbalanced parens in CREATE TABLE %q", tbl)
	return ""
}

func mustAtoi(t *testing.T, s string) int {
	t.Helper()
	v, err := strconv.Atoi(s)
	if err != nil {
		t.Fatalf("non-numeric %q: %v", s, err)
	}
	return v
}

// indexDropOf returns the byte offset of the `DROP TABLE IF EXISTS <tbl>` for an
// exact table name (word-boundary), or -1.
func indexDropOf(sql, tbl string) int {
	loc := regexp.MustCompile(`(?i)DROP TABLE IF EXISTS\s+` + tbl + `\b`).FindStringIndex(sql)
	if loc == nil {
		return -1
	}
	return loc[0]
}
