package pg

// mana_action_pricing_question_generate_migration_test.go
//
// Static guard for migration 0024 — the ADDITIVE per-question authoring mana
// pricing model for the unified authoring flow. The unified flow charges ONE
// per ACCEPTED AI-generated question; manual-authored questions are NOT charged.
//
//	question_authoring_generate        → B  = 10  (pure-text AI question)
//	question_authoring_generate_image  → 2B = 20  (AI question carrying any image;
//	                                                stem and/or answer both = 20)
//
// Why a SQL-content test (not a live-DB or stubbed-resolver test):
//   - The deliverable IS the migration. Migrations auto-apply at deploy; they
//     are NOT applied from these tests, and the shared Cloud SQL is routinely
//     cost-paused — so a live-DB assertion is not reliably runnable here. The
//     existing stubbed adapter unit tests (mana_price_plan_repository_test.go)
//     prove the resolution PLUMBING with canned rows; they cannot prove the
//     migration registers 10 / 20.
//   - This test pins the billing-sensitive invariants of the migration text:
//     the two prices (B=10, 2B=20), the 2×B relationship, the refundable /
//     per_item / meter_home flags mirrored from the question_authoring_*
//     siblings, and — critically — that the migration is purely ADDITIVE (no
//     UPDATE/DELETE/ALTER in the up; no mention of any existing action_code).
//   - End-to-end resolution (ManaPricePlanStore resolves these codes to 10/20
//     against a live chora_identity) is covered by the `integration` build-tag
//     suite when a DB is present.
//
// ADR-178 configurable price-plan layer (tenant > plan-default > flat catalogue).

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const (
	qGenCode      = "question_authoring_generate"
	qGenImageCode = "question_authoring_generate_image"
	qGenBaseB     = 10 // base price B — a pure-text AI-generated question
	qGenImage2B   = 20 // 2×B — an AI-generated question carrying any image
)

// qGenUpFile / qGenDownFile are the expected migration filenames. NEXT free
// number after the highest existing (0023). RED until both exist.
const (
	qGenUpFile   = "0024_mana_action_pricing_question_generate.up.sql"
	qGenDownFile = "0024_mana_action_pricing_question_generate.down.sql"
)

// qGenExistingSiblings are the question_authoring_* codes that already exist
// (migrations 0009/0017/0023). The additive 0024 migration MUST NOT mention,
// re-price, or otherwise touch any of them.
var qGenExistingSiblings = []string{
	"question_authoring_model_answer",
	"question_authoring_ai_draft",
	"question_authoring_batch_parse",
	"question_authoring_batch_per_item",
	"question_authoring_image_regen",
}

// migrationsDir walks up from the test CWD (the package dir) to the
// chora-identity migrations directory, anchored on a known migration file.
func migrationsDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 8; i++ {
		cand := filepath.Join(dir, "migrations")
		if _, err := os.Stat(filepath.Join(cand, "0017_mana_price_plan_rules_layer.up.sql")); err == nil {
			return cand
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not locate chora-identity migrations dir starting from CWD")
	return ""
}

func readMigrationFile(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join(migrationsDir(t), name)
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read migration %s: %v (RED until migration 0024 exists)", name, err)
	}
	return string(data)
}

// stripSQLComments removes `-- ...` line comments so keyword scans (UPDATE /
// DELETE / sibling codes) inspect executable SQL only, not the header prose.
// (The 0024 migration keeps `--` out of every string literal.)
func stripSQLComments(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		if idx := strings.Index(line, "--"); idx >= 0 {
			line = line[:idx]
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

// insertRegion returns the text of the first `INSERT INTO <table> ... ;`
// statement (the 0024 migration has exactly one INSERT per table).
func insertRegion(t *testing.T, sql, table string) string {
	t.Helper()
	marker := "INSERT INTO " + table
	i := strings.Index(sql, marker)
	if i < 0 {
		t.Fatalf("migration 0024 up: no %q statement found", marker)
	}
	rest := sql[i:]
	if j := strings.Index(rest, ";"); j >= 0 {
		return rest[:j]
	}
	return rest
}

// priceFor extracts a single integer price for code from region using pattern
// (one capture group). Fails loud on no match / non-numeric.
func priceFor(t *testing.T, region, code, pattern, label string) int {
	t.Helper()
	re := regexp.MustCompile(strings.Replace(pattern, "CODE", regexp.QuoteMeta(code), 1))
	m := re.FindStringSubmatch(region)
	if m == nil {
		t.Fatalf("%s: no price found for %q (pattern %q) in:\n%s", label, code, pattern, strings.TrimSpace(region))
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("%s: non-numeric price %q for %q: %v", label, m[1], code, err)
	}
	return n
}

// TestMigration0024_QuestionGeneratePricing is the RED→GREEN guard for the
// additive per-accepted-question pricing migration.
func TestMigration0024_QuestionGeneratePricing(t *testing.T) {
	up := readMigrationFile(t, qGenUpFile)
	upX := stripSQLComments(up)

	// --- flat catalogue (mana_action_pricing): B=10, 2B=20 -------------------
	t.Run("catalogue_prices_B_and_2B", func(t *testing.T) {
		region := insertRegion(t, upX, "mana_action_pricing")
		// '<code>', <int>,   (exact closing quote ⇒ no _image prefix collision)
		text := priceFor(t, region, qGenCode, `'CODE'\s*,\s*(\d+)`, "catalogue text")
		img := priceFor(t, region, qGenImageCode, `'CODE'\s*,\s*(\d+)`, "catalogue image")
		if text != qGenBaseB {
			t.Errorf("catalogue %s = %d, want B=%d", qGenCode, text, qGenBaseB)
		}
		if img != qGenImage2B {
			t.Errorf("catalogue %s = %d, want 2B=%d", qGenImageCode, img, qGenImage2B)
		}
		if img != 2*text {
			t.Errorf("2×B invariant broken: image %d != 2×text %d", img, text)
		}
	})

	// --- action registry (mana_action_def): refundable + per_item + meter_home
	t.Run("action_def_flags_mirror_siblings", func(t *testing.T) {
		region := insertRegion(t, upX, "mana_action_def")
		for _, code := range []string{qGenCode, qGenImageCode} {
			re := regexp.MustCompile(`\(\s*'` + regexp.QuoteMeta(code) + `'\s*,([^)]*)\)`)
			m := re.FindStringSubmatch(region)
			if m == nil {
				t.Fatalf("mana_action_def: no row for %q in:\n%s", code, strings.TrimSpace(region))
			}
			row := m[1]
			if !strings.Contains(row, "'authoring'") {
				t.Errorf("%s: category not 'authoring' (row: %s)", code, row)
			}
			// refundable, per_item are columns 4 & 5 → TRUE, TRUE.
			if !regexp.MustCompile(`TRUE\s*,\s*TRUE`).MatchString(row) {
				t.Errorf("%s: refundable+per_item not both TRUE (row: %s)", code, row)
			}
			if !strings.Contains(row, "'creation'") {
				t.Errorf("%s: meter_home not 'creation' (row: %s)", code, row)
			}
		}
	})

	// --- platform-default price rule (mana_price_rule): 10 / 20 on default plan
	t.Run("platform_default_rule_prices", func(t *testing.T) {
		region := insertRegion(t, upX, "mana_price_rule")
		// Attaches to the platform 'default' active plan (like migration 0018).
		for _, must := range []string{"plan_code", "'default'", "'platform'", "'active'"} {
			if !strings.Contains(region, must) {
				t.Errorf("mana_price_rule region missing %q (must attach to the platform default plan)", must)
			}
		}
		text := priceFor(t, region, qGenCode, `'CODE'\s+AS\s+action_code\s*,\s*(\d+)\s+AS\s+mana_cost`, "rule text")
		img := priceFor(t, region, qGenImageCode, `'CODE'\s+AS\s+action_code\s*,\s*(\d+)\s+AS\s+mana_cost`, "rule image")
		if text != qGenBaseB || img != qGenImage2B {
			t.Errorf("rule prices = {%d,%d}, want {%d,%d}", text, img, qGenBaseB, qGenImage2B)
		}
	})

	// --- ADDITIVE-ONLY: no destructive DML, no mention of existing codes ------
	t.Run("up_is_additive_only", func(t *testing.T) {
		if re := regexp.MustCompile(`(?i)\b(update|delete|alter|drop|truncate)\b`); re.MatchString(upX) {
			t.Errorf("up migration contains destructive DML %q — must be INSERT-only (billing-sensitive: additive only)", re.FindString(upX))
		}
		for _, sib := range qGenExistingSiblings {
			if strings.Contains(upX, sib) {
				t.Errorf("up migration references existing sibling %q — must NOT touch existing codes", sib)
			}
		}
		// Each of the 3 inserts is idempotent.
		if n := strings.Count(upX, "DO NOTHING"); n < 3 {
			t.Errorf("up has %d `DO NOTHING` clauses, want >=3 (idempotent per-table insert)", n)
		}
	})

	// --- down reverses ONLY the two new codes, across all three tables --------
	t.Run("down_reverts_only_new_codes", func(t *testing.T) {
		down := stripSQLComments(readMigrationFile(t, qGenDownFile))
		for _, code := range []string{qGenCode, qGenImageCode} {
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
		for _, sib := range qGenExistingSiblings {
			if strings.Contains(down, sib) {
				t.Errorf("down migration references existing sibling %q — must remove ONLY the two new codes", sib)
			}
		}
	})
}
