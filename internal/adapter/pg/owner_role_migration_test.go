package pg

// owner_role_migration_test.go: static guard for migration 0041, the one
// that makes ownership visible (UX refactor R21, first-launch spec 13.3.3
// option (a), work item S7-B3).
//
// Before 0041, chora_identity.membership_role held only
// (learner, instructor, admin, auditor, author), so the tenant-bootstrapped
// subscriber wrote the owner's mirror row as `admin` and every screen that
// reads the mirror rendered the owner as an ordinary admin. The JWT carried
// `owner` all along, because roles there come from chora_tenancy.members, so
// the platform knew who the owner was and no human could see it.
//
// Two things this migration must get right, and both differ from the
// 0020_author_role template it otherwise follows:
//
//  1. `OWNER` is ALREADY in role_catalog. Migration 0014 seeded it with
//     seeded_in='jwt_extension' and the note "JWT-stamped; not in PG ENUM".
//     An INSERT ... ON CONFLICT DO NOTHING would therefore do nothing and
//     leave the registry asserting something that has just stopped being
//     true. 0041 must UPDATE that row.
//  2. No UNIQUE-index change. 0020 needed one because AUTHOR made the mirror
//     multi-role; uq_tenant_memberships_gcid_tenant_role has covered
//     (gcid, tenant_id, role) ever since, and an owner row fits it as it is.
//
// Why a SQL-content test rather than a live-DB one: same rationale as the
// 0027/0030/0036/0037 guards. The deliverable IS the migration text, and the
// shared Cloud SQL is routinely cost-paused. The migration was additionally
// applied against the local Postgres 18 mirror during development; that run
// is evidence, this file is the regression fence.

import (
	"regexp"
	"strings"
	"testing"
)

const (
	ownerRoleUpFile   = "0041_owner_role.up.sql"
	ownerRoleDownFile = "0041_owner_role.down.sql"
)

func TestMigration0041_OwnerRole(t *testing.T) {
	up := readMigrationFile(t, ownerRoleUpFile)
	upX := stripSQLComments(up)

	t.Run("adds_owner_to_membership_role_enum_idempotently", func(t *testing.T) {
		// The 0020 template exactly: ADD VALUE IF NOT EXISTS, so a re-run on a
		// database that already has the value is a no-op rather than an error.
		re := regexp.MustCompile(`(?i)ALTER\s+TYPE\s+membership_role\s+ADD\s+VALUE\s+IF\s+NOT\s+EXISTS\s+'owner'`)
		if !re.MatchString(upX) {
			t.Errorf("0041.up must ALTER TYPE membership_role ADD VALUE IF NOT EXISTS 'owner'; got:\n%s", upX)
		}
	})

	t.Run("updates_the_existing_owner_role_catalog_row", func(t *testing.T) {
		// The row exists (0014). Only an UPDATE can correct it; an INSERT would
		// be swallowed by the ON CONFLICT and the note would stay wrong.
		if !regexp.MustCompile(`(?i)UPDATE\s+role_catalog`).MatchString(upX) {
			t.Errorf("0041.up must UPDATE the role_catalog OWNER row seeded by 0014; got:\n%s", upX)
		}
		if !strings.Contains(upX, "'OWNER'") {
			t.Errorf("0041.up must address the canonical_label 'OWNER'; got:\n%s", upX)
		}
		if !strings.Contains(upX, "0041_owner_role") {
			t.Errorf("0041.up must re-stamp seeded_in to 0041_owner_role so the registry says " +
				"where the ENUM value came from")
		}
		if strings.Contains(upX, "not in PG ENUM") {
			t.Errorf("0041.up must not carry forward the 0014 note 'not in PG ENUM'; that claim " +
				"stops being true in this very migration")
		}
	})

	t.Run("does_not_grant_ownership_to_anybody", func(t *testing.T) {
		// Widening the ENUM must not move a single membership row. Ownership is
		// written by tenant bootstrap and moved by the S7 handover; a migration
		// that quietly promoted an admin would be a privilege escalation
		// nobody reviewed.
		if regexp.MustCompile(`(?i)(INSERT\s+INTO|UPDATE)\s+tenant_memberships`).MatchString(upX) {
			t.Errorf("0041.up must not write tenant_memberships; it widens the vocabulary only:\n%s", upX)
		}
	})

	t.Run("touches_no_index_or_constraint", func(t *testing.T) {
		// 0020 changed the mirror's UNIQUE index because AUTHOR made it
		// multi-role. That is already done; 0041 needs nothing.
		for _, kw := range []string{"CREATE UNIQUE INDEX", "DROP CONSTRAINT", "ADD CONSTRAINT", "DROP INDEX"} {
			if strings.Contains(strings.ToUpper(upX), kw) {
				t.Errorf("0041.up must not touch indexes or constraints, found %q:\n%s", kw, upX)
			}
		}
	})

	down := readMigrationFile(t, ownerRoleDownFile)
	downX := stripSQLComments(down)

	t.Run("down_is_best_effort_and_never_deletes", func(t *testing.T) {
		// PostgreSQL cannot remove an ENUM value, and role_catalog is
		// append-only by design (the 0020/0035 down precedent): mark the row,
		// never DELETE it, so a historically issued token stays traceable.
		if regexp.MustCompile(`(?i)DELETE\s+FROM\s+role_catalog`).MatchString(downX) {
			t.Errorf("0041.down must not DELETE from the append-only role_catalog:\n%s", downX)
		}
		if !regexp.MustCompile(`(?i)UPDATE\s+role_catalog`).MatchString(downX) {
			t.Errorf("0041.down must mark the OWNER row as rolled back:\n%s", downX)
		}
		if !strings.Contains(downX, "ROLLED BACK") {
			t.Errorf("0041.down must stamp the 0020/0035 'ROLLED BACK' marker on the note:\n%s", downX)
		}
	})

	t.Run("down_does_not_strip_ownership", func(t *testing.T) {
		// The 0020 down could deactivate author rows because author is
		// re-grantable. Ownership is not: deactivating owner rows on a
		// rollback would leave tenants unowned with no way back, which is the
		// exact defect this whole package exists to close.
		if regexp.MustCompile(`(?i)(UPDATE|DELETE\s+FROM)\s+tenant_memberships`).MatchString(downX) {
			t.Errorf("0041.down must not touch tenant_memberships; a rollback that deactivated "+
				"owner rows would strip ownership with no way to grant it back:\n%s", downX)
		}
	})
}
