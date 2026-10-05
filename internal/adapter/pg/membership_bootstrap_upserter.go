// membership_bootstrap_upserter.go — pgx-backed implementation of
// events.TenantMembershipUpserter for the H+ Setup-Tenant Phase 2
// consumer (CHO-1630).
//
// SQL contract:
//
//	INSERT INTO tenant_memberships (gcid, tenant_id, role, status)
//	VALUES (...) ON CONFLICT (gcid, tenant_id, role) DO NOTHING
//
// At-least-once delivery from chora-tenancy's outbox means duplicate
// inserts are normal — the unique (gcid, tenant_id, role) index
// (migration 0020, multi-role mirror per ADR-182) makes re-delivery a
// no-op while allowing one row per role.
//
// RLS contract: tenant_memberships carries the tenant_isolation policy
// (`tenant_id = current_setting('chora.tenant_id', true)::uuid`,
// migration 0001_initial.sql). chora_identity_app_rw is NOBYPASSRLS in
// production, so the INSERT MUST run inside RunInTenantTx with
// SET LOCAL chora.tenant_id matching the row being written.
package pg

import (
	"context"
	"errors"
	"fmt"
)

// MembershipBootstrapUpserter satisfies
// events.TenantMembershipUpserter by writing the mirror
// tenant_memberships row inside a SET LOCAL chora.tenant_id transaction.
type MembershipBootstrapUpserter struct {
	q *PgxPoolQuerier
}

// NewMembershipBootstrapUpserter constructs the production-wired
// upserter. Panics on nil querier so wiring bugs fail loud at boot.
func NewMembershipBootstrapUpserter(q *PgxPoolQuerier) *MembershipBootstrapUpserter {
	if q == nil {
		panic("pg.NewMembershipBootstrapUpserter: nil PgxPoolQuerier")
	}
	return &MembershipBootstrapUpserter{q: q}
}

// UpsertMembershipOnBootstrap inserts the mirror tenant_memberships row
// for the bootstrap event. role MUST be a valid membership_role ENUM
// value (lowercase: learner / instructor / admin / auditor — per ADR-165
// OWNER is JWT-only and NOT a tenant_memberships value).
func (u *MembershipBootstrapUpserter) UpsertMembershipOnBootstrap(
	ctx context.Context, gcid, tenantID, role string,
) error {
	if gcid == "" {
		return errors.New("pg.UpsertMembershipOnBootstrap: empty gcid")
	}
	if tenantID == "" {
		return errors.New("pg.UpsertMembershipOnBootstrap: empty tenant_id")
	}
	if role == "" {
		return errors.New("pg.UpsertMembershipOnBootstrap: empty role")
	}

	return u.q.RunInTenantTx(ctx, tenantID, func(ctx context.Context, tx Tx) error {
		return bootstrapUpsertExec(ctx, tx, gcid, tenantID, role)
	})
}

// bootstrapUpsertExec is the Tx-seam body of the bootstrap mirror upsert —
// extracted so the 3-col conflict target is unit-assertable without a
// *PgxPoolQuerier. The conflict target MUST stay (gcid, tenant_id, role):
// migration 0020 drops the 2-col unique, so the old target 42P10-fails
// once 0020 applies (code + migration land in the same deploy).
func bootstrapUpsertExec(ctx context.Context, tx Tx, gcid, tenantID, role string) error {
	insert := `
            INSERT INTO tenant_memberships (gcid, tenant_id, role, status)
            VALUES ($1::uuid, $2::uuid, $3::membership_role, 'active'::membership_status)
            ON CONFLICT (gcid, tenant_id, role) DO NOTHING
        `
	if err := tx.Exec(ctx, insert, gcid, tenantID, role); err != nil {
		return fmt.Errorf("pg.UpsertMembershipOnBootstrap: insert: %w", err)
	}
	return nil
}
