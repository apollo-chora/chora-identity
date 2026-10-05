// pending_invite_repository_test.go — WS3 / CHO-1873 (ADR-194 D2). Asserts the
// SQL shape + RLS-tx-wrapping invariants for the pending_invites store without
// a live DB (stub TxQuerier harness, shared with the other pg repo tests).
package pg

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

func mustInvite(t *testing.T) *identity.PendingInvite {
	t.Helper()
	pi, err := identity.NewPendingInvite(identity.NewPendingInviteParams{
		TenantID:      maTenant,
		Email:         "anika@mtm.sg",
		Roles:         []identity.Role{identity.RoleInstructor},
		InvitedByGcid: maGcid,
	})
	if err != nil {
		t.Fatalf("NewPendingInvite: %v", err)
	}
	return pi
}

func TestPendingInvite_Insert_insideTenantTx(t *testing.T) {
	tx := &stubTx{}
	q := &stubTxQuerier{tx: tx}
	repo := NewPendingInviteRepository(q)

	if err := repo.Insert(context.Background(), mustInvite(t)); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if q.callCount != 1 || q.gotTenantID != maTenant {
		t.Fatalf("RLS tx invariant: calls=%d tenant=%s", q.callCount, q.gotTenantID)
	}
	if len(tx.queries) != 1 {
		t.Fatalf("queries: got %d want 1", len(tx.queries))
	}
	for _, frag := range []string{"INSERT INTO pending_invites", "$4::text[]", "pending_invite_status"} {
		if !strings.Contains(tx.queries[0].SQL, frag) {
			t.Errorf("SQL missing %q:\n%s", frag, tx.queries[0].SQL)
		}
	}
}

func TestPendingInvite_Insert_uniqueViolationMapsExists(t *testing.T) {
	// pgx surfaces a unique violation with "SQLSTATE 23505" in the message.
	tx := &stubTx{execErr: errFakePG("ERROR: duplicate key (SQLSTATE 23505)")}
	repo := NewPendingInviteRepository(&stubTxQuerier{tx: tx})
	err := repo.Insert(context.Background(), mustInvite(t))
	if err != identity.ErrPendingInviteExists {
		t.Errorf("got %v want ErrPendingInviteExists", err)
	}
}

func TestPendingInvite_ListByTenant_scansPending(t *testing.T) {
	row := []any{
		"inv-1", "anika@mtm.sg", []string{"instructor"}, maGcid, "tok-1", "pending",
		time.Now(), nil, nil, time.Now(), time.Now(),
	}
	tx := &stubTx{rows: &stubRows{values: [][]any{row}}}
	q := &stubTxQuerier{tx: tx}
	repo := NewPendingInviteRepository(q)

	out, err := repo.ListByTenant(context.Background(), maTenant)
	if err != nil {
		t.Fatalf("ListByTenant: %v", err)
	}
	if q.gotTenantID != maTenant {
		t.Errorf("tenant: got %s want %s", q.gotTenantID, maTenant)
	}
	if len(out) != 1 || out[0].InviteID != "inv-1" || out[0].Status != identity.PendingInviteStatusPending {
		t.Fatalf("rows: got %+v", out)
	}
	if len(out[0].Roles) != 1 || out[0].Roles[0] != identity.RoleInstructor {
		t.Errorf("roles: got %v", out[0].Roles)
	}
	if !strings.Contains(tx.queries[0].SQL, "FROM pending_invites") ||
		!strings.Contains(tx.queries[0].SQL, "status = 'pending'") {
		t.Errorf("SQL:\n%s", tx.queries[0].SQL)
	}
}

func TestPendingInvite_Revoke(t *testing.T) {
	// happy: a row comes back → revoked.
	tx := &stubTx{queryRowFn: rowQueue(&stubMemberSearchRow{vals: []any{"inv-1"}})}
	repo := NewPendingInviteRepository(&stubTxQuerier{tx: tx})
	if err := repo.Revoke(context.Background(), maTenant, "inv-1"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if !strings.Contains(tx.queries[0].SQL, "status = 'revoked'") {
		t.Errorf("SQL must set revoked:\n%s", tx.queries[0].SQL)
	}
	// not-found maps to the domain sentinel.
	tx2 := &stubTx{queryRowFn: rowQueue(&stubMemberSearchRow{err: ErrNoRows})}
	if err := NewPendingInviteRepository(&stubTxQuerier{tx: tx2}).
		Revoke(context.Background(), maTenant, "ghost"); err != identity.ErrPendingInviteNotFound {
		t.Errorf("got %v want ErrPendingInviteNotFound", err)
	}
}

func TestPendingInvite_MatchByEmail_crossTenantViaDefiner(t *testing.T) {
	row := []any{"inv-1", maTenant, []string{"instructor"}, time.Now()}
	tx := &stubTx{rows: &stubRows{values: [][]any{row}}}
	q := &stubTxQuerier{tx: tx}
	repo := NewPendingInviteRepository(q)

	out, err := repo.MatchByEmail(context.Background(), "  Anika@MTM.sg ")
	if err != nil {
		t.Fatalf("MatchByEmail: %v", err)
	}
	// Runs under the placeholder scope (the SECURITY DEFINER func ignores it).
	if q.gotTenantID != crossTenantMatcherScope {
		t.Errorf("matcher scope: got %s want %s", q.gotTenantID, crossTenantMatcherScope)
	}
	if !strings.Contains(tx.queries[0].SQL, "match_pending_invites_by_email") {
		t.Errorf("SQL must call the matcher:\n%s", tx.queries[0].SQL)
	}
	// Email normalised before the lookup.
	if got, _ := tx.queries[0].Args[0].(string); got != "anika@mtm.sg" {
		t.Errorf("email arg: got %q want normalised", got)
	}
	if len(out) != 1 || out[0].TenantID != maTenant || len(out[0].Roles) != 1 {
		t.Fatalf("matches: got %+v", out)
	}
}

func TestPendingInvite_MarkAccepted_idempotent(t *testing.T) {
	// happy.
	tx := &stubTx{queryRowFn: rowQueue(&stubMemberSearchRow{vals: []any{"inv-1"}})}
	repo := NewPendingInviteRepository(&stubTxQuerier{tx: tx})
	if err := repo.MarkAccepted(context.Background(), maTenant, "inv-1", maGcid); err != nil {
		t.Fatalf("MarkAccepted: %v", err)
	}
	if !strings.Contains(tx.queries[0].SQL, "status = 'accepted'") {
		t.Errorf("SQL must set accepted:\n%s", tx.queries[0].SQL)
	}
	// no-longer-pending → idempotent nil (a resolve retry is safe).
	tx2 := &stubTx{queryRowFn: rowQueue(&stubMemberSearchRow{err: ErrNoRows})}
	if err := NewPendingInviteRepository(&stubTxQuerier{tx: tx2}).
		MarkAccepted(context.Background(), maTenant, "inv-1", maGcid); err != nil {
		t.Errorf("idempotent MarkAccepted: got %v want nil", err)
	}
}

// errFakePG is a minimal error whose message carries a SQLSTATE for the
// unique-violation mapping test.
type errFakePG string

func (e errFakePG) Error() string { return string(e) }
