// Coverage top-up for the in-memory User / Membership / Snapshot /
// Passkey repositories — exercises the error + helper branches the
// main spec files leave untested.
package inmem_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/apollo-chora/chora-identity/internal/adapter/inmem"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// -----------------------------------------------------------------------------
// User repository — FindByFederatedSubject + AllForTest helpers
// -----------------------------------------------------------------------------

func TestUserRepo_FindByFederatedSubject_Hit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r := inmem.NewUserRepository()
	u := mustNewUser(t, "find@chora.dev")
	_ = r.Save(ctx, u)

	got, ok := r.FindByFederatedSubject(u.FederatedSubject)
	if !ok {
		t.Fatal("FindByFederatedSubject should find the saved user")
	}
	if got.Gcid != u.Gcid {
		t.Errorf("Gcid = %q; want %q", got.Gcid, u.Gcid)
	}
}

func TestUserRepo_FindByFederatedSubject_Miss(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r := inmem.NewUserRepository()
	u := mustNewUser(t, "miss@chora.dev")
	_ = r.Save(ctx, u)

	if got, ok := r.FindByFederatedSubject("no-such-subject"); ok || got != nil {
		t.Errorf("expected (nil, false); got (%v, %v)", got, ok)
	}
}

func TestUserRepo_AllForTest_ReturnsCopies(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r := inmem.NewUserRepository()
	a := mustNewUser(t, "a@chora.dev")
	b := mustNewUser(t, "b@chora.dev")
	_ = r.Save(ctx, a)
	_ = r.Save(ctx, b)

	all := r.AllForTest()
	if len(all) != 2 {
		t.Fatalf("AllForTest len = %d; want 2", len(all))
	}
	// Mutating the returned slice must not corrupt the store.
	all[0].DisplayName = "mutated"
	got, _ := r.GetByGcid(ctx, all[0].Gcid)
	if got.DisplayName == "mutated" {
		t.Error("AllForTest returned a live reference, not a defensive copy")
	}
}

// -----------------------------------------------------------------------------
// Membership repository — GetByID + UpdateRole error branches
// -----------------------------------------------------------------------------

func TestMembershipRepo_GetByID_NotFound(t *testing.T) {
	t.Parallel()
	r := inmem.NewMembershipRepository()
	_, err := r.GetByID(context.Background(), "missing")
	if !errors.Is(err, identity.ErrMembershipNotFound) {
		t.Errorf("err = %v; want ErrMembershipNotFound", err)
	}
}

func TestMembershipRepo_UpdateRole_NotFound(t *testing.T) {
	t.Parallel()
	r := inmem.NewMembershipRepository()
	m, _ := identity.NewTenantMembership(identity.NewMembershipParams{
		Gcid: "01970000-0000-7000-9000-000000000001", TenantID: tenantA, Role: identity.RoleLearner,
	})
	err := r.UpdateRole(context.Background(), m)
	if !errors.Is(err, identity.ErrMembershipNotFound) {
		t.Errorf("err = %v; want ErrMembershipNotFound", err)
	}
}

// -----------------------------------------------------------------------------
// Snapshot repository — NextSequence with existing snapshots
// -----------------------------------------------------------------------------

func TestSnapshotRepo_NextSequence_WithExistingSnapshots(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r := inmem.NewSnapshotRepository()
	gcid := "01970000-0000-7000-9000-000000000001"
	other := "01970000-0000-7000-9000-000000000099"

	// Sequences 3 and 1 for the gcid; a higher one for a different gcid.
	for _, s := range []int{3, 1} {
		sn, _ := identity.NewPortableSnapshot(identity.NewPortableSnapshotParams{Gcid: gcid, Sequence: s, PayloadHash: "h"})
		_ = r.Append(ctx, sn)
	}
	otherSn, _ := identity.NewPortableSnapshot(identity.NewPortableSnapshotParams{Gcid: other, Sequence: 99, PayloadHash: "h"})
	_ = r.Append(ctx, otherSn)

	n, err := r.NextSequence(ctx, gcid)
	if err != nil {
		t.Fatalf("NextSequence: %v", err)
	}
	if n != 4 {
		t.Errorf("NextSequence = %d; want 4 (max 3 + 1, ignoring other gcid)", n)
	}
}

// -----------------------------------------------------------------------------
// PasskeyChallengeRepository — first-save-wins consumed guard
// -----------------------------------------------------------------------------

func TestPasskeyChallengeRepo_SaveRejectsConsumedReplacement(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r := inmem.NewPasskeyChallengeRepository()
	c, _ := identity.NewPasskeyChallenge(identity.NewPasskeyChallengeParams{
		ChallengeBytes: []byte("32-bytes-of-entropy-12345678901234"),
		RPID:           "chora.site",
		TTL:            5 * time.Minute,
	})
	// Persist the terminal (Consumed) state first, then attempt the
	// race-loser re-save — the stored entry must reject it.
	if err := c.MarkConsumed(); err != nil {
		t.Fatal(err)
	}
	if err := r.Save(ctx, c); err != nil {
		t.Fatalf("first Save (consumed): %v", err)
	}
	if err := r.Save(ctx, c); err == nil || !errors.Is(err, identity.ErrPasskeyChallengeConsumed) {
		t.Fatalf("second Save err = %v; want ErrPasskeyChallengeConsumed", err)
	}
}

// -----------------------------------------------------------------------------
// PasskeyCredentialRepository — empty ListByGcid
// -----------------------------------------------------------------------------

func TestPasskeyCredentialRepo_ListByGcid_Empty(t *testing.T) {
	t.Parallel()
	r := inmem.NewPasskeyCredentialRepository()
	got, err := r.ListByGcid(context.Background(), "no-credentials-gcid")
	if err != nil {
		t.Fatalf("ListByGcid: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("len = %d; want 0", len(got))
	}
}
