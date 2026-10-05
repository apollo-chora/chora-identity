package inmem_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/apollo-chora/chora-identity/internal/adapter/inmem"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// -----------------------------------------------------------------------------
// PasskeyChallengeRepository
// -----------------------------------------------------------------------------

func TestPasskeyChallengeRepo_SaveAndGet(t *testing.T) {
	r := inmem.NewPasskeyChallengeRepository()
	ctx := context.Background()

	c, err := identity.NewPasskeyChallenge(identity.NewPasskeyChallengeParams{
		ChallengeBytes: []byte("32-bytes-of-entropy-12345678901234"),
		RPID:           "chora.site",
		UserHandle:     "phyllis@mightymind.sg",
		TTL:            5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Save(ctx, c); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err := r.GetByID(ctx, c.ChallengeID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ChallengeID != c.ChallengeID {
		t.Fatalf("challenge_id mismatch")
	}
	if !bytes.Equal(got.ChallengeBytes, c.ChallengeBytes) {
		t.Fatalf("challenge_bytes mismatch")
	}
	if got.Status != identity.PasskeyChallengeStatusPending {
		t.Fatalf("expected pending; got %v", got.Status)
	}
}

func TestPasskeyChallengeRepo_NotFound(t *testing.T) {
	r := inmem.NewPasskeyChallengeRepository()
	ctx := context.Background()
	_, err := r.GetByID(ctx, "non-existent-id")
	if !errors.Is(err, identity.ErrPasskeyChallengeNotFound) {
		t.Fatalf("expected ErrPasskeyChallengeNotFound; got %v", err)
	}
}

func TestPasskeyChallengeRepo_OverwriteByIDPersistsState(t *testing.T) {
	r := inmem.NewPasskeyChallengeRepository()
	ctx := context.Background()
	c, _ := identity.NewPasskeyChallenge(identity.NewPasskeyChallengeParams{
		ChallengeBytes: []byte("32-bytes-of-entropy-12345678901234"),
		RPID:           "chora.site",
		TTL:            time.Hour,
	})
	_ = r.Save(ctx, c)

	if err := c.MarkVerified("01935b5a-9bcf-7000-8000-000000000001"); err != nil {
		t.Fatal(err)
	}
	if err := r.Save(ctx, c); err != nil {
		t.Fatal(err)
	}
	got, _ := r.GetByID(ctx, c.ChallengeID)
	if got.Status != identity.PasskeyChallengeStatusVerified {
		t.Fatalf("expected status=verified after second save; got %v", got.Status)
	}
}

// -----------------------------------------------------------------------------
// PasskeyCredentialRepository
// -----------------------------------------------------------------------------

func TestPasskeyCredentialRepo_SaveAndGet(t *testing.T) {
	r := inmem.NewPasskeyCredentialRepository()
	ctx := context.Background()
	credID := []byte{0x01, 0x02, 0x03, 0x04}
	c, err := identity.NewPasskeyCredential(identity.NewPasskeyCredentialParams{
		Gcid:            "01935b5a-9bcf-7000-8000-000000000001",
		CredentialID:    credID,
		PublicKeyCOSE:   []byte("cose-key-bytes"),
		AttestationType: "none",
		RPID:            "chora.site",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Save(ctx, c); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := r.GetByCredentialID(ctx, credID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.CredentialUUID != c.CredentialUUID {
		t.Fatalf("credential_uuid mismatch")
	}
}

func TestPasskeyCredentialRepo_GetByCredentialID_NotFound(t *testing.T) {
	r := inmem.NewPasskeyCredentialRepository()
	_, err := r.GetByCredentialID(context.Background(), []byte("missing"))
	if !errors.Is(err, identity.ErrPasskeyCredentialNotFound) {
		t.Fatalf("expected ErrPasskeyCredentialNotFound; got %v", err)
	}
}

func TestPasskeyCredentialRepo_ListByGcid(t *testing.T) {
	r := inmem.NewPasskeyCredentialRepository()
	ctx := context.Background()
	gcid := "01935b5a-9bcf-7000-8000-000000000001"
	c1, _ := identity.NewPasskeyCredential(identity.NewPasskeyCredentialParams{
		Gcid:          gcid,
		CredentialID:  []byte("cred-1"),
		PublicKeyCOSE: []byte("k1"),
		RPID:          "chora.site",
	})
	c2, _ := identity.NewPasskeyCredential(identity.NewPasskeyCredentialParams{
		Gcid:          gcid,
		CredentialID:  []byte("cred-2"),
		PublicKeyCOSE: []byte("k2"),
		RPID:          "chora.site",
	})
	otherGcid := "01935b5a-9bcf-7000-8000-000000000002"
	c3, _ := identity.NewPasskeyCredential(identity.NewPasskeyCredentialParams{
		Gcid:          otherGcid,
		CredentialID:  []byte("cred-3"),
		PublicKeyCOSE: []byte("k3"),
		RPID:          "chora.site",
	})

	for _, c := range []*identity.PasskeyCredential{c1, c2, c3} {
		if err := r.Save(ctx, c); err != nil {
			t.Fatal(err)
		}
	}

	got, err := r.ListByGcid(ctx, gcid)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 credentials for gcid; got %d", len(got))
	}
}

func TestPasskeyCredentialRepo_SaveUpdatesSignCount(t *testing.T) {
	r := inmem.NewPasskeyCredentialRepository()
	ctx := context.Background()
	c, _ := identity.NewPasskeyCredential(identity.NewPasskeyCredentialParams{
		Gcid:          "01935b5a-9bcf-7000-8000-000000000001",
		CredentialID:  []byte("cred-1"),
		PublicKeyCOSE: []byte("k1"),
		RPID:          "chora.site",
	})
	_ = r.Save(ctx, c)

	if err := c.RecordUse(7); err != nil {
		t.Fatal(err)
	}
	if err := r.Save(ctx, c); err != nil {
		t.Fatal(err)
	}
	got, _ := r.GetByCredentialID(ctx, []byte("cred-1"))
	if got.SignCount != 7 {
		t.Fatalf("expected sign_count 7; got %d", got.SignCount)
	}
}
