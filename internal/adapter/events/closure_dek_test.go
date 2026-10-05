// Tests for the closure subscriber's DEK shred terminal step (Tier 3 D11).
package events_test

import (
	"context"
	"errors"
	"testing"

	"github.com/apollo-chora/chora-identity/internal/adapter/events"
	"github.com/apollo-chora/chora-identity/internal/adapter/inmem"
	"github.com/apollo-chora/chora-identity/internal/domain/crypto"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

func TestClosureSubscriber_ShredsDEK(t *testing.T) {
	users := inmem.NewUserRepository()
	rec := events.NewRecorder()
	pub := events.NewEconomyPublisher(rec)
	km := crypto.NewInMemoryKeyManager([]byte("test-master-32-bytes-padding-12345"))

	gcid := "01935b5a-9bcf-7000-8000-0000000000aa"
	tenantID := "01935b5a-9bcf-7000-8000-000000000010"

	u, _ := identity.NewUser(identity.NewUserParams{
		Email: "phyllis@mightymind.sg", IdentityProvider: identity.ProviderOIDC,
		FederatedSubject: "google|phyllis-001",
	})
	u.Gcid = gcid
	_ = users.Save(context.Background(), u)

	// Issue DEK + encrypt a known PII payload.
	if _, err := km.IssueDEK(gcid); err != nil {
		t.Fatal(err)
	}
	ct, err := km.Encrypt(gcid, []byte("phyllis-NRIC-S1234567A"))
	if err != nil {
		t.Fatal(err)
	}

	sub := events.NewClosureSubscriberWithDEK(users, pub, km, nil)

	env := events.NewEnvelope(tenantID, gcid,
		"00-1234567890abcdef1234567890abcdef-1234567890abcdef-01", "")
	payload := events.PseudonymiseRequestedPayload{
		SagaID: "saga-1", Gcid: gcid, TenantID: tenantID,
	}
	if err := sub.Handle(context.Background(), env, payload); err != nil {
		t.Fatal(err)
	}

	// Confirm: the DEK is shredded — Decrypt of the original ciphertext fails
	// with ErrDEKShredded.
	_, err = km.Decrypt(gcid, ct)
	if !errors.Is(err, crypto.ErrDEKShredded) {
		t.Fatalf("expected ErrDEKShredded after closure; got %v", err)
	}
}

func TestClosureSubscriber_NoDEK_StillCompletes(t *testing.T) {
	// When DEK manager is absent (legacy wiring), the closure subscriber
	// completes the local saga without the shred step. Confirms backwards
	// compatibility for the NewClosureSubscriber (no-DEK) constructor.
	users := inmem.NewUserRepository()
	rec := events.NewRecorder()
	pub := events.NewEconomyPublisher(rec)

	gcid := "01935b5a-9bcf-7000-8000-0000000000bb"
	tenantID := "01935b5a-9bcf-7000-8000-000000000010"
	u, _ := identity.NewUser(identity.NewUserParams{
		Email: "x@y.com", IdentityProvider: identity.ProviderOIDC, FederatedSubject: "z",
	})
	u.Gcid = gcid
	_ = users.Save(context.Background(), u)

	sub := events.NewClosureSubscriber(users, pub, nil) // no DEK
	env := events.NewEnvelope(tenantID, gcid,
		"00-1234567890abcdef1234567890abcdef-1234567890abcdef-01", "")
	payload := events.PseudonymiseRequestedPayload{
		SagaID: "saga-2", Gcid: gcid, TenantID: tenantID,
	}
	if err := sub.Handle(context.Background(), env, payload); err != nil {
		t.Fatalf("closure should succeed without DEK: %v", err)
	}
}
