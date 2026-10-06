// Tests for the gRPC service-side handlers.
package grpcadapter_test

import (
	"context"
	"testing"

	"github.com/apollo-chora/chora-identity/internal/adapter/events"
	grpcadapter "github.com/apollo-chora/chora-identity/internal/adapter/grpc"
	mana "github.com/apollo-chora/chora-identity/internal/domain/user_mana"
)

const gG = "01970000-0000-7000-8000-000000000010"

// tenantE is a canonical tenant UUID used for envelope emission checks.
const tenantE = "01970000-0000-7000-8000-00000000ee01"

// -----------------------------------------------------------------------------
// ManaServer
// -----------------------------------------------------------------------------

func newManaServer(t *testing.T) (*grpcadapter.ManaServer, *mana.InMemoryStore) {
	t.Helper()
	store := mana.NewInMemoryStore()
	q := mana.NewQuoter(store)
	return grpcadapter.NewManaServer(q, store, nil), store
}

func TestManaServer_CreditAndGetBalance(t *testing.T) {
	t.Parallel()
	srv, _ := newManaServer(t)
	ctx := context.Background()

	cr, err := srv.CreditMana(ctx, &grpcadapter.CreditManaRequest{
		Gcid: gG, Source: "subscription_grant", Units: 500,
		Reason: "subscription_grant", IdempotencyKey: "ck-1",
		SourceSubscriptionID: "sub-1",
	})
	if err != nil {
		t.Fatalf("CreditMana: %v", err)
	}
	if cr.BalanceAfterUnits != 500 {
		t.Errorf("balance=%d want 500", cr.BalanceAfterUnits)
	}

	bal, err := srv.GetBalance(ctx, &grpcadapter.GetBalanceRequest{Gcid: gG})
	if err != nil {
		t.Fatalf("GetBalance: %v", err)
	}
	if bal.BalanceUnits != 500 {
		t.Errorf("BalanceUnits=%d want 500", bal.BalanceUnits)
	}
}

func TestManaServer_DeductMana_Sufficient(t *testing.T) {
	t.Parallel()
	srv, _ := newManaServer(t)
	ctx := context.Background()

	_, _ = srv.CreditMana(ctx, &grpcadapter.CreditManaRequest{
		Gcid: gG, Source: "subscription_grant", Units: 500,
		Reason: "subscription_grant", IdempotencyKey: "ck-1",
	})
	res, err := srv.DeductMana(ctx, &grpcadapter.DeductManaRequest{
		Gcid: gG, ActionCode: "familiar_chat", Units: 100,
		IdempotencyKey: "dk-1",
	})
	if err != nil {
		t.Fatalf("DeductMana: %v", err)
	}
	if !res.Success {
		t.Errorf("expected success")
	}
	if res.BalanceAfterUnits != 400 {
		t.Errorf("BalanceAfterUnits=%d want 400", res.BalanceAfterUnits)
	}
}

func TestManaServer_DeductMana_Insufficient(t *testing.T) {
	t.Parallel()
	srv, _ := newManaServer(t)
	ctx := context.Background()

	_, _ = srv.CreditMana(ctx, &grpcadapter.CreditManaRequest{
		Gcid: gG, Source: "subscription_grant", Units: 50,
		Reason: "subscription_grant", IdempotencyKey: "ck",
	})
	res, err := srv.DeductMana(ctx, &grpcadapter.DeductManaRequest{
		Gcid: gG, ActionCode: "familiar_chat", Units: 1000,
		IdempotencyKey: "dk-2",
	})
	if err != nil {
		t.Fatalf("DeductMana: %v", err)
	}
	if res.Success {
		t.Errorf("expected !success on insufficient balance")
	}
	if res.RequiredUnits != 1000 {
		t.Errorf("RequiredUnits=%d", res.RequiredUnits)
	}
	if res.CurrentBalanceUnits != 50 {
		t.Errorf("CurrentBalanceUnits=%d", res.CurrentBalanceUnits)
	}
}

func TestManaServer_DeductMana_Idempotent(t *testing.T) {
	t.Parallel()
	srv, store := newManaServer(t)
	ctx := context.Background()
	_, _ = srv.CreditMana(ctx, &grpcadapter.CreditManaRequest{
		Gcid: gG, Source: "topup", Units: 500,
		Reason: "topup", IdempotencyKey: "ck",
	})

	for i := 0; i < 3; i++ {
		_, err := srv.DeductMana(ctx, &grpcadapter.DeductManaRequest{
			Gcid: gG, ActionCode: "x", Units: 100,
			IdempotencyKey: "dk-replay",
		})
		if err != nil {
			t.Fatalf("DeductMana #%d: %v", i, err)
		}
	}
	got, _ := store.GetMana(ctx, gG)
	if got.BalanceUnits != 400 {
		t.Errorf("replay caused multi-debit; balance=%d want 400", got.BalanceUnits)
	}
}

func TestManaServer_NilGuard(t *testing.T) {
	t.Parallel()
	var srv *grpcadapter.ManaServer
	if _, err := srv.DeductMana(context.Background(), &grpcadapter.DeductManaRequest{}); err == nil {
		t.Errorf("expected error for nil receiver")
	}
}

func TestManaServer_RejectsInvalidSource(t *testing.T) {
	t.Parallel()
	srv, _ := newManaServer(t)
	_, err := srv.CreditMana(context.Background(), &grpcadapter.CreditManaRequest{
		Gcid: gG, Source: "fakemoney", Units: 10,
		Reason: "promo", IdempotencyKey: "k",
	})
	if err == nil {
		t.Errorf("expected error for invalid source")
	}
}

// TestManaServer_DeductMana_EmitsDebitedEvent asserts the per-debit event
// emission branch (`!res.Replayed && s.publisher != nil`) fires a
// chora.identity.user_mana.debited.v1 envelope with the req tenant + gcid.
func TestManaServer_DeductMana_EmitsDebitedEvent(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	q := mana.NewQuoter(store)
	rec := events.NewRecorder()
	srv := grpcadapter.NewManaServer(q, store, events.NewEconomyPublisher(rec))
	ctx := context.Background()

	if _, err := srv.CreditMana(ctx, &grpcadapter.CreditManaRequest{
		Gcid: gG, Source: "topup", Units: 500,
		Reason: "topup", IdempotencyKey: "ck-emit", TenantID: tenantE,
	}); err != nil {
		t.Fatalf("seed credit: %v", err)
	}
	if _, err := srv.DeductMana(ctx, &grpcadapter.DeductManaRequest{
		Gcid: gG, ActionCode: "x", Units: 100,
		IdempotencyKey: "dk-emit", TenantID: tenantE,
	}); err != nil {
		t.Fatalf("DeductMana: %v", err)
	}
	got := rec.RecordedByTopic("chora.identity.user_mana.debited.v1")
	if len(got) != 1 {
		t.Fatalf("expected 1 debited.v1 emit, got %d", len(got))
	}
	if got[0].Envelope.GCID != gG || got[0].Envelope.TenantID != tenantE {
		t.Errorf("envelope gcid/tenant = %q/%q", got[0].Envelope.GCID, got[0].Envelope.TenantID)
	}
}

func TestManaServer_CreditMana_EmitsCreditedEvent(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	q := mana.NewQuoter(store)
	rec := events.NewRecorder()
	srv := grpcadapter.NewManaServer(q, store, events.NewEconomyPublisher(rec))
	ctx := context.Background()

	if _, err := srv.CreditMana(ctx, &grpcadapter.CreditManaRequest{
		Gcid: gG, Source: "topup", Units: 500,
		Reason: "topup", IdempotencyKey: "ck-emit2", TenantID: tenantE,
	}); err != nil {
		t.Fatalf("CreditMana: %v", err)
	}
	got := rec.RecordedByTopic("chora.identity.user_mana.credited.v1")
	if len(got) != 1 {
		t.Fatalf("expected 1 credited.v1 emit, got %d", len(got))
	}
}

// TestManaServer_DeductMana_NonInsufficientErrorPropagates drives the plain
// `return nil, err` branch via an unpriceable units==0 debit (the pricer
// error is NOT an InsufficientBalanceError, so it must surface raw).
func TestManaServer_DeductMana_NonInsufficientErrorPropagates(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	q := mana.NewQuoter(store, mana.WithPricer(staticPricer{prices: map[string]int64{"priced": 5}}))
	srv := grpcadapter.NewManaServer(q, store, nil)

	_, err := srv.DeductMana(context.Background(), &grpcadapter.DeductManaRequest{
		Gcid: gG, ActionCode: "not-in-catalogue", Units: 0, IdempotencyKey: "dk-u",
	})
	if err == nil || mana.IsInsufficientBalance(err) {
		t.Fatalf("expected a non-insufficient error, got %v", err)
	}
}

func TestManaServer_CreditMana_QuoterErrorPropagates(t *testing.T) {
	t.Parallel()
	srv, _ := newManaServer(t)
	_, err := srv.CreditMana(context.Background(), &grpcadapter.CreditManaRequest{
		Gcid: gG, Source: "topup", Units: -5,
		Reason: "topup", IdempotencyKey: "k-neg",
	})
	if err == nil {
		t.Fatal("negative units must surface a quoter error")
	}
}

func TestManaServer_GetBalance_InvalidGCIDErrors(t *testing.T) {
	t.Parallel()
	srv, _ := newManaServer(t)
	if _, err := srv.GetBalance(context.Background(), &grpcadapter.GetBalanceRequest{Gcid: ""}); err == nil {
		t.Fatal("empty gcid must propagate the domain validation error")
	}
}

func TestManaServer_NilRequestBranches(t *testing.T) {
	t.Parallel()
	srv, _ := newManaServer(t)
	if _, err := srv.DeductMana(context.Background(), nil); err == nil {
		t.Error("nil DeductMana request must error")
	}
	if _, err := srv.CreditMana(context.Background(), nil); err == nil {
		t.Error("nil CreditMana request must error")
	}
	if _, err := srv.GetBalance(context.Background(), nil); err == nil {
		t.Error("nil GetBalance request must error")
	}
}

func TestManaServer_NilReceiverBranches(t *testing.T) {
	t.Parallel()
	var srv *grpcadapter.ManaServer
	if _, err := srv.CreditMana(context.Background(), &grpcadapter.CreditManaRequest{}); err == nil {
		t.Error("nil receiver CreditMana must error")
	}
	if _, err := srv.GetBalance(context.Background(), &grpcadapter.GetBalanceRequest{}); err == nil {
		t.Error("nil receiver GetBalance must error")
	}
}
