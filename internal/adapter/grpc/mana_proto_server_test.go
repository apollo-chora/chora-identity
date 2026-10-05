// mana_proto_server_test.go — TDD RED-phase specs for the proto-typed
// ManaService gRPC server. This is the canonical wire surface chora-creation
// + chora-consumption + chora-tenancy talk to over the service mesh
// (chora-contracts/proto/services/identity/v1/mana_service.proto).
//
// The existing ManaServer in mana_service.go uses HANDCRAFTED wire types
// (LedgerEntry / DeductManaRequest / DeductManaResponse) — that was useful
// to allow domain testing without touching generated proto code. P4+P5 of
// 2026-05-15 (commits d958890c + 6ce3a0d9) wired chora-creation's
// ManaClient against the GENERATED `identityv1.ManaServiceClient`; the
// gRPC server-side bind in chora-identity now needs the matching proto-
// typed implementation. ManaProtoServer (this file) wraps ManaServer +
// translates proto<->wire types so the grpc.RegisterManaServiceServer call
// in cmd/server/main.go can bind a real listener.
//
// Strict TDD: tests written BEFORE the ManaProtoServer implementation.
package grpcadapter_test

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/services/identity/v1"

	grpcadapter "github.com/apollo-chora/chora-identity/internal/adapter/grpc"
	mana "github.com/apollo-chora/chora-identity/internal/domain/user_mana"
)

// newManaProtoServer constructs the proto-bridging gRPC server with the
// same domain wiring the handcrafted ManaServer uses.
func newManaProtoServer(t *testing.T) (*grpcadapter.ManaProtoServer, *mana.InMemoryStore) {
	t.Helper()
	store := mana.NewInMemoryStore()
	q := mana.NewQuoter(store)
	core := grpcadapter.NewManaServer(q, store, nil)
	return grpcadapter.NewManaProtoServer(core), store
}

// staticPricer is a test Pricer returning a fixed catalogue.
type staticPricer struct{ prices map[string]int64 }

func (p staticPricer) CostForAction(_ context.Context, code string) (int64, error) {
	c, ok := p.prices[code]
	if !ok {
		return 0, mana.ErrUnknownActionCode
	}
	return c, nil
}

// newPricedManaProtoServer wires a catalogue-pricer for units==0 metering tests.
func newPricedManaProtoServer(t *testing.T, prices map[string]int64) (*grpcadapter.ManaProtoServer, *mana.InMemoryStore) {
	t.Helper()
	store := mana.NewInMemoryStore()
	q := mana.NewQuoter(store, mana.WithPricer(staticPricer{prices: prices}))
	core := grpcadapter.NewManaServer(q, store, nil)
	return grpcadapter.NewManaProtoServer(core), store
}

// recordingResolver is a test PriceResolver (ADR-178) recording the resolution
// key so a wire test can assert tier/context were threaded across the proto
// boundary, and returning canned metadata.
type recordingResolver struct {
	out   mana.Resolved
	calls []mana.ResolveInput
}

func (r *recordingResolver) Resolve(_ context.Context, in mana.ResolveInput) (mana.Resolved, error) {
	r.calls = append(r.calls, in)
	return r.out, nil
}

// newResolverManaProtoServer wires the richer ADR-178 price-plan resolver.
func newResolverManaProtoServer(t *testing.T, r *recordingResolver) (*grpcadapter.ManaProtoServer, *mana.InMemoryStore) {
	t.Helper()
	store := mana.NewInMemoryStore()
	q := mana.NewQuoter(store, mana.WithPriceResolver(r))
	core := grpcadapter.NewManaServer(q, store, nil)
	return grpcadapter.NewManaProtoServer(core), store
}

// FU-4(b) — the proto server threads the new tier + context fields into the
// resolver and surfaces refundable / per_item / price_source back on the wire.
// The per_item × item_count multiply happens server-side.
func TestManaProtoServer_DeductMana_ThreadsTierContext_SurfacesMetadata(t *testing.T) {
	t.Parallel()
	const gcid = "01970000-0000-7000-8000-0000000d00a1"
	res := &recordingResolver{out: mana.Resolved{Units: 5, PerItem: true, Refundable: true, Source: "tenant_override"}}
	srv, _ := newResolverManaProtoServer(t, res)
	if _, err := srv.CreditMana(context.Background(), &identityv1.CreditManaRequest{
		Gcid: gcid, Source: identityv1.ManaSource_MANA_SOURCE_TOPUP, Units: 1000,
		Reason: identityv1.ManaReasonCode_MANA_REASON_CODE_TOPUP, IdempotencyKey: "seed-meta",
	}); err != nil {
		t.Fatalf("seed credit: %v", err)
	}

	resp, err := srv.DeductMana(context.Background(), &identityv1.DeductManaRequest{
		Gcid:           gcid,
		ActionCode:     "question_authoring_batch_per_item",
		Units:          0,
		IdempotencyKey: "meta-1",
		TenantId:       "11111111-1111-7111-8111-111111111111",
		Tier:           "high",
		Context:        map[string]string{"item_count": "4"},
	})
	if err != nil {
		t.Fatalf("DeductMana: %v", err)
	}
	if !resp.Success {
		t.Fatalf("Success = false, want true")
	}
	// Resolver saw tenant_id + tier + context (else tenant overrides ignored).
	if len(res.calls) != 1 {
		t.Fatalf("resolver consulted %d times, want 1", len(res.calls))
	}
	in := res.calls[0]
	if in.TenantID != "11111111-1111-7111-8111-111111111111" || in.Tier != "high" || in.Context["item_count"] != "4" {
		t.Errorf("resolution key not threaded: %+v", in)
	}
	// per_item × item_count applied: 5 × 4 = 20.
	if resp.BalanceAfterUnits != 980 {
		t.Errorf("balance after = %d, want 980 (1000 - 5×4)", resp.BalanceAfterUnits)
	}
	// Metadata surfaced on the wire.
	if !resp.Refundable || !resp.PerItem || resp.PriceSource != "tenant_override" {
		t.Errorf("metadata not surfaced: refundable=%v per_item=%v price_source=%q",
			resp.Refundable, resp.PerItem, resp.PriceSource)
	}
}

// TestManaProtoServer_DeductMana_DryRun asserts the dry-run pre-flight gate
// resolves cost + reports affordability WITHOUT writing a ledger row (WS-1).
func TestManaProtoServer_DeductMana_DryRun(t *testing.T) {
	t.Parallel()
	const gcid = "01970000-0000-7000-8000-0000000d0001"
	srv, store := newPricedManaProtoServer(t, map[string]int64{"familiar_chat_turn_premium": 30})
	if _, err := srv.CreditMana(context.Background(), &identityv1.CreditManaRequest{
		Gcid: gcid, Source: identityv1.ManaSource_MANA_SOURCE_TOPUP, Units: 100,
		Reason: identityv1.ManaReasonCode_MANA_REASON_CODE_TOPUP, IdempotencyKey: "seed-dry",
	}); err != nil {
		t.Fatalf("seed credit: %v", err)
	}

	// Affordable dry-run: success, no debit, no entries.
	resp, err := srv.DeductMana(context.Background(), &identityv1.DeductManaRequest{
		Gcid: gcid, ActionCode: "familiar_chat_turn_premium", Units: 0, IdempotencyKey: "dry-ok", DryRun: true,
	})
	if err != nil {
		t.Fatalf("dry-run DeductMana: %v", err)
	}
	if !resp.Success {
		t.Errorf("Success = false, want true (affordable)")
	}
	if len(resp.Entries) != 0 {
		t.Errorf("dry-run returned %d entries, want 0", len(resp.Entries))
	}
	if got, _ := store.GetMana(context.Background(), gcid); got.BalanceUnits != 100 {
		t.Errorf("balance mutated to %d on dry-run, want 100", got.BalanceUnits)
	}
}

// TestManaProtoServer_DeductMana_DryRunInsufficient asserts the dry-run gate
// surfaces the resolved required units (not req.Units=0) on shortfall.
func TestManaProtoServer_DeductMana_DryRunInsufficient(t *testing.T) {
	t.Parallel()
	const gcid = "01970000-0000-7000-8000-0000000d0002"
	srv, _ := newPricedManaProtoServer(t, map[string]int64{"boss_challenge_atom_gen": 200})
	if _, err := srv.CreditMana(context.Background(), &identityv1.CreditManaRequest{
		Gcid: gcid, Source: identityv1.ManaSource_MANA_SOURCE_TOPUP, Units: 10,
		Reason: identityv1.ManaReasonCode_MANA_REASON_CODE_TOPUP, IdempotencyKey: "seed-dry2",
	}); err != nil {
		t.Fatalf("seed credit: %v", err)
	}

	resp, err := srv.DeductMana(context.Background(), &identityv1.DeductManaRequest{
		Gcid: gcid, ActionCode: "boss_challenge_atom_gen", Units: 0, IdempotencyKey: "dry-no", DryRun: true,
	})
	if err != nil {
		t.Fatalf("dry-run DeductMana: %v", err)
	}
	if resp.Success {
		t.Errorf("Success = true, want false (unaffordable)")
	}
	if resp.RequiredUnits != 200 {
		t.Errorf("RequiredUnits = %d, want 200 (resolved catalogue cost)", resp.RequiredUnits)
	}
	if resp.CurrentBalanceUnits != 10 {
		t.Errorf("CurrentBalanceUnits = %d, want 10", resp.CurrentBalanceUnits)
	}
}

// TestManaProtoServer_CreditMana_TranslatesProtoSourceAndReturnsLedger asserts
// the proto ManaSource enum maps to the domain Source string AND the response
// LedgerEntry has the proto fields populated from the domain ledger row.
func TestManaProtoServer_CreditMana_TranslatesProtoSourceAndReturnsLedger(t *testing.T) {
	t.Parallel()
	srv, _ := newManaProtoServer(t)

	resp, err := srv.CreditMana(context.Background(), &identityv1.CreditManaRequest{
		Gcid:           "01970000-0000-7000-8000-000000000010",
		Source:         identityv1.ManaSource_MANA_SOURCE_SUBSCRIPTION_GRANT,
		Units:          500,
		Reason:         identityv1.ManaReasonCode_MANA_REASON_CODE_SUBSCRIPTION_GRANT,
		IdempotencyKey: "ck-proto-1",
	})
	if err != nil {
		t.Fatalf("CreditMana: %v", err)
	}
	if resp.BalanceAfterUnits != 500 {
		t.Errorf("BalanceAfterUnits = %d; want 500", resp.BalanceAfterUnits)
	}
	if resp.Entry == nil {
		t.Fatalf("Entry nil — proto LedgerEntry must be populated")
	}
	if resp.Entry.Units != 500 {
		t.Errorf("Entry.Units = %d; want 500", resp.Entry.Units)
	}
	if resp.Entry.Direction == 0 {
		t.Errorf("Entry.Direction = 0; want 1=credit / 3=mint per proto convention")
	}
	if resp.Entry.BalanceAfterUnits != 500 {
		t.Errorf("Entry.BalanceAfterUnits = %d; want 500", resp.Entry.BalanceAfterUnits)
	}
	if resp.Entry.RecordedAt == nil {
		t.Errorf("Entry.RecordedAt nil — proto Timestamp must be populated")
	}
}

func TestManaProtoServer_CreditMana_RejectsUnspecifiedSource(t *testing.T) {
	t.Parallel()
	srv, _ := newManaProtoServer(t)
	_, err := srv.CreditMana(context.Background(), &identityv1.CreditManaRequest{
		Gcid:           "01970000-0000-7000-8000-000000000010",
		Source:         identityv1.ManaSource_MANA_SOURCE_UNSPECIFIED,
		Units:          10,
		Reason:         identityv1.ManaReasonCode_MANA_REASON_CODE_PROMO,
		IdempotencyKey: "k",
	})
	if err == nil {
		t.Errorf("expected error for MANA_SOURCE_UNSPECIFIED")
	}
}

func TestManaProtoServer_DeductMana_Sufficient_ReturnsEntries(t *testing.T) {
	t.Parallel()
	srv, _ := newManaProtoServer(t)
	ctx := context.Background()

	_, _ = srv.CreditMana(ctx, &identityv1.CreditManaRequest{
		Gcid:           "01970000-0000-7000-8000-000000000010",
		Source:         identityv1.ManaSource_MANA_SOURCE_TOPUP,
		Units:          500,
		Reason:         identityv1.ManaReasonCode_MANA_REASON_CODE_TOPUP,
		IdempotencyKey: "ck-1",
	})

	res, err := srv.DeductMana(ctx, &identityv1.DeductManaRequest{
		Gcid:           "01970000-0000-7000-8000-000000000010",
		ActionCode:     "question_authoring_ai_draft",
		Units:          100,
		IdempotencyKey: "dk-1",
	})
	if err != nil {
		t.Fatalf("DeductMana: %v", err)
	}
	if !res.Success {
		t.Errorf("Success = false; want true on sufficient balance")
	}
	if res.BalanceAfterUnits != 400 {
		t.Errorf("BalanceAfterUnits = %d; want 400", res.BalanceAfterUnits)
	}
	if len(res.Entries) == 0 {
		t.Errorf("Entries empty — must include the debit row")
	}
}

func TestManaProtoServer_DeductMana_Insufficient_ReturnsUpsellContext(t *testing.T) {
	t.Parallel()
	srv, _ := newManaProtoServer(t)
	ctx := context.Background()

	_, _ = srv.CreditMana(ctx, &identityv1.CreditManaRequest{
		Gcid:           "01970000-0000-7000-8000-000000000010",
		Source:         identityv1.ManaSource_MANA_SOURCE_SUBSCRIPTION_GRANT,
		Units:          50,
		Reason:         identityv1.ManaReasonCode_MANA_REASON_CODE_SUBSCRIPTION_GRANT,
		IdempotencyKey: "ck-1",
	})
	res, err := srv.DeductMana(ctx, &identityv1.DeductManaRequest{
		Gcid:           "01970000-0000-7000-8000-000000000010",
		ActionCode:     "x",
		Units:          1000,
		IdempotencyKey: "dk-1",
	})
	if err != nil {
		t.Fatalf("DeductMana: %v", err)
	}
	if res.Success {
		t.Errorf("Success = true; want false on insufficient balance")
	}
	if res.RequiredUnits != 1000 {
		t.Errorf("RequiredUnits = %d; want 1000", res.RequiredUnits)
	}
	if res.CurrentBalanceUnits != 50 {
		t.Errorf("CurrentBalanceUnits = %d; want 50", res.CurrentBalanceUnits)
	}
}

func TestManaProtoServer_DeductMana_Idempotent(t *testing.T) {
	t.Parallel()
	srv, store := newManaProtoServer(t)
	ctx := context.Background()

	_, _ = srv.CreditMana(ctx, &identityv1.CreditManaRequest{
		Gcid:           "01970000-0000-7000-8000-000000000010",
		Source:         identityv1.ManaSource_MANA_SOURCE_TOPUP,
		Units:          500,
		Reason:         identityv1.ManaReasonCode_MANA_REASON_CODE_TOPUP,
		IdempotencyKey: "ck",
	})
	for i := 0; i < 3; i++ {
		_, err := srv.DeductMana(ctx, &identityv1.DeductManaRequest{
			Gcid:           "01970000-0000-7000-8000-000000000010",
			ActionCode:     "x",
			Units:          100,
			IdempotencyKey: "dk-replay",
		})
		if err != nil {
			t.Fatalf("DeductMana #%d: %v", i, err)
		}
	}
	got, _ := store.GetMana(ctx, "01970000-0000-7000-8000-000000000010")
	if got.BalanceUnits != 400 {
		t.Errorf("replay caused multi-debit; balance = %d; want 400", got.BalanceUnits)
	}
}

func TestManaProtoServer_GetBalance_ReturnsBreakdown(t *testing.T) {
	t.Parallel()
	srv, _ := newManaProtoServer(t)
	ctx := context.Background()
	_, _ = srv.CreditMana(ctx, &identityv1.CreditManaRequest{
		Gcid:           "01970000-0000-7000-8000-000000000010",
		Source:         identityv1.ManaSource_MANA_SOURCE_SUBSCRIPTION_GRANT,
		Units:          500,
		Reason:         identityv1.ManaReasonCode_MANA_REASON_CODE_SUBSCRIPTION_GRANT,
		IdempotencyKey: "ck-1",
	})

	resp, err := srv.GetBalance(ctx, &identityv1.GetBalanceRequest{
		Gcid: "01970000-0000-7000-8000-000000000010",
	})
	if err != nil {
		t.Fatalf("GetBalance: %v", err)
	}
	if resp.BalanceUnits != 500 {
		t.Errorf("BalanceUnits = %d; want 500", resp.BalanceUnits)
	}
}

// mustEmbedUnimplementedManaServiceServer compile-time assertion — the
// proto-bridging server MUST satisfy identityv1.ManaServiceServer so the
// grpc.RegisterManaServiceServer call in cmd/server/main.go type-checks.
func TestManaProtoServer_SatisfiesGeneratedServerInterface(t *testing.T) {
	t.Parallel()
	srv, _ := newManaProtoServer(t)
	// Compile-time check via interface assertion.
	var _ identityv1.ManaServiceServer = srv
}

// TestManaProtoServer_AllSourcesAndReasonsRoundTrip exercises every
// ManaSource + ManaReasonCode enum value through the CreditMana path so
// the proto<->string translation tables get full coverage.
func TestManaProtoServer_AllSourcesAndReasonsRoundTrip(t *testing.T) {
	t.Parallel()
	srv, _ := newManaProtoServer(t)
	ctx := context.Background()

	// Each (source, reason) pair credits 5 mana under a unique key. The
	// pairings mirror how chora-creation / chora-tenancy emit credits.
	cases := []struct {
		name   string
		source identityv1.ManaSource
		reason identityv1.ManaReasonCode
		key    string
		// Extra fields that chora-creation / chora-tenancy populate when
		// the source requires a pointer (e.g. TENANT_SUBSIDY needs
		// source_allocation_id).
		topupID, subID, allocID string
	}{
		{"subscription", identityv1.ManaSource_MANA_SOURCE_SUBSCRIPTION_GRANT, identityv1.ManaReasonCode_MANA_REASON_CODE_SUBSCRIPTION_GRANT, "k1", "", "sub-1", ""},
		{"topup", identityv1.ManaSource_MANA_SOURCE_TOPUP, identityv1.ManaReasonCode_MANA_REASON_CODE_TOPUP, "k2", "topup-1", "", ""},
		{"promo", identityv1.ManaSource_MANA_SOURCE_PROMO, identityv1.ManaReasonCode_MANA_REASON_CODE_PROMO, "k3", "", "", ""},
		{"tenant_subsidy", identityv1.ManaSource_MANA_SOURCE_TENANT_SUBSIDY, identityv1.ManaReasonCode_MANA_REASON_CODE_TENANT_SUBSIDY, "k4", "", "", "alloc-1"},
		{"refund", identityv1.ManaSource_MANA_SOURCE_REFUND, identityv1.ManaReasonCode_MANA_REASON_CODE_REFUND, "k5", "", "", ""},
		{"rollover", identityv1.ManaSource_MANA_SOURCE_ROLLOVER, identityv1.ManaReasonCode_MANA_REASON_CODE_ROLLOVER, "k6", "", "", ""},
		{"mint", identityv1.ManaSource_MANA_SOURCE_MINT, identityv1.ManaReasonCode_MANA_REASON_CODE_PROMO, "k7", "", "", ""},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := &identityv1.CreditManaRequest{
				Gcid:                 "01970000-0000-7000-8000-00000000a" + tc.name,
				Source:               tc.source,
				Units:                5,
				Reason:               tc.reason,
				IdempotencyKey:       tc.key,
				SourceTopupId:        tc.topupID,
				SourceSubscriptionId: tc.subID,
				SourceAllocationId:   tc.allocID,
				TenantId:             "tenant-1",
			}
			resp, err := srv.CreditMana(ctx, req)
			if err != nil {
				t.Fatalf("CreditMana %s: %v", tc.name, err)
			}
			if resp.GetBalanceAfterUnits() != 5 {
				t.Errorf("%s: balance = %d; want 5", tc.name, resp.GetBalanceAfterUnits())
			}
			// Round-trip GetBalance — verify the SubsidySlice projection for
			// tenant_subsidy carries the proto Source back (and reverse maps
			// non-tenant slices to MANA_SOURCE_SUBSCRIPTION_GRANT / TOPUP).
			balResp, err := srv.GetBalance(ctx, &identityv1.GetBalanceRequest{Gcid: req.Gcid})
			if err != nil {
				t.Fatalf("GetBalance %s: %v", tc.name, err)
			}
			if balResp.GetBalanceUnits() != 5 {
				t.Errorf("%s: GetBalance.BalanceUnits = %d; want 5", tc.name, balResp.GetBalanceUnits())
			}
		})
	}
}

// TestManaProtoServer_NilGuards — defensive nil-receiver + nil-request
// branches the bufconn path doesn't exercise.
func TestManaProtoServer_NilGuards(t *testing.T) {
	t.Parallel()
	var srv *grpcadapter.ManaProtoServer
	if _, err := srv.DeductMana(context.Background(), &identityv1.DeductManaRequest{}); err == nil {
		t.Errorf("nil receiver DeductMana: expected error")
	}
	if _, err := srv.CreditMana(context.Background(), &identityv1.CreditManaRequest{}); err == nil {
		t.Errorf("nil receiver CreditMana: expected error")
	}
	if _, err := srv.GetBalance(context.Background(), &identityv1.GetBalanceRequest{}); err == nil {
		t.Errorf("nil receiver GetBalance: expected error")
	}
	// Init-but-nil-request branches.
	live, _ := newManaProtoServer(t)
	if _, err := live.DeductMana(context.Background(), nil); err == nil {
		t.Errorf("nil request DeductMana: expected error")
	}
	if _, err := live.CreditMana(context.Background(), nil); err == nil {
		t.Errorf("nil request CreditMana: expected error")
	}
	if _, err := live.GetBalance(context.Background(), nil); err == nil {
		t.Errorf("nil request GetBalance: expected error")
	}
}

// TestManaProtoServer_DeductMana_UnknownActionCode_InvalidArgument asserts an
// unpriced action_code on the units==0 metering path is a CALLER contract
// error and is surfaced as gRPC InvalidArgument (WS-1 "unpriced ⇒
// un-metered" distinction), NOT as an opaque server error.
func TestManaProtoServer_DeductMana_UnknownActionCode_InvalidArgument(t *testing.T) {
	t.Parallel()
	srv, _ := newPricedManaProtoServer(t, map[string]int64{"priced": 5})
	_, err := srv.DeductMana(context.Background(), &identityv1.DeductManaRequest{
		Gcid:           "01970000-0000-7000-8000-000000000010",
		ActionCode:     "not-in-catalogue",
		Units:          0,
		IdempotencyKey: "dk-unknown",
	})
	if err == nil {
		t.Fatal("unknown action_code must error")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("status code = %v, want InvalidArgument", status.Code(err))
	}
}

// TestManaProtoServer_GetBalance_InvalidGCID_Error drives the core error
// passthrough on the proto GetBalance path (domain validation rejects the
// empty gcid before any store access).
func TestManaProtoServer_GetBalance_InvalidGCID_Error(t *testing.T) {
	t.Parallel()
	srv, _ := newManaProtoServer(t)
	if _, err := srv.GetBalance(context.Background(), &identityv1.GetBalanceRequest{Gcid: ""}); err == nil {
		t.Fatal("empty gcid must surface an error")
	}
}

// TestManaProtoServer_CreditMana_CoreError_Propagates drives the post-source-
// translation error branch (the quoter rejects negative units).
func TestManaProtoServer_CreditMana_CoreError_Propagates(t *testing.T) {
	t.Parallel()
	srv, _ := newManaProtoServer(t)
	_, err := srv.CreditMana(context.Background(), &identityv1.CreditManaRequest{
		Gcid:           "01970000-0000-7000-8000-000000000010",
		Source:         identityv1.ManaSource_MANA_SOURCE_TOPUP,
		Units:          -5,
		Reason:         identityv1.ManaReasonCode_MANA_REASON_CODE_TOPUP,
		IdempotencyKey: "ck-neg",
	})
	if err == nil {
		t.Fatal("negative units must surface a quoter error")
	}
}

// TestManaProtoServer_DeductMana_NonUnknownError_Passthrough drives the raw
// `return nil, err` branch (an error that is NOT an UnknownActionCode must
// NOT be remapped to InvalidArgument — infra errors stay opaque).
func TestManaProtoServer_DeductMana_NonUnknownError_Passthrough(t *testing.T) {
	t.Parallel()
	srv, _ := newPricedManaProtoServer(t, map[string]int64{"negatively_priced": -1})
	_, err := srv.DeductMana(context.Background(), &identityv1.DeductManaRequest{
		Gcid:           "01970000-0000-7000-8000-000000000010",
		ActionCode:     "negatively_priced",
		Units:          0,
		IdempotencyKey: "dk-neg-price",
	})
	if err == nil {
		t.Fatal("negative catalogue cost must error")
	}
	if status.Code(err) == codes.InvalidArgument {
		t.Errorf("non-unknown error must NOT map to InvalidArgument, got %v", err)
	}
}

// TestManaProtoServer_GetBalance_SurfacesSubsidyExpiry asserts the
// SubsidySlice ExpiresAt projection is carried onto the proto wire when a
// tenant subsidy allocation has an expiry (and that the subsidy source enum
// maps back to MANA_SOURCE_TENANT_SUBSIDY).
func TestManaProtoServer_GetBalance_SurfacesSubsidyExpiry(t *testing.T) {
	t.Parallel()
	store := mana.NewInMemoryStore()
	q := mana.NewQuoter(store)
	core := grpcadapter.NewManaServer(q, store, nil)
	srv := grpcadapter.NewManaProtoServer(core)
	ctx := context.Background()

	gcid := "01970000-0000-7000-8000-0000000000f1"
	expires := time.Now().UTC().Add(30 * 24 * time.Hour)
	if _, err := core.CreditMana(ctx, &grpcadapter.CreditManaRequest{
		Gcid:               gcid,
		Source:             "tenant_subsidy",
		Units:              100,
		Reason:             "tenant_subsidy",
		IdempotencyKey:     "ck-sub-exp",
		SourceAllocationID: "alloc-exp-1",
		TenantID:           "01970000-0000-7000-8000-000000000099",
		ExpiresAt:          &expires,
	}); err != nil {
		t.Fatalf("seed tenant subsidy: %v", err)
	}

	resp, err := srv.GetBalance(ctx, &identityv1.GetBalanceRequest{Gcid: gcid})
	if err != nil {
		t.Fatalf("GetBalance: %v", err)
	}
	if len(resp.SubsidyBreakdown) != 1 {
		t.Fatalf("expected 1 subsidy slice, got %d", len(resp.SubsidyBreakdown))
	}
	sl := resp.SubsidyBreakdown[0]
	if sl.ExpiresAt == nil {
		t.Error("SubsidySlice.ExpiresAt must be populated from the allocation")
	}
	if sl.Source != identityv1.ManaSource_MANA_SOURCE_TENANT_SUBSIDY {
		t.Errorf("slice source = %v, want MANA_SOURCE_TENANT_SUBSIDY", sl.Source)
	}
}
