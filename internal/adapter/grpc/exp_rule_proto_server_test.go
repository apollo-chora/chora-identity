// exp_rule_proto_server_test.go — TDD RED-phase specs for the proto-typed
// ExpRuleService gRPC server (ADR-218 D6). This is the wire surface
// chora-consumption's familiar growth award path calls to unify onto identity's
// ExpRuleResolver (the live in-code growth/curve.go map becomes the fail-loud
// fallback; parity seeds — migration 0029 — guarantee identical values).
//
// ExpRuleProtoServer wraps the pure-domain exp_rules.ExpRuleResolver and
// translates between the generated identityv1.* types and the domain input /
// output. Error mapping: unknown/empty source (exp_rules.IsUnknownSource) →
// InvalidArgument; any other resolver/store error → Internal; a DISABLED source
// is a SUCCESSFUL resolution with enabled=false (NOT an error).
//
// Strict TDD: tests written BEFORE the ExpRuleProtoServer implementation.
package grpcadapter_test

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/services/identity/v1"

	grpcadapter "github.com/apollo-chora/chora-identity/internal/adapter/grpc"
	exprules "github.com/apollo-chora/chora-identity/internal/domain/exp_rules"
)

// stubExpRuleStore is a hand-rolled exp_rules.ExpRuleStore double. It records the
// last resolution input and returns a canned ResolvedExpRule (or error). The
// precedence ladder itself lives in the pg adapter; this double lets the proto
// server + domain resolver be exercised in isolation.
type stubExpRuleStore struct {
	out    exprules.ResolvedExpRule
	err    error
	got    exprules.ExpResolveInput
	called int
}

func (s *stubExpRuleStore) ResolveExpRule(_ context.Context, in exprules.ExpResolveInput) (exprules.ResolvedExpRule, error) {
	s.called++
	s.got = in
	if s.err != nil {
		return exprules.ResolvedExpRule{}, s.err
	}
	return s.out, nil
}

// newExpRuleProtoServer wires the proto server over the real domain resolver + a
// stub store — the same composition cmd/server/main.go uses (resolver over the pg
// store).
func newExpRuleProtoServer(store exprules.ExpRuleStore) *grpcadapter.ExpRuleProtoServer {
	return grpcadapter.NewExpRuleProtoServer(exprules.NewExpRuleResolver(store))
}

// ADR-218 D6 — a catalogue default resolves and every response field is wired 1:1
// from the domain output (the behaviour-neutral parity path).
func TestExpRuleProtoServer_ResolveExpRule_CatalogueDefault(t *testing.T) {
	t.Parallel()
	store := &stubExpRuleStore{out: exprules.ResolvedExpRule{
		SourceCode: "atom_session", ExpValue: 3, DailyCap: 30,
		Eligibility: "", Enabled: true, Source: "catalogue",
	}}
	srv := newExpRuleProtoServer(store)

	resp, err := srv.ResolveExpRule(context.Background(), &identityv1.ResolveExpRuleRequest{
		SourceCode: "atom_session",
	})
	if err != nil {
		t.Fatalf("ResolveExpRule: %v", err)
	}
	if resp.GetSourceCode() != "atom_session" {
		t.Errorf("SourceCode = %q, want atom_session", resp.GetSourceCode())
	}
	if resp.GetExpValue() != 3 {
		t.Errorf("ExpValue = %d, want 3", resp.GetExpValue())
	}
	if resp.GetDailyCap() != 30 {
		t.Errorf("DailyCap = %d, want 30", resp.GetDailyCap())
	}
	if !resp.GetEnabled() {
		t.Errorf("Enabled = false, want true")
	}
	if resp.GetResolutionSource() != "catalogue" {
		t.Errorf("ResolutionSource = %q, want catalogue", resp.GetResolutionSource())
	}
}

// ADR-218 D6 — the tenant + plan + context selectors are threaded to the store
// verbatim (resolution happens server-side; the proto server is a pure bridge).
func TestExpRuleProtoServer_ResolveExpRule_ThreadsInput(t *testing.T) {
	t.Parallel()
	store := &stubExpRuleStore{out: exprules.ResolvedExpRule{
		SourceCode: "hex_expand", ExpValue: 4, DailyCap: 12, Eligibility: "growth_stage>=4", Enabled: true, Source: "tenant",
	}}
	srv := newExpRuleProtoServer(store)

	resp, err := srv.ResolveExpRule(context.Background(), &identityv1.ResolveExpRuleRequest{
		SourceCode: "hex_expand",
		TenantId:   "11111111-1111-7111-8111-111111111111",
		Plan:       "pro",
		Context:    map[string]string{"growth_stage": "4"},
	})
	if err != nil {
		t.Fatalf("ResolveExpRule: %v", err)
	}
	in := store.got
	if in.SourceCode != "hex_expand" || in.TenantID != "11111111-1111-7111-8111-111111111111" {
		t.Errorf("store input source/tenant not threaded: %+v", in)
	}
	if in.Plan != "pro" || in.Context["growth_stage"] != "4" {
		t.Errorf("store input plan/context not threaded: %+v", in)
	}
	// eligibility + tenant resolution source ride through verbatim.
	if resp.GetEligibility() != "growth_stage>=4" || resp.GetResolutionSource() != "tenant" {
		t.Errorf("elig/source = {%q,%q}, want {growth_stage>=4,tenant}", resp.GetEligibility(), resp.GetResolutionSource())
	}
}

// ADR-203 L16 — an unknown source (store returns ErrUnknownSource) maps to gRPC
// InvalidArgument (a caller contract error, not a server fault; the source is
// non-configurable and cannot be minted).
func TestExpRuleProtoServer_ResolveExpRule_UnknownSourceInvalidArgument(t *testing.T) {
	t.Parallel()
	store := &stubExpRuleStore{err: exprules.ErrUnknownSource}
	srv := newExpRuleProtoServer(store)

	_, err := srv.ResolveExpRule(context.Background(), &identityv1.ResolveExpRuleRequest{SourceCode: "i_passed_the_real_pmp"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("status = %v, want InvalidArgument", status.Code(err))
	}
}

// ADR-201 §5 — an empty source_code is rejected as InvalidArgument WITHOUT
// consulting the store (the resolver guards it).
func TestExpRuleProtoServer_ResolveExpRule_EmptySourceInvalidArgument(t *testing.T) {
	t.Parallel()
	store := &stubExpRuleStore{}
	srv := newExpRuleProtoServer(store)

	_, err := srv.ResolveExpRule(context.Background(), &identityv1.ResolveExpRuleRequest{SourceCode: "   "})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("status = %v, want InvalidArgument", status.Code(err))
	}
	if store.called != 0 {
		t.Errorf("store consulted %d times on empty source, want 0", store.called)
	}
}

// §12 EXP-editor "enabled" knob — a DISABLED source resolves SUCCESSFULLY with
// enabled=false (the caller skips the award). It is NOT an error.
func TestExpRuleProtoServer_ResolveExpRule_DisabledIsSuccess(t *testing.T) {
	t.Parallel()
	store := &stubExpRuleStore{out: exprules.ResolvedExpRule{
		SourceCode: "atom_authored", ExpValue: 20, DailyCap: 40, Enabled: false, Source: "tenant",
	}}
	srv := newExpRuleProtoServer(store)

	resp, err := srv.ResolveExpRule(context.Background(), &identityv1.ResolveExpRuleRequest{
		SourceCode: "atom_authored", TenantId: "11111111-1111-7111-8111-111111111111",
	})
	if err != nil {
		t.Fatalf("ResolveExpRule: %v (disabled is a valid resolved state, not an error)", err)
	}
	if resp.GetEnabled() {
		t.Errorf("Enabled = true, want false (source disabled by tenant override)")
	}
	// The value still rides through — the caller decides to skip on enabled=false.
	if resp.GetExpValue() != 20 {
		t.Errorf("ExpValue = %d, want 20", resp.GetExpValue())
	}
}

// ADR-201 §5 — a store/DB fault (NOT unknown-source) maps to gRPC Internal, not
// InvalidArgument (a real server fault the caller may retry).
func TestExpRuleProtoServer_ResolveExpRule_StoreErrorInternal(t *testing.T) {
	t.Parallel()
	store := &stubExpRuleStore{err: errors.New("connection reset by peer")}
	srv := newExpRuleProtoServer(store)

	_, err := srv.ResolveExpRule(context.Background(), &identityv1.ResolveExpRuleRequest{SourceCode: "atom_session"})
	if status.Code(err) != codes.Internal {
		t.Fatalf("status = %v, want Internal", status.Code(err))
	}
}

// Defensive nil-receiver + nil-request branches the bufconn path doesn't hit.
func TestExpRuleProtoServer_NilGuards(t *testing.T) {
	t.Parallel()
	var srv *grpcadapter.ExpRuleProtoServer
	if _, err := srv.ResolveExpRule(context.Background(), &identityv1.ResolveExpRuleRequest{SourceCode: "atom_session"}); err == nil {
		t.Errorf("nil receiver ResolveExpRule: expected error")
	}
	live := newExpRuleProtoServer(&stubExpRuleStore{})
	if _, err := live.ResolveExpRule(context.Background(), nil); err == nil {
		t.Errorf("nil request ResolveExpRule: expected error")
	}
}

// Compile-time assertion — the proto-bridging server MUST satisfy
// identityv1.ExpRuleServiceServer so the RegisterExpRuleServiceServer call in
// cmd/server/main.go type-checks.
func TestExpRuleProtoServer_SatisfiesGeneratedServerInterface(t *testing.T) {
	t.Parallel()
	var _ identityv1.ExpRuleServiceServer = newExpRuleProtoServer(&stubExpRuleStore{})
}
