// Package grpcadapter — ExpRuleProtoServer is the wire bridge for the
// chora-contracts-defined ExpRuleService gRPC contract (ADR-218 D6). It wraps the
// pure-domain exp_rules.ExpRuleResolver and translates between the proto-generated
// types (identityv1.*) and the domain resolve input / output.
//
// Primary caller: chora-consumption's familiar growth award path. Per ADR-218 D6,
// the live in-code growth/curve.go source map unifies onto this resolver (the
// in-code map remains only as the fail-loud-logged fallback when this service is
// unreachable; parity seeds — migration 0029 — guarantee identical values). The
// resolver runs the precedence ladder (tenant override → platform plan →
// exp_source_def catalogue default) server-side over the pg ExpRuleStore.
//
// Per chora-contracts/proto/services/identity/v1/exp_rule_service.proto + ADR-201 §5.
package grpcadapter

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/services/identity/v1"

	exprules "github.com/apollo-chora/chora-identity/internal/domain/exp_rules"
)

// ExpRuleProtoServer adapts the pure-domain ExpRuleResolver to the proto-typed
// identityv1.ExpRuleServiceServer interface.
type ExpRuleProtoServer struct {
	identityv1.UnimplementedExpRuleServiceServer
	resolver *exprules.ExpRuleResolver
}

// NewExpRuleProtoServer constructs the bridge over a domain resolver (production:
// exp_rules.NewExpRuleResolver over the pg ExpRuleStore).
func NewExpRuleProtoServer(resolver *exprules.ExpRuleResolver) *ExpRuleProtoServer {
	return &ExpRuleProtoServer{resolver: resolver}
}

// Compile-time check — must satisfy the generated server interface so
// RegisterExpRuleServiceServer type-checks in cmd/server/main.go.
var _ identityv1.ExpRuleServiceServer = (*ExpRuleProtoServer)(nil)

// ResolveExpRule — proto-typed handler that delegates to the domain resolver +
// translates the response back to proto types. Error mapping (ADR-218 D6):
//   - unknown / empty / deprecated source (exprules.IsUnknownSource) → the source
//     is non-configurable (ADR-203 L16) and cannot be minted by a caller, so this
//     is a caller contract error → codes.InvalidArgument;
//   - any other resolver / store fault → codes.Internal (a retryable server fault);
//   - a DISABLED source is NOT an error — it resolves SUCCESSFULLY with
//     enabled=false and the caller (chora-consumption growth admission) skips the
//     award.
func (s *ExpRuleProtoServer) ResolveExpRule(ctx context.Context, req *identityv1.ResolveExpRuleRequest) (*identityv1.ResolveExpRuleResponse, error) {
	if s == nil || s.resolver == nil {
		return nil, errors.New("grpcadapter.ExpRuleProtoServer: not initialised")
	}
	if req == nil {
		return nil, errors.New("grpcadapter.ExpRuleProtoServer: request required")
	}

	got, err := s.resolver.Resolve(ctx, exprules.ExpResolveInput{
		SourceCode: req.GetSourceCode(),
		TenantID:   req.GetTenantId(),
		Plan:       req.GetPlan(),
		Context:    req.GetContext(),
	})
	if err != nil {
		if exprules.IsUnknownSource(err) {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &identityv1.ResolveExpRuleResponse{
		SourceCode:       got.SourceCode,
		ExpValue:         got.ExpValue,
		DailyCap:         got.DailyCap,
		Eligibility:      got.Eligibility,
		Enabled:          got.Enabled,
		ResolutionSource: got.Source,
	}, nil
}
