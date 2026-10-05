// identity_proto_server.go — IdentityProtoServer binds the chora-contracts
// `chora.services.identity.v1.Identity` gRPC contract (identity.proto). It is
// the service-to-service sync surface for resolving a GCID → profile (email,
// display name) — the canonical inter-service path per the locked Protocol
// Strategy (CLAUDE.md §4: service-to-service = gRPC over the mesh; REST is for
// admin/learner CRUD).
//
// Why this file exists: the proto + generated client have shipped for a while
// (chora-notifications email-send recipient resolver + chora-gateway
// phyllis_handler both dial identityv1.NewIdentityClient(...).GetMe), and
// cmd/server/main.go even advertises Identity as SERVING on the gRPC health
// surface — but RegisterIdentityServer was never called, so every GetMe got
// `Unimplemented: unknown service chora.services.identity.v1.Identity`. This is
// the API-First (AP-01) gap: a defined contract that callers depend on, never
// implemented. Surfaced 2026-06-02 by the email-channel live send-path test
// (CHO-1634). Mirrors ManaProtoServer (mana_proto_server.go) — a thin
// proto<->domain bridge over the existing identity.UserRepository.GetByGcid.
//
// Scope: only GetMe is implemented (the sole consumed RPC). GetMeRoles +
// ResolveRoleByCourse have no callers and remain Unimplemented via the embedded
// UnimplementedIdentityServer (adding them would be speculative — no contract
// consumer to satisfy).
package grpcadapter

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	identityv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/services/identity/v1"

	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// userByGcidGetter is the minimal slice of identity.UserRepository the Identity
// gRPC server needs. Satisfied by the production pgx UserRepository (and the
// inmem fallback) without coupling this adapter to the full repository.
type userByGcidGetter interface {
	GetByGcid(ctx context.Context, gcid string) (*identity.User, error)
}

// IdentityProtoServer implements the generated identityv1.IdentityServer.
type IdentityProtoServer struct {
	identityv1.UnimplementedIdentityServer
	users userByGcidGetter
}

// NewIdentityProtoServer constructs the bridge over a UserRepository-shaped
// getter.
func NewIdentityProtoServer(users userByGcidGetter) *IdentityProtoServer {
	return &IdentityProtoServer{users: users}
}

// GetMe resolves a GCID to its profile. Despite the name (kept for the
// contract), the request carries the target GCID explicitly — this is a
// service-to-service lookup, not a "current caller" call. Error mapping:
//   - empty gcid / nil req  → InvalidArgument
//   - user not found        → NotFound
//   - any other repo error  → Internal
func (s *IdentityProtoServer) GetMe(ctx context.Context, req *identityv1.GetMeRequest) (*identityv1.GetMeResponse, error) {
	if s == nil || s.users == nil {
		return nil, status.Error(codes.Internal, "identity grpc: server not initialised")
	}
	if req == nil || req.GetGcid() == "" {
		return nil, status.Error(codes.InvalidArgument, "identity grpc: gcid is required")
	}
	u, err := s.users.GetByGcid(ctx, req.GetGcid())
	if err != nil {
		if errors.Is(err, identity.ErrUserNotFound) {
			return nil, status.Errorf(codes.NotFound, "identity grpc: gcid %s not found", req.GetGcid())
		}
		return nil, status.Errorf(codes.Internal, "identity grpc: get user %s: %v", req.GetGcid(), err)
	}
	me := &identityv1.Me{
		Gcid:        u.Gcid,
		Email:       u.Email,
		DisplayName: u.DisplayName,
	}
	if !u.CreatedAt.IsZero() {
		me.CreatedAt = timestamppb.New(u.CreatedAt.UTC())
	}
	return &identityv1.GetMeResponse{Me: me}, nil
}
