package grpcadapter

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/services/identity/v1"

	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// stubUserGetter is a hand fake for userByGcidGetter.
type stubUserGetter struct {
	user    *identity.User
	err     error
	gotGcid string
}

func (s *stubUserGetter) GetByGcid(_ context.Context, gcid string) (*identity.User, error) {
	s.gotGcid = gcid
	return s.user, s.err
}

func TestIdentityProtoServer_GetMe_HappyPath(t *testing.T) {
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	stub := &stubUserGetter{user: &identity.User{
		Gcid:        "00000000-0000-7000-8000-000000001999",
		Email:       "daleleung76@gmail.com",
		DisplayName: "Dale",
		CreatedAt:   created,
	}}
	s := NewIdentityProtoServer(stub)
	resp, err := s.GetMe(context.Background(), &identityv1.GetMeRequest{Gcid: "00000000-0000-7000-8000-000000001999"})
	if err != nil {
		t.Fatalf("GetMe unexpected err: %v", err)
	}
	if stub.gotGcid != "00000000-0000-7000-8000-000000001999" {
		t.Errorf("GetByGcid called with %q", stub.gotGcid)
	}
	me := resp.GetMe()
	if me.GetEmail() != "daleleung76@gmail.com" {
		t.Errorf("email = %q", me.GetEmail())
	}
	if me.GetGcid() != "00000000-0000-7000-8000-000000001999" {
		t.Errorf("gcid = %q", me.GetGcid())
	}
	if me.GetDisplayName() != "Dale" {
		t.Errorf("display_name = %q", me.GetDisplayName())
	}
	if me.GetCreatedAt() == nil || !me.GetCreatedAt().AsTime().Equal(created) {
		t.Errorf("created_at = %v want %v", me.GetCreatedAt().AsTime(), created)
	}
}

func TestIdentityProtoServer_GetMe_EmptyGcid_InvalidArgument(t *testing.T) {
	s := NewIdentityProtoServer(&stubUserGetter{})
	_, err := s.GetMe(context.Background(), &identityv1.GetMeRequest{Gcid: ""})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", status.Code(err))
	}
}

func TestIdentityProtoServer_GetMe_NilRequest_InvalidArgument(t *testing.T) {
	s := NewIdentityProtoServer(&stubUserGetter{})
	_, err := s.GetMe(context.Background(), nil)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", status.Code(err))
	}
}

func TestIdentityProtoServer_GetMe_NotFound(t *testing.T) {
	s := NewIdentityProtoServer(&stubUserGetter{err: identity.ErrUserNotFound})
	_, err := s.GetMe(context.Background(), &identityv1.GetMeRequest{Gcid: "missing"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("code = %v, want NotFound", status.Code(err))
	}
}

func TestIdentityProtoServer_GetMe_RepoError_Internal(t *testing.T) {
	s := NewIdentityProtoServer(&stubUserGetter{err: errors.New("db down")})
	_, err := s.GetMe(context.Background(), &identityv1.GetMeRequest{Gcid: "x"})
	if status.Code(err) != codes.Internal {
		t.Fatalf("code = %v, want Internal", status.Code(err))
	}
}

func TestIdentityProtoServer_GetMe_NilServer_Internal(t *testing.T) {
	var s *IdentityProtoServer
	_, err := s.GetMe(context.Background(), &identityv1.GetMeRequest{Gcid: "x"})
	if status.Code(err) != codes.Internal {
		t.Fatalf("code = %v, want Internal", status.Code(err))
	}
}
