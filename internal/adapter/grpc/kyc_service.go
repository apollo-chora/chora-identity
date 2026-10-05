// gRPC KYC service handler — thin wrapper over kyc.Repository for
// GetVerificationStatus per chora-contracts/proto/services/identity/v1/kyc_service.proto.
package grpcadapter

import (
	"context"
	"errors"
	"time"

	"github.com/apollo-chora/chora-identity/internal/domain/kyc"
)

// KycStatusResponse mirrors the proto wire shape.
type KycStatusResponse struct {
	VerificationID           string
	Gcid                     string
	Method                   string
	Status                   string
	Provider                 string
	VerifiedAt               *time.Time
	SkillsfutureScopeGranted bool
	RejectionCode            string
	RetryAllowed             bool
	ExpiresAt                *time.Time
}

// GetVerificationStatusRequest mirrors the proto.
type GetVerificationStatusRequest struct {
	Gcid string
}

// KycServer is the gRPC handler bound to a kyc.Repository.
type KycServer struct {
	repo kyc.Repository
}

// NewKycServer wires the handler.
func NewKycServer(repo kyc.Repository) *KycServer { return &KycServer{repo: repo} }

// GetVerificationStatus — server-side handler. Returns ErrNotFound when the
// caller has never initiated a verification.
func (s *KycServer) GetVerificationStatus(ctx context.Context, req *GetVerificationStatusRequest) (*KycStatusResponse, error) {
	if s == nil || s.repo == nil {
		return nil, errors.New("grpc.kyc: server not initialised")
	}
	if req == nil || req.Gcid == "" {
		return nil, errors.New("grpc.kyc: gcid required")
	}
	v, err := s.repo.GetLatestByGcid(ctx, req.Gcid)
	if err != nil {
		return nil, err
	}
	return &KycStatusResponse{
		VerificationID:           v.VerificationID,
		Gcid:                     v.Gcid,
		Method:                   string(v.Method),
		Status:                   string(v.Status),
		Provider:                 v.Provider,
		VerifiedAt:               v.VerifiedAt,
		SkillsfutureScopeGranted: v.SkillsfutureScopeGranted,
		RejectionCode:            v.RejectionCode,
		RetryAllowed:             v.RetryAllowed,
		ExpiresAt:                v.ExpiresAt,
	}, nil
}
