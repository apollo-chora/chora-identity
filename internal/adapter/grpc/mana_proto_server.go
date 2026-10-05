// Package grpcadapter — ManaProtoServer is the canonical wire bridge for
// the chora-contracts-defined ManaService gRPC contract. It wraps the
// handcrafted ManaServer (mana_service.go) + translates between the
// proto-generated types (`identityv1.*`) and the handcrafted wire types.
//
// Why a bridge: the handcrafted ManaServer was written to exercise the
// domain quoter without depending on protoc-gen output (so package tests
// stayed lean). P4+P5 of 2026-05-15 (chora-creation commits d958890c +
// 6ce3a0d9) wired chora-creation's ManaClient against the GENERATED
// `identityv1.ManaServiceClient`. To bind a real gRPC server in
// cmd/server/main.go we now need an implementation that satisfies the
// generated `identityv1.ManaServiceServer` interface — this file.
//
// Per ADR-142 + chora-contracts/proto/services/identity/v1/mana_service.proto.
package grpcadapter

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	identityv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/services/identity/v1"

	mana "github.com/apollo-chora/chora-identity/internal/domain/user_mana"
)

// ManaProtoServer adapts the handcrafted ManaServer to the proto-typed
// `identityv1.ManaServiceServer` interface.
type ManaProtoServer struct {
	identityv1.UnimplementedManaServiceServer
	core *ManaServer
}

// NewManaProtoServer constructs the bridge.
func NewManaProtoServer(core *ManaServer) *ManaProtoServer {
	return &ManaProtoServer{core: core}
}

// DeductMana — proto-typed handler that delegates to the handcrafted
// ManaServer + translates the response back to proto types.
func (s *ManaProtoServer) DeductMana(ctx context.Context, req *identityv1.DeductManaRequest) (*identityv1.DeductManaResponse, error) {
	if s == nil || s.core == nil {
		return nil, errors.New("grpcadapter.ManaProtoServer: not initialised")
	}
	if req == nil {
		return nil, errors.New("grpcadapter.ManaProtoServer: request required")
	}
	wireReq := &DeductManaRequest{
		Gcid:           req.GetGcid(),
		ActionCode:     req.GetActionCode(),
		Units:          req.GetUnits(),
		IdempotencyKey: req.GetIdempotencyKey(),
		RequestID:      req.GetRequestId(),
		TenantID:       req.GetTenantId(),
		DryRun:         req.GetDryRun(),
		Tier:           req.GetTier(),
		Context:        req.GetContext(),
	}
	wireResp, err := s.core.DeductMana(ctx, wireReq)
	if err != nil {
		// An unpriced/unknown action_code is a caller contract error, not a
		// server fault — map to InvalidArgument so the WS-1 metering seam can
		// distinguish "unpriced ⇒ un-metered" from a real infra failure.
		if mana.IsUnknownActionCode(err) {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		return nil, err
	}
	out := &identityv1.DeductManaResponse{
		Success:             wireResp.Success,
		RequiredUnits:       wireResp.RequiredUnits,
		CurrentBalanceUnits: wireResp.CurrentBalanceUnits,
		BalanceAfterUnits:   wireResp.BalanceAfterUnits,
		Refundable:          wireResp.Refundable,
		PerItem:             wireResp.PerItem,
		PriceSource:         wireResp.PriceSource,
	}
	for _, e := range wireResp.Entries {
		out.Entries = append(out.Entries, ledgerWireToProto(e))
	}
	return out, nil
}

// CreditMana — proto-typed handler. Translates the proto ManaSource enum
// to the handcrafted domain Source string + the proto ManaReasonCode to
// the domain Reason string.
func (s *ManaProtoServer) CreditMana(ctx context.Context, req *identityv1.CreditManaRequest) (*identityv1.CreditManaResponse, error) {
	if s == nil || s.core == nil {
		return nil, errors.New("grpcadapter.ManaProtoServer: not initialised")
	}
	if req == nil {
		return nil, errors.New("grpcadapter.ManaProtoServer: request required")
	}
	source, err := protoSourceToString(req.GetSource())
	if err != nil {
		return nil, err
	}
	wireReq := &CreditManaRequest{
		Gcid:                 req.GetGcid(),
		Source:               source,
		Units:                req.GetUnits(),
		Reason:               protoReasonToString(req.GetReason()),
		IdempotencyKey:       req.GetIdempotencyKey(),
		SourceSubscriptionID: req.GetSourceSubscriptionId(),
		SourceTopupID:        req.GetSourceTopupId(),
		SourceAllocationID:   req.GetSourceAllocationId(),
		TenantID:             req.GetTenantId(),
		ReasonText:           req.GetReasonText(),
	}
	// Note: CreditManaRequest in proto does not carry expires_at — that's
	// on the SubsidySlice projection only. Wire CreditManaRequest.ExpiresAt
	// is left nil; the domain quoter handles allocation expiry separately
	// per ADR-142.
	wireResp, err := s.core.CreditMana(ctx, wireReq)
	if err != nil {
		return nil, err
	}
	entry := ledgerWireToProto(wireResp.Entry)
	return &identityv1.CreditManaResponse{
		Entry:             entry,
		BalanceAfterUnits: wireResp.BalanceAfterUnits,
	}, nil
}

// GetBalance — proto-typed handler. Translates the SubsidySlice projection
// into proto SubsidySlice messages.
func (s *ManaProtoServer) GetBalance(ctx context.Context, req *identityv1.GetBalanceRequest) (*identityv1.GetBalanceResponse, error) {
	if s == nil || s.core == nil {
		return nil, errors.New("grpcadapter.ManaProtoServer: not initialised")
	}
	if req == nil {
		return nil, errors.New("grpcadapter.ManaProtoServer: request required")
	}
	wireResp, err := s.core.GetBalance(ctx, &GetBalanceRequest{Gcid: req.GetGcid()})
	if err != nil {
		return nil, err
	}
	out := &identityv1.GetBalanceResponse{
		BalanceUnits:   wireResp.BalanceUnits,
		LifetimeEarned: wireResp.LifetimeEarned,
		LifetimeSpent:  wireResp.LifetimeSpent,
	}
	if wireResp.LastCreditedAt != nil {
		out.LastCreditedAt = timestamppb.New(*wireResp.LastCreditedAt)
	}
	for _, sl := range wireResp.SubsidyBreakdown {
		protoSlice := &identityv1.SubsidySlice{
			TenantId:           sl.TenantID,
			Units:              sl.Units,
			Source:             stringSourceToProto(sl.Source),
			SourceAllocationId: sl.SourceAllocationID,
		}
		if sl.ExpiresAt != nil {
			protoSlice.ExpiresAt = timestamppb.New(*sl.ExpiresAt)
		}
		out.SubsidyBreakdown = append(out.SubsidyBreakdown, protoSlice)
	}
	return out, nil
}

// -----------------------------------------------------------------------------
// Enum <-> string translation
// -----------------------------------------------------------------------------

// protoSourceToString maps the proto enum to the domain Source string. Returns
// an error on MANA_SOURCE_UNSPECIFIED (fail-loud — chora-creation MUST send a
// valid enum or the credit is rejected).
func protoSourceToString(s identityv1.ManaSource) (string, error) {
	switch s {
	case identityv1.ManaSource_MANA_SOURCE_SUBSCRIPTION_GRANT:
		return "subscription_grant", nil
	case identityv1.ManaSource_MANA_SOURCE_TOPUP:
		return "topup", nil
	case identityv1.ManaSource_MANA_SOURCE_PROMO:
		return "promo", nil
	case identityv1.ManaSource_MANA_SOURCE_TENANT_SUBSIDY:
		return "tenant_subsidy", nil
	case identityv1.ManaSource_MANA_SOURCE_REFUND:
		return "refund", nil
	case identityv1.ManaSource_MANA_SOURCE_ROLLOVER:
		return "rollover", nil
	case identityv1.ManaSource_MANA_SOURCE_MINT:
		return "mint", nil
	}
	return "", errors.New("grpcadapter.ManaProtoServer: unspecified or unknown ManaSource")
}

// stringSourceToProto inverts protoSourceToString for response shaping. Maps
// unknown strings to MANA_SOURCE_UNSPECIFIED (defensive — the domain Source
// type is the source-of-truth so a mismatch here is a domain bug).
func stringSourceToProto(s string) identityv1.ManaSource {
	switch s {
	case "subscription_grant":
		return identityv1.ManaSource_MANA_SOURCE_SUBSCRIPTION_GRANT
	case "topup":
		return identityv1.ManaSource_MANA_SOURCE_TOPUP
	case "promo":
		return identityv1.ManaSource_MANA_SOURCE_PROMO
	case "tenant_subsidy":
		return identityv1.ManaSource_MANA_SOURCE_TENANT_SUBSIDY
	case "refund":
		return identityv1.ManaSource_MANA_SOURCE_REFUND
	case "rollover":
		return identityv1.ManaSource_MANA_SOURCE_ROLLOVER
	case "mint":
		return identityv1.ManaSource_MANA_SOURCE_MINT
	}
	return identityv1.ManaSource_MANA_SOURCE_UNSPECIFIED
}

// protoReasonToString maps the proto reason enum to the domain reason
// string. Unknown / unspecified maps to empty (the domain Reason check
// would reject if empty + required — quoter handles).
func protoReasonToString(r identityv1.ManaReasonCode) string {
	switch r {
	case identityv1.ManaReasonCode_MANA_REASON_CODE_SUBSCRIPTION_GRANT:
		return "subscription_grant"
	case identityv1.ManaReasonCode_MANA_REASON_CODE_COMPANION_ACTION:
		return "familiar_action"
	case identityv1.ManaReasonCode_MANA_REASON_CODE_REFUND:
		return "refund"
	case identityv1.ManaReasonCode_MANA_REASON_CODE_ACCOUNT_CLOSURE:
		return "account_closure"
	case identityv1.ManaReasonCode_MANA_REASON_CODE_PROMO:
		return "promo"
	case identityv1.ManaReasonCode_MANA_REASON_CODE_TENANT_SUBSIDY:
		return "tenant_subsidy"
	case identityv1.ManaReasonCode_MANA_REASON_CODE_TOPUP:
		return "topup"
	case identityv1.ManaReasonCode_MANA_REASON_CODE_ROLLOVER:
		return "rollover"
	}
	return ""
}

// stringReasonToProto inverts protoReasonToString for response shaping.
func stringReasonToProto(r string) identityv1.ManaReasonCode {
	switch r {
	case "subscription_grant":
		return identityv1.ManaReasonCode_MANA_REASON_CODE_SUBSCRIPTION_GRANT
	case "familiar_action":
		return identityv1.ManaReasonCode_MANA_REASON_CODE_COMPANION_ACTION
	case "refund":
		return identityv1.ManaReasonCode_MANA_REASON_CODE_REFUND
	case "account_closure":
		return identityv1.ManaReasonCode_MANA_REASON_CODE_ACCOUNT_CLOSURE
	case "promo":
		return identityv1.ManaReasonCode_MANA_REASON_CODE_PROMO
	case "tenant_subsidy":
		return identityv1.ManaReasonCode_MANA_REASON_CODE_TENANT_SUBSIDY
	case "topup":
		return identityv1.ManaReasonCode_MANA_REASON_CODE_TOPUP
	case "rollover":
		return identityv1.ManaReasonCode_MANA_REASON_CODE_ROLLOVER
	}
	return identityv1.ManaReasonCode_MANA_REASON_CODE_UNSPECIFIED
}

// ledgerWireToProto translates the handcrafted LedgerEntry wire type to
// the proto LedgerEntry message.
func ledgerWireToProto(e LedgerEntry) *identityv1.LedgerEntry {
	out := &identityv1.LedgerEntry{
		EntryId:              e.EntryID,
		Gcid:                 e.Gcid,
		Direction:            e.Direction,
		Units:                e.Units,
		Reason:               stringReasonToProto(e.Reason),
		SourceSubscriptionId: e.SourceSubscriptionID,
		SourceTopupId:        e.SourceTopupID,
		SourceAllocationId:   e.SourceAllocationID,
		ActionCode:           e.ActionCode,
		BalanceAfterUnits:    e.BalanceAfterUnits,
	}
	if !e.RecordedAt.IsZero() {
		out.RecordedAt = timestamppb.New(e.RecordedAt)
	}
	return out
}
