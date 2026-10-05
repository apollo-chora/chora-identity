// Package grpcadapter implements the gRPC service-side handlers for the
// per-user economy. The full gRPC binding (`grpc.Server.RegisterService`)
// is wired at cmd/server with `grpc-go` once protoc-gen-go-grpc has run
// against `chora-contracts/proto/services/identity/v1/mana_service.proto`.
//
// This file exposes Go-native handler signatures that match the wire
// shapes 1:1 (DeductMana / CreditMana / GetBalance) so production wiring
// is a thin shim over these.
//
// Hexagonal: this adapter depends on the user_mana domain (Quoter +
// types) and the events.Publisher port. No infrastructure imports leak
// into the domain.
package grpcadapter

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/apollo-chora/chora-identity/internal/adapter/events"
	mana "github.com/apollo-chora/chora-identity/internal/domain/user_mana"
)

// -----------------------------------------------------------------------------
// Wire types — mirror chora-contracts/proto/services/identity/v1/mana_service.proto
// (handcrafted to allow domain testing without depending on generated code).
// -----------------------------------------------------------------------------

// LedgerEntry projection on the wire.
type LedgerEntry struct {
	EntryID              string
	Gcid                 string
	Direction            int32 // 1=credit, 2=debit, 3=mint, 4=refund, 5=rollover
	Units                int64
	Reason               string
	SourceSubscriptionID string
	SourceTopupID        string
	SourceAllocationID   string
	ActionCode           string
	BalanceAfterUnits    int64
	RecordedAt           time.Time
}

// SubsidySlice projection on the wire.
type SubsidySlice struct {
	TenantID           string
	Units              int64
	Source             string
	ExpiresAt          *time.Time
	SourceAllocationID string
}

// DeductManaRequest mirrors the proto.
type DeductManaRequest struct {
	Gcid           string
	ActionCode     string
	Units          int64
	IdempotencyKey string
	RequestID      string
	TenantID       string
	// DryRun resolves cost + checks affordability without debiting (WS-1
	// metering pre-flight gate). On affordable: Success=true, no entries. On
	// shortfall: Success=false + RequiredUnits + CurrentBalanceUnits.
	DryRun bool
	// Tier + Context are the ADR-178 price-plan resolution axes (FU-4(b)). Tier
	// is the BACKLOG LLM-tier selector; Context carries item_count for per_item
	// (× N) batch pricing. Both threaded into the units==0 resolution.
	Tier    string
	Context map[string]string
}

// DeductManaResponse mirrors the proto.
type DeductManaResponse struct {
	Success             bool
	RequiredUnits       int64
	CurrentBalanceUnits int64
	Entries             []LedgerEntry
	BalanceAfterUnits   int64
	// Resolved price-plan metadata (ADR-178 §2.1) — set on the units==0 path.
	Refundable  bool
	PerItem     bool
	PriceSource string
}

// CreditManaRequest mirrors the proto.
type CreditManaRequest struct {
	Gcid                 string
	Source               string // "subscription_grant" | "topup" | "promo" | "tenant_subsidy" | "refund" | "rollover" | "mint"
	Units                int64
	Reason               string
	IdempotencyKey       string
	SourceSubscriptionID string
	SourceTopupID        string
	SourceAllocationID   string
	TenantID             string
	ReasonText           string
	ExpiresAt            *time.Time
}

// CreditManaResponse mirrors the proto.
type CreditManaResponse struct {
	Entry             LedgerEntry
	BalanceAfterUnits int64
}

// GetBalanceRequest mirrors the proto.
type GetBalanceRequest struct {
	Gcid string
}

// GetBalanceResponse mirrors the proto.
type GetBalanceResponse struct {
	BalanceUnits     int64
	LifetimeEarned   int64
	LifetimeSpent    int64
	SubsidyBreakdown []SubsidySlice
	LastCreditedAt   *time.Time
}

// -----------------------------------------------------------------------------
// ManaServer — gRPC service handler
// -----------------------------------------------------------------------------

// ManaServer is the gRPC handler bound to the mana.Quoter + an optional
// EconomyPublisher (for chora.identity.user_mana.* event emission).
type ManaServer struct {
	quoter    *mana.Quoter
	store     mana.Store
	publisher *events.EconomyPublisher
}

// NewManaServer wires the handler.
func NewManaServer(quoter *mana.Quoter, store mana.Store, publisher *events.EconomyPublisher) *ManaServer {
	return &ManaServer{quoter: quoter, store: store, publisher: publisher}
}

// DeductMana — server-side handler.
func (s *ManaServer) DeductMana(ctx context.Context, req *DeductManaRequest) (*DeductManaResponse, error) {
	if s == nil || s.quoter == nil {
		return nil, errors.New("grpc.mana: server not initialised")
	}
	if req == nil {
		return nil, errors.New("grpc.mana: request required")
	}
	res, err := s.quoter.DeductMana(ctx, mana.DeductInput{
		Gcid:           req.Gcid,
		ActionCode:     req.ActionCode,
		Units:          req.Units,
		IdempotencyKey: req.IdempotencyKey,
		RequestID:      req.RequestID,
		TenantID:       req.TenantID,
		DryRun:         req.DryRun,
		Tier:           req.Tier,
		Context:        req.Context,
	})
	if mana.IsInsufficientBalance(err) {
		// Surface upsell context. On a catalogue-priced debit (req.Units==0)
		// the resolved cost + available balance ride on the typed error, so the
		// upsell shows the real required amount rather than 0.
		required := req.Units
		bal := int64(0)
		var ibe *mana.InsufficientBalanceError
		if errors.As(err, &ibe) {
			required = ibe.RequiredUnits
			bal = ibe.AvailableUnits
		} else if s.store != nil {
			if got, gerr := s.store.GetMana(ctx, req.Gcid); gerr == nil && got != nil {
				bal = got.BalanceUnits
			}
		}
		return &DeductManaResponse{
			Success:             false,
			RequiredUnits:       required,
			CurrentBalanceUnits: bal,
		}, nil
	}
	if err != nil {
		return nil, err
	}

	entries := make([]LedgerEntry, 0, len(res.Entries))
	for _, e := range res.Entries {
		entries = append(entries, ledgerToWire(e))
		// Emit per-debit event when not replayed.
		if !res.Replayed && s.publisher != nil {
			env := events.NewEnvelope(req.TenantID, req.Gcid, traceparentFromCtx(ctx), "")
			env.IdempotencyKey = e.IdempotencyKey
			_ = s.publisher.PublishManaDebited(env, e)
		}
	}
	return &DeductManaResponse{
		Success:             true,
		Entries:             entries,
		BalanceAfterUnits:   res.BalanceAfterUnits,
		CurrentBalanceUnits: res.BalanceAfterUnits,
		Refundable:          res.Refundable,
		PerItem:             res.PerItem,
		PriceSource:         res.PriceSource,
	}, nil
}

// CreditMana — server-side handler.
func (s *ManaServer) CreditMana(ctx context.Context, req *CreditManaRequest) (*CreditManaResponse, error) {
	if s == nil || s.quoter == nil {
		return nil, errors.New("grpc.mana: server not initialised")
	}
	if req == nil {
		return nil, errors.New("grpc.mana: request required")
	}
	source := mana.Source(req.Source)
	if !source.Valid() {
		return nil, errors.New("grpc.mana: invalid source")
	}
	res, err := s.quoter.CreditMana(ctx, mana.CreditInput{
		Gcid:                 req.Gcid,
		Source:               source,
		Units:                req.Units,
		Reason:               mana.Reason(req.Reason),
		IdempotencyKey:       req.IdempotencyKey,
		SourceSubscriptionID: req.SourceSubscriptionID,
		SourceTopupID:        req.SourceTopupID,
		SourceAllocationID:   req.SourceAllocationID,
		TenantID:             req.TenantID,
		ReasonText:           req.ReasonText,
		ExpiresAt:            req.ExpiresAt,
	})
	if err != nil {
		return nil, err
	}
	if !res.Replayed && s.publisher != nil {
		env := events.NewEnvelope(req.TenantID, req.Gcid, traceparentFromCtx(ctx), "")
		env.IdempotencyKey = res.Entry.IdempotencyKey
		_ = s.publisher.PublishManaCredited(env, res.Entry)
	}
	return &CreditManaResponse{
		Entry:             ledgerToWire(res.Entry),
		BalanceAfterUnits: res.BalanceAfterUnits,
	}, nil
}

// GetBalance — server-side handler.
func (s *ManaServer) GetBalance(ctx context.Context, req *GetBalanceRequest) (*GetBalanceResponse, error) {
	if s == nil || s.quoter == nil {
		return nil, errors.New("grpc.mana: server not initialised")
	}
	if req == nil {
		return nil, errors.New("grpc.mana: request required")
	}
	bal, slices, err := s.quoter.Breakdown(ctx, req.Gcid)
	if err != nil {
		return nil, err
	}
	out := &GetBalanceResponse{BalanceUnits: bal}
	for _, sl := range slices {
		out.SubsidyBreakdown = append(out.SubsidyBreakdown, SubsidySlice{
			TenantID:           sl.TenantID,
			Units:              sl.Units,
			Source:             string(sl.Source),
			ExpiresAt:          sl.ExpiresAt,
			SourceAllocationID: sl.SourceAllocationID,
		})
	}
	if s.store != nil {
		if got, gerr := s.store.GetMana(ctx, req.Gcid); gerr == nil && got != nil {
			out.LifetimeEarned = got.LifetimeEarned
			out.LifetimeSpent = got.LifetimeSpent
			out.LastCreditedAt = got.LastCreditedAt
		}
	}
	return out, nil
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func ledgerToWire(e *mana.LedgerEntry) LedgerEntry {
	return LedgerEntry{
		EntryID:              e.EntryID,
		Gcid:                 e.Gcid,
		Direction:            directionCode(e.Direction),
		Units:                e.Units,
		Reason:               string(e.Reason),
		SourceSubscriptionID: e.SourceSubscriptionID,
		SourceTopupID:        e.SourceTopupID,
		SourceAllocationID:   e.SourceAllocationID,
		ActionCode:           e.SourceActionID,
		BalanceAfterUnits:    e.BalanceAfterUnits,
		RecordedAt:           e.RecordedAt,
	}
}

func directionCode(d mana.Direction) int32 {
	switch d {
	case mana.DirectionCredit:
		return 1
	case mana.DirectionDebit:
		return 2
	case mana.DirectionMint:
		return 3
	case mana.DirectionRefund:
		return 4
	case mana.DirectionRollover:
		return 5
	}
	return 0
}

// traceparentFromCtx extracts the W3C traceparent string from a context.
// Real wiring (M12+) reads this from incoming gRPC metadata; the dev shim
// tolerates a missing key.
func traceparentFromCtx(ctx context.Context) string {
	if v, ok := ctx.Value(traceparentCtxKey{}).(string); ok && strings.TrimSpace(v) != "" {
		return v
	}
	return "00-00000000000000000000000000000000-0000000000000000-00"
}

// traceparentCtxKey is the typed context key used by tests + the cmd/server
// wiring to inject a synthetic traceparent on inbound gRPC messages.
type traceparentCtxKey struct{}

// WithTraceparent stamps a traceparent on a context for downstream Pub/Sub
// envelope emission.
func WithTraceparent(ctx context.Context, tp string) context.Context {
	return context.WithValue(ctx, traceparentCtxKey{}, tp)
}
