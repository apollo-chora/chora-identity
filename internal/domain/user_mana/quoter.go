// Package user_mana — the Quoter domain service implements Spend FIFO
// (subsidy allocations first by ExpiresAt ASC NULLS LAST then AllocatedAt
// ASC, then personal balance) per ADR-142.
package user_mana

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Store is the persistence port the Quoter depends on. It composes the
// Mana, Allocation, and Ledger storage. The HTTP/gRPC adapter wires an
// implementation; tests use NewInMemoryStore.
type Store interface {
	GetMana(ctx context.Context, gcid string) (*UserMana, error)
	SaveMana(ctx context.Context, m *UserMana) error
	AppendLedger(ctx context.Context, e *LedgerEntry) error
	ListLedger(ctx context.Context, filter LedgerFilter) ([]*LedgerEntry, error)
	FindLedgerByIdempotencyKey(ctx context.Context, gcid, key string) ([]*LedgerEntry, error)
	ListAllocations(ctx context.Context, gcid string) ([]*Allocation, error)
	SaveAllocation(ctx context.Context, gcid string, a *Allocation) error
	UpdateAllocationRemaining(ctx context.Context, gcid, allocationID string, remaining int64) error
	// CreditWallet applies a personal-balance credit and the matching ledger
	// row. Implementations MUST make the wallet write and the ledger insert
	// ATOMIC (one transaction) so a crash cannot leave balance != ledger, and
	// MUST honour (gcid, idempotency_key): a repeat call returns Replayed=true
	// without crediting again — but ONLY when the replayed operation matches the
	// incoming one (see CreditWalletMatchesLedger); a reused key describing a
	// different operation MUST fail with ErrIdempotencyConflict.
	//
	// When in.DemoGrantCaps is set the demo-grant caps are enforced INSIDE the
	// same transaction (see DemoGrantCaps).
	CreditWallet(ctx context.Context, in CreditWalletInput) (*CreditWalletResult, error)
	// DemoGrantTotalUnits totals the `demo_grant` units recorded across ALL
	// GCIDs. This is the cross-user budget axis: an RLS-scoped implementation
	// can only see the caller's own rows, so the pg adapter reads it through a
	// SECURITY DEFINER helper (migration 0043). It is deliberately restricted to
	// the demo-grant reason — it is not a general per-reason aggregation port —
	// and MUST fail closed: an implementation whose elevated reader is
	// unavailable returns an error, never a zero total.
	DemoGrantTotalUnits(ctx context.Context) (int64, error)
}

// Quoter is the domain service for credit/debit Mana operations.
type Quoter struct {
	store    Store
	pricer   Pricer
	resolver PriceResolver
}

// QuoterOption configures an optional Quoter dependency.
type QuoterOption func(*Quoter)

// WithPricer attaches the pricing-catalogue resolution port. Required for the
// WS-1 umbrella-metering path (catalogue-priced DeductMana with Units==0);
// omitted callers (credit-only paths, tests using explicit Units) need no
// Pricer.
func WithPricer(p Pricer) QuoterOption { return func(q *Quoter) { q.pricer = p } }

// WithPriceResolver attaches the richer ADR-178 price-plan resolution port. When
// wired it SUPERSEDES WithPricer for the units==0 path — resolving tenant/tier/
// context-aware prices + per_item/refundable/price_source metadata (FU-4(b)).
func WithPriceResolver(r PriceResolver) QuoterOption { return func(q *Quoter) { q.resolver = r } }

// NewQuoter wires the quoter to a store, plus any options (e.g. WithPricer).
func NewQuoter(store Store, opts ...QuoterOption) *Quoter {
	q := &Quoter{store: store}
	for _, opt := range opts {
		opt(q)
	}
	return q
}

// DeductInput — input for DeductMana.
type DeductInput struct {
	Gcid           string
	ActionCode     string
	Units          int64
	IdempotencyKey string
	RequestID      string
	TenantID       string
	// DryRun resolves cost + checks affordability WITHOUT writing a ledger row
	// or mutating the wallet — the WS-1 metering pre-flight gate. On success it
	// returns the current available balance; on shortfall it returns
	// *InsufficientBalanceError carrying the resolved required + available units.
	DryRun bool
	// Tier is the optional ADR-178 LLM-tier selector ('low'|'high'). "" (today's
	// behaviour for every action) = tier-agnostic. Threaded into the price-plan
	// resolver on the units==0 path; ignored unless the action is tier_aware.
	Tier string
	// Context is the forward-compatible resolution context (ADR-178 §A4). The
	// only load-bearing key today is "item_count": for a per_item action the
	// resolved per-unit cost is multiplied by it (× N batch pricing) server-side
	// — the sole per_item action is question_authoring_batch_per_item.
	Context map[string]string
}

// DeductResult — output for DeductMana (one-or-more ledger rows + new balance).
type DeductResult struct {
	Entries           []*LedgerEntry
	BalanceAfterUnits int64
	Replayed          bool
	// Resolved price-plan metadata (ADR-178), set on the units==0 path so the
	// meter home / gRPC caller can decide refund-on-failure (Refundable) and see
	// which precedence rung priced the action (PriceSource). PerItem echoes the
	// action def (the × item_count multiply was already applied to Entries).
	// All zero-valued on an explicit Units>0 debit (no resolution occurred).
	Refundable  bool
	PerItem     bool
	PriceSource string
}

// DeductMana applies a Spend FIFO debit: subsidies first (by ExpiresAt ASC
// NULLS LAST, then AllocatedAt ASC), then personal balance.
//
// Idempotent on (gcid, idempotency_key): a repeat call returns the same
// result without re-debiting.
func (q *Quoter) DeductMana(ctx context.Context, in DeductInput) (result *DeductResult, retErr error) {
	if err := validateGcid(in.Gcid); err != nil {
		return nil, err
	}
	if in.Units < 0 {
		return nil, fmt.Errorf("user_mana: deduct units must be >= 0; got %d", in.Units)
	}
	if strings.TrimSpace(in.IdempotencyKey) == "" {
		return nil, errors.New("user_mana: idempotency_key required")
	}

	// Resolve the debit amount. Units>0 is an explicit caller-priced debit
	// (legacy ad-hoc debit sites + tests); Units==0 is the umbrella-metering
	// path — resolve the price for ActionCode (ADR-142 §4, ADR-178 §2).
	//
	// ADR-178 / FU-4(b): when a PriceResolver is wired it supersedes the flat
	// Pricer — it resolves TENANT/TIER/CONTEXT-aware (so an H+ price-plan
	// override actually applies) and returns the per_item / refundable /
	// price_source metadata. For a per_item action the resolved per-unit cost is
	// multiplied by context.item_count (× N batch pricing) server-side. The
	// metadata is stamped onto every successful result by the defer below.
	units := in.Units
	var meta Resolved
	if units == 0 {
		if q.resolver != nil {
			r, err := q.resolver.Resolve(ctx, ResolveInput{
				ActionCode: in.ActionCode,
				TenantID:   in.TenantID,
				Tier:       in.Tier,
				Context:    in.Context,
			})
			if err != nil {
				return nil, err
			}
			meta = r
			units = r.EffectiveTotal(itemCountFromContext(in.Context))
		} else {
			cost, err := q.resolveCost(ctx, in.ActionCode)
			if err != nil {
				return nil, err
			}
			units = cost
		}
	}

	// Stamp the resolved price-plan metadata onto whatever successful result a
	// return path below produces (dry-run quote, idempotent replay, free-action,
	// or a real debit). Zero-valued meta (explicit Units>0 debit) is a no-op.
	defer func() {
		if retErr == nil && result != nil {
			result.Refundable = meta.Refundable
			result.PerItem = meta.PerItem
			result.PriceSource = meta.Source
		}
	}()

	// Dry-run pre-flight gate (WS-1): resolve-and-check affordability without
	// any write. Runs before the idempotency replay + debit so it never mutates.
	if in.DryRun {
		return q.quote(ctx, in.Gcid, units)
	}

	// Idempotency replay short-circuit.
	if existing, err := q.store.FindLedgerByIdempotencyKey(ctx, in.Gcid, in.IdempotencyKey); err == nil && len(existing) > 0 {
		mana, _ := q.store.GetMana(ctx, in.Gcid)
		var bal int64
		if mana != nil {
			bal = mana.BalanceUnits
		}
		return &DeductResult{Entries: existing, BalanceAfterUnits: bal, Replayed: true}, nil
	}

	// Free action (catalogue cost 0 — e.g. summon_familiar /
	// daily_dose_deterministic): no debit, no ledger row, balance unchanged.
	if units == 0 {
		return q.zeroCostResult(ctx, in.Gcid)
	}

	mana, err := q.store.GetMana(ctx, in.Gcid)
	if err != nil {
		return nil, err
	}
	if mana == nil {
		mana = NewUserMana(in.Gcid)
	}

	allocs, err := q.store.ListAllocations(ctx, in.Gcid)
	if err != nil {
		return nil, err
	}
	subsidyTotal := int64(0)
	for _, a := range allocs {
		subsidyTotal += a.RemainingUnits
	}
	if subsidyTotal+mana.BalanceUnits < units {
		return nil, &InsufficientBalanceError{
			RequiredUnits:  units,
			AvailableUnits: subsidyTotal + mana.BalanceUnits,
		}
	}

	// FIFO sort: ExpiresAt ASC NULLS LAST, then AllocatedAt ASC.
	sort.SliceStable(allocs, func(i, j int) bool {
		ai, aj := allocs[i], allocs[j]
		switch {
		case ai.ExpiresAt == nil && aj.ExpiresAt != nil:
			return false
		case ai.ExpiresAt != nil && aj.ExpiresAt == nil:
			return true
		case ai.ExpiresAt != nil && aj.ExpiresAt != nil:
			if !ai.ExpiresAt.Equal(*aj.ExpiresAt) {
				return ai.ExpiresAt.Before(*aj.ExpiresAt)
			}
		}
		return ai.AllocatedAt.Before(aj.AllocatedAt)
	})

	remaining := units
	entries := make([]*LedgerEntry, 0, len(allocs)+1)

	for _, a := range allocs {
		if remaining == 0 {
			break
		}
		if a.RemainingUnits == 0 {
			continue
		}
		take := a.RemainingUnits
		if take > remaining {
			take = remaining
		}
		// Apply against the personal-balance check by updating allocation; the
		// allocation drain doesn't touch UserMana.balance_units (it's "outside").
		// However, the user-visible balance MUST reflect the drain — so the
		// total balance reported includes subsidies + personal. We handle this
		// by mirroring allocation debits on UserMana.
		if err := mana.Debit(0); err != nil {
			// no-op; placeholder to keep aggregate "touched"
		}
		// We can't actually subtract from mana.BalanceUnits here because the
		// subsidy has its own unit pool — but we MUST keep the UserMana
		// aggregate's lifetime_spent in sync.
		mana.LifetimeSpent += take

		newRem := a.RemainingUnits - take
		if err := q.store.UpdateAllocationRemaining(ctx, in.Gcid, a.AllocationID, newRem); err != nil {
			return nil, err
		}
		a.RemainingUnits = newRem

		// Compute provisional balance_after as remaining subsidy total + personal.
		runningSubsidy := int64(0)
		for _, b := range allocs {
			runningSubsidy += b.RemainingUnits
		}
		balAfter := runningSubsidy + mana.BalanceUnits

		e, err := NewLedgerEntry(NewLedgerParams{
			Gcid:               in.Gcid,
			Direction:          DirectionDebit,
			Units:              take,
			Reason:             ReasonFamiliarAction,
			SourceActionID:     in.ActionCode,
			SourceAllocationID: a.AllocationID,
			IdempotencyKey:     in.IdempotencyKey,
			RequestID:          in.RequestID,
			BalanceAfterUnits:  balAfter,
		})
		if err != nil {
			return nil, err
		}
		if err := q.store.AppendLedger(ctx, e); err != nil {
			return nil, err
		}
		entries = append(entries, e)
		remaining -= take
	}

	if remaining > 0 {
		// Drain personal balance.
		// Roll back the lifetime_spent inflation we added during subsidy loop;
		// mana.Debit will increment it cleanly here.
		// (Subsidy drains don't actually touch mana.LifetimeSpent — refactor by
		// tracking explicitly.)
		// Restore lifetime_spent to pre-subsidy state, then apply Debit.
		mana.LifetimeSpent -= (units - remaining)
		if err := mana.Debit(remaining); err != nil {
			return nil, err
		}
		// Bring lifetime_spent back to total spent for this op.
		mana.LifetimeSpent += (units - remaining)

		runningSubsidy := int64(0)
		for _, b := range allocs {
			runningSubsidy += b.RemainingUnits
		}
		balAfter := runningSubsidy + mana.BalanceUnits

		e, err := NewLedgerEntry(NewLedgerParams{
			Gcid:              in.Gcid,
			Direction:         DirectionDebit,
			Units:             remaining,
			Reason:            ReasonFamiliarAction,
			SourceActionID:    in.ActionCode,
			IdempotencyKey:    in.IdempotencyKey,
			RequestID:         in.RequestID,
			BalanceAfterUnits: balAfter,
		})
		if err != nil {
			return nil, err
		}
		if err := q.store.AppendLedger(ctx, e); err != nil {
			return nil, err
		}
		entries = append(entries, e)
		remaining = 0
	}

	if err := q.store.SaveMana(ctx, mana); err != nil {
		return nil, err
	}

	finalSubsidy := int64(0)
	for _, a := range allocs {
		finalSubsidy += a.RemainingUnits
	}
	return &DeductResult{
		Entries:           entries,
		BalanceAfterUnits: finalSubsidy + mana.BalanceUnits,
	}, nil
}

// resolveCost looks up the catalogue price for a units==0 (catalogue-priced)
// debit. Returns ErrUnknownActionCode for an empty/unpriced code; an explicit
// config error when no Pricer is wired (a units==0 debit must never be a silent
// free pass).
// itemCountFromContext parses the per-item batch multiplier from the resolution
// context (ADR-178 §A4). Returns 1 (a single item) when absent, empty, or
// unparseable / < 1 — a missing or garbage count must NEVER zero the charge.
func itemCountFromContext(c map[string]string) int64 {
	if c == nil {
		return 1
	}
	n, err := strconv.ParseInt(strings.TrimSpace(c["item_count"]), 10, 64)
	if err != nil || n < 1 {
		return 1
	}
	return n
}

func (q *Quoter) resolveCost(ctx context.Context, actionCode string) (int64, error) {
	code := strings.TrimSpace(actionCode)
	if code == "" {
		return 0, fmt.Errorf("%w: empty action_code on units==0 debit", ErrUnknownActionCode)
	}
	if q.pricer == nil {
		return 0, fmt.Errorf("user_mana: catalogue-priced debit (units==0, action_code=%q) requires a Pricer; none configured", code)
	}
	cost, err := q.pricer.CostForAction(ctx, code)
	if err != nil {
		return 0, err
	}
	if cost < 0 {
		return 0, fmt.Errorf("user_mana: catalogue cost for %q is negative (%d)", code, cost)
	}
	return cost, nil
}

// quote computes affordability for a resolved cost without any write. Returns
// the current available (subsidy + personal) balance on success, or
// *InsufficientBalanceError (resolved required + available) on shortfall.
func (q *Quoter) quote(ctx context.Context, gcid string, units int64) (*DeductResult, error) {
	mana, err := q.store.GetMana(ctx, gcid)
	if err != nil {
		return nil, err
	}
	available := int64(0)
	if mana != nil {
		available = mana.BalanceUnits
	}
	allocs, err := q.store.ListAllocations(ctx, gcid)
	if err != nil {
		return nil, err
	}
	for _, a := range allocs {
		available += a.RemainingUnits
	}
	if available < units {
		return nil, &InsufficientBalanceError{RequiredUnits: units, AvailableUnits: available}
	}
	return &DeductResult{Entries: nil, BalanceAfterUnits: available}, nil
}

// zeroCostResult returns a no-op success for a free action (catalogue cost 0):
// no ledger row, balance reported as subsidy + personal.
func (q *Quoter) zeroCostResult(ctx context.Context, gcid string) (*DeductResult, error) {
	mana, err := q.store.GetMana(ctx, gcid)
	if err != nil {
		return nil, err
	}
	bal := int64(0)
	if mana != nil {
		bal = mana.BalanceUnits
	}
	allocs, err := q.store.ListAllocations(ctx, gcid)
	if err != nil {
		return nil, err
	}
	for _, a := range allocs {
		bal += a.RemainingUnits
	}
	return &DeductResult{Entries: nil, BalanceAfterUnits: bal}, nil
}

// CreditInput — input for CreditMana.
type CreditInput struct {
	Gcid                 string
	Source               Source
	Units                int64
	Reason               Reason
	IdempotencyKey       string
	SourceSubscriptionID string
	SourceTopupID        string
	SourceAllocationID   string
	TenantID             string
	ExpiresAt            *time.Time
	ReasonText           string
}

// CreditResult — output for CreditMana.
type CreditResult struct {
	Entry             *LedgerEntry
	BalanceAfterUnits int64
	Replayed          bool
}

// CreditWalletInput is the input for an atomic wallet credit (Store.CreditWallet).
//
// It is the persistence-layer counterpart of CreditInput for the paths that
// touch ONLY the personal balance — mints, grants, promos, refunds, rollovers.
// The tenant-subsidy path keeps using CreditInput because it also writes an
// Allocation row outside the wallet.
type CreditWalletInput struct {
	Gcid                 string
	Units                int64
	Direction            Direction
	Reason               Reason
	IdempotencyKey       string
	RequestID            string
	SourceSubscriptionID string
	SourceActionID       string
	SourceAllocationID   string
	SourceTopupID        string
	// DemoGrantCaps, when non-nil, makes the credit enforce the DEMO-GRANT caps
	// in the same transaction that writes the wallet and the ledger row. nil for
	// every other credit path (and for the seed grant, whose grants are one-time
	// account provisioning and must NOT consume the interactive demo budget).
	DemoGrantCaps *DemoGrantCaps
}

// DemoGrantCaps are the demo-grant limits enforced transactionally by
// CreditWallet. Both are reserved/consumed counters, not aggregations over the
// ledger, so the check and the consumption are serialized by the row locks the
// adapter takes before crediting.
type DemoGrantCaps struct {
	// MaxPerGcid caps the number of INTERACTIVE demo grants one GCID may claim
	// (0 = uncapped).
	MaxPerGcid int64
	// BudgetUnits caps the platform-wide total units the interactive demo grant
	// may mint (0 = uncapped).
	BudgetUnits int64
}

// CreditWalletResult is the outcome of an atomic wallet credit.
type CreditWalletResult struct {
	// Wallet is the post-credit wallet snapshot (nil only on a replay of a
	// grant whose wallet row has since been removed — not reachable today).
	Wallet *UserMana
	// Entry is the appended ledger row, or the pre-existing row on a replay.
	Entry *LedgerEntry
	// BalanceAfterUnits is subsidy total + personal balance, matching
	// Entry.BalanceAfterUnits.
	BalanceAfterUnits int64
	// Replayed reports that the idempotency key had already been applied and
	// that NO credit was made.
	Replayed bool
}

// Demo-grant and idempotency errors. They are sentinels so the HTTP adapter can
// map them to 429/409 instead of a generic 500.
var (
	// ErrDemoGrantLimitReached — the per-GCID demo grant cap is exhausted.
	ErrDemoGrantLimitReached = errors.New("user_mana: demo grant limit reached for this gcid")
	// ErrDemoGrantBudgetExhausted — the platform-wide demo grant budget is
	// exhausted.
	ErrDemoGrantBudgetExhausted = errors.New("user_mana: demo grant budget exhausted")
	// ErrIdempotencyConflict — the idempotency key was already used for a
	// DIFFERENT operation (see CreditWalletMatchesLedger).
	ErrIdempotencyConflict = errors.New("user_mana: idempotency key reused with a different operation")
)

// ValidateCreditWalletInput enforces the invariants every CreditWallet
// implementation relies on, so the pg and in-memory adapters reject the same
// inputs for the same reasons.
func ValidateCreditWalletInput(in CreditWalletInput) error {
	if err := validateGcid(in.Gcid); err != nil {
		return err
	}
	if err := validateUnits(in.Units); err != nil {
		return err
	}
	if !in.Direction.Valid() {
		return fmt.Errorf("user_mana: invalid direction %q", in.Direction)
	}
	if !in.Reason.Valid() {
		return fmt.Errorf("user_mana: invalid reason %q", in.Reason)
	}
	if strings.TrimSpace(in.IdempotencyKey) == "" {
		return errors.New("user_mana: idempotency_key required")
	}
	if c := in.DemoGrantCaps; c != nil && (c.MaxPerGcid < 0 || c.BudgetUnits < 0) {
		return fmt.Errorf("user_mana: demo grant caps must be >= 0; got max_per_gcid=%d budget=%d",
			c.MaxPerGcid, c.BudgetUnits)
	}
	return nil
}

// CreditWalletMatchesLedger reports whether the ledger entry e records exactly
// the operation in describes.
//
// A (gcid, idempotency_key) replay is only valid when the ORIGINAL operation
// matches the incoming one. Reusing a key with a different amount, direction,
// reason or source identifier is an idempotency CONFLICT, never a successful
// replay. RequestID is excluded: it is a per-request trace id, so a legitimate
// retry carries a different one.
func CreditWalletMatchesLedger(e *LedgerEntry, in CreditWalletInput) bool {
	if e == nil {
		return false
	}
	return e.Units == in.Units &&
		e.Direction == in.Direction &&
		e.Reason == in.Reason &&
		e.SourceSubscriptionID == in.SourceSubscriptionID &&
		e.SourceActionID == in.SourceActionID &&
		e.SourceAllocationID == in.SourceAllocationID &&
		e.SourceTopupID == in.SourceTopupID
}

// CreditMana adds units to the user's wallet. For Source=tenant_subsidy a
// new Allocation is also stored so the FIFO Quoter can drain it later.
//
// Idempotent on (gcid, idempotency_key).
func (q *Quoter) CreditMana(ctx context.Context, in CreditInput) (*CreditResult, error) {
	if err := validateGcid(in.Gcid); err != nil {
		return nil, err
	}
	if err := validateUnits(in.Units); err != nil {
		return nil, err
	}
	if !in.Source.Valid() {
		return nil, fmt.Errorf("user_mana: invalid source %q", in.Source)
	}
	if !in.Reason.Valid() {
		return nil, fmt.Errorf("user_mana: invalid reason %q", in.Reason)
	}
	if strings.TrimSpace(in.IdempotencyKey) == "" {
		return nil, errors.New("user_mana: idempotency_key required")
	}

	if existing, err := q.store.FindLedgerByIdempotencyKey(ctx, in.Gcid, in.IdempotencyKey); err == nil && len(existing) > 0 {
		mana, _ := q.store.GetMana(ctx, in.Gcid)
		allocs, _ := q.store.ListAllocations(ctx, in.Gcid)
		bal := int64(0)
		if mana != nil {
			bal = mana.BalanceUnits
		}
		for _, a := range allocs {
			bal += a.RemainingUnits
		}
		return &CreditResult{Entry: existing[0], BalanceAfterUnits: bal, Replayed: true}, nil
	}

	mana, err := q.store.GetMana(ctx, in.Gcid)
	if err != nil {
		return nil, err
	}
	if mana == nil {
		mana = NewUserMana(in.Gcid)
	}

	direction := DirectionCredit
	if in.Source == SourceMint {
		direction = DirectionMint
	} else if in.Source == SourceRefund {
		direction = DirectionRefund
	} else if in.Source == SourceRollover {
		direction = DirectionRollover
	}

	if in.Source == SourceTenantSubsidy {
		// Subsidy goes into a separate Allocation; UserMana lifetime_earned is
		// still incremented for analytics parity.
		alloc := &Allocation{
			AllocationID:   in.SourceAllocationID,
			TenantID:       in.TenantID,
			RemainingUnits: in.Units,
			ExpiresAt:      in.ExpiresAt,
			AllocatedAt:    time.Now().UTC(),
		}
		if alloc.AllocationID == "" {
			alloc.AllocationID = newUUIDv7()
		}
		if err := q.store.SaveAllocation(ctx, in.Gcid, alloc); err != nil {
			return nil, err
		}
		mana.LifetimeEarned, err = CheckedAddUnits(mana.LifetimeEarned, in.Units)
		if err != nil {
			return nil, err
		}
		now := time.Now().UTC()
		mana.LastCreditedAt = &now
		// touch version
		mana.UpdatedAt = now
		mana.Version++

		// The subsidy is a separate Allocation pool, NOT personal balance, so
		// it does not go through CreditWallet. SaveMana + AppendLedger stay
		// separate here (two-table projection, not a single-account mutation).
		if err := q.store.SaveMana(ctx, mana); err != nil {
			return nil, err
		}
		allocs, _ := q.store.ListAllocations(ctx, in.Gcid)
		subsidy := int64(0)
		for _, a := range allocs {
			subsidy, err = CheckedAddUnits(subsidy, a.RemainingUnits)
			if err != nil {
				return nil, err
			}
		}
		balAfter, err := CheckedAddUnits(subsidy, mana.BalanceUnits)
		if err != nil {
			return nil, err
		}
		e, err := NewLedgerEntry(NewLedgerParams{
			Gcid:                 in.Gcid,
			Direction:            direction,
			Units:                in.Units,
			Reason:               in.Reason,
			SourceSubscriptionID: in.SourceSubscriptionID,
			SourceTopupID:        in.SourceTopupID,
			SourceAllocationID:   in.SourceAllocationID,
			IdempotencyKey:       in.IdempotencyKey,
			BalanceAfterUnits:    balAfter,
		})
		if err != nil {
			return nil, err
		}
		if err := q.store.AppendLedger(ctx, e); err != nil {
			return nil, err
		}
		return &CreditResult{Entry: e, BalanceAfterUnits: balAfter}, nil
	}

	// Every other source credits the PERSONAL balance: route it through the
	// atomic primitive so the wallet write and the ledger insert commit
	// together (or not at all).
	res, err := q.store.CreditWallet(ctx, CreditWalletInput{
		Gcid:                 in.Gcid,
		Units:                in.Units,
		Direction:            direction,
		Reason:               in.Reason,
		IdempotencyKey:       in.IdempotencyKey,
		SourceSubscriptionID: in.SourceSubscriptionID,
		SourceTopupID:        in.SourceTopupID,
		SourceAllocationID:   in.SourceAllocationID,
	})
	if err != nil {
		return nil, err
	}
	return &CreditResult{
		Entry:             res.Entry,
		BalanceAfterUnits: res.BalanceAfterUnits,
		Replayed:          res.Replayed,
	}, nil
}

// Breakdown returns balance + per-source slices in deterministic FIFO order
// (subsidies first by ExpiresAt ASC NULLS LAST, then a single personal slice).
func (q *Quoter) Breakdown(ctx context.Context, gcid string) (int64, []SubsidySlice, error) {
	if err := validateGcid(gcid); err != nil {
		return 0, nil, err
	}
	mana, err := q.store.GetMana(ctx, gcid)
	if err != nil {
		return 0, nil, err
	}
	if mana == nil {
		mana = NewUserMana(gcid)
	}
	allocs, err := q.store.ListAllocations(ctx, gcid)
	if err != nil {
		return 0, nil, err
	}
	sort.SliceStable(allocs, func(i, j int) bool {
		ai, aj := allocs[i], allocs[j]
		switch {
		case ai.ExpiresAt == nil && aj.ExpiresAt != nil:
			return false
		case ai.ExpiresAt != nil && aj.ExpiresAt == nil:
			return true
		case ai.ExpiresAt != nil && aj.ExpiresAt != nil:
			if !ai.ExpiresAt.Equal(*aj.ExpiresAt) {
				return ai.ExpiresAt.Before(*aj.ExpiresAt)
			}
		}
		return ai.AllocatedAt.Before(aj.AllocatedAt)
	})

	slices := make([]SubsidySlice, 0, len(allocs)+1)
	subsidyTotal := int64(0)
	for _, a := range allocs {
		if a.RemainingUnits == 0 {
			continue
		}
		slices = append(slices, SubsidySlice{
			TenantID:           a.TenantID,
			Units:              a.RemainingUnits,
			Source:             SourceTenantSubsidy,
			ExpiresAt:          a.ExpiresAt,
			SourceAllocationID: a.AllocationID,
		})
		subsidyTotal += a.RemainingUnits
	}
	if mana.BalanceUnits > 0 {
		slices = append(slices, SubsidySlice{
			Units: mana.BalanceUnits,
			// The non-allocation remainder is the learner's own (personal) base
			// balance — top-ups, grants, etc. that aren't tenant-pool subsidies.
			// (Was mislabelled subscription_grant — CHO-1883 balance-breakdown.)
			Source: SourcePersonal,
		})
	}
	return subsidyTotal + mana.BalanceUnits, slices, nil
}

// -----------------------------------------------------------------------------
// In-memory Store implementation (for tests + initial deployment)
// -----------------------------------------------------------------------------

// InMemoryStore implements Store with maps + mutex. Production swaps in
// pgx-backed adapter (M12+). Exposed as a domain-package type for clarity
// in tests; the production adapter package implements the same interface.
type InMemoryStore struct {
	mu          sync.Mutex
	mana        map[string]*UserMana
	allocations map[string][]*Allocation
	ledger      []*LedgerEntry
	// demoBudget mirrors the pg adapter's `demo_grant_budget` reserved/consumed
	// counters (keyed "global" / "gcid:<gcid>"), so the in-memory store enforces
	// the same demo-grant caps the pg transaction enforces. Lazily created.
	demoBudget map[string]demoBudgetRow
}

// demoBudgetRow is one consumed-counter row of the demo-grant budget.
type demoBudgetRow struct {
	consumedUnits  int64
	consumedGrants int64
}

// NewInMemoryStore returns an empty in-memory Store.
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		mana:        make(map[string]*UserMana),
		allocations: make(map[string][]*Allocation),
		ledger:      make([]*LedgerEntry, 0),
		demoBudget:  make(map[string]demoBudgetRow),
	}
}

func (s *InMemoryStore) GetMana(_ context.Context, gcid string) (*UserMana, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.mana[gcid]
	if !ok {
		return nil, nil
	}
	clone := *m
	if m.LastCreditedAt != nil {
		t := *m.LastCreditedAt
		clone.LastCreditedAt = &t
	}
	return &clone, nil
}

// SaveMana upserts. Adapters must enforce OCC; the in-memory store is
// loose for test simplicity.
func (s *InMemoryStore) SaveMana(_ context.Context, m *UserMana) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	clone := *m
	if m.LastCreditedAt != nil {
		t := *m.LastCreditedAt
		clone.LastCreditedAt = &t
	}
	s.mana[m.Gcid] = &clone
	return nil
}

func (s *InMemoryStore) AppendLedger(_ context.Context, e *LedgerEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	clone := *e
	s.ledger = append(s.ledger, &clone)
	return nil
}

func (s *InMemoryStore) ListLedger(_ context.Context, f LedgerFilter) ([]*LedgerEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*LedgerEntry, 0)
	for _, e := range s.ledger {
		if f.Gcid != "" && e.Gcid != f.Gcid {
			continue
		}
		if f.From != nil && e.RecordedAt.Before(*f.From) {
			continue
		}
		if f.To != nil && !e.RecordedAt.Before(*f.To) {
			continue
		}
		if f.Direction != nil && e.Direction != *f.Direction {
			continue
		}
		if f.Reason != nil && e.Reason != *f.Reason {
			continue
		}
		clone := *e
		out = append(out, &clone)
	}
	// Newest-first, stable total order (recorded_at DESC, entry_id DESC) so
	// keyset pagination has no gaps/overlaps even on equal timestamps. Mirrors
	// the pg repo's ORDER BY (CHO-1883).
	sort.Slice(out, func(i, j int) bool {
		if !out[i].RecordedAt.Equal(out[j].RecordedAt) {
			return out[i].RecordedAt.After(out[j].RecordedAt)
		}
		return out[i].EntryID > out[j].EntryID
	})
	if f.Cursor != "" {
		ct, cid, err := DecodeLedgerCursor(f.Cursor)
		if err != nil {
			return nil, err
		}
		kept := make([]*LedgerEntry, 0, len(out))
		for _, e := range out {
			// Keep rows strictly older than the cursor tuple.
			if e.RecordedAt.After(ct) {
				continue
			}
			if e.RecordedAt.Equal(ct) && e.EntryID >= cid {
				continue
			}
			kept = append(kept, e)
		}
		out = kept
	}
	if f.PageSize > 0 && len(out) > f.PageSize {
		out = out[:f.PageSize]
	}
	return out, nil
}

func (s *InMemoryStore) FindLedgerByIdempotencyKey(_ context.Context, gcid, key string) ([]*LedgerEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if key == "" {
		return nil, nil
	}
	out := make([]*LedgerEntry, 0)
	for _, e := range s.ledger {
		if e.Gcid == gcid && e.IdempotencyKey == key {
			clone := *e
			out = append(out, &clone)
		}
	}
	return out, nil
}

func (s *InMemoryStore) ListAllocations(_ context.Context, gcid string) ([]*Allocation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	src, ok := s.allocations[gcid]
	if !ok {
		return nil, nil
	}
	out := make([]*Allocation, 0, len(src))
	for _, a := range src {
		clone := *a
		if a.ExpiresAt != nil {
			t := *a.ExpiresAt
			clone.ExpiresAt = &t
		}
		out = append(out, &clone)
	}
	return out, nil
}

func (s *InMemoryStore) SaveAllocation(_ context.Context, gcid string, a *Allocation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	clone := *a
	if a.ExpiresAt != nil {
		t := *a.ExpiresAt
		clone.ExpiresAt = &t
	}
	for i, existing := range s.allocations[gcid] {
		if existing.AllocationID == a.AllocationID {
			s.allocations[gcid][i] = &clone
			return nil
		}
	}
	s.allocations[gcid] = append(s.allocations[gcid], &clone)
	return nil
}

func (s *InMemoryStore) UpdateAllocationRemaining(_ context.Context, gcid, allocationID string, remaining int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.allocations[gcid] {
		if a.AllocationID == allocationID {
			a.RemainingUnits = remaining
			return nil
		}
	}
	return fmt.Errorf("user_mana: allocation %q not found for gcid %q", allocationID, gcid)
}

// CreditWallet applies an atomic credit: the wallet mutation and the ledger
// append happen under ONE mutex, so the in-memory store has the same
// atomicity guarantee the pg adapter gets from its single transaction. When
// in.DemoGrantCaps is set the demo-grant caps are checked and consumed under
// that same mutex, mirroring the pg adapter's transactional enforcement.
func (s *InMemoryStore) CreditWallet(_ context.Context, in CreditWalletInput) (*CreditWalletResult, error) {
	if err := ValidateCreditWalletInput(in); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if existing := s.findLedgerLocked(in.Gcid, in.IdempotencyKey); len(existing) > 0 {
		if !CreditWalletMatchesLedger(existing[0], in) {
			return nil, fmt.Errorf("%w: gcid=%s key=%s", ErrIdempotencyConflict, in.Gcid, in.IdempotencyKey)
		}
		m, _ := s.mana[in.Gcid]
		bal, err := s.balanceIncludingSubsidyLocked(m, in.Gcid)
		if err != nil {
			return nil, err
		}
		return &CreditWalletResult{Wallet: cloneMana(m), Entry: existing[0],
			BalanceAfterUnits: bal, Replayed: true}, nil
	}

	if in.DemoGrantCaps != nil {
		if err := s.consumeDemoBudgetLocked(in); err != nil {
			return nil, err
		}
	}

	m, ok := s.mana[in.Gcid]
	if !ok {
		m = NewUserMana(in.Gcid)
	}
	if err := m.Credit(in.Units); err != nil {
		return nil, err
	}
	s.mana[in.Gcid] = m

	balAfter, err := s.balanceAfterLocked(m, in.Gcid)
	if err != nil {
		return nil, err
	}
	e, err := NewLedgerEntry(NewLedgerParams{
		Gcid:                 in.Gcid,
		Direction:            in.Direction,
		Units:                in.Units,
		Reason:               in.Reason,
		SourceSubscriptionID: in.SourceSubscriptionID,
		SourceActionID:       in.SourceActionID,
		SourceAllocationID:   in.SourceAllocationID,
		SourceTopupID:        in.SourceTopupID,
		IdempotencyKey:       in.IdempotencyKey,
		RequestID:            in.RequestID,
		BalanceAfterUnits:    balAfter,
	})
	if err != nil {
		return nil, err
	}
	s.ledger = append(s.ledger, e)
	return &CreditWalletResult{Wallet: cloneMana(m), Entry: e,
		BalanceAfterUnits: e.BalanceAfterUnits}, nil
}

// consumeDemoBudgetLocked checks the demo-grant caps and consumes the counters.
// Caller holds mu; it runs BEFORE the credit so a capped request writes nothing.
func (s *InMemoryStore) consumeDemoBudgetLocked(in CreditWalletInput) error {
	caps := in.DemoGrantCaps
	globalKey := demoBudgetGlobalKey
	gcidKey := demoBudgetGcidPrefix + in.Gcid
	global := s.demoBudget[globalKey]
	perGcid := s.demoBudget[gcidKey]

	if caps.MaxPerGcid > 0 && perGcid.consumedGrants >= caps.MaxPerGcid {
		return fmt.Errorf("%w: gcid=%s grants=%d cap=%d",
			ErrDemoGrantLimitReached, in.Gcid, perGcid.consumedGrants, caps.MaxPerGcid)
	}
	if caps.BudgetUnits > 0 {
		projected, err := CheckedAddUnits(global.consumedUnits, in.Units)
		if err != nil {
			return err
		}
		if projected > caps.BudgetUnits {
			return fmt.Errorf("%w: consumed=%d grant=%d budget=%d",
				ErrDemoGrantBudgetExhausted, global.consumedUnits, in.Units, caps.BudgetUnits)
		}
	}

	globalUnits, err := CheckedAddUnits(global.consumedUnits, in.Units)
	if err != nil {
		return err
	}
	gcidUnits, err := CheckedAddUnits(perGcid.consumedUnits, in.Units)
	if err != nil {
		return err
	}
	global.consumedUnits, global.consumedGrants = globalUnits, global.consumedGrants+1
	perGcid.consumedUnits, perGcid.consumedGrants = gcidUnits, perGcid.consumedGrants+1
	s.demoBudget[globalKey], s.demoBudget[gcidKey] = global, perGcid
	return nil
}

// demo-grant budget keys, mirroring the pg adapter's `demo_grant_budget`
// budget_key values.
const (
	demoBudgetGlobalKey  = "global"
	demoBudgetGcidPrefix = "gcid:"
)

// DemoGrantTotalUnits totals the `demo_grant` units across every gcid. The
// in-memory store has no RLS, so this is a plain scan.
func (s *InMemoryStore) DemoGrantTotalUnits(_ context.Context) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out int64
	for _, e := range s.ledger {
		if e.Reason != ReasonDemoGrant {
			continue
		}
		sum, err := CheckedAddUnits(out, e.Units)
		if err != nil {
			return 0, err
		}
		out = sum
	}
	return out, nil
}

// findLedgerLocked returns the ledger rows matching (gcid, key). Caller holds mu.
func (s *InMemoryStore) findLedgerLocked(gcid, key string) []*LedgerEntry {
	if key == "" {
		return nil
	}
	out := make([]*LedgerEntry, 0)
	for _, e := range s.ledger {
		if e.Gcid == gcid && e.IdempotencyKey == key {
			clone := *e
			out = append(out, &clone)
		}
	}
	return out
}

// balanceAfterLocked computes subsidy total + personal balance for the ledger
// row's balance_after_units. Caller holds mu.
func (s *InMemoryStore) balanceAfterLocked(m *UserMana, gcid string) (int64, error) {
	bal := int64(0)
	for _, a := range s.allocations[gcid] {
		sum, err := CheckedAddUnits(bal, a.RemainingUnits)
		if err != nil {
			return 0, err
		}
		bal = sum
	}
	if m != nil {
		return CheckedAddUnits(bal, m.BalanceUnits)
	}
	return bal, nil
}

// balanceIncludingSubsidyLocked is balanceAfterLocked with a nil-safe wallet.
func (s *InMemoryStore) balanceIncludingSubsidyLocked(m *UserMana, gcid string) (int64, error) {
	return s.balanceAfterLocked(m, gcid)
}

// cloneMana deep-copies a wallet snapshot (nil-safe). Caller holds mu.
func cloneMana(m *UserMana) *UserMana {
	if m == nil {
		return nil
	}
	clone := *m
	if m.LastCreditedAt != nil {
		t := *m.LastCreditedAt
		clone.LastCreditedAt = &t
	}
	return &clone
}

// AddAllocation is a test convenience that bypasses SaveAllocation's upsert.
func (s *InMemoryStore) AddAllocation(gcid string, a *Allocation) {
	s.mu.Lock()
	defer s.mu.Unlock()
	clone := *a
	if a.ExpiresAt != nil {
		t := *a.ExpiresAt
		clone.ExpiresAt = &t
	}
	s.allocations[gcid] = append(s.allocations[gcid], &clone)
}

// AllocationsFor returns a snapshot for tests.
func (s *InMemoryStore) AllocationsFor(gcid string) []*Allocation {
	s.mu.Lock()
	defer s.mu.Unlock()
	src := s.allocations[gcid]
	out := make([]*Allocation, 0, len(src))
	for _, a := range src {
		clone := *a
		out = append(out, &clone)
	}
	return out
}
