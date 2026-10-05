// Package user_mana is the per-user mana wallet aggregate + append-only
// ManaLedger + Spend FIFO Quoter for the Identity supporting domain.
//
// Mana = the 4th currency (real-money-backed prepaid credit, GCID-scoped,
// non-tenant-transferable). Distinct from in-platform XP/Coins/Reputation
// per ADR-142. Persists across subscription cancellation.
//
// The aggregate enforces: balance >= 0, lifetime_earned/spent monotone,
// OCC version increments on every mutation. Adapters MUST honour Version.
package user_mana

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrInsufficientBalance is returned when a debit exceeds the available
// (subsidy + personal) balance.
var ErrInsufficientBalance = errors.New("user_mana: insufficient balance")

// IsInsufficientBalance reports whether err wraps ErrInsufficientBalance.
func IsInsufficientBalance(err error) bool { return errors.Is(err, ErrInsufficientBalance) }

// InsufficientBalanceError carries the resolved required units + currently
// available (subsidy + personal) units for the upsell payload (the WS-1
// metering 402-equivalent). It wraps ErrInsufficientBalance so
// IsInsufficientBalance / errors.Is keep matching. Use errors.As to recover the
// amounts — required reflects the RESOLVED catalogue cost on a units==0 debit,
// not the caller's req.Units (which is 0).
type InsufficientBalanceError struct {
	RequiredUnits  int64
	AvailableUnits int64
}

func (e *InsufficientBalanceError) Error() string {
	return fmt.Sprintf("user_mana: insufficient balance: need %d, have %d", e.RequiredUnits, e.AvailableUnits)
}

// Unwrap lets errors.Is(err, ErrInsufficientBalance) match.
func (e *InsufficientBalanceError) Unwrap() error { return ErrInsufficientBalance }

// -----------------------------------------------------------------------------
// UserMana aggregate
// -----------------------------------------------------------------------------

// UserMana is a per-GCID wallet snapshot. There is exactly one row per GCID;
// the ManaLedger holds the audit-grade movement history.
type UserMana struct {
	Gcid           string
	BalanceUnits   int64
	LifetimeEarned int64
	LifetimeSpent  int64
	LastCreditedAt *time.Time
	Version        int64
	UpdatedAt      time.Time
}

// NewUserMana mints a fresh wallet at zero balance.
func NewUserMana(gcid string) *UserMana {
	now := time.Now().UTC()
	return &UserMana{
		Gcid:      gcid,
		Version:   1,
		UpdatedAt: now,
	}
}

// Credit increases the spendable balance + lifetime_earned. Returns error on
// invalid units.
func (m *UserMana) Credit(units int64) error {
	if units <= 0 {
		return errors.New("user_mana: credit units must be > 0")
	}
	m.BalanceUnits += units
	m.LifetimeEarned += units
	now := time.Now().UTC()
	m.LastCreditedAt = &now
	m.touch()
	return nil
}

// Debit decreases the spendable balance + increments lifetime_spent. Returns
// ErrInsufficientBalance when balance would go negative.
func (m *UserMana) Debit(units int64) error {
	if units <= 0 {
		return errors.New("user_mana: debit units must be > 0")
	}
	if m.BalanceUnits < units {
		return ErrInsufficientBalance
	}
	m.BalanceUnits -= units
	m.LifetimeSpent += units
	m.touch()
	return nil
}

// Refund reverses a prior debit — increases balance + decrements lifetime_spent.
func (m *UserMana) Refund(units int64) error {
	if units <= 0 {
		return errors.New("user_mana: refund units must be > 0")
	}
	if m.LifetimeSpent < units {
		return errors.New("user_mana: cannot refund more than lifetime_spent")
	}
	m.BalanceUnits += units
	m.LifetimeSpent -= units
	m.touch()
	return nil
}

func (m *UserMana) touch() {
	m.UpdatedAt = time.Now().UTC()
	m.Version++
}

// -----------------------------------------------------------------------------
// Allocation — TenantManaAllocation projection (cross-domain reference)
//
// Stored in chora_identity (denormalised projection) for FIFO spend order.
// Source-of-truth is chora_tenancy; the projection is updated via Pub/Sub
// chora.tenancy.tenant_mana_allocation.granted.v1 events.
// -----------------------------------------------------------------------------

// Allocation is a tenant-funded subsidy slice attached to a GCID.
type Allocation struct {
	AllocationID   string
	TenantID       string
	RemainingUnits int64
	ExpiresAt      *time.Time
	AllocatedAt    time.Time
}

// -----------------------------------------------------------------------------
// SubsidySlice — spendable slice projection for UI / gRPC GetBalance
// -----------------------------------------------------------------------------

// Source classifies the slice for UI rendering.
type Source string

const (
	SourceSubscriptionGrant Source = "subscription_grant"
	SourceTopup             Source = "topup"
	SourceTenantSubsidy     Source = "tenant_subsidy"
	SourcePromo             Source = "promo"
	SourceRollover          Source = "rollover"
	SourceRefund            Source = "refund"
	SourceMint              Source = "mint"
	SourcePersonal          Source = "personal" // catch-all for personal balance slice
)

// Valid reports whether the source is one of the known classifications.
func (s Source) Valid() bool {
	switch s {
	case SourceSubscriptionGrant, SourceTopup, SourceTenantSubsidy,
		SourcePromo, SourceRollover, SourceRefund, SourceMint, SourcePersonal:
		return true
	}
	return false
}

// SubsidySlice is one source-tagged segment of a user's spendable balance.
type SubsidySlice struct {
	TenantID           string
	Units              int64
	Source             Source
	ExpiresAt          *time.Time
	SourceAllocationID string
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func validateGcid(gcid string) error {
	if strings.TrimSpace(gcid) == "" {
		return errors.New("user_mana: gcid required")
	}
	return nil
}

func validateUnits(units int64) error {
	if units <= 0 {
		return fmt.Errorf("user_mana: units must be > 0; got %d", units)
	}
	return nil
}

// newUUIDv7 — RFC 9562 §5.7. Inline implementation to keep this domain
// dependency-free (uuid pkg used elsewhere; consistency preserved).
func newUUIDv7() string {
	const buflen = 16
	var b [buflen]byte
	now := uint64(time.Now().UnixMilli())
	b[0] = byte(now >> 40)
	b[1] = byte(now >> 32)
	b[2] = byte(now >> 24)
	b[3] = byte(now >> 16)
	b[4] = byte(now >> 8)
	b[5] = byte(now)
	var randTail [10]byte
	_, _ = rand.Read(randTail[:])
	copy(b[6:], randTail[:])
	b[6] = (b[6] & 0x0f) | 0x70
	b[8] = (b[8] & 0x3f) | 0x80
	hexstr := hex.EncodeToString(b[:])
	return hexstr[0:8] + "-" + hexstr[8:12] + "-" + hexstr[12:16] + "-" + hexstr[16:20] + "-" + hexstr[20:32]
}
