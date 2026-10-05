// Package user_subscription is the per-user Familiar subscription aggregate
// for the Identity supporting domain (chora_identity database, Team 3 / Platform).
//
// Distinct from chora-tenancy add-on Subscription (tenant-level). Per-user
// subscriptions are 3-tier (Familiar Basic / Standard / Premium) and grant
// monthly mana drips into the user's UserMana balance per ADR-142.
//
// State machine (canonical lifecycle):
//
//	pending_activation  → active (on first invoice paid)
//	active              → paused | cancelled | expired | grace
//	paused              → active | cancelled
//	grace               → active | cancelled | expired
//	cancelled / expired → terminal
//
// Mana persists across cancellation per ADR-142 prepaid-credit semantics.
package user_subscription

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// -----------------------------------------------------------------------------
// Tier
// -----------------------------------------------------------------------------

// Tier identifies the 3 Familiar plan tiers per ADR-142.
type Tier string

const (
	TierBasic    Tier = "familiar_basic"
	TierStandard Tier = "familiar_standard"
	TierPremium  Tier = "familiar_premium"
)

// Valid reports whether the tier is one of the known 3.
func (t Tier) Valid() bool {
	switch t {
	case TierBasic, TierStandard, TierPremium:
		return true
	}
	return false
}

// -----------------------------------------------------------------------------
// BillingPeriod
// -----------------------------------------------------------------------------

// BillingPeriod is the Stripe cycle (monthly or annually). Annual plans drip
// mana monthly per ADR-142 Q1.
type BillingPeriod string

const (
	BillingMonthly  BillingPeriod = "monthly"
	BillingAnnually BillingPeriod = "annually"
)

func (b BillingPeriod) Valid() bool {
	switch b {
	case BillingMonthly, BillingAnnually:
		return true
	}
	return false
}

// -----------------------------------------------------------------------------
// Status — lifecycle states
// -----------------------------------------------------------------------------

// Status of the subscription per ADR-142.
type Status string

const (
	StatusPendingActivation Status = "pending_activation"
	StatusActive            Status = "active"
	StatusPaused            Status = "paused"
	StatusCancelled         Status = "cancelled"
	StatusExpired           Status = "expired"
	StatusGrace             Status = "grace"
)

// -----------------------------------------------------------------------------
// Subscription aggregate root
// -----------------------------------------------------------------------------

// Subscription is the per-user Familiar plan aggregate. UUIDv7 identifier;
// soft-delete via DeletedAt; OCC version for concurrent updates.
type Subscription struct {
	SubscriptionID       string
	Gcid                 string
	TenantID             string
	PlanCode             string
	Tier                 Tier
	Status               Status
	BillingPeriod        BillingPeriod
	ManaMonthlyUnits     int64
	OnboardingBonusUnits int64
	StripeSubscriptionID string

	CurrentPeriodStart time.Time
	CurrentPeriodEnd   time.Time

	// Audit fields preserved across plan changes.
	PriorPlanCode      string
	CancellationReason string
	CancelledAt        *time.Time
	CancelledByGcid    string

	Version   int64
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
}

// NewParams is the constructor input.
type NewParams struct {
	Gcid                 string
	TenantID             string
	PlanCode             string
	Tier                 Tier
	BillingPeriod        BillingPeriod
	ManaMonthlyUnits     int64
	OnboardingBonusUnits int64
	StripeSubscriptionID string
	PeriodStart          time.Time
	PeriodEnd            time.Time
}

// NewSubscription constructs a fresh Subscription in pending_activation.
func NewSubscription(p NewParams) (*Subscription, error) {
	if strings.TrimSpace(p.Gcid) == "" {
		return nil, errors.New("user_subscription: gcid required")
	}
	if strings.TrimSpace(p.PlanCode) == "" {
		return nil, errors.New("user_subscription: plan_code required")
	}
	if !p.Tier.Valid() {
		return nil, fmt.Errorf("user_subscription: invalid tier %q", p.Tier)
	}
	if !p.BillingPeriod.Valid() {
		return nil, fmt.Errorf("user_subscription: invalid billing_period %q", p.BillingPeriod)
	}
	if p.ManaMonthlyUnits < 0 {
		return nil, errors.New("user_subscription: mana_monthly_units must be >= 0")
	}
	if p.OnboardingBonusUnits < 0 {
		return nil, errors.New("user_subscription: onboarding_bonus_units must be >= 0")
	}
	if p.PeriodEnd.Before(p.PeriodStart) {
		return nil, errors.New("user_subscription: period_end must be >= period_start")
	}

	now := time.Now().UTC()
	return &Subscription{
		SubscriptionID:       newUUIDv7(),
		Gcid:                 p.Gcid,
		TenantID:             p.TenantID,
		PlanCode:             p.PlanCode,
		Tier:                 p.Tier,
		Status:               StatusPendingActivation,
		BillingPeriod:        p.BillingPeriod,
		ManaMonthlyUnits:     p.ManaMonthlyUnits,
		OnboardingBonusUnits: p.OnboardingBonusUnits,
		StripeSubscriptionID: p.StripeSubscriptionID,
		CurrentPeriodStart:   p.PeriodStart.UTC(),
		CurrentPeriodEnd:     p.PeriodEnd.UTC(),
		Version:              1,
		CreatedAt:            now,
		UpdatedAt:            now,
	}, nil
}

// -----------------------------------------------------------------------------
// State transitions
// -----------------------------------------------------------------------------

// Activate transitions pending_activation → active. Idempotent on already-active.
func (s *Subscription) Activate() error {
	switch s.Status {
	case StatusPendingActivation, StatusGrace:
		s.setStatus(StatusActive)
		return nil
	case StatusActive:
		return nil
	default:
		return fmt.Errorf("user_subscription: cannot activate from %q", s.Status)
	}
}

// EnterGrace transitions active → grace (e.g., on Stripe payment failure).
func (s *Subscription) EnterGrace(reason string) error {
	if s.Status != StatusActive {
		return fmt.Errorf("user_subscription: cannot enter grace from %q", s.Status)
	}
	s.setStatus(StatusGrace)
	return nil
}

// RecoverFromGrace transitions grace → active (payment recovered).
func (s *Subscription) RecoverFromGrace() error {
	if s.Status != StatusGrace {
		return fmt.Errorf("user_subscription: cannot recover from grace in state %q", s.Status)
	}
	s.setStatus(StatusActive)
	return nil
}

// Cancel transitions active|paused|grace → cancelled. Idempotent.
func (s *Subscription) Cancel(reason, byGcid string, effectiveAt time.Time) error {
	if s.Status == StatusCancelled {
		return nil
	}
	switch s.Status {
	case StatusActive, StatusPaused, StatusGrace, StatusPendingActivation:
		t := effectiveAt.UTC()
		s.CancelledAt = &t
		s.CancellationReason = reason
		s.CancelledByGcid = byGcid
		s.setStatus(StatusCancelled)
		return nil
	default:
		return fmt.Errorf("user_subscription: cannot cancel from %q", s.Status)
	}
}

// Pause transitions active → paused (compliance/admin hold).
func (s *Subscription) Pause(reason string) error {
	if s.Status == StatusPaused {
		return nil
	}
	if s.Status != StatusActive {
		return fmt.Errorf("user_subscription: cannot pause from %q", s.Status)
	}
	s.setStatus(StatusPaused)
	return nil
}

// Resume transitions paused → active.
func (s *Subscription) Resume() error {
	if s.Status == StatusActive {
		return nil
	}
	if s.Status != StatusPaused {
		return fmt.Errorf("user_subscription: cannot resume from %q", s.Status)
	}
	s.setStatus(StatusActive)
	return nil
}

// Renew advances the billing period. Allowed only from active or grace.
func (s *Subscription) Renew(periodStart, periodEnd time.Time) error {
	if s.Status != StatusActive && s.Status != StatusGrace {
		return fmt.Errorf("user_subscription: cannot renew from %q", s.Status)
	}
	if periodEnd.Before(periodStart) {
		return errors.New("user_subscription: period_end must be >= period_start")
	}
	s.CurrentPeriodStart = periodStart.UTC()
	s.CurrentPeriodEnd = periodEnd.UTC()
	if s.Status == StatusGrace {
		s.Status = StatusActive
	}
	s.touch()
	return nil
}

// ChangePlanParams is the input for ChangePlan.
type ChangePlanParams struct {
	ToPlanCode        string
	ToTier            Tier
	ToBillingPeriod   BillingPeriod
	BillingDeltaCents int64
	EffectiveAt       time.Time
	RequestedByGcid   string
	ManaMonthlyUnits  int64
}

// ChangePlan transitions plan tier in place. Allowed only when active or grace.
func (s *Subscription) ChangePlan(p ChangePlanParams) error {
	if s.Status != StatusActive && s.Status != StatusGrace && s.Status != StatusPaused {
		return fmt.Errorf("user_subscription: cannot change plan from %q", s.Status)
	}
	if !p.ToTier.Valid() {
		return fmt.Errorf("user_subscription: invalid target tier %q", p.ToTier)
	}
	if !p.ToBillingPeriod.Valid() {
		return fmt.Errorf("user_subscription: invalid target billing_period %q", p.ToBillingPeriod)
	}
	if p.ManaMonthlyUnits < 0 {
		return errors.New("user_subscription: mana_monthly_units must be >= 0")
	}
	s.PriorPlanCode = s.PlanCode
	s.PlanCode = p.ToPlanCode
	s.Tier = p.ToTier
	s.BillingPeriod = p.ToBillingPeriod
	s.ManaMonthlyUnits = p.ManaMonthlyUnits
	s.touch()
	return nil
}

// MarkExpired transitions any non-terminal status → expired (period ran out).
func (s *Subscription) MarkExpired() error {
	if s.Status == StatusExpired {
		return nil
	}
	if s.Status == StatusCancelled {
		return nil
	}
	s.setStatus(StatusExpired)
	return nil
}

// SoftDelete sets DeletedAt; preserves the row for closure saga audit.
func (s *Subscription) SoftDelete() {
	if s.DeletedAt != nil {
		return
	}
	now := time.Now().UTC()
	s.DeletedAt = &now
	s.touch()
}

// IsActiveLike reports whether the subscription should still grant mana drips.
func (s *Subscription) IsActiveLike() bool {
	return s.Status == StatusActive || s.Status == StatusGrace
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func (s *Subscription) setStatus(next Status) {
	s.Status = next
	s.touch()
}

func (s *Subscription) touch() {
	s.UpdatedAt = time.Now().UTC()
	s.Version++
}

// newUUIDv7 returns a freshly generated UUIDv7 string per RFC 9562 §5.7.
// Inline implementation keeps this domain dependency-free of uuid pkg
// (already used elsewhere; kept consistent here).
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
