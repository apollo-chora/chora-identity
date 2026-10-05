// Domain events for the per-user subscription aggregate. These mirror the
// proto wire envelope shape (chora.identity.user_subscription.*.v1) and are
// produced as map[string]any payloads for the events.Publisher port; the
// Pub/Sub adapter handles full Protobuf marshalling at M12+.
package user_subscription

import "time"

// EventType — name within the topic.
type EventType string

const (
	EventCreated     EventType = "created"
	EventRenewed     EventType = "renewed"
	EventCancelled   EventType = "cancelled"
	EventPlanChanged EventType = "plan_changed"
)

// TopicName returns the canonical Pub/Sub topic.
func TopicName(evt EventType) string {
	return "chora.identity.user_subscription." + string(evt) + ".v1"
}

// CreatedPayload — canonical JSON shape for user_subscription.created.v1.
type CreatedPayload struct {
	SubscriptionID       string    `json:"subscription_id"`
	Gcid                 string    `json:"gcid"`
	TenantID             string    `json:"tenant_id"`
	PlanCode             string    `json:"plan_code"`
	Tier                 string    `json:"tier"`
	Status               string    `json:"status"`
	BillingPeriod        string    `json:"billing_period"`
	CurrentPeriodStart   time.Time `json:"current_period_start"`
	CurrentPeriodEnd     time.Time `json:"current_period_end"`
	StripeSubscriptionID string    `json:"stripe_subscription_id"`
	ManaMonthlyUnits     int64     `json:"mana_monthly_units"`
	OnboardingBonusUnits int64     `json:"onboarding_bonus_units"`
	CreatedAt            time.Time `json:"created_at"`
}

// CreatedFrom builds a CreatedPayload from a Subscription aggregate.
func CreatedFrom(s *Subscription) CreatedPayload {
	return CreatedPayload{
		SubscriptionID:       s.SubscriptionID,
		Gcid:                 s.Gcid,
		TenantID:             s.TenantID,
		PlanCode:             s.PlanCode,
		Tier:                 string(s.Tier),
		Status:               string(s.Status),
		BillingPeriod:        string(s.BillingPeriod),
		CurrentPeriodStart:   s.CurrentPeriodStart,
		CurrentPeriodEnd:     s.CurrentPeriodEnd,
		StripeSubscriptionID: s.StripeSubscriptionID,
		ManaMonthlyUnits:     s.ManaMonthlyUnits,
		OnboardingBonusUnits: s.OnboardingBonusUnits,
		CreatedAt:            s.CreatedAt,
	}
}

// CancelledPayload — canonical JSON shape for user_subscription.cancelled.v1.
type CancelledPayload struct {
	SubscriptionID     string    `json:"subscription_id"`
	Gcid               string    `json:"gcid"`
	TenantID           string    `json:"tenant_id"`
	PlanCode           string    `json:"plan_code"`
	Tier               string    `json:"tier"`
	CancellationReason string    `json:"cancellation_reason"`
	CancelledByGcid    string    `json:"cancelled_by_gcid"`
	EffectiveAt        time.Time `json:"effective_at"`
	CancelledAt        time.Time `json:"cancelled_at"`
}

// CancelledFrom builds a CancelledPayload from a Subscription aggregate.
func CancelledFrom(s *Subscription) CancelledPayload {
	var t time.Time
	if s.CancelledAt != nil {
		t = *s.CancelledAt
	}
	return CancelledPayload{
		SubscriptionID:     s.SubscriptionID,
		Gcid:               s.Gcid,
		TenantID:           s.TenantID,
		PlanCode:           s.PlanCode,
		Tier:               string(s.Tier),
		CancellationReason: s.CancellationReason,
		CancelledByGcid:    s.CancelledByGcid,
		EffectiveAt:        t,
		CancelledAt:        t,
	}
}

// RenewedPayload — canonical JSON shape for user_subscription.renewed.v1.
type RenewedPayload struct {
	SubscriptionID       string    `json:"subscription_id"`
	Gcid                 string    `json:"gcid"`
	TenantID             string    `json:"tenant_id"`
	PlanCode             string    `json:"plan_code"`
	Tier                 string    `json:"tier"`
	BillingPeriod        string    `json:"billing_period"`
	PriorPeriodEnd       time.Time `json:"prior_period_end"`
	CurrentPeriodStart   time.Time `json:"current_period_start"`
	CurrentPeriodEnd     time.Time `json:"current_period_end"`
	StripeSubscriptionID string    `json:"stripe_subscription_id"`
	ManaMonthlyUnits     int64     `json:"mana_monthly_units"`
	RenewedAt            time.Time `json:"renewed_at"`
}

// PlanChangedPayload — canonical JSON shape for user_subscription.plan_changed.v1.
type PlanChangedPayload struct {
	SubscriptionID    string    `json:"subscription_id"`
	Gcid              string    `json:"gcid"`
	TenantID          string    `json:"tenant_id"`
	FromPlanCode      string    `json:"from_plan_code"`
	ToPlanCode        string    `json:"to_plan_code"`
	FromTier          string    `json:"from_tier"`
	ToTier            string    `json:"to_tier"`
	FromBillingPeriod string    `json:"from_billing_period"`
	ToBillingPeriod   string    `json:"to_billing_period"`
	BillingDeltaCents int64     `json:"billing_delta_cents"`
	ScheduleID        string    `json:"schedule_id"`
	EffectiveAt       time.Time `json:"effective_at"`
	RequestedByGcid   string    `json:"requested_by_gcid"`
	ChangedAt         time.Time `json:"changed_at"`
}
