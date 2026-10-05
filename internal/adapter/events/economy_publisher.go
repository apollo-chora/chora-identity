// Per-user economy publishers — extends the generic events.Publisher with
// typed helper methods for the 11 new topics introduced by BE-USR-1
// (chora.identity.user_subscription.* + user_mana.* + kyc.*).
//
// The methods accept domain aggregates / payloads and translate them into
// map[string]any for the underlying Publisher contract. Binary protobuf wire
// encoding is applied by the inner Publisher (CloudPublisher / outbox.Publisher)
// via internal/adapter/events/protomarshal.MarshalPayload at write time;
// time.Time fields become RFC3339Nano strings + int64 fields become float64
// through json.Marshal in toMap, and the protomarshal encoder reconstitutes
// both back to wire-correct shapes.
package events

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/apollo-chora/chora-identity/internal/domain/kyc"
	mana "github.com/apollo-chora/chora-identity/internal/domain/user_mana"
	usersub "github.com/apollo-chora/chora-identity/internal/domain/user_subscription"
)

// EconomyPublisher wraps a Publisher with typed helpers per-aggregate.
type EconomyPublisher struct {
	inner Publisher
}

// NewEconomyPublisher constructs the typed publisher.
func NewEconomyPublisher(inner Publisher) *EconomyPublisher {
	return &EconomyPublisher{inner: inner}
}

// PublishSubscriptionCreated emits chora.identity.user_subscription.created.v1.
func (p *EconomyPublisher) PublishSubscriptionCreated(env Envelope, s *usersub.Subscription) error {
	if p == nil || p.inner == nil {
		return errors.New("events: EconomyPublisher not initialised")
	}
	payload, err := toMap(usersub.CreatedFrom(s))
	if err != nil {
		return err
	}
	return p.inner.Publish(usersub.TopicName(usersub.EventCreated), env, payload)
}

// PublishSubscriptionCancelled emits chora.identity.user_subscription.cancelled.v1.
func (p *EconomyPublisher) PublishSubscriptionCancelled(env Envelope, s *usersub.Subscription) error {
	if p == nil || p.inner == nil {
		return errors.New("events: EconomyPublisher not initialised")
	}
	payload, err := toMap(usersub.CancelledFrom(s))
	if err != nil {
		return err
	}
	return p.inner.Publish(usersub.TopicName(usersub.EventCancelled), env, payload)
}

// PublishSubscriptionRenewed emits chora.identity.user_subscription.renewed.v1.
func (p *EconomyPublisher) PublishSubscriptionRenewed(env Envelope, payload usersub.RenewedPayload) error {
	if p == nil || p.inner == nil {
		return errors.New("events: EconomyPublisher not initialised")
	}
	m, err := toMap(payload)
	if err != nil {
		return err
	}
	return p.inner.Publish(usersub.TopicName(usersub.EventRenewed), env, m)
}

// PublishSubscriptionPlanChanged emits chora.identity.user_subscription.plan_changed.v1.
func (p *EconomyPublisher) PublishSubscriptionPlanChanged(env Envelope, payload usersub.PlanChangedPayload) error {
	if p == nil || p.inner == nil {
		return errors.New("events: EconomyPublisher not initialised")
	}
	m, err := toMap(payload)
	if err != nil {
		return err
	}
	return p.inner.Publish(usersub.TopicName(usersub.EventPlanChanged), env, m)
}

// PublishManaCredited emits chora.identity.user_mana.credited.v1.
func (p *EconomyPublisher) PublishManaCredited(env Envelope, e *mana.LedgerEntry) error {
	return p.publishLedger(env, mana.EventCredited, e)
}

// PublishManaDebited emits chora.identity.user_mana.debited.v1.
func (p *EconomyPublisher) PublishManaDebited(env Envelope, e *mana.LedgerEntry) error {
	return p.publishLedger(env, mana.EventDebited, e)
}

// PublishManaRefunded emits chora.identity.user_mana.refunded.v1.
func (p *EconomyPublisher) PublishManaRefunded(env Envelope, e *mana.LedgerEntry) error {
	return p.publishLedger(env, mana.EventRefunded, e)
}

// PublishManaSnapshot emits chora.identity.user_mana.snapshot_taken.v1.
func (p *EconomyPublisher) PublishManaSnapshot(env Envelope, payload mana.SnapshotPayload) error {
	if p == nil || p.inner == nil {
		return errors.New("events: EconomyPublisher not initialised")
	}
	m, err := toMap(payload)
	if err != nil {
		return err
	}
	return p.inner.Publish(mana.TopicName(mana.EventSnapshotTaken), env, m)
}

// PublishKycSubmitted emits chora.identity.kyc.submitted.v1.
func (p *EconomyPublisher) PublishKycSubmitted(env Envelope, v *kyc.Verification) error {
	if p == nil || p.inner == nil {
		return errors.New("events: EconomyPublisher not initialised")
	}
	payload, err := toMap(kyc.SubmittedFrom(v))
	if err != nil {
		return err
	}
	return p.inner.Publish(kyc.TopicName(kyc.EventSubmitted), env, payload)
}

// PublishKycVerified emits chora.identity.kyc.verified.v1.
func (p *EconomyPublisher) PublishKycVerified(env Envelope, v *kyc.Verification) error {
	if p == nil || p.inner == nil {
		return errors.New("events: EconomyPublisher not initialised")
	}
	payload, err := toMap(kyc.VerifiedFrom(v))
	if err != nil {
		return err
	}
	return p.inner.Publish(kyc.TopicName(kyc.EventVerified), env, payload)
}

// PublishKycRejected emits chora.identity.kyc.rejected.v1.
func (p *EconomyPublisher) PublishKycRejected(env Envelope, v *kyc.Verification) error {
	if p == nil || p.inner == nil {
		return errors.New("events: EconomyPublisher not initialised")
	}
	payload, err := toMap(kyc.RejectedFrom(v))
	if err != nil {
		return err
	}
	return p.inner.Publish(kyc.TopicName(kyc.EventRejected), env, payload)
}

// -----------------------------------------------------------------------------
// CourseRole projection events
// -----------------------------------------------------------------------------

// RoleGrantedPayload carries the projected CourseRole assignment downstream.
// Mirrors chora.identity.v1.RoleGranted (chora-contracts/proto/events/identity/role.proto).
type RoleGrantedPayload struct {
	RoleAssignmentID string    `json:"role_assignment_id"`
	Gcid             string    `json:"gcid"`
	TenantID         string    `json:"tenant_id"`
	CourseID         string    `json:"course_id"`
	Role             string    `json:"role"`
	Source           string    `json:"source"`
	SourceEventID    string    `json:"source_event_id,omitempty"`
	GrantedByGcid    string    `json:"granted_by_gcid"`
	GrantedAt        time.Time `json:"granted_at"`
}

// PublishRoleGranted emits chora.identity.role.granted.v1.
func (p *EconomyPublisher) PublishRoleGranted(env Envelope, payload RoleGrantedPayload) error {
	if p == nil || p.inner == nil {
		return errors.New("events: EconomyPublisher not initialised")
	}
	m, err := toMap(payload)
	if err != nil {
		return err
	}
	return p.inner.Publish("chora.identity.role.granted.v1", env, m)
}

func (p *EconomyPublisher) publishLedger(env Envelope, evt mana.EventType, e *mana.LedgerEntry) error {
	if p == nil || p.inner == nil {
		return errors.New("events: EconomyPublisher not initialised")
	}
	if e == nil {
		return errors.New("events: ledger entry required")
	}
	payload, err := toMap(mana.LedgerEntryPayloadFrom(e))
	if err != nil {
		return err
	}
	return p.inner.Publish(mana.TopicName(evt), env, payload)
}

// toMap is a thin JSON round-trip to coerce a typed payload into the
// map[string]any contract the Publisher port expects. The production
// Pub/Sub adapter will replace this with Protobuf marshalling per
// chora.common.v1 + chora.identity.v1 schemas.
func toMap(v any) (map[string]any, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	out := make(map[string]any)
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}
