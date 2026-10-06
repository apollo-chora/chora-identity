// eventbus_bindings.go — adapters that project eventbus deliveries onto the
// identity subscriber methods. Kept separate from the subscribers so the
// domain-facing Handle* methods stay transport-agnostic.
package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/apollo-chora/chora-common/eventbus"
	commonv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/common/v1"
	paymentsv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/payments/v1"
	tenancyv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/tenancy/v1"
)

// UserManaTopUpHandler adapts the UserManaTopUpSubscriber to an
// eventbus.Handler. chora-payments publishes the capture as Protobuf wire
// bytes, so the payload is proto.Unmarshal'd into the generated type.
func UserManaTopUpHandler(s *UserManaTopUpSubscriber) eventbus.Handler {
	return func(ctx context.Context, msg eventbus.Message) error {
		if s == nil {
			return errors.New("events: user_mana_topup handler not initialised")
		}
		var ev paymentsv1.UserManaTopUpPaymentCaptured
		if err := proto.Unmarshal(msg.Payload, &ev); err != nil {
			return fmt.Errorf("events: user_mana_topup payload decode: %w", err)
		}
		return s.HandlePaymentCaptured(ctx, &ev)
	}
}

// identityEnvelopeFromMsg projects the transport envelope (reconstructed
// from NATS headers by the eventbus) onto the identity events.Envelope.
// Payments + tenancy Protobuf payloads embed chora.common.v1.EventEnvelope as
// field 1, so the embedded envelope is the fallback for tenant/gcid/trace
// fields the transport envelope may lack; the traceparent finally falls back
// to a context-derived value so downstream re-publishes (role_granted,
// kyc_submitted) always carry a valid W3C trace context.
func identityEnvelopeFromMsg(ctx context.Context, msg eventbus.Message, embedded *commonv1.EventEnvelope) Envelope {
	env := Envelope{
		EventID:        msg.Envelope.EventID,
		IdempotencyKey: msg.Envelope.IdempotencyKey,
		TenantID:       msg.Envelope.TenantID,
		GCID:           msg.Envelope.GCID,
		OccurredAt:     msg.Envelope.OccurredAt,
		PublishedAt:    msg.Envelope.PublishedAt,
		Traceparent:    msg.Envelope.Traceparent,
		Tracestate:     msg.Envelope.Tracestate,
		SourceProject:  msg.Envelope.SourceProject,
		SourceService:  msg.Envelope.SourceService,
		SchemaVersion:  msg.Envelope.SchemaVersion,
	}
	if embedded != nil {
		if env.TenantID == "" {
			env.TenantID = embedded.GetTenantId()
		}
		if env.GCID == "" {
			env.GCID = embedded.GetGcid()
		}
		if env.Traceparent == "" {
			env.Traceparent = embedded.GetTraceparent()
		}
		if env.Tracestate == "" {
			env.Tracestate = embedded.GetTracestate()
		}
	}
	if env.Traceparent == "" {
		env.Traceparent = w3cTraceparentFromContext(ctx)
	}
	return env
}

// EnrollmentHandler adapts the EnrollmentSubscriber to an eventbus.Handler.
// chora-delivery publishes chora.delivery.enrollment.created.v1 as JSON (the
// topic has no Protobuf encoder in chora-delivery's protomarshal registry),
// so the payload is json.Unmarshal'd onto EnrollmentCreatedPayload.
func EnrollmentHandler(s *EnrollmentSubscriber) eventbus.Handler {
	return func(ctx context.Context, msg eventbus.Message) error {
		if s == nil {
			return errors.New("events: enrollment handler not initialised")
		}
		var p EnrollmentCreatedPayload
		if err := json.Unmarshal(msg.Payload, &p); err != nil {
			return errors.Join(errors.New("events: enrollment payload decode"), err)
		}
		return s.Handle(ctx, identityEnvelopeFromMsg(ctx, msg, nil), p)
	}
}

// PaymentsHandler adapts the PaymentsSubscriber to an eventbus.Handler.
// chora-payments publishes the user_subscription.*.v1 family as Protobuf
// wire bytes (the EventEnvelope is proto-embedded), so each subject is
// proto.Unmarshal'd onto its generated type and mapped onto the subscriber's
// loose JSON projection. One handler serves all four topics; the subject
// selects the decode target + FSM entry point.
func PaymentsHandler(s *PaymentsSubscriber) eventbus.Handler {
	return func(ctx context.Context, msg eventbus.Message) error {
		if s == nil {
			return errors.New("events: payments handler not initialised")
		}
		switch msg.Subject {
		case TopicPaymentsUserSubscriptionCaptured:
			var ev paymentsv1.UserSubscriptionPaymentCaptured
			if err := proto.Unmarshal(msg.Payload, &ev); err != nil {
				return fmt.Errorf("events: payments captured payload decode: %w", err)
			}
			payload := PaymentsUserSubscriptionPaymentCapturedPayload{
				PurchaseID:            ev.GetPurchaseId(),
				LearnerGcid:           ev.GetLearnerGcid(),
				PlanSku:               ev.GetPlanSku(),
				BillingPeriod:         ev.GetBillingPeriod(),
				StripeSubscriptionID:  ev.GetStripeSubscriptionId(),
				StripeInvoiceID:       ev.GetStripeInvoiceId(),
				StripePaymentIntentID: ev.GetStripePaymentIntentId(),
				StripeChargeID:        ev.GetStripeChargeId(),
				AmountCentsPaid:       ev.GetAmountCentsPaid(),
				Currency:              ev.GetCurrency(),
				PeriodStart:           ev.GetPeriodStart().AsTime(),
				PeriodEnd:             ev.GetPeriodEnd().AsTime(),
				PaidAt:                ev.GetPaidAt().AsTime(),
			}
			return s.HandlePaymentCaptured(ctx, identityEnvelopeFromMsg(ctx, msg, ev.GetEnvelope()), payload)
		case TopicPaymentsUserSubscriptionFailed:
			var ev paymentsv1.UserSubscriptionPaymentFailed
			if err := proto.Unmarshal(msg.Payload, &ev); err != nil {
				return fmt.Errorf("events: payments failed payload decode: %w", err)
			}
			payload := PaymentsUserSubscriptionPaymentFailedPayload{
				PurchaseID:           ev.GetPurchaseId(),
				LearnerGcid:          ev.GetLearnerGcid(),
				PlanSku:              ev.GetPlanSku(),
				StripeSubscriptionID: ev.GetStripeSubscriptionId(),
				StripeInvoiceID:      ev.GetStripeInvoiceId(),
				StripeFailureCode:    ev.GetStripeFailureCode(),
				StripeFailureMessage: ev.GetStripeFailureMessage(),
				NextAttemptAt:        ev.GetNextAttemptAt().AsTime(),
				FailedAt:             ev.GetFailedAt().AsTime(),
			}
			return s.HandlePaymentFailed(ctx, identityEnvelopeFromMsg(ctx, msg, ev.GetEnvelope()), payload)
		case TopicPaymentsUserSubscriptionRefunded:
			var ev paymentsv1.UserSubscriptionRefunded
			if err := proto.Unmarshal(msg.Payload, &ev); err != nil {
				return fmt.Errorf("events: payments refunded payload decode: %w", err)
			}
			payload := PaymentsUserSubscriptionRefundedPayload{
				PurchaseID:           ev.GetPurchaseId(),
				LearnerGcid:          ev.GetLearnerGcid(),
				StripeSubscriptionID: ev.GetStripeSubscriptionId(),
				StripeInvoiceID:      ev.GetStripeInvoiceId(),
				StripeChargeID:       ev.GetStripeChargeId(),
				StripeRefundID:       ev.GetStripeRefundId(),
				AmountCentsRefunded:  ev.GetAmountCentsRefunded(),
				Currency:             ev.GetCurrency(),
				Reason:               ev.GetReason(),
				RefundedAt:           ev.GetRefundedAt().AsTime(),
			}
			return s.HandleRefunded(ctx, identityEnvelopeFromMsg(ctx, msg, ev.GetEnvelope()), payload)
		case TopicPaymentsUserSubscriptionExpired:
			var ev paymentsv1.UserSubscriptionExpired
			if err := proto.Unmarshal(msg.Payload, &ev); err != nil {
				return fmt.Errorf("events: payments expired payload decode: %w", err)
			}
			payload := PaymentsUserSubscriptionExpiredPayload{
				PurchaseID:      ev.GetPurchaseId(),
				LearnerGcid:     ev.GetLearnerGcid(),
				PlanSku:         ev.GetPlanSku(),
				StripeSessionID: ev.GetStripeSessionId(),
				ExpiredAt:       ev.GetExpiredAt().AsTime(),
			}
			// No stripe_subscription_id on the expired proto: the subscriber
			// drops cleanly when the field is empty (initial Checkout
			// abandoned before a subscription handle exists).
			return s.HandleExpired(ctx, identityEnvelopeFromMsg(ctx, msg, ev.GetEnvelope()), payload)
		default:
			return fmt.Errorf("events: payments handler unknown subject %q", msg.Subject)
		}
	}
}

// KycFeeHandler adapts the KycFeeSubscriber to an eventbus.Handler.
// chora-payments publishes the identity_kyc_fee.*.v1 family as Protobuf
// wire bytes. Only payment_captured acts (pending → submitted, entering the
// manual-review queue); failed / refunded / expired are documented clean
// no-ops — the verification simply never leaves pending — so they are acked
// without action (kyc_fee_subscriber.go header).
func KycFeeHandler(s *KycFeeSubscriber) eventbus.Handler {
	return func(ctx context.Context, msg eventbus.Message) error {
		if s == nil {
			return errors.New("events: kyc_fee handler not initialised")
		}
		switch msg.Subject {
		case TopicPaymentsIdentityKycFeeCaptured:
			var ev paymentsv1.IdentityKycFeePaymentCaptured
			if err := proto.Unmarshal(msg.Payload, &ev); err != nil {
				return fmt.Errorf("events: kyc_fee captured payload decode: %w", err)
			}
			payload := PaymentsIdentityKycFeePaymentCapturedPayload{
				PurchaseID:            ev.GetPurchaseId(),
				LearnerGcid:           ev.GetLearnerGcid(),
				KycDocType:            ev.GetKycDocType(),
				StripeSessionID:       ev.GetStripeSessionId(),
				StripePaymentIntentID: ev.GetStripePaymentIntentId(),
				StripeChargeID:        ev.GetStripeChargeId(),
				AmountCentsPaid:       ev.GetAmountCentsPaid(),
				Currency:              ev.GetCurrency(),
				PaidAt:                ev.GetPaidAt().AsTime(),
			}
			return s.HandlePaymentCaptured(ctx, identityEnvelopeFromMsg(ctx, msg, ev.GetEnvelope()), payload)
		case TopicPaymentsIdentityKycFeeFailed, TopicPaymentsIdentityKycFeeRefunded, TopicPaymentsIdentityKycFeeExpired:
			return nil
		default:
			return fmt.Errorf("events: kyc_fee handler unknown subject %q", msg.Subject)
		}
	}
}

// TenantBootstrappedHandler adapts the TenantBootstrappedSubscriber to an
// eventbus.Handler. chora-tenancy publishes chora.tenancy.tenant.bootstrapped.v1
// as Protobuf wire bytes (tenancyv1.TenantBootstrapped, envelope
// proto-embedded), so the payload is proto.Unmarshal'd and mapped onto the
// subscriber's loose JSON projection.
func TenantBootstrappedHandler(s *TenantBootstrappedSubscriber) eventbus.Handler {
	return func(ctx context.Context, msg eventbus.Message) error {
		if s == nil {
			return errors.New("events: tenant_bootstrapped handler not initialised")
		}
		var ev tenancyv1.TenantBootstrapped
		if err := proto.Unmarshal(msg.Payload, &ev); err != nil {
			return fmt.Errorf("events: tenant_bootstrapped payload decode: %w", err)
		}
		payload := TenantBootstrappedPayload{
			TenantID:       ev.GetTenantId(),
			OwnerGCID:      ev.GetOwnerGcid(),
			DisplayName:    ev.GetDisplayName(),
			OwnerMemberID:  ev.GetOwnerMemberId(),
			EntitlementID:  ev.GetEntitlementId(),
			BootstrappedAt: ev.GetBootstrappedAt().AsTime(),
		}
		return s.HandleTenantBootstrapped(ctx, identityEnvelopeFromMsg(ctx, msg, ev.GetEnvelope()), payload)
	}
}
