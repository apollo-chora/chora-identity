// Subscriber for chora.delivery.enrollment.created.v1 — projects each
// enrolment into a CourseRoleAssignment(role=learner) row in chora_identity.
//
// Per Phyllis MVP §6 + audit-identity-fillgaps.md §3.2 (P0):
//
//	enrollment.created.v1  → project CourseRoleAssignment(learner)
//	                       → emit chora.identity.role.granted.v1
//
// Contract source: chora-contracts/proto/events/identity/role.proto +
// chora-contracts/asyncapi/delivery/enrollment.created.v1.yaml.
//
// Idempotency: M12.3 W2a (2026-05-12) — replaces the in-process map
// dedup with chora-go-common/idempotent.Store (PostgresStore in prod;
// MemoryStore in dev / tests). The in-process map lost state on pod-death
// + multi-replica deployments; the inbox Store survives both failure
// modes per `.claude/skills/agentic-resilience-d6/SKILL.md` Pillar 2
// consumer-side dual.
//
// Hexagonal: this is an INBOUND ADAPTER. Domain logic (CourseRoleAssignment +
// validation) lives in domain/identity/role_resolver.go.
package events

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/apollo-chora/chora-common/idempotent"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// TopicEnrollmentCreated is the canonical chora-delivery topic this
// subscriber binds to.
const TopicEnrollmentCreated = "chora.delivery.enrollment.created.v1"

// EnrollmentInboxTTL is the dedupe-key retention window for the
// enrollment subscriber's inbox. 24h is the canonical default per the
// closure subscriber + chora-creation's W1.7 pattern.
const EnrollmentInboxTTL = 24 * time.Hour

// EnrollmentCreatedPayload mirrors the AsyncAPI payload shape at
// chora-contracts/asyncapi/delivery/enrollment.created.v1.yaml.
//
// The chora-delivery event is the source-of-truth; this struct is the
// loose JSON projection used during local dev / integration tests.
type EnrollmentCreatedPayload struct {
	EnrollmentID string    `json:"enrollment_id"`
	CourseID     string    `json:"course_id"`
	LearnerGCID  string    `json:"learner_gcid"`
	EnrolledAt   time.Time `json:"enrolled_at"`
}

// EnrollmentSubscriber wires the chora-delivery enrolment event to the
// CourseRoleAssignment projection in chora_identity.
//
// Inbox dedupe (W2a): IdempotencyKey from the envelope (or a synthetic
// "enrollment:" + course_id + ":" + gcid key) is checked against a
// chora-go-common/idempotent.Store to skip duplicate deliveries.
// Replaces the prior in-process map dedup which lost state on pod
// restart + multi-replica setups.
type EnrollmentSubscriber struct {
	roles     identity.CourseRoleWriter
	publisher *EconomyPublisher
	inbox     idempotent.Store
	ttl       time.Duration
}

// NewEnrollmentSubscriber constructs the subscriber with its projection
// writer + downstream publisher + inbox store.
//
// nil inbox triggers a defensive MemoryStore fallback (dev-only;
// production passes PostgresStore). The TTL defaults to
// EnrollmentInboxTTL — callers can override via WithInboxTTL.
//
// Note: SubscribedTopic() is also available on the empty zero-value
// EnrollmentSubscriber so callers wiring topics in cmd/server can use the
// constant before instantiating dependencies.
func NewEnrollmentSubscriber(
	roles identity.CourseRoleWriter,
	publisher *EconomyPublisher,
	inbox idempotent.Store,
) *EnrollmentSubscriber {
	if inbox == nil {
		inbox = idempotent.NewMemoryStore()
	}
	return &EnrollmentSubscriber{
		roles:     roles,
		publisher: publisher,
		inbox:     inbox,
		ttl:       EnrollmentInboxTTL,
	}
}

// WithInboxTTL overrides the inbox dedupe TTL. Returns the same subscriber
// for fluent wiring in tests.
func (s *EnrollmentSubscriber) WithInboxTTL(d time.Duration) *EnrollmentSubscriber {
	if d > 0 {
		s.ttl = d
	}
	return s
}

// SubscribedTopic returns the canonical Pub/Sub topic this subscriber binds
// to.
func (s *EnrollmentSubscriber) SubscribedTopic() string {
	return TopicEnrollmentCreated
}

// Handle processes one enrollment.created.v1 message.
//
// Returns nil on success (or idempotent replay). Errors are non-retriable
// validation failures; the wrapping Pub/Sub adapter routes them to DLQ.
//
// Idempotency: inbox.Process on the envelope's IdempotencyKey (or a
// synthetic "enrollment:" + course_id + ":" + gcid fallback) collapses
// duplicate deliveries across pod-restart + multi-replica failure modes.
func (s *EnrollmentSubscriber) Handle(ctx context.Context, env Envelope, payload EnrollmentCreatedPayload) error {
	if s == nil || s.roles == nil || s.inbox == nil {
		return errors.New("events: EnrollmentSubscriber not initialised")
	}
	if err := s.validate(env, payload); err != nil {
		return err
	}

	// Inbox key — prefer the envelope's idempotency_key (set by the
	// producer); fall back to a business-natural composite key when the
	// producer omitted one.
	idem := strings.TrimSpace(env.IdempotencyKey)
	if idem == "" {
		idem = "enrollment:" + payload.CourseID + ":" + payload.LearnerGCID
	}

	return s.inbox.Process(ctx, idem, s.ttl, func() error {
		// Mint a deterministic role-assignment id for the projection.
		roleAssignmentID, err := uuid.NewV7()
		if err != nil {
			return fmt.Errorf("events: enrollment role_assignment_id: %w", err)
		}

		// Project the assignment.
		a := identity.CourseRoleAssignment{
			Gcid:     payload.LearnerGCID,
			CourseID: payload.CourseID,
			TenantID: env.TenantID,
			Role:     identity.CourseRoleLearner,
		}
		inserted, err := s.roles.Upsert(ctx, a)
		if err != nil {
			return fmt.Errorf("events: enrollment upsert: %w", err)
		}
		// On replay (inserted=false), the inbox above already short-circuited;
		// this branch handles the first delivery cleanly.
		_ = inserted

		// Emit the projected RoleGranted event so downstream consumers (BFF cache,
		// observability audit, IMDA D2 transparency evidence) see it.
		if s.publisher != nil {
			grant := RoleGrantedPayload{
				RoleAssignmentID: roleAssignmentID.String(),
				Gcid:             payload.LearnerGCID,
				TenantID:         env.TenantID,
				CourseID:         payload.CourseID,
				Role:             string(identity.CourseRoleLearner),
				Source:           "ROLE_GRANT_SOURCE_ENROLMENT",
				SourceEventID:    env.EventID,
				GrantedByGcid:    payload.LearnerGCID, // self-enrolment per Phyllis flow
				GrantedAt:        time.Now().UTC(),
			}
			// Build a fresh envelope so the published event has its OWN event_id
			// + idempotency_key (not the inbound one).
			outEnv := NewEnvelope(env.TenantID, payload.LearnerGCID, env.Traceparent, env.Tracestate)
			outEnv.IdempotencyKey = "role_granted:" + payload.CourseID + ":" + payload.LearnerGCID
			if err := s.publisher.PublishRoleGranted(outEnv, grant); err != nil {
				// Don't fail the projection write on publish error — the subscriber's
				// outbox in production will retry; in dev the Recorder never errors.
				return fmt.Errorf("events: publish role_granted: %w", err)
			}
		}
		return nil
	})
}

// validate runs the input-validation gate.
func (s *EnrollmentSubscriber) validate(env Envelope, p EnrollmentCreatedPayload) error {
	if strings.TrimSpace(p.LearnerGCID) == "" {
		return errors.New("events: enrollment learner_gcid required")
	}
	if identity.IsAGID(p.LearnerGCID) {
		return errors.New("events: AGID cannot hold a CourseRoleAssignment")
	}
	if strings.TrimSpace(p.CourseID) == "" {
		return errors.New("events: enrollment course_id required")
	}
	if strings.TrimSpace(p.EnrollmentID) == "" {
		return errors.New("events: enrollment enrollment_id required")
	}
	if strings.TrimSpace(env.TenantID) == "" {
		return errors.New("events: enrollment envelope.tenant_id required")
	}
	return nil
}
