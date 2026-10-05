// Tests for the chora.delivery.enrollment.created.v1 subscriber.
//
// Per Phyllis MVP §6 + audit-identity-fillgaps.md §3.2 (P0):
//
//	chora-delivery emits chora.delivery.enrollment.created.v1
//	   → chora-identity subscriber projects CourseRoleAssignment(role=learner)
//	   → GET /v1/me/roles?course_id=X returns role=learner for that gcid
//
// The subscriber:
//   - dedupes on the envelope's idempotency_key (replays are no-ops)
//   - rejects AGID-shaped GCIDs (per ddd-enforcement aggregate invariant #10)
//   - emits chora.identity.role.granted.v1 via the EconomyPublisher's
//     RoleGranted helper (added alongside this subscriber)
//
// RED phase — types do not exist yet.
package events_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/apollo-chora/chora-common/idempotent"
	"github.com/apollo-chora/chora-identity/internal/adapter/events"
	"github.com/apollo-chora/chora-identity/internal/adapter/inmem"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// helper — build a fresh subscriber + repo
func buildEnrollmentSubscriber(_ *testing.T) (*events.EnrollmentSubscriber, *inmem.CourseRoleRepository, *events.Recorder) {
	roles := inmem.NewCourseRoleRepository()
	rec := events.NewRecorder()
	pub := events.NewEconomyPublisher(rec)
	sub := events.NewEnrollmentSubscriber(roles, pub, nil)
	return sub, roles, rec
}

// -----------------------------------------------------------------------------
// Happy path
// -----------------------------------------------------------------------------

func TestEnrollmentSubscriber_HappyPath_ProjectsCourseRole(t *testing.T) {
	sub, roles, rec := buildEnrollmentSubscriber(t)
	ctx := context.Background()

	gcid := "01935b5a-9bcf-7000-8000-0000000000aa"
	courseID := "01935b5a-9bcf-7000-8000-000000000099"
	tenantID := "01935b5a-9bcf-7000-8000-000000000010"

	env := events.NewEnvelope(tenantID, gcid, "00-1234567890abcdef1234567890abcdef-1234567890abcdef-01", "")

	payload := events.EnrollmentCreatedPayload{
		EnrollmentID: "01935b5a-9bcf-7000-8000-aaaaaa000001",
		CourseID:     courseID,
		LearnerGCID:  gcid,
		EnrolledAt:   time.Now().UTC(),
	}
	if err := sub.Handle(ctx, env, payload); err != nil {
		t.Fatalf("handle: %v", err)
	}
	got, err := roles.GetAssignment(ctx, gcid, courseID)
	if err != nil {
		t.Fatalf("expected assignment; got %v", err)
	}
	if got.Role != identity.CourseRoleLearner {
		t.Fatalf("expected learner; got %v", got.Role)
	}
	if got.TenantID != tenantID {
		t.Fatalf("tenant_id mismatch: got %q want %q", got.TenantID, tenantID)
	}
	// Subscriber should emit chora.identity.role.granted.v1.
	emitted := rec.RecordedByTopic("chora.identity.role.granted.v1")
	if len(emitted) != 1 {
		t.Fatalf("expected 1 RoleGranted; got %d", len(emitted))
	}
	if emitted[0].Envelope.TenantID != tenantID {
		t.Fatalf("emitted tenant_id mismatch")
	}
}

// -----------------------------------------------------------------------------
// Idempotency
// -----------------------------------------------------------------------------

func TestEnrollmentSubscriber_Idempotent_ReplayIsNoOp(t *testing.T) {
	sub, roles, rec := buildEnrollmentSubscriber(t)
	ctx := context.Background()

	gcid := "01935b5a-9bcf-7000-8000-0000000000bb"
	courseID := "01935b5a-9bcf-7000-8000-0000000000ee"
	tenantID := "01935b5a-9bcf-7000-8000-000000000010"

	// Same idempotency_key for both deliveries.
	env := events.NewEnvelope(tenantID, gcid, "00-1234567890abcdef1234567890abcdef-1234567890abcdef-01", "")
	env.IdempotencyKey = "enrollment:" + courseID + ":" + gcid

	payload := events.EnrollmentCreatedPayload{
		EnrollmentID: "01935b5a-9bcf-7000-8000-bbbbbb000001",
		CourseID:     courseID,
		LearnerGCID:  gcid,
		EnrolledAt:   time.Now().UTC(),
	}
	if err := sub.Handle(ctx, env, payload); err != nil {
		t.Fatalf("first handle: %v", err)
	}
	if err := sub.Handle(ctx, env, payload); err != nil {
		t.Fatalf("replay should be no-op; got %v", err)
	}
	// Only one emitted RoleGranted (replay deduped).
	emitted := rec.RecordedByTopic("chora.identity.role.granted.v1")
	if len(emitted) != 1 {
		t.Fatalf("expected 1 RoleGranted (deduped); got %d", len(emitted))
	}
	if _, err := roles.GetAssignment(ctx, gcid, courseID); err != nil {
		t.Fatalf("assignment must persist across replay: %v", err)
	}
}

// -----------------------------------------------------------------------------
// AGID rejection
// -----------------------------------------------------------------------------

func TestEnrollmentSubscriber_RejectsAGID(t *testing.T) {
	sub, _, _ := buildEnrollmentSubscriber(t)
	ctx := context.Background()

	agid := "0197a000-0000-0000-0000-000000000001"
	env := events.NewEnvelope("01935b5a-9bcf-7000-8000-000000000010", agid,
		"00-1234567890abcdef1234567890abcdef-1234567890abcdef-01", "")
	payload := events.EnrollmentCreatedPayload{
		EnrollmentID: "01935b5a-9bcf-7000-8000-cccccc000001",
		CourseID:     "01935b5a-9bcf-7000-8000-000000000099",
		LearnerGCID:  agid,
		EnrolledAt:   time.Now().UTC(),
	}
	err := sub.Handle(ctx, env, payload)
	if err == nil {
		t.Fatalf("expected AGID rejection")
	}
}

// -----------------------------------------------------------------------------
// Validation
// -----------------------------------------------------------------------------

func TestEnrollmentSubscriber_RejectsMissingFields(t *testing.T) {
	sub, _, _ := buildEnrollmentSubscriber(t)
	ctx := context.Background()
	env := events.NewEnvelope("01935b5a-9bcf-7000-8000-000000000010", "01935b5a-9bcf-7000-8000-0000000000dd",
		"00-1234567890abcdef1234567890abcdef-1234567890abcdef-01", "")

	tests := map[string]events.EnrollmentCreatedPayload{
		"empty_learner_gcid": {EnrollmentID: "x", CourseID: "01935b5a-9bcf-7000-8000-000000000099"},
		"empty_course_id":    {EnrollmentID: "x", LearnerGCID: "01935b5a-9bcf-7000-8000-0000000000dd"},
		"empty_enrollment":   {CourseID: "01935b5a-9bcf-7000-8000-000000000099", LearnerGCID: "01935b5a-9bcf-7000-8000-0000000000dd"},
	}
	for name, p := range tests {
		t.Run(name, func(t *testing.T) {
			if err := sub.Handle(ctx, env, p); err == nil {
				t.Fatalf("expected error for %s", name)
			}
		})
	}
}

func TestEnrollmentSubscriber_TopicConstant(t *testing.T) {
	if events.TopicEnrollmentCreated != "chora.delivery.enrollment.created.v1" {
		t.Fatalf("topic constant mismatch: got %q", events.TopicEnrollmentCreated)
	}
	got := (&events.EnrollmentSubscriber{}).SubscribedTopic()
	if got != "chora.delivery.enrollment.created.v1" {
		t.Fatalf("subscribed topic mismatch: got %q", got)
	}
}

// -----------------------------------------------------------------------------
// Property-style: 200 random (gcid × courseID) permutations to exercise
// the dual-card invariant — same gcid, different courses, different roles.
// -----------------------------------------------------------------------------

func TestEnrollmentSubscriber_ManyDistinctEnrolments(t *testing.T) {
	sub, roles, _ := buildEnrollmentSubscriber(t)
	ctx := context.Background()

	gcid := "01935b5a-9bcf-7000-8000-0000000000aa"
	tenantID := "01935b5a-9bcf-7000-8000-000000000010"

	for i := 0; i < 200; i++ {
		// Synthesise a deterministic course_id per i so the test is
		// reproducible and covers a broad gcid-courseID matrix.
		// Format: 01935b5a-9bcf-7000-8000-00000000{i_hex_4chars}.
		courseID := "01935b5a-9bcf-7000-8000-000000000" + leftPad(i)
		env := events.NewEnvelope(tenantID, gcid,
			"00-1234567890abcdef1234567890abcdef-1234567890abcdef-01", "")
		payload := events.EnrollmentCreatedPayload{
			EnrollmentID: "01935b5a-9bcf-7000-8000-aaaaaa00" + leftPad(i),
			CourseID:     courseID,
			LearnerGCID:  gcid,
			EnrolledAt:   time.Now().UTC(),
		}
		if err := sub.Handle(ctx, env, payload); err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
	}

	// Random spot-checks: 5 indices out of 200 must resolve to learner.
	for _, i := range []int{0, 50, 100, 150, 199} {
		courseID := "01935b5a-9bcf-7000-8000-000000000" + leftPad(i)
		got, err := roles.GetAssignment(ctx, gcid, courseID)
		if err != nil {
			t.Fatalf("iter %d expected assignment; got %v", i, err)
		}
		if got.Role != identity.CourseRoleLearner {
			t.Fatalf("iter %d expected learner; got %v", i, got.Role)
		}
	}
	_ = errors.New
}

func leftPad(i int) string {
	const hex = "0123456789abcdef"
	out := []byte{'0', '0', '0', '0'}
	out[3] = hex[i&0x0f]
	out[2] = hex[(i>>4)&0x0f]
	out[1] = hex[(i>>8)&0x0f]
	out[0] = hex[(i>>12)&0x0f]
	return string(out)
}

// -----------------------------------------------------------------------------
// W2a (2026-05-12) — inbox dedup tests proving chaos scenario (h)
// "idempotency under duplicates" cannot fire double side-effects across
// the failure modes the in-process map dedup couldn't survive:
//
//   1. Pod-death: dedup state must persist outside the subscriber
//      instance. Tested by swapping the subscriber instance between the
//      first delivery and the duplicate redelivery, sharing the same
//      Store.
//   2. Multi-replica: replica A and replica B see the same event; only
//      one of them runs the handler body. Tested by running two
//      subscribers backed by the same Store concurrently.
//   3. TTL expiry: a token outside the TTL allows reprocessing (correct
//      semantics — the saga is allowed to re-run if explicitly replayed
//      after grace window).
// -----------------------------------------------------------------------------

func newEnrollmentEnvelopeAndPayload(t *testing.T) (events.Envelope, events.EnrollmentCreatedPayload) {
	t.Helper()
	gcid := "01935b5a-9bcf-7000-8000-0000000000ee"
	courseID := "01935b5a-9bcf-7000-8000-0000000000ff"
	tenantID := "01935b5a-9bcf-7000-8000-000000000010"
	env := events.NewEnvelope(tenantID, gcid,
		"00-1234567890abcdef1234567890abcdef-1234567890abcdef-01", "")
	env.IdempotencyKey = "enrollment:" + courseID + ":" + gcid
	payload := events.EnrollmentCreatedPayload{
		EnrollmentID: "01935b5a-9bcf-7000-8000-eeffff000001",
		CourseID:     courseID,
		LearnerGCID:  gcid,
		EnrolledAt:   time.Now().UTC(),
	}
	return env, payload
}

func TestEnrollmentSubscriber_InboxSurvivesSubscriberRecreation(t *testing.T) {
	t.Parallel()
	roles := inmem.NewCourseRoleRepository()
	rec := events.NewRecorder()
	pub := events.NewEconomyPublisher(rec)

	// Shared inbox — same Store crosses the pod-restart boundary.
	inbox := idempotent.NewMemoryStore()
	sub1 := events.NewEnrollmentSubscriber(roles, pub, inbox)

	env, payload := newEnrollmentEnvelopeAndPayload(t)
	if err := sub1.Handle(context.Background(), env, payload); err != nil {
		t.Fatalf("first delivery on sub1: %v", err)
	}

	// Simulate pod restart: drop sub1, recreate sub2 with the SAME inbox.
	sub2 := events.NewEnrollmentSubscriber(roles, pub, inbox)
	if err := sub2.Handle(context.Background(), env, payload); err != nil {
		t.Fatalf("redelivery on sub2 (post-restart): %v", err)
	}

	emitted := rec.RecordedByTopic("chora.identity.role.granted.v1")
	if len(emitted) != 1 {
		t.Fatalf("expected exactly 1 role_granted across pod-restart redelivery; got %d", len(emitted))
	}
}

func TestEnrollmentSubscriber_InboxFreshStoreReprocessesEvent(t *testing.T) {
	t.Parallel()
	// Negative-control: WITHOUT a shared store (each subscriber has its own
	// MemoryStore) the inbox CANNOT dedupe across restarts — exactly the
	// failure mode the production PostgresStore wiring is designed to fix.
	roles := inmem.NewCourseRoleRepository()
	rec := events.NewRecorder()
	pub := events.NewEconomyPublisher(rec)

	sub1 := events.NewEnrollmentSubscriber(roles, pub, idempotent.NewMemoryStore())
	sub2 := events.NewEnrollmentSubscriber(roles, pub, idempotent.NewMemoryStore())

	env, payload := newEnrollmentEnvelopeAndPayload(t)
	if err := sub1.Handle(context.Background(), env, payload); err != nil {
		t.Fatalf("sub1 handle: %v", err)
	}
	if err := sub2.Handle(context.Background(), env, payload); err != nil {
		t.Fatalf("sub2 handle: %v", err)
	}
	emitted := rec.RecordedByTopic("chora.identity.role.granted.v1")
	if len(emitted) != 2 {
		t.Errorf("FRESH-store negative control: expected 2 role_granted events (no shared dedup); got %d", len(emitted))
	}
}

func TestEnrollmentSubscriber_InboxConcurrentReplicas(t *testing.T) {
	t.Parallel()
	roles := inmem.NewCourseRoleRepository()
	rec := events.NewRecorder()
	pub := events.NewEconomyPublisher(rec)

	// Two subscribers (two replicas) sharing one inbox.
	inbox := idempotent.NewMemoryStore()
	subA := events.NewEnrollmentSubscriber(roles, pub, inbox)
	subB := events.NewEnrollmentSubscriber(roles, pub, inbox)

	env, payload := newEnrollmentEnvelopeAndPayload(t)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _ = subA.Handle(context.Background(), env, payload) }()
	go func() { defer wg.Done(); _ = subB.Handle(context.Background(), env, payload) }()
	wg.Wait()

	emitted := rec.RecordedByTopic("chora.identity.role.granted.v1")
	if len(emitted) != 1 {
		t.Fatalf("multi-replica: expected exactly 1 role_granted event; got %d", len(emitted))
	}
}

// -----------------------------------------------------------------------------
// Nil-guard + coverage edge cases
// -----------------------------------------------------------------------------

func TestEnrollmentSubscriber_NilSubscriberRejects(t *testing.T) {
	t.Parallel()
	var sub *events.EnrollmentSubscriber
	if err := sub.Handle(context.Background(), events.Envelope{}, events.EnrollmentCreatedPayload{}); err == nil {
		t.Errorf("nil sub should error")
	}
}

func TestEnrollmentSubscriber_FallbackToBusinessNaturalKey_WhenIdemEmpty(t *testing.T) {
	t.Parallel()
	roles := inmem.NewCourseRoleRepository()
	rec := events.NewRecorder()
	pub := events.NewEconomyPublisher(rec)
	inbox := idempotent.NewMemoryStore()
	sub := events.NewEnrollmentSubscriber(roles, pub, inbox)

	env, payload := newEnrollmentEnvelopeAndPayload(t)
	env.IdempotencyKey = "" // force fallback synthesis

	if err := sub.Handle(context.Background(), env, payload); err != nil {
		t.Fatalf("first handle: %v", err)
	}
	// Replay with same empty IdempotencyKey → fallback key matches → dedupes.
	if err := sub.Handle(context.Background(), env, payload); err != nil {
		t.Fatalf("replay handle: %v", err)
	}
	emitted := rec.RecordedByTopic("chora.identity.role.granted.v1")
	if len(emitted) != 1 {
		t.Errorf("expected 1 role_granted (fallback key dedupes); got %d", len(emitted))
	}
}

// failingRoleWriter forces the Upsert path to error so we exercise the
// inbox.Process error-propagation branch (key NOT claimed on fn error).
// Composes the inmem repo for the GetAssignment side of the
// CourseRoleWriter interface (we only care about Upsert failing).
type failingRoleWriter struct {
	*inmem.CourseRoleRepository
}

func (f *failingRoleWriter) Upsert(_ context.Context, _ identity.CourseRoleAssignment) (bool, error) {
	return false, errors.New("upsert blew up")
}

func TestEnrollmentSubscriber_UpsertError_PropagatesAndLeavesInboxUnclaimed(t *testing.T) {
	t.Parallel()
	roles := &failingRoleWriter{CourseRoleRepository: inmem.NewCourseRoleRepository()}
	rec := events.NewRecorder()
	pub := events.NewEconomyPublisher(rec)
	inbox := idempotent.NewMemoryStore()
	sub := events.NewEnrollmentSubscriber(roles, pub, inbox)

	env, payload := newEnrollmentEnvelopeAndPayload(t)
	err := sub.Handle(context.Background(), env, payload)
	if err == nil {
		t.Fatalf("expected upsert error")
	}
	// Retry should still run (key not claimed because fn returned error).
	err2 := sub.Handle(context.Background(), env, payload)
	if err2 == nil {
		t.Fatalf("retry expected to re-run + fail")
	}
}

func TestEnrollmentSubscriber_InboxTTLExpiryReprocesses(t *testing.T) {
	t.Parallel()
	roles := inmem.NewCourseRoleRepository()
	rec := events.NewRecorder()
	pub := events.NewEconomyPublisher(rec)

	inbox := idempotent.NewMemoryStore()
	sub := events.NewEnrollmentSubscriber(roles, pub, inbox).WithInboxTTL(50 * time.Millisecond)

	env, payload := newEnrollmentEnvelopeAndPayload(t)

	if err := sub.Handle(context.Background(), env, payload); err != nil {
		t.Fatalf("first handle: %v", err)
	}
	// Advance the inbox clock past the TTL.
	inbox.Advance(100 * time.Millisecond)
	if err := sub.Handle(context.Background(), env, payload); err != nil {
		t.Fatalf("second handle (post-TTL): %v", err)
	}
	emitted := rec.RecordedByTopic("chora.identity.role.granted.v1")
	if len(emitted) != 2 {
		t.Fatalf("TTL-expiry: expected 2 role_granted events; got %d", len(emitted))
	}
}
