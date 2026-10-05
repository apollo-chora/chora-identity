// Tests for the identity closure pull-loop adapter (CHO-1719 gap 4).
//
// ClosurePullHandler bridges the chora-common eventbus delivery loop to
// the identity ClosureSubscriber.Handle (which, unlike the other nine
// domains, takes the identity events.Envelope alongside the payload):
//
//	chora.identity.pii.pseudonymise.requested.v1 (durable consumer)
//	  → ClosurePullHandler (JSON decode + envelope projection)
//	    → ClosureSubscriber.Handle
//	      → ack on chora.identity.account.pseudonymised.v1
package events_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/apollo-chora/chora-common/envelope"
	"github.com/apollo-chora/chora-common/eventbus"

	"github.com/apollo-chora/chora-identity/internal/adapter/events"
	"github.com/apollo-chora/chora-identity/internal/adapter/inmem"
)

func newIdentityPullFixture(t *testing.T) (*events.ClosureSubscriber, *inmem.UserRepository, *events.Recorder) {
	t.Helper()
	users := inmem.NewUserRepository()
	rec := events.NewRecorder()
	sub := events.NewClosureSubscriberWithTerminal(
		users, events.NewEconomyPublisher(rec), nil, &fakeDeleter{},
		events.ClosureTombstones{}, nil,
	)
	return sub, users, rec
}

func pullBody(t *testing.T) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]string{
		"saga_id": "saga-pull-1", "gcid": termGcid, "tenant_id": termTenant,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return body
}

func TestIdentityClosurePullHandler_DispatchesAndAcksOnNewTopic(t *testing.T) {
	sub, users, rec := newIdentityPullFixture(t)
	seedActiveUser(t, users, termGcid)
	handler := events.ClosurePullHandler(sub)

	msg := eventbus.Message{
		Subject: events.TopicPseudonymiseRequested,
		Envelope: envelope.Envelope{
			TenantID:       termTenant,
			GCID:           termGcid,
			IdempotencyKey: "idem-1",
			Traceparent:    "00-feedface-cafebabe-01",
		},
		Payload: pullBody(t),
	}
	if err := handler(context.Background(), msg); err != nil {
		t.Fatalf("handler: %v", err)
	}
	emitted := rec.RecordedByTopic("chora.identity.account.pseudonymised.v1")
	if len(emitted) != 1 {
		t.Fatalf("want 1 ack on the reconciled topic; got %d", len(emitted))
	}
	// Trace context flows from the pull envelope into the ack envelope.
	if emitted[0].Envelope.Traceparent != "00-feedface-cafebabe-01" {
		t.Errorf("traceparent = %q", emitted[0].Envelope.Traceparent)
	}
}

func TestIdentityClosurePullHandler_TenantFallsBackToPayload(t *testing.T) {
	// Some publishers stamp tenant only in the JSON body; identity Handle
	// validates env.TenantID, so the pull adapter must project it.
	sub, users, rec := newIdentityPullFixture(t)
	seedActiveUser(t, users, termGcid)
	handler := events.ClosurePullHandler(sub)

	msg := eventbus.Message{
		Subject:  events.TopicPseudonymiseRequested,
		Envelope: envelope.Envelope{},
		Payload:  pullBody(t),
	}
	if err := handler(context.Background(), msg); err != nil {
		t.Fatalf("handler: %v", err)
	}
	if n := len(rec.RecordedByTopic(events.TopicPseudonymiseCompleted)); n != 1 {
		t.Fatalf("want 1 ack; got %d", n)
	}
}

func TestIdentityClosurePullHandler_MalformedJSONErrors(t *testing.T) {
	sub, _, rec := newIdentityPullFixture(t)
	handler := events.ClosurePullHandler(sub)
	msg := eventbus.Message{
		Subject: events.TopicPseudonymiseRequested,
		Payload: []byte("{not-json"),
	}
	if err := handler(context.Background(), msg); err == nil {
		t.Fatal("malformed payload must error (nack)")
	}
	if n := len(rec.Recorded()); n != 0 {
		t.Fatalf("no ack on decode failure; got %d", n)
	}
}

func TestIdentityClosurePullHandler_NilSubscriberErrors(t *testing.T) {
	if err := events.ClosurePullHandler(nil)(context.Background(), eventbus.Message{Payload: []byte("{}")}); err == nil {
		t.Fatal("nil subscriber must error")
	}
}
