// Pull-loop adapter binding the identity closure-saga subscriber to the
// chora-common eventbus. The eventbus acks on nil and nacks on error
// (ack-after-processing per D6.2).
//
// Identity's ClosureSubscriber.Handle — unlike the other nine domains —
// takes the identity events.Envelope alongside the payload (its inbox
// dedupe keys on the envelope IdempotencyKey), so this adapter projects
// the eventbus envelope onto the local shape instead of relying on
// payload-only trace fallback.
package events

import (
	"context"
	"encoding/json"
	"errors"
	"log"

	"github.com/apollo-chora/chora-common/eventbus"
)

// ClosurePullHandler adapts the ClosureSubscriber to an eventbus.Handler.
func ClosurePullHandler(s *ClosureSubscriber) eventbus.Handler {
	return func(ctx context.Context, msg eventbus.Message) error {
		if s == nil {
			return errors.New("events: closure pull handler not initialised")
		}
		var p PseudonymiseRequestedPayload
		if err := json.Unmarshal(msg.Payload, &p); err != nil {
			return errors.Join(errors.New("events: closure payload decode"), err)
		}
		env := Envelope{
			EventID:        msg.Envelope.EventID,
			IdempotencyKey: msg.Envelope.IdempotencyKey,
			TenantID:       msg.Envelope.TenantID,
			GCID:           msg.Envelope.GCID,
			Traceparent:    msg.Envelope.Traceparent,
			Tracestate:     msg.Envelope.Tracestate,
			SourceProject:  msg.Envelope.SourceProject,
			SourceService:  msg.Envelope.SourceService,
			SchemaVersion:  msg.Envelope.SchemaVersion,
		}
		// Handle validates env.TenantID; some publishers stamp tenant only
		// in the JSON body — project it so the validation gate sees it.
		if env.TenantID == "" {
			env.TenantID = p.TenantID
		}
		if env.GCID == "" {
			env.GCID = p.Gcid
		}
		// Trace fallback chain: envelope → payload → synthesised
		// placeholder (the identity envelope validator requires a
		// non-empty W3C traceparent on the outgoing ack).
		if env.Traceparent == "" {
			env.Traceparent = p.Traceparent
		}
		if env.Tracestate == "" {
			env.Tracestate = p.Tracestate
		}
		if env.Traceparent == "" {
			env.Traceparent = w3cTraceparentFromContext(ctx)
		}
		if err := s.Handle(ctx, env, p); err != nil {
			// The eventbus receive loop nacks handler errors WITHOUT
			// logging them — log here so the terminal chain is diagnosable.
			log.Printf("identity: closure terminal chain failed (gcid=%s): %v", env.GCID, err)
			return err
		}
		log.Printf("identity: closure terminal chain complete (gcid=%s)", env.GCID)
		return nil
	}
}
