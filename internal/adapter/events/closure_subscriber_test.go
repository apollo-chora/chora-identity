// Tests for the federated closure-saga subscriber.
//
// Per Tier 3 D11 + audit-identity-fillgaps.md §3.5:
//
//	chora.closure_orchestrator.saga.initiated.v1
//	  → chora.identity.pii.pseudonymise.requested.v1 (per-domain fan-out)
//	    → chora-identity ClosureSubscriber.Handle
//	      → start the local Identity Closure Saga (5-state machine)
//	      → emit chora.identity.account.pseudonymised.v1
//
// The subscriber processes the per-domain pseudonymise request from the
// federated saga and starts the local saga aggregate against the User row.
package events_test

import (
	"context"
	"errors"
	"testing"

	"github.com/apollo-chora/chora-identity/internal/adapter/events"
	"github.com/apollo-chora/chora-identity/internal/adapter/inmem"
	"github.com/apollo-chora/chora-identity/internal/domain/crypto"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

func TestClosureSubscriber_SubscribedTopic(t *testing.T) {
	sub := events.NewClosureSubscriber(nil, nil, nil)
	if got := sub.SubscribedTopic(); got != events.TopicPseudonymiseRequested {
		t.Errorf("SubscribedTopic = %q, want %q", got, events.TopicPseudonymiseRequested)
	}
}

func buildClosureSubscriber(t *testing.T) (*events.ClosureSubscriber, *inmem.UserRepository, *events.Recorder) {
	users := inmem.NewUserRepository()
	rec := events.NewRecorder()
	pub := events.NewEconomyPublisher(rec)
	sub := events.NewClosureSubscriber(users, pub, nil)
	return sub, users, rec
}

func TestClosureSubscriber_HappyPath(t *testing.T) {
	sub, users, rec := buildClosureSubscriber(t)
	ctx := context.Background()

	gcid := "01935b5a-9bcf-7000-8000-0000000000aa"
	tenantID := "01935b5a-9bcf-7000-8000-000000000010"

	// Pre-seed an active user.
	u, _ := identity.NewUser(identity.NewUserParams{
		Email: "phyllis@mightymind.sg", IdentityProvider: identity.ProviderOIDC,
		FederatedSubject: "google|phyllis-001",
	})
	u.Gcid = gcid
	_ = users.Save(ctx, u)

	env := events.NewEnvelope(tenantID, gcid,
		"00-1234567890abcdef1234567890abcdef-1234567890abcdef-01", "")
	payload := events.PseudonymiseRequestedPayload{
		SagaID:   "01935b5a-9bcf-7000-8000-saga0000001",
		Gcid:     gcid,
		TenantID: tenantID,
	}
	if err := sub.Handle(ctx, env, payload); err != nil {
		t.Fatalf("handle: %v", err)
	}
	got, _ := users.GetByGcid(ctx, gcid)
	if got.Status != identity.UserStatusClosed {
		t.Fatalf("expected user Closed; got %v", got.Status)
	}
	// Subscriber emits pseudonymise.completed.
	emitted := rec.RecordedByTopic("chora.identity.account.pseudonymised.v1")
	if len(emitted) != 1 {
		t.Fatalf("expected 1 completed event; got %d", len(emitted))
	}
}

func TestClosureSubscriber_RejectsAGID(t *testing.T) {
	sub, _, _ := buildClosureSubscriber(t)
	ctx := context.Background()

	agid := "0197a000-0000-0000-0000-000000000001"
	env := events.NewEnvelope("01935b5a-9bcf-7000-8000-000000000010", agid,
		"00-1234567890abcdef1234567890abcdef-1234567890abcdef-01", "")
	payload := events.PseudonymiseRequestedPayload{
		SagaID: "x", Gcid: agid, TenantID: "01935b5a-9bcf-7000-8000-000000000010",
	}
	if err := sub.Handle(ctx, env, payload); err == nil {
		t.Fatalf("expected AGID rejection")
	}
}

func TestClosureSubscriber_IdempotentReplay(t *testing.T) {
	sub, users, rec := buildClosureSubscriber(t)
	ctx := context.Background()

	gcid := "01935b5a-9bcf-7000-8000-0000000000bb"
	tenantID := "01935b5a-9bcf-7000-8000-000000000010"
	u, _ := identity.NewUser(identity.NewUserParams{
		Email: "x@y.com", IdentityProvider: identity.ProviderOIDC, FederatedSubject: "z",
	})
	u.Gcid = gcid
	_ = users.Save(ctx, u)

	env := events.NewEnvelope(tenantID, gcid,
		"00-1234567890abcdef1234567890abcdef-1234567890abcdef-01", "")
	env.IdempotencyKey = "closure:" + gcid

	payload := events.PseudonymiseRequestedPayload{
		SagaID: "saga-1", Gcid: gcid, TenantID: tenantID,
	}
	if err := sub.Handle(ctx, env, payload); err != nil {
		t.Fatal(err)
	}
	if err := sub.Handle(ctx, env, payload); err != nil {
		t.Fatalf("replay should be no-op; got %v", err)
	}
	emitted := rec.RecordedByTopic("chora.identity.account.pseudonymised.v1")
	if len(emitted) != 1 {
		t.Fatalf("expected 1 completed (deduped); got %d", len(emitted))
	}
}

func TestClosureSubscriber_TopicConstant(t *testing.T) {
	if events.TopicPseudonymiseRequested != "chora.identity.pii.pseudonymise.requested.v1" {
		t.Fatalf("topic constant mismatch: got %q", events.TopicPseudonymiseRequested)
	}
}

func TestClosureSubscriber_RejectsMissingFields(t *testing.T) {
	sub, _, _ := buildClosureSubscriber(t)
	ctx := context.Background()
	env := events.NewEnvelope("01935b5a-9bcf-7000-8000-000000000010", "01935b5a-9bcf-7000-8000-0000000000aa",
		"00-1234567890abcdef1234567890abcdef-1234567890abcdef-01", "")
	tests := map[string]events.PseudonymiseRequestedPayload{
		"empty_gcid":    {SagaID: "x", TenantID: "01935b5a-9bcf-7000-8000-000000000010"},
		"empty_saga_id": {Gcid: "01935b5a-9bcf-7000-8000-0000000000aa", TenantID: "01935b5a-9bcf-7000-8000-000000000010"},
		"empty_tenant":  {SagaID: "x", Gcid: "01935b5a-9bcf-7000-8000-0000000000aa"},
	}
	for name, p := range tests {
		t.Run(name, func(t *testing.T) {
			if err := sub.Handle(ctx, env, p); err == nil {
				t.Fatalf("expected error for %s", name)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// ClosureSubscriber error branches + optional terminal-step coverage
// -----------------------------------------------------------------------------

type fakeClosureRepo struct {
	users   identity.UserRepository
	getUser *identity.User
	getErr  error
	saveErr error
}

func (f *fakeClosureRepo) Save(_ context.Context, _ *identity.User) error { return f.saveErr }
func (f *fakeClosureRepo) GetByGcid(_ context.Context, gcid string) (*identity.User, error) {
	if f.users != nil {
		return f.users.GetByGcid(context.Background(), gcid)
	}
	return f.getUser, f.getErr
}

type fakeDEK struct {
	crypto.KeyManager
	shredded []string
	shredErr error
}

func (f *fakeDEK) ShredDEK(gcid string) error {
	f.shredded = append(f.shredded, gcid)
	return f.shredErr
}

func closureEnvAndPayload() (events.Envelope, events.PseudonymiseRequestedPayload) {
	gcid := "01935b5a-9bcf-7000-8000-0000000000ab"
	env := events.NewEnvelope("01935b5a-9bcf-7000-8000-000000000010", gcid, "00-trace-01", "")
	payload := events.PseudonymiseRequestedPayload{
		SagaID:   "01935b5a-9bcf-7000-8000-saga0000002",
		Gcid:     gcid,
		TenantID: "01935b5a-9bcf-7000-8000-000000000010",
	}
	return env, payload
}

func TestClosureSubscriber_Validate_AllBranches(t *testing.T) {
	t.Parallel()
	sub := events.NewClosureSubscriber(nil, nil, nil)
	env, payload := closureEnvAndPayload()

	cases := []struct {
		name    string
		env     events.Envelope
		payload events.PseudonymiseRequestedPayload
	}{
		{"missing saga", env, func() events.PseudonymiseRequestedPayload {
			p := payload
			p.SagaID = ""
			return p
		}()},
		{"missing gcid", env, func() events.PseudonymiseRequestedPayload {
			p := payload
			p.Gcid = ""
			return p
		}()},
		{"AGID gcid", env, func() events.PseudonymiseRequestedPayload {
			p := payload
			p.Gcid = "0197a000000000000000000000000000"
			return p
		}()},
		{"missing payload tenant", env, func() events.PseudonymiseRequestedPayload {
			p := payload
			p.TenantID = ""
			return p
		}()},
		{"missing envelope tenant", events.Envelope{}, payload},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if err := sub.Handle(context.Background(), tc.env, tc.payload); err == nil {
				t.Error("expected validation error")
			}
		})
	}
}

func TestClosureSubscriber_UserNotFound_EmitsCompletedNoOp(t *testing.T) {
	t.Parallel()
	users := inmem.NewUserRepository() // empty — ErrUserNotFound
	rec := events.NewRecorder()
	sub := events.NewClosureSubscriber(users, events.NewEconomyPublisher(rec), nil)
	env, payload := closureEnvAndPayload()
	if err := sub.Handle(context.Background(), env, payload); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	got := rec.RecordedByTopic(events.TopicPseudonymiseCompleted)
	if len(got) != 1 {
		t.Fatalf("expected 1 completed emit, got %d", len(got))
	}
	if got[0].Payload["saga_id"] != payload.SagaID {
		t.Errorf("saga_id missing: %+v", got[0].Payload)
	}
}

func TestClosureSubscriber_UserNotFound_NilPublisher_OK(t *testing.T) {
	t.Parallel()
	sub := events.NewClosureSubscriber(inmem.NewUserRepository(), nil, nil)
	env, payload := closureEnvAndPayload()
	if err := sub.Handle(context.Background(), env, payload); err != nil {
		t.Fatalf("Handle with nil publisher must succeed: %v", err)
	}
}

func TestClosureSubscriber_LookupError_Propagates(t *testing.T) {
	t.Parallel()
	boom := errors.New("users db down")
	sub := events.NewClosureSubscriber(&fakeClosureRepo{getErr: boom}, nil, nil)
	env, payload := closureEnvAndPayload()
	if err := sub.Handle(context.Background(), env, payload); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom", err)
	}
}

func TestClosureSubscriber_SaveError_Propagates(t *testing.T) {
	t.Parallel()
	u, err := identity.NewUser(identity.NewUserParams{
		Email: "saveerr@mightymind.sg", IdentityProvider: identity.ProviderOIDC,
		FederatedSubject: "google|saveerr-001",
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	env, payload := closureEnvAndPayload()
	u.Gcid = payload.Gcid
	boom := errors.New("write failed")
	sub := events.NewClosureSubscriber(&fakeClosureRepo{getUser: u, saveErr: boom}, nil, nil)
	if err := sub.Handle(context.Background(), env, payload); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom", err)
	}
}

func TestClosureSubscriber_DEKShred_TerminalStep(t *testing.T) {
	t.Parallel()
	users := inmem.NewUserRepository()
	u, err := identity.NewUser(identity.NewUserParams{
		Email: "dek@mightymind.sg", IdentityProvider: identity.ProviderOIDC,
		FederatedSubject: "google|dek-001",
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	env, payload := closureEnvAndPayload()
	u.Gcid = payload.Gcid
	if err := users.Save(context.Background(), u); err != nil {
		t.Fatalf("seed save: %v", err)
	}
	rec := events.NewRecorder()
	dek := &fakeDEK{}
	sub := events.NewClosureSubscriberWithDEK(users, events.NewEconomyPublisher(rec), dek, nil)
	if err := sub.Handle(context.Background(), env, payload); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if len(dek.shredded) != 1 || dek.shredded[0] != payload.Gcid {
		t.Errorf("ShredDEK calls = %v, want [%s]", dek.shredded, payload.Gcid)
	}
	if len(rec.RecordedByTopic(events.TopicPseudonymiseCompleted)) != 1 {
		t.Error("completed event must still be emitted after shred")
	}
}

func TestClosureSubscriber_DEKShred_ErrorIsNonFatal(t *testing.T) {
	t.Parallel()
	users := inmem.NewUserRepository()
	u, err := identity.NewUser(identity.NewUserParams{
		Email: "dekerr@mightymind.sg", IdentityProvider: identity.ProviderOIDC,
		FederatedSubject: "google|dekerr-001",
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	env, payload := closureEnvAndPayload()
	u.Gcid = payload.Gcid
	if err := users.Save(context.Background(), u); err != nil {
		t.Fatalf("seed save: %v", err)
	}
	sub := events.NewClosureSubscriberWithDEK(users, nil, &fakeDEK{shredErr: errors.New("kms unavailable")}, nil)
	if err := sub.Handle(context.Background(), env, payload); err != nil {
		t.Fatalf("shred failure must not fail the saga: %v", err)
	}
}
