// CHO-1719 — identity terminal-step tests: GCIP account deletion (frees
// the email at the IdP), email tombstone (frees uniqueness in
// chora_identity), DEK shred (existing), and the re-registration
// invariant (same email → FRESH GCID; old GCID stays pseudonymised).
package events_test

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/apollo-chora/chora-identity/internal/adapter/events"
	"github.com/apollo-chora/chora-identity/internal/adapter/inmem"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// fakeDeleter doubles the events.AccountDeleter port.
type fakeDeleter struct {
	calls []string
	fail  error
}

func (f *fakeDeleter) DeleteAccount(_ context.Context, uid string) error {
	if f.fail != nil {
		return f.fail
	}
	f.calls = append(f.calls, uid)
	return nil
}

func seedActiveUser(t *testing.T, users *inmem.UserRepository, gcid string) *identity.User {
	t.Helper()
	u, err := identity.NewUser(identity.NewUserParams{
		Email:            "phyllis@mightymind.sg",
		DisplayName:      "Phyllis",
		IdentityProvider: identity.ProviderOIDC,
		FederatedSubject: "fed-sub-phyllis",
	})
	if err != nil {
		t.Fatalf("NewUser: %v", err)
	}
	u.Gcid = gcid
	if err := users.Save(context.Background(), u); err != nil {
		t.Fatalf("seed save: %v", err)
	}
	return u
}

const (
	termGcid   = "01935b5a-9bcf-7000-8000-0000000000cc"
	termTenant = "01935b5a-9bcf-7000-8000-000000000010"
)

func termPayload() events.PseudonymiseRequestedPayload {
	return events.PseudonymiseRequestedPayload{
		SagaID: "saga-term-1", Gcid: termGcid, TenantID: termTenant,
	}
}

var tombstoneEmailRE = regexp.MustCompile(`^user-[0-9a-f]{12}@redacted\.invalid$`)

func TestClosureSubscriber_TerminalSteps_GCIPDeleteAndTombstone(t *testing.T) {
	users := inmem.NewUserRepository()
	rec := events.NewRecorder()
	del := &fakeDeleter{}
	sub := events.NewClosureSubscriberWithTerminal(
		users, events.NewEconomyPublisher(rec), nil, del,
		events.ClosureTombstones{}, nil,
	)
	seedActiveUser(t, users, termGcid)

	env := events.NewEnvelope(termTenant, termGcid, "00-a-b-01", "")
	if err := sub.Handle(context.Background(), env, termPayload()); err != nil {
		t.Fatalf("handle: %v", err)
	}

	// GCIP user deleted with the ORIGINAL federated subject (federated subject).
	if len(del.calls) != 1 || del.calls[0] != "fed-sub-phyllis" {
		t.Fatalf("deleter calls = %v; want the original federated subject", del.calls)
	}

	got, err := users.GetByGcid(context.Background(), termGcid)
	if err != nil {
		t.Fatalf("GetByGcid: %v", err)
	}
	if !tombstoneEmailRE.MatchString(got.Email) {
		t.Errorf("email = %q; want tombstone user-{hash}@redacted.invalid", got.Email)
	}
	if got.DisplayName != "Former member" {
		t.Errorf("display name = %q", got.DisplayName)
	}
	if got.Status != identity.UserStatusClosed || got.DeletedAt == nil {
		t.Errorf("user must be closed + soft-deleted; status=%v deleted_at=%v", got.Status, got.DeletedAt)
	}
	if !strings.HasPrefix(got.FederatedSubject, "shredded:") {
		t.Errorf("federated subject = %q; want shredded: tombstone", got.FederatedSubject)
	}

	// Ack lands on the taxonomy-correct NEW topic with domain=identity.
	emitted := rec.RecordedByTopic("chora.identity.account.pseudonymised.v1")
	if len(emitted) != 1 {
		t.Fatalf("want 1 ack on chora.identity.account.pseudonymised.v1; got %d", len(emitted))
	}
	if emitted[0].Payload["domain"] != "identity" {
		t.Errorf("ack domain = %v", emitted[0].Payload["domain"])
	}
}

func TestClosureSubscriber_DeleterFailureNacksAndRetries(t *testing.T) {
	users := inmem.NewUserRepository()
	rec := events.NewRecorder()
	del := &fakeDeleter{fail: errors.New("gcip 500")}
	sub := events.NewClosureSubscriberWithTerminal(
		users, events.NewEconomyPublisher(rec), nil, del,
		events.ClosureTombstones{}, nil,
	)
	seedActiveUser(t, users, termGcid)

	env := events.NewEnvelope(termTenant, termGcid, "00-a-b-01", "")
	if err := sub.Handle(context.Background(), env, termPayload()); err == nil {
		t.Fatal("GCIP delete failure must error (pull loop nacks; email would never be freed)")
	}

	// User untouched — pseudonymisation must NOT proceed past a failed
	// GCIP deletion or a redelivery would skip it (user row soft-deleted
	// = GetByGcid miss = idempotent-completed short-circuit).
	got, err := users.GetByGcid(context.Background(), termGcid)
	if err != nil {
		t.Fatalf("GetByGcid: %v", err)
	}
	if got.Email != "phyllis@mightymind.sg" || got.Status != identity.UserStatusActive {
		t.Fatalf("user must be untouched after deleter failure; got %+v", got)
	}
	if n := len(rec.RecordedByTopic("chora.identity.account.pseudonymised.v1")); n != 0 {
		t.Fatalf("no ack on failure; got %d", n)
	}

	// Retry (redelivery) succeeds once GCIP recovers — the inbox must not
	// have recorded the failed attempt.
	del.fail = nil
	if err := sub.Handle(context.Background(), env, termPayload()); err != nil {
		t.Fatalf("retry handle: %v", err)
	}
	if n := len(rec.RecordedByTopic("chora.identity.account.pseudonymised.v1")); n != 1 {
		t.Fatalf("want 1 ack after successful retry; got %d", n)
	}
}

func TestClosureSubscriber_ReRegistrationMintsFreshGCID(t *testing.T) {
	// The CHO-1719 gap-7 invariant at subscriber level: close → email
	// reusable → fresh GCID; old GCID stays pseudonymised.
	users := inmem.NewUserRepository()
	rec := events.NewRecorder()
	sub := events.NewClosureSubscriberWithTerminal(
		users, events.NewEconomyPublisher(rec), nil, &fakeDeleter{},
		events.ClosureTombstones{}, nil,
	)
	old := seedActiveUser(t, users, termGcid)
	originalEmail := old.Email

	env := events.NewEnvelope(termTenant, termGcid, "00-a-b-01", "")
	if err := sub.Handle(context.Background(), env, termPayload()); err != nil {
		t.Fatalf("handle: %v", err)
	}

	closed, err := users.GetByGcid(context.Background(), termGcid)
	if err != nil {
		t.Fatalf("GetByGcid: %v", err)
	}
	if closed.Email == originalEmail {
		t.Fatal("closure must release the original email")
	}

	// Re-registration with the SAME email mints a FRESH GCID (resolve-time
	// NewUser path); the old aggregate stays pseudonymised.
	fresh, err := identity.NewUser(identity.NewUserParams{
		Email:            originalEmail,
		IdentityProvider: identity.ProviderOIDC,
		FederatedSubject: "fed-sub-phyllis-NEW",
	})
	if err != nil {
		t.Fatalf("re-registration NewUser: %v", err)
	}
	if fresh.Gcid == termGcid {
		t.Fatal("re-registration must mint a FRESH GCID")
	}
	if err := users.Save(context.Background(), fresh); err != nil {
		t.Fatalf("save fresh: %v", err)
	}
	// The IdP-stable lookup key of the OLD account no longer resolves —
	// the shredded subject can never resurrect the closed account.
	if _, found := users.FindByFederatedSubject("fed-sub-phyllis"); found {
		t.Fatal("old federated subject must not resolve after pseudonymisation")
	}
	if closed.Status != identity.UserStatusClosed || closed.DeletedAt == nil {
		t.Fatal("old aggregate must stay pseudonymised")
	}
}

func TestClosureSubscriber_AlreadyShreddedSkipsDeleter(t *testing.T) {
	// Redelivery after a complete prior run: subject already tombstoned →
	// the deleter must NOT be re-invoked with a shredded:* token.
	users := inmem.NewUserRepository()
	rec := events.NewRecorder()
	del := &fakeDeleter{}
	sub := events.NewClosureSubscriberWithTerminal(
		users, events.NewEconomyPublisher(rec), nil, del,
		events.ClosureTombstones{}, nil,
	)
	u := seedActiveUser(t, users, termGcid)
	u.Pseudonymise("user-x@redacted.invalid", "Former member")
	if err := users.Save(context.Background(), u); err != nil {
		t.Fatalf("save: %v", err)
	}

	env := events.NewEnvelope(termTenant, termGcid, "00-a-b-01", "")
	if err := sub.Handle(context.Background(), env, termPayload()); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(del.calls) != 0 {
		t.Fatalf("deleter must be skipped for shredded subject; calls=%v", del.calls)
	}
	if n := len(rec.RecordedByTopic("chora.identity.account.pseudonymised.v1")); n != 1 {
		t.Fatalf("idempotent completed ack expected; got %d", n)
	}
}
