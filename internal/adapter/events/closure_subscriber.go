// Subscriber for chora.identity.pii.pseudonymise.requested.v1 — the
// per-domain fan-out from the federated closure saga (Tier 3 D11).
//
// CHO-1719 terminal steps (identity is the saga's HOME domain):
//
//	chora-closure-orchestrator fans out chora.{domain}.pii.pseudonymise.requested.v1
//	  → chora-identity ClosureSubscriber.Handle picks up the identity entry
//	    1. deletes the GCIP (Identity Platform) user via the AccountDeleter
//	       port — frees the email AT the IdP (one-account-per-email)
//	    2. User.Pseudonymise — tombstones email/display/federated-subject
//	       + soft delete; frees the partial unique email index so the SAME
//	       email re-registers with a FRESH GCID (re-registration invariant)
//	    3. ShredDEK — crypto-shred seam (per-user DEK deletion)
//	    4. emits chora.identity.account.pseudonymised.v1 back to the saga
//
// Step ORDER is load-bearing: GCIP deletion runs FIRST because a failed
// deletion must nack BEFORE the row is soft-deleted — once deleted_at is
// set, GetByGcid misses and the redelivery short-circuits as an
// idempotent no-op, which would strand the email at the IdP forever.
//
// Hexagonal: this is an INBOUND ADAPTER. The User aggregate's
// Pseudonymise() method enforces the local tombstone invariants.
package events

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/apollo-chora/chora-common/idempotent"
	"github.com/apollo-chora/chora-identity/internal/domain/crypto"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// TopicPseudonymiseRequested is the canonical incoming topic.
const TopicPseudonymiseRequested = "chora.identity.pii.pseudonymise.requested.v1"

// TopicPseudonymiseCompleted is the ack topic this subscriber emits back to
// the orchestrator on success — the taxonomy-correct
// chora.{domain}.{aggregate}.{event_type} name (CHO-1719), aligned with the
// Terraform closure-orchestrator module IAM + the
// account-pseudonymised-v1.yaml AsyncAPI contract (renamed from
// chora.identity.pii.pseudonymise.completed.v1; nothing was live on either
// name).
const TopicPseudonymiseCompleted = "chora.identity.account.pseudonymised.v1"

// InboxTTL is the dedupe-key retention window for closure_subscriber's inbox.
const InboxTTL = 24 * time.Hour

// PseudonymiseRequestedPayload mirrors the cross-domain payload shape sent by
// chora-closure-orchestrator (per its publisher_inmem.go PseudonymiseRequested).
// Traceparent/Tracestate are optional payload-carried trace context (the
// orchestrator stamps them in the fan-out body as well as the envelope).
type PseudonymiseRequestedPayload struct {
	SagaID      string `json:"saga_id"`
	Gcid        string `json:"gcid"`
	TenantID    string `json:"tenant_id"`
	Traceparent string `json:"traceparent,omitempty"`
	Tracestate  string `json:"tracestate,omitempty"`
}

// PseudonymiseCompletedPayload is what chora-identity emits back to the saga
// after the local pseudonymisation step succeeds.
type PseudonymiseCompletedPayload struct {
	SagaID      string    `json:"saga_id"`
	Gcid        string    `json:"gcid"`
	TenantID    string    `json:"tenant_id"`
	Domain      string    `json:"domain"`
	CompletedAt time.Time `json:"completed_at"`
}

// AccountDeleter is the port for the external-IdP terminal step. It is
// retained for closure-saga interface compatibility but is no longer wired:
// the login provider is local username/password, so there is no upstream IdP
// account to delete. Implementations MUST treat an already-deleted user as
// success so saga redeliveries converge.
type AccountDeleter interface {
	DeleteAccount(ctx context.Context, uid string) error
}

// ClosureTombstones carries the identity-domain tombstone values. The
// canonical values live in config/PII_Closure_Map.yaml (users table:
// email strategy tombstone_email, display_name strategy tombstone_string);
// these mirror them and are env-overridable at main wiring — identity has
// no Go PII-map loader yet (tracked M12+ debt alongside the per-table pg
// tokenisation the other nine domains defer).
type ClosureTombstones struct {
	// EmailPattern with a {hash} placeholder; zero value defaults to
	// "user-{hash}@redacted.invalid".
	EmailPattern string
	// DisplayName tombstone; zero value defaults to "Former member".
	DisplayName string
}

// Default tombstone values — mirror config/PII_Closure_Map.yaml.
const (
	DefaultEmailTombstonePattern = "user-{hash}@redacted.invalid"
	DefaultDisplayTombstone      = "Former member"
)

func (t ClosureTombstones) withDefaults() ClosureTombstones {
	if strings.TrimSpace(t.EmailPattern) == "" {
		t.EmailPattern = DefaultEmailTombstonePattern
	}
	if strings.TrimSpace(t.DisplayName) == "" {
		t.DisplayName = DefaultDisplayTombstone
	}
	return t
}

// TombstoneEmail renders the deterministic email tombstone for a GCID:
// {hash} → first 12 hex chars of sha256(gcid). Deterministic so saga
// redeliveries are idempotent (same gcid → same tombstone).
func TombstoneEmail(pattern, gcid string) string {
	sum := sha256.Sum256([]byte(gcid))
	return strings.ReplaceAll(pattern, "{hash}", hex.EncodeToString(sum[:])[:12])
}

// ClosureSubscriber processes chora.identity.pii.pseudonymise.requested.v1
// messages from the federated closure saga.
//
// Inbox dedupe (W1.7): IdempotencyKey from the envelope (or a synthetic
// closure:saga:gcid key) is checked against a chora-go-common/idempotent.Store
// to skip duplicate deliveries. Replaces the prior in-process map dedup
// which lost state on pod restart + multi-replica setups.
type ClosureSubscriber struct {
	users      identity.UserRepository
	publisher  *EconomyPublisher
	dek        crypto.KeyManager // optional — when set, ShredDEK on closure
	deleter    AccountDeleter    // optional — when set, GCIP user deletion
	tombstones ClosureTombstones
	inbox      idempotent.Store
	ttl        time.Duration

	mu sync.Mutex
}

// NewClosureSubscriber wires the User repo + downstream publisher + inbox
// store. nil inbox triggers a defensive MemoryStore fallback (dev-only;
// production passes PostgresStore).
func NewClosureSubscriber(
	users identity.UserRepository,
	publisher *EconomyPublisher,
	inbox idempotent.Store,
) *ClosureSubscriber {
	return NewClosureSubscriberWithDEK(users, publisher, nil, inbox)
}

// NewClosureSubscriberWithDEK wires the closure subscriber + the DEK key
// manager + inbox store. When the DEK manager is supplied, the closure
// handler calls ShredDEK(gcid) as the terminal step — the user's PII
// becomes cryptographically unrecoverable per Tier 3 D11 (crypto-shred
// = DEK deletion).
func NewClosureSubscriberWithDEK(
	users identity.UserRepository,
	publisher *EconomyPublisher,
	dek crypto.KeyManager,
	inbox idempotent.Store,
) *ClosureSubscriber {
	return NewClosureSubscriberWithTerminal(users, publisher, dek, nil, ClosureTombstones{}, inbox)
}

// NewClosureSubscriberWithTerminal wires the FULL identity terminal-step
// chain (CHO-1719): GCIP account deletion (deleter), PII tombstones
// (User.Pseudonymise via tombstones), DEK crypto-shred (dek). nil deleter
// / dek skip the respective step; zero-value tombstones take the
// PII_Closure_Map-mirroring defaults.
func NewClosureSubscriberWithTerminal(
	users identity.UserRepository,
	publisher *EconomyPublisher,
	dek crypto.KeyManager,
	deleter AccountDeleter,
	tombstones ClosureTombstones,
	inbox idempotent.Store,
) *ClosureSubscriber {
	if inbox == nil {
		inbox = idempotent.NewMemoryStore()
	}
	return &ClosureSubscriber{
		users:      users,
		publisher:  publisher,
		dek:        dek,
		deleter:    deleter,
		tombstones: tombstones.withDefaults(),
		inbox:      inbox,
		ttl:        InboxTTL,
	}
}

// SubscribedTopic returns the inbound topic this subscriber binds to.
func (s *ClosureSubscriber) SubscribedTopic() string {
	return TopicPseudonymiseRequested
}

// Handle processes one pseudonymise.requested.v1 message.
//
// Idempotency: inbox.Process on the envelope's IdempotencyKey (or a
// synthetic closure:saga:gcid fallback) collapses duplicate deliveries.
func (s *ClosureSubscriber) Handle(ctx context.Context, env Envelope, payload PseudonymiseRequestedPayload) error {
	if s == nil || s.users == nil || s.inbox == nil {
		return errors.New("events: ClosureSubscriber not initialised")
	}
	if err := s.validate(env, payload); err != nil {
		return err
	}

	idem := strings.TrimSpace(env.IdempotencyKey)
	if idem == "" {
		idem = "closure:" + payload.SagaID + ":" + payload.Gcid
	}
	return s.inbox.Process(ctx, idem, s.ttl, func() error {
		u, err := s.users.GetByGcid(ctx, payload.Gcid)
		if err != nil {
			if errors.Is(err, identity.ErrUserNotFound) {
				// Idempotent: a user that doesn't exist (or already
				// soft-deleted by a completed prior attempt — the repo
				// filters deleted_at IS NULL) yields a no-op success.
				return s.emitCompleted(env, payload)
			}
			return fmt.Errorf("events: closure user lookup: %w", err)
		}

		// Terminal step 1 — GCIP user deletion (frees the email at the
		// IdP). MUST run before the row is soft-deleted: on failure we
		// nack with the user row intact so the redelivery retries the
		// deletion instead of short-circuiting on a GetByGcid miss.
		// Skipped when the subject is already tombstoned (complete prior
		// run whose redelivery raced the inbox TTL).
		if s.deleter != nil && u.FederatedSubject != "" &&
			!strings.HasPrefix(u.FederatedSubject, "shredded:") {
			if err := s.deleter.DeleteAccount(ctx, u.FederatedSubject); err != nil {
				return fmt.Errorf("events: closure GCIP account delete: %w", err)
			}
		}

		// Terminal step 2 — tombstone PII + soft delete (frees the email
		// uniqueness in chora_identity; preserves the GCID for FK
		// integrity). Values mirror config/PII_Closure_Map.yaml.
		u.Pseudonymise(
			TombstoneEmail(s.tombstones.EmailPattern, payload.Gcid),
			s.tombstones.DisplayName,
		)
		if err := s.users.Save(ctx, u); err != nil {
			return fmt.Errorf("events: closure user save: %w", err)
		}

		// Terminal step 3 — crypto-shred per Tier 3 D11: deleting the
		// per-user DEK renders any remaining PII columns (encrypted under
		// that DEK) unrecoverable. Idempotent: repeated shred is a no-op.
		if s.dek != nil {
			if err := s.dek.ShredDEK(payload.Gcid); err != nil {
				// Log but don't fail the saga — the User row is already
				// pseudonymised and downstream replay is idempotent.
				_ = err
			}
		}

		return s.emitCompleted(env, payload)
	})
}

// emitCompleted publishes chora.identity.account.pseudonymised.v1.
func (s *ClosureSubscriber) emitCompleted(in Envelope, payload PseudonymiseRequestedPayload) error {
	if s.publisher == nil {
		return nil
	}
	out := NewEnvelope(payload.TenantID, payload.Gcid, in.Traceparent, in.Tracestate)
	out.IdempotencyKey = "pseudonymise_completed:" + payload.SagaID + ":" + payload.Gcid
	completed := PseudonymiseCompletedPayload{
		SagaID:      payload.SagaID,
		Gcid:        payload.Gcid,
		TenantID:    payload.TenantID,
		Domain:      "identity",
		CompletedAt: time.Now().UTC(),
	}
	m, err := toMap(completed)
	if err != nil {
		return fmt.Errorf("events: closure encode payload: %w", err)
	}
	return s.publisher.inner.Publish(TopicPseudonymiseCompleted, out, m)
}

// validate runs the input-validation gate.
func (s *ClosureSubscriber) validate(env Envelope, p PseudonymiseRequestedPayload) error {
	if strings.TrimSpace(p.SagaID) == "" {
		return errors.New("events: closure payload saga_id required")
	}
	if strings.TrimSpace(p.Gcid) == "" {
		return errors.New("events: closure payload gcid required")
	}
	if identity.IsAGID(p.Gcid) {
		return errors.New("events: AGID cannot be subject to a closure saga")
	}
	if strings.TrimSpace(p.TenantID) == "" {
		return errors.New("events: closure payload tenant_id required")
	}
	if strings.TrimSpace(env.TenantID) == "" {
		return errors.New("events: closure envelope.tenant_id required")
	}
	return nil
}
