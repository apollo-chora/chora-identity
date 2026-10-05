// In-memory adapter for kyc.PrefillRepository.
//
// Production swaps to a pgx-backed repo backed by chora_identity DB. The
// raw NRIC is encrypted under the per-user DEK at the SQL repo layer; this
// in-memory implementation stores plaintext (intentional — tests need to
// compare values for assertion). The redacted view never includes raw NRIC.
package repo

import (
	"context"
	"errors"
	"log"
	"sync"

	"github.com/apollo-chora/chora-common/durabilityguard"
	"github.com/apollo-chora/chora-identity/internal/domain/kyc"
)

// ErrPrefillNotDurable is returned by Save when a database is configured and
// the guard is in enforce mode. It is deliberately not returned in report mode:
// see the note on Save.
var ErrPrefillNotDurable = errors.New(
	"kyc prefill: refusing to accept MyInfo data into a volatile store while a database is configured")

// InMemPrefillRepo is the in-memory implementation of kyc.PrefillRepository.
type InMemPrefillRepo struct {
	mu    sync.RWMutex
	store map[string]*kyc.MyInfoPrefill // keyed by gcid

	// dbConfigured records whether a database was configured at construction.
	// When it is, every Save here is losing real MyInfo data.
	dbConfigured bool
	warned       bool
}

// NewInMemPrefillRepo constructs an empty repo.
func NewInMemPrefillRepo() *InMemPrefillRepo {
	return &InMemPrefillRepo{
		store:        make(map[string]*kyc.MyInfoPrefill),
		dbConfigured: durabilityguard.DBConfigured(),
	}
}

// Save upserts the prefill record for the given gcid.
//
// ⚠ FAIL-LOUD WHEN A DATABASE IS CONFIGURED (2026-09-02, CHO-2419 follow-up).
// There is no pg adapter for this port and NO TABLE for it either: chora_identity
// holds 51 tables and none is a MyInfo prefill, and no migration mentions one.
// So with a database configured, every Save here accepts a Singpass MyInfo
// record (full name, raw NRIC, date of birth, nationality, mobile, employer,
// full address) and returns nil while discarding it on the next restart. A nil
// return that discards PII is a fabricated success, which the engineering
// standard forbids outright.
//
// The durability guard reports this port at boot, but a boot report is one line
// among seven violations and says nothing at the moment data is actually lost.
// This says it at the point of loss, names what was lost, and is greppable.
//
// Report vs enforce follows the guard's existing switch rather than inventing a
// second one. In report mode it logs and still stores, because returning an
// error here would break the live Singpass KYC fast-path for a gap that has
// existed for months and that no adapter yet exists to fix. Under
// CHORA_DURABILITY_GUARD=enforce it refuses, which is the correct behaviour once
// the ADR-186 encrypted table lands and an operator is choosing to demand
// durability.
func (r *InMemPrefillRepo) Save(_ context.Context, p *kyc.MyInfoPrefill) error {
	if r.dbConfigured {
		gcid := ""
		if p != nil {
			gcid = p.Gcid
		}
		if durabilityguard.ModeFromEnv() == durabilityguard.ModeEnforce {
			log.Printf("DURABILITY-GUARD service=chora-identity port=myinfo_prefill FATAL-WRITE "+
				"gcid=%s: refusing a MyInfo prefill write into a volatile store with CHORA_DB_DSN set", gcid)
			return ErrPrefillNotDurable
		}
		r.mu.Lock()
		first := !r.warned
		r.warned = true
		r.mu.Unlock()
		if first {
			log.Printf("DURABILITY-GUARD service=chora-identity port=myinfo_prefill ERROR: " +
				"MyInfo prefill (name, raw NRIC, DOB, nationality, mobile, employer, address) is being " +
				"written to an IN-MEMORY store while CHORA_DB_DSN is set. There is no pg adapter and no " +
				"table for this port, so every record is lost on restart. Tracked as an ADR-scoped " +
				"decision: the table is new PII on the ADR-186 crypto-shred path and needs a " +
				"PII_Closure_Map.yaml entry. Set CHORA_DURABILITY_GUARD=enforce to refuse instead.")
		}
		log.Printf("DURABILITY-GUARD service=chora-identity port=myinfo_prefill LOSSY-WRITE gcid=%s", gcid)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	clone := *p
	if p.DeletedAt != nil {
		t := *p.DeletedAt
		clone.DeletedAt = &t
	}
	r.store[p.Gcid] = &clone
	return nil
}

// GetByGcid returns the latest prefill for the gcid, or ErrPrefillNotFound.
func (r *InMemPrefillRepo) GetByGcid(_ context.Context, gcid string) (*kyc.MyInfoPrefill, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.store[gcid]
	if !ok || p.DeletedAt != nil {
		return nil, kyc.ErrPrefillNotFound
	}
	clone := *p
	return &clone, nil
}

// HasPrefill is a test-friendly helper used by handler-level specs to assert
// the prefill was persisted without exposing internal fields.
func (r *InMemPrefillRepo) HasPrefill(gcid string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.store[gcid]
	return ok && p.DeletedAt == nil
}

// Compile-time guard.
var _ kyc.PrefillRepository = (*InMemPrefillRepo)(nil)
