// In-memory adapters for the WebAuthn / Passkey persistence ports.
//
// Production wires this to pgx against the chora_identity DB
// (passkey_challenges + passkey_credentials tables; deferred to M12).
package inmem

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"

	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// -----------------------------------------------------------------------------
// PasskeyChallengeRepository
// -----------------------------------------------------------------------------

// PasskeyChallengeRepository is the in-memory adapter for
// identity.PasskeyChallengeRepository.
type PasskeyChallengeRepository struct {
	mu         sync.RWMutex
	challenges map[string]*identity.PasskeyChallenge // keyed by challenge_id
}

// NewPasskeyChallengeRepository constructs a fresh in-memory store.
func NewPasskeyChallengeRepository() *PasskeyChallengeRepository {
	return &PasskeyChallengeRepository{challenges: make(map[string]*identity.PasskeyChallenge)}
}

// Save inserts or replaces the challenge by ChallengeID. Defensive copy on
// write so callers can mutate their own pointer without corrupting the store.
//
// Resilience contract (per memory feedback_resilience_priority.md):
// concurrent verify calls on the same challenge_id MUST NOT both succeed.
// First-Save-Wins on the Pending → Consumed terminal transition: once the
// stored entry is in Consumed state, ANY subsequent Save (even one that
// itself carries Consumed) is rejected with
// identity.ErrPasskeyChallengeConsumed. This collapses the read-modify-save
// TOCTOU window — concurrent goroutines both observe Pending, both compute
// Consumed locally, and exactly one wins the Save race.
//
// The production pgx adapter (M12) implements the same invariant via
// SELECT ... FOR UPDATE on the challenge row + status guard in the UPDATE
// WHERE clause:
//
//	UPDATE passkey_challenges SET status = 'consumed', verified_gcid = $2
//	WHERE challenge_id = $1 AND status != 'consumed'
//	RETURNING ... — caller checks rows-affected; 0 means the lost-race path.
func (r *PasskeyChallengeRepository) Save(_ context.Context, c *identity.PasskeyChallenge) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.challenges[c.ChallengeID]; ok {
		// First-Save-Wins: a stored Consumed entry is terminal. Any further
		// Save attempts (including ones that locally hold Consumed status)
		// are race-losers and rejected.
		if existing.Status == identity.PasskeyChallengeStatusConsumed {
			return identity.ErrPasskeyChallengeConsumed
		}
	}
	clone := *c
	clone.ChallengeBytes = append([]byte(nil), c.ChallengeBytes...)
	r.challenges[c.ChallengeID] = &clone
	return nil
}

// GetByID returns a defensive copy of the stored challenge or
// identity.ErrPasskeyChallengeNotFound.
func (r *PasskeyChallengeRepository) GetByID(_ context.Context, challengeID string) (*identity.PasskeyChallenge, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.challenges[challengeID]
	if !ok {
		return nil, identity.ErrPasskeyChallengeNotFound
	}
	clone := *c
	clone.ChallengeBytes = append([]byte(nil), c.ChallengeBytes...)
	return &clone, nil
}

// -----------------------------------------------------------------------------
// PasskeyCredentialRepository
// -----------------------------------------------------------------------------

// PasskeyCredentialRepository is the in-memory adapter for
// identity.PasskeyCredentialRepository. Indexes credentials by
// SHA-256(credential_id) so the (gcid, credential_id_hash) compound key
// is fast.
type PasskeyCredentialRepository struct {
	mu         sync.RWMutex
	byCredHash map[string]*identity.PasskeyCredential // keyed by hex(sha256(cred_id))
	byUUID     map[string]*identity.PasskeyCredential // keyed by credential_uuid
	byGcid     map[string][]string                    // gcid -> list of credential_uuid
}

// NewPasskeyCredentialRepository constructs a fresh in-memory store.
func NewPasskeyCredentialRepository() *PasskeyCredentialRepository {
	return &PasskeyCredentialRepository{
		byCredHash: make(map[string]*identity.PasskeyCredential),
		byUUID:     make(map[string]*identity.PasskeyCredential),
		byGcid:     make(map[string][]string),
	}
}

// hashCredID returns hex(sha256(b)) — used as the per-credential key.
func hashCredID(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Save inserts or updates the credential. Defensive copy on write.
func (r *PasskeyCredentialRepository) Save(_ context.Context, c *identity.PasskeyCredential) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	clone := *c
	clone.CredentialID = append([]byte(nil), c.CredentialID...)
	clone.PublicKeyCOSE = append([]byte(nil), c.PublicKeyCOSE...)
	hash := hashCredID(c.CredentialID)
	// First time saving by UUID — register on the gcid index.
	if _, exists := r.byUUID[c.CredentialUUID]; !exists {
		r.byGcid[c.Gcid] = append(r.byGcid[c.Gcid], c.CredentialUUID)
	}
	r.byUUID[c.CredentialUUID] = &clone
	r.byCredHash[hash] = &clone
	return nil
}

// GetByCredentialID returns a defensive copy or ErrPasskeyCredentialNotFound.
func (r *PasskeyCredentialRepository) GetByCredentialID(_ context.Context, credentialID []byte) (*identity.PasskeyCredential, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.byCredHash[hashCredID(credentialID)]
	if !ok {
		return nil, identity.ErrPasskeyCredentialNotFound
	}
	clone := *c
	clone.CredentialID = append([]byte(nil), c.CredentialID...)
	clone.PublicKeyCOSE = append([]byte(nil), c.PublicKeyCOSE...)
	return &clone, nil
}

// ListByGcid returns all credentials for a gcid (active + revoked).
func (r *PasskeyCredentialRepository) ListByGcid(_ context.Context, gcid string) ([]*identity.PasskeyCredential, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	uuids := r.byGcid[gcid]
	out := make([]*identity.PasskeyCredential, 0, len(uuids))
	for _, u := range uuids {
		c, ok := r.byUUID[u]
		if !ok {
			continue
		}
		clone := *c
		clone.CredentialID = append([]byte(nil), c.CredentialID...)
		clone.PublicKeyCOSE = append([]byte(nil), c.PublicKeyCOSE...)
		out = append(out, &clone)
	}
	return out, nil
}
