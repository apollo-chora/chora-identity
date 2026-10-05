// WebAuthn repository ports — persistence interfaces owned by the domain.
//
// Adapters (in-memory, Cloud SQL via pgx) implement these; the domain MUST
// NOT import any adapter package.
package identity

import (
	"context"
	"errors"
)

// Sentinels — exported so handlers can errors.Is() against them.
var (
	ErrPasskeyChallengeNotFound  = errors.New("passkey challenge not found")
	ErrPasskeyCredentialNotFound = errors.New("passkey credential not found")
)

// PasskeyChallengeRepository is the per-challenge persistence port.
// Single-use guarantee: MarkConsumed is the only way a Pending/Verified
// challenge is closed for replay protection.
type PasskeyChallengeRepository interface {
	Save(ctx context.Context, c *PasskeyChallenge) error
	GetByID(ctx context.Context, challengeID string) (*PasskeyChallenge, error)
}

// PasskeyCredentialRepository is the long-lived credential persistence port.
// One credential row per (gcid, credential_id_hash) pair.
type PasskeyCredentialRepository interface {
	Save(ctx context.Context, c *PasskeyCredential) error
	// GetByCredentialID returns the credential row matching the
	// authenticator-supplied credential_id bytes. Adapters typically index
	// by SHA-256(credential_id) for compact key.
	GetByCredentialID(ctx context.Context, credentialID []byte) (*PasskeyCredential, error)
	// ListByGcid returns all credentials owned by a gcid (active + revoked).
	ListByGcid(ctx context.Context, gcid string) ([]*PasskeyCredential, error)
}
