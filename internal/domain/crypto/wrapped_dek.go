// wrapped_dek.go — the WrappedDEKStore port + record for the real (envelope-
// encryption) KeyManager per ADR-186.
//
// The MVP InMemoryKeyManager (dek_stub.go) DERIVES the per-user DEK as
// HMAC(master, gcid) — which is deterministically recomputable, so "forgetting"
// it is NOT a real crypto-shred (a restart regenerates the identical key). The
// real CloudKMSKeyManager (adapter/cryptokms) instead mints a RANDOM per-user
// DEK, wraps it with the Cloud KMS master KEK, and persists ONLY the wrapped
// form here. Crypto-shred = delete the wrapped row → the DEK is unrecoverable.
package crypto

import "context"

// WrappedDEK is one persisted wrapped-DEK record (keyed by gcid). Wrapped is
// the master-KEK-wrapped DEK ciphertext; the plaintext DEK is NEVER stored.
// Deleted=true + empty Wrapped is the crypto-shred tombstone.
type WrappedDEK struct {
	Gcid           string
	Wrapped        []byte
	KEKVersion     string // KMS encrypt response name — re-wrap on KEK rotation
	KMSOperationID string // logical shred op id (audit traceback)
	Deleted        bool
}

// WrappedDEKStore persists + tombstones wrapped per-user DEKs. Production wires
// the pg-backed adapter (chora_identity.user_dek_wrap); tests use the in-memory
// impl. The store is keyed by gcid (GCID is globally unique + tenant-portable),
// which is also why the closure subscriber — cross-tenant by design — can shred
// without a tenant context.
type WrappedDEKStore interface {
	// Get returns the record (alive OR tombstoned) or (nil, nil) if absent.
	Get(ctx context.Context, gcid string) (*WrappedDEK, error)
	// Put persists a freshly wrapped DEK. Idempotent — re-put is a no-op.
	Put(ctx context.Context, dek WrappedDEK) error
	// MarkDeleted tombstones the row (deleted_at) + scrubs the wrapped bytes.
	// Idempotent — absent / already-deleted is a no-op (never errors).
	MarkDeleted(ctx context.Context, gcid, opID string) error
}
