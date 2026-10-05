// user_dek_wrap_repository.go — pgx-backed crypto.WrappedDEKStore (ADR-186).
//
// Stores the master-KEK-wrapped per-user DEK (the plaintext DEK is NEVER
// persisted) in chora_identity.user_dek_wrap, keyed by gcid. Crypto-shred =
// MarkDeleted (deleted_at tombstone + scrub the wrapped bytes) → the DEK is
// unrecoverable.
//
// NO RLS on user_dek_wrap (migration 0021): it holds OPAQUE wrapped key
// ciphertext keyed by gcid (not tenant business data / not readable PII), and
// the closure subscriber writes it cross-tenant (no tenant context). Consistent
// with ADR-186 §D6 — a key table, not an RLS-bypass policy. Cross-DB queries
// forbidden — this table lives in chora_identity.
package pg

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/apollo-chora/chora-identity/internal/domain/crypto"
)

// UserDEKWrapRepository is the pgx-backed wrapped-DEK store.
type UserDEKWrapRepository struct {
	q Querier
}

// NewUserDEKWrapRepository wraps a Querier (production: *PgxPoolQuerier).
func NewUserDEKWrapRepository(q Querier) *UserDEKWrapRepository {
	return &UserDEKWrapRepository{q: q}
}

const (
	userDEKWrapSelectSQL = `SELECT wrapped_dek, kek_version, kms_operation_id, deleted_at ` +
		`FROM user_dek_wrap WHERE gcid = $1`
	// Idempotent re-issue: ON CONFLICT keeps the original wrap (protects
	// in-flight ciphertexts) — re-wrapping would orphan them.
	userDEKWrapInsertSQL = `INSERT INTO user_dek_wrap (gcid, wrapped_dek, kek_version, created_at) ` +
		`VALUES ($1, $2, $3, now()) ON CONFLICT (gcid) DO NOTHING`
	// Tombstone + scrub in one statement; only the first shred wins
	// (deleted_at IS NULL gate). Idempotent.
	userDEKWrapTombstoneSQL = `UPDATE user_dek_wrap ` +
		`SET deleted_at = now(), wrapped_dek = ''::bytea, kms_operation_id = $2 ` +
		`WHERE gcid = $1 AND deleted_at IS NULL`
)

// Get returns the wrapped DEK record (alive OR tombstoned) or (nil, nil).
func (r *UserDEKWrapRepository) Get(ctx context.Context, gcid string) (*crypto.WrappedDEK, error) {
	var (
		wrapped   []byte
		kek       string
		opID      string
		deletedAt *time.Time
	)
	err := r.q.QueryRow(ctx, userDEKWrapSelectSQL, gcid).Scan(&wrapped, &kek, &opID, &deletedAt)
	if errors.Is(err, ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("pg: user_dek_wrap get: %w", err)
	}
	return &crypto.WrappedDEK{
		Gcid:           gcid,
		Wrapped:        wrapped,
		KEKVersion:     kek,
		KMSOperationID: opID,
		Deleted:        deletedAt != nil,
	}, nil
}

// Put persists a freshly wrapped DEK (idempotent — ON CONFLICT DO NOTHING).
func (r *UserDEKWrapRepository) Put(ctx context.Context, dek crypto.WrappedDEK) error {
	if err := r.q.Exec(ctx, userDEKWrapInsertSQL, dek.Gcid, dek.Wrapped, dek.KEKVersion); err != nil {
		return fmt.Errorf("pg: user_dek_wrap put: %w", err)
	}
	return nil
}

// MarkDeleted tombstones the row + scrubs the wrapped bytes (idempotent).
func (r *UserDEKWrapRepository) MarkDeleted(ctx context.Context, gcid, opID string) error {
	if err := r.q.Exec(ctx, userDEKWrapTombstoneSQL, gcid, opID); err != nil {
		return fmt.Errorf("pg: user_dek_wrap tombstone: %w", err)
	}
	return nil
}

// compile-time: the repo satisfies the WrappedDEKStore port.
var _ crypto.WrappedDEKStore = (*UserDEKWrapRepository)(nil)
