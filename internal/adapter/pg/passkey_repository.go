// passkey_repository.go — pgx-backed implementations of
// identity.PasskeyChallengeRepository + identity.PasskeyCredentialRepository.
//
// Closes the M12 deferral marked at internal/adapter/inmem/passkey_repository.go:4
// ("…deferred to M12"). Production wires these against chora_identity DB
// (migration 0015 — passkey_challenges + passkey_credentials).
//
// SQL contract:
//
//   - Challenge.Save: UPSERT on conflict(challenge_id). The first-save-wins
//     invariant (see inmem.PasskeyChallengeRepository.Save) is preserved by
//     reading the stored row inside the same call and rejecting any UPSERT
//     against a row already in PasskeyChallengeStatusConsumed. The check is
//     non-atomic at the read/UPDATE boundary in the pgx-pool path; production
//     callers that need strict atomicity may upgrade to a SELECT ... FOR
//     UPDATE wrapper via TxQuerier (the helper signature is intentionally
//     compatible).
//   - Challenge.GetByID: returns identity.ErrPasskeyChallengeNotFound on miss.
//   - Credential.Save: UPSERT on conflict(credential_id_hash). The hash is
//     sha256(credential_id_bytes) — keeps the unique key fixed-width even
//     when authenticators emit variable-length credential IDs.
//   - Credential.GetByCredentialID / ListByGcid: standard fetch + scan.
//
// Soft delete: passkey rows use status='revoked' semantics (revocation is
// in the credential aggregate) rather than a deleted_at column, matching
// the existing inmem repo behaviour. Queries return active + revoked rows
// for ListByGcid (the inmem repo does the same — callers filter on status).
//
// RLS: passkey_challenges + passkey_credentials are identity-scoped (NOT
// tenant-scoped). The schema has no tenant_id column, matching the `users`
// table convention (migration 0001 §"users"). No SET LOCAL chora.tenant_id
// is required for any of these queries.
//
// Cross-DB queries forbidden — chora-identity reads only chora_identity.
package pg

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// ----------------------------------------------------------------------------
// PasskeyChallengeRepository
// ----------------------------------------------------------------------------

// PasskeyChallengeRepository is the pgx-backed implementation of
// identity.PasskeyChallengeRepository.
type PasskeyChallengeRepository struct {
	q Querier
}

// NewPasskeyChallengeRepository wraps a *PgxPoolQuerier.
func NewPasskeyChallengeRepository(querier *PgxPoolQuerier) *PasskeyChallengeRepository {
	return &PasskeyChallengeRepository{q: querier}
}

// NewPasskeyChallengeRepositoryWithQuerier accepts the lower-level Querier;
// used by unit tests that stub the SQL surface.
func NewPasskeyChallengeRepositoryWithQuerier(q Querier) *PasskeyChallengeRepository {
	return &PasskeyChallengeRepository{q: q}
}

const passkeyChallengeColumns = `challenge_id, challenge_bytes, rp_id, user_handle,
    status, COALESCE(verified_gcid::text, ''),
    created_at, expires_at`

// Save inserts or updates the challenge. Rejects writes against a row that
// the DB already considers Consumed (terminal first-save-wins invariant).
func (r *PasskeyChallengeRepository) Save(ctx context.Context, c *identity.PasskeyChallenge) error {
	if c == nil {
		return errors.New("pg.PasskeyChallengeRepository.Save: nil challenge")
	}

	// First-save-wins: refuse to overwrite a stored Consumed row.
	existing, err := r.GetByID(ctx, c.ChallengeID)
	if err == nil && existing.Status == identity.PasskeyChallengeStatusConsumed {
		return identity.ErrPasskeyChallengeConsumed
	}
	if err != nil && !errors.Is(err, identity.ErrPasskeyChallengeNotFound) {
		return fmt.Errorf("pg.PasskeyChallengeRepository.Save: preflight: %w", err)
	}

	q := `
        INSERT INTO passkey_challenges (
            challenge_id, challenge_bytes, rp_id, user_handle,
            status, verified_gcid, created_at, expires_at
        )
        VALUES (
            $1, $2, $3, $4,
            $5::passkey_challenge_status, NULLIF($6, '')::uuid, $7, $8
        )
        ON CONFLICT (challenge_id) DO UPDATE SET
            status        = EXCLUDED.status,
            verified_gcid = EXCLUDED.verified_gcid,
            expires_at    = EXCLUDED.expires_at
    `
	return r.q.Exec(ctx, q,
		c.ChallengeID,
		append([]byte(nil), c.ChallengeBytes...),
		c.RPID,
		c.UserHandle,
		string(c.Status),
		c.VerifiedGCID,
		c.CreatedAt,
		c.ExpiresAt,
	)
}

// GetByID returns the challenge with the supplied ID.
func (r *PasskeyChallengeRepository) GetByID(ctx context.Context, challengeID string) (*identity.PasskeyChallenge, error) {
	q := `
        SELECT ` + passkeyChallengeColumns + `
        FROM passkey_challenges
        WHERE challenge_id = $1
    `
	row := r.q.QueryRow(ctx, q, challengeID)
	c, err := scanPasskeyChallenge(row)
	if err != nil {
		if errors.Is(err, ErrNoRows) {
			return nil, identity.ErrPasskeyChallengeNotFound
		}
		return nil, fmt.Errorf("pg.PasskeyChallengeRepository.GetByID: %w", err)
	}
	return c, nil
}

// scanPasskeyChallenge maps a row to *identity.PasskeyChallenge.
func scanPasskeyChallenge(row Row) (*identity.PasskeyChallenge, error) {
	var (
		c            identity.PasskeyChallenge
		status       string
		verifiedGCID string
	)
	err := row.Scan(
		&c.ChallengeID,
		&c.ChallengeBytes,
		&c.RPID,
		&c.UserHandle,
		&status,
		&verifiedGCID,
		&c.CreatedAt,
		&c.ExpiresAt,
	)
	if err != nil {
		return nil, err
	}
	c.Status = identity.PasskeyChallengeStatus(status)
	c.VerifiedGCID = verifiedGCID
	c.CreatedAt = c.CreatedAt.UTC()
	c.ExpiresAt = c.ExpiresAt.UTC()
	return &c, nil
}

// ----------------------------------------------------------------------------
// PasskeyCredentialRepository
// ----------------------------------------------------------------------------

// ListQuerier extends Querier with Query (returning Rows) — required by
// ListByGcid which streams multiple credential rows. The production wrapper
// PgxPoolQuerier satisfies this via PgxPoolQuerier.Query(); unit tests inject
// a stub implementing both surfaces.
type ListQuerier interface {
	Querier
	Query(ctx context.Context, sql string, args ...any) (Rows, error)
}

// PasskeyCredentialRepository is the pgx-backed implementation of
// identity.PasskeyCredentialRepository.
type PasskeyCredentialRepository struct {
	q  Querier
	lq ListQuerier // may be nil if constructed without list support
}

// NewPasskeyCredentialRepository wraps a *PgxPoolQuerier.
func NewPasskeyCredentialRepository(querier *PgxPoolQuerier) *PasskeyCredentialRepository {
	return &PasskeyCredentialRepository{q: querier, lq: poolListQuerier{querier: querier}}
}

// NewPasskeyCredentialRepositoryWithQuerier accepts the lower-level Querier
// for unit tests that don't exercise ListByGcid.
func NewPasskeyCredentialRepositoryWithQuerier(q Querier) *PasskeyCredentialRepository {
	return &PasskeyCredentialRepository{q: q}
}

// NewPasskeyCredentialRepositoryWithListQuerier accepts a ListQuerier; used
// by unit tests that exercise ListByGcid.
func NewPasskeyCredentialRepositoryWithListQuerier(lq ListQuerier) *PasskeyCredentialRepository {
	return &PasskeyCredentialRepository{q: lq, lq: lq}
}

const passkeyCredentialColumns = `credential_uuid, gcid::text, credential_id, public_key,
    attestation_type, rp_id, sign_count, status, created_at, last_used_at`

// hashCredID returns hex(sha256(b)) — matches the inmem repo key.
func hashCredID(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Save upserts the credential.
func (r *PasskeyCredentialRepository) Save(ctx context.Context, c *identity.PasskeyCredential) error {
	if c == nil {
		return errors.New("pg.PasskeyCredentialRepository.Save: nil credential")
	}
	q := `
        INSERT INTO passkey_credentials (
            credential_uuid, gcid, credential_id, credential_id_hash,
            public_key, attestation_type, rp_id, sign_count,
            status, created_at, last_used_at,
            aaguid, attestation_verified, authenticator_description,
            mds_certification_level, attestation_object
        )
        VALUES (
            $1, $2::uuid, $3, $4,
            $5, $6, $7, $8,
            $9::passkey_credential_status, $10, $11,
            $12, $13, $14,
            $15, $16
        )
        ON CONFLICT (credential_id_hash) DO UPDATE SET
            sign_count                = EXCLUDED.sign_count,
            status                    = EXCLUDED.status,
            last_used_at              = EXCLUDED.last_used_at,
            aaguid                    = EXCLUDED.aaguid,
            attestation_verified      = EXCLUDED.attestation_verified,
            authenticator_description = EXCLUDED.authenticator_description,
            mds_certification_level   = EXCLUDED.mds_certification_level,
            attestation_object        = EXCLUDED.attestation_object
    `
	return r.q.Exec(ctx, q,
		c.CredentialUUID,
		c.Gcid,
		append([]byte(nil), c.CredentialID...),
		hashCredID(c.CredentialID),
		append([]byte(nil), c.PublicKeyCOSE...),
		c.AttestationType,
		c.RPID,
		int64(c.SignCount),
		string(c.Status),
		c.CreatedAt,
		nullableTime(c.LastUsedAt),
		nullableBytes(c.AAGUID),
		c.AttestationVerified,
		nullableStr(c.AuthenticatorDescription),
		nullableStr(c.MDSCertificationLevel),
		nullableBytes(c.AttestationObject),
	)
}

// nullableBytes returns nil for an empty slice so pgx writes SQL NULL.
func nullableBytes(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

// nullableStr returns nil for an empty string so pgx writes SQL NULL.
func nullableStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// nullableTime returns nil when t is nil, *t otherwise — used so the pgx
// driver writes a SQL NULL into TIMESTAMPTZ columns rather than a zero
// time.Time.
func nullableTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return *t
}

// GetByCredentialID returns the credential whose credential_id matches the
// supplied bytes (looked up via sha256 hash for compact indexing).
func (r *PasskeyCredentialRepository) GetByCredentialID(ctx context.Context, credentialID []byte) (*identity.PasskeyCredential, error) {
	q := `
        SELECT ` + passkeyCredentialColumns + `
        FROM passkey_credentials
        WHERE credential_id_hash = $1
    `
	row := r.q.QueryRow(ctx, q, hashCredID(credentialID))
	c, err := scanPasskeyCredential(row)
	if err != nil {
		if errors.Is(err, ErrNoRows) {
			return nil, identity.ErrPasskeyCredentialNotFound
		}
		return nil, fmt.Errorf("pg.PasskeyCredentialRepository.GetByCredentialID: %w", err)
	}
	return c, nil
}

// ListByGcid returns all credentials owned by gcid (active + revoked), as
// per the domain port contract (the handler layer filters by status).
func (r *PasskeyCredentialRepository) ListByGcid(ctx context.Context, gcid string) ([]*identity.PasskeyCredential, error) {
	if r.lq == nil {
		return nil, errors.New("pg.PasskeyCredentialRepository.ListByGcid: no ListQuerier wired")
	}
	q := `
        SELECT ` + passkeyCredentialColumns + `
        FROM passkey_credentials
        WHERE gcid = $1::uuid
        ORDER BY created_at ASC
    `
	rows, err := r.lq.Query(ctx, q, gcid)
	if err != nil {
		return nil, fmt.Errorf("pg.PasskeyCredentialRepository.ListByGcid: %w", err)
	}
	defer rows.Close()
	var out []*identity.PasskeyCredential
	for rows.Next() {
		c, scanErr := scanPasskeyCredentialRows(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("pg.PasskeyCredentialRepository.ListByGcid: scan: %w", scanErr)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("pg.PasskeyCredentialRepository.ListByGcid: iter: %w", err)
	}
	return out, nil
}

// scanPasskeyCredential is the QueryRow scan variant.
func scanPasskeyCredential(row Row) (*identity.PasskeyCredential, error) {
	return scanPasskeyCredentialFn(row.Scan)
}

// scanPasskeyCredentialRows is the iteration scan variant.
func scanPasskeyCredentialRows(rows Rows) (*identity.PasskeyCredential, error) {
	return scanPasskeyCredentialFn(rows.Scan)
}

// scanPasskeyCredentialFn factors the shared scan logic for both Row +
// Rows surfaces — both expose the same Scan signature so a single function
// covers both.
func scanPasskeyCredentialFn(scan func(dest ...any) error) (*identity.PasskeyCredential, error) {
	var (
		c          identity.PasskeyCredential
		signCount  int64
		status     string
		lastUsedAt *time.Time
	)
	err := scan(
		&c.CredentialUUID,
		&c.Gcid,
		&c.CredentialID,
		&c.PublicKeyCOSE,
		&c.AttestationType,
		&c.RPID,
		&signCount,
		&status,
		&c.CreatedAt,
		&lastUsedAt,
	)
	if err != nil {
		return nil, err
	}
	c.SignCount = uint32(signCount) //nolint:gosec // sign_count stored as BIGINT; domain uses uint32 (WebAuthn §6.1.1)
	c.Status = identity.PasskeyCredentialStatus(status)
	c.CreatedAt = c.CreatedAt.UTC()
	if lastUsedAt != nil {
		t := lastUsedAt.UTC()
		c.LastUsedAt = &t
	}
	return &c, nil
}

// ----------------------------------------------------------------------------
// poolListQuerier — thin wrapper that exposes PgxPoolQuerier.Pool().Query as
// the local Rows surface. Kept here (not in runtime.go) so the runtime
// surface stays minimal for non-passkey adapters.
// ----------------------------------------------------------------------------

type poolListQuerier struct {
	querier *PgxPoolQuerier
}

func (p poolListQuerier) Exec(ctx context.Context, sql string, args ...any) error {
	return p.querier.Exec(ctx, sql, args...)
}

func (p poolListQuerier) QueryRow(ctx context.Context, sql string, args ...any) Row {
	return p.querier.QueryRow(ctx, sql, args...)
}

func (p poolListQuerier) Query(ctx context.Context, sql string, args ...any) (Rows, error) {
	pool := p.querier.Pool()
	if pool == nil {
		return nil, errors.New("pg: nil pool")
	}
	rs, err := pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("pg.Query: %w", err)
	}
	return &pgxRows{r: rs}, nil
}

// Compile-time checks.
var (
	_ identity.PasskeyChallengeRepository  = (*PasskeyChallengeRepository)(nil)
	_ identity.PasskeyCredentialRepository = (*PasskeyCredentialRepository)(nil)
)
