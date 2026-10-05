// user_repository.go — pgx-backed implementation of identity.UserRepository.
//
// SQL contract:
//
//   - Save: UPSERT on conflict(gcid). The `users` table has a UNIQUE
//     (identity_provider, federated_subject) constraint; an UPSERT-by-gcid
//     keeps idempotency under retry.
//   - GetByGcid: returns identity.ErrUserNotFound when missing.
//   - FindByFederatedSubject: returns (nil, false, nil) on miss; this is
//     the lookup the Identity Platform Blocking Function uses on
//     beforeCreate idempotency + beforeSignIn re-resolution.
//
// Soft delete: queries filter `deleted_at IS NULL` per ddd-enforcement.
//
// RLS: `users` is identity-scoped (NOT tenant-scoped) — the table has no
// tenant_id column, so no `SET LOCAL chora.tenant_id` is required for
// these queries. Tenant_memberships is tenant-scoped; that adapter (when
// added) will wrap calls in `rls.RunInTx`.
package pg

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/apollo-chora/chora-identity/internal/adapter/events"
	"github.com/apollo-chora/chora-identity/internal/adapter/outbox"
	"github.com/apollo-chora/chora-identity/internal/domain/identity"
)

// UserRepository is the pgx-backed implementation of identity.UserRepository.
type UserRepository struct {
	q Querier
	// txr runs the plain-tx atomic display-name-update + outbox-enqueue path.
	// nil in a bare-Querier wiring (no tx support); UpdateDisplayName fails
	// loud rather than silently dropping the projection event.
	txr PlainTxQuerier
}

// NewUserRepository wraps a *pgxpool.Pool.
func NewUserRepository(querier *PgxPoolQuerier) *UserRepository {
	return &UserRepository{q: querier, txr: querier}
}

// NewUserRepositoryWithQuerier accepts the lower-level Querier; used by
// unit tests that stub the SQL surface. When the querier ALSO satisfies
// PlainTxQuerier (production pool + tx-capable stubs), the transactional
// UpdateDisplayName path is wired automatically.
func NewUserRepositoryWithQuerier(q Querier) *UserRepository {
	r := &UserRepository{q: q}
	if txr, ok := q.(PlainTxQuerier); ok {
		r.txr = txr
	}
	return r
}

const userColumns = `gcid, email, display_name, identity_provider,
    federated_subject, status, COALESCE(kyc_method::text, ''),
    kyc_verified_at, verification_status, created_at, updated_at`

// Save persists the User. Upserts on (gcid).
func (r *UserRepository) Save(ctx context.Context, u *identity.User) error {
	if u == nil {
		return errors.New("pg.UserRepository.Save: nil user")
	}
	// federated_subject + deleted_at participate in the UPSERT so the
	// closure terminal step (User.Pseudonymise, CHO-1719) persists: the
	// soft delete frees the partial unique email index and the
	// "shredded:{gcid}" subject tombstone retires the UNIQUE
	// (identity_provider, federated_subject) pair.
	q := `
        INSERT INTO users (
            gcid, email, display_name, identity_provider, federated_subject,
            status, kyc_method, kyc_verified_at, verification_status,
            created_at, updated_at, deleted_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, '')::kyc_method, $8, $9, $10, $11, $12)
        ON CONFLICT (gcid) DO UPDATE SET
            email = EXCLUDED.email,
            display_name = EXCLUDED.display_name,
            federated_subject = EXCLUDED.federated_subject,
            status = EXCLUDED.status,
            kyc_method = EXCLUDED.kyc_method,
            kyc_verified_at = EXCLUDED.kyc_verified_at,
            verification_status = EXCLUDED.verification_status,
            updated_at = EXCLUDED.updated_at,
            deleted_at = EXCLUDED.deleted_at
    `
	return r.q.Exec(ctx, q,
		u.Gcid,
		u.Email,
		u.DisplayName,
		string(u.IdentityProvider),
		u.FederatedSubject,
		string(u.Status),
		string(u.KycMethod),
		u.KycVerifiedAt,
		string(u.VerificationStatus),
		u.CreatedAt,
		u.UpdatedAt,
		u.DeletedAt,
	)
}

// GetByGcid returns the user with the supplied GCID.
func (r *UserRepository) GetByGcid(ctx context.Context, gcid string) (*identity.User, error) {
	q := `
        SELECT ` + userColumns + `
        FROM users
        WHERE gcid = $1 AND deleted_at IS NULL
    `
	row := r.q.QueryRow(ctx, q, gcid)
	u, err := scanUser(row)
	if err != nil {
		if errors.Is(err, ErrNoRows) {
			return nil, identity.ErrUserNotFound
		}
		return nil, fmt.Errorf("pg.GetByGcid: %w", err)
	}
	return u, nil
}

// FindByEmail returns (user, true, nil) on hit, (nil, false, nil) on miss,
// (nil, false, err) on database error. Matching is case-insensitive and
// excludes soft-deleted users. L1 Tenant lane (CHO-1707): resolves the
// add-member-by-email target.
func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*identity.User, bool, error) {
	q := `
        SELECT ` + userColumns + `
        FROM users
        WHERE lower(email) = lower($1) AND deleted_at IS NULL
        LIMIT 1
    `
	row := r.q.QueryRow(ctx, q, email)
	u, err := scanUser(row)
	if err != nil {
		if errors.Is(err, ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("pg.FindByEmail: %w", err)
	}
	return u, true, nil
}

// FindByFederatedSubject returns (user, true, nil) on hit, (nil, false, nil)
// on miss, (nil, false, err) on database error.
func (r *UserRepository) FindByFederatedSubject(ctx context.Context, sub string) (*identity.User, bool, error) {
	q := `
        SELECT ` + userColumns + `
        FROM users
        WHERE federated_subject = $1 AND deleted_at IS NULL
        LIMIT 1
    `
	row := r.q.QueryRow(ctx, q, sub)
	u, err := scanUser(row)
	if err != nil {
		if errors.Is(err, ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("pg.FindByFederatedSubject: %w", err)
	}
	return u, true, nil
}

// scanUser maps a row to *identity.User.
func scanUser(row Row) (*identity.User, error) {
	var (
		u            identity.User
		ip           string
		status       string
		kycMethod    string
		kycVerified  *time.Time
		verification string
	)
	err := row.Scan(
		&u.Gcid,
		&u.Email,
		&u.DisplayName,
		&ip,
		&u.FederatedSubject,
		&status,
		&kycMethod,
		&kycVerified,
		&verification,
		&u.CreatedAt,
		&u.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	u.IdentityProvider = identity.IdentityProvider(ip)
	u.Status = identity.UserStatus(status)
	if kycMethod != "" {
		u.KycMethod = identity.KycMethod(kycMethod)
	}
	if kycVerified != nil {
		t := kycVerified.UTC()
		u.KycVerifiedAt = &t
	}
	u.VerificationStatus = identity.VerificationStatus(verification)
	return &u, nil
}

// UpdateDisplayName patches users.display_name for an existing GCID (CHO-1817
// H+ Members admin editor) AND — atomically, in the SAME transaction — enqueues
// a chora.identity.user.profile_updated.v1 outbox row so other domains project
// the new (gcid → display_name) into their local directory (Q3). Returns
// identity.ErrUserNotFound when no live user carries the GCID. Empty display
// names are rejected upstream by the handler; the gcid guard here is defensive.
//
// Transactional outbox: the SELECT-FOR-UPDATE (old name) + UPDATE + outbox
// INSERT all run on one pgx transaction, so the projection event can never be
// lost between the state write and enqueue (and rolls back with the write on
// any failure). The event fires ONLY when the name actually changes — an
// unchanged PATCH is a no-op emit (avoids downstream noise + is naturally
// idempotent against client retries). actingTenantID is the acting admin's
// tenant, carried as envelope provenance (the consumer keys its directory by
// the global gcid).
func (r *UserRepository) UpdateDisplayName(ctx context.Context, gcid, displayName, actingTenantID string) error {
	if strings.TrimSpace(gcid) == "" {
		return errors.New("pg.UserRepository.UpdateDisplayName: gcid required")
	}
	if r.txr == nil {
		return errors.New("pg.UserRepository.UpdateDisplayName: transactional runner not wired (atomic outbox emit requires a pool-backed PlainTxQuerier)")
	}

	return r.txr.RunInTx(ctx, func(ctx context.Context, tx Tx) error {
		// 1) Read the current row (FOR UPDATE locks it against a concurrent
		//    rename) — capture the OLD name to decide whether to emit + the
		//    email for the event payload.
		var email, oldName string
		selRow := tx.QueryRow(ctx, `
            SELECT email, display_name
              FROM users
             WHERE gcid = $1::uuid AND deleted_at IS NULL
             FOR UPDATE`, gcid)
		if err := selRow.Scan(&email, &oldName); err != nil {
			if errors.Is(err, ErrNoRows) {
				return identity.ErrUserNotFound
			}
			return fmt.Errorf("pg.UserRepository.UpdateDisplayName: select: %w", err)
		}

		// 2) Apply the write (preserve existing behaviour: always bump
		//    updated_at). RETURNING gives the committed updated_at for the
		//    event payload.
		var updatedAt time.Time
		updRow := tx.QueryRow(ctx, `
            UPDATE users
               SET display_name = $2, updated_at = now()
             WHERE gcid = $1::uuid AND deleted_at IS NULL
             RETURNING updated_at`, gcid, displayName)
		if err := updRow.Scan(&updatedAt); err != nil {
			return fmt.Errorf("pg.UserRepository.UpdateDisplayName: update: %w", err)
		}

		// 3) Emit ONLY on an actual change — enqueue the outbox row via the
		//    SAME tx (transactional outbox). Unchanged name → no event.
		if oldName == displayName {
			return nil
		}
		txPub := events.NewProfileUpdatedPublisher(outbox.NewTxBoundPublisher(tx))
		return txPub.PublishProfileUpdated(ctx, events.ProfileUpdatedEvent{
			Gcid:        gcid,
			DisplayName: displayName,
			Email:       email,
			TenantID:    actingTenantID,
			UpdatedAt:   updatedAt,
		})
	})
}

// backfillBatchSize bounds how many profile_updated.v1 outbox rows are enqueued
// per transaction during BackfillProfileDirectory — one bounded tx per batch
// keeps a directory-wide replay off a single long-held transaction.
const backfillBatchSize = 200

// profileBackfillRow is the projectable slice of a users row the backfill needs
// to rebuild the (gcid → display_name) directory event.
type profileBackfillRow struct {
	gcid        string
	email       string
	displayName string
	updatedAt   time.Time
}

// BackfillProfileDirectory re-emits chora.identity.user.profile_updated.v1 for
// EVERY live user with a non-empty display_name (CHO-2327). Identity only emits
// that projection event on UpdateDisplayName, so a downstream directory (e.g.
// chora-delivery.user_directory) never learned the names of members whose
// display_name predates the projection being wired — those rosters render raw
// GCIDs. This replays the projection for the whole directory so it catches up,
// using identity's OWN DB + transactional outbox (no external DB credentials).
//
// Shape: a single read tx snapshots the projectable users (the cursor is fully
// drained before any emit — pgx forbids interleaving a live Query with Exec on
// the same conn), then each batch of emits rides its OWN tx via the tx-bound
// publisher (transactional outbox — the same primitive UpdateDisplayName uses).
// A publish failure rolls its batch back and returns the committed-so-far count
// plus the error (fail loud — never a silent partial success).
//
// Idempotent + safe to re-run: each emit carries the user's CURRENT
// display_name + updated_at, so the consumer's dedup-on-event_id +
// last-writer-wins-on-updated_at can never regress a newer name; a missing
// directory row is inserted, an equal/older one is a no-op.
//
// actingTenantID is carried as envelope provenance ONLY — the consumer keys its
// directory by the GLOBAL gcid and ignores tenant_id, but the mandatory-envelope
// contract requires it non-empty. display_name is a GCID-portable public
// property, so replaying it under the acting admin's tenant leaks nothing new.
func (r *UserRepository) BackfillProfileDirectory(ctx context.Context, actingTenantID string) (scanned, emitted int, err error) {
	if strings.TrimSpace(actingTenantID) == "" {
		return 0, 0, errors.New("pg.UserRepository.BackfillProfileDirectory: actingTenantID required (envelope provenance)")
	}
	if r.txr == nil {
		return 0, 0, errors.New("pg.UserRepository.BackfillProfileDirectory: transactional runner not wired (atomic outbox emit requires a pool-backed PlainTxQuerier)")
	}

	// Phase 1 — snapshot the projectable users in one read tx. Blank names are
	// the "nothing to project" state and soft-deleted users are excluded.
	var rows []profileBackfillRow
	if e := r.txr.RunInTx(ctx, func(ctx context.Context, tx Tx) error {
		rs, e := tx.Query(ctx, `
            SELECT gcid, email, display_name, updated_at
              FROM users
             WHERE display_name <> '' AND deleted_at IS NULL
             ORDER BY created_at`)
		if e != nil {
			return fmt.Errorf("list: %w", e)
		}
		defer rs.Close()
		for rs.Next() {
			var pr profileBackfillRow
			if e := rs.Scan(&pr.gcid, &pr.email, &pr.displayName, &pr.updatedAt); e != nil {
				return fmt.Errorf("scan: %w", e)
			}
			rows = append(rows, pr)
		}
		return rs.Err()
	}); e != nil {
		return 0, 0, fmt.Errorf("pg.UserRepository.BackfillProfileDirectory: %w", e)
	}
	scanned = len(rows)

	// Phase 2 — re-emit per user, batched, each batch in its own tx.
	for start := 0; start < len(rows); start += backfillBatchSize {
		end := start + backfillBatchSize
		if end > len(rows) {
			end = len(rows)
		}
		batch := rows[start:end]
		batchEmitted := 0
		if e := r.txr.RunInTx(ctx, func(ctx context.Context, tx Tx) error {
			txPub := events.NewProfileUpdatedPublisher(outbox.NewTxBoundPublisher(tx))
			n := 0
			for _, pr := range batch {
				if strings.TrimSpace(pr.displayName) == "" {
					continue // defensive — the WHERE already excludes blanks
				}
				if e := txPub.PublishProfileUpdated(ctx, events.ProfileUpdatedEvent{
					Gcid:        pr.gcid,
					DisplayName: pr.displayName,
					Email:       pr.email,
					TenantID:    actingTenantID,
					UpdatedAt:   pr.updatedAt,
				}); e != nil {
					return fmt.Errorf("emit gcid=%s: %w", pr.gcid, e)
				}
				n++
			}
			batchEmitted = n
			return nil
		}); e != nil {
			// Fail loud: return the committed-batch count + the error.
			return scanned, emitted, fmt.Errorf("pg.UserRepository.BackfillProfileDirectory: %w", e)
		}
		emitted += batchEmitted
	}
	return scanned, emitted, nil
}

// Compile-time check.
var _ identity.UserRepository = (*UserRepository)(nil)
