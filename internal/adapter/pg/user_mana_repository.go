// user_mana_repository.go — pgx-backed implementation of user_mana.Store
// (the durable mana wallet, WS-2.7).
//
// Mana is the umbrella prepaid-credit currency for every LLM call (ADR-142 §4).
// Under WS-1 hard-block metering an in-memory wallet would reset balances on
// every pod restart and lock users out of LLM, so the wallet MUST be durable.
// The user_mana / mana_ledger / mana_subsidy_allocations tables + the
// user_isolation RLS policy already exist (migrations 0002/0003); this adapter
// wires them.
//
// RLS axis: user_mana / mana_ledger carry `user_isolation` keyed on
// chora.user_gcid; mana_subsidy_allocations carries BOTH user_isolation
// (gcid) and tenant_isolation (tenant_id) as permissive (OR'd) policies, so a
// user's own allocations are visible/insertable via SET LOCAL chora.user_gcid
// alone. Every method therefore runs inside RunInUserTx (migration 0003).
//
// OCC: SaveMana upserts with a `WHERE user_mana.version = EXCLUDED.version - 1`
// guard; a 0-row result (no RETURNING) is surfaced as a version-conflict error
// per the aggregate's documented contract ("Adapters MUST honour Version").
//
// ⚠ Cross-method atomicity (INHERITED LIMITATION, tracked follow-up): the
// user_mana.Store port exposes GetMana/SaveMana/AppendLedger as SEPARATE
// methods, so the Quoter's CreditMana/DeductMana write the balance and the
// ledger row in SEPARATE transactions — there is no single ACID boundary across
// them. A crash between SaveMana and AppendLedger can leave balance != ledger
// (the in-memory store had the same non-atomicity, but lost it on restart;
// pg makes it durable). The dominant credit path (Stripe top-up) is protected
// upstream by the subscriber's idempotent.Store inbox (dedup BEFORE CreditMana),
// so at-least-once redelivery does not double-credit. A fully-atomic
// CreditMana/DeductMana requires a transactional Store method
// (e.g. ApplyMovement(mana, ledger) in one tx) — a port change deferred as a
// separate work item.
package pg

import (
	"context"
	"errors"
	"fmt"
	"time"

	mana "github.com/apollo-chora/chora-identity/internal/domain/user_mana"
)

// ManaStore is the pgx-backed user_mana.Store.
type ManaStore struct {
	txr UserTxQuerier
}

// NewManaStore wraps a UserTxQuerier (production: *PgxPoolQuerier).
func NewManaStore(txr UserTxQuerier) *ManaStore {
	return &ManaStore{txr: txr}
}

// Compile-time check.
var _ mana.Store = (*ManaStore)(nil)

// ErrManaOCCConflict — SaveMana lost an optimistic-concurrency race.
var ErrManaOCCConflict = errors.New("pg.ManaStore: optimistic-concurrency conflict on user_mana")

// GetMana returns the wallet snapshot for a gcid, or (nil, nil) when absent.
func (s *ManaStore) GetMana(ctx context.Context, gcid string) (*mana.UserMana, error) {
	var out *mana.UserMana
	err := s.txr.RunInUserTx(ctx, gcid, "", func(ctx context.Context, tx Tx) error {
		row := tx.QueryRow(ctx, `
			SELECT gcid, balance_units, lifetime_earned, lifetime_spent,
			       last_credited_at, version, updated_at
			  FROM user_mana
			 WHERE gcid = $1`, gcid)
		var (
			m            mana.UserMana
			lastCredited *time.Time
		)
		if err := row.Scan(&m.Gcid, &m.BalanceUnits, &m.LifetimeEarned, &m.LifetimeSpent,
			&lastCredited, &m.Version, &m.UpdatedAt); err != nil {
			if errors.Is(err, ErrNoRows) {
				return nil // out stays nil — absent wallet
			}
			return fmt.Errorf("pg.ManaStore.GetMana scan: %w", err)
		}
		m.LastCreditedAt = lastCredited
		out = &m
		return nil
	})
	return out, err
}

// SaveMana upserts the wallet with an OCC guard on version.
func (s *ManaStore) SaveMana(ctx context.Context, m *mana.UserMana) error {
	if m == nil {
		return errors.New("pg.ManaStore.SaveMana: nil wallet")
	}
	return s.txr.RunInUserTx(ctx, m.Gcid, "", func(ctx context.Context, tx Tx) error {
		row := tx.QueryRow(ctx, `
			INSERT INTO user_mana
			    (gcid, balance_units, lifetime_earned, lifetime_spent,
			     last_credited_at, version, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (gcid) DO UPDATE SET
			    balance_units    = EXCLUDED.balance_units,
			    lifetime_earned  = EXCLUDED.lifetime_earned,
			    lifetime_spent   = EXCLUDED.lifetime_spent,
			    last_credited_at = EXCLUDED.last_credited_at,
			    version          = EXCLUDED.version,
			    updated_at       = EXCLUDED.updated_at
			WHERE user_mana.version = EXCLUDED.version - 1
			RETURNING gcid`,
			m.Gcid, m.BalanceUnits, m.LifetimeEarned, m.LifetimeSpent,
			m.LastCreditedAt, m.Version, m.UpdatedAt)
		var got string
		if err := row.Scan(&got); err != nil {
			if errors.Is(err, ErrNoRows) {
				return fmt.Errorf("%w: gcid=%s version=%d", ErrManaOCCConflict, m.Gcid, m.Version)
			}
			return fmt.Errorf("pg.ManaStore.SaveMana: %w", err)
		}
		return nil
	})
}

// AppendLedger inserts one append-only ledger row.
func (s *ManaStore) AppendLedger(ctx context.Context, e *mana.LedgerEntry) error {
	if e == nil {
		return errors.New("pg.ManaStore.AppendLedger: nil entry")
	}
	return s.txr.RunInUserTx(ctx, e.Gcid, "", func(ctx context.Context, tx Tx) error {
		return tx.Exec(ctx, `
			INSERT INTO mana_ledger
			    (entry_id, gcid, direction, units, reason,
			     source_subscription_id, source_action_id, source_allocation_id, source_topup_id,
			     balance_after_units, idempotency_key, request_id, reverses_entry_id, recorded_at)
			VALUES ($1, $2, $3::mana_direction, $4, $5::mana_reason,
			        $6, $7, $8, $9,
			        $10, $11, $12, $13, $14)`,
			e.EntryID, e.Gcid, string(e.Direction), e.Units, string(e.Reason),
			nullUUID(e.SourceSubscriptionID), nullText(e.SourceActionID), nullUUID(e.SourceAllocationID), nullUUID(e.SourceTopupID),
			e.BalanceAfterUnits, e.IdempotencyKey, nullText(e.RequestID), nullUUID(e.ReversesEntryID), e.RecordedAt)
	})
}

// FindLedgerByIdempotencyKey returns ledger rows matching (gcid, key).
func (s *ManaStore) FindLedgerByIdempotencyKey(ctx context.Context, gcid, key string) ([]*mana.LedgerEntry, error) {
	if key == "" {
		return nil, nil
	}
	var out []*mana.LedgerEntry
	err := s.txr.RunInUserTx(ctx, gcid, "", func(ctx context.Context, tx Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT entry_id, gcid, direction, units, reason,
			       source_subscription_id, source_action_id, source_allocation_id, source_topup_id,
			       balance_after_units, idempotency_key, request_id, reverses_entry_id, recorded_at
			  FROM mana_ledger
			 WHERE gcid = $1 AND idempotency_key = $2
			 ORDER BY recorded_at ASC`, gcid, key)
		if err != nil {
			return fmt.Errorf("pg.ManaStore.FindLedgerByIdempotencyKey: %w", err)
		}
		defer rows.Close()
		ledger, serr := scanLedgerRows(rows)
		if serr != nil {
			return serr
		}
		out = ledger
		return rows.Err()
	})
	return out, err
}

// ListLedger returns ledger rows for a gcid filtered by time/direction/reason.
func (s *ManaStore) ListLedger(ctx context.Context, f mana.LedgerFilter) ([]*mana.LedgerEntry, error) {
	if f.Gcid == "" {
		return nil, mana.ErrInvalidFilter
	}
	// Decode the keyset cursor up-front so a malformed cursor fails fast
	// (ErrInvalidFilter → 400) before opening a tx (CHO-1883).
	var curTime time.Time
	var curID string
	if f.Cursor != "" {
		var derr error
		curTime, curID, derr = mana.DecodeLedgerCursor(f.Cursor)
		if derr != nil {
			return nil, derr
		}
	}
	var out []*mana.LedgerEntry
	err := s.txr.RunInUserTx(ctx, f.Gcid, "", func(ctx context.Context, tx Tx) error {
		// Build a parameterised WHERE incrementally; recorded_at DESC matches
		// idx_mana_ledger_gcid_recorded_at.
		sql := `SELECT entry_id, gcid, direction, units, reason,
		               source_subscription_id, source_action_id, source_allocation_id, source_topup_id,
		               balance_after_units, idempotency_key, request_id, reverses_entry_id, recorded_at
		          FROM mana_ledger WHERE gcid = $1`
		args := []any{f.Gcid}
		if f.From != nil {
			args = append(args, *f.From)
			sql += fmt.Sprintf(" AND recorded_at >= $%d", len(args))
		}
		if f.To != nil {
			args = append(args, *f.To)
			sql += fmt.Sprintf(" AND recorded_at < $%d", len(args))
		}
		if f.Direction != nil {
			args = append(args, string(*f.Direction))
			sql += fmt.Sprintf(" AND direction = $%d::mana_direction", len(args))
		}
		if f.Reason != nil {
			args = append(args, string(*f.Reason))
			sql += fmt.Sprintf(" AND reason = $%d::mana_reason", len(args))
		}
		if f.Cursor != "" {
			args = append(args, curTime)
			ti := len(args)
			args = append(args, curID)
			ii := len(args)
			// Keyset page: rows strictly older than the cursor tuple. Row-value
			// comparison gives a stable (recorded_at, entry_id) total order.
			sql += fmt.Sprintf(" AND (recorded_at, entry_id) < ($%d::timestamptz, $%d::uuid)", ti, ii)
		}
		sql += " ORDER BY recorded_at DESC, entry_id DESC"
		if f.PageSize > 0 {
			args = append(args, f.PageSize)
			sql += fmt.Sprintf(" LIMIT $%d", len(args))
		}
		rows, err := tx.Query(ctx, sql, args...)
		if err != nil {
			return fmt.Errorf("pg.ManaStore.ListLedger: %w", err)
		}
		defer rows.Close()
		ledger, serr := scanLedgerRows(rows)
		if serr != nil {
			return serr
		}
		out = ledger
		return rows.Err()
	})
	return out, err
}

// ListAllocations returns the subsidy allocations attached to a gcid.
func (s *ManaStore) ListAllocations(ctx context.Context, gcid string) ([]*mana.Allocation, error) {
	var out []*mana.Allocation
	err := s.txr.RunInUserTx(ctx, gcid, "", func(ctx context.Context, tx Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT allocation_id, tenant_id, remaining_units, expires_at, allocated_at
			  FROM mana_subsidy_allocations
			 WHERE gcid = $1
			 ORDER BY expires_at ASC NULLS LAST, allocated_at ASC`, gcid)
		if err != nil {
			return fmt.Errorf("pg.ManaStore.ListAllocations: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var (
				a         mana.Allocation
				expiresAt *time.Time
			)
			if err := rows.Scan(&a.AllocationID, &a.TenantID, &a.RemainingUnits, &expiresAt, &a.AllocatedAt); err != nil {
				return fmt.Errorf("pg.ManaStore.ListAllocations scan: %w", err)
			}
			a.ExpiresAt = expiresAt
			out = append(out, &a)
		}
		return rows.Err()
	})
	return out, err
}

// SaveAllocation upserts a subsidy allocation projection.
func (s *ManaStore) SaveAllocation(ctx context.Context, gcid string, a *mana.Allocation) error {
	if a == nil {
		return errors.New("pg.ManaStore.SaveAllocation: nil allocation")
	}
	return s.txr.RunInUserTx(ctx, gcid, "", func(ctx context.Context, tx Tx) error {
		return tx.Exec(ctx, `
			INSERT INTO mana_subsidy_allocations
			    (allocation_id, gcid, tenant_id, remaining_units, expires_at, allocated_at)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (allocation_id) DO UPDATE SET
			    remaining_units = EXCLUDED.remaining_units,
			    expires_at      = EXCLUDED.expires_at`,
			a.AllocationID, gcid, a.TenantID, a.RemainingUnits, a.ExpiresAt, a.AllocatedAt)
	})
}

// UpdateAllocationRemaining sets the remaining units on one allocation.
func (s *ManaStore) UpdateAllocationRemaining(ctx context.Context, gcid, allocationID string, remaining int64) error {
	return s.txr.RunInUserTx(ctx, gcid, "", func(ctx context.Context, tx Tx) error {
		return tx.Exec(ctx, `
			UPDATE mana_subsidy_allocations
			   SET remaining_units = $3
			 WHERE gcid = $1 AND allocation_id = $2`, gcid, allocationID, remaining)
	})
}

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

// scanLedgerRows scans a mana_ledger result set into domain entries, mapping
// nullable uuid/text columns from *string back to "".
func scanLedgerRows(rows Rows) ([]*mana.LedgerEntry, error) {
	var out []*mana.LedgerEntry
	for rows.Next() {
		var (
			e          mana.LedgerEntry
			dir, rsn   string
			subID      *string
			actionID   *string
			allocID    *string
			topupID    *string
			requestID  *string
			reversesID *string
		)
		if err := rows.Scan(&e.EntryID, &e.Gcid, &dir, &e.Units, &rsn,
			&subID, &actionID, &allocID, &topupID,
			&e.BalanceAfterUnits, &e.IdempotencyKey, &requestID, &reversesID, &e.RecordedAt); err != nil {
			return nil, fmt.Errorf("pg.ManaStore: scan ledger row: %w", err)
		}
		e.Direction = mana.Direction(dir)
		e.Reason = mana.Reason(rsn)
		e.SourceSubscriptionID = deref(subID)
		e.SourceActionID = deref(actionID)
		e.SourceAllocationID = deref(allocID)
		e.SourceTopupID = deref(topupID)
		e.RequestID = deref(requestID)
		e.ReversesEntryID = deref(reversesID)
		out = append(out, &e)
	}
	return out, nil
}

// nullUUID maps an empty string to nil so a uuid column receives NULL rather
// than the empty string (which is not a valid uuid).
func nullUUID(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// nullText maps an empty string to nil for nullable text/varchar columns.
func nullText(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
