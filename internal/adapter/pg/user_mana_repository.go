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
// ⚠ Cross-method atomicity — CLOSED for the personal-balance credit path.
// The port additionally exposes CreditWallet (wallet credit + ledger row in
// ONE pgx transaction, with a pre-write idempotency lookup plus an in-tx
// advisory-lock re-check, a payload check on replay, and the demo-grant caps
// enforced under row locks inside the same transaction), and CreditMana routes
// every non-subsidy source through it. A crash between the wallet write and the
// ledger insert can no longer leave balance != ledger on those paths. The
// tenant-subsidy path still writes the Allocation and the wallet separately (it
// is a two-table projection, not a single-account mutation); the dominant
// credit path (Stripe top-up) is also protected upstream by the subscriber's
// idempotent.Store inbox (dedup BEFORE CreditMana), so at-least-once
// redelivery does not double-credit.
package pg

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	mana "github.com/apollo-chora/chora-identity/internal/domain/user_mana"
)

// ManaStore is the pgx-backed user_mana.Store.
type ManaStore struct {
	txr UserTxQuerier
	// plainTxr is optional: set when the constructor was handed a querier that
	// can also open a GUC-free transaction (production *PgxPoolQuerier does).
	// The cross-GCID demo-grant total needs no RLS scope, so it cannot go
	// through RunInUserTx. It FAILS CLOSED: with a stub txr — i.e. no elevated
	// reader — DemoGrantTotalUnits returns an error rather than reporting an
	// empty (zero) budget, which a budget check must never treat as "no spend".
	plainTxr PlainTxQuerier
}

// NewManaStore wraps a UserTxQuerier (production: *PgxPoolQuerier).
func NewManaStore(txr UserTxQuerier) *ManaStore {
	s := &ManaStore{txr: txr}
	if p, ok := txr.(PlainTxQuerier); ok {
		s.plainTxr = p
	}
	return s
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

// -----------------------------------------------------------------------------
// Atomic wallet credit — Store.CreditWallet
// -----------------------------------------------------------------------------

// CreditWallet applies a personal-balance credit and appends the matching
// mana_ledger row in ONE pgx transaction.
//
// One tx, in order:
//  1. pg_advisory_xact_lock on (gcid, idempotency_key) — serializes
//     concurrent duplicates of the SAME grant so exactly one can win.
//  2. Re-check mana_ledger for the idempotency key. If a row is already there
//     AND it records the same operation, return it with Replayed=true and write
//     NOTHING; if it records a different operation, fail with
//     ErrIdempotencyConflict. This closes the race left open by the caller's
//     pre-write FindLedgerByIdempotencyKey lookup.
//  2b. When in.DemoGrantCaps is set, lock the GCID and the shared demo-grant
//     budget rows and enforce the per-GCID cap and the platform-wide budget
//     (checkDemoGrantCapsTx) — before anything is written.
//  3. Lock/upsert the wallet row. ON CONFLICT DO UPDATE takes a row lock on an
//     existing wallet, so concurrent credits to the same wallet serialize
//     instead of one losing to an optimistic-concurrency conflict.
//  4. Apply the credit with CHECKED arithmetic: balance_units += units and
//     lifetime_earned += units, last_credited_at / version / updated_at bumped.
//     An int64 overflow is a domain error, never a wrapped balance.
//  5. Write the wallet back and insert the ledger row.
//  6. Charge the demo-grant counters, when caps were enforced.
//
// A crash anywhere in there rolls the whole unit back, so the balance can
// never diverge from the ledger on this path — and a rejected cap can never
// consume budget it did not grant.
func (s *ManaStore) CreditWallet(ctx context.Context, in mana.CreditWalletInput) (*mana.CreditWalletResult, error) {
	if err := mana.ValidateCreditWalletInput(in); err != nil {
		return nil, err
	}
	var res *mana.CreditWalletResult
	err := s.txr.RunInUserTx(ctx, in.Gcid, "", func(ctx context.Context, tx Tx) error {
		out, err := creditWalletTx(ctx, tx, in)
		if err != nil {
			return err
		}
		res = out
		return nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// SeedDemoGrant applies the demo seed grant on the CALLER's transaction.
//
// cmd/seed writes inside its own transaction and cannot go through
// RunInUserTx, which opens a second independent transaction — a grant that
// committed there would survive a seed rollback, breaking the seed's
// all-or-nothing guarantee. The seed's idempotency key is deterministic
// (`demo-seed:v1:<gcid>`), so re-running the seed is a no-op: the in-tx
// re-check finds the existing ledger row and credits nothing.
func SeedDemoGrant(ctx context.Context, tx Tx, gcid, idempotencyKey string, units int64) (*mana.CreditWalletResult, error) {
	return creditWalletTx(ctx, tx, mana.CreditWalletInput{
		Gcid:           gcid,
		Units:          units,
		Direction:      mana.DirectionMint,
		Reason:         mana.ReasonDemoGrant,
		IdempotencyKey: idempotencyKey,
	})
}

// NewTxBridge adapts a pgx.Tx to the Tx interface, for callers that already
// hold an open transaction (cmd/seed) and so cannot go through RunInUserTx.
//
// It reuses the pgxTx adapter RunInUserTx itself uses, so a Scan maps
// pgx.ErrNoRows to the package's ErrNoRows exactly as the pool-backed path does.
// The previous bridge returned the raw pgx.Row, so the in-transaction
// idempotency re-check — a SELECT that finds nothing on the FIRST seed run —
// surfaced pgx.ErrNoRows as a hard error ("no rows in result set") and the seed
// grant could never be applied against a real database.
func NewTxBridge(tx pgx.Tx) Tx { return &pgxTx{tx: tx} }

// advisoryLockKeyTx takes a transaction-scoped advisory lock on a composite
// (namespace, parts...) key.
//
// Each part is hashed on its own and the hashes are XOR-combined, so no part is
// ever embedded in a SQL parameter: the previous implementation joined the parts
// with "\x00", and a NUL byte is legal in a Go string but ILLEGAL in a Postgres
// text parameter — every credit failed with SQLSTATE 22021 (invalid byte
// sequence for encoding "UTF8") against a real database while the stub Tx
// happily accepted it. Hashing the parts separately also removes the separator
// ambiguity entirely.
func advisoryLockKeyTx(ctx context.Context, tx Tx, namespace string, parts ...string) error {
	expr := "hashtextextended($1, 0)"
	args := []any{namespace}
	for i, p := range parts {
		expr += fmt.Sprintf(" # hashtextextended($%d, 0)", i+2)
		args = append(args, p)
	}
	if err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock("+expr+")", args...); err != nil {
		return fmt.Errorf("pg.ManaStore advisory lock (%s): %w", namespace, err)
	}
	return nil
}

// creditWalletTx is the transactional core shared by CreditWallet (which opens
// the RLS-scoped tx) and SeedDemoGrant (which is handed the seed's tx).
func creditWalletTx(ctx context.Context, tx Tx, in mana.CreditWalletInput) (*mana.CreditWalletResult, error) {
	// 1. Serialize concurrent duplicates of this exact grant. The key mixes the
	//    gcid and the idempotency key so distinct grants never contend.
	if err := advisoryLockKeyTx(ctx, tx, "mana-credit-grant", in.Gcid, in.IdempotencyKey); err != nil {
		return nil, err
	}

	// 2. Idempotency re-check under the lock. A replay is only valid when the
	//    recorded operation MATCHES the incoming one: the same key with a
	//    different amount/direction/reason/source is a conflict, not a replay.
	row := tx.QueryRow(ctx, `
		SELECT entry_id, gcid, direction, units, reason,
		       source_subscription_id, source_action_id, source_allocation_id, source_topup_id,
		       balance_after_units, idempotency_key, request_id, reverses_entry_id, recorded_at
		  FROM mana_ledger
		 WHERE gcid = $1 AND idempotency_key = $2
		 ORDER BY recorded_at ASC
		 LIMIT 1`, in.Gcid, in.IdempotencyKey)
	existing, err := scanLedgerRow(row)
	if err != nil && !errors.Is(err, ErrNoRows) {
		return nil, fmt.Errorf("pg.ManaStore.CreditWallet idempotency recheck: %w", err)
	}
	if existing != nil {
		if !mana.CreditWalletMatchesLedger(existing, in) {
			return nil, fmt.Errorf("%w: gcid=%s key=%s", mana.ErrIdempotencyConflict, in.Gcid, in.IdempotencyKey)
		}
		wallet, err := getManaTx(ctx, tx, in.Gcid)
		if err != nil {
			return nil, err
		}
		bal, err := balanceIncludingSubsidyTx(ctx, tx, wallet, in.Gcid)
		if err != nil {
			return nil, err
		}
		return &mana.CreditWalletResult{
			Wallet:            wallet,
			Entry:             existing,
			BalanceAfterUnits: bal,
			Replayed:          true,
		}, nil
	}

	// 2b. Demo-grant caps — INSIDE this transaction, after the locks and before
	//     any write, so two concurrent requests can neither exceed the
	//     platform-wide budget nor the per-GCID cap.
	if in.DemoGrantCaps != nil {
		if err := checkDemoGrantCapsTx(ctx, tx, in); err != nil {
			return nil, err
		}
	}

	// 3. Lock/upsert the wallet row (takes a row lock when it already exists).
	wallet, err := lockWalletTx(ctx, tx, in.Gcid)
	if err != nil {
		return nil, err
	}

	// 4. Apply the credit — checked arithmetic: a silently wrapping int64 would
	//    corrupt the balance before SQL ever sees it.
	balance, err := mana.CheckedAddUnits(wallet.BalanceUnits, in.Units)
	if err != nil {
		return nil, err
	}
	earned, err := mana.CheckedAddUnits(wallet.LifetimeEarned, in.Units)
	if err != nil {
		return nil, err
	}
	wallet.BalanceUnits, wallet.LifetimeEarned = balance, earned
	now := time.Now().UTC()
	wallet.LastCreditedAt = &now
	wallet.UpdatedAt = now
	wallet.Version++

	// 5. Write the wallet back, then append the ledger row.
	written, err := putWalletTx(ctx, tx, wallet)
	if err != nil {
		return nil, err
	}
	subsidy, err := subsidyTotalTx(ctx, tx, in.Gcid)
	if err != nil {
		return nil, err
	}
	balAfter, err := mana.CheckedAddUnits(subsidy, written.BalanceUnits)
	if err != nil {
		return nil, err
	}

	entry := &mana.LedgerEntry{
		EntryID:              uuid.Must(uuid.NewV7()).String(),
		Gcid:                 in.Gcid,
		Direction:            in.Direction,
		Units:                in.Units,
		Reason:               in.Reason,
		SourceSubscriptionID: in.SourceSubscriptionID,
		SourceActionID:       in.SourceActionID,
		SourceAllocationID:   in.SourceAllocationID,
		SourceTopupID:        in.SourceTopupID,
		BalanceAfterUnits:    balAfter,
		IdempotencyKey:       in.IdempotencyKey,
		RequestID:            in.RequestID,
		RecordedAt:           now,
	}
	if err := insertLedgerTx(ctx, tx, entry); err != nil {
		return nil, err
	}

	// 6. Consume the reserved budget/allowance. Same transaction as the credit,
	//    so a failed ledger insert cannot leave the counters charged.
	if in.DemoGrantCaps != nil {
		if err := consumeDemoGrantBudgetTx(ctx, tx, in); err != nil {
			return nil, err
		}
	}
	return &mana.CreditWalletResult{
		Wallet:            written,
		Entry:             entry,
		BalanceAfterUnits: balAfter,
	}, nil
}

// demo-grant budget keys — the `demo_grant_budget.budget_key` values.
const (
	demoBudgetGlobalKey  = "global"
	demoBudgetGcidPrefix = "gcid:"
)

// checkDemoGrantCapsTx enforces the demo-grant caps inside the credit
// transaction.
//
// Locking, in order:
//  1. pg_advisory_xact_lock on the GCID — serializes every demo grant for one
//     user, so two requests with DIFFERENT idempotency keys cannot both pass
//     the per-GCID cap. (The (gcid, key) lock in step 1 of creditWalletTx only
//     serializes duplicates of the SAME grant.)
//  2. the shared `global` budget row, then the GCID's own row, both
//     SELECT ... FOR UPDATE. A fixed lock order (global → gcid) keeps concurrent
//     grants deadlock-free.
//
// The checks run only AFTER both locks are held, and read the RESERVED/CONSUMED
// counters rather than aggregating the ledger — an aggregate over the whole
// ledger would be neither bounded nor serialized against concurrent credits.
func checkDemoGrantCapsTx(ctx context.Context, tx Tx, in mana.CreditWalletInput) error {
	caps := in.DemoGrantCaps
	if err := advisoryLockKeyTx(ctx, tx, "mana-demo-grant-gcid", in.Gcid); err != nil {
		return err
	}
	globalUnits, _, err := lockDemoBudgetRowTx(ctx, tx, demoBudgetGlobalKey)
	if err != nil {
		return err
	}
	_, gcidGrants, err := lockDemoBudgetRowTx(ctx, tx, demoBudgetGcidPrefix+in.Gcid)
	if err != nil {
		return err
	}
	if caps.MaxPerGcid > 0 && gcidGrants >= caps.MaxPerGcid {
		return fmt.Errorf("%w: gcid=%s grants=%d cap=%d",
			mana.ErrDemoGrantLimitReached, in.Gcid, gcidGrants, caps.MaxPerGcid)
	}
	if caps.BudgetUnits > 0 {
		projected, err := mana.CheckedAddUnits(globalUnits, in.Units)
		if err != nil {
			return err
		}
		if projected > caps.BudgetUnits {
			return fmt.Errorf("%w: consumed=%d grant=%d budget=%d",
				mana.ErrDemoGrantBudgetExhausted, globalUnits, in.Units, caps.BudgetUnits)
		}
	}
	return nil
}

// lockDemoBudgetRowTx creates the row if absent and returns its consumed
// counters, holding a row lock until the transaction ends.
func lockDemoBudgetRowTx(ctx context.Context, tx Tx, key string) (units, grants int64, err error) {
	if err := tx.Exec(ctx, `
		INSERT INTO demo_grant_budget (budget_key) VALUES ($1)
		ON CONFLICT (budget_key) DO NOTHING`, key); err != nil {
		return 0, 0, fmt.Errorf("pg.ManaStore demo budget init: %w", err)
	}
	row := tx.QueryRow(ctx, `
		SELECT consumed_units, consumed_grants
		  FROM demo_grant_budget
		 WHERE budget_key = $1
		   FOR UPDATE`, key)
	if err := row.Scan(&units, &grants); err != nil {
		return 0, 0, fmt.Errorf("pg.ManaStore demo budget lock: %w", err)
	}
	return units, grants, nil
}

// consumeDemoGrantBudgetTx charges the reserved demo-grant counters for a
// committed credit.
func consumeDemoGrantBudgetTx(ctx context.Context, tx Tx, in mana.CreditWalletInput) error {
	for _, key := range []string{demoBudgetGlobalKey, demoBudgetGcidPrefix + in.Gcid} {
		if err := tx.Exec(ctx, `
			UPDATE demo_grant_budget
			   SET consumed_units  = consumed_units + $2,
			       consumed_grants = consumed_grants + 1,
			       updated_at      = now()
			 WHERE budget_key = $1`, key, in.Units); err != nil {
			return fmt.Errorf("pg.ManaStore demo budget consume: %w", err)
		}
	}
	return nil
}

// noGcidSentinel is the UUID used to pin `chora.user_gcid` for reads that have
// no user scope. See DemoGrantTotalUnits for why it must be set at all.
const noGcidSentinel = "00000000-0000-7000-8000-000000000000"

// DemoGrantTotalUnits totals the `demo_grant` units across ALL GCIDs via the
// SECURITY DEFINER helper added by migration 0043 (tightened by 0044). A plain
// SELECT would be filtered by the user_isolation RLS policy (migration 0003)
// down to the caller's own rows, and the runtime role is NOBYPASSRLS
// (migration 0025).
//
// FAIL CLOSED: when the elevated (GUC-free) reader is unavailable this returns
// an error. It must never report 0 — a caller enforcing a budget would read a
// zero total as "nothing has been granted" and hand out the whole budget again.
func (s *ManaStore) DemoGrantTotalUnits(ctx context.Context) (int64, error) {
	if s.plainTxr == nil {
		return 0, errors.New("pg.ManaStore.DemoGrantTotalUnits: no elevated querier wired (cross-GCID read unavailable)")
	}
	var out int64
	err := s.plainTxr.RunInTx(ctx, func(ctx context.Context, tx Tx) error {
		// `chora.user_gcid` is a PLACEHOLDER GUC: Postgres materializes it on
		// the first SET of a session and, at the end of the setting
		// transaction, reverts it to the EMPTY STRING rather than to "unset".
		// Every pooled connection that has already served a RunInUserTx is
		// therefore in a state where the user_isolation policy's
		// `current_setting('chora.user_gcid', true)::uuid` raises SQLSTATE
		// 22P02 (invalid input syntax for type uuid: ""). Pin the GUC to a UUID
		// no account can hold so the elevated read is deterministic — what makes
		// the cross-GCID rows visible is the helper's own role-targeted policy
		// (migration 0044), not this scope.
		if err := tx.Exec(ctx, `SET LOCAL chora.user_gcid = '`+noGcidSentinel+`'`); err != nil {
			return fmt.Errorf("pg.ManaStore.DemoGrantTotalUnits: scope guc: %w", err)
		}
		return tx.QueryRow(ctx, `SELECT public.mana_demo_grant_total_units()`).Scan(&out)
	})
	if err != nil {
		return 0, fmt.Errorf("pg.ManaStore.DemoGrantTotalUnits: %w", err)
	}
	return out, nil
}

// -----------------------------------------------------------------------------
// CreditWallet tx helpers
// -----------------------------------------------------------------------------

// lockWalletTx inserts the wallet row if absent and returns the locked
// current snapshot. The ON CONFLICT DO UPDATE is what takes the row lock.
func lockWalletTx(ctx context.Context, tx Tx, gcid string) (*mana.UserMana, error) {
	row := tx.QueryRow(ctx, `
		INSERT INTO user_mana
		    (gcid, balance_units, lifetime_earned, lifetime_spent,
		     last_credited_at, version, updated_at)
		VALUES ($1, 0, 0, 0, NULL, 1, now())
		ON CONFLICT (gcid) DO UPDATE SET gcid = EXCLUDED.gcid
		RETURNING gcid, balance_units, lifetime_earned, lifetime_spent,
		          last_credited_at, version, updated_at`, gcid)
	m, err := scanWalletRow(row)
	if err != nil {
		return nil, fmt.Errorf("pg.ManaStore lock wallet: %w", err)
	}
	return m, nil
}

// putWalletTx upserts the wallet row unconditionally. Safe without the OCC
// version guard because the caller holds the row lock from lockWalletTx.
func putWalletTx(ctx context.Context, tx Tx, m *mana.UserMana) (*mana.UserMana, error) {
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
		RETURNING gcid, balance_units, lifetime_earned, lifetime_spent,
		          last_credited_at, version, updated_at`,
		m.Gcid, m.BalanceUnits, m.LifetimeEarned, m.LifetimeSpent,
		m.LastCreditedAt, m.Version, m.UpdatedAt)
	out, err := scanWalletRow(row)
	if err != nil {
		return nil, fmt.Errorf("pg.ManaStore put wallet: %w", err)
	}
	return out, nil
}

// getManaTx reads the wallet without locking (replay path only).
func getManaTx(ctx context.Context, tx Tx, gcid string) (*mana.UserMana, error) {
	row := tx.QueryRow(ctx, `
		SELECT gcid, balance_units, lifetime_earned, lifetime_spent,
		       last_credited_at, version, updated_at
		  FROM user_mana
		 WHERE gcid = $1`, gcid)
	m, err := scanWalletRow(row)
	if errors.Is(err, ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("pg.ManaStore get wallet: %w", err)
	}
	return m, nil
}

// subsidyTotalTx sums the remaining units across a gcid's allocations.
func subsidyTotalTx(ctx context.Context, tx Tx, gcid string) (int64, error) {
	var out int64
	err := tx.QueryRow(ctx, `
		SELECT COALESCE(sum(remaining_units), 0)::bigint
		  FROM mana_subsidy_allocations
		 WHERE gcid = $1`, gcid).Scan(&out)
	if err != nil {
		return 0, fmt.Errorf("pg.ManaStore subsidy total: %w", err)
	}
	return out, nil
}

// balanceIncludingSubsidyTx mirrors the Quoter's user-visible balance
// (subsidy slices + personal balance) for the replay path.
func balanceIncludingSubsidyTx(ctx context.Context, tx Tx, wallet *mana.UserMana, gcid string) (int64, error) {
	subsidy, err := subsidyTotalTx(ctx, tx, gcid)
	if err != nil {
		return 0, err
	}
	if wallet == nil {
		return subsidy, nil
	}
	return mana.CheckedAddUnits(subsidy, wallet.BalanceUnits)
}

// insertLedgerTx appends one mana_ledger row.
func insertLedgerTx(ctx context.Context, tx Tx, e *mana.LedgerEntry) error {
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
}

// scanWalletRow scans a user_mana result row.
func scanWalletRow(row Row) (*mana.UserMana, error) {
	var (
		m            mana.UserMana
		lastCredited *time.Time
	)
	if err := row.Scan(&m.Gcid, &m.BalanceUnits, &m.LifetimeEarned, &m.LifetimeSpent,
		&lastCredited, &m.Version, &m.UpdatedAt); err != nil {
		if errors.Is(err, ErrNoRows) {
			return nil, ErrNoRows
		}
		return nil, err
	}
	m.LastCreditedAt = lastCredited
	return &m, nil
}

// scanLedgerRow scans one mana_ledger result row, returning (nil, nil) when the
// result set is empty.
func scanLedgerRow(row Row) (*mana.LedgerEntry, error) {
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
	if err := row.Scan(&e.EntryID, &e.Gcid, &dir, &e.Units, &rsn,
		&subID, &actionID, &allocID, &topupID,
		&e.BalanceAfterUnits, &e.IdempotencyKey, &requestID, &reversesID, &e.RecordedAt); err != nil {
		if errors.Is(err, ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	e.Direction = mana.Direction(dir)
	e.Reason = mana.Reason(rsn)
	e.SourceSubscriptionID = deref(subID)
	e.SourceActionID = deref(actionID)
	e.SourceAllocationID = deref(allocID)
	e.SourceTopupID = deref(topupID)
	e.RequestID = deref(requestID)
	e.ReversesEntryID = deref(reversesID)
	return &e, nil
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
