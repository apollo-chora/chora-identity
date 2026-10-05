// inmem_mana_ledger.go is a documentation-only adapter — the canonical
// in-memory ledger lives on user_mana.InMemoryStore (kept together with the
// quoter for cohesion). This file exists so future pgx-backed adapter work
// has a clean split-out point.
//
// Production pgx adapter (M12+):
//   - mana_ledger     : append-only INSERTs only; partitioned by month.
//   - user_mana       : UPDATE under OCC version match.
//   - mana_allocation : UPSERT keyed on allocation_id.
package repo
