// tx_publisher.go — same-tx transactional outbox insert (Q3).
//
// The default Publisher (publisher.go) enqueues via Store.Insert on the Store's
// OWN connection, so the domain state write and the outbox enqueue are two
// separate transactions (the mana adapter documents the same inherited gap).
// TxBoundPublisher closes that gap for call-sites that DO hold an open domain
// transaction: it inserts the outbox row through the CALLER's tx, so the state
// write (e.g. users UPDATE) and the event enqueue commit — or roll back —
// atomically. This is the canonical transactional-outbox contract.
//
// It reuses Publisher.buildRow, so the on-wire row is byte-identical to the
// Store path (envelope attribute set, payload encoding, aggregate derivation).
// Only the INSERT target differs: an ExecTx (the caller's transaction) instead
// of the Store connection.
package outbox

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/apollo-chora/chora-identity/internal/adapter/events"
)

// ExecTx is the minimal in-transaction Exec surface required to insert an
// outbox row. A pgx-backed *pg.Tx (services/chora-identity/internal/adapter/pg)
// satisfies it structurally — no import from outbox → pg is required.
type ExecTx interface {
	Exec(ctx context.Context, sql string, args ...any) error
}

// TxBoundPublisher satisfies events.Publisher by inserting the outbox row via a
// caller-supplied transaction. Construct one per domain transaction, hand it to
// a typed publisher (e.g. events.NewProfileUpdatedPublisher), and the event
// enqueues in the SAME tx as the aggregate write.
type TxBoundPublisher struct {
	p  *Publisher
	tx ExecTx
}

// NewTxBoundPublisher wraps an open transaction. The embedded Publisher is used
// only for buildRow + its config defaults (source_project / source_service);
// it never touches a Store, so a nil-Store Publisher is intentional.
func NewTxBoundPublisher(tx ExecTx) *TxBoundPublisher {
	return &TxBoundPublisher{p: NewPublisher(PublisherConfig{}), tx: tx}
}

// Publish builds the canonical outbox row and INSERTs it via the caller's tx.
// A tx Exec error propagates so the caller rolls the whole transaction back
// (atomicity). Uses context.Background for the Exec — mirroring the Store path
// in publisher.go; the transaction lifecycle (Begin/Commit) is ctx-scoped by
// the caller's RunInTx.
func (t *TxBoundPublisher) Publish(topic string, env events.Envelope, payload map[string]any) error {
	if t.tx == nil {
		return fmt.Errorf("outbox: TxBoundPublisher tx not wired")
	}
	row, err := t.p.buildRow(topic, env, payload)
	if err != nil {
		return err
	}
	return insertRowViaTx(context.Background(), t.tx, row)
}

// insertRowViaTx runs the outbox_events INSERT on the supplied tx. Mirrors the
// PostgresStore.Insert column set (migrations 0005 + 0008); tenant_id + gcid are
// UUID columns, so empty values map to NULL (the migration's nullable design +
// permissive RLS for platform / directory-global events) rather than failing a
// text→uuid cast.
func insertRowViaTx(ctx context.Context, tx ExecTx, row Row) error {
	envJSON, err := json.Marshal(row.Envelope)
	if err != nil {
		return fmt.Errorf("outbox: marshal envelope: %w", err)
	}
	const q = `INSERT INTO outbox_events (
        id, tenant_id, gcid, aggregate_type, aggregate_id, event_type, topic,
        payload, envelope, idempotency_key, occurred_at, status
    ) VALUES (
        $1, $2::uuid, $3::uuid, $4, $5, $6, $7, $8, $9::jsonb, $10, $11, 'pending'
    )`
	if err := tx.Exec(ctx, q,
		row.ID, nullUUIDArg(row.TenantID), nullUUIDArg(row.GCID),
		row.AggregateType, row.AggregateID, row.EventType, row.Topic,
		row.Payload, string(envJSON), row.IdempotencyKey, row.OccurredAt,
	); err != nil {
		return fmt.Errorf("outbox: insertRowViaTx: %w", err)
	}
	return nil
}

// nullUUIDArg maps an empty string to a nil arg so a UUID column receives NULL
// rather than an invalid empty-string uuid literal.
func nullUUIDArg(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// Compile-time port assertion.
var _ events.Publisher = (*TxBoundPublisher)(nil)
