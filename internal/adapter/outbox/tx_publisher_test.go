// tx_publisher_test.go — same-tx transactional outbox insert (Q3).
//
// TxBoundPublisher satisfies events.Publisher but inserts the outbox row via
// the CALLER's transaction (an ExecTx) instead of the Store's own connection —
// so the domain state write (users UPDATE) and the outbox enqueue commit
// atomically in one DB transaction. These tests assert the INSERT is emitted
// on the supplied tx with the canonical column set + JSON payload.
package outbox_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/apollo-chora/chora-identity/internal/adapter/events"
	"github.com/apollo-chora/chora-identity/internal/adapter/outbox"
)

// stubExecTx records Exec calls; satisfies outbox.ExecTx.
type stubExecTx struct {
	sqls []string
	args [][]any
	err  error
}

func (s *stubExecTx) Exec(_ context.Context, sql string, args ...any) error {
	s.sqls = append(s.sqls, sql)
	s.args = append(s.args, args)
	return s.err
}

func envFor(tenant, gcid string) events.Envelope {
	env := events.NewEnvelope(tenant, gcid, "00-11111111111111111111111111111111-2222222222222222-01", "")
	return env
}

func TestTxBoundPublisher_InsertsOutboxRowViaCallerTx(t *testing.T) {
	t.Parallel()
	tx := &stubExecTx{}
	pub := outbox.NewTxBoundPublisher(tx)

	// Compile-time: it IS an events.Publisher.
	var _ events.Publisher = pub

	env := envFor("01970000-0000-7000-8000-0000000000bb", "01970000-0000-7000-8000-0000000000aa")
	payload := map[string]any{
		"gcid":         "01970000-0000-7000-8000-0000000000aa",
		"display_name": "Alice Wonder",
		"email":        "alice@example.com",
		"updated_at":   time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := pub.Publish(events.TopicProfileUpdated, env, payload); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	if len(tx.sqls) != 1 {
		t.Fatalf("expected exactly 1 Exec on the caller tx, got %d", len(tx.sqls))
	}
	sql := tx.sqls[0]
	if !strings.Contains(sql, "INSERT INTO outbox_events") {
		t.Errorf("expected INSERT INTO outbox_events, got %q", sql)
	}
	if !strings.Contains(sql, "'pending'") {
		t.Errorf("outbox row must enqueue status 'pending', got %q", sql)
	}

	// Args must carry the topic + a JSON-encoded payload with the projection.
	flat := flatten(tx.args[0])
	if !containsStr(flat, events.TopicProfileUpdated) {
		t.Errorf("insert args must carry topic %q; got %v", events.TopicProfileUpdated, flat)
	}
	if !anyJSONContains(tx.args[0], "display_name") || !anyJSONContains(tx.args[0], "Alice Wonder") {
		t.Errorf("insert args must carry a JSON payload with the display_name projection; args=%v", tx.args[0])
	}
}

func TestTxBoundPublisher_RejectsNonCanonicalTopic(t *testing.T) {
	t.Parallel()
	tx := &stubExecTx{}
	pub := outbox.NewTxBoundPublisher(tx)
	err := pub.Publish("not.canonical", envFor("01970000-0000-7000-8000-0000000000bb", "01970000-0000-7000-8000-0000000000aa"), map[string]any{"x": 1})
	if err == nil {
		t.Fatalf("expected error for non-canonical topic")
	}
	if len(tx.sqls) != 0 {
		t.Errorf("no INSERT must be attempted on a rejected topic; got %d", len(tx.sqls))
	}
}

func TestTxBoundPublisher_PropagatesTxError(t *testing.T) {
	t.Parallel()
	tx := &stubExecTx{err: errBoom}
	pub := outbox.NewTxBoundPublisher(tx)
	err := pub.Publish(events.TopicProfileUpdated,
		envFor("01970000-0000-7000-8000-0000000000bb", "01970000-0000-7000-8000-0000000000aa"),
		map[string]any{"gcid": "01970000-0000-7000-8000-0000000000aa", "display_name": "x"})
	if err == nil {
		t.Fatalf("expected the tx Exec error to propagate (so the caller rolls back)")
	}
}

// -- helpers ------------------------------------------------------------------

var errBoom = &boomErr{}

type boomErr struct{}

func (*boomErr) Error() string { return "boom" }

func flatten(args []any) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if s, ok := a.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func containsStr(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}

func anyJSONContains(args []any, needle string) bool {
	for _, a := range args {
		switch v := a.(type) {
		case []byte:
			if strings.Contains(string(v), needle) {
				return true
			}
		case string:
			if strings.Contains(v, needle) {
				return true
			}
		}
	}
	return false
}
