// singpass_state_test.go covers the properties this adapter exists for, in the
// order they matter: SINGLE-USE (a replayed callback must fail), FAIL-CLOSED (a
// store outage must deny rather than allow), and the TTL/expiry contract.
//
// Following the precedent in chora-user-event-stream's redis adapter, this
// avoids miniredis (which would churn the workspace go.work.sum) and drives a
// dependency-free RESP3 stand-in speaking only the five commands the adapter
// uses: HELLO, SET (with NX/PX), GET, GETDEL and DEL.
package redisstate

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	httpadapter "github.com/apollo-chora/chora-identity/internal/adapter/http"
)

// --- dependency-free RESP3 key-value stand-in -------------------------------

type fakeRedis struct {
	ln   net.Listener
	addr string

	mu   sync.Mutex
	kv   map[string]string
	fail bool // when set, every command replies with an error (outage sim)
}

func newFakeRedis(t *testing.T) *fakeRedis {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake redis listen: %v", err)
	}
	f := &fakeRedis{ln: ln, addr: ln.Addr().String(), kv: map[string]string{}}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return f
}

func (f *fakeRedis) setFail(v bool) { f.mu.Lock(); f.fail = v; f.mu.Unlock() }

func (f *fakeRedis) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	r := bufio.NewReader(c)
	for {
		args, err := readCommand(r)
		if err != nil {
			return
		}
		if len(args) == 0 {
			continue
		}
		f.mu.Lock()
		fail := f.fail
		f.mu.Unlock()
		cmd := strings.ToUpper(args[0])
		if fail && cmd != "HELLO" {
			_, _ = c.Write([]byte("-ERR simulated outage\r\n"))
			continue
		}
		_, _ = c.Write(f.reply(cmd, args))
	}
}

func (f *fakeRedis) reply(cmd string, args []string) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch cmd {
	case "HELLO":
		// Minimal RESP3 map reply; go-redis only needs it to not error.
		return []byte("%1\r\n$6\r\nserver\r\n$5\r\nfakes\r\n")
	case "SET":
		k, v := args[1], args[2]
		nx := false
		for _, a := range args[3:] {
			if strings.EqualFold(a, "NX") {
				nx = true
			}
		}
		if nx {
			if _, exists := f.kv[k]; exists {
				return []byte("_\r\n") // RESP3 null => SetNX false
			}
		}
		f.kv[k] = v
		return []byte("+OK\r\n")
	case "GET":
		v, ok := f.kv[args[1]]
		if !ok {
			return []byte("_\r\n")
		}
		return bulk(v)
	case "GETDEL":
		v, ok := f.kv[args[1]]
		if !ok {
			return []byte("_\r\n")
		}
		delete(f.kv, args[1])
		return bulk(v)
	case "DEL":
		n := 0
		for _, k := range args[1:] {
			if _, ok := f.kv[k]; ok {
				delete(f.kv, k)
				n++
			}
		}
		return []byte(fmt.Sprintf(":%d\r\n", n))
	default:
		return []byte("+OK\r\n")
	}
}

func bulk(s string) []byte { return []byte(fmt.Sprintf("$%d\r\n%s\r\n", len(s), s)) }

func readCommand(r *bufio.Reader) ([]string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(line, "*") {
		return nil, errors.New("expected array")
	}
	n, err := strconv.Atoi(line[1:])
	if err != nil {
		return nil, err
	}
	args := make([]string, 0, n)
	for i := 0; i < n; i++ {
		hdr, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		ln, err := strconv.Atoi(strings.TrimRight(hdr, "\r\n")[1:])
		if err != nil {
			return nil, err
		}
		buf := make([]byte, ln+2)
		if _, err := readFull(r, buf); err != nil {
			return nil, err
		}
		args = append(args, string(buf[:ln]))
	}
	return args, nil
}

func readFull(r *bufio.Reader, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, err := r.Read(b[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func newTestStore(t *testing.T, f *fakeRedis) *Store {
	t.Helper()
	s, err := NewStore(Config{Addr: f.addr, TTL: time.Minute})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func rec(state string) *httpadapter.SingpassStateRecord {
	return &httpadapter.SingpassStateRecord{
		State:        state,
		Gcid:         "01935b5a-0000-7000-8000-000000000001",
		TenantID:     "chora-master",
		CodeVerifier: "verifier-abc",
		CreatedAt:    time.Now().UTC(),
		ExpiresAt:    time.Now().UTC().Add(10 * time.Minute),
	}
}

// --- the properties --------------------------------------------------------

// A replayed callback must fail. This is the reason the adapter exists.
func TestGetAndConsumeIsSingleUse(t *testing.T) {
	s := newTestStore(t, newFakeRedis(t))
	ctx := context.Background()
	if err := s.Put(ctx, rec("state-1")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.GetAndConsume(ctx, "state-1")
	if err != nil {
		t.Fatalf("first GetAndConsume: %v", err)
	}
	if got.CodeVerifier != "verifier-abc" || got.Gcid == "" {
		t.Fatalf("first GetAndConsume returned %+v", got)
	}
	second, err := s.GetAndConsume(ctx, "state-1")
	if !errors.Is(err, ErrStateNotFound) {
		t.Fatalf("replay must fail with ErrStateNotFound, got record=%+v err=%v", second, err)
	}
}

// A store outage must DENY. Returning a nil error here would be a CSRF hole.
func TestGetAndConsumeFailsClosedOnStoreError(t *testing.T) {
	f := newFakeRedis(t)
	s := newTestStore(t, f)
	ctx := context.Background()
	if err := s.Put(ctx, rec("state-2")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	f.setFail(true)
	got, err := s.GetAndConsume(ctx, "state-2")
	if err == nil {
		t.Fatalf("outage must surface as an error, got record=%+v nil err", got)
	}
	if got != nil {
		t.Fatalf("outage must not return a record, got %+v", got)
	}
	if errors.Is(err, ErrStateNotFound) {
		t.Fatalf("an outage must be distinguishable from a missing token, got %v", err)
	}
}

// An unknown token is not an error the caller can distinguish from a consumed
// one: telling them apart would be a probing oracle.
func TestGetAndConsumeUnknownToken(t *testing.T) {
	s := newTestStore(t, newFakeRedis(t))
	if _, err := s.GetAndConsume(context.Background(), "never-issued"); !errors.Is(err, ErrStateNotFound) {
		t.Fatalf("want ErrStateNotFound, got %v", err)
	}
}

// SetNX: a token already in flight must not be silently overwritten, which
// would discard the first flow's code verifier.
func TestPutRefusesDuplicateToken(t *testing.T) {
	s := newTestStore(t, newFakeRedis(t))
	ctx := context.Background()
	if err := s.Put(ctx, rec("state-3")); err != nil {
		t.Fatalf("first Put: %v", err)
	}
	if err := s.Put(ctx, rec("state-3")); err == nil {
		t.Fatal("second Put with the same token must fail")
	}
}

// A record past its ExpiresAt is not returned even if the key survived, so an
// expired state is never resurrected on retry.
func TestGetAndConsumeRejectsExpiredRecord(t *testing.T) {
	s := newTestStore(t, newFakeRedis(t))
	ctx := context.Background()
	r := rec("state-4")
	r.ExpiresAt = time.Now().UTC().Add(-time.Second)
	if err := s.Put(ctx, r); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := s.GetAndConsume(ctx, "state-4"); !errors.Is(err, ErrStateNotFound) {
		t.Fatalf("expired record must not be returned, got %v", err)
	}
}

// Put must reject a record with no token rather than writing a blank key.
func TestPutRejectsEmptyState(t *testing.T) {
	s := newTestStore(t, newFakeRedis(t))
	if err := s.Put(context.Background(), &httpadapter.SingpassStateRecord{}); err == nil {
		t.Fatal("Put with an empty state token must fail")
	}
}

// Get is the non-consuming read the port doc keeps for tests and admin
// tooling: it must return the record and leave it usable.
func TestGetDoesNotConsume(t *testing.T) {
	s := newTestStore(t, newFakeRedis(t))
	ctx := context.Background()
	if err := s.Put(ctx, rec("state-5")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := s.Get(ctx, "state-5"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, err := s.GetAndConsume(ctx, "state-5"); err != nil {
		t.Fatalf("Get must not consume, but GetAndConsume then failed: %v", err)
	}
}

func TestGetUnknownToken(t *testing.T) {
	s := newTestStore(t, newFakeRedis(t))
	if _, err := s.Get(context.Background(), "never-issued"); !errors.Is(err, ErrStateNotFound) {
		t.Fatalf("want ErrStateNotFound, got %v", err)
	}
}

// Delete makes the token unusable, and deleting an absent token is not an
// error: the caller's intent is that it no longer work, and it does not.
func TestDelete(t *testing.T) {
	s := newTestStore(t, newFakeRedis(t))
	ctx := context.Background()
	if err := s.Put(ctx, rec("state-6")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Delete(ctx, "state-6"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.GetAndConsume(ctx, "state-6"); !errors.Is(err, ErrStateNotFound) {
		t.Fatalf("token must be gone after Delete, got %v", err)
	}
	if err := s.Delete(ctx, "already-gone"); err != nil {
		t.Fatalf("deleting an absent token must not error: %v", err)
	}
}

// A malformed CA must fail at construction. This is the one case that fails
// loud rather than degrading, because it is an operator config error and
// falling back would hide it.
func TestNewStoreRejectsMalformedCA(t *testing.T) {
	if _, err := NewStore(Config{Addr: "127.0.0.1:6379", CACertPEM: "not a certificate"}); err == nil {
		t.Fatal("a CA PEM containing no certificate must fail construction")
	}
}

// No CA means no TLS, which is only appropriate inside the mesh but must not
// error.
func TestNewStoreWithoutCA(t *testing.T) {
	s, err := NewStore(Config{Addr: "127.0.0.1:6379"})
	if err != nil {
		t.Fatalf("NewStore without a CA: %v", err)
	}
	_ = s.Close()
}

// An unset TTL falls back to DefaultTTL rather than to zero, which would make
// every key immortal or immediately dead depending on the server.
func TestDefaultTTLApplied(t *testing.T) {
	s, err := NewStore(Config{Addr: "127.0.0.1:6379"})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer func() { _ = s.Close() }()
	if s.ttl != DefaultTTL {
		t.Fatalf("want DefaultTTL %v, got %v", DefaultTTL, s.ttl)
	}
}
