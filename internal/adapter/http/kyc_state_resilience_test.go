// kyc_state_resilience_test.go — RED tests for the Singpass state-token
// repository's atomic single-use guarantee per the resilience-priority
// directive (memory feedback_resilience_priority.md, 2026-05-10).
//
// Audit gap: kyc_handler.singpassCallback called StateRepo.Get then
// `defer StateRepo.Delete` — non-atomic. Under multi-pod load (or even
// concurrent goroutines on a single pod), two callbacks holding the same
// state token could both succeed at Get and proceed to issue duplicate
// kyc.verified.v1 events, mint duplicate IMDA evidence, etc.
//
// The fix is a new GetAndConsume(ctx, state) method on the
// SingpassStateRepository port that atomically reads + deletes the record;
// the in-memory adapter wraps the read+delete under the existing exclusive
// mutex. Production wiring (M12 Memorystore-backed adapter) implements
// the same primitive via WATCH/MULTI/EXEC or DEL+GET on a Lua script.
package httpadapter_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	httpadapter "github.com/apollo-chora/chora-identity/internal/adapter/http"
)

// TestSingpassStateRepo_GetAndConsume_ReturnsRecord_OnFirstCall asserts the
// happy path — first caller gets the record + the underlying entry is gone.
func TestSingpassStateRepo_GetAndConsume_ReturnsRecord_OnFirstCall(t *testing.T) {
	t.Parallel()
	repo := httpadapter.NewInMemSingpassStateRepository()
	ctx := context.Background()

	rec := &httpadapter.SingpassStateRecord{
		State:          "state-aaa",
		Gcid:           "gcid-1",
		TenantID:       "tenant-1",
		CodeVerifier:   "verifier-1",
		VerificationID: "v-1",
		CreatedAt:      time.Now().UTC(),
		ExpiresAt:      time.Now().UTC().Add(10 * time.Minute),
	}
	if err := repo.Put(ctx, rec); err != nil {
		t.Fatalf("put: %v", err)
	}

	got, err := repo.GetAndConsume(ctx, "state-aaa")
	if err != nil {
		t.Fatalf("GetAndConsume: %v", err)
	}
	if got == nil || got.Gcid != "gcid-1" {
		t.Fatalf("got=%+v want gcid-1", got)
	}

	// Second call must report the state already consumed.
	if _, err := repo.GetAndConsume(ctx, "state-aaa"); err == nil {
		t.Fatalf("second GetAndConsume must fail — state already consumed")
	}
}

// TestSingpassStateRepo_GetAndConsume_ConcurrentCallers_OnlyOneSucceeds is
// the race-safety invariant: under N concurrent callers with the same state
// token, exactly one must observe success and N-1 must observe a missing
// state. Without GetAndConsume, the read-then-delete window lets multiple
// callers proceed.
func TestSingpassStateRepo_GetAndConsume_ConcurrentCallers_OnlyOneSucceeds(t *testing.T) {
	t.Parallel()
	repo := httpadapter.NewInMemSingpassStateRepository()
	ctx := context.Background()

	rec := &httpadapter.SingpassStateRecord{
		State:          "state-race",
		Gcid:           "gcid-race",
		TenantID:       "tenant-race",
		CodeVerifier:   "verifier-race",
		VerificationID: "v-race",
		CreatedAt:      time.Now().UTC(),
		ExpiresAt:      time.Now().UTC().Add(10 * time.Minute),
	}
	if err := repo.Put(ctx, rec); err != nil {
		t.Fatalf("put: %v", err)
	}

	const N = 64
	var successes int64
	var failures int64
	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			got, err := repo.GetAndConsume(ctx, "state-race")
			if err == nil && got != nil {
				atomic.AddInt64(&successes, 1)
			} else {
				atomic.AddInt64(&failures, 1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if successes != 1 {
		t.Fatalf("successes=%d want exactly 1 (replay-safety violated)", successes)
	}
	if failures != N-1 {
		t.Fatalf("failures=%d want %d", failures, N-1)
	}
}

// TestSingpassStateRepo_GetAndConsume_Expired returns an error and does not
// resurrect an expired record.
func TestSingpassStateRepo_GetAndConsume_Expired(t *testing.T) {
	t.Parallel()
	repo := httpadapter.NewInMemSingpassStateRepository()
	ctx := context.Background()

	rec := &httpadapter.SingpassStateRecord{
		State:          "state-expired",
		Gcid:           "gcid-expired",
		TenantID:       "tenant-expired",
		CodeVerifier:   "verifier-expired",
		VerificationID: "v-expired",
		CreatedAt:      time.Now().UTC().Add(-20 * time.Minute),
		ExpiresAt:      time.Now().UTC().Add(-10 * time.Minute), // already past
	}
	if err := repo.Put(ctx, rec); err != nil {
		t.Fatalf("put: %v", err)
	}

	if _, err := repo.GetAndConsume(ctx, "state-expired"); err == nil {
		t.Fatalf("GetAndConsume must reject expired record")
	}
	// Even after a failed-due-to-expiry call, the record should be gone
	// (never let an expired token come back to life through the cracks).
	if _, err := repo.GetAndConsume(ctx, "state-expired"); err == nil {
		t.Fatalf("expired record must be deleted on first GetAndConsume")
	}
}

// TestSingpassStateRepo_GetAndConsume_Unknown returns an error.
func TestSingpassStateRepo_GetAndConsume_Unknown(t *testing.T) {
	t.Parallel()
	repo := httpadapter.NewInMemSingpassStateRepository()
	ctx := context.Background()

	_, err := repo.GetAndConsume(ctx, "state-does-not-exist")
	if err == nil {
		t.Fatalf("GetAndConsume must fail for unknown state")
	}
	// Don't constrain the exact sentinel — just require non-nil error.
	if errors.Is(err, nil) {
		t.Fatalf("err is nil")
	}
}
