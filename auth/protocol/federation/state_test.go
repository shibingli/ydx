package federation

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMemoryStateStoreSingleUseAndExpiry(t *testing.T) {
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	store := NewMemoryStateStore(5*time.Minute, WithStateClock(func() time.Time { return now }))
	ctx := context.Background()

	record := &StateRecord{State: "state-1", Provider: "mock", Nonce: "nonce", Verifier: "verifier", RedirectURL: "https://app/callback"}
	if err := store.Save(ctx, record); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := store.Save(ctx, record); !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("duplicate Save error = %v", err)
	}
	consumed, err := store.Consume(ctx, "state-1")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if consumed.State != record.State || consumed.Provider != record.Provider || consumed.Nonce != record.Nonce || consumed.Verifier != record.Verifier {
		t.Fatalf("consumed record = %#v", consumed)
	}
	if _, err := store.Consume(ctx, "state-1"); !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("second Consume error = %v", err)
	}
	if _, err := store.Consume(ctx, ""); !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("empty Consume error = %v", err)
	}

	if err := store.Save(ctx, &StateRecord{State: "expired-soon"}); err != nil {
		t.Fatalf("Save expiring record: %v", err)
	}
	now = now.Add(5 * time.Minute)
	if _, err := store.Consume(ctx, "expired-soon"); !errors.Is(err, ErrStateExpired) {
		t.Fatalf("expired Consume error = %v", err)
	}
	if _, err := store.Consume(ctx, "expired-soon"); !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("expired record was not consumed: %v", err)
	}
	if err := store.Save(ctx, &StateRecord{State: "already-expired", ExpiresAt: now.Add(-time.Second)}); !errors.Is(err, ErrStateExpired) {
		t.Fatalf("already expired Save error = %v", err)
	}
}

func TestMemoryStateStoreCopiesRecords(t *testing.T) {
	store := NewMemoryStateStore(time.Minute)
	record := &StateRecord{State: "state", Provider: "mock", Nonce: "nonce"}
	if err := store.Save(context.Background(), record); err != nil {
		t.Fatalf("Save: %v", err)
	}
	record.Provider = "mutated"
	consumed, err := store.Consume(context.Background(), "state")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if consumed.Provider != "mock" {
		t.Fatalf("stored record aliased caller data: %#v", consumed)
	}
}

func TestMemoryStateStoreConcurrentConsume(t *testing.T) {
	store := NewMemoryStateStore(time.Minute)
	if err := store.Save(context.Background(), &StateRecord{State: "race-state", Provider: "mock"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	const workers = 64
	var wg sync.WaitGroup
	var successes int64
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := store.Consume(context.Background(), "race-state"); err == nil {
				atomic.AddInt64(&successes, 1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if successes != 1 {
		t.Fatalf("concurrent Consume successes = %d, want 1", successes)
	}
}

func TestMemoryStateStoreHonorsContext(t *testing.T) {
	store := NewMemoryStateStore(time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := store.Save(ctx, &StateRecord{State: "canceled"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Save canceled error = %v", err)
	}
	if _, err := store.Consume(ctx, "canceled"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Consume canceled error = %v", err)
	}
}
