package core

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMemoryStoreTTLAndTake(t *testing.T) {
	store := NewMemoryStore()
	now := time.Unix(1700000000, 0)
	store.now = func() time.Time { return now }
	ctx := context.Background()
	if err := store.Put(ctx, "k", []byte("value"), time.Second); err != nil {
		t.Fatal(err)
	}
	got, ok, err := store.Get(ctx, "k")
	if err != nil || !ok || string(got) != "value" {
		t.Fatalf("Get: %q %v %v", got, ok, err)
	}
	now = now.Add(2 * time.Second)
	if _, ok, _ := store.Get(ctx, "k"); ok {
		t.Fatal("expired key returned")
	}
}

func TestMemoryStoreConcurrentTakeOnlyOne(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	if err := store.Put(ctx, "k", []byte("value"), time.Minute); err != nil {
		t.Fatal(err)
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, ok, err := store.Take(ctx, "k")
			if err != nil {
				t.Errorf("Take: %v", err)
				return
			}
			if ok {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("Take winners = %d, want 1", wins.Load())
	}
}

func TestMemoryStoreRejectsEmptyKey(t *testing.T) {
	store := NewMemoryStore()
	if err := store.Put(context.Background(), "", []byte("x"), time.Minute); err == nil {
		t.Fatal("expected an error")
	}
}

func TestMemoryStorePutIfAbsentAndDeleteIf(t *testing.T) {
	store := NewMemoryStore()
	now := time.Unix(1700000000, 0)
	store.now = func() time.Time { return now }
	ctx := context.Background()
	if ok, err := store.PutIfAbsent(ctx, "k", []byte("first"), time.Minute); err != nil || !ok {
		t.Fatalf("first PutIfAbsent: %v %v", ok, err)
	}
	if ok, err := store.PutIfAbsent(ctx, "k", []byte("second"), time.Minute); err != nil || ok {
		t.Fatalf("second PutIfAbsent: %v %v", ok, err)
	}
	if ok, err := store.DeleteIf(ctx, "k", []byte("second")); err != nil || ok {
		t.Fatalf("mismatched DeleteIf: %v %v", ok, err)
	}
	if ok, err := store.DeleteIf(ctx, "k", []byte("first")); err != nil || !ok {
		t.Fatalf("matching DeleteIf: %v %v", ok, err)
	}
	if ok, err := store.PutIfAbsent(ctx, "k", []byte("third"), time.Second); err != nil || !ok {
		t.Fatalf("PutIfAbsent after delete: %v %v", ok, err)
	}
	now = now.Add(2 * time.Second)
	if ok, err := store.PutIfAbsent(ctx, "k", []byte("fourth"), time.Second); err != nil || !ok {
		t.Fatalf("PutIfAbsent after expiry: %v %v", ok, err)
	}
}
