package auth

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestManagedMemoryStoresCleanup(t *testing.T) {
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	ms := NewManagedMemoryStores(MemoryStoreOptions{})
	ms.SetClock(func() time.Time { return base })
	ctx := context.Background()

	sessions := []*Session{
		{ID: "absolute-expired", UserID: "u", ExpiresAt: base.Add(-time.Minute)},
		{ID: "idle-expired", UserID: "u", IdleExpiresAt: base.Add(-time.Minute)},
		{ID: "active", UserID: "u", ExpiresAt: base.Add(time.Hour), IdleExpiresAt: base.Add(30 * time.Minute)},
		{ID: "no-deadline", UserID: "u"},
	}
	for _, session := range sessions {
		if err := ms.Stores.Sessions.CreateSession(ctx, session); err != nil {
			t.Fatalf("CreateSession(%q): %v", session.ID, err)
		}
	}

	tokens := []*OneTimeToken{
		{Hash: "expired", Purpose: "purpose", ExpiresAt: base.Add(-time.Minute)},
		{Hash: "active", Purpose: "purpose", ExpiresAt: base.Add(time.Hour)},
		{Hash: "forever", Purpose: "purpose"},
		{Hash: "used", Purpose: "purpose", ExpiresAt: base.Add(time.Hour), UsedAt: base.Add(-time.Minute)},
	}
	for _, token := range tokens {
		if err := ms.Stores.Tokens.CreateToken(ctx, token); err != nil {
			t.Fatalf("CreateToken(%q): %v", token.Hash, err)
		}
	}

	for i := 1; i <= 4; i++ {
		event := &AuditEvent{ID: "a" + strconv.Itoa(i), Type: "test", At: base}
		if err := ms.Stores.Audits.RecordAudit(ctx, event); err != nil {
			t.Fatalf("RecordAudit: %v", err)
		}
	}
	// Lower the cap without trimming so Cleanup has work to do. | 仅降低上限而不立即裁剪，使 Cleanup
	// 有工作需要完成。
	ms.audits.maxEvents = 2

	result, err := ms.Cleanup(ctx)
	if err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if result.Sessions != 2 || result.Tokens != 1 || result.Audits != 2 {
		t.Fatalf("cleanup result = %+v", result)
	}

	for _, id := range []string{"absolute-expired", "idle-expired"} {
		if _, err := ms.Stores.Sessions.GetSession(ctx, id); !errors.Is(err, ErrSessionNotFound) {
			t.Fatalf("session %q = %v, want ErrSessionNotFound", id, err)
		}
	}
	for _, id := range []string{"active", "no-deadline"} {
		if _, err := ms.Stores.Sessions.GetSession(ctx, id); err != nil {
			t.Fatalf("session %q was removed: %v", id, err)
		}
	}

	if _, err := ms.Stores.Tokens.PeekToken(ctx, "expired", "purpose", base); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("expired token = %v, want ErrTokenInvalid after cleanup", err)
	}
	if _, err := ms.Stores.Tokens.PeekToken(ctx, "used", "purpose", base); !errors.Is(err, ErrTokenUsed) {
		t.Fatalf("used token = %v, want ErrTokenUsed", err)
	}
	for _, hash := range []string{"active", "forever"} {
		if _, err := ms.Stores.Tokens.PeekToken(ctx, hash, "purpose", base); err != nil {
			t.Fatalf("token %q was removed: %v", hash, err)
		}
	}

	events, total, err := ms.Stores.Audits.ListAudit(ctx, AuditQuery{})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if total != 2 || len(events) != 2 || events[0].ID != "a3" || events[1].ID != "a4" {
		t.Fatalf("audit after cleanup = total %d events %+v", total, events)
	}

	result, err = ms.Cleanup(ctx)
	if err != nil || result != (MemoryCleanupResult{}) {
		t.Fatalf("second cleanup = %+v, %v", result, err)
	}
}

func TestMemoryAuditStoreMaxEvents(t *testing.T) {
	store := NewMemoryAuditStore()
	ctx := context.Background()
	for i := 1; i <= 5; i++ {
		if err := store.RecordAudit(ctx, &AuditEvent{ID: "a" + strconv.Itoa(i), At: time.Unix(int64(i), 0).UTC()}); err != nil {
			t.Fatalf("RecordAudit: %v", err)
		}
	}
	if _, total, _ := store.ListAudit(ctx, AuditQuery{}); total != 5 {
		t.Fatalf("unlimited total = %d", total)
	}
	if removed := store.SetMaxEvents(3); removed != 2 {
		t.Fatalf("SetMaxEvents removed %d, want 2", removed)
	}
	events, total, _ := store.ListAudit(ctx, AuditQuery{})
	if total != 3 || events[0].ID != "a3" || events[2].ID != "a5" {
		t.Fatalf("capped events = total %d %+v", total, events)
	}
	if err := store.RecordAudit(ctx, &AuditEvent{ID: "a6", At: time.Unix(6, 0).UTC()}); err != nil {
		t.Fatalf("RecordAudit: %v", err)
	}
	events, total, _ = store.ListAudit(ctx, AuditQuery{})
	if total != 3 || events[0].ID != "a4" || events[2].ID != "a6" {
		t.Fatalf("rolling cap = total %d %+v", total, events)
	}
	if removed := store.SetMaxEvents(0); removed != 0 {
		t.Fatalf("removing cap trimmed %d", removed)
	}
	if err := store.RecordAudit(ctx, &AuditEvent{ID: "a7", At: time.Unix(7, 0).UTC()}); err != nil {
		t.Fatalf("RecordAudit: %v", err)
	}
	if _, total, _ := store.ListAudit(ctx, AuditQuery{}); total != 4 {
		t.Fatalf("uncapped total = %d", total)
	}
}

func TestManagedMemoryStoresStartClose(t *testing.T) {
	base := time.Now().UTC()
	ms := NewManagedMemoryStores(MemoryStoreOptions{CleanupInterval: 5 * time.Millisecond})
	ms.SetClock(func() time.Time { return base })
	ctx := context.Background()
	if err := ms.Stores.Tokens.CreateToken(ctx, &OneTimeToken{Hash: "expired", Purpose: "purpose", ExpiresAt: base.Add(-time.Minute)}); err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if err := ms.Stores.Sessions.CreateSession(ctx, &Session{ID: "expired-session", UserID: "u", ExpiresAt: base.Add(-time.Minute)}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if err := ms.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := ms.Start(); err != nil {
		t.Fatalf("second Start: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := ms.Stores.Tokens.PeekToken(ctx, "expired", "purpose", base); errors.Is(err, ErrTokenInvalid) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("background cleanup did not remove the expired token")
		}
		time.Sleep(5 * time.Millisecond)
	}
	deadline = time.Now().Add(3 * time.Second)
	for {
		if _, err := ms.Stores.Sessions.GetSession(ctx, "expired-session"); errors.Is(err, ErrSessionNotFound) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("background cleanup did not remove the expired session")
		}
		time.Sleep(5 * time.Millisecond)
	}

	if err := ms.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := ms.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := ms.Start(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("Start after Close = %v, want ErrInvalidConfig", err)
	}

	if err := ms.Stores.Tokens.CreateToken(ctx, &OneTimeToken{Hash: "after-close", Purpose: "purpose", ExpiresAt: base.Add(-time.Minute)}); err != nil {
		t.Fatalf("CreateToken after close: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if _, err := ms.Stores.Tokens.PeekToken(ctx, "after-close", "purpose", base); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("background cleanup ran after Close: %v", err)
	}

	// Explicit cleanup remains available after Close. | Close 之后仍可显式清理。
	result, err := ms.Cleanup(ctx)
	if err != nil {
		t.Fatalf("Cleanup after Close: %v", err)
	}
	if result.Tokens != 1 {
		t.Fatalf("Cleanup after Close removed %d tokens, want 1", result.Tokens)
	}
}

func TestManagedMemoryStoresCleanupCanceledContext(t *testing.T) {
	base := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	ms := NewManagedMemoryStores(MemoryStoreOptions{})
	ms.SetClock(func() time.Time { return base })
	ctx := context.Background()
	if err := ms.Stores.Tokens.CreateToken(ctx, &OneTimeToken{Hash: "expired", Purpose: "purpose", ExpiresAt: base.Add(-time.Minute)}); err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := ms.Cleanup(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Cleanup = %v, want context.Canceled", err)
	}
	if _, err := ms.Stores.Tokens.PeekToken(ctx, "expired", "purpose", base); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("canceled Cleanup mutated the store: %v", err)
	}
	if _, err := ms.Cleanup(nil); err != nil {
		t.Fatalf("nil-context Cleanup: %v", err)
	}
}

func TestManagedMemoryStoresConcurrentCleanup(t *testing.T) {
	ms := NewManagedMemoryStores(MemoryStoreOptions{CleanupInterval: time.Millisecond, MaxAuditEvents: 32})
	if err := ms.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() {
		if err := ms.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	}()
	ctx := context.Background()
	const (
		workers    = 8
		iterations = 40
	)
	var wg sync.WaitGroup
	wg.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func(worker int) {
			defer wg.Done()
			now := time.Now().UTC()
			for i := 0; i < iterations; i++ {
				suffix := strconv.Itoa(worker) + "-" + strconv.Itoa(i)
				_ = ms.Stores.Sessions.CreateSession(ctx, &Session{ID: "s-" + suffix, UserID: "u", ExpiresAt: now.Add(-time.Second)})
				_ = ms.Stores.Tokens.CreateToken(ctx, &OneTimeToken{Hash: "t-" + suffix, Purpose: "purpose", ExpiresAt: now.Add(-time.Second)})
				_ = ms.Stores.Audits.RecordAudit(ctx, &AuditEvent{ID: "event-" + suffix, At: now})
				if _, err := ms.Cleanup(ctx); err != nil {
					t.Errorf("Cleanup: %v", err)
					return
				}
				_, _, _ = ms.Stores.Audits.ListAudit(ctx, AuditQuery{Limit: 10})
			}
		}(worker)
	}
	wg.Wait()
}
