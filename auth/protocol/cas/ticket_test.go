package cas

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth"
)

func TestNewTicketIDPrefixAndUniqueness(t *testing.T) {
	cases := []struct {
		typ    TicketType
		prefix string
	}{
		{TicketTGT, TicketPrefixTGT},
		{TicketST, TicketPrefixST},
		{TicketPGT, TicketPrefixPGT},
		{TicketPT, TicketPrefixPT},
	}
	seen := make(map[string]struct{})
	for _, tc := range cases {
		id, err := NewTicketID(tc.typ)
		if err != nil {
			t.Fatalf("NewTicketID(%s): %v", tc.typ, err)
		}
		if !strings.HasPrefix(id, tc.prefix) {
			t.Fatalf("NewTicketID(%s) = %q, want prefix %q", tc.typ, id, tc.prefix)
		}
		if len(id) <= len(tc.prefix) {
			t.Fatalf("NewTicketID(%s) = %q, want entropy", tc.typ, id)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("NewTicketID(%s) returned a duplicate %q", tc.typ, id)
		}
		seen[id] = struct{}{}
	}
	if _, err := NewTicketID(TicketType("XX")); !errors.Is(err, ErrTicketTypeMismatch) {
		t.Fatalf("NewTicketID(unknown) error = %v, want ErrTicketTypeMismatch", err)
	}
}

func TestMemoryTicketStoreLifecycle(t *testing.T) {
	store := NewMemoryTicketStore()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	ticket := testTicket(TicketST, "ST-one", now, now.Add(time.Minute))
	if err := store.Save(context.Background(), ticket); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := store.Get(context.Background(), ticket.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != ticket.ID || got.Type != TicketST {
		t.Fatalf("Get = %#v, want ST-one", got)
	}
	// Mutating a returned record must never affect the stored record. | 修改返回记录不得影响存储记录。
	got.UserID = "mutated"
	if again, _ := store.Get(context.Background(), ticket.ID); again.UserID != ticket.UserID {
		t.Fatalf("store returned an aliased record")
	}
	if _, err := store.Consume(context.Background(), ticket.ID, TicketTGT, now); !errors.Is(err, ErrTicketTypeMismatch) {
		t.Fatalf("Consume wrong type error = %v, want ErrTicketTypeMismatch", err)
	}
	consumed, err := store.Consume(context.Background(), ticket.ID, TicketST, now)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if !consumed.Consumed() {
		t.Fatalf("Consume did not mark the ticket used")
	}
	if _, err := store.Consume(context.Background(), ticket.ID, TicketST, now); !errors.Is(err, ErrTicketUsed) {
		t.Fatalf("second Consume error = %v, want ErrTicketUsed", err)
	}
	if err := store.Delete(context.Background(), ticket.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.Get(context.Background(), ticket.ID); !errors.Is(err, ErrTicketNotFound) {
		t.Fatalf("Get after Delete error = %v, want ErrTicketNotFound", err)
	}
	if err := store.Delete(context.Background(), "ST-absent"); err != nil {
		t.Fatalf("Delete absent: %v", err)
	}
}

func TestMemoryTicketStoreExpiry(t *testing.T) {
	store := NewMemoryTicketStore()
	now := time.Date(2026, time.March, 1, 0, 0, 0, 0, time.UTC)
	ticket := testTicket(TicketST, "ST-old", now.Add(-time.Hour), now.Add(-time.Minute))
	if err := store.Save(context.Background(), ticket); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := store.Consume(context.Background(), ticket.ID, TicketST, now); !errors.Is(err, ErrTicketExpired) {
		t.Fatalf("Consume expired error = %v, want ErrTicketExpired", err)
	}
	if ticket.Active(now) {
		t.Fatalf("expired ticket reports Active")
	}
	if !ticket.ActiveWithSkew(now, 2*time.Minute) {
		t.Fatalf("ActiveWithSkew did not extend the deadline")
	}
}

func TestMemoryTicketStoreConcurrentConsume(t *testing.T) {
	store := NewMemoryTicketStore()
	now := time.Date(2026, time.April, 1, 0, 0, 0, 0, time.UTC)
	ticket := testTicket(TicketST, "ST-race", now, now.Add(time.Minute))
	if err := store.Save(context.Background(), ticket); err != nil {
		t.Fatalf("Save: %v", err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := store.Consume(context.Background(), ticket.ID, TicketST, now); err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if successes != 1 {
		t.Fatalf("concurrent Consume successes = %d, want 1", successes)
	}
}

func TestMemoryTicketStoreIndexesAndDeletion(t *testing.T) {
	store := NewMemoryTicketStore()
	ctx := context.Background()
	now := time.Date(2026, time.May, 1, 0, 0, 0, 0, time.UTC)
	tgt := testTicket(TicketTGT, "TGT-root", now, now.Add(time.Hour))
	tgt.RootTGTID = tgt.ID
	st := testTicket(TicketST, "ST-service", now, now.Add(time.Hour))
	st.ParentID = tgt.ID
	st.RootTGTID = tgt.ID
	st.Service = "https://app.example.com/callback"
	pgt := testTicket(TicketPGT, "PGT-proxy", now, now.Add(time.Hour))
	pgt.ParentID = tgt.ID
	pgt.RootTGTID = tgt.ID
	pt := testTicket(TicketPT, "PT-target", now, now.Add(time.Hour))
	pt.ParentID = pgt.ID
	pt.RootTGTID = tgt.ID
	pt.Service = "https://api.example.com/data"
	for _, ticket := range []*Ticket{tgt, st, pgt, pt} {
		if err := store.Save(ctx, ticket); err != nil {
			t.Fatalf("Save(%s): %v", ticket.ID, err)
		}
	}
	if got := store.Len(); got != 4 {
		t.Fatalf("Len = %d, want 4", got)
	}
	byService, err := store.ListByService(ctx, st.Service)
	if err != nil || len(byService) != 1 || byService[0].ID != st.ID {
		t.Fatalf("ListByService = %#v, %v", byService, err)
	}
	family, err := store.ListByRootTGT(ctx, tgt.ID)
	if err != nil || len(family) != 4 {
		t.Fatalf("ListByRootTGT = %d, %v, want 4", len(family), err)
	}
	deleted, err := store.DeleteByUser(ctx, tgt.UserID)
	if err != nil || deleted != 4 {
		t.Fatalf("DeleteByUser = %d, %v, want 4", deleted, err)
	}
	if store.Len() != 0 {
		t.Fatalf("Len after DeleteByUser = %d, want 0", store.Len())
	}
	for _, ticket := range []*Ticket{tgt, st} {
		if err := store.Save(ctx, ticket.Clone()); err != nil {
			t.Fatalf("re-Save(%s): %v", ticket.ID, err)
		}
	}
	deleted, err = store.DeleteByRootTGT(ctx, tgt.ID)
	if err != nil || deleted != 2 {
		t.Fatalf("DeleteByRootTGT = %d, %v, want 2", deleted, err)
	}
	if _, err := store.Get(ctx, tgt.ID); !errors.Is(err, ErrTicketNotFound) {
		t.Fatalf("Get deleted TGT error = %v", err)
	}
}

func TestMemoryTicketStoreDeleteExpiredAndJanitor(t *testing.T) {
	store := NewMemoryTicketStore()
	now := time.Date(2026, time.June, 1, 0, 0, 0, 0, time.UTC)
	if err := store.Save(context.Background(), testTicket(TicketST, "ST-expired", now.Add(-time.Hour), now.Add(-time.Minute))); err != nil {
		t.Fatalf("Save expired: %v", err)
	}
	if err := store.Save(context.Background(), testTicket(TicketST, "ST-live", now, now.Add(time.Hour))); err != nil {
		t.Fatalf("Save live: %v", err)
	}
	deleted, err := store.DeleteExpired(context.Background(), now)
	if err != nil || deleted != 1 {
		t.Fatalf("DeleteExpired = %d, %v, want 1", deleted, err)
	}
	running := NewMemoryTicketStore()
	running.SetClock(func() time.Time { return now })
	if err := running.Save(context.Background(), testTicket(TicketST, "ST-gc", now.Add(-time.Hour), now.Add(-time.Minute))); err != nil {
		t.Fatalf("Save gc: %v", err)
	}
	running.StartGC(2 * time.Millisecond)
	deadline := time.Now().Add(2 * time.Second)
	for running.Len() != 0 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if running.Len() != 0 {
		t.Fatalf("janitor did not remove the expired ticket")
	}
	running.Stop()
	running.Stop()
	if err := running.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func testTicket(typ TicketType, id string, issued, expires time.Time) *Ticket {
	return &Ticket{
		ID:         id,
		Type:       typ,
		UserID:     "user-1",
		Principal:  testPrincipal(),
		IssuedAt:   issued,
		ExpiresAt:  expires,
		RootTGTID:  id,
		RememberMe: false,
	}
}

func testPrincipal() *auth.Principal {
	return &auth.Principal{
		Subject:     "user-1",
		Username:    "alice",
		DisplayName: "Alice",
		Attributes: map[string]string{
			"email": "alice@example.com",
			"role":  "admin",
		},
	}
}
