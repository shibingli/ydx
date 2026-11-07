package webauthn

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func testCredential(t *testing.T, signer testSigner, id, userID string, createdAt time.Time) *Credential {
	t.Helper()
	return &Credential{
		ID:              []byte(id),
		UserID:          userID,
		Username:        userID,
		UserDisplayName: userID,
		UserHandle:      []byte(userID),
		PublicKey:       signer.coseKey(t),
		Transports:      []string{"internal", "hybrid", "internal", "bad token"},
		CreatedAt:       createdAt,
	}
}

func TestMemoryChallengeStorePutConsume(t *testing.T) {
	store := NewMemoryChallengeStoreWithClock(func() time.Time { return testNow })
	ceremony := &Ceremony{
		ID:        "ceremony-id",
		Kind:      CeremonyRegistration,
		Challenge: []byte("challenge-value"),
		RPID:      testRPID,
		Origins:   []string{testOrigin},
		CreatedAt: testNow,
		ExpiresAt: testNow.Add(time.Minute),
	}
	if err := store.Put(context.Background(), ceremony); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if store.Len() != 1 {
		t.Fatalf("Len = %d", store.Len())
	}
	ceremony.Challenge[0] ^= 0xff
	ceremony.Origins[0] = "https://mutated.test"

	key := b64([]byte("challenge-value"))
	got, err := store.Consume(context.Background(), key)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if string(got.Challenge) != "challenge-value" {
		t.Fatalf("stored ceremony was not deep-copied: %q", got.Challenge)
	}
	if got.Origins[0] != testOrigin {
		t.Fatalf("stored origins were not deep-copied: %v", got.Origins)
	}
	if store.Len() != 0 {
		t.Fatalf("Len after Consume = %d", store.Len())
	}
	if _, err := store.Consume(context.Background(), key); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("second Consume error = %v, want ErrChallengeNotFound", err)
	}
}

func TestMemoryChallengeStoreExpiry(t *testing.T) {
	now := testNow
	store := NewMemoryChallengeStoreWithClock(func() time.Time { return now })
	ceremony := &Ceremony{Challenge: []byte("expiring"), ExpiresAt: testNow.Add(time.Minute)}
	if err := store.Put(context.Background(), ceremony); err != nil {
		t.Fatalf("Put: %v", err)
	}
	now = testNow.Add(2 * time.Minute)
	if _, err := store.Consume(context.Background(), b64(ceremony.Challenge)); !errors.Is(err, ErrChallengeExpired) {
		t.Fatalf("expired Consume error = %v, want ErrChallengeExpired", err)
	}
	if store.Len() != 0 {
		t.Fatalf("expired entry was not removed: Len = %d", store.Len())
	}
}

func TestMemoryChallengeStoreInvalidInput(t *testing.T) {
	store := NewMemoryChallengeStoreWithClock(func() time.Time { return testNow })
	if err := store.Put(context.Background(), nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil ceremony error = %v", err)
	}
	if err := store.Put(context.Background(), &Ceremony{}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("empty challenge error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := store.Put(ctx, &Ceremony{Challenge: []byte("x")}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Put error = %v", err)
	}
	if _, err := store.Consume(ctx, "x"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Consume error = %v", err)
	}
}

func TestMemoryChallengeStoreConcurrentConsume(t *testing.T) {
	store := NewMemoryChallengeStoreWithClock(func() time.Time { return testNow })
	ceremony := &Ceremony{Challenge: []byte("race-challenge"), ExpiresAt: testNow.Add(time.Minute)}
	if err := store.Put(context.Background(), ceremony); err != nil {
		t.Fatalf("Put: %v", err)
	}
	const workers = 16
	var wg sync.WaitGroup
	results := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.Consume(context.Background(), b64(ceremony.Challenge))
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
			continue
		}
		if !errors.Is(err, ErrChallengeNotFound) {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("Consume succeeded %d times", successes)
	}
}

func TestMemoryCredentialStore(t *testing.T) {
	store := NewMemoryCredentialStore()
	signer := newECSigner(t)
	ctx := context.Background()
	credential := testCredential(t, signer, "credential-1", "user-1", testNow)
	if err := store.Save(ctx, credential); err != nil {
		t.Fatalf("Save: %v", err)
	}
	stored, err := store.GetByCredentialID(ctx, credential.ID)
	if err != nil {
		t.Fatalf("GetByCredentialID: %v", err)
	}
	if stored.UserID != "user-1" || stored.PublicKey.Alg != AlgES256 {
		t.Fatalf("stored = %#v", stored)
	}
	if len(stored.Transports) != 4 || stored.Transports[0] != "internal" {
		t.Fatalf("transports were not preserved: %v", stored.Transports)
	}

	stored.PublicKey.X[0] ^= 0xff
	stored.ID[0] ^= 0xff
	stored.Transports[0] = "usb"
	again, err := store.GetByCredentialID(ctx, credential.ID)
	if err != nil {
		t.Fatalf("GetByCredentialID: %v", err)
	}
	if again.PublicKey.X[0] == stored.PublicKey.X[0] {
		t.Fatal("stored credential shares the COSE key with the caller")
	}
	if string(again.ID) != "credential-1" || again.Transports[0] != "internal" {
		t.Fatalf("stored credential was mutated through a returned value: %#v", again)
	}

	if err := store.Save(ctx, credential); !errors.Is(err, ErrCredentialExists) {
		t.Fatalf("duplicate Save error = %v, want ErrCredentialExists", err)
	}
	if _, err := store.GetByCredentialID(ctx, []byte("missing")); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("missing credential error = %v", err)
	}
	if err := store.UpdateSignCount(ctx, credential.ID, 9); err != nil {
		t.Fatalf("UpdateSignCount: %v", err)
	}
	updated, err := store.GetByCredentialID(ctx, credential.ID)
	if err != nil {
		t.Fatalf("GetByCredentialID: %v", err)
	}
	if updated.SignCount != 9 {
		t.Fatalf("sign count = %d", updated.SignCount)
	}
	if err := store.UpdateSignCount(ctx, []byte("missing"), 1); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("missing UpdateSignCount error = %v", err)
	}
}

func TestMemoryCredentialStoreListByUser(t *testing.T) {
	store := NewMemoryCredentialStore()
	signer := newECSigner(t)
	ctx := context.Background()
	inputs := []*Credential{
		testCredential(t, signer, "c-late", "user-1", testNow.Add(time.Minute)),
		testCredential(t, signer, "c-b", "user-1", testNow),
		testCredential(t, signer, "c-a", "user-1", testNow),
		testCredential(t, signer, "c-other", "user-2", testNow),
	}
	for _, credential := range inputs {
		if err := store.Save(ctx, credential); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}
	list, err := store.ListByUser(ctx, "user-1")
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("ListByUser returned %d credentials", len(list))
	}
	want := []string{"c-a", "c-b", "c-late"}
	for i := range want {
		if string(list[i].ID) != want[i] {
			t.Fatalf("ListByUser order = %v", []string{string(list[0].ID), string(list[1].ID), string(list[2].ID)})
		}
	}
	empty, err := store.ListByUser(ctx, "nobody")
	if err != nil {
		t.Fatalf("ListByUser(nobody): %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("ListByUser(nobody) = %v", empty)
	}
}

func TestMemoryCredentialStoreValidation(t *testing.T) {
	store := NewMemoryCredentialStore()
	signer := newECSigner(t)
	ctx := context.Background()
	valid := testCredential(t, signer, "id", "user", testNow)
	cases := []struct {
		name       string
		credential *Credential
	}{
		{name: "nil", credential: nil},
		{name: "empty ID", credential: &Credential{UserID: "user", PublicKey: signer.coseKey(t)}},
		{name: "empty user", credential: &Credential{ID: []byte("id"), PublicKey: signer.coseKey(t)}},
		{name: "nil key", credential: &Credential{ID: []byte("id"), UserID: "user"}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if err := store.Save(ctx, test.credential); !errors.Is(err, ErrInvalidCredential) {
				t.Fatalf("error = %v, want ErrInvalidCredential", err)
			}
		})
	}
	valid.PublicKey.X = nil
	if err := store.Save(ctx, valid); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("invalid COSE key error = %v", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := store.Save(canceled, testCredential(t, signer, "id", "user", testNow)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Save error = %v", err)
	}
	if _, err := store.GetByCredentialID(canceled, []byte("id")); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled GetByCredentialID error = %v", err)
	}
	if err := store.UpdateSignCount(canceled, []byte("id"), 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled UpdateSignCount error = %v", err)
	}
	if _, err := store.ListByUser(canceled, "user"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled ListByUser error = %v", err)
	}
}
