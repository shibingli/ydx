package kms

import (
	"bytes"
	"context"
	"errors"
	"math"
	"strings"
	"sync"
	"testing"
	"time"
)

// testClock is a concurrency-safe mutable clock. | testClock 是并发安全的可变时钟。
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

// newTestClock returns a clock fixed at a deterministic instant. | newTestClock 返回固定在确定时刻的时钟。
func newTestClock() *testClock {
	return &testClock{now: time.Unix(1700000000, 0).UTC()}
}

// Now returns the current test time. | Now 返回当前测试时间。
func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the clock forward. | Advance 把时钟向前推进。
func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// newServiceForTest builds a Service over a fresh store and test clock. | newServiceForTest 在全新存储
// 与测试时钟上构建 Service。
func newServiceForTest(t *testing.T, config Config) (*Service, *testClock) {
	t.Helper()
	clock := newTestClock()
	if config.Store == nil {
		config.Store = NewMemoryStore()
	}
	if config.Clock == nil {
		config.Clock = clock.Now
	}
	service, err := New(config)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return service, clock
}

// createKeyForTest creates and optionally activates a key. | createKeyForTest 创建密钥并可选择激活。
func createKeyForTest(t *testing.T, service *Service, request CreateKeyRequest, activate bool) *Key {
	t.Helper()
	ctx := context.Background()
	key, err := service.CreateKey(ctx, request)
	if err != nil {
		t.Fatalf("CreateKey(%+v): %v", request, err)
	}
	if !activate {
		return key
	}
	key, err = service.Activate(ctx, key.ID)
	if err != nil {
		t.Fatalf("Activate(%s): %v", key.ID, err)
	}
	return key
}

func TestServiceLifecycle(t *testing.T) {
	ctx := context.Background()
	service, clock := newServiceForTest(t, Config{})
	key := createKeyForTest(t, service, CreateKeyRequest{Type: KeyTypeAES, Bits: 256, Alias: "orders"}, false)
	if key.State != StatePreActive {
		t.Fatalf("state = %s, want %s", key.State, StatePreActive)
	}
	if key.Material != nil || len(key.Versions) != 1 || key.Versions[0].Material != nil {
		t.Fatal("CreateKey leaked private material")
	}
	if _, err := service.Encrypt(ctx, key.ID, []byte("data"), nil); !errors.Is(err, ErrKeyNotUsable) {
		t.Fatalf("Encrypt before Activate err = %v, want ErrKeyNotUsable", err)
	}
	active, err := service.Activate(ctx, key.Alias)
	if err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if active.State != StateActive || !active.ActivatedAt.Equal(clock.Now()) {
		t.Fatalf("activated key = %+v", active)
	}
	if _, err := service.Activate(ctx, key.ID); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("double Activate err = %v, want ErrInvalidState", err)
	}
	plaintext := []byte("lifecycle secret")
	ciphertext, err := service.Encrypt(ctx, key.ID, plaintext, nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	deactivated, err := service.Deactivate(ctx, key.ID)
	if err != nil {
		t.Fatalf("Deactivate: %v", err)
	}
	if deactivated.State != StateDeactivated {
		t.Fatalf("state = %s, want deactivated", deactivated.State)
	}
	decrypted, err := service.Decrypt(ctx, key.ID, ciphertext, nil)
	if err != nil || !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("Decrypt after deactivation = %q, %v", decrypted, err)
	}
	if _, err := service.Encrypt(ctx, key.ID, plaintext, nil); !errors.Is(err, ErrKeyNotUsable) {
		t.Fatalf("Encrypt after deactivation err = %v, want ErrKeyNotUsable", err)
	}
	if _, err := service.Activate(ctx, key.ID); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("reactivate err = %v, want ErrInvalidState", err)
	}
	if _, err := service.Compromise(ctx, key.ID); err != nil {
		t.Fatalf("Compromise: %v", err)
	}
	if _, err := service.Decrypt(ctx, key.ID, ciphertext, nil); !errors.Is(err, ErrKeyNotUsable) {
		t.Fatalf("Decrypt after compromise err = %v, want ErrKeyNotUsable", err)
	}
	destroyed, err := service.Destroy(ctx, key.ID)
	if err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if destroyed.State != StateDestroyed {
		t.Fatalf("state = %s, want destroyed", destroyed.State)
	}
	raw, err := service.Store().GetKey(ctx, key.ID)
	if err != nil {
		t.Fatalf("GetKey raw: %v", err)
	}
	if len(raw.Material) != 0 || len(raw.PublicMaterial) != 0 || len(raw.Versions) != 1 || len(raw.Versions[0].Material) != 0 {
		t.Fatal("Destroy did not erase material")
	}
	events, err := service.ListAudit(ctx, AuditFilter{KeyID: key.ID})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	seen := make(map[string]bool)
	for _, event := range events {
		seen[event.Operation] = true
	}
	for _, operation := range []string{OperationKeyCreate, OperationKeyActivate, OperationKeyDeactivate, OperationKeyCompromise, OperationKeyDestroy, OperationEncrypt, OperationDecrypt} {
		if !seen[operation] {
			t.Errorf("missing audit operation %s in %+v", operation, seen)
		}
	}
}

func TestServiceLifecycleGuardsAndScheduledDeletion(t *testing.T) {
	ctx := context.Background()
	service, clock := newServiceForTest(t, Config{})
	active := createKeyForTest(t, service, CreateKeyRequest{Type: KeyTypeAES}, true)
	if _, err := service.Destroy(ctx, active.ID); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("Destroy(active) err = %v, want ErrInvalidState", err)
	}
	scheduled, err := service.ScheduleDelete(ctx, active.ID, time.Hour)
	if err != nil {
		t.Fatalf("ScheduleDelete: %v", err)
	}
	if scheduled.State != StatePendingDeletion || !scheduled.DeleteAfter.Equal(clock.Now().Add(time.Hour)) {
		t.Fatalf("scheduled key = %+v", scheduled)
	}
	if _, err := service.Encrypt(ctx, active.ID, []byte("x"), nil); !errors.Is(err, ErrKeyNotUsable) {
		t.Fatalf("Encrypt pending deletion err = %v", err)
	}
	if count, err := service.DestroyExpired(ctx, clock.Now()); err != nil || count != 0 {
		t.Fatalf("DestroyExpired early = %d, %v", count, err)
	}
	clock.Advance(time.Hour)
	if count, err := service.DestroyExpired(ctx, clock.Now()); err != nil || count != 1 {
		t.Fatalf("DestroyExpired due = %d, %v", count, err)
	}
	stored, err := service.GetKey(ctx, active.ID)
	if err != nil || stored.State != StateDestroyed {
		t.Fatalf("destroyed pending key = %+v, %v", stored, err)
	}

	preActive := createKeyForTest(t, service, CreateKeyRequest{Type: KeyTypeSM4}, false)
	if _, err := service.Destroy(ctx, preActive.ID); err != nil {
		t.Fatalf("Destroy(pre-active): %v", err)
	}
	if _, err := service.CreateKey(ctx, CreateKeyRequest{Type: KeyTypeAES, RotationInterval: -time.Second}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("negative rotation err = %v, want ErrInvalidRequest", err)
	}
}

func TestServiceAliasAndUpdate(t *testing.T) {
	ctx := context.Background()
	service, _ := newServiceForTest(t, Config{})
	first := createKeyForTest(t, service, CreateKeyRequest{Type: KeyTypeAES, Alias: "shared", Tags: []string{"b", "a", "a"}}, false)
	if _, err := service.CreateKey(ctx, CreateKeyRequest{Type: KeyTypeAES, Alias: "shared"}); !errors.Is(err, ErrAliasExists) {
		t.Fatalf("duplicate alias err = %v", err)
	}
	alias := "renamed"
	metadata := map[string]string{"team": "crypto"}
	tags := []string{"z", "a"}
	second, err := service.UpdateKey(ctx, first.ID, UpdateKeyRequest{Alias: &alias, Metadata: metadata, Tags: tags})
	if err != nil {
		t.Fatalf("UpdateKey: %v", err)
	}
	if second.Alias != alias || second.Metadata["team"] != "crypto" || strings.Join(second.Tags, ",") != "a,z" {
		t.Fatalf("updated key = %+v", second)
	}
	resolved, err := service.Resolve(ctx, alias)
	if err != nil || resolved.ID != first.ID {
		t.Fatalf("Resolve alias = %+v, %v", resolved, err)
	}
	empty := ""
	if _, err := service.UpdateKey(ctx, first.ID, UpdateKeyRequest{Alias: &empty}); err != nil {
		t.Fatalf("clear alias: %v", err)
	}
	if _, err := service.Resolve(ctx, alias); !errors.Is(err, ErrAliasNotFound) {
		t.Fatalf("Resolve cleared alias err = %v", err)
	}
	events, err := service.ListAudit(ctx, AuditFilter{Operation: OperationKeyUpdate, KeyID: first.ID})
	if err != nil || len(events) != 2 {
		t.Fatalf("update audit = %d, %v", len(events), err)
	}
}

func TestServiceRotationAndRotateAllDue(t *testing.T) {
	ctx := context.Background()
	service, clock := newServiceForTest(t, Config{})
	key := createKeyForTest(t, service, CreateKeyRequest{Type: KeyTypeAES, Bits: 256, RotationInterval: time.Hour}, true)
	oldCiphertext, err := service.Encrypt(ctx, key.ID, []byte("before rotation"), nil)
	if err != nil {
		t.Fatalf("Encrypt before rotation: %v", err)
	}
	rotated, err := service.Rotate(ctx, key.ID)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if rotated.Version != 2 {
		t.Fatalf("version = %d, want 2", rotated.Version)
	}
	versions, err := service.ListVersions(ctx, key.ID)
	if err != nil || len(versions) != 2 {
		t.Fatalf("ListVersions = %d, %v", len(versions), err)
	}
	if versions[0].Version != 1 || versions[0].State != StateDeactivated || versions[0].Material != nil {
		t.Fatalf("old version = %+v", versions[0])
	}
	decrypted, err := service.Decrypt(ctx, key.ID, oldCiphertext, nil)
	if err != nil || string(decrypted) != "before rotation" {
		t.Fatalf("Decrypt old ciphertext = %q, %v", decrypted, err)
	}
	newCiphertext, err := service.Encrypt(ctx, key.ID, []byte("after rotation"), nil)
	if err != nil {
		t.Fatalf("Encrypt after rotation: %v", err)
	}
	parsed, err := parseCipherEnvelope(cipherMagic, newCiphertext)
	if err != nil || parsed.version != 2 {
		t.Fatalf("parsed new ciphertext = %+v, %v", parsed, err)
	}
	clock.Advance(2 * time.Hour)
	rotatedCount, err := service.RotateAllDue(ctx, clock.Now())
	if err != nil || rotatedCount != 1 {
		t.Fatalf("RotateAllDue = %d, %v", rotatedCount, err)
	}
	current, err := service.GetKey(ctx, key.ID)
	if err != nil || current.Version != 3 {
		t.Fatalf("key after RotateAllDue = %+v, %v", current, err)
	}
	preActive := createKeyForTest(t, service, CreateKeyRequest{Type: KeyTypeAES}, false)
	if _, err := service.Rotate(ctx, preActive.ID); !errors.Is(err, ErrKeyNotUsable) {
		t.Fatalf("Rotate pre-active err = %v, want ErrKeyNotUsable", err)
	}
}

func TestServiceSigningSurvivesRotation(t *testing.T) {
	ctx := context.Background()
	service, _ := newServiceForTest(t, Config{})
	key := createKeyForTest(t, service, CreateKeyRequest{Type: KeyTypeECDSA, Bits: 256}, true)
	message := []byte("signed before rotation")
	signature, err := service.Sign(ctx, key.ID, message)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := service.Rotate(ctx, key.ID); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	valid, err := service.Verify(ctx, key.ID, message, signature)
	if err != nil || !valid {
		t.Fatalf("Verify old signature = %v, %v", valid, err)
	}
	valid, err = service.Verify(ctx, key.ID, []byte("different"), signature)
	if err != nil || valid {
		t.Fatalf("Verify tampered message = %v, %v", valid, err)
	}
}

func TestServiceAtRestWrapping(t *testing.T) {
	ctx := context.Background()
	root := &Key{Type: KeyTypeAES, Material: bytes.Repeat([]byte{7}, 32)}
	store := NewMemoryStore()
	service, err := New(Config{Store: store, RootKey: root, Clock: newTestClock().Now, ExportPolicy: ExportPolicy{AllowPrivate: true}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	key := createKeyForTest(t, service, CreateKeyRequest{Type: KeyTypeAES, Bits: 256, Exportable: true}, true)
	raw, err := store.GetKey(ctx, key.ID)
	if err != nil {
		t.Fatalf("raw GetKey: %v", err)
	}
	if !bytes.HasPrefix(raw.Material, atRestMagic) {
		t.Fatalf("stored material does not start with at-rest magic: %x", raw.Material)
	}
	if len(raw.Versions) != 1 || !bytes.HasPrefix(raw.Versions[0].Material, atRestMagic) {
		t.Fatal("stored version material is not wrapped")
	}
	plaintext := []byte("wrapped at rest")
	ciphertext, err := service.Encrypt(ctx, key.ID, plaintext, nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	decrypted, err := service.Decrypt(ctx, key.ID, ciphertext, nil)
	if err != nil || !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("Decrypt = %q, %v", decrypted, err)
	}
	exported, err := service.ExportKey(ctx, key.ID, ExportRequest{Format: ExportFormatRaw, Private: true})
	if err != nil {
		t.Fatalf("ExportKey private: %v", err)
	}
	if len(exported.Material) != 32 {
		t.Fatalf("exported material length = %d, want 32", len(exported.Material))
	}

	wrong := &Key{Type: KeyTypeAES, Material: bytes.Repeat([]byte{8}, 32)}
	wrongService, err := New(Config{Store: store, RootKey: wrong, Clock: newTestClock().Now})
	if err != nil {
		t.Fatalf("New wrong root: %v", err)
	}
	if _, err := wrongService.Decrypt(ctx, key.ID, ciphertext, nil); !errors.Is(err, ErrInvalidMaterial) {
		t.Fatalf("Decrypt with wrong root err = %v, want ErrInvalidMaterial", err)
	}

	passphraseService, err := New(Config{Store: NewMemoryStore(), Passphrase: "correct horse battery staple", Clock: newTestClock().Now})
	if err != nil {
		t.Fatalf("New passphrase: %v", err)
	}
	passKey := createKeyForTest(t, passphraseService, CreateKeyRequest{Type: KeyTypeChaCha20}, true)
	passCiphertext, err := passphraseService.Encrypt(ctx, passKey.ID, plaintext, nil)
	if err != nil {
		t.Fatalf("passphrase Encrypt: %v", err)
	}
	if out, err := passphraseService.Decrypt(ctx, passKey.ID, passCiphertext, nil); err != nil || !bytes.Equal(out, plaintext) {
		t.Fatalf("passphrase Decrypt = %q, %v", out, err)
	}
}

func TestServiceGenerateRandom(t *testing.T) {
	ctx := context.Background()
	service, _ := newServiceForTest(t, Config{})
	first, err := service.GenerateRandom(ctx, 32)
	if err != nil {
		t.Fatalf("GenerateRandom: %v", err)
	}
	second, err := service.GenerateRandom(ctx, 32)
	if err != nil {
		t.Fatalf("GenerateRandom second: %v", err)
	}
	if len(first) != 32 || bytes.Equal(first, second) {
		t.Fatal("random output is wrong length or repeated")
	}
	if _, err := service.GenerateRandom(ctx, 0); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("zero length err = %v", err)
	}
	if _, err := service.GenerateRandom(ctx, (1<<20)+1); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("oversize err = %v", err)
	}
	events, err := service.ListAudit(ctx, AuditFilter{Operation: OperationRandom, Outcome: OutcomeSuccess})
	if err != nil || len(events) != 2 {
		t.Fatalf("random audit = %d, %v", len(events), err)
	}
}

func TestServiceAuditActorAndDenial(t *testing.T) {
	ctx := WithActor(context.Background(), "alice")
	service, _ := newServiceForTest(t, Config{})
	key, err := service.CreateKey(ctx, CreateKeyRequest{Type: KeyTypeAES, Exportable: true})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	if _, err := service.Activate(ctx, key.ID); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if _, err := service.Encrypt(ctx, key.ID, []byte("audited"), []byte("aad")); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := service.ExportKey(ctx, key.ID, ExportRequest{Format: ExportFormatRaw, Private: true}); !errors.Is(err, ErrExportDenied) {
		t.Fatalf("ExportKey err = %v, want ErrExportDenied", err)
	}
	events, err := service.ListAudit(ctx, AuditFilter{Actor: "alice"})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if len(events) < 3 {
		t.Fatalf("actor audit events = %d, want >= 3", len(events))
	}
	denied := false
	for _, event := range events {
		if event.Actor != "alice" {
			t.Fatalf("event actor = %q", event.Actor)
		}
		if event.Operation == OperationKeyExport && event.Outcome == OutcomeDenied {
			denied = true
		}
		for key, value := range event.Detail {
			if strings.Contains(value, "audited") && key == "plaintext" {
				t.Fatal("audit leaked plaintext")
			}
		}
	}
	if !denied {
		t.Fatal("missing denied export audit event")
	}
}

// conflictOnceStore injects one optimistic-concurrency conflict. | conflictOnceStore 注入一次乐观并发冲突。
type conflictOnceStore struct {
	*MemoryStore
	conflictMu sync.Mutex
	remaining  int
}

// UpdateKey returns ErrConflict for the first remaining calls. | UpdateKey 在前 remaining 次调用返回 ErrConflict。
func (s *conflictOnceStore) UpdateKey(ctx context.Context, key *Key) error {
	s.conflictMu.Lock()
	if s.remaining > 0 {
		s.remaining--
		s.conflictMu.Unlock()
		return ErrConflict
	}
	s.conflictMu.Unlock()
	return s.MemoryStore.UpdateKey(ctx, key)
}

// alwaysConflictStore always rejects updates. | alwaysConflictStore 始终拒绝更新。
type alwaysConflictStore struct {
	*MemoryStore
}

// UpdateKey always returns ErrConflict. | UpdateKey 始终返回 ErrConflict。
func (s *alwaysConflictStore) UpdateKey(context.Context, *Key) error { return ErrConflict }

func TestServiceOptimisticConcurrencyRetry(t *testing.T) {
	ctx := context.Background()
	base := NewMemoryStore()
	store := &conflictOnceStore{MemoryStore: base, remaining: 1}
	service, err := New(Config{Store: store, Clock: newTestClock().Now})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	key := createKeyForTest(t, service, CreateKeyRequest{Type: KeyTypeAES}, false)
	alias := "after-retry"
	updated, err := service.UpdateKey(ctx, key.ID, UpdateKeyRequest{Alias: &alias})
	if err != nil {
		t.Fatalf("UpdateKey with retry: %v", err)
	}
	if updated.Alias != alias || updated.Revision != 2 {
		t.Fatalf("updated key = %+v", updated)
	}
	stored, err := base.GetKey(ctx, key.ID)
	if err != nil || stored.Alias != alias || stored.Revision != 2 {
		t.Fatalf("stored key = %+v, %v", stored, err)
	}

	blocked, err := New(Config{Store: &alwaysConflictStore{MemoryStore: base}, Clock: newTestClock().Now})
	if err != nil {
		t.Fatalf("New blocked: %v", err)
	}
	if _, err := blocked.UpdateKey(ctx, key.ID, UpdateKeyRequest{Alias: &alias}); !errors.Is(err, ErrConflict) {
		t.Fatalf("exhausted retry err = %v, want ErrConflict", err)
	}
	events, err := blocked.ListAudit(ctx, AuditFilter{Operation: OperationKeyUpdate, Outcome: OutcomeFailure})
	if err != nil || len(events) != 1 {
		t.Fatalf("failed update audit = %d, %v", len(events), err)
	}
}

func TestServiceConcurrentEncryption(t *testing.T) {
	ctx := context.Background()
	service, _ := newServiceForTest(t, Config{})
	key := createKeyForTest(t, service, CreateKeyRequest{Type: KeyTypeAES}, true)
	var wait sync.WaitGroup
	errsCh := make(chan error, 128)
	for worker := 0; worker < 8; worker++ {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			for i := 0; i < 16; i++ {
				plaintext := []byte{byte(worker), byte(i)}
				ciphertext, err := service.Encrypt(ctx, key.ID, plaintext, nil)
				if err != nil {
					errsCh <- err
					return
				}
				decrypted, err := service.Decrypt(ctx, key.ID, ciphertext, nil)
				if err != nil {
					errsCh <- err
					return
				}
				if !bytes.Equal(decrypted, plaintext) {
					errsCh <- errors.New("round trip mismatch")
					return
				}
				if _, err := service.GetKey(ctx, key.ID); err != nil {
					errsCh <- err
					return
				}
			}
		}(worker)
	}
	wait.Wait()
	close(errsCh)
	for err := range errsCh {
		t.Fatalf("concurrent operation: %v", err)
	}
}

// nonceHistoryKeys lists the nonce cache keys retained for keyID. | nonceHistoryKeys 列出 keyID
// 保留的 nonce 缓存键。
func nonceHistoryKeys(service *Service, keyID string) []string {
	var out []string
	prefix := keyID + "/"
	service.nonces.Range(func(key, _ any) bool {
		if name, ok := key.(string); ok && strings.HasPrefix(name, prefix) {
			out = append(out, name)
		}
		return true
	})
	return out
}

// TestServiceForgetsNonceHistoryAfterLifecycleTransitions keeps the per-version nonce caches bounded.
// | TestServiceForgetsNonceHistoryAfterLifecycleTransitions 保证按版本维护的 nonce 缓存有界。
func TestServiceForgetsNonceHistoryAfterLifecycleTransitions(t *testing.T) {
	ctx := context.Background()
	service, _ := newServiceForTest(t, Config{})
	encrypt := func(keyID string) {
		t.Helper()
		if _, err := service.Encrypt(ctx, keyID, []byte("payload"), nil); err != nil {
			t.Fatalf("Encrypt(%s): %v", keyID, err)
		}
	}

	rotated := createKeyForTest(t, service, CreateKeyRequest{Type: KeyTypeAES, Bits: 256}, true)
	encrypt(rotated.ID)
	if len(nonceHistoryKeys(service, rotated.ID)) == 0 {
		t.Fatal("expected a nonce cache before rotation")
	}
	if _, err := service.Rotate(ctx, rotated.ID); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if history := nonceHistoryKeys(service, rotated.ID); len(history) != 0 {
		t.Fatalf("nonce history after rotate = %v, want empty", history)
	}

	deactivated := createKeyForTest(t, service, CreateKeyRequest{Type: KeyTypeAES, Bits: 256}, true)
	encrypt(deactivated.ID)
	if _, err := service.Deactivate(ctx, deactivated.ID); err != nil {
		t.Fatalf("Deactivate: %v", err)
	}
	if history := nonceHistoryKeys(service, deactivated.ID); len(history) != 0 {
		t.Fatalf("nonce history after deactivate = %v, want empty", history)
	}

	compromised := createKeyForTest(t, service, CreateKeyRequest{Type: KeyTypeAES, Bits: 256}, true)
	encrypt(compromised.ID)
	if _, err := service.Compromise(ctx, compromised.ID); err != nil {
		t.Fatalf("Compromise: %v", err)
	}
	if history := nonceHistoryKeys(service, compromised.ID); len(history) != 0 {
		t.Fatalf("nonce history after compromise = %v, want empty", history)
	}

	scheduled := createKeyForTest(t, service, CreateKeyRequest{Type: KeyTypeAES, Bits: 256}, true)
	encrypt(scheduled.ID)
	if _, err := service.ScheduleDelete(ctx, scheduled.ID, time.Hour); err != nil {
		t.Fatalf("ScheduleDelete: %v", err)
	}
	if history := nonceHistoryKeys(service, scheduled.ID); len(history) != 0 {
		t.Fatalf("nonce history after schedule delete = %v, want empty", history)
	}

	destroyed := createKeyForTest(t, service, CreateKeyRequest{Type: KeyTypeAES, Bits: 256}, false)
	var nonce [gcmNonceSize]byte
	copy(nonce[:], []byte("0123456789ab"))
	if !service.rememberNonce(destroyed.ID, 1, nonce[:]) {
		t.Fatal("expected a fresh nonce")
	}
	if _, err := service.Destroy(ctx, destroyed.ID); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if history := nonceHistoryKeys(service, destroyed.ID); len(history) != 0 {
		t.Fatalf("nonce history after destroy = %v, want empty", history)
	}
}

// captureUpdateStore records keys passed while armed and then returns ErrConflict. |
// captureUpdateStore 在启用记录后记录传入的密钥并返回 ErrConflict。
type captureUpdateStore struct {
	*MemoryStore
	captureMu sync.Mutex
	captured  []*Key
	armed     bool
}

// arm makes later UpdateKey calls conflict and record their argument. | arm 让后续 UpdateKey 调用
// 冲突并记录参数。
func (s *captureUpdateStore) arm() {
	s.captureMu.Lock()
	s.captured = nil
	s.armed = true
	s.captureMu.Unlock()
}

// UpdateKey records key and returns ErrConflict while armed. | UpdateKey 在启用记录时记录 key 并返回 ErrConflict。
func (s *captureUpdateStore) UpdateKey(ctx context.Context, key *Key) error {
	s.captureMu.Lock()
	if !s.armed {
		s.captureMu.Unlock()
		return s.MemoryStore.UpdateKey(ctx, key)
	}
	s.captured = append(s.captured, key)
	s.captureMu.Unlock()
	return ErrConflict
}

// TestServiceRotateRejectsVersionSpaceExhaustion checks that a key at version math.MaxUint32 cannot
// wrap around and reuse version 1. | TestServiceRotateRejectsVersionSpaceExhaustion 校验版本号为
// math.MaxUint32 的密钥不会回绕并复用版本 1。
func TestServiceRotateRejectsVersionSpaceExhaustion(t *testing.T) {
	ctx := context.Background()
	service, _ := newServiceForTest(t, Config{})
	key := createKeyForTest(t, service, CreateKeyRequest{ID: "rotate-version-exhausted", Type: KeyTypeAES, Bits: 256}, true)
	stored, err := service.store.GetKey(ctx, key.ID)
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	stored.Version = math.MaxUint32
	if err := service.store.UpdateKey(ctx, stored); err != nil {
		t.Fatalf("UpdateKey: %v", err)
	}

	rotated, err := service.Rotate(ctx, key.ID)
	if !errors.Is(err, ErrInvalidState) {
		t.Fatalf("Rotate err = %v, want ErrInvalidState | Rotate 错误 = %v，期望 ErrInvalidState", err, err)
	}
	if rotated != nil {
		t.Fatalf("Rotate returned %+v, want nil", rotated)
	}
	stored, err = service.store.GetKey(ctx, key.ID)
	if err != nil {
		t.Fatalf("GetKey after Rotate: %v", err)
	}
	if stored.MaxVersion() != math.MaxUint32 || len(stored.Versions) != 1 {
		t.Fatalf("key changed after rejected rotation: maxVersion=%d versions=%d", stored.MaxVersion(), len(stored.Versions))
	}
}

// TestServiceRotateZeroizesAbandonedMaterial checks that failed rotation attempts erase key material.
// | TestServiceRotateZeroizesAbandonedMaterial 校验轮换失败时擦除密钥材料。
func TestServiceRotateZeroizesAbandonedMaterial(t *testing.T) {
	ctx := context.Background()
	store := &captureUpdateStore{MemoryStore: NewMemoryStore()}
	service, err := New(Config{Store: store, Clock: newTestClock().Now})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	key := createKeyForTest(t, service, CreateKeyRequest{Type: KeyTypeAES, Bits: 256}, true)
	store.arm()
	if _, err := service.Rotate(ctx, key.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("Rotate err = %v, want ErrConflict", err)
	}
	store.captureMu.Lock()
	captured := append([]*Key(nil), store.captured...)
	store.captureMu.Unlock()
	if len(captured) != mutationRetries {
		t.Fatalf("captured attempts = %d, want %d", len(captured), mutationRetries)
	}
	for attempt, failed := range captured {
		for _, material := range [][]byte{failed.Material, failed.PublicMaterial} {
			for _, b := range material {
				if b != 0 {
					t.Fatalf("attempt %d retained key material", attempt)
				}
			}
		}
		for _, version := range failed.Versions {
			for _, b := range version.Material {
				if b != 0 {
					t.Fatalf("attempt %d retained version material", attempt)
				}
			}
		}
	}
}
