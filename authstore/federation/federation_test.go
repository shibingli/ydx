package federation_test

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"

	authfederation "github.com/shibingli/ydx/auth/protocol/federation"
	federationstore "github.com/shibingli/ydx/authstore/federation"
)

// testContext is the background context shared by tests. | testContext 是测试共享的后台上下文。
var testContext = context.Background()

// newClient returns one independent go-redis client against server. | newClient 针对 server 返回一个
// 独立 go-redis 客户端。
func newClient(t *testing.T, server *miniredis.Miniredis) goredis.UniversalClient {
	t.Helper()
	client := goredis.NewClient(&goredis.Options{
		Addr:        server.Addr(),
		MaxRetries:  -1,
		DialTimeout: 500 * time.Millisecond,
	})
	t.Cleanup(func() {
		_ = client.Close()
	})
	return client
}

// newStoreOn creates one store on an existing server. | newStoreOn 在已有服务器上创建一个存储。
func newStoreOn(t *testing.T, server *miniredis.Miniredis, options federationstore.Options) *federationstore.Store {
	t.Helper()
	store, err := federationstore.New(newClient(t, server), options)
	if err != nil {
		t.Fatalf("new store: %v | 创建存储失败", err)
	}
	return store
}

// newPair returns two independent stores sharing one miniredis, modelling two application
// instances. | newPair 返回共享同一 miniredis 的两个独立存储，模拟两个应用实例。
func newPair(t *testing.T, options federationstore.Options) (*federationstore.Store, *federationstore.Store, *miniredis.Miniredis) {
	t.Helper()
	server := miniredis.RunT(t)
	return newStoreOn(t, server, options), newStoreOn(t, server, options), server
}

// stateKey returns the documented default-layout key for state. | stateKey 返回 state 在默认布局下
// 的文档化键。
func stateKey(state string) string {
	return "ydx:authstore:federation:{authstore:federation}:state:" + strconv.Itoa(len(state)) + ":" + state
}

// chooseStore alternates between two stores. | chooseStore 在两个存储之间交替。
func chooseStore(index int, first, second *federationstore.Store) *federationstore.Store {
	if index%2 == 0 {
		return first
	}
	return second
}

// TestNewValidation covers constructor validation, the default prefix and the default TTL.
// | TestNewValidation 覆盖构造校验、默认前缀与默认有效期。
func TestNewValidation(t *testing.T) {
	if federationstore.DefaultKeyPrefix != "ydx:authstore:federation:" {
		t.Fatalf("DefaultKeyPrefix = %q | 默认前缀不正确", federationstore.DefaultKeyPrefix)
	}
	if authfederation.DefaultStateTTL <= 0 {
		t.Fatalf("DefaultStateTTL = %v | 默认有效期非法", authfederation.DefaultStateTTL)
	}
	if _, err := federationstore.New(nil, federationstore.Options{}); !errors.Is(err, authfederation.ErrInvalidConfig) {
		t.Fatalf("nil client error = %v, want ErrInvalidConfig | nil 客户端错误不符", err)
	}
	server := miniredis.RunT(t)
	client := newClient(t, server)
	for _, prefix := range []string{"bad{prefix", "bad}prefix"} {
		if _, err := federationstore.New(client, federationstore.Options{KeyPrefix: prefix}); !errors.Is(err, authfederation.ErrInvalidConfig) {
			t.Fatalf("brace prefix %q error = %v, want ErrInvalidConfig | 花括号前缀错误不符", prefix, err)
		}
	}
	store, err := federationstore.New(client, federationstore.Options{})
	if err != nil {
		t.Fatalf("new store: %v | 创建存储失败", err)
	}
	if store == nil {
		t.Fatal("New returned a nil store | New 返回了空存储")
	}
	var _ authfederation.StateStore = store
}

// TestNewDoesNotDial verifies that New performs no network round trip.
// | TestNewDoesNotDial 验证 New 不进行网络往返。
func TestNewDoesNotDial(t *testing.T) {
	client := goredis.NewClient(&goredis.Options{
		Addr:        "127.0.0.1:1",
		MaxRetries:  -1,
		DialTimeout: 50 * time.Millisecond,
	})
	t.Cleanup(func() {
		_ = client.Close()
	})
	if _, err := federationstore.New(client, federationstore.Options{}); err != nil {
		t.Fatalf("New dialed: %v | New 不应连接网络", err)
	}
}

// TestSaveConsumeRoundTrip covers the full record shape, duplicate rejection, caller-side deep-copy
// isolation, UTC normalization and one-time consumption across two instances.
// | TestSaveConsumeRoundTrip 覆盖完整记录字段、重复拒绝、调用方隔离的深拷贝、UTC 规范化以及
// 跨两个实例的一次性消费。
func TestSaveConsumeRoundTrip(t *testing.T) {
	first, second, server := newPair(t, federationstore.Options{TTL: time.Minute})
	now := time.Now().UTC()
	zone := time.FixedZone("UTC+8", 8*60*60)
	record := &authfederation.StateRecord{
		State:       "state-1",
		Provider:    "provider-a",
		Nonce:       "nonce-a",
		Verifier:    "verifier-a",
		RedirectURL: "https://example.test/callback",
		CreatedAt:   now.Add(-time.Minute).In(zone),
		ExpiresAt:   now.Add(time.Hour).In(zone),
	}
	if err := first.Save(testContext, record); err != nil {
		t.Fatalf("save: %v | 保存失败", err)
	}
	if !server.Exists(stateKey("state-1")) {
		t.Fatal("saved key missing | 保存键不存在")
	}
	// Mutating the caller-owned record after Save must not alter stored state.
	// | 保存后修改调用方记录不得改变已存状态。
	record.Provider = "mutated"
	record.Nonce = "mutated"
	record.Verifier = "mutated"
	record.RedirectURL = "https://mutated.test"
	record.CreatedAt = now.Add(-time.Hour)
	record.ExpiresAt = now.Add(-time.Minute)

	duplicate := &authfederation.StateRecord{
		State:     "state-1",
		Provider:  "provider-b",
		ExpiresAt: now.Add(2 * time.Hour),
	}
	if err := second.Save(testContext, duplicate); !errors.Is(err, authfederation.ErrStateMismatch) {
		t.Fatalf("duplicate save error = %v, want ErrStateMismatch | 重复保存错误不符", err)
	}
	expiredDuplicate := &authfederation.StateRecord{
		State:     "state-1",
		Provider:  "provider-b",
		ExpiresAt: now.Add(-time.Minute),
	}
	if err := second.Save(testContext, expiredDuplicate); !errors.Is(err, authfederation.ErrStateMismatch) {
		t.Fatalf("expired duplicate error = %v, want ErrStateMismatch | 过期重复保存错误不符", err)
	}

	got, err := second.Consume(testContext, "state-1")
	if err != nil {
		t.Fatalf("consume: %v | 消费失败", err)
	}
	if got == record {
		t.Fatal("consume returned the caller record | 消费返回了调用方记录")
	}
	if got.State != "state-1" || got.Provider != "provider-a" || got.Nonce != "nonce-a" ||
		got.Verifier != "verifier-a" || got.RedirectURL != "https://example.test/callback" {
		t.Fatalf("record fields = %+v | 记录字段不符", got)
	}
	if got.CreatedAt.Location() != time.UTC || got.ExpiresAt.Location() != time.UTC {
		t.Fatalf("times are not UTC: %v, %v | 时间未规范化为 UTC", got.CreatedAt, got.ExpiresAt)
	}
	if !got.CreatedAt.Equal(now.Add(-time.Minute)) || !got.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("times changed: %v, %v | 时间被改变", got.CreatedAt, got.ExpiresAt)
	}
	if _, err := first.Consume(testContext, "state-1"); !errors.Is(err, authfederation.ErrStateMismatch) {
		t.Fatalf("second consume error = %v, want ErrStateMismatch | 二次消费错误不符", err)
	}
}

// TestSaveDerivesTimes covers default TTL derivation and zero CreatedAt handling.
// | TestSaveDerivesTimes 覆盖默认有效期推导与零值 CreatedAt 处理。
func TestSaveDerivesTimes(t *testing.T) {
	first, second, _ := newPair(t, federationstore.Options{TTL: 3 * time.Minute})
	before := time.Now().UTC()
	if err := first.Save(testContext, &authfederation.StateRecord{State: "defaults"}); err != nil {
		t.Fatalf("save defaults: %v | 保存默认记录失败", err)
	}
	after := time.Now().UTC()
	got, err := second.Consume(testContext, "defaults")
	if err != nil {
		t.Fatalf("consume defaults: %v | 消费默认记录失败", err)
	}
	if got.CreatedAt.Before(before.Add(-time.Second)) || got.CreatedAt.After(after.Add(time.Second)) {
		t.Fatalf("CreatedAt = %v, window %v..%v | CreatedAt 不在时间窗口", got.CreatedAt, before, after)
	}
	if got.CreatedAt.Location() != time.UTC || got.ExpiresAt.Location() != time.UTC {
		t.Fatalf("times are not UTC: %v, %v | 时间未规范化为 UTC", got.CreatedAt, got.ExpiresAt)
	}
	if got.ExpiresAt.Sub(got.CreatedAt) != 3*time.Minute {
		t.Fatalf("lifetime = %v, want 3m | 有效期不符", got.ExpiresAt.Sub(got.CreatedAt))
	}

	zone := time.FixedZone("UTC-5", -5*60*60)
	created := time.Now().Add(-time.Minute).In(zone)
	if err := first.Save(testContext, &authfederation.StateRecord{
		State:     "from-created",
		CreatedAt: created,
	}); err != nil {
		t.Fatalf("save from created: %v | 保存带创建时间记录失败", err)
	}
	got, err = second.Consume(testContext, "from-created")
	if err != nil {
		t.Fatalf("consume from created: %v | 消费带创建时间记录失败", err)
	}
	if !got.CreatedAt.Equal(created) || got.CreatedAt.Location() != time.UTC {
		t.Fatalf("CreatedAt = %v, want %v in UTC | CreatedAt 不符", got.CreatedAt, created)
	}
	if got.ExpiresAt.Sub(got.CreatedAt) != 3*time.Minute {
		t.Fatalf("lifetime = %v, want 3m | 有效期不符", got.ExpiresAt.Sub(got.CreatedAt))
	}
}

// TestDefaultStateTTL covers the package default TTL when Options.TTL is zero.
// | TestDefaultStateTTL 覆盖 Options.TTL 为零时的包默认有效期。
func TestDefaultStateTTL(t *testing.T) {
	first, second, _ := newPair(t, federationstore.Options{})
	if err := first.Save(testContext, &authfederation.StateRecord{State: "default-ttl"}); err != nil {
		t.Fatalf("save: %v | 保存失败", err)
	}
	got, err := second.Consume(testContext, "default-ttl")
	if err != nil {
		t.Fatalf("consume: %v | 消费失败", err)
	}
	if got.ExpiresAt.Sub(got.CreatedAt) != authfederation.DefaultStateTTL {
		t.Fatalf("lifetime = %v, want %v | 默认有效期不符", got.ExpiresAt.Sub(got.CreatedAt), authfederation.DefaultStateTTL)
	}
}

// TestExpiryLifecycle covers logical expiry with retained physical keys, expired Save rejection,
// replacement of an expired record and post-consume mismatch. | TestExpiryLifecycle 覆盖保留物理键
// 时的逻辑过期、过期保存拒绝、过期记录替换以及消费后的不匹配。
func TestExpiryLifecycle(t *testing.T) {
	first, second, server := newPair(t, federationstore.Options{TTL: time.Minute})
	now := time.Now().UTC()
	// ClockTTL keeps TIME, PEXPIREAT and key expiry on the same deterministic clock.
	// | ClockTTL 让 TIME、PEXPIREAT 与键过期使用同一确定性时钟。
	server.SetTime(now)
	server.ClockTTL(true)
	expiresAt := now.Add(time.Minute)
	if err := first.Save(testContext, &authfederation.StateRecord{
		State:     "consume-expired",
		Provider:  "old",
		ExpiresAt: expiresAt,
	}); err != nil {
		t.Fatalf("save consume-expired: %v | 保存待过期记录失败", err)
	}
	if err := first.Save(testContext, &authfederation.StateRecord{
		State:     "replace-expired",
		Provider:  "old",
		ExpiresAt: expiresAt,
	}); err != nil {
		t.Fatalf("save replace-expired: %v | 保存待替换记录失败", err)
	}
	server.SetTime(now.Add(2 * time.Minute))
	// The logical deadline passed but the physical key remains for classification.
	// | 逻辑期限已过，但物理键仍保留用于错误分类。
	if !server.Exists(stateKey("consume-expired")) {
		t.Fatal("expired key vanished before the retention window | 过期键在保留窗口前消失")
	}
	if _, err := second.Consume(testContext, "consume-expired"); !errors.Is(err, authfederation.ErrStateExpired) {
		t.Fatalf("expired consume error = %v, want ErrStateExpired | 过期消费错误不符", err)
	}
	if _, err := second.Consume(testContext, "consume-expired"); !errors.Is(err, authfederation.ErrStateMismatch) {
		t.Fatalf("consumed expired error = %v, want ErrStateMismatch | 消费后错误不符", err)
	}

	if err := first.Save(testContext, &authfederation.StateRecord{
		State:     "already-expired",
		ExpiresAt: now.Add(-time.Minute),
	}); !errors.Is(err, authfederation.ErrStateExpired) {
		t.Fatalf("expired save error = %v, want ErrStateExpired | 过期保存错误不符", err)
	}

	future := now.Add(10 * time.Minute)
	if err := second.Save(testContext, &authfederation.StateRecord{
		State:     "replace-expired",
		Provider:  "new",
		ExpiresAt: future,
	}); err != nil {
		t.Fatalf("replace expired save: %v | 替换过期记录失败", err)
	}
	got, err := first.Consume(testContext, "replace-expired")
	if err != nil {
		t.Fatalf("consume replaced: %v | 消费替换记录失败", err)
	}
	if got.Provider != "new" {
		t.Fatalf("Provider = %q, want new | 替换记录字段不符", got.Provider)
	}
}

// TestCleanupAfterRetention covers physical key removal at the logical deadline plus retention.
// | TestCleanupAfterRetention 覆盖逻辑期限加保留时长后的物理键删除。
func TestCleanupAfterRetention(t *testing.T) {
	first, _, server := newPair(t, federationstore.Options{TTL: time.Minute})
	now := time.Now().UTC()
	// ClockTTL keeps TIME, PEXPIREAT and key expiry on the same deterministic clock.
	// | ClockTTL 让 TIME、PEXPIREAT 与键过期使用同一确定性时钟。
	server.SetTime(now)
	server.ClockTTL(true)
	if err := first.Save(testContext, &authfederation.StateRecord{
		State:     "cleanup",
		ExpiresAt: now.Add(time.Minute),
	}); err != nil {
		t.Fatalf("save: %v | 保存失败", err)
	}
	server.SetTime(now.Add(7 * time.Minute))
	if server.Exists(stateKey("cleanup")) {
		t.Fatal("key survived the retention window | 键在保留窗口后仍存在")
	}
	if _, err := first.Consume(testContext, "cleanup"); !errors.Is(err, authfederation.ErrStateMismatch) {
		t.Fatalf("consume cleaned error = %v, want ErrStateMismatch | 清理后消费错误不符", err)
	}
}

// TestConsumeConcurrentExactlyOnce verifies that concurrent consumers on two instances produce
// exactly one success. | TestConsumeConcurrentExactlyOnce 验证两个实例的并发消费恰好一次成功。
func TestConsumeConcurrentExactlyOnce(t *testing.T) {
	first, second, _ := newPair(t, federationstore.Options{})
	if err := first.Save(testContext, &authfederation.StateRecord{
		State:     "concurrent-consume",
		Provider:  "provider",
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}); err != nil {
		t.Fatalf("save: %v | 保存失败", err)
	}
	const workers = 64
	var successes int64
	var mismatches int64
	var unexpected int64
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(store *federationstore.Store) {
			defer wg.Done()
			<-start
			record, err := store.Consume(testContext, "concurrent-consume")
			switch {
			case err == nil && record != nil:
				atomic.AddInt64(&successes, 1)
			case errors.Is(err, authfederation.ErrStateMismatch):
				atomic.AddInt64(&mismatches, 1)
			default:
				atomic.AddInt64(&unexpected, 1)
			}
		}(chooseStore(i, first, second))
	}
	close(start)
	wg.Wait()
	if successes != 1 || mismatches != workers-1 || unexpected != 0 {
		t.Fatalf("successes = %d, mismatches = %d, unexpected = %d | 并发消费计数不符", successes, mismatches, unexpected)
	}
}

// TestSaveConcurrentExactlyOnce verifies that concurrent duplicate saves produce exactly one
// success. | TestSaveConcurrentExactlyOnce 验证并发重复保存恰好一次成功。
func TestSaveConcurrentExactlyOnce(t *testing.T) {
	first, second, _ := newPair(t, federationstore.Options{})
	expiresAt := time.Now().UTC().Add(time.Hour)
	const workers = 64
	var successes int64
	var mismatches int64
	var unexpected int64
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(store *federationstore.Store) {
			defer wg.Done()
			<-start
			err := store.Save(testContext, &authfederation.StateRecord{
				State:     "concurrent-save",
				Provider:  "provider",
				ExpiresAt: expiresAt,
			})
			switch {
			case err == nil:
				atomic.AddInt64(&successes, 1)
			case errors.Is(err, authfederation.ErrStateMismatch):
				atomic.AddInt64(&mismatches, 1)
			default:
				atomic.AddInt64(&unexpected, 1)
			}
		}(chooseStore(i, first, second))
	}
	close(start)
	wg.Wait()
	if successes != 1 || mismatches != workers-1 || unexpected != 0 {
		t.Fatalf("successes = %d, mismatches = %d, unexpected = %d | 并发保存计数不符", successes, mismatches, unexpected)
	}
}

// TestPrefixAndSegmentIsolation covers namespace isolation and length-prefixed arbitrary values.
// | TestPrefixAndSegmentIsolation 覆盖命名空间隔离与长度前缀的任意值。
func TestPrefixAndSegmentIsolation(t *testing.T) {
	server := miniredis.RunT(t)
	first := newStoreOn(t, server, federationstore.Options{KeyPrefix: "tenant-a:"})
	second := newStoreOn(t, server, federationstore.Options{KeyPrefix: "tenant-b:"})
	expiresAt := time.Now().UTC().Add(time.Hour)
	if err := first.Save(testContext, &authfederation.StateRecord{
		State: "shared", Provider: "tenant-a", ExpiresAt: expiresAt,
	}); err != nil {
		t.Fatalf("save tenant-a: %v | 保存租户 A 失败", err)
	}
	if err := second.Save(testContext, &authfederation.StateRecord{
		State: "shared", Provider: "tenant-b", ExpiresAt: expiresAt,
	}); err != nil {
		t.Fatalf("save tenant-b: %v | 保存租户 B 失败", err)
	}
	gotA, err := first.Consume(testContext, "shared")
	if err != nil || gotA.Provider != "tenant-a" {
		t.Fatalf("consume tenant-a = %+v, %v | 消费租户 A 不符", gotA, err)
	}
	gotB, err := second.Consume(testContext, "shared")
	if err != nil || gotB.Provider != "tenant-b" {
		t.Fatalf("consume tenant-b = %+v, %v | 消费租户 B 不符", gotB, err)
	}

	for _, state := range []string{"a", "a:b", "a:3:b", "with{brace}", "长度"} {
		if err := first.Save(testContext, &authfederation.StateRecord{
			State: state, Provider: state, ExpiresAt: expiresAt,
		}); err != nil {
			t.Fatalf("save %q: %v | 保存 state 失败", state, err)
		}
		got, consumeErr := first.Consume(testContext, state)
		if consumeErr != nil || got.Provider != state {
			t.Fatalf("consume %q = %+v, %v | 消费 state 不符", state, got, consumeErr)
		}
	}
}

// TestErrors covers nil receivers, invalid input, canceled contexts, closed backends, corrupt
// records and the guarantee that errors never embed addresses or record contents.
// | TestErrors 覆盖 nil 接收者、非法输入、取消上下文、关闭后端、损坏记录，以及错误绝不嵌入地址
// 或记录内容的保证。
func TestErrors(t *testing.T) {
	var nilStore *federationstore.Store
	if err := nilStore.Save(testContext, &authfederation.StateRecord{State: "x"}); !errors.Is(err, authfederation.ErrInvalidConfig) {
		t.Fatalf("nil save error = %v, want ErrInvalidConfig | nil 保存错误不符", err)
	}
	if _, err := nilStore.Consume(testContext, "x"); !errors.Is(err, authfederation.ErrInvalidConfig) {
		t.Fatalf("nil consume error = %v, want ErrInvalidConfig | nil 消费错误不符", err)
	}

	first, _, server := newPair(t, federationstore.Options{})
	if err := first.Save(testContext, nil); !errors.Is(err, authfederation.ErrStateMismatch) {
		t.Fatalf("nil record error = %v, want ErrStateMismatch | nil 记录错误不符", err)
	}
	if err := first.Save(testContext, &authfederation.StateRecord{}); !errors.Is(err, authfederation.ErrStateMismatch) {
		t.Fatalf("empty state error = %v, want ErrStateMismatch | 空 state 错误不符", err)
	}
	if _, err := first.Consume(testContext, ""); !errors.Is(err, authfederation.ErrStateMismatch) {
		t.Fatalf("empty consume error = %v, want ErrStateMismatch | 空消费错误不符", err)
	}

	ctx, cancel := context.WithCancel(testContext)
	cancel()
	if err := first.Save(ctx, &authfederation.StateRecord{
		State: "canceled", ExpiresAt: time.Now().UTC().Add(time.Hour),
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled save error = %v, want context.Canceled | 取消保存错误不符", err)
	}
	if _, err := first.Consume(ctx, "canceled"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled consume error = %v, want context.Canceled | 取消消费错误不符", err)
	}
	// Context cancellation takes precedence over record validation, matching MemoryStateStore.
	// | 上下文取消优先于记录校验，与 MemoryStateStore 一致。
	if err := first.Save(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled nil save error = %v, want context.Canceled | 取消 nil 保存错误不符", err)
	}
	if _, err := first.Consume(ctx, ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled empty consume error = %v, want context.Canceled | 取消空消费错误不符", err)
	}

	address := server.Addr()
	server.Close()
	err := first.Save(testContext, &authfederation.StateRecord{
		State:     "closed-secret-state",
		Provider:  "closed-secret-provider",
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	})
	if !errors.Is(err, federationstore.ErrStoreUnavailable) {
		t.Fatalf("closed save error = %v, want ErrStoreUnavailable | 关闭保存错误不符", err)
	}
	for _, leaked := range []string{address, "closed-secret-state", "closed-secret-provider"} {
		if strings.Contains(err.Error(), leaked) {
			t.Fatalf("save error leaked %q: %v | 保存错误泄露内容", leaked, err)
		}
	}
	_, err = first.Consume(testContext, "closed-secret-state")
	if !errors.Is(err, federationstore.ErrStoreUnavailable) {
		t.Fatalf("closed consume error = %v, want ErrStoreUnavailable | 关闭消费错误不符", err)
	}
	if strings.Contains(err.Error(), address) || strings.Contains(err.Error(), "closed-secret-state") {
		t.Fatalf("consume error leaked content: %v | 消费错误泄露内容", err)
	}
}

// TestCorruptRecord covers malformed stored JSON and ensures the corrupt key is removed.
// | TestCorruptRecord 覆盖存储 JSON 损坏，并确保损坏键被删除。
func TestCorruptRecord(t *testing.T) {
	server := miniredis.RunT(t)
	client := newClient(t, server)
	store, err := federationstore.New(client, federationstore.Options{})
	if err != nil {
		t.Fatalf("new store: %v | 创建存储失败", err)
	}
	expireSec := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	key := stateKey("corrupt")
	if err := client.HSet(testContext, key,
		"data", "{not-json",
		"expSec", expireSec,
		"expNsec", "0",
	).Err(); err != nil {
		t.Fatalf("seed corrupt record: %v | 写入损坏记录失败", err)
	}
	if _, err := store.Consume(testContext, "corrupt"); !errors.Is(err, federationstore.ErrStoreUnavailable) {
		t.Fatalf("corrupt consume error = %v, want ErrStoreUnavailable | 损坏记录错误不符", err)
	}
	if server.Exists(key) {
		t.Fatal("corrupt key was not removed | 损坏键未被删除")
	}
}
