package oidc_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"

	"github.com/shibingli/ydx/auth"
	authoidc "github.com/shibingli/ydx/auth/protocol/oidc"
	oidcstore "github.com/shibingli/ydx/authstore/oidc"
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
func newStoreOn(t *testing.T, server *miniredis.Miniredis, options oidcstore.Options) *oidcstore.Store {
	t.Helper()
	store, err := oidcstore.New(newClient(t, server), options)
	if err != nil {
		t.Fatalf("new store: %v | 创建存储失败", err)
	}
	return store
}

// newPair returns two independent stores sharing one miniredis, modelling two application
// instances. | newPair 返回共享同一 miniredis 的两个独立存储，模拟两个应用实例。
func newPair(t *testing.T, options oidcstore.Options) (*oidcstore.Store, *oidcstore.Store, *miniredis.Miniredis) {
	t.Helper()
	server := miniredis.RunT(t)
	return newStoreOn(t, server, options), newStoreOn(t, server, options), server
}

// TestNewValidation covers constructor validation and the default prefix.
// | TestNewValidation 覆盖构造校验与默认前缀。
func TestNewValidation(t *testing.T) {
	if oidcstore.DefaultKeyPrefix != "ydx:authstore:oidc:" {
		t.Fatalf("DefaultKeyPrefix = %q | 默认前缀不正确", oidcstore.DefaultKeyPrefix)
	}
	if _, err := oidcstore.New(nil, oidcstore.Options{}); !errors.Is(err, auth.ErrInvalidConfig) {
		t.Fatalf("nil client error = %v, want ErrInvalidConfig | nil 客户端错误不符", err)
	}
	server := miniredis.RunT(t)
	client := newClient(t, server)
	for _, prefix := range []string{"bad{prefix", "bad}prefix"} {
		if _, err := oidcstore.New(client, oidcstore.Options{KeyPrefix: prefix}); !errors.Is(err, auth.ErrInvalidConfig) {
			t.Fatalf("brace prefix %q error = %v, want ErrInvalidConfig | 花括号前缀错误不符", prefix, err)
		}
	}
	store, err := oidcstore.New(client, oidcstore.Options{})
	if err != nil {
		t.Fatalf("new store: %v | 创建存储失败", err)
	}
	if store == nil {
		t.Fatal("New returned a nil store | New 返回了空存储")
	}
	var _ authoidc.LogoutReplayStore = store
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
	if _, err := oidcstore.New(client, oidcstore.Options{}); err != nil {
		t.Fatalf("New dialed: %v | New 不应连接网络", err)
	}
}

// TestAcceptSingleUseAcrossInstances covers freshness, replay rejection, empty input, nil receivers
// and the in-memory fallback deadline. | TestAcceptSingleUseAcrossInstances 覆盖新鲜标识、重放拒绝、
// 空输入、nil 接收者与内存存储一致的期限回退。
func TestAcceptSingleUseAcrossInstances(t *testing.T) {
	first, second, _ := newPair(t, oidcstore.Options{})
	expiresAt := time.Now().UTC().Add(time.Hour)

	fresh, err := first.Accept(testContext, "jti-1", expiresAt)
	if err != nil || !fresh {
		t.Fatalf("first accept = %v, %v; want fresh | 首次接受不符", fresh, err)
	}
	fresh, err = second.Accept(testContext, "jti-1", expiresAt.Add(time.Minute))
	if err != nil || fresh {
		t.Fatalf("replay accept = %v, %v; want replay | 重放接受不符", fresh, err)
	}
	fresh, err = first.Accept(testContext, "jti-1", expiresAt)
	if err != nil || fresh {
		t.Fatalf("local replay accept = %v, %v; want replay | 本地重放接受不符", fresh, err)
	}

	if _, err := first.Accept(testContext, "", expiresAt); !errors.Is(err, authoidc.ErrInvalidToken) {
		t.Fatalf("empty jti error = %v, want ErrInvalidToken | 空 jti 错误不符", err)
	}
	var nilStore *oidcstore.Store
	if _, err := nilStore.Accept(testContext, "jti", expiresAt); !errors.Is(err, authoidc.ErrInvalidToken) {
		t.Fatalf("nil store error = %v, want ErrInvalidToken | nil 存储错误不符", err)
	}

	fresh, err = first.Accept(testContext, "fallback-zero", time.Time{})
	if err != nil || !fresh {
		t.Fatalf("zero deadline accept = %v, %v; want fresh | 零期限接受不符", fresh, err)
	}
	fresh, err = second.Accept(testContext, "fallback-zero", time.Time{})
	if err != nil || fresh {
		t.Fatalf("zero deadline replay = %v, %v; want replay | 零期限重放不符", fresh, err)
	}
	fresh, err = first.Accept(testContext, "fallback-past", time.Now().Add(-time.Minute))
	if err != nil || !fresh {
		t.Fatalf("past deadline accept = %v, %v; want fresh | 过去期限接受不符", fresh, err)
	}
}

// TestAcceptExpiryAndCleanup covers key expiry, acceptance after expiry and the length-prefixed
// encoding of arbitrary identifiers. | TestAcceptExpiryAndCleanup 覆盖键过期、过期后重新接受以及
// 任意标识的长度前缀编码。
func TestAcceptExpiryAndCleanup(t *testing.T) {
	first, second, server := newPair(t, oidcstore.Options{})
	base := time.Now().UTC()
	// ClockTTL keeps TIME, PEXPIREAT and key expiry on the same deterministic clock.
	// | ClockTTL 让 TIME、PEXPIREAT 与键过期使用同一确定性时钟。
	server.SetTime(base)
	server.ClockTTL(true)
	firstDeadline := base.Add(time.Hour)
	if fresh, err := first.Accept(testContext, "jti", firstDeadline); err != nil || !fresh {
		t.Fatalf("accept = %v, %v | 接受失败", fresh, err)
	}
	server.SetTime(base.Add(2 * time.Hour))
	// The key carried an exact deadline, so Redis removed it.
	// | 键携带精确期限，因此 Redis 已将其删除。
	if server.Exists("ydx:authstore:oidc:{authstore:oidc}:replay:3:jti") {
		t.Fatal("expired replay key still exists | 过期重放键仍然存在")
	}
	secondDeadline := base.Add(4 * time.Hour)
	if fresh, err := second.Accept(testContext, "jti", secondDeadline); err != nil || !fresh {
		t.Fatalf("accept after expiry = %v, %v; want fresh | 过期后接受不符", fresh, err)
	}
	if fresh, err := first.Accept(testContext, "jti", secondDeadline); err != nil || fresh {
		t.Fatalf("accept after reinsert = %v, %v; want replay | 重新写入后接受不符", fresh, err)
	}

	for _, jti := range []string{"a", "a:b", "a:3:b", "contains{braces}", "长度"} {
		if fresh, err := first.Accept(testContext, jti, secondDeadline); err != nil || !fresh {
			t.Fatalf("accept %q = %v, %v | 接受标识失败", jti, fresh, err)
		}
	}
}

// TestAcceptRedisClockFallback verifies that a deadline already elapsed at the Redis clock is
// replaced with a Redis-clock fallback, so application clock skew cannot admit a replay.
// | TestAcceptRedisClockFallback 验证在 Redis 时钟下已过去的期限会被 Redis 时钟回退替换，因此
// 应用时钟偏差不会放行重放。
func TestAcceptRedisClockFallback(t *testing.T) {
	first, second, server := newPair(t, oidcstore.Options{})
	localNow := time.Now().UTC()
	redisNow := localNow.Add(24 * time.Hour)
	server.SetTime(redisNow)
	expiresAt := localNow.Add(time.Hour)
	if fresh, err := first.Accept(testContext, "skewed-jti", expiresAt); err != nil || !fresh {
		t.Fatalf("skewed accept = %v, %v; want fresh | 时钟偏差接受不符", fresh, err)
	}
	if fresh, err := second.Accept(testContext, "skewed-jti", expiresAt); err != nil || fresh {
		t.Fatalf("skewed replay = %v, %v; want replay | 时钟偏差重放不符", fresh, err)
	}
	// Move Redis beyond the fallback window; the identifier is fresh again.
	// | 将 Redis 移过回退窗口后，该标识再次变为新鲜。
	server.SetTime(redisNow.Add(6 * time.Minute))
	if fresh, err := first.Accept(testContext, "skewed-jti", expiresAt); err != nil || !fresh {
		t.Fatalf("post-fallback accept = %v, %v; want fresh | 回退窗口后接受不符", fresh, err)
	}
}

// TestAcceptPrefixIsolation verifies that stores with different prefixes do not share replay state.
// | TestAcceptPrefixIsolation 验证不同前缀的存储不共享重放状态。
func TestAcceptPrefixIsolation(t *testing.T) {
	server := miniredis.RunT(t)
	first := newStoreOn(t, server, oidcstore.Options{KeyPrefix: "tenant-a:"})
	second := newStoreOn(t, server, oidcstore.Options{KeyPrefix: "tenant-b:"})
	expiresAt := time.Now().UTC().Add(time.Hour)
	if fresh, err := first.Accept(testContext, "shared-jti", expiresAt); err != nil || !fresh {
		t.Fatalf("tenant-a accept = %v, %v | 租户 A 接受失败", fresh, err)
	}
	if fresh, err := second.Accept(testContext, "shared-jti", expiresAt); err != nil || !fresh {
		t.Fatalf("tenant-b accept = %v, %v | 租户 B 接受失败", fresh, err)
	}
	if fresh, err := first.Accept(testContext, "shared-jti", expiresAt); err != nil || fresh {
		t.Fatalf("tenant-a replay = %v, %v | 租户 A 重放不符", fresh, err)
	}
}

// TestAcceptConcurrentExactlyOnce verifies that concurrent calls from two instances produce exactly
// one fresh result. | TestAcceptConcurrentExactlyOnce 验证两个实例的并发调用恰好产生一次新鲜结果。
func TestAcceptConcurrentExactlyOnce(t *testing.T) {
	first, second, _ := newPair(t, oidcstore.Options{})
	expiresAt := time.Now().UTC().Add(time.Hour)
	const workers = 64
	var freshCount int64
	var unexpected int64
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(store *oidcstore.Store) {
			defer wg.Done()
			<-start
			fresh, err := store.Accept(testContext, "concurrent-jti", expiresAt)
			if err != nil {
				atomic.AddInt64(&unexpected, 1)
				return
			}
			if fresh {
				atomic.AddInt64(&freshCount, 1)
			}
		}(chooseStore(i, first, second))
	}
	close(start)
	wg.Wait()
	if freshCount != 1 || unexpected != 0 {
		t.Fatalf("fresh = %d, errors = %d; want exactly one fresh and no errors | 新鲜次数或错误数不符", freshCount, unexpected)
	}
}

// chooseStore alternates between two stores. | chooseStore 在两个存储之间交替。
func chooseStore(index int, first, second *oidcstore.Store) *oidcstore.Store {
	if index%2 == 0 {
		return first
	}
	return second
}

// TestAcceptContextAndBackendErrors covers canceled contexts, closed backends and the guarantee that
// backend errors never embed the Redis address. | TestAcceptContextAndBackendErrors 覆盖取消上下文、
// 已关闭后端，以及后端错误绝不嵌入 Redis 地址的保证。
func TestAcceptContextAndBackendErrors(t *testing.T) {
	first, _, server := newPair(t, oidcstore.Options{})
	expiresAt := time.Now().UTC().Add(time.Hour)
	ctx, cancel := context.WithCancel(testContext)
	cancel()
	if fresh, err := first.Accept(ctx, "canceled-jti", expiresAt); !errors.Is(err, context.Canceled) || fresh {
		t.Fatalf("canceled accept = %v, %v; want context.Canceled | 取消上下文结果不符", fresh, err)
	}

	address := server.Addr()
	server.Close()
	fresh, err := first.Accept(testContext, "closed-jti", expiresAt)
	if fresh || !errors.Is(err, oidcstore.ErrStoreUnavailable) {
		t.Fatalf("closed backend = %v, %v; want ErrStoreUnavailable | 关闭后端错误不符", fresh, err)
	}
	if strings.Contains(err.Error(), address) {
		t.Fatalf("backend error leaked address %q: %v | 后端错误泄露地址", address, err)
	}
	if strings.Contains(err.Error(), "closed-jti") {
		t.Fatalf("backend error leaked jti: %v | 后端错误泄露 jti", err)
	}
}
