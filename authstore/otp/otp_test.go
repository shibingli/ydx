package otp_test

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

	authotp "github.com/shibingli/ydx/auth/mfa/otp"
	otpstore "github.com/shibingli/ydx/authstore/otp"
)

// testContext is the context shared by the guard tests. | testContext 是保护器测试共享的上下文。
var testContext = context.Background()

// newGuardsOn creates one independent guard against an existing miniredis. | newGuardsOn 针对已有
// miniredis 创建一个独立的保护器。
func newGuardsOn(t *testing.T, server *miniredis.Miniredis, prefix string) *otpstore.ReplayGuard {
	t.Helper()
	client := goredis.NewClient(&goredis.Options{Addr: server.Addr()})
	t.Cleanup(func() {
		_ = client.Close()
	})
	guard, err := otpstore.New(client, otpstore.Options{KeyPrefix: prefix})
	if err != nil {
		t.Fatalf("new guard: %v | 创建保护器失败", err)
	}
	return guard
}

// newPair returns two independent guards sharing one miniredis, modelling two instances.
// | newPair 返回共享同一 miniredis 的两套独立保护器，用于模拟两个实例。
func newPair(t *testing.T) (*otpstore.ReplayGuard, *otpstore.ReplayGuard) {
	t.Helper()
	server := miniredis.RunT(t)
	return newGuardsOn(t, server, ""), newGuardsOn(t, server, "")
}

// TestNewValidation covers constructor validation, the default prefix and interface conformance.
// | TestNewValidation 覆盖构造校验、默认前缀与接口符合性。
func TestNewValidation(t *testing.T) {
	if otpstore.DefaultKeyPrefix != "ydx:authstore:otp:" {
		t.Fatalf("DefaultKeyPrefix = %q | 默认前缀不正确", otpstore.DefaultKeyPrefix)
	}
	if _, err := otpstore.New(nil, otpstore.Options{}); !errors.Is(err, authotp.ErrInvalidConfig) {
		t.Fatalf("nil client error = %v, want ErrInvalidConfig | nil 客户端错误不符", err)
	}
	server := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: server.Addr()})
	t.Cleanup(func() {
		_ = client.Close()
	})
	if _, err := otpstore.New(client, otpstore.Options{KeyPrefix: "bad}prefix"}); !errors.Is(err, authotp.ErrInvalidConfig) {
		t.Fatalf("brace prefix error = %v, want ErrInvalidConfig | 花括号前缀错误不符", err)
	}
	guard, err := otpstore.New(client, otpstore.Options{})
	if err != nil {
		t.Fatalf("new guard: %v | 创建保护器失败", err)
	}
	var port authotp.ReplayGuard = guard
	if port == nil {
		t.Fatal("New returned a nil port | New 返回了空端口")
	}
}

// TestNewDoesNotDial verifies that New performs no network round trip. | TestNewDoesNotDial 验证
// New 不进行网络往返。
func TestNewDoesNotDial(t *testing.T) {
	client := goredis.NewClient(&goredis.Options{
		Addr:        "127.0.0.1:1",
		MaxRetries:  -1,
		DialTimeout: 20 * time.Millisecond,
	})
	t.Cleanup(func() {
		_ = client.Close()
	})
	if _, err := otpstore.New(client, otpstore.Options{}); err != nil {
		t.Fatalf("New dialed: %v | New 不应连接网络", err)
	}
}

// TestAcceptLifecycle covers first acceptance, duplicate rejection and step/key separation across
// two instances. | TestAcceptLifecycle 覆盖首次接受、重复拒绝与两实例间的步/键区分。
func TestAcceptLifecycle(t *testing.T) {
	first, second := newPair(t)
	fresh, err := first.Accept(testContext, "user-1", 42, time.Minute)
	if err != nil || !fresh {
		t.Fatalf("first accept = %v/%v | 首次接受失败", fresh, err)
	}
	if fresh, err := second.Accept(testContext, "user-1", 42, time.Minute); err != nil || fresh {
		t.Fatalf("duplicate accept = %v/%v, want false | 重复接受未被拒绝", fresh, err)
	}
	if fresh, err := second.Accept(testContext, "user-1", 43, time.Minute); err != nil || !fresh {
		t.Fatalf("new step accept = %v/%v | 新时间步未被接受", fresh, err)
	}
	if fresh, err := second.Accept(testContext, "user-2", 42, time.Minute); err != nil || !fresh {
		t.Fatalf("new key accept = %v/%v | 新键未被接受", fresh, err)
	}
}

// TestAcceptValidation covers nil contexts, empty keys and non-positive TTLs.
// | TestAcceptValidation 覆盖 nil 上下文、空键与非正 TTL。
func TestAcceptValidation(t *testing.T) {
	guard := newGuardsOn(t, miniredis.RunT(t), "")
	var nilContext context.Context
	if fresh, err := guard.Accept(nilContext, "user-1", 1, time.Minute); fresh || !errors.Is(err, authotp.ErrInvalidRequest) {
		t.Fatalf("nil context = %v/%v | nil 上下文错误不符", fresh, err)
	}
	if fresh, err := guard.Accept(testContext, "", 1, time.Minute); fresh || !errors.Is(err, authotp.ErrInvalidRequest) {
		t.Fatalf("empty key = %v/%v | 空键错误不符", fresh, err)
	}
	for _, ttl := range []time.Duration{0, -time.Second} {
		if fresh, err := guard.Accept(testContext, "user-1", 1, ttl); fresh || !errors.Is(err, authotp.ErrInvalidConfig) {
			t.Fatalf("ttl %s = %v/%v | 非正 TTL 错误不符", ttl, fresh, err)
		}
	}
	cancelled, cancel := context.WithCancel(testContext)
	cancel()
	if fresh, err := guard.Accept(cancelled, "user-1", 1, time.Minute); fresh || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled = %v/%v | 取消上下文错误不符", fresh, err)
	}
	deadline, cancelDeadline := context.WithDeadline(testContext, time.Now().Add(-time.Second))
	defer cancelDeadline()
	if _, err := guard.Accept(deadline, "user-1", 1, time.Minute); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline = %v | 截止时间错误不符", err)
	}
}

// TestAcceptConcurrentExactlyOnce models many instances racing for one fresh pair.
// | TestAcceptConcurrentExactlyOnce 模拟多实例争抢同一个全新键值对。
func TestAcceptConcurrentExactlyOnce(t *testing.T) {
	first, second := newPair(t)
	var successes atomic.Int64
	var failures atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 128; i++ {
		guard := first
		if i%2 == 1 {
			guard = second
		}
		wg.Add(1)
		go func(guard *otpstore.ReplayGuard) {
			defer wg.Done()
			fresh, err := guard.Accept(testContext, "user-race", 7, time.Minute)
			if err != nil {
				failures.Add(1)
				return
			}
			if fresh {
				successes.Add(1)
			}
		}(guard)
	}
	wg.Wait()
	if failures.Load() != 0 {
		t.Fatalf("accept failures = %d | 接受失败次数非零", failures.Load())
	}
	if successes.Load() != 1 {
		t.Fatalf("accept successes = %d, want 1 | 成功接受次数不为 1", successes.Load())
	}
}

// TestAcceptExpiry checks that Redis TTL expiry lets the same pair be accepted again, matching the
// in-memory guard. | TestAcceptExpiry 检查 Redis TTL 过期后同一键值对可再次接受，与内存保护器一致。
func TestAcceptExpiry(t *testing.T) {
	server := miniredis.RunT(t)
	first := newGuardsOn(t, server, "")
	second := newGuardsOn(t, server, "")
	ttl := 2 * time.Second
	if fresh, err := first.Accept(testContext, "user-ttl", 9, ttl); err != nil || !fresh {
		t.Fatalf("first accept = %v/%v | 首次接受失败", fresh, err)
	}
	if fresh, err := second.Accept(testContext, "user-ttl", 9, ttl); err != nil || fresh {
		t.Fatalf("live duplicate = %v/%v | 有效期内重复未被拒绝", fresh, err)
	}
	keys := server.Keys()
	if len(keys) != 1 {
		t.Fatalf("keys = %v | 键数量不正确", keys)
	}
	if stored := server.TTL(keys[0]); stored != ttl {
		t.Fatalf("TTL = %s, want %s | TTL 不正确", stored, ttl)
	}
	server.FastForward(ttl)
	if fresh, err := second.Accept(testContext, "user-ttl", 9, ttl); err != nil || !fresh {
		t.Fatalf("post-expiry accept = %v/%v | 过期后未被再次接受", fresh, err)
	}
}

// TestAcceptSubMillisecondTTL verifies the minimum Redis expiry clamp. | TestAcceptSubMillisecondTTL
// 验证最小 Redis 期限钳制。
func TestAcceptSubMillisecondTTL(t *testing.T) {
	server := miniredis.RunT(t)
	guard := newGuardsOn(t, server, "")
	if fresh, err := guard.Accept(testContext, "user-nano", 1, time.Nanosecond); err != nil || !fresh {
		t.Fatalf("accept = %v/%v | 纳秒 TTL 接受失败", fresh, err)
	}
	keys := server.Keys()
	if len(keys) != 1 {
		t.Fatalf("keys = %v | 键数量不正确", keys)
	}
	if stored := server.TTL(keys[0]); stored != time.Millisecond {
		t.Fatalf("TTL = %s, want 1ms | 最小 TTL 钳制不正确", stored)
	}
}

// TestPrefixIsolation runs two guards with distinct prefixes on one server.
// | TestPrefixIsolation 在同一服务器上运行两套不同前缀的保护器。
func TestPrefixIsolation(t *testing.T) {
	server := miniredis.RunT(t)
	first := newGuardsOn(t, server, "one:")
	second := newGuardsOn(t, server, "two:")
	if fresh, err := first.Accept(testContext, "user-1", 1, time.Minute); err != nil || !fresh {
		t.Fatalf("first accept = %v/%v | 第一前缀接受失败", fresh, err)
	}
	if fresh, err := second.Accept(testContext, "user-1", 1, time.Minute); err != nil || !fresh {
		t.Fatalf("second prefix collided: %v/%v | 第二前缀发生冲突", fresh, err)
	}
}

// TestKeyLayout verifies the default prefix, the shared hash tag and the length-prefixed segment.
// | TestKeyLayout 验证默认前缀、共享哈希标签与长度前缀段。
func TestKeyLayout(t *testing.T) {
	server := miniredis.RunT(t)
	guard := newGuardsOn(t, server, otpstore.DefaultKeyPrefix)
	key := "user-abc"
	step := int64(123)
	if fresh, err := guard.Accept(testContext, key, step, time.Minute); err != nil || !fresh {
		t.Fatalf("accept = %v/%v | 接受失败", fresh, err)
	}
	keys := server.Keys()
	if len(keys) != 1 {
		t.Fatalf("keys = %v | 键数量不正确", keys)
	}
	want := otpstore.DefaultKeyPrefix + "{authstore:otp}:replay:" +
		strconv.Itoa(len(key)) + ":" + key + ":" + strconv.FormatInt(step, 10)
	if keys[0] != want {
		t.Fatalf("key = %q, want %q | 键布局不正确", keys[0], want)
	}
}

// TestBackendErrorsAreRedacted verifies classification and the absence of addresses.
// | TestBackendErrorsAreRedacted 验证错误分类且不泄露地址。
func TestBackendErrorsAreRedacted(t *testing.T) {
	client := goredis.NewClient(&goredis.Options{
		Addr:        "127.0.0.1:1",
		MaxRetries:  -1,
		DialTimeout: 50 * time.Millisecond,
	})
	t.Cleanup(func() {
		_ = client.Close()
	})
	guard, err := otpstore.New(client, otpstore.Options{})
	if err != nil {
		t.Fatalf("new guard: %v | 创建保护器失败", err)
	}
	fresh, err := guard.Accept(testContext, "user-1", 1, time.Minute)
	if fresh || !errors.Is(err, authotp.ErrReplayStore) {
		t.Fatalf("accept = %v/%v, want ErrReplayStore | 后端错误未映射为重放存储错误", fresh, err)
	}
	if strings.Contains(err.Error(), "127.0.0.1") || strings.Contains(err.Error(), ":1") {
		t.Fatalf("error leaked the address: %v | 错误泄露了地址", err)
	}
}
