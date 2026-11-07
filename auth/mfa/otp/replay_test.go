package otp

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fixedClock returns a clock function pinned to at. | fixedClock 返回固定在 at 的时钟函数。
func fixedClock(at time.Time) func() time.Time {
	return func() time.Time { return at }
}

// TestMemoryReplayGuard checks fresh, duplicate, keyed and step-separated entries. | TestMemoryReplayGuard 检查全新、重复、分键与分步记录。
func TestMemoryReplayGuard(t *testing.T) {
	t.Parallel()
	guard := NewMemoryReplayGuard()
	ctx := context.Background()
	accept := func(key string, step int64) bool {
		t.Helper()
		ok, err := guard.Accept(ctx, key, step, time.Minute)
		if err != nil {
			t.Fatalf("Accept(%q, %d): %v | Accept 失败", key, step, err)
		}
		return ok
	}
	if !accept("credential-1", 10) {
		t.Fatal("first Accept was rejected | 首次 Accept 被拒绝")
	}
	if accept("credential-1", 10) {
		t.Error("duplicate Accept was accepted | 重复 Accept 被接受")
	}
	if !accept("credential-1", 11) {
		t.Error("a new step was rejected | 新时间步被拒绝")
	}
	if !accept("credential-2", 10) {
		t.Error("a new key was rejected | 新键被拒绝")
	}
}

// TestMemoryReplayGuardInvalid checks argument validation. | TestMemoryReplayGuardInvalid 检查参数校验。
func TestMemoryReplayGuardInvalid(t *testing.T) {
	t.Parallel()
	guard := NewMemoryReplayGuard()
	ctx := context.Background()
	// A typed nil context exercises the guard's explicit nil-context validation. | 带类型的 nil
	// 上下文用于验证 guard 对 nil 上下文的显式校验。
	var nilContext context.Context
	if _, err := guard.Accept(nilContext, "key", 1, time.Minute); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("nil context error = %v, want ErrInvalidRequest | nil 上下文错误应为 ErrInvalidRequest", err)
	}
	if _, err := guard.Accept(ctx, "", 1, time.Minute); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("empty key error = %v, want ErrInvalidRequest | 空键错误应为 ErrInvalidRequest", err)
	}
	if _, err := guard.Accept(ctx, "key", 1, 0); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("zero ttl error = %v, want ErrInvalidConfig | 零 TTL 错误应为 ErrInvalidConfig", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := guard.Accept(cancelled, "key", 1, time.Minute); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled context error = %v, want context.Canceled | 已取消上下文错误应为 context.Canceled", err)
	}
}

// TestMemoryReplayGuardExpiry checks that a pair becomes fresh again after ttl. | TestMemoryReplayGuardExpiry 检查键值对在 ttl 后重新变为全新。
func TestMemoryReplayGuardExpiry(t *testing.T) {
	t.Parallel()
	now := time.Unix(1000, 0)
	guard := NewMemoryReplayGuard()
	guard.now = func() time.Time { return now }
	ctx := context.Background()
	if ok, err := guard.Accept(ctx, "key", 1, 10*time.Second); err != nil || !ok {
		t.Fatalf("first Accept = (%v, %v), want (true, nil) | 首次 Accept 失败", ok, err)
	}
	now = now.Add(9 * time.Second)
	if ok, err := guard.Accept(ctx, "key", 1, 10*time.Second); err != nil || ok {
		t.Fatalf("live duplicate Accept = (%v, %v), want (false, nil) | 有效期内重复 Accept 未被拒绝", ok, err)
	}
	now = now.Add(time.Second)
	if ok, err := guard.Accept(ctx, "key", 1, 10*time.Second); err != nil || !ok {
		t.Fatalf("expired Accept = (%v, %v), want (true, nil) | 过期后 Accept 未通过", ok, err)
	}
}

// TestMemoryReplayGuardCapacity checks bounded growth and zero-value usability. | TestMemoryReplayGuardCapacity 检查有界增长与零值可用性。
func TestMemoryReplayGuardCapacity(t *testing.T) {
	t.Parallel()
	now := time.Unix(1000, 0)
	guard := NewMemoryReplayGuard()
	guard.now = func() time.Time { return now }
	guard.capacity = 2
	ctx := context.Background()
	if ok, _ := guard.Accept(ctx, "short", 1, time.Second); !ok {
		t.Fatal("short entry was rejected | 短 TTL 记录被拒绝")
	}
	if ok, _ := guard.Accept(ctx, "long", 1, time.Hour); !ok {
		t.Fatal("long entry was rejected | 长 TTL 记录被拒绝")
	}
	if ok, _ := guard.Accept(ctx, "new", 1, time.Hour); !ok {
		t.Fatal("new entry was rejected at capacity | 容量上限时新记录被拒绝")
	}
	if len(guard.entries) > guard.capacity {
		t.Errorf("entries = %d, capacity = %d | 记录数超过容量", len(guard.entries), guard.capacity)
	}

	var zero MemoryReplayGuard
	if ok, err := zero.Accept(ctx, "key", 1, time.Minute); err != nil || !ok {
		t.Errorf("zero-value guard Accept = (%v, %v), want (true, nil) | 零值 guard 失败", ok, err)
	}
	if ok, err := zero.Accept(ctx, "key", 1, time.Minute); err != nil || ok {
		t.Errorf("zero-value duplicate Accept = (%v, %v), want (false, nil) | 零值 guard 重复未拒绝", ok, err)
	}
}

// TestMemoryReplayGuardConcurrent checks that exactly one concurrent caller wins. | TestMemoryReplayGuardConcurrent 检查并发调用中恰好一个成功。
func TestMemoryReplayGuardConcurrent(t *testing.T) {
	t.Parallel()
	guard := NewMemoryReplayGuard()
	ctx := context.Background()
	var accepted int32
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := guard.Accept(ctx, "shared", 7, time.Minute)
			if err != nil {
				t.Errorf("Accept: %v | Accept 失败", err)
				return
			}
			if ok {
				atomic.AddInt32(&accepted, 1)
			}
		}()
	}
	wg.Wait()
	if accepted != 1 {
		t.Errorf("accepted = %d, want exactly 1 | 并发接受次数应为 1", accepted)
	}
}

// failingGuard always reports a backend failure. | failingGuard 始终报告后端故障。
type failingGuard struct{}

// Accept implements ReplayGuard. | Accept 实现 ReplayGuard。
func (failingGuard) Accept(context.Context, string, int64, time.Duration) (bool, error) {
	return false, errors.New("backend down | 后端故障")
}

// TestValidatorWithoutGuard checks plain validation. | TestValidatorWithoutGuard 检查无重放保护校验。
func TestValidatorWithoutGuard(t *testing.T) {
	t.Parallel()
	secret := testSecret("12345678901234567890")
	at := time.Unix(1234567890, 0).UTC()
	cfg := Config{Skew: 1}
	code, err := TOTP(secret, at, cfg)
	if err != nil {
		t.Fatalf("TOTP: %v", err)
	}
	validator := NewValidator(cfg, WithClock(fixedClock(at)))
	for i := 0; i < 3; i++ {
		step, ok, err := validator.ValidateTOTP(context.Background(), secret, code)
		if err != nil || !ok {
			t.Fatalf("ValidateTOTP = (%d, %v, %v), want (step, true, nil) | 校验失败", step, ok, err)
		}
		if want := TimeStep(at, DefaultPeriod); step != want {
			t.Errorf("step = %d, want %d | 时间步不匹配", step, want)
		}
	}
}

// TestValidatorReplay checks replay detection and key separation. | TestValidatorReplay 检查重放检测与键隔离。
func TestValidatorReplay(t *testing.T) {
	t.Parallel()
	secret := testSecret("12345678901234567890")
	at := time.Unix(1234567890, 0).UTC()
	cfg := Config{Skew: 1}
	code, err := TOTP(secret, at, cfg)
	if err != nil {
		t.Fatalf("TOTP: %v", err)
	}
	ctx := context.Background()
	guard := NewMemoryReplayGuard()
	validator := NewValidator(cfg, WithClock(fixedClock(at)), WithReplayGuard(guard))
	if _, ok, err := validator.ValidateTOTP(ctx, secret, code); err != nil || !ok {
		t.Fatalf("first ValidateTOTP = (%v, %v), want (true, nil) | 首次校验失败", ok, err)
	}
	if _, ok, err := validator.ValidateTOTP(ctx, secret, code); ok || !errors.Is(err, ErrReplay) {
		t.Fatalf("replayed ValidateTOTP = (%v, %v), want (false, ErrReplay) | 重放未被拒绝", ok, err)
	}

	guarded := NewValidator(cfg, WithClock(fixedClock(at)), WithReplayGuard(NewMemoryReplayGuard()))
	keyedOne := NewValidator(cfg, WithClock(fixedClock(at)), WithReplayGuard(guarded.guard), WithReplayKey("user-1"))
	keyedTwo := NewValidator(cfg, WithClock(fixedClock(at)), WithReplayGuard(guarded.guard), WithReplayKey("user-2"))
	if _, ok, err := keyedOne.ValidateTOTP(ctx, secret, code); err != nil || !ok {
		t.Fatalf("keyedOne first validation failed: %v | 键一首次校验失败", err)
	}
	if _, ok, err := keyedTwo.ValidateTOTP(ctx, secret, code); err != nil || !ok {
		t.Fatalf("keyedTwo first validation failed: %v | 键二首次校验失败", err)
	}
	if _, ok, err := keyedOne.ValidateTOTP(ctx, secret, code); ok || !errors.Is(err, ErrReplay) {
		t.Errorf("keyedOne replay = (%v, %v), want ErrReplay | 键一重放未被拒绝", ok, err)
	}
}

// TestValidatorDefaultKey checks that the same secret replays under the default fingerprint key.
// | TestValidatorDefaultKey 检查同一密钥在默认指纹键下会被判重放。
func TestValidatorDefaultKey(t *testing.T) {
	t.Parallel()
	secret := testSecret("12345678901234567890")
	at := time.Unix(1234567890, 0).UTC()
	cfg := Config{}
	code, err := TOTP(secret, at, cfg)
	if err != nil {
		t.Fatalf("TOTP: %v", err)
	}
	guard := NewMemoryReplayGuard()
	first := NewValidator(cfg, WithClock(fixedClock(at)), WithReplayGuard(guard))
	second := NewValidator(cfg, WithClock(fixedClock(at)), WithReplayGuard(guard))
	if _, ok, err := first.ValidateTOTP(context.Background(), secret, code); err != nil || !ok {
		t.Fatalf("first validation failed: %v | 首次校验失败", err)
	}
	if _, ok, err := second.ValidateTOTP(context.Background(), secret, code); ok || !errors.Is(err, ErrReplay) {
		t.Errorf("second validator replay = (%v, %v), want ErrReplay | 默认键未判重放", ok, err)
	}
}

// TestValidatorGuardFailure checks backend error propagation. | TestValidatorGuardFailure 检查后端错误传播。
func TestValidatorGuardFailure(t *testing.T) {
	t.Parallel()
	secret := testSecret("12345678901234567890")
	at := time.Unix(1234567890, 0).UTC()
	cfg := Config{}
	code, err := TOTP(secret, at, cfg)
	if err != nil {
		t.Fatalf("TOTP: %v", err)
	}
	validator := NewValidator(cfg, WithClock(fixedClock(at)), WithReplayGuard(failingGuard{}))
	if _, ok, err := validator.ValidateTOTP(context.Background(), secret, code); ok || !errors.Is(err, ErrReplayStore) {
		t.Errorf("ValidateTOTP = (%v, %v), want (false, ErrReplayStore) | 后端故障未传播", ok, err)
	}
}

// TestValidatorHOTP checks HOTP validation and replay detection. | TestValidatorHOTP 检查 HOTP 校验与重放检测。
func TestValidatorHOTP(t *testing.T) {
	t.Parallel()
	secret := testSecret("12345678901234567890")
	code, err := HOTP(secret, 5, Config{})
	if err != nil {
		t.Fatalf("HOTP: %v", err)
	}
	validator := NewValidator(Config{Skew: 1},
		WithReplayGuard(NewMemoryReplayGuard()), WithReplayKey("credential-1"))
	ctx := context.Background()
	matched, ok, err := validator.ValidateHOTP(ctx, secret, code, 4)
	if err != nil || !ok || matched != 5 {
		t.Fatalf("ValidateHOTP = (%d, %v, %v), want (5, true, nil) | HOTP 校验失败", matched, ok, err)
	}
	if _, ok, err := validator.ValidateHOTP(ctx, secret, code, 4); ok || !errors.Is(err, ErrReplay) {
		t.Errorf("HOTP replay = (%v, %v), want ErrReplay | HOTP 重放未被拒绝", ok, err)
	}
}

// TestNilValidator checks nil receiver handling. | TestNilValidator 检查 nil 接收者处理。
func TestNilValidator(t *testing.T) {
	t.Parallel()
	var validator *Validator
	if _, _, err := validator.ValidateTOTP(context.Background(), "x", "123456"); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("nil ValidateTOTP error = %v, want ErrInvalidConfig | nil 校验器错误应为 ErrInvalidConfig", err)
	}
	if _, _, err := validator.ValidateHOTP(context.Background(), "x", "123456", 0); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("nil ValidateHOTP error = %v, want ErrInvalidConfig | nil 校验器错误应为 ErrInvalidConfig", err)
	}
}

// TestReplayWindow checks the TTL calculation. | TestReplayWindow 检查 TTL 计算。
func TestReplayWindow(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		cfg  Config
		want time.Duration
	}{
		{"default", Config{}, 30 * time.Second},
		{"skew one", Config{Skew: 1}, 90 * time.Second},
		{"skew two longer period", Config{Skew: 2, Period: time.Minute}, 5 * time.Minute},
		{"invalid config falls back", Config{Skew: MaxSkew + 1}, DefaultPeriod},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := replayWindow(tt.cfg); got != tt.want {
				t.Errorf("replayWindow = %s, want %s | TTL 不匹配", got, tt.want)
			}
		})
	}
}
