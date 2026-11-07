package otp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"sync"
	"time"

	"github.com/shibingli/ydx/errs"
)

// ReplayGuard records accepted one-time codes and rejects reuse of the same (key, step) pair.
// Implementations must make Accept atomic: exactly one concurrent caller for a fresh pair may
// receive true. | ReplayGuard 记录已接受的一次性口令，并拒绝重复使用同一 (key, step) 对。
// 实现必须保证 Accept 原子：对全新键值对的并发调用中只能有一个返回 true。
type ReplayGuard interface {
	// Accept records (key, step) for ttl and reports whether it was fresh. A false result with a
	// nil error means the pair was already accepted and is still live. | Accept 记录 (key, step)
	// 并报告它是否全新。返回 false 且错误为空表示该键值对已被接受且仍在有效期内。
	Accept(ctx context.Context, key string, step int64, ttl time.Duration) (bool, error)
}

// defaultReplayCapacity bounds the memory used by MemoryReplayGuard before expired entries are
// purged and live entries are evicted oldest-first. | defaultReplayCapacity 限定 MemoryReplayGuard
// 的内存占用上限；达到上限后先清理过期项，再按最早过期优先淘汰存活项。
const defaultReplayCapacity = 1 << 16

// replayEntry identifies one accepted code without concatenating the key and step. | replayEntry
// 标识一个已接受的口令，避免拼接键与步。
type replayEntry struct {
	key  string
	step int64
}

// MemoryReplayGuard is an in-process ReplayGuard. It is safe for concurrent use, and its zero
// value uses a monotonic wall clock and the default capacity. State is lost on restart, so a
// multi-instance deployment needs a shared implementation of ReplayGuard. | MemoryReplayGuard 是
// 进程内的 ReplayGuard。它可安全并发使用，零值使用单调墙钟与默认容量。重启会丢失状态，因此多实例
// 部署需要共享的 ReplayGuard 实现。
type MemoryReplayGuard struct {
	now      func() time.Time
	entries  map[replayEntry]time.Time
	capacity int
	mu       sync.Mutex
}

// NewMemoryReplayGuard returns an empty in-process replay guard. | NewMemoryReplayGuard 返回空的进程内重放保护器。
func NewMemoryReplayGuard() *MemoryReplayGuard {
	return &MemoryReplayGuard{
		now:      time.Now,
		entries:  make(map[replayEntry]time.Time),
		capacity: defaultReplayCapacity,
	}
}

// Accept records (key, step) for ttl and reports whether it was fresh. It returns
// ErrInvalidRequest for a nil context or empty key, ErrInvalidConfig for a non-positive ttl, and
// the context error when ctx is already cancelled. | Accept 记录 (key, step) 并报告它是否全新。
// 对空上下文或空键返回 ErrInvalidRequest，对非正 ttl 返回 ErrInvalidConfig，上下文已取消时返回
// 上下文错误。
func (g *MemoryReplayGuard) Accept(ctx context.Context, key string, step int64, ttl time.Duration) (bool, error) {
	if ctx == nil {
		return false, errs.Detail(ErrInvalidRequest, "nil context | 上下文为空")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if key == "" {
		return false, errs.Detail(ErrInvalidRequest, "replay key is empty | 重放保护键为空")
	}
	if ttl <= 0 {
		return false, errs.Detail(ErrInvalidConfig,
			"replay TTL %s is not positive | 重放保护 TTL %s 非正", ttl, ttl)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.now == nil {
		g.now = time.Now
	}
	if g.capacity <= 0 {
		g.capacity = defaultReplayCapacity
	}
	if g.entries == nil {
		g.entries = make(map[replayEntry]time.Time)
	}
	now := g.now()
	entry := replayEntry{key: key, step: step}
	if expiry, exists := g.entries[entry]; exists && now.Before(expiry) {
		return false, nil
	}
	if len(g.entries) >= g.capacity {
		g.evictLocked(now)
	}
	g.entries[entry] = now.Add(ttl)
	return true, nil
}

// evictLocked removes expired entries, then the earliest-expiring live entries when the map is
// still at capacity. g.mu must be held. | evictLocked 先删除过期项，若映射仍处于容量上限，再按最早
// 过期顺序删除存活项。调用时必须持有 g.mu。
func (g *MemoryReplayGuard) evictLocked(now time.Time) {
	for entry, expiry := range g.entries {
		if !now.Before(expiry) {
			delete(g.entries, entry)
		}
	}
	if len(g.entries) < g.capacity {
		return
	}
	type expiryPair struct {
		expiry time.Time
		entry  replayEntry
	}
	pairs := make([]expiryPair, 0, len(g.entries))
	for entry, expiry := range g.entries {
		pairs = append(pairs, expiryPair{entry: entry, expiry: expiry})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].expiry.Before(pairs[j].expiry) })
	target := g.capacity / 2
	for i := 0; i < len(pairs) && len(g.entries) > target; i++ {
		delete(g.entries, pairs[i].entry)
	}
}

// Validator validates HOTP and TOTP codes with an optional ReplayGuard. It is immutable after
// construction and safe for concurrent use. | Validator 使用可选的 ReplayGuard 校验 HOTP 与 TOTP
// 口令。构造后不可变，可安全并发使用。
type Validator struct {
	guard ReplayGuard
	now   func() time.Time
	cfg   Config
	key   string
}

// ValidatorOption configures a Validator. | ValidatorOption 配置 Validator。
type ValidatorOption func(*Validator)

// NewValidator returns a Validator using cfg. Without WithReplayGuard it only checks code
// correctness, so the same TOTP code can be presented repeatedly. | NewValidator 返回使用 cfg 的
// Validator。未配置 WithReplayGuard 时它只检查口令正确性，因此同一个 TOTP 口令可以被重复提交。
func NewValidator(cfg Config, opts ...ValidatorOption) *Validator {
	validator := &Validator{cfg: cfg, now: func() time.Time { return time.Now().UTC() }}
	for _, opt := range opts {
		if opt != nil {
			opt(validator)
		}
	}
	return validator
}

// WithReplayGuard installs guard. A nil guard disables replay protection. | WithReplayGuard 安装 guard。nil 表示关闭重放保护。
func WithReplayGuard(guard ReplayGuard) ValidatorOption {
	return func(validator *Validator) { validator.guard = guard }
}

// WithReplayKey sets the key used for replay entries. Without it the validator uses a SHA-256
// fingerprint of the secret, which is stable but cannot distinguish two users who share a secret.
// | WithReplayKey 设置重放记录使用的键。未设置时校验器使用密钥的 SHA-256 指纹，它稳定但无法区分
// 共享同一密钥的两个用户。
func WithReplayKey(key string) ValidatorOption {
	return func(validator *Validator) { validator.key = key }
}

// WithClock overrides the time source. A nil function is ignored. | WithClock 覆盖时间源。nil 函数会被忽略。
func WithClock(now func() time.Time) ValidatorOption {
	return func(validator *Validator) {
		if now != nil {
			validator.now = now
		}
	}
}

// ValidateTOTP validates code against secret at the validator clock. On success it returns the
// matched time step and records it in the replay guard when one is configured; a reused step
// yields (step, false, ErrReplay). | ValidateTOTP 在校验器时钟下用 secret 校验 code。成功时返回
// 命中的时间步，并在配置了重放保护时记录该步；重复使用的时间步返回 (step, false, ErrReplay)。
func (v *Validator) ValidateTOTP(ctx context.Context, secret, code string) (int64, bool, error) {
	if v == nil {
		return 0, false, errs.Detail(ErrInvalidConfig, "nil validator | 校验器为空")
	}
	step, ok, err := ValidateTOTP(secret, code, v.nowTime(), v.cfg)
	if err != nil || !ok {
		return step, ok, err
	}
	if v.guard != nil {
		accepted, err := v.guard.Accept(ctx, v.replayKey(secret), step, replayWindow(v.cfg))
		if err != nil {
			return step, false, errs.Wrap(err, ErrReplayStore)
		}
		if !accepted {
			return step, false, errs.Detail(ErrReplay, "time step %d was already used | 时间步 %d 已被使用", step, step)
		}
	}
	return step, true, nil
}

// ValidateHOTP validates code against secret in the counter window starting at counter. On
// success it returns the matched counter and records it in the replay guard when one is
// configured; a reused counter yields (counter, false, ErrReplay). | ValidateHOTP 从 counter 起
// 的计数器窗口内用 secret 校验 code。成功时返回命中的计数器，并在配置了重放保护时记录该计数器；
// 重复使用的计数器返回 (counter, false, ErrReplay)。
func (v *Validator) ValidateHOTP(ctx context.Context, secret, code string, counter uint64) (uint64, bool, error) {
	if v == nil {
		return 0, false, errs.Detail(ErrInvalidConfig, "nil validator | 校验器为空")
	}
	matched, ok, err := ValidateHOTP(secret, code, counter, v.cfg)
	if err != nil || !ok {
		return matched, ok, err
	}
	if v.guard != nil {
		if matched > uint64(maxInt64) {
			return matched, false, errs.Detail(ErrInvalidConfig,
				"counter %d exceeds the replay guard range | 计数器 %d 超出重放保护范围", matched, matched)
		}
		accepted, err := v.guard.Accept(ctx, v.replayKey(secret), int64(matched), replayWindow(v.cfg))
		if err != nil {
			return matched, false, errs.Wrap(err, ErrReplayStore)
		}
		if !accepted {
			return matched, false, errs.Detail(ErrReplay, "counter %d was already used | 计数器 %d 已被使用", matched, matched)
		}
	}
	return matched, true, nil
}

// nowTime returns the validator clock in UTC. | nowTime 返回 UTC 的校验器时钟。
func (v *Validator) nowTime() time.Time {
	if v.now == nil {
		return time.Now().UTC()
	}
	return v.now().UTC()
}

// replayKey returns the configured key or a secret fingerprint. | replayKey 返回配置的键或密钥指纹。
func (v *Validator) replayKey(secret string) string {
	if v.key != "" {
		return v.key
	}
	return secretFingerprint(secret)
}

// secretFingerprint returns a stable SHA-256 fingerprint of a secret without storing it. | secretFingerprint 返回密钥的稳定 SHA-256 指纹而不存储密钥本身。
func secretFingerprint(secret string) string {
	sum := sha256.Sum256([]byte(canonicalSecret(secret)))
	return "otp:" + hex.EncodeToString(sum[:])
}

// replayWindow returns how long a matched step must be remembered: the widest time span in which
// the same code can still validate. | replayWindow 返回命中步需要记住的时长：同一口令仍能通过校验的最宽时间跨度。
func replayWindow(cfg Config) time.Duration {
	c, err := cfg.Normalize()
	if err != nil {
		return DefaultPeriod
	}
	multiplier := time.Duration(2*c.Skew + 1)
	if multiplier <= 0 || c.Period > time.Duration(maxInt64)/multiplier {
		return time.Duration(maxInt64)
	}
	return c.Period * multiplier
}
