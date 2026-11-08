package saml

import (
	"context"
	"sync"
	"time"

	"github.com/shibingli/ydx/errs"
)

// DefaultReplayFallback is the replay-record retention used when an assertion carries none of
// Conditions/NotOnOrAfter, SubjectConfirmationData/NotOnOrAfter or SessionNotOnOrAfter. |
// DefaultReplayFallback 是断言既无 Conditions/NotOnOrAfter、SubjectConfirmationData/NotOnOrAfter
// 也无 SessionNotOnOrAfter 时使用的重放记录保留时长。
const DefaultReplayFallback = 10 * time.Minute

// ReplayWindow controls how long an assertion identifier is retained by a replay store. By default
// retention follows the earliest of Conditions/NotOnOrAfter,
// SubjectConfirmationData/NotOnOrAfter and SessionNotOnOrAfter, and falls back to
// DefaultReplayFallback when the assertion carries no upper bound. MinRetention and MaxRetention
// optionally clamp the computed expiry; a zero duration disables the corresponding clamp. |
// ReplayWindow 控制重放存储保留断言标识的时长。默认保留时长取
// Conditions/NotOnOrAfter、SubjectConfirmationData/NotOnOrAfter 与 SessionNotOnOrAfter 三者中最早
// 者；断言未携带上界时使用 DefaultReplayFallback。MinRetention 与 MaxRetention 可选地约束计算出的
// 过期时间；零值禁用对应约束。
type ReplayWindow struct {
	// Fallback is used only when the assertion carries no upper bound; zero means
	// DefaultReplayFallback. | Fallback 仅在断言未携带上界时使用；零值表示 DefaultReplayFallback。
	Fallback time.Duration
	// MinRetention raises an earlier expiry to now+MinRetention; zero disables the floor. |
	// MinRetention 把更早的过期时间提升到 now+MinRetention；零值禁用下限。
	MinRetention time.Duration
	// MaxRetention lowers a later expiry to now+MaxRetention; zero disables the cap. | MaxRetention
	// 把更晚的过期时间降低到 now+MaxRetention；零值禁用上限。
	MaxRetention time.Duration
}

// Normalized validates the window and fills in the default fallback. Negative durations and a
// positive MaxRetention smaller than a positive MinRetention report ErrInvalidConfig. |
// Normalized 校验窗口并填充默认回退时长。负时长，以及正 MaxRetention 小于正 MinRetention，均返回
// ErrInvalidConfig。
func (w ReplayWindow) Normalized() (ReplayWindow, error) {
	if w.Fallback < 0 || w.MinRetention < 0 || w.MaxRetention < 0 {
		return w, errs.Detail(ErrInvalidConfig, "replay window durations must not be negative | 重放窗口时长不得为负")
	}
	if w.Fallback == 0 {
		w.Fallback = DefaultReplayFallback
	}
	if w.MaxRetention > 0 && w.MaxRetention < w.MinRetention {
		return w, errs.Detail(ErrInvalidConfig, "replay max retention %s is smaller than min retention %s | 重放最大保留 %s 小于最小保留 %s",
			w.MaxRetention, w.MinRetention, w.MaxRetention, w.MinRetention)
	}
	return w, nil
}

// expiry computes the replay-record expiry for the earliest assertion bound. hasBound reports
// whether bound is meaningful. MinRetention and MaxRetention are applied after the bound or
// fallback is selected. | expiry 依据最早的断言上界计算重放记录过期时间。hasBound 表示 bound 是否
// 有效。选定上界或回退值后再应用 MinRetention 与 MaxRetention。
func (w ReplayWindow) expiry(now, bound time.Time, hasBound bool) time.Time {
	expiresAt := now.Add(w.Fallback)
	if hasBound {
		expiresAt = bound
	}
	if w.MinRetention > 0 {
		if earliest := now.Add(w.MinRetention); expiresAt.Before(earliest) {
			expiresAt = earliest
		}
	}
	if w.MaxRetention > 0 {
		if latest := now.Add(w.MaxRetention); expiresAt.After(latest) {
			expiresAt = latest
		}
	}
	return expiresAt
}

// AssertionReplayCleaner is an optional extension of AssertionReplayStore for stores that retain
// records until expiry. CleanupAssertions removes records whose expiry is at or before now and
// returns the number removed. Implementations must be safe for concurrent use with SeenAndStore. |
// AssertionReplayCleaner 是 AssertionReplayStore 的可选扩展，用于保留记录至过期的存储。
// CleanupAssertions 删除过期时间等于或早于 now 的记录并返回删除数量。实现必须可与 SeenAndStore
// 并发安全调用。
type AssertionReplayCleaner interface {
	// CleanupAssertions removes expired records and returns the removed count. | CleanupAssertions
	// 删除过期记录并返回删除数量。
	CleanupAssertions(ctx context.Context, now time.Time) (int, error)
}

// MemoryAssertionReplayStore is a concurrency-safe in-memory AssertionReplayStore with explicit
// expiry cleanup. The zero value is ready to use. SeenAndStore is atomic: exactly one of several
// concurrent calls for the same fresh identifier reports seen=false. A nil *MemoryAssertionReplayStore
// fails closed with ErrInvalidConfig instead of disabling replay detection. |
// MemoryAssertionReplayStore 是并发安全、支持显式过期清理的内存 AssertionReplayStore。零值即可使用。
// SeenAndStore 具有原子性：同一新标识的多个并发调用中恰好一个返回 seen=false。空的
// *MemoryAssertionReplayStore 以 ErrInvalidConfig 失败关闭，而不会禁用重放检测。
type MemoryAssertionReplayStore struct {
	mu      sync.Mutex
	records map[string]time.Time
}

// NewMemoryAssertionReplayStore returns an empty in-memory replay store. | NewMemoryAssertionReplayStore
// 返回空内存重放存储。
func NewMemoryAssertionReplayStore() *MemoryAssertionReplayStore {
	return &MemoryAssertionReplayStore{records: make(map[string]time.Time)}
}

// SeenAndStore atomically records assertionID until expiresAt. It returns seen=true when the
// identifier has a live record at now. An empty identifier reports ErrInvalidResponse and a nil
// receiver reports ErrInvalidConfig; callers must treat any error as a failed validation. |
// SeenAndStore 原子记录 assertionID 直到 expiresAt。标识在 now 时仍有有效记录则返回 seen=true。
// 标识为空返回 ErrInvalidResponse，接收者为空返回 ErrInvalidConfig；调用方必须把任何错误视为校验失败。
func (s *MemoryAssertionReplayStore) SeenAndStore(_ context.Context, assertionID string, expiresAt, now time.Time) (bool, error) {
	if s == nil {
		return false, errs.Detail(ErrInvalidConfig, "assertion replay store is nil | 断言重放存储为空")
	}
	if assertionID == "" {
		return false, errs.Detail(ErrInvalidResponse, "assertion id is empty | 断言标识为空")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.records == nil {
		s.records = make(map[string]time.Time)
	}
	if existing, ok := s.records[assertionID]; ok && now.Before(existing) {
		return true, nil
	}
	s.records[assertionID] = expiresAt
	return false, nil
}

// CleanupAssertions removes records whose expiry is at or before now and returns the removed
// count. A nil receiver reports ErrInvalidConfig. | CleanupAssertions 删除过期时间等于或早于 now
// 的记录并返回删除数量。接收者为空返回 ErrInvalidConfig。
func (s *MemoryAssertionReplayStore) CleanupAssertions(_ context.Context, now time.Time) (int, error) {
	if s == nil {
		return 0, errs.Detail(ErrInvalidConfig, "assertion replay store is nil | 断言重放存储为空")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for id, expiresAt := range s.records {
		if !now.Before(expiresAt) {
			delete(s.records, id)
			removed++
		}
	}
	return removed, nil
}

// replayExpiry computes the replay-record expiry for an assertion. The earliest available bound is
// selected from Conditions/NotOnOrAfter, the bearer SubjectConfirmationData/NotOnOrAfter and every
// AuthnStatement/SessionNotOnOrAfter. Expired sessions are rejected before any replay record is
// written. | replayExpiry 计算断言的重放记录过期时间。从 Conditions/NotOnOrAfter、承载
// SubjectConfirmationData/NotOnOrAfter 及所有 AuthnStatement/SessionNotOnOrAfter 中选择最早上界。
// 已过期会话在写入任何重放记录之前被拒绝。
func replayExpiry(window ReplayWindow, assertion *Assertion, bearer *SubjectConfirmationData, now time.Time, skew time.Duration) (time.Time, error) {
	var bound time.Time
	hasBound := false
	consider := func(value string) error {
		if value == "" {
			return nil
		}
		parsed, err := ParseTime(value)
		if err != nil {
			return err
		}
		if !hasBound || parsed.Before(bound) {
			bound = parsed
			hasBound = true
		}
		return nil
	}
	if assertion.Conditions != nil {
		if err := consider(assertion.Conditions.NotOnOrAfter); err != nil {
			return time.Time{}, err
		}
	}
	if bearer != nil {
		if err := consider(bearer.NotOnOrAfter); err != nil {
			return time.Time{}, err
		}
	}
	for index := range assertion.AuthnStatement {
		statement := &assertion.AuthnStatement[index]
		if statement.SessionNotOnOrAfter == "" {
			continue
		}
		parsed, err := ParseTime(statement.SessionNotOnOrAfter)
		if err != nil {
			return time.Time{}, err
		}
		// SessionNotOnOrAfter bounds the IdP session exactly like Conditions/NotOnOrAfter bounds the
		// assertion: a value at or before the tolerated clock boundary is expired. | SessionNotOnOrAfter
		// 与 Conditions/NotOnOrAfter 约束断言的方式一致地约束 IdP 会话：等于或早于容忍时钟边界即过期。
		if !now.Add(-skew).Before(parsed) {
			return time.Time{}, ErrResponseExpired
		}
		if !hasBound || parsed.Before(bound) {
			bound = parsed
			hasBound = true
		}
	}
	return window.expiry(now, bound, hasBound), nil
}
