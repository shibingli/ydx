package auth

import (
	"context"
	"sync"
	"time"

	"github.com/shibingli/ydx/errs"
)

// MemoryStoreOptions configures managed in-memory stores. | MemoryStoreOptions 配置受管理的内存存储。
type MemoryStoreOptions struct {
	// CleanupInterval is the background sweep period. Zero or negative disables the background
	// sweeper; Cleanup can still be invoked explicitly. | CleanupInterval 是后台清扫周期。零或负数
	// 禁用后台清扫；仍可显式调用 Cleanup。
	CleanupInterval time.Duration
	// MaxAuditEvents caps retained audit events. Zero or negative keeps every event. | MaxAuditEvents
	// 限制保留的审计事件数。零或负数保留全部事件。
	MaxAuditEvents int
}

// MemoryCleanupResult reports how many records one sweep removed. | MemoryCleanupResult 报告一次清扫
// 删除的记录数。
type MemoryCleanupResult struct {
	// Sessions is the number of sessions removed because their absolute or idle deadline passed. |
	// Sessions 是因绝对或空闲期限已过而删除的会话数。
	Sessions int
	// Tokens is the number of expired one-time tokens removed. | Tokens 是删除的已过期一次性令牌数。
	Tokens int
	// Audits is the number of audit events trimmed by the retention cap. | Audits 是因保留上限被
	// 裁剪的审计事件数。
	Audits int
}

// MemoryStores is a managed in-memory store set with optional periodic cleanup. | MemoryStores 是带
// 可选周期清理的受管理内存存储集合。
//
// It embeds Stores, so it satisfies every dependency that accepts Stores. Start launches the sweeper
// and Close stops it and waits for the goroutine; a zero CleanupInterval never launches one. | 它内嵌
// Stores，因此可直接用于接受 Stores 的依赖。Start 启动清扫器，Close 停止并等待该 goroutine；零
// CleanupInterval 不会启动任何 goroutine。
type MemoryStores struct {
	Stores
	// sessions, tokens and audits are the concrete stores used by cleanup. | sessions、tokens 与
	// audits 是清理使用的具体存储。
	sessions *MemorySessionStore
	tokens   *MemoryTokenStore
	audits   *MemoryAuditStore
	// interval is the background sweep period. | interval 是后台清扫周期。
	interval time.Duration
	// mu guards lifecycle state and clock. | mu 保护生命周期状态与时钟。
	mu sync.Mutex
	// clock overrides time for tests; nil uses the wall clock. | clock 为测试替换时间；nil 使用系统时钟。
	clock func() time.Time
	// cancel stops the sweeper. | cancel 停止清扫器。
	cancel context.CancelFunc
	// done closes when the sweeper exits. | done 在清扫器退出时关闭。
	done chan struct{}
	// started reports whether the sweeper is running. | started 表示清扫器是否已启动。
	started bool
	// closed reports whether Close has run. | closed 表示 Close 是否已执行。
	closed bool
}

// NewManagedMemoryStores returns a managed in-memory store set. | NewManagedMemoryStores 返回受管理的
// 内存存储集合。
//
// Unlike NewMemoryStores it retains the concrete store handles needed for cleanup and can be started
// and closed. | 与 NewMemoryStores 不同，它保留清理所需的具体存储句柄，并可启动与关闭。
func NewManagedMemoryStores(opts MemoryStoreOptions) *MemoryStores {
	audits := NewMemoryAuditStore()
	audits.SetMaxEvents(opts.MaxAuditEvents)
	ms := &MemoryStores{
		sessions: NewMemorySessionStore(),
		tokens:   NewMemoryTokenStore(),
		audits:   audits,
		interval: opts.CleanupInterval,
	}
	ms.Stores = Stores{
		Users:       NewMemoryUserStore(),
		Sessions:    ms.sessions,
		Identities:  NewMemoryIdentityStore(),
		Credentials: NewMemoryCredentialStore(),
		Audits:      audits,
		Tokens:      ms.tokens,
	}
	return ms
}

// Start launches the periodic cleaner. It is idempotent and does nothing when CleanupInterval is not
// positive; Start after Close returns ErrInvalidConfig. | Start 启动周期清理器。它可重复调用；
// CleanupInterval 非正数时不执行任何操作；Close 之后调用 Start 返回 ErrInvalidConfig。
func (s *MemoryStores) Start() error {
	if s == nil {
		return errs.Detail(ErrInvalidConfig, "memory stores are nil | 内存存储为空")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errs.Detail(ErrInvalidConfig, "memory stores are closed | 内存存储已关闭")
	}
	if s.started || s.interval <= 0 {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	s.cancel = cancel
	s.done = done
	s.started = true
	go s.cleanLoop(ctx, done)
	return nil
}

// cleanLoop sweeps at the configured interval until ctx is canceled. | cleanLoop 按配置周期清扫，
// 直到 ctx 被取消。
func (s *MemoryStores) cleanLoop(ctx context.Context, done chan struct{}) {
	defer close(done)
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// A canceled context ends the loop on the next select; sweep errors are limited to context
			// cancellation and cleanup itself has no other failure mode. | 取消后的上下文会在下一次
			// select 结束循环；清扫错误只可能是上下文取消，清理本身没有其他失败模式。
			_, _ = s.Cleanup(ctx)
		}
	}
}

// Close stops the periodic cleaner and waits for its goroutine. It is idempotent and safe on a nil
// receiver. The stores remain usable for explicit operations after Close. | Close 停止周期清理器并
// 等待其 goroutine。它可重复调用，nil 接收者安全。关闭后存储仍可用于显式操作。
func (s *MemoryStores) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.closed {
		done := s.done
		s.mu.Unlock()
		if done != nil {
			<-done
		}
		return nil
	}
	s.closed = true
	cancel := s.cancel
	done := s.done
	s.cancel = nil
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
	return nil
}

// SetClock replaces the cleanup time source; nil restores the wall clock. It is intended for
// deterministic tests. | SetClock 替换清理时间源；nil 恢复系统时钟。它用于确定性测试。
func (s *MemoryStores) SetClock(clock func() time.Time) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.clock = clock
	s.mu.Unlock()
}

// now returns the current cleanup time in UTC. | now 返回 UTC 的当前清理时间。
func (s *MemoryStores) now() time.Time {
	s.mu.Lock()
	clock := s.clock
	s.mu.Unlock()
	if clock == nil {
		return time.Now().UTC()
	}
	return clock().UTC()
}

// Cleanup performs one sweep and reports the removed counts. Sessions whose absolute or idle
// deadline passed, expired one-time tokens and audit events beyond the retention cap are removed.
// A nil context is treated as context.Background; a canceled context returns its error before any
// mutation. Removing a record makes later lookups report ErrSessionNotFound or ErrTokenInvalid
// instead of an expired result. | Cleanup 执行一次清扫并报告删除数。绝对或空闲期限已过的会话、
// 已过期的一次性令牌以及超过保留上限的审计事件会被删除。nil 上下文视为 context.Background；
// 已取消的上下文会在任何修改前返回其错误。记录被删除后，后续查询将报告 ErrSessionNotFound 或
// ErrTokenInvalid，而不是过期结果。
func (s *MemoryStores) Cleanup(ctx context.Context) (MemoryCleanupResult, error) {
	var result MemoryCleanupResult
	if s == nil {
		return result, errs.Detail(ErrInvalidConfig, "memory stores are nil | 内存存储为空")
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return result, err
		}
	}
	now := s.now()
	result.Sessions = s.sessions.deleteStaleSessions(now)
	removed, err := s.tokens.DeleteExpiredTokens(ctx, now)
	if err != nil {
		return result, err
	}
	result.Tokens = removed
	result.Audits = s.audits.trim()
	return result, nil
}

// deleteStaleSessions removes sessions whose absolute or idle deadline passed at now. Unlike
// DeleteExpiredSessions it also considers IdleExpiresAt, because a session without an absolute
// deadline could otherwise stay in memory forever. | deleteStaleSessions 删除在 now 时刻绝对或空闲
// 期限已过的会话。与 DeleteExpiredSessions 不同，它同时考虑 IdleExpiresAt，否则没有绝对期限的
// 会话可能永远留在内存中。
func (s *MemorySessionStore) deleteStaleSessions(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, session := range s.sessions {
		absolute := !session.ExpiresAt.IsZero() && !now.Before(session.ExpiresAt)
		idle := !session.IdleExpiresAt.IsZero() && !now.Before(session.IdleExpiresAt)
		if absolute || idle {
			delete(s.sessions, id)
			n++
		}
	}
	return n
}

// DeleteExpiredTokens removes tokens whose ExpiresAt passed at now and returns the count. Tokens
// without an expiry are retained, and used-but-unexpired tokens keep reporting ErrTokenUsed until
// their deadline passes. | DeleteExpiredTokens 删除在 now 时刻 ExpiresAt 已过的令牌并返回数量。
// 没有期限的令牌会保留；已使用但未过期的令牌在期限到达前仍报告 ErrTokenUsed。
func (s *MemoryTokenStore) DeleteExpiredTokens(ctx context.Context, now time.Time) (int, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for key, token := range s.tokens {
		if !token.ExpiresAt.IsZero() && !now.Before(token.ExpiresAt) {
			delete(s.tokens, key)
			n++
		}
	}
	return n, nil
}

// SetMaxEvents sets the retained audit event cap and returns how many events were trimmed
// immediately. Zero or negative removes the cap. | SetMaxEvents 设置保留的审计事件上限并返回立即
// 裁剪的事件数。零或负数移除上限。
func (s *MemoryAuditStore) SetMaxEvents(maxEvents int) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maxEvents = maxEvents
	return s.trimLocked()
}

// trim removes events beyond the retention cap and returns the count. | trim 删除超过保留上限的事件
// 并返回数量。
func (s *MemoryAuditStore) trim() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.trimLocked()
}

// trimLocked drops the oldest events beyond maxEvents; the caller must hold s.mu. | trimLocked 丢弃
// 超过 maxEvents 的最旧事件；调用方必须持有 s.mu。
func (s *MemoryAuditStore) trimLocked() int {
	if s.maxEvents <= 0 || len(s.events) <= s.maxEvents {
		return 0
	}
	drop := len(s.events) - s.maxEvents
	remaining := copy(s.events, s.events[drop:])
	clear(s.events[remaining:])
	s.events = s.events[:remaining]
	return drop
}
