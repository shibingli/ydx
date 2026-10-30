package cron

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// MemoryLocker is an in-process Locker. It coordinates schedulers inside one
// process (tests, embedded workers) and is deliberately not a substitute for a
// shared backend in a multi-node deployment. | MemoryLocker 是进程内 Locker，
// 用于协调同一进程内的多个调度器（测试、嵌入式工作进程）；在多机部署中不能替代共享后端。
type MemoryLocker struct {
	locks map[string]memoryClaim
	seq   atomic.Uint64
	mu    sync.Mutex
}

// memoryClaim records the owner token and expiry of one key. | memoryClaim 记录一个键的持有者令牌与到期时间。
type memoryClaim struct {
	expires time.Time
	token   uint64
}

// memoryLock is one acquired claim. | memoryLock 是一个已获取的锁。
type memoryLock struct {
	locker *MemoryLocker
	key    string
	token  uint64
}

// NewMemoryLocker returns an empty in-process locker. | NewMemoryLocker 返回空的进程内锁。
func NewMemoryLocker() *MemoryLocker {
	return &MemoryLocker{locks: make(map[string]memoryClaim)}
}

// TryLock claims key for ttl; an expired claim is reclaimable. |
// TryLock 以 ttl 抢占 key；已过期的锁可被回收。
func (m *MemoryLocker) TryLock(ctx context.Context, key string, ttl time.Duration) (Lock, bool, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
	}
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	if current, held := m.locks[key]; held && current.expires.After(now) {
		return nil, false, nil
	}
	token := m.seq.Add(1)
	m.locks[key] = memoryClaim{token: token, expires: now.Add(ttl)}
	return &memoryLock{locker: m, key: key, token: token}, true, nil
}

// Unlock releases the claim only when this owner still holds it. |
// Unlock 仅在本持有者仍持有时释放。
func (l *memoryLock) Unlock(ctx context.Context) error {
	if l == nil || l.locker == nil {
		return nil
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	l.locker.mu.Lock()
	defer l.locker.mu.Unlock()
	if current, held := l.locker.locks[l.key]; held && current.token == l.token {
		delete(l.locker.locks, l.key)
	}
	return nil
}

// Refresh extends the claim; it reports false once the claim expired or was
// replaced by another owner. | Refresh 续租；锁已过期或被其它持有者替换时返回 false。
func (l *memoryLock) Refresh(ctx context.Context, ttl time.Duration) (bool, error) {
	if l == nil || l.locker == nil {
		return false, nil
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return false, err
		}
	}
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	now := time.Now()
	l.locker.mu.Lock()
	defer l.locker.mu.Unlock()
	current, held := l.locker.locks[l.key]
	if !held || current.token != l.token || !current.expires.After(now) {
		return false, nil
	}
	current.expires = now.Add(ttl)
	l.locker.locks[l.key] = current
	return true, nil
}

// compile-time assertions for the in-process implementations. | 进程内实现的编译期断言。
var (
	_ Locker        = (*MemoryLocker)(nil)
	_ Lock          = (*memoryLock)(nil)
	_ LockRefresher = (*memoryLock)(nil)
	_ Store         = (*MemoryStore)(nil)
)
