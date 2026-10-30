package cron

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/shibingli/ydx/errs"
)

// Store persists job definitions. Scheduler.Start loads every definition it
// returns, and Add, Update, Pause, Resume and Remove write through it. An
// implementation must be safe for concurrent use and must copy the Metadata map
// it stores or returns, so callers cannot mutate stored state by aliasing it. |
// Store 持久化任务定义：Scheduler.Start 加载其返回的全部定义，Add、Update、Pause、
// Resume 与 Remove 会写穿到它。实现必须并发安全，并复制存入或返回的 Metadata 映射，
// 避免调用方通过别名修改存储状态。
type Store interface {
	// Save inserts or replaces a definition. | Save 插入或替换定义。
	Save(ctx context.Context, definition Definition) error
	// Delete removes the definition with id; a missing id is not an error. | Delete 删除 id 对应的定义；不存在不报错。
	Delete(ctx context.Context, id string) error
	// List returns every stored definition. | List 返回全部已存定义。
	List(ctx context.Context) ([]Definition, error)
}

// Locker coordinates Singleton jobs across nodes. TryLock must be atomic: when
// two nodes race for the same key, at most one receives ok. The returned Lock is
// owner-specific, so Unlock and Refresh never affect another owner's claim.
// Claims for scheduled fires are kept until their TTL expires, so the TTL is
// also the deduplication window; implement LockRefresher when a run may outlive
// the TTL. | Locker 在多节点间协调 Singleton 任务。TryLock 必须原子：两个节点竞争同一键时
// 最多一个得到 ok。返回的 Lock 绑定持有者，Unlock 与 Refresh 不会影响其它持有者的锁。
// 计划触发的锁保留到 TTL 过期，因此 TTL 也是去重窗口；运行可能超过 TTL 时应实现 LockRefresher。
type Locker interface {
	// TryLock claims key for ttl, reporting ok=false when it is already held. |
	// TryLock 以 ttl 抢占 key，已被占用时返回 ok=false。
	TryLock(ctx context.Context, key string, ttl time.Duration) (Lock, bool, error)
}

// Lock is one acquired claim. | Lock 是一个已获取的锁。
type Lock interface {
	// Unlock releases the claim only when this owner still holds it. | Unlock 仅当本持有者仍持有时释放。
	Unlock(ctx context.Context) error
}

// LockRefresher is an optional extension: when a Lock implements it, the
// scheduler extends the claim while a long run is in flight and cancels the run
// if the claim was lost. | LockRefresher 是可选扩展：Lock 实现它时，调度器会在长任务运行期间
// 续租，并在锁丢失时取消运行。
type LockRefresher interface {
	// Refresh extends the claim; ok=false means the claim was lost. | Refresh 续租；ok=false 表示锁已丢失。
	Refresh(ctx context.Context, ttl time.Duration) (bool, error)
}

// MemoryStore is an in-process Store for tests and single-node deployments. It
// is safe for concurrent use and copies every definition in and out. |
// MemoryStore 是用于测试与单机部署的进程内 Store；并发安全，并在存入与返回时复制定义。
type MemoryStore struct {
	definitions map[string]Definition
	mu          sync.RWMutex
}

// NewMemoryStore returns an empty in-memory store. | NewMemoryStore 返回空的内存存储。
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{definitions: make(map[string]Definition)}
}

// Save inserts or replaces a definition. | Save 插入或替换定义。
func (m *MemoryStore) Save(ctx context.Context, definition Definition) error {
	if err := ctxError(ctx); err != nil {
		return err
	}
	if definition.ID == "" {
		return errs.Detail(ErrInvalidDefinition, "empty id")
	}
	stored := definition
	stored.Metadata = copyMetadata(definition.Metadata)
	m.mu.Lock()
	m.definitions[definition.ID] = stored
	m.mu.Unlock()
	return nil
}

// Delete removes a definition; a missing id is not an error. | Delete 删除定义；不存在不报错。
func (m *MemoryStore) Delete(ctx context.Context, id string) error {
	if err := ctxError(ctx); err != nil {
		return err
	}
	m.mu.Lock()
	delete(m.definitions, id)
	m.mu.Unlock()
	return nil
}

// List returns every definition ordered by id. | List 按 ID 排序返回全部定义。
func (m *MemoryStore) List(ctx context.Context) ([]Definition, error) {
	if err := ctxError(ctx); err != nil {
		return nil, err
	}
	m.mu.RLock()
	definitions := make([]Definition, 0, len(m.definitions))
	for _, definition := range m.definitions {
		stored := definition
		stored.Metadata = copyMetadata(definition.Metadata)
		definitions = append(definitions, stored)
	}
	m.mu.RUnlock()
	sort.Slice(definitions, func(i, j int) bool { return definitions[i].ID < definitions[j].ID })
	return definitions, nil
}

// ctxError turns a cancelled context into a declared store error. |
// ctxError 把已取消的上下文转为已声明的存储错误。
func ctxError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return errs.Wrap(err, ErrStoreFailed)
	}
	return nil
}
