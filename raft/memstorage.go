package raft

import (
	"sync"

	"github.com/shibingli/ydx/errs"
)

// MemStorage is an in-memory Storage implementation for tests, ephemeral
// clusters and benchmarking. It provides no durability across process restarts.
// | MemStorage 是用于测试、临时集群与基准的内存 Storage 实现，进程重启后不提供
// 持久性。
type MemStorage struct {
	snap    *Snapshot
	entries []Entry
	hard    HardState
	mu      sync.Mutex
}

// NewMemStorage returns an empty in-memory store. | NewMemStorage 返回空的内存存储。
func NewMemStorage() *MemStorage {
	return &MemStorage{}
}

// Load implements Storage. | Load 实现 Storage。
func (s *MemStorage) Load() (Recovery, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := Recovery{HardState: s.hard}
	if s.snap != nil {
		rec.Snapshot = s.snap.clone()
	}
	base := uint64(0)
	if s.snap != nil {
		base = s.snap.Index
	}
	for i := range s.entries {
		if s.entries[i].Index <= base {
			continue
		}
		if len(rec.Entries) == 0 {
			if s.entries[i].Index != base+1 {
				return Recovery{}, errs.Detail(ErrCorrupt,
					"storage starts at %d, want %d", s.entries[i].Index, base+1)
			}
		} else if s.entries[i].Index != rec.Entries[len(rec.Entries)-1].Index+1 {
			return Recovery{}, errs.Detail(ErrCorrupt, "storage gap at index %d", s.entries[i].Index)
		}
		rec.Entries = append(rec.Entries, s.entries[i].clone())
	}
	return rec, nil
}

// Persist implements Storage. | Persist 实现 Storage。
func (s *MemStorage) Persist(batch PersistBatch) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if batch.Snapshot != nil && (s.snap == nil || batch.Snapshot.Index > s.snap.Index) {
		// Snapshot data is immutable by contract; retaining the caller's image
		// avoids duplicating a potentially large payload in the in-memory store.
		// Older images are ignored so a delayed completion cannot regress the
		// base below newer committed state. | 快照数据按约定不可变；保留调用方镜像
		// 可避免在内存存储中复制大负载。更旧的镜像会被忽略，避免迟到的完成把基点
		// 回退到更新的已提交状态之下。
		s.snap = batch.Snapshot
		if batch.SnapshotReplacesLog {
			s.entries = nil
		} else {
			cut := 0
			for cut < len(s.entries) && s.entries[cut].Index <= s.snap.Index {
				cut++
			}
			if cut > 0 {
				s.entries = append([]Entry(nil), s.entries[cut:]...)
			}
		}
	}
	if batch.Truncate > 0 {
		s.truncateLocked(batch.Truncate)
	}
	if len(batch.Entries) > 0 && cap(s.entries)-len(s.entries) < len(batch.Entries) {
		// Grow once with a doubling policy; the per-entry append below then never
		// reallocates on the common append-only path. | 一次性按翻倍策略扩容，下面的
		// 逐项追加在常见的只追加路径上不再重新分配。
		s.entries = growEntries(s.entries, len(batch.Entries))
	}
	for i := range batch.Entries {
		e := batch.Entries[i]
		if e.Index == 0 {
			return errs.Detail(ErrInvalidConfig, "entry index zero")
		}
		// Entries covered by the current snapshot base are already durable in
		// the image and must not re-enter the log out of order. | 当前快照基点
		// 覆盖的日志项已在镜像中持久化，不得乱序重新进入日志。
		if s.snap != nil && e.Index <= s.snap.Index {
			continue
		}
		if len(s.entries) == 0 {
			base := uint64(0)
			if s.snap != nil {
				base = s.snap.Index
			}
			if e.Index != base+1 {
				return errs.Detail(ErrCorrupt, "storage gap at index %d, want %d", e.Index, base+1)
			}
		}
		if len(s.entries) > 0 {
			last := s.entries[len(s.entries)-1]
			switch {
			case e.Index <= last.Index:
				pos := int(e.Index - s.entries[0].Index)
				if pos >= 0 && pos < len(s.entries) {
					if s.entries[pos].Term == e.Term {
						continue
					}
					s.entries = s.entries[:pos]
				}
			case e.Index != last.Index+1:
				return errs.Detail(ErrCorrupt, "non-contiguous entry %d after %d", e.Index, last.Index)
			}
		}
		// Entries are immutable after append; the Raft log copies on truncate,
		// so storing the value avoids a second data copy on the hot path. | 日志项
		// 追加后不可变；Raft 日志在截断时复制，因此直接存值可避免热路径上的第二次
		// 数据复制。
		s.entries = append(s.entries, e)
	}
	if batch.HardState != nil {
		s.hard = *batch.HardState
	}
	return nil
}

// truncateLocked removes entries with index >= index. | truncateLocked 删除索引不小于
// index 的日志项。
func (s *MemStorage) truncateLocked(index uint64) {
	if len(s.entries) == 0 {
		return
	}
	if index <= s.entries[0].Index {
		s.entries = nil
		return
	}
	cut := int(index - s.entries[0].Index)
	if cut < len(s.entries) {
		s.entries = s.entries[:cut]
	}
}

// Compact implements Storage. | Compact 实现 Storage。
func (s *MemStorage) Compact(index uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.snap == nil || s.snap.Index < index {
		return errs.Detail(ErrCompacted, "no snapshot at %d", index)
	}
	cut := 0
	for cut < len(s.entries) && s.entries[cut].Index <= index {
		cut++
	}
	if cut > 0 {
		s.entries = append([]Entry(nil), s.entries[cut:]...)
	}
	return nil
}

// PersistImmediate implements ImmediateStorage. | PersistImmediate 实现
// ImmediateStorage。
func (s *MemStorage) PersistImmediate() bool { return true }

// Close implements Storage. | Close 实现 Storage。
func (s *MemStorage) Close() error { return nil }
