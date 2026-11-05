package raft

// Recovery is the durable state loaded at startup. Entries must be contiguous
// and immediately follow Snapshot. | Recovery 是启动时加载的持久状态。Entries 必须
// 连续，且紧接在 Snapshot 之后。
type Recovery struct {
	HardState HardState
	Snapshot  *Snapshot
	Entries   []Entry
}

// PersistBatch is one durable write. Truncate, when non-zero, removes every
// stored entry with index >= Truncate before Entries are appended. Snapshot,
// when non-nil, installs a snapshot. SnapshotReplacesLog distinguishes an
// InstallSnapshot (the follower's entire log is stale) from a local compaction
// snapshot (entries after the snapshot remain valid). | PersistBatch 是一次持久写。
// Truncate 非零时先删除索引不小于 Truncate 的已存日志项，再追加 Entries。Snapshot
// 非空时安装快照。SnapshotReplacesLog 区分 InstallSnapshot（跟随者整段旧日志都已
// 失效）与本地压缩快照（快照之后的日志项仍然有效）。
type PersistBatch struct {
	HardState           *HardState
	Truncate            uint64
	Entries             []Entry
	Snapshot            *Snapshot
	SnapshotReplacesLog bool
}

// ImmediateStorage is an optional optimization for in-memory or otherwise
// O(1) stores. When PersistImmediate reports true, the Raft event loop calls
// Persist directly instead of handing the batch to the writer goroutine. The
// store must be fast, non-blocking and safe against the event loop; FileStorage
// deliberately does not implement this. | ImmediateStorage 是内存型或 O(1) 存储的
// 可选优化。PersistImmediate 返回 true 时，Raft 事件循环直接调用 Persist，而不是
// 交给写协程。存储必须快速、非阻塞且可被事件循环安全调用；FileStorage 有意不实现。
type ImmediateStorage interface {
	Storage
	PersistImmediate() bool
}

// ImmediateTransport is an optional optimization for transports whose Send only
// enqueues and never blocks. When SendImmediate reports true the event loop
// calls Send directly and may reuse the message slice after it returns; the
// transport must not retain the slice or its backing array. | ImmediateTransport
// 是 Send 只入队且从不阻塞的传输的可选优化。SendImmediate 返回 true 时，事件循环
// 直接调用 Send，并在返回后复用消息切片；传输不得保留该切片或其底层数组。
type ImmediateTransport interface {
	Transport
	SendImmediate() bool
}

// Storage is the durable backend. Persist must not return until the batch is
// durable for the configured durability level; Raft safety depends on that
// ordering. Implementations are used by a single writer goroutine and may assume
// no concurrent Persist calls, but Load and Close must be safe against it.
// | Storage 是持久化后端。Persist 在批次达到配置的持久级别前不得返回；Raft 安全
// 性依赖该顺序。实现由单个写协程调用，可假定 Persist 不并发，但 Load 与 Close 必须
// 能安全并发。
type Storage interface {
	// Load returns the durable snapshot, hard state and entries after it. | Load
	// 返回持久快照、硬状态及其后的日志项。
	Load() (Recovery, error)
	// Persist atomically applies one durable batch. | Persist 原子应用一个持久批次。
	Persist(batch PersistBatch) error
	// Compact releases entries through index; the latest snapshot must cover it.
	// | Compact 释放 index 及之前的日志项；最新快照必须覆盖该索引。
	Compact(index uint64) error
	// Close flushes and releases resources. | Close 刷新并释放资源。
	Close() error
}
