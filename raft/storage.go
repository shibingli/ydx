package raft

// Recovery is the durable state loaded at startup. Entries must be contiguous
// and immediately follow Snapshot. | Recovery 是启动时加载的持久状态。Entries 必须
// 连续，且紧接在 Snapshot 之后。
type Recovery struct {
	Snapshot  *Snapshot
	Entries   []Entry
	HardState HardState
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
	Snapshot            *Snapshot
	Entries             []Entry
	Truncate            uint64
	SnapshotReplacesLog bool
}

// localSnapshotFileStorage is implemented by storages that can write a local
// (non-InstallSnapshot) image independently, then append its WAL marker later.
// This lets a large snapshot fsync overlap ongoing WAL group commits.
// | localSnapshotFileStorage 由能够独立写入本地（非 InstallSnapshot）镜像、随后
// 追加 WAL 标记的存储实现。这样大快照的 fsync 可以与持续的 WAL 组提交重叠。
type localSnapshotFileStorage interface {
	WriteSnapshotFile(snap *Snapshot) error
	PersistLocalSnapshotMarker(snap *Snapshot, hs *HardState) error
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
// ordering. A Snapshot batch installs the image and its durability marker;
// Compact, which the node calls immediately afterwards, releases the entries the
// image covers. Implementations are used by a single writer goroutine and may
// assume no concurrent Persist calls, but Load and Close must be safe against it.
// | Storage 是持久化后端。Persist 在批次达到配置的持久级别前不得返回；Raft 安全
// 性依赖该顺序。Snapshot 批次安装镜像及其持久标记；节点随后立即调用 Compact
// 释放镜像覆盖的日志项。实现由单个写协程调用，可假定 Persist 不并发，但 Load 与
// Close 必须能安全并发。
type Storage interface {
	// Load returns the durable snapshot, hard state and entries after it. The
	// returned Snapshot and Entries become owned by the caller: implementations
	// must not reuse or mutate them afterwards. | Load 返回持久快照、硬状态及其后的
	// 日志项。返回的 Snapshot 与 Entries 归调用方所有：实现此后不得复用或修改它们。
	Load() (Recovery, error)
	// Persist atomically applies one durable batch. | Persist 原子应用一个持久批次。
	Persist(batch PersistBatch) error
	// Compact releases entries through index; the latest snapshot must cover it.
	// | Compact 释放 index 及之前的日志项；最新快照必须覆盖该索引。
	Compact(index uint64) error
	// Close flushes and releases resources. | Close 刷新并释放资源。
	Close() error
}
