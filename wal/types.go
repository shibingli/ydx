package wal

import (
	"context"
	"io"
	"os"
	"time"
)

// Record is one user-visible log record. | Record 是一条用户可见的日志记录。
//
// LSN is ignored on write and filled by the WAL on read. TxnID is ignored by
// Append and filled for records committed through a Tx. Timestamp is UnixNano;
// zero means "use the current time" on write. | LSN 在写入时被忽略、读取时由 WAL
// 填充。TxnID 在普通 Append 时被忽略，通过 Tx 提交的记录读取时由 WAL 填充。
// Timestamp 为 UnixNano，写入时 0 表示使用当前时间。
type Record struct {
	Key       []byte
	Data      []byte
	LSN       uint64
	Timestamp int64
	TxnID     uint64
	Flags     uint16
}

// Time returns the record timestamp as a time.Time. | Time 以 time.Time 返回记录时间戳。
func (r Record) Time() time.Time {
	return time.Unix(0, r.Timestamp)
}

// Clone returns a deep copy of the record's key and data. Key and Data share
// one allocation. | Clone 返回记录 Key 与 Data 的深拷贝；二者共享一次内存分配。
func (r Record) Clone() Record {
	out := r
	if n := len(r.Key) + len(r.Data); n > 0 {
		buf := make([]byte, n)
		copied := copy(buf, r.Key)
		copy(buf[copied:], r.Data)
		out.Key, out.Data = nil, nil
		if copied > 0 {
			out.Key = buf[:copied]
		}
		if copied < n {
			out.Data = buf[copied:]
		}
	}
	return out
}

// Reserved record flags. | 保留的记录标志位。
//
// FlagStreamChunk marks a chunk of a stream and FlagStreamEnd marks the empty
// terminal record of a stream. Bits 2-11 are available to callers. | FlagStreamChunk
// 标记流数据块，FlagStreamEnd 标记流的空结束记录；bit2-11 供调用方使用。
const (
	FlagStreamChunk uint16 = 1 << 0
	FlagStreamEnd   uint16 = 1 << 1
)

// RecordFlagsMask is the set of record flags a caller may carry. | RecordFlagsMask 是调用方可携带的记录标志位集合。
const RecordFlagsMask uint16 = 0x0FFF

// SyncMode selects when the writer synchronizes data. | SyncMode 选择写入协程何时同步数据。
type SyncMode uint8

const (
	// SyncModeAlways synchronizes every commit before it is acknowledged. | SyncModeAlways 在每次确认提交前同步。
	SyncModeAlways SyncMode = iota
	// SyncModeInterval acknowledges writes and synchronizes on a timer. | SyncModeInterval 先确认写入，再按定时器同步。
	SyncModeInterval
	// SyncModeNever synchronizes only on Sync, rotation, truncation, or Close. | SyncModeNever 仅在 Sync、轮转、截断或 Close 时同步。
	SyncModeNever
)

// SyncPolicy configures the durability policy. | SyncPolicy 配置持久化策略。
type SyncPolicy struct {
	Mode     SyncMode
	Interval time.Duration
}

// SyncAlways returns the zero-RPO policy: every commit is synchronized before
// Append returns. | SyncAlways 返回零 RPO 策略：每次提交在 Append 返回前完成同步。
func SyncAlways() SyncPolicy { return SyncPolicy{Mode: SyncModeAlways} }

// SyncInterval returns a policy that synchronizes at most once per interval. | SyncInterval 返回按间隔批量同步的策略。
func SyncInterval(d time.Duration) SyncPolicy {
	return SyncPolicy{Mode: SyncModeInterval, Interval: d}
}

// SyncNever returns a policy that synchronizes only on explicit Sync, rotation,
// truncation, or Close. | SyncNever 返回仅在显式 Sync、轮转、截断或 Close 时
// 同步的策略。
func SyncNever() SyncPolicy { return SyncPolicy{Mode: SyncModeNever} }

// HashAlgorithm selects the content and idempotency digest. | HashAlgorithm 选择内容与幂等摘要算法。
type HashAlgorithm uint8

const (
	// HashSHA256 is the default international digest. | HashSHA256 是默认的国际摘要算法。
	HashSHA256 HashAlgorithm = iota
	// HashSM3 is the Chinese national digest. | HashSM3 是国密摘要算法。
	HashSM3
)

// IsolationLevel selects transaction visibility. | IsolationLevel 选择事务可见性级别。
type IsolationLevel uint8

const (
	// IsolationSnapshot fixes the committed prefix at Begin. | IsolationSnapshot 在 Begin 时固定已提交前缀。
	IsolationSnapshot IsolationLevel = iota
	// IsolationReadCommitted reads the latest committed prefix on each call. | IsolationReadCommitted 每次读取最新已提交前缀。
	IsolationReadCommitted
	// IsolationSerializable adds declared-key optimistic conflict detection. | IsolationSerializable 增加声明键的乐观冲突检测。
	IsolationSerializable
)

// Snapshot is an immutable committed prefix. | Snapshot 是不可变的已提交前缀。
type Snapshot struct {
	CommitSeq uint64
	LastLSN   uint64
}

// StreamInfo describes a chunked stream. | StreamInfo 描述一个分块流。
type StreamInfo struct {
	ID       [16]byte
	FirstLSN uint64
	LastLSN  uint64
	Bytes    uint64
	Chunks   uint64
	Complete bool
}

// TxnInfo is returned by Tx.Commit. | TxnInfo 由 Tx.Commit 返回。
type TxnInfo struct {
	Streams           []StreamInfo
	TxnID             uint64
	CommitSeq         uint64
	FirstLSN          uint64
	LastLSN           uint64
	Records           uint64
	Bytes             uint64
	CommittedUnixNano int64
}

// Stats is a point-in-time snapshot of WAL counters. | Stats 是 WAL 计数器的时间点快照。
type Stats struct {
	FirstLSN, LastLSN          uint64
	CommitSeq                  uint64
	Records, Bytes             uint64
	Segments, SealedSegments   int
	Syncs, SyncErrors          uint64
	GroupBatches, GroupRecords uint64
	CompressedRecords          uint64
	CompressedBytesIn          uint64
	CompressedBytesOut         uint64
	DedupRefs                  uint64
	DedupSavedBytes            uint64
	DedupOverflow              uint64
	IdempotentHits             uint64
	IdempotentConflicts        uint64
	StreamChunks               uint64
	TxnCommits                 uint64
	TxnRollbacks               uint64
	TxnConflicts               uint64
	OpenTxns                   uint64
	ManifestSegments           uint64
	IndexCacheEntries          uint64
	IndexCacheBytes            uint64
	KeyIndexOverflow           uint64
	KeyIndexRebuilds           uint64
	KeyIndexScans              uint64
	CheckpointErrors           uint64
	BackupQueued               uint64
	BackupDone                 uint64
	BackupFailed               uint64
	BackupPending              uint64
	BackupSnapshots            uint64
	BackupSnapshotErrors       uint64
	RetentionSkipped           uint64
	CleanupErrors              uint64
	RecoveryTruncatedBytes     int64
	RecoveryMissingLSNs        uint64
	RecoveryGapIntervals       int
	RecoveryGapDegraded        bool
	RecoveredFromAnchor        bool
	AutoRepaired               bool
	Poisoned                   bool
}

// EngineInfo describes the detected platform fast paths. | EngineInfo 描述探测到的平台快路径。
type EngineInfo struct {
	OS                string
	Arch              string
	HashAlgorithm     string
	CompressionCodecs []string
	BuildTags         []string
	CRC32CHardware    bool
	AESGCMHardware    bool
	SM3Hardware       bool
	SM4Hardware       bool
	IOUring           bool
	Pwritev2DSync     bool
	DirSyncDurable    bool
	Reflink           bool
}

// DedupOptions configures in-segment content deduplication. | DedupOptions 配置段内内容去重。
type DedupOptions struct {
	MinBytes   int
	MaxEntries int
}

// IdempotencyOptions configures the AppendOnce window. | IdempotencyOptions 配置 AppendOnce 幂等窗口。
type IdempotencyOptions struct {
	MaxEntries int
	TTL        time.Duration
}

// Retention configures automatic deletion. | Retention 配置自动保留策略。
type Retention struct {
	MaxAge   time.Duration
	MaxBytes int64
}

// FastPathMode selects how Linux fast paths are chosen. | FastPathMode 选择 Linux 快路径的启用方式。
type FastPathMode uint8

const (
	// FastPathAuto enables safe auto-detection. | FastPathAuto 启用安全的自动探测。
	FastPathAuto FastPathMode = iota
	// FastPathOff disables every Linux fast path. | FastPathOff 关闭全部 Linux 快路径。
	FastPathOff
	// FastPathCustom follows the boolean fields in FastPathOptions. | FastPathCustom 按 FastPathOptions 的布尔字段执行。
	FastPathCustom
)

// FastPathOptions configures optional Linux fast paths. | FastPathOptions 配置可选的 Linux 快路径。
type FastPathOptions struct {
	Mode            FastPathMode
	Pwritev2DSync   bool
	FadviseDontNeed bool
	Preallocate     bool
}

// IOEngine is the pluggable positional I/O engine. | IOEngine 是可插拔的位置写 I/O 引擎。
//
// WriteAt writes every part at off. When syncData is true it must make the data
// durable before returning, handle short writes and EINTR, and it is called by
// the single writer goroutine only. ReadAt must be safe for concurrent callers.
// Close is called once when the WAL no longer needs the engine. | WriteAt 在 off
// 处写入全部 parts；syncData 为 true 时必须在返回前保证持久化，并处理短写与
// EINTR，且只会由单写协程调用。ReadAt 必须支持并发调用。WAL 不再使用引擎时
// 调用一次 Close。
type IOEngine interface {
	WriteAt(f *os.File, parts [][]byte, off int64, syncData bool) error
	ReadAt(f *os.File, dst []byte, off int64) (int, error)
	Sync(f *os.File) error
	Close() error
}

// SegmentMeta describes one sealed segment for backup. | SegmentMeta 描述一个用于备份的封段。
type SegmentMeta struct {
	Seq         uint64
	BaseLSN     uint64
	LastLSN     uint64
	Records     uint64
	Bytes       uint64
	MinTime     int64
	MaxTime     int64
	SegmentCRC  uint32
	IdxCRC      uint32
	CommitSeq   uint64
	CreatedNano int64
	WalID       [16]byte
}

// BackupGap is one accepted missing LSN interval captured in a backup set. |
// BackupGap 是备份集里记录的一个已接受缺失 LSN 区间。
type BackupGap struct {
	Start uint64
	End   uint64
}

// BackupSet is a consistent, restore-complete backup snapshot: the metadata
// needed to rebuild META, MANIFEST, and the recovery anchor together with the
// sealed segments that cover [FirstLSN, LastLSN]. | BackupSet 是一个一致、
// 可完整恢复的备份快照：包含重建 META、MANIFEST 与恢复锚点所需的元数据，以及
// 覆盖 [FirstLSN,LastLSN] 的封段清单。
type BackupSet struct {
	Segments      []SegmentMeta
	Gaps          []BackupGap
	CreatedNano   int64
	FirstLSN      uint64
	LastLSN       uint64
	NextLSN       uint64
	NextSeq       uint64
	CommitSeq     uint64
	ActiveKeyKCV  uint64
	ActiveKeyID   uint32
	WalID         [16]byte
	Encrypted     bool
	Serializable  bool
	HashAlgorithm HashAlgorithm
}

// SnapshotBackup is implemented by backup targets that can atomically publish
// a restore-complete backup set. BackupSnapshot is called after every segment
// in the set has been uploaded; implementations must write the set metadata
// last and atomically (tmp + fsync + rename + directory fsync). It runs on the
// BackupNow caller goroutine and must not call back into blocking WAL methods. |
// SnapshotBackup 由能够原子发布完整恢复集的备份目标实现。集合中每个分段上传
// 成功后才会调用 BackupSnapshot；实现必须最后写入集合元数据，并保证原子性
// （tmp + fsync + rename + 目录 fsync）。它运行在 BackupNow 调用方协程上，
// 不得回调会阻塞的 WAL 方法。
type SnapshotBackup interface {
	BackupSnapshot(ctx context.Context, set BackupSet) error
}

// SegmentBundle carries the readers for one sealed segment. | SegmentBundle 携带一个封段的读取器。
//
// Data and Index are valid only during the Backup call. An implementation that
// needs to upload asynchronously must copy the bytes or finish inside the call.
// | Data 与 Index 仅在 Backup 调用期间有效；需要异步上传的实现必须先复制，或在
// 调用内完成。
type SegmentBundle struct {
	Data  io.Reader
	Index io.Reader
	Meta  SegmentMeta
}

// Backup is the pluggable asynchronous backup target. | Backup 是可插拔的异步备份目标。
//
// Backup and Verify callbacks run on backup workers; they must not call back
// into blocking WAL methods such as Close, FlushBackups, or BackupNow. |
// Backup 与 Verify 回调运行在备份 worker 上；不得回调 Close、FlushBackups 或
// BackupNow 等会阻塞的 WAL 方法。
type Backup interface {
	// Target returns a stable target identifier; changing it invalidates old
	// .bak markers and triggers re-upload. | Target 返回稳定的目标标识；返回值
	// 改变会使旧 .bak 标记失效并触发重传。
	Target() string
	// Backup consumes Data and Index until EOF and must make the target object
	// atomic on its own. | Backup 读取 Data/Index 直到 EOF，并自行保证目标对象的原子性。
	Backup(ctx context.Context, seg SegmentBundle) error
}

// BackupVerifier is an optional interface that proves a segment exists at the
// target. | BackupVerifier 是可选接口，用于证实分段确实完整存在于目标端。
type BackupVerifier interface {
	Verify(ctx context.Context, meta SegmentMeta) error
}

// Indexer is an optional post-commit hook. | Indexer 是可选的提交后索引钩子。
//
// Index runs on the caller goroutine after the record is durable and before
// Append returns. The key and data slices are valid only during the call; the
// implementation must not retain them or call back into the WAL. | Index 在记录
// 持久化后、Append 返回前由调用方协程执行；key/data 仅在调用期间有效，实现不得
// 保留切片，也不得回调 WAL。
type Indexer interface {
	Index(meta RecordMeta, key, data []byte)
}

// RecordMeta is the metadata passed to Indexer. | RecordMeta 是传给 Indexer 的元数据。
type RecordMeta struct {
	LSN       uint64
	Timestamp int64
	TxnID     uint64
	Flags     uint16
	KeyLen    int
	DataLen   int
}

// Query filters a WAL scan. | Query 过滤 WAL 扫描。
type Query struct {
	Since    time.Time
	Until    time.Time
	Key      []byte
	Contains []byte
	From     uint64
	To       uint64
	Limit    int
}
