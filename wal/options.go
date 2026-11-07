package wal

import (
	"os"
	"time"

	"github.com/shibingli/ydx/errs"
)

// Default configuration values. | 默认配置值。
const (
	defaultSegmentMaxBytes                   = int64(64 << 20)
	defaultMaxRecordBytes                    = 16 << 20
	defaultQueueSize                         = 4096
	defaultMaxBatchRecords                   = 512
	defaultMaxBatchBytes                     = 4 << 20
	defaultMaxWritevParts                    = 512
	defaultIndexIntervalBytes                = 32 << 10
	defaultIndexRecordsPerEntry              = 64
	defaultCheckpointBytes                   = int64(8 << 20)
	defaultIndexCacheBytes                   = int64(64 << 20)
	defaultReadFDCacheSize                   = 32
	defaultManifestShardRecords              = 4096
	defaultManifestCompactRatio              = 0.5
	defaultManifestGapProbeMax               = 64
	defaultStreamChunkSize                   = 1 << 20
	defaultTxnMaxBytes                       = int64(4 << 20)
	defaultTxnMaxRecords                     = uint64(1_000_000)
	defaultTxnConflictWindow                 = uint64(65536)
	defaultTxnMaxKeys                        = 4096
	defaultTxnConflictMaxEntries             = 1_048_576
	defaultTxnConflictScanBytes              = int64(64 << 20)
	defaultKeyIndexMaxEntries                = 1_000_000
	defaultKeyIndexMaxKeyBytes               = 4096
	defaultDedupMinBytes                     = 1 << 10
	defaultDedupMaxEntries                   = 1_048_576
	defaultIdemMaxEntries                    = 65536
	defaultBackupWorkers                     = 2
	defaultVerifyTimeout                     = 30 * time.Second
	defaultSyncInterval                      = 10 * time.Millisecond
	defaultReaderBuffer                      = 64 << 10
	defaultFileMode              os.FileMode = 0o600
	defaultDirMode               os.FileMode = 0o700
	formatHardLimit                          = 1 << 30
	recordHeaderSize                         = 48
	recordHeaderSizeEncrypted                = 60
	aeadTagSize                              = 16
	nonceSize                                = 12
	// maxDenseRecords bounds the optional dense LSN-to-offset index. | maxDenseRecords 限制可选的稠密 LSN→偏移索引。
	maxDenseRecords = 1 << 20
)

// options is the normalized, private Open configuration. | options 是归一化后的私有 Open 配置。
type options struct {
	backup                 Backup
	indexer                Indexer
	ioEngine               IOEngine
	keyRing                *KeyRing
	errorHandler           func(error)
	compression            Compression
	syncPolicy             SyncPolicy
	dedup                  DedupOptions
	idempotency            IdempotencyOptions
	retention              Retention
	segmentMaxBytes        int64
	segmentMaxAge          time.Duration
	segmentMaxRecords      uint64
	maxRecordBytes         int
	queueSize              int
	maxBatchRecords        int
	maxBatchBytes          int
	maxWritevParts         int
	indexIntervalBytes     int
	checkpointBytes        int64
	indexCacheBytes        int64
	readFDCacheSize        int
	manifestShardRecords   int
	manifestCompactRatio   float64
	manifestGapProbeMax    int
	streamChunkSize        int
	txnMaxBytes            int64
	txnMaxRecords          uint64
	txnConflictWindow      uint64
	txnMaxKeys             int
	txnConflictMaxEntries  int
	txnConflictScanBytes   int64
	keyIndexMaxEntries     int
	keyIndexMaxKeyBytes    int
	backupWorkers          int
	backupMaxPending       int
	backupVerifyTimeout    time.Duration
	retentionVerifyTimeout time.Duration
	fileMode               os.FileMode
	dirMode                os.FileMode
	fastPath               FastPathOptions
	manifestEnabled        bool
	defaultIsolation       IsolationLevel
	serializableDurability bool
	keyIndex               bool
	plaintextKeyIndex      bool
	allowPlaintext         bool
	skipKeyCheck           bool
	hashAlgorithm          HashAlgorithm
	hashAlgorithmSet       bool
	dedupEnabled           bool
	idempotencyEnabled     bool
	retentionEnabled       bool
	monotonicTimestamps    bool
	macFullFsync           bool
	readOnly               bool
	noLock                 bool
	allowLSNGaps           bool
	autoRepair             bool
}

// Option customizes Open. | Option 定制 Open 行为。
type Option func(*options)

func defaultOptions() options {
	return options{
		syncPolicy:             SyncAlways(),
		segmentMaxBytes:        defaultSegmentMaxBytes,
		maxRecordBytes:         defaultMaxRecordBytes,
		queueSize:              defaultQueueSize,
		maxBatchRecords:        defaultMaxBatchRecords,
		maxBatchBytes:          defaultMaxBatchBytes,
		maxWritevParts:         defaultMaxWritevParts,
		indexIntervalBytes:     defaultIndexIntervalBytes,
		checkpointBytes:        defaultCheckpointBytes,
		indexCacheBytes:        defaultIndexCacheBytes,
		readFDCacheSize:        defaultReadFDCacheSize,
		manifestEnabled:        true,
		manifestShardRecords:   defaultManifestShardRecords,
		manifestCompactRatio:   defaultManifestCompactRatio,
		manifestGapProbeMax:    defaultManifestGapProbeMax,
		streamChunkSize:        defaultStreamChunkSize,
		defaultIsolation:       IsolationSnapshot,
		txnMaxBytes:            defaultTxnMaxBytes,
		txnMaxRecords:          defaultTxnMaxRecords,
		txnConflictWindow:      defaultTxnConflictWindow,
		txnMaxKeys:             defaultTxnMaxKeys,
		txnConflictMaxEntries:  defaultTxnConflictMaxEntries,
		txnConflictScanBytes:   defaultTxnConflictScanBytes,
		keyIndexMaxEntries:     defaultKeyIndexMaxEntries,
		keyIndexMaxKeyBytes:    defaultKeyIndexMaxKeyBytes,
		hashAlgorithm:          HashSHA256,
		backupWorkers:          defaultBackupWorkers,
		backupVerifyTimeout:    defaultVerifyTimeout,
		retentionVerifyTimeout: defaultVerifyTimeout,
		fastPath:               FastPathOptions{Mode: FastPathAuto, Pwritev2DSync: true},
		macFullFsync:           true,
		autoRepair:             true,
		fileMode:               defaultFileMode,
		dirMode:                defaultDirMode,
	}
}

// WithSyncPolicy sets the durability policy. | WithSyncPolicy 设置持久化策略。
func WithSyncPolicy(p SyncPolicy) Option { return func(o *options) { o.syncPolicy = p } }

// WithSegmentMaxBytes sets the rotation size threshold. | WithSegmentMaxBytes 设置按大小轮转的阈值。
func WithSegmentMaxBytes(n int64) Option { return func(o *options) { o.segmentMaxBytes = n } }

// WithSegmentMaxAge sets the rotation age threshold; zero disables it. | WithSegmentMaxAge 设置按时间轮转的阈值，0 表示关闭。
func WithSegmentMaxAge(d time.Duration) Option { return func(o *options) { o.segmentMaxAge = d } }

// WithSegmentMaxRecords sets the rotation record threshold; zero disables it. | WithSegmentMaxRecords 设置按记录数轮转的阈值，0 表示关闭。
func WithSegmentMaxRecords(n uint64) Option { return func(o *options) { o.segmentMaxRecords = n } }

// WithMaxRecordBytes sets the maximum size of a newly written record. | WithMaxRecordBytes 设置新写入记录的最大字节数。
func WithMaxRecordBytes(n int) Option { return func(o *options) { o.maxRecordBytes = n } }

// WithQueueSize sets the bounded append queue capacity. | WithQueueSize 设置有界追加队列容量。
func WithQueueSize(n int) Option { return func(o *options) { o.queueSize = n } }

// WithMaxBatchRecords sets the group-commit record limit. | WithMaxBatchRecords 设置组提交的记录数上限。
func WithMaxBatchRecords(n int) Option { return func(o *options) { o.maxBatchRecords = n } }

// WithMaxBatchBytes sets the group-commit byte limit. | WithMaxBatchBytes 设置组提交的字节数上限。
func WithMaxBatchBytes(n int) Option { return func(o *options) { o.maxBatchBytes = n } }

// WithMaxWritevParts sets the maximum iovec parts per write call. | WithMaxWritevParts 设置单次写入的 iovec 分片上限。
func WithMaxWritevParts(n int) Option { return func(o *options) { o.maxWritevParts = n } }

// WithIndexIntervalBytes sets the sparse-index byte interval. | WithIndexIntervalBytes 设置稀疏索引的字节间隔。
func WithIndexIntervalBytes(n int) Option { return func(o *options) { o.indexIntervalBytes = n } }

// WithCheckpointBytes sets the active-segment checkpoint interval. | WithCheckpointBytes 设置活动段检查点间隔。
func WithCheckpointBytes(n int64) Option { return func(o *options) { o.checkpointBytes = n } }

// WithIndexCacheBytes sets the sparse-index cache budget. | WithIndexCacheBytes 设置稀疏索引缓存上限。
func WithIndexCacheBytes(n int64) Option { return func(o *options) { o.indexCacheBytes = n } }

// WithReadFDCacheSize sets the random-read fd cache size. | WithReadFDCacheSize 设置随机读 fd 缓存数量。
func WithReadFDCacheSize(n int) Option { return func(o *options) { o.readFDCacheSize = n } }

// WithManifest enables or disables the sharded segment manifest. | WithManifest 启用或关闭分片段目录。
func WithManifest(enabled bool) Option { return func(o *options) { o.manifestEnabled = enabled } }

// WithManifestShardRecords sets the record count per manifest shard. | WithManifestShardRecords 设置每个 MANIFEST 分片的记录数。
func WithManifestShardRecords(n int) Option { return func(o *options) { o.manifestShardRecords = n } }

// WithManifestCompactRatio sets the stale ratio that triggers shard compaction. | WithManifestCompactRatio 设置触发分片压缩的陈旧比例。
func WithManifestCompactRatio(r float64) Option {
	return func(o *options) { o.manifestCompactRatio = r }
}

// WithManifestGapProbeMax sets the per-sequence stat probe limit. | WithManifestGapProbeMax 设置逐序号 stat 探测上限。
func WithManifestGapProbeMax(n int) Option { return func(o *options) { o.manifestGapProbeMax = n } }

// WithStreamChunkSize sets the AppendStream chunk size. | WithStreamChunkSize 设置 AppendStream 分块大小。
func WithStreamChunkSize(n int) Option { return func(o *options) { o.streamChunkSize = n } }

// WithDefaultIsolation sets the default transaction isolation level. | WithDefaultIsolation 设置默认事务隔离级别。
func WithDefaultIsolation(l IsolationLevel) Option {
	return func(o *options) { o.defaultIsolation = l }
}

// WithTxnMaxBytes sets the transaction buffer byte limit. | WithTxnMaxBytes 设置事务缓冲字节上限。
func WithTxnMaxBytes(n int64) Option { return func(o *options) { o.txnMaxBytes = n } }

// WithTxnMaxRecords sets the transaction record limit. | WithTxnMaxRecords 设置事务记录数上限。
func WithTxnMaxRecords(n uint64) Option { return func(o *options) { o.txnMaxRecords = n } }

// WithTxnConflictWindow sets the serializable conflict window. | WithTxnConflictWindow 设置可串行化冲突窗口。
func WithTxnConflictWindow(n uint64) Option { return func(o *options) { o.txnConflictWindow = n } }

// WithSerializableDurability persists declared write-key digests in transaction
// control records. It must be enabled when the WAL is created. | WithSerializableDurability
// 在事务控制记录中持久化声明的写键摘要；必须在创建 WAL 时启用。
func WithSerializableDurability(enabled bool) Option {
	return func(o *options) { o.serializableDurability = enabled }
}

// WithTxnMaxKeys sets the read+write key limit per transaction. | WithTxnMaxKeys 设置单事务读+写键合计上限。
func WithTxnMaxKeys(n int) Option { return func(o *options) { o.txnMaxKeys = n } }

// WithTxnConflictMaxEntries sets the keyVersion table limit. | WithTxnConflictMaxEntries 设置 keyVersion 表上限。
func WithTxnConflictMaxEntries(n int) Option {
	return func(o *options) { o.txnConflictMaxEntries = n }
}

// WithTxnConflictScanBytes sets the Open-time conflict-window rebuild budget. | WithTxnConflictScanBytes 设置 Open 重建冲突窗口的扫描预算。
func WithTxnConflictScanBytes(n int64) Option {
	return func(o *options) { o.txnConflictScanBytes = n }
}

// WithKeyIndex enables the in-memory Key index. | WithKeyIndex 启用内存 Key 索引。
func WithKeyIndex(enabled bool) Option { return func(o *options) { o.keyIndex = enabled } }

// WithKeyIndexMaxEntries sets the Key index entry limit. | WithKeyIndexMaxEntries 设置 Key 索引条目上限。
func WithKeyIndexMaxEntries(n int) Option { return func(o *options) { o.keyIndexMaxEntries = n } }

// WithKeyIndexMaxKeyBytes sets the maximum key length stored in the Key index. | WithKeyIndexMaxKeyBytes 设置进入 Key 索引的最大键长度。
func WithKeyIndexMaxKeyBytes(n int) Option { return func(o *options) { o.keyIndexMaxKeyBytes = n } }

// WithPlaintextKeyIndex explicitly accepts plaintext keys in .idx files for an
// encrypted WAL. | WithPlaintextKeyIndex 明确接受加密 WAL 的 .idx 中保存明文 Key。
func WithPlaintextKeyIndex(enabled bool) Option {
	return func(o *options) { o.plaintextKeyIndex = enabled }
}

// WithEncryption enables record encryption with the given key ring. | WithEncryption 使用给定密钥环启用记录级加密。
func WithEncryption(ring *KeyRing) Option { return func(o *options) { o.keyRing = ring } }

// WithAllowPlaintext allows opening a non-empty plaintext WAL with a key ring. | WithAllowPlaintext 允许带密钥环打开非空明文 WAL。
func WithAllowPlaintext(enabled bool) Option { return func(o *options) { o.allowPlaintext = enabled } }

// WithSkipKeyCheck skips the META KCV check for recovery tools. | WithSkipKeyCheck 为恢复工具跳过 META KCV 校验。
func WithSkipKeyCheck(enabled bool) Option { return func(o *options) { o.skipKeyCheck = enabled } }

// WithCompression configures record compression. | WithCompression 配置记录级压缩。
func WithCompression(c Compression) Option {
	return func(o *options) {
		c.Codecs = append([]Codec(nil), c.Codecs...)
		o.compression = c
	}
}

// WithHashAlgorithm selects the content and idempotency digest. When omitted,
// a persisted Serializable hash algorithm is adopted from META; an explicit
// value must match it. | WithHashAlgorithm 选择内容与幂等摘要算法。未显式设置时
// 采用 META 中持久化的 Serializable 哈希算法；显式值必须与之一致。
func WithHashAlgorithm(h HashAlgorithm) Option {
	return func(o *options) {
		o.hashAlgorithm = h
		o.hashAlgorithmSet = true
	}
}

// WithContentDedup enables in-segment content deduplication. | WithContentDedup 启用段内内容去重。
func WithContentDedup(d DedupOptions) Option {
	return func(o *options) {
		o.dedup = d
		o.dedupEnabled = true
	}
}

// WithIdempotency enables the AppendOnce idempotency window. | WithIdempotency 启用 AppendOnce 幂等窗口。
func WithIdempotency(i IdempotencyOptions) Option {
	return func(o *options) {
		o.idempotency = i
		o.idempotencyEnabled = true
	}
}

// WithBackup enables asynchronous backup. | WithBackup 启用异步备份。
func WithBackup(b Backup) Option { return func(o *options) { o.backup = b } }

// WithBackupWorkers sets the backup worker count. | WithBackupWorkers 设置备份协程数量。
func WithBackupWorkers(n int) Option { return func(o *options) { o.backupWorkers = n } }

// WithBackupMaxPending sets the soft backup backlog warning threshold. | WithBackupMaxPending 设置备份积压软告警阈值。
func WithBackupMaxPending(n int) Option { return func(o *options) { o.backupMaxPending = n } }

// WithBackupVerifyTimeout sets the BackupVerifier timeout used by retention. | WithBackupVerifyTimeout 设置保留策略调用 BackupVerifier 的超时。
func WithBackupVerifyTimeout(d time.Duration) Option {
	return func(o *options) { o.backupVerifyTimeout = d }
}

// WithRetention enables automatic retention. | WithRetention 启用自动保留。
func WithRetention(r Retention) Option {
	return func(o *options) {
		o.retention = r
		o.retentionEnabled = true
	}
}

// WithRetentionVerifyTimeout sets the auto-retention verification timeout. | WithRetentionVerifyTimeout 设置自动保留的校验超时。
func WithRetentionVerifyTimeout(d time.Duration) Option {
	return func(o *options) { o.retentionVerifyTimeout = d }
}

// WithIndexer installs the post-commit index hook. | WithIndexer 安装提交后索引钩子。
func WithIndexer(i Indexer) Option { return func(o *options) { o.indexer = i } }

// WithErrorHandler installs the asynchronous error callback. The callback runs
// on a WAL worker and must not block or call back into blocking WAL methods. | WithErrorHandler
// 安装异步错误回调；回调在 WAL worker 上执行，必须非阻塞且不得回调阻塞的 WAL 方法。
func WithErrorHandler(fn func(error)) Option { return func(o *options) { o.errorHandler = fn } }

// WithMonotonicTimestamps promises that record timestamps never decrease; it
// enables time-based sparse-index binary search and rejects decreasing values. | WithMonotonicTimestamps
// 承诺记录时间戳不递减；启用基于时间的稀疏索引二分，并拒绝递减的时间戳。
func WithMonotonicTimestamps(enabled bool) Option {
	return func(o *options) { o.monotonicTimestamps = enabled }
}

// WithLinuxFastPath configures optional Linux fast paths. | WithLinuxFastPath 配置可选的 Linux 快路径。
func WithLinuxFastPath(f FastPathOptions) Option { return func(o *options) { o.fastPath = f } }

// WithIOEngine installs a custom positional I/O engine. | WithIOEngine 安装自定义位置写 I/O 引擎。
func WithIOEngine(e IOEngine) Option { return func(o *options) { o.ioEngine = e } }

// WithMacOSFullFsync selects F_FULLFSYNC on macOS. | WithMacOSFullFsync 选择 macOS 上使用 F_FULLFSYNC。
func WithMacOSFullFsync(enabled bool) Option { return func(o *options) { o.macFullFsync = enabled } }

// WithReadOnly opens the WAL without any writer, backup, or mutation. | WithReadOnly 以只读方式打开，不启动写入、备份或修改。
func WithReadOnly(enabled bool) Option { return func(o *options) { o.readOnly = enabled } }

// WithNoLock skips the directory lock; the caller must guarantee a single
// writer. | WithNoLock 跳过目录锁；调用方必须自行保证单写者。
func WithNoLock(enabled bool) Option { return func(o *options) { o.noLock = enabled } }

// WithAllowLSNGaps allows lossy recovery when segments or directory entries were
// lost. | WithAllowLSNGaps 在分段或目录项丢失时允许有损恢复。
func WithAllowLSNGaps(enabled bool) Option { return func(o *options) { o.allowLSNGaps = enabled } }

// WithAutoRepair controls automatic metadata repair (default true). When META,
// MANIFEST, and the recovery anchor are all lost, Open rebuilds them from
// segment headers, sidecars, and a bounded scan. Discovered LSN gaps are
// recorded in the recovery anchor and reported through Stats and ErrorHandler.
// Set it to false to restore the strict v1 behavior that refuses to open. |
// WithAutoRepair 控制元数据自动修复（默认 true）。META、MANIFEST 与恢复锚点
// 全部丢失时，Open 从段头、侧车与有界扫描重建；发现的 LSN 缺口写入恢复锚点，
// 并通过 Stats 与 ErrorHandler 报告。设为 false 可恢复 v1 的严格拒绝行为。
func WithAutoRepair(enabled bool) Option { return func(o *options) { o.autoRepair = enabled } }

// WithFileMode sets the mode of newly created files. | WithFileMode 设置新建文件的权限。
func WithFileMode(mode os.FileMode) Option { return func(o *options) { o.fileMode = mode } }

// WithDirMode sets the mode of newly created directories. | WithDirMode 设置新建目录的权限。
func WithDirMode(mode os.FileMode) Option { return func(o *options) { o.dirMode = mode } }

// normalize validates and fills defaults. | normalize 校验配置并填充默认值。
func (o *options) normalize() error {
	if o.syncPolicy.Mode > SyncModeNever {
		return errs.Detail(ErrInvalidOptions, "unknown sync mode %[1]d | 未知同步模式 %[1]d", o.syncPolicy.Mode)
	}
	if o.syncPolicy.Mode == SyncModeInterval && o.syncPolicy.Interval <= 0 {
		o.syncPolicy.Interval = defaultSyncInterval
	}
	if o.segmentMaxBytes <= 0 {
		return errs.Detail(ErrInvalidOptions, "SegmentMaxBytes must be positive | SegmentMaxBytes 必须为正数")
	}
	if o.maxRecordBytes <= 0 {
		o.maxRecordBytes = defaultMaxRecordBytes
	}
	if o.maxRecordBytes < recordHeaderSizeEncrypted+aeadTagSize+1 || o.maxRecordBytes > formatHardLimit {
		return errs.Detail(ErrInvalidOptions, "MaxRecordBytes must be in [%[1]d, %[2]d] | MaxRecordBytes 必须在 [%[1]d, %[2]d] 内",
			recordHeaderSizeEncrypted+aeadTagSize+1, formatHardLimit)
	}
	if o.queueSize <= 0 {
		o.queueSize = defaultQueueSize
	}
	if o.maxBatchRecords <= 0 {
		o.maxBatchRecords = defaultMaxBatchRecords
	}
	if o.maxBatchBytes <= 0 {
		o.maxBatchBytes = defaultMaxBatchBytes
	}
	if o.maxWritevParts <= 0 {
		o.maxWritevParts = defaultMaxWritevParts
	}
	if o.indexIntervalBytes <= 0 {
		o.indexIntervalBytes = defaultIndexIntervalBytes
	}
	if o.checkpointBytes <= 0 {
		o.checkpointBytes = defaultCheckpointBytes
	}
	if o.indexCacheBytes < 0 {
		return errs.Detail(ErrInvalidOptions, "IndexCacheBytes must not be negative | IndexCacheBytes 不得为负数")
	}
	if o.readFDCacheSize <= 0 {
		o.readFDCacheSize = defaultReadFDCacheSize
	}
	if o.manifestShardRecords <= 0 {
		o.manifestShardRecords = defaultManifestShardRecords
	}
	if o.manifestCompactRatio < 0 || o.manifestCompactRatio > 1 {
		return errs.Detail(ErrInvalidOptions, "ManifestCompactRatio must be in [0,1] | ManifestCompactRatio 必须在 [0,1] 内")
	}
	if o.manifestGapProbeMax < 0 {
		return errs.Detail(ErrInvalidOptions, "ManifestGapProbeMax must not be negative | ManifestGapProbeMax 不得为负数")
	}
	if o.streamChunkSize <= 0 {
		o.streamChunkSize = defaultStreamChunkSize
	}
	maxChunk := o.maxRecordBytes - recordHeaderSizeEncrypted - aeadTagSize - streamIDSize
	if maxChunk < 1 {
		maxChunk = 1
	}
	if o.streamChunkSize > maxChunk {
		o.streamChunkSize = maxChunk
	}
	if o.defaultIsolation > IsolationSerializable {
		return errs.Detail(ErrInvalidOptions, "unknown isolation level %[1]d | 未知隔离级别 %[1]d", o.defaultIsolation)
	}
	if o.txnMaxBytes <= 0 {
		o.txnMaxBytes = defaultTxnMaxBytes
	}
	if o.txnMaxRecords == 0 {
		o.txnMaxRecords = defaultTxnMaxRecords
	}
	if o.txnConflictWindow == 0 {
		o.txnConflictWindow = defaultTxnConflictWindow
	}
	if o.txnMaxKeys <= 0 {
		o.txnMaxKeys = defaultTxnMaxKeys
	}
	if o.txnConflictMaxEntries <= 0 {
		o.txnConflictMaxEntries = defaultTxnConflictMaxEntries
	}
	if o.txnConflictScanBytes <= 0 {
		o.txnConflictScanBytes = defaultTxnConflictScanBytes
	}
	if o.keyIndexMaxEntries <= 0 {
		o.keyIndexMaxEntries = defaultKeyIndexMaxEntries
	}
	if o.keyIndexMaxKeyBytes <= 0 {
		o.keyIndexMaxKeyBytes = defaultKeyIndexMaxKeyBytes
	}
	if o.keyIndex && o.keyRing != nil && !o.plaintextKeyIndex {
		return errs.Detail(ErrInvalidOptions, "KeyIndex with encryption requires WithPlaintextKeyIndex(true) | 加密 WAL 启用 KeyIndex 需要显式 WithPlaintextKeyIndex(true)")
	}
	if o.hashAlgorithm > HashSM3 {
		return errs.Detail(ErrInvalidOptions, "unknown hash algorithm %[1]d | 未知哈希算法 %[1]d", o.hashAlgorithm)
	}
	if err := o.compression.validate(); err != nil {
		return err
	}
	if o.dedupEnabled {
		if o.dedup.MinBytes <= 0 {
			o.dedup.MinBytes = defaultDedupMinBytes
		}
		if o.dedup.MaxEntries <= 0 {
			o.dedup.MaxEntries = defaultDedupMaxEntries
		}
	}
	if o.idempotencyEnabled {
		if o.idempotency.MaxEntries <= 0 {
			o.idempotency.MaxEntries = defaultIdemMaxEntries
		}
		if o.idempotency.TTL < 0 {
			return errs.Detail(ErrInvalidOptions, "Idempotency TTL must not be negative | 幂等 TTL 不得为负数")
		}
	}
	if o.backup != nil {
		if o.backupWorkers <= 0 {
			o.backupWorkers = defaultBackupWorkers
		}
		if o.backupMaxPending < 0 {
			return errs.Detail(ErrInvalidOptions, "BackupMaxPending must not be negative | BackupMaxPending 不得为负数")
		}
		if o.backupVerifyTimeout <= 0 {
			o.backupVerifyTimeout = defaultVerifyTimeout
		}
	}
	if o.retentionEnabled {
		if o.retention.MaxAge < 0 || o.retention.MaxBytes < 0 {
			return errs.Detail(ErrInvalidOptions, "Retention limits must not be negative | 保留限制不得为负数")
		}
		if o.retentionVerifyTimeout <= 0 {
			o.retentionVerifyTimeout = defaultVerifyTimeout
		}
	}
	if o.fastPath.Mode > FastPathCustom {
		return errs.Detail(ErrInvalidOptions, "unknown fast path mode %[1]d | 未知快路径模式 %[1]d", o.fastPath.Mode)
	}
	if o.fileMode == 0 {
		o.fileMode = defaultFileMode
	}
	if o.dirMode == 0 {
		o.dirMode = defaultDirMode
	}
	return nil
}
