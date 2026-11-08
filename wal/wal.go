package wal

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shibingli/ydx/errs"
)

// WAL is one write-ahead log directory. | WAL 是一个预写日志目录。
//
// A WAL is safe for concurrent Append, AppendBatch, AppendOnce, Async, Reader,
// Scan, Query, backup, and truncation calls. A Reader or Tx is not safe for
// concurrent use by multiple goroutines. | WAL 可被并发 Append、AppendBatch、
// AppendOnce、异步写、Reader、Scan、Query、备份与截断调用；Reader 与 Tx 不能被
// 多个协程并发使用。
type WAL struct {
	reqPool sync.Pool

	readBufPool     sync.Pool
	readScratchPool sync.Pool
	readHeaderPool  sync.Pool
	engine          IOEngine
	closeErr        error
	indexer         Indexer
	writerErr       error

	backupCtx    context.Context
	backupVerify BackupVerifier

	retentionCtx context.Context

	lock       *dirLock
	meta       *metaStore
	manifest   *manifest
	anchor     *anchorState
	anchorFile *anchorStore
	gaps       *gapSet
	fdcache    *fdCache
	idxcache   *indexCache

	closing  chan struct{}
	closedCh chan struct{}
	poison   atomic.Pointer[error]
	segBySeq map[uint64]*segment
	active   *segment

	keyRing *KeyRing
	bound   *boundRing
	nonce   *nonceGen

	dedup   *dedupTable
	idem    *idemTable
	occ     *occState
	handler func(error)

	appendQ           chan *appendRequest
	writerDone        chan struct{}
	notifyCh          chan struct{}
	checkpointPending *checkpointJob
	checkpointNotify  chan struct{}
	checkpointStop    chan struct{}
	cleanerCh         chan struct{}
	cleanerStop       chan struct{}
	backupCh          chan struct{}
	backupCancel      context.CancelFunc
	backupItems       map[uint64]*backupItem
	retentionCancel   context.CancelFunc
	retentionStop     chan struct{}
	retentionTrigger  chan struct{}
	dir               string
	backupTarget      string

	recoveryReports []error

	segments      []*segment
	aadScratch    []byte
	preparedArena []preparedRecord
	planArena     []reqPlan
	planPtrs      []*reqPlan
	itemBuf       []*preparedRecord
	userItemBuf   []*preparedRecord
	partBuf       [][]byte
	batchBuf      []*appendRequest
	cleanerQ      []*segment

	opts options

	counters counters

	checkpointWG sync.WaitGroup
	cleanerWG    sync.WaitGroup
	backupWG     sync.WaitGroup
	retentionWG  sync.WaitGroup

	createdNano    int64
	firstLSN       uint64
	firstLSNAtomic atomic.Uint64
	nextLSN        uint64
	nextSeq        uint64
	gapFloor       uint64
	commitSeq      uint64
	snapVersion    atomic.Uint64
	snapCommit     atomic.Uint64
	snapLast       atomic.Uint64

	activeKCV     uint64
	lastTimestamp int64
	notifyGen     uint64
	followReaders atomic.Int64

	checkpointBytes   int64
	syncedSize        int64
	syncedLSN         uint64
	syncedRecordCount uint64
	syncedCommitSeq   uint64
	cleanerGen        uint64
	backupGen         uint64
	readLeases        int

	mu sync.RWMutex
	// commitMu serializes every mutation that touches the active segment: the
	// writer loop's data/control requests, age/sync ticks, and AppendDirect.
	// It lets a single-writer integration bypass the append queue without
	// racing rotation, truncation, or close. | commitMu 串行化所有修改活动段的操作：
	// 写协程的数据/控制请求、年龄/同步定时器与 AppendDirect。它使单写者集成可以
	// 绕过追加队列，同时不与轮转、截断或关闭竞争。
	commitMu        sync.Mutex
	writeBufMu      sync.Mutex
	writeBuf        []byte
	writeBufFile    *os.File
	writeBufOff     int64
	readersActive   atomic.Int32
	policy          *sizePolicyState
	closeOnce       sync.Once
	engineCloseOnce sync.Once
	anchorMu        sync.Mutex
	writerErrMu     sync.Mutex

	notifyMu sync.Mutex

	workerMu sync.Mutex

	checkpointMu sync.Mutex

	cleanerMu sync.Mutex

	backupMu sync.Mutex

	readMu sync.Mutex
	// idxWriteMu serializes on-demand sidecar upgrades with Close. A Query may
	// rebuild a segment index concurrently with Close; Close waits here before
	// releasing the directory lock so no sidecar write can land after a new
	// process opens the directory. | idxWriteMu 串行化按需侧车升级与 Close：
	// Query 可能在 Close 期间重建段索引，Close 在释放目录锁前先经过此屏障，
	// 避免新进程打开目录后仍有侧车写入落盘。
	idxWriteMu sync.Mutex
	// stateDirty records that nextLSN/commitSeq/nextSeq changed since the last
	// anchor write. Clean open/close without writes then avoids all anchor I/O.
	// | stateDirty 表示自上次锚点写入后 nextLSN/commitSeq/nextSeq 已变化；
	// 无写入的干净打开/关闭因此完全不触碰锚点。
	stateDirty  atomic.Bool
	closedFlag  atomic.Bool
	activeKeyID uint32
	syncedCRC   uint32
	walID       [16]byte

	recoveredFromAnchor bool
	autoRepaired        bool
	anchorPersisted     bool
	closed              bool
	encrypted           bool
	serializableDurable bool
	hashAlg             HashAlgorithm

	keyIndexOverflow bool
	workersStarted   bool

	pendingSync bool

	cleanerBusy bool

	backupWarned bool

	readClosed bool
}

// Open opens or creates a WAL directory. | Open 打开或创建 WAL 目录。
func Open(dir string, opts ...Option) (*WAL, error) {
	if dir == "" {
		return nil, errs.Detail(ErrInvalidOptions, "directory is empty | 目录为空")
	}
	o := defaultOptions()
	for _, fn := range opts {
		if fn != nil {
			fn(&o)
		}
	}
	if err := o.normalize(); err != nil {
		return nil, err
	}
	if !o.readOnly {
		if err := ensureDir(dir, o.dirMode); err != nil {
			return nil, err
		}
	} else if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		if err == nil {
			err = errs.Detail(ErrInvalidOptions, "%s is not a directory | %s 不是目录", dir, dir)
		}
		return nil, errs.WrapDetail(err, ErrStorage, "stat directory %s | 检查目录 %s 失败", dir, dir)
	}
	lock, err := acquireDirLock(filepath.Join(dir, "wal.lock"), o.readOnly, o.noLock)
	if err != nil {
		return nil, err
	}
	w := &WAL{
		dir:              dir,
		opts:             o,
		lock:             lock,
		gaps:             newGapSet(),
		closing:          make(chan struct{}),
		closedCh:         make(chan struct{}),
		notifyCh:         make(chan struct{}),
		checkpointNotify: make(chan struct{}, 1),
		checkpointStop:   make(chan struct{}),
		cleanerCh:        make(chan struct{}),
		cleanerStop:      make(chan struct{}),
		backupCh:         make(chan struct{}),
		retentionStop:    make(chan struct{}),
		retentionTrigger: make(chan struct{}, 1),
		appendQ:          make(chan *appendRequest, o.queueSize),
		writerDone:       make(chan struct{}),
	}
	if o.backup != nil {
		w.backupItems = make(map[uint64]*backupItem)
	}
	w.engine = defaultIOEngine(&o)
	if o.ioEngine != nil {
		w.engine = o.ioEngine
	}
	w.policy = newSizePolicyState(o.sizePolicy, o.writeBufferBytes)
	w.policy.bindEngine(w.engine)
	w.fdcache = newFDCache(dir, o.readFDCacheSize)
	w.idxcache = newIndexCache(o.indexCacheBytes)
	w.dedup = newDedupTable(o.dedup.MaxEntries)
	if o.idempotencyEnabled {
		w.idem = newIdemTable(o.idempotency.MaxEntries, o.idempotency.TTL)
	}
	w.occ = newOCC(o.txnConflictWindow, o.txnConflictMaxEntries)
	w.indexer = o.indexer
	w.handler = o.errorHandler
	w.hashAlg = o.hashAlgorithm
	w.aadScratch = make([]byte, 0, 32+recordHeaderSizeEncrypted)

	if err := w.recover(); err != nil {
		w.abortOpen()
		return nil, err
	}
	if !o.readOnly {
		// A segment retired by an earlier cleaner may have lost its .wal but kept
		// its .idx/.bak after a crash; remove those orphans before serving reads. |
		// 早先的 cleaner 可能已删除 .wal 却因崩溃留下 .idx/.bak；在提供读取前
		// 清掉这些孤儿文件。
		w.sweepOrphanSidecars()
	}
	if !o.readOnly {
		// A clean default open defers the anchor read. If META already records
		// that the anchor exists, no stat is needed; otherwise check once, and
		// when the anchor is missing write it before META so the new META
		// generation records its presence. | 干净的默认打开延迟读取锚点。META 已
		// 记录锚点存在时无需 stat；否则检查一次，锚点缺失时先写锚点再写 META，
		// 让新 META 代次记录其存在。
		anchorMissing := false
		if !w.anchorPersisted {
			if w.meta != nil && w.meta.hasState && w.meta.state.flags&metaFlagAnchor != 0 {
				w.anchorPersisted = true
			} else if _, statErr := os.Stat(anchorPath(w.dir)); statErr == nil {
				w.anchorPersisted = true
			} else if os.IsNotExist(statErr) {
				anchorMissing = true
			}
		}
		if anchorMissing {
			if err := w.persistAnchorIfChanged(); err != nil {
				w.abortOpen()
				return nil, err
			}
		}
		if err := w.persistMetaIfChanged(); err != nil {
			w.abortOpen()
			return nil, err
		}
		writeAnchor := w.anchorFile != nil || w.stateDirty.Load() || anchorMissing
		if writeAnchor {
			if err := w.persistAnchorIfChanged(); err != nil {
				w.abortOpen()
				return nil, err
			}
		}
		// Backup reconciliation must run even before the first write. Other
		// workers start lazily on the first admission. | 备份对账必须在首次写入
		// 前启动；其它 worker 在第一次准入时惰性启动。
		if o.backup != nil {
			w.startWorkers()
		}
	}
	w.flushRecoveryReports()
	return w, nil
}

// abortOpen releases every resource acquired before a failed Open without
// rewriting META or compacting MANIFEST. | abortOpen 在 Open 失败时释放已获取的
// 资源，且不重写 META、不压缩 MANIFEST。
func (w *WAL) abortOpen() {
	if w.active != nil {
		w.active.closeWriter()
		w.active = nil
	}
	for _, seg := range w.segments {
		if seg.f != nil {
			seg.closeWriter()
		}
	}
	if w.fdcache != nil {
		w.fdcache.closeAll()
	}
	if w.idxcache != nil {
		w.idxcache.closeAll()
	}
	if w.engine != nil {
		_ = w.engine.Close()
	}
	if w.bound != nil {
		w.bound.close()
		w.bound = nil
	}
	if w.meta != nil {
		_ = w.meta.close()
	}
	if w.anchorFile != nil {
		_ = w.anchorFile.close()
	}
	if w.manifest != nil {
		w.manifest.closeHandle()
	}
	if w.lock != nil {
		_ = w.lock.Close()
	}
}

// metaCurrent reports whether persisted META already matches the in-memory
// state. | metaCurrent 报告已持久化 META 是否已与内存状态一致。
func (w *WAL) metaCurrent() bool {
	if w.meta == nil || !w.meta.hasState || w.meta.upgrade {
		return false
	}
	cur := w.metaSnapshot()
	cur.generation = w.meta.state.generation
	return cur == w.meta.state
}

// persistMetaIfChanged writes META only when the recovered or final state
// differs from what is already durable; this removes two fsyncs from every
// clean open and close. | persistMetaIfChanged 仅在恢复或最终状态与已持久化状态不同
// 时写入 META；这样每次干净打开与关闭可省去两次 fsync。
func (w *WAL) persistMetaIfChanged() error {
	if w.metaCurrent() {
		return nil
	}
	if err := w.meta.write(w.metaSnapshot()); err != nil {
		return err
	}
	// A META rewrite means the durable state changed; make sure Close mirrors
	// it into the anchor even when no append happened. | META 重写意味着持久
	// 状态变化；即使没有追加，Close 也必须把它镜像到锚点。
	w.stateDirty.Store(true)
	return nil
}

// metaSnapshot builds the current META state. | metaSnapshot 构建当前 META 状态。
func (w *WAL) metaSnapshot() metaState {
	st := metaState{
		nextSeq:      w.nextSeq,
		nextLSN:      w.nextLSN,
		createdNano:  w.createdNano,
		firstLSN:     w.firstLSN,
		commitSeq:    w.commitSeq,
		gapFloor:     w.gapFloor,
		activeKeyKCV: w.activeKCV,
		walID:        w.walID,
		activeKeyID:  w.activeKeyID,
	}
	if w.encrypted {
		st.flags |= metaFlagEncrypted
	}
	if w.serializableDurable {
		st.flags |= metaFlagSerializable
		st.setHashAlgorithm(w.hashAlg)
	}
	if w.anchorPersisted {
		st.flags |= metaFlagAnchor
	}
	return st
}

// setPoison records the first fatal error. | setPoison 记录首个致命错误。
func (w *WAL) setPoison(err error) {
	if err == nil {
		return
	}
	w.poison.CompareAndSwap(nil, &err)
}

// poisonedErr returns the first fatal error. | poisonedErr 返回首个致命错误。
func (w *WAL) poisonedErr() error {
	if p := w.poison.Load(); p != nil {
		return *p
	}
	return nil
}

// isClosed reports the closed flag. | isClosed 返回关闭标志。
func (w *WAL) isClosed() bool {
	return w.closedFlag.Load()
}

// FirstLSN returns the lowest readable LSN. | FirstLSN 返回最低可读 LSN。
func (w *WAL) FirstLSN() uint64 {
	return w.firstLSNAtomic.Load()
}

// LastLSN returns the committed high-water LSN. | LastLSN 返回已提交高水位 LSN。
func (w *WAL) LastLSN() uint64 {
	return w.Snapshot().LastLSN
}

// Snapshot returns the current committed prefix. A seqlock publishes the pair
// without allocating a pointer per batch. | Snapshot 返回当前已提交前缀。使用
// seqlock 发布成对值，避免每批分配一个指针。
func (w *WAL) Snapshot() Snapshot {
	for {
		v1 := w.snapVersion.Load()
		if v1&1 != 0 {
			runtime.Gosched()
			continue
		}
		commit := w.snapCommit.Load()
		last := w.snapLast.Load()
		if w.snapVersion.Load() == v1 {
			return Snapshot{CommitSeq: commit, LastLSN: last}
		}
	}
}

// publishSnapshot atomically publishes a committed prefix. | publishSnapshot
// 原子发布已提交前缀。
func (w *WAL) publishSnapshot(commit, last uint64) {
	v := w.snapVersion.Load()
	w.snapVersion.Store(v + 1)
	w.snapCommit.Store(commit)
	w.snapLast.Store(last)
	w.snapVersion.Store(v + 2)
}

// Stats returns a point-in-time counter snapshot. | Stats 返回时间点计数器快照。
func (w *WAL) Stats() Stats {
	s := w.counters.snapshot()
	s.DedupOverflow = w.dedup.overflow.Load()
	w.mu.RLock()
	s.FirstLSN = w.firstLSN
	s.Segments = len(w.segments)
	for _, seg := range w.segments {
		if seg.currentState() == segmentSealed {
			s.SealedSegments++
		}
	}
	w.mu.RUnlock()
	snap := w.Snapshot()
	s.LastLSN = snap.LastLSN
	s.CommitSeq = snap.CommitSeq
	if w.manifest != nil {
		s.ManifestSegments = w.manifest.segmentCount()
	}
	entries, indexBytes := w.idxcache.stats()
	s.IndexCacheEntries = uint64(entries)
	s.IndexCacheBytes = uint64(indexBytes)
	s.BackupPending = w.backupPendingCount()
	if w.gaps != nil {
		s.RecoveryGapIntervals = w.gaps.count()
		s.RecoveryGapDegraded = w.gaps.isDegraded()
	}
	s.RecoveredFromAnchor = w.recoveredFromAnchor
	s.AutoRepaired = w.autoRepaired
	s.Poisoned = w.poisonedErr() != nil
	return s
}

// EngineInfo returns detected platform fast paths. | EngineInfo 返回探测到的平台快路径。
func (w *WAL) EngineInfo() EngineInfo {
	info := detectEngineInfo()
	info.HashAlgorithm = hashName(w.hashAlg)
	if w.engine != nil {
		if de, ok := w.engine.(*defaultEngine); ok {
			info.Pwritev2DSync = de.pwritev2.Load()
			info.DirSyncDurable = de.dirSyncDurable
		}
	}
	if w.opts.compression.Active != 0 {
		info.CompressionCodecs = append(info.CompressionCodecs, codecName(w.opts.compression.Active))
	}
	return info
}

// Append writes one record and returns its LSN. It returns after the record
// reaches the configured durability policy: durable before returning with the
// default SyncAlways, while SyncInterval and SyncNever return once the writer
// accepted the record. The caller may reuse Key/Data afterwards. | Append 写入
// 一条记录并返回其 LSN；返回时记录已达到配置的持久级别：默认 SyncAlways 在返回前
// 已持久化，SyncInterval 与 SyncNever 则在写入者接受记录后返回。调用方之后可复用
// Key/Data。
func (w *WAL) Append(ctx context.Context, rec Record) (uint64, error) {
	if w.opts.readOnly {
		return 0, ErrReadOnly
	}
	if err := w.validateUserRecord(rec, false); err != nil {
		return 0, err
	}
	req := w.acquireRequest(kindData)
	defer w.releaseRequest(req)
	req.one[0] = rec
	req.recs = req.one[:1]
	if err := w.admit(ctx, req, false); err != nil {
		return 0, err
	}
	res := <-req.done
	if res.err != nil {
		return 0, res.err
	}
	if w.indexer != nil {
		ts := rec.Timestamp
		if len(res.timestamps) > 0 {
			ts = res.timestamps[0]
		}
		w.runIndexer(RecordMeta{LSN: res.lsn, Timestamp: ts, Flags: rec.Flags, KeyLen: len(rec.Key), DataLen: len(rec.Data)}, rec.Key, rec.Data)
	}
	return res.lsn, nil
}

// AppendDirect writes one record without the shared append queue and returns its
// LSN. It is intended for an integration that already has a single writer and
// serializes every WAL mutation; callers must not invoke it concurrently with
// Append, AppendBatch, Sync, Rotate, Truncate, SetActiveKey, or Close. It returns
// after the record is durable for the configured sync policy. | AppendDirect 绕过
// 共享追加队列写入一条记录并返回 LSN。它面向已保证单写者、并自行串行化全部 WAL
// 变更的集成；调用方不得与 Append、AppendBatch、Sync、Rotate、Truncate、
// SetActiveKey 或 Close 并发调用。记录达到配置的持久级别后返回。
func (w *WAL) AppendDirect(ctx context.Context, rec Record) (uint64, error) {
	if w.opts.readOnly {
		return 0, ErrReadOnly
	}
	if err := w.validateUserRecord(rec, false); err != nil {
		return 0, err
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
	}
	w.ensureWorkers()
	req := w.acquireRequest(kindData)
	defer w.releaseRequest(req)
	req.one[0] = rec
	req.recs = req.one[:1]
	req.direct = true
	req.directRes = appendResult{}
	w.commitMu.Lock()
	if w.isClosed() {
		w.commitMu.Unlock()
		return 0, ErrClosed
	}
	if err := w.poisonedErr(); err != nil {
		w.commitMu.Unlock()
		return 0, err
	}
	w.commitBatch([]*appendRequest{req})
	w.commitMu.Unlock()
	res := req.directRes
	if res.err != nil {
		return 0, res.err
	}
	if w.indexer != nil {
		ts := rec.Timestamp
		if len(res.timestamps) > 0 {
			ts = res.timestamps[0]
		}
		w.runIndexer(RecordMeta{LSN: res.lsn, Timestamp: ts, Flags: rec.Flags, KeyLen: len(rec.Key), DataLen: len(rec.Data)}, rec.Key, rec.Data)
	}
	return res.lsn, nil
}

// AppendBatch writes a batch atomically and returns its last LSN. | AppendBatch
// 原子写入一批记录并返回最后一条 LSN。
func (w *WAL) AppendBatch(ctx context.Context, recs []Record) (uint64, error) {
	if w.opts.readOnly {
		return 0, ErrReadOnly
	}
	if len(recs) == 0 {
		// An empty batch still observes the WAL lifecycle; returning success on a
		// closed or poisoned WAL would hide a terminal state. | 空批次仍须反映 WAL
		// 生命周期；在已关闭或 poisoned 的 WAL 上返回成功会掩盖终态。
		if w.isClosed() {
			return 0, ErrClosed
		}
		if err := w.poisonedErr(); err != nil {
			return 0, err
		}
		return w.LastLSN(), nil
	}
	for _, rec := range recs {
		if err := w.validateUserRecord(rec, false); err != nil {
			return 0, err
		}
	}
	// The caller's slice is borrowed only for the duration of this call; the
	// writer encodes it before the result is delivered. | 仅在本次调用期间借用调用方
	// 的切片；写入协程在结果投递前完成编码。
	req := w.acquireRequest(kindData)
	defer w.releaseRequest(req)
	req.recs = recs
	if err := w.admit(ctx, req, false); err != nil {
		return 0, err
	}
	res := <-req.done
	if res.err != nil {
		return 0, res.err
	}
	if w.indexer != nil {
		for i, rec := range recs {
			lsn := res.firstLSN + uint64(i)
			ts := rec.Timestamp
			if i < len(res.timestamps) {
				ts = res.timestamps[i]
			}
			w.runIndexer(RecordMeta{LSN: lsn, Timestamp: ts, Flags: rec.Flags, KeyLen: len(rec.Key), DataLen: len(rec.Data)}, rec.Key, rec.Data)
		}
	}
	return res.lsn, nil
}

// AppendOnce writes one record at most once for a caller-supplied idempotency
// key. | AppendOnce 对调用方提供的幂等键最多写入一次。
func (w *WAL) AppendOnce(ctx context.Context, dedupKey []byte, rec Record) (uint64, bool, error) {
	if w.opts.readOnly {
		return 0, false, ErrReadOnly
	}
	if !w.opts.idempotencyEnabled {
		return 0, false, errs.Detail(ErrInvalidOptions, "AppendOnce requires WithIdempotency | AppendOnce 需要 WithIdempotency")
	}
	if len(dedupKey) == 0 {
		return 0, false, errs.Detail(ErrInvalidOptions, "idempotency key is empty | 幂等键为空")
	}
	if err := w.validateUserRecord(rec, false); err != nil {
		return 0, false, err
	}
	req := w.acquireRequest(kindData)
	defer w.releaseRequest(req)
	if cap(req.dedupBuf) < len(dedupKey) {
		req.dedupBuf = make([]byte, len(dedupKey))
	}
	req.dedupBuf = req.dedupBuf[:len(dedupKey)]
	copy(req.dedupBuf, dedupKey)
	req.one[0] = rec
	req.recs = req.one[:1]
	req.once = true
	req.dedupKey = req.dedupBuf
	if err := w.admit(ctx, req, false); err != nil {
		return 0, false, err
	}
	res := <-req.done
	if res.err != nil {
		return res.lsn, res.duplicate, res.err
	}
	if w.indexer != nil && !res.duplicate {
		ts := rec.Timestamp
		if len(res.timestamps) > 0 {
			ts = res.timestamps[0]
		}
		w.runIndexer(RecordMeta{LSN: res.lsn, Timestamp: ts, Flags: rec.Flags, KeyLen: len(rec.Key), DataLen: len(rec.Data)}, rec.Key, rec.Data)
	}
	return res.lsn, res.duplicate, nil
}

// AppendAsync enqueues one record without waiting for the commit. The writer
// encodes it asynchronously, so Key and Data must not be modified until the
// returned future's Done channel closes (or Result returns). | AppendAsync 入队
// 一条记录而不等待提交完成；写入协程会异步编码，因此 future 的 Done 通道关闭
// （或 Result 返回）前不得修改 Key/Data。
func (w *WAL) AppendAsync(rec Record) (*AppendFuture, error) {
	if w.opts.readOnly {
		return nil, ErrReadOnly
	}
	if w.indexer != nil {
		return nil, errs.Detail(ErrUnsupported, "AppendAsync does not support Indexer | AppendAsync 不支持 Indexer")
	}
	if err := w.validateUserRecord(rec, false); err != nil {
		return nil, err
	}
	future := newAppendFuture()
	req := &appendRequest{kind: kindData, recs: []Record{rec}, async: true, future: future}
	if err := w.admit(nil, req, true); err != nil {
		return nil, err
	}
	return future, nil
}

// validateUserRecord checks caller flags and size limits. | validateUserRecord
// 校验调用方标志与大小限制。
func (w *WAL) validateUserRecord(rec Record, allowStream bool) error {
	if rec.Flags&^RecordFlagsMask != 0 {
		return errs.Detail(ErrInvalidRecord, "record flags 0x%[1]04x exceed the mask | 记录 flags 0x%[1]04x 超出掩码", rec.Flags)
	}
	if !allowStream && rec.Flags&(FlagStreamChunk|FlagStreamEnd) != 0 {
		return errs.Detail(ErrInvalidRecord, "stream flags are reserved for AppendStream | 流标志仅供 AppendStream 使用")
	}
	keyLen, ok := addSizes(len(rec.Key), len(rec.Data))
	if !ok || keyLen > formatHardLimit {
		return errs.Detail(ErrRecordTooLarge, "record payload overflows | 记录负载溢出")
	}
	if keyLen+recordHeaderSizeEncrypted+aeadTagSize > w.opts.maxRecordBytes {
		return errs.Detail(ErrRecordTooLarge, "record needs %[1]d bytes, limit %[2]d | 记录需要 %[1]d 字节，上限 %[2]d",
			keyLen+recordHeaderSizeEncrypted+aeadTagSize, w.opts.maxRecordBytes)
	}
	return nil
}

// runIndexer invokes the user hook on the caller goroutine. A panic propagates
// to the caller; the record is already durable. | runIndexer 在调用方协程执行
// 用户钩子；panic 会向调用方传播，此时记录已持久化。
func (w *WAL) runIndexer(meta RecordMeta, key, data []byte) {
	if w.indexer != nil {
		w.indexer.Index(meta, key, data)
	}
}

// admit enqueues req under the gated admission protocol. | admit 在门控准入协议下入队 req。
func (w *WAL) admit(ctx context.Context, req *appendRequest, async bool) error {
	if ctx == nil {
		ctx = context.Background()
	}
	w.ensureWorkers()
	backoff := 50 * time.Microsecond
	for {
		w.mu.RLock()
		if w.closed {
			w.mu.RUnlock()
			return ErrClosed
		}
		if err := w.poisonedErr(); err != nil {
			w.mu.RUnlock()
			return err
		}
		select {
		case w.appendQ <- req:
			w.mu.RUnlock()
			return nil
		default:
			w.mu.RUnlock()
		}
		if async {
			return ErrQueueFull
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		if backoff < 5*time.Millisecond {
			backoff *= 2
		}
	}
}

// acquireRequest returns a reset append request with its buffered result
// channel. Requests are pooled so the steady-state Append path does not
// allocate. | acquireRequest 返回已重置的追加请求及其带缓冲结果通道；请求池化
// 使稳态 Append 路径零分配。
func (w *WAL) acquireRequest(kind reqKind) *appendRequest {
	req, _ := w.reqPool.Get().(*appendRequest)
	if req == nil {
		return &appendRequest{kind: kind, done: make(chan appendResult, 1)}
	}
	done, dedupBuf := req.done, req.dedupBuf
	*req = appendRequest{kind: kind, done: done, dedupBuf: dedupBuf}
	return req
}

// releaseRequest drops caller references and returns req to the pool. It must
// only run after the writer has delivered the result. | releaseRequest 清除调用方
// 引用并把 req 归还请求池；必须在写入协程投递结果之后调用。
func (w *WAL) releaseRequest(req *appendRequest) {
	if req == nil || req.done == nil {
		return
	}
	req.recs = nil
	req.one[0] = Record{}
	req.txn = nil
	req.plan = nil
	req.future = nil
	req.async = false
	req.once = false
	req.allowStream = false
	req.direct = false
	req.directRes = appendResult{}
	req.dedupKey = nil
	if cap(req.dedupBuf) > 4096 {
		req.dedupBuf = nil
	}
	w.reqPool.Put(req)
}

// control enqueues a control request and waits for the writer. | control 入队控制请求并等待写入协程。
func (w *WAL) control(ctx context.Context, kind reqKind) (appendResult, error) {
	req := &appendRequest{kind: kind, done: make(chan appendResult, 1)}
	if err := w.admit(ctx, req, false); err != nil {
		return appendResult{}, err
	}
	res := <-req.done
	return res, res.err
}

// Sync flushes pending writes and returns after they are durable. | Sync 刷新待同步写入并在持久化后返回。
func (w *WAL) Sync() error {
	if w.opts.readOnly {
		return ErrReadOnly
	}
	_, err := w.control(nil, kindSync)
	return err
}

// Rotate seals the active segment and starts a new one. | Rotate 封存活动段并创建新段。
func (w *WAL) Rotate() error {
	if w.opts.readOnly {
		return ErrReadOnly
	}
	_, err := w.control(nil, kindRotate)
	return err
}

// SetActiveKey rotates to a new encryption key and persists the choice. | SetActiveKey
// 轮换到新加密密钥并持久化选择。
func (w *WAL) SetActiveKey(id uint32) error {
	if w.opts.readOnly {
		return ErrReadOnly
	}
	req := &appendRequest{kind: kindSetActiveKey, keyID: id, done: make(chan appendResult, 1)}
	if err := w.admit(nil, req, false); err != nil {
		return err
	}
	res := <-req.done
	return res.err
}

// Truncate logically removes every record below beforeLSN and returns the
// number of segments retired. | Truncate 逻辑删除 beforeLSN 以下的全部记录，并返回
// 退休的分段数。
func (w *WAL) Truncate(beforeLSN uint64) (int, error) {
	if w.opts.readOnly {
		return 0, ErrReadOnly
	}
	req := &appendRequest{kind: kindTruncate, beforeLSN: beforeLSN, done: make(chan appendResult, 1)}
	if err := w.admit(nil, req, false); err != nil {
		return 0, err
	}
	res := <-req.done
	return res.segments, res.err
}

// Close flushes, seals, stops workers, persists META, and releases the
// directory lock. It is idempotent. | Close 刷新、封段、停止 worker、持久化 META
// 并释放目录锁；重复调用幂等。
func (w *WAL) Close() error {
	w.closeOnce.Do(func() {
		w.closeErr = w.doClose()
	})
	return w.closeErr
}

// doClose implements the single authoritative close sequence. | doClose 实现唯一权威的关闭序列。
func (w *WAL) doClose() error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil
	}
	w.closed = true
	w.closedFlag.Store(true)
	close(w.closing)
	w.mu.Unlock()

	if !w.opts.readOnly {
		w.workerMu.Lock()
		started := w.workersStarted
		w.workerMu.Unlock()
		if started {
			// Stop retention first so it cannot enqueue a truncate after the writer exits. | 先停止保留 worker，避免 writer 退出后再入队截断。
			if w.retentionCancel != nil {
				close(w.retentionStop)
				w.retentionCancel()
				w.retentionWG.Wait()
			}

			closeReq := &appendRequest{kind: kindClose, done: make(chan appendResult, 1)}
			w.appendQ <- closeReq
			<-w.writerDone
			<-closeReq.done

			close(w.checkpointStop)
			w.checkpointWG.Wait()

			close(w.cleanerStop)
			w.notifyCleaner()
			w.cleanerWG.Wait()

			if w.backupCancel != nil {
				w.backupCancel()
				w.backupWG.Wait()
			}
		} else if w.active != nil {
			// No worker was ever started, so no writer drained the active
			// segment. Recovery only leaves an empty segment here; close it. |
			// 从未启动 worker 时没有 writer 排空活动段；恢复在此只会留下空段，
			// 直接关闭句柄。
			w.active.closeWriter()
			w.active = nil
		}
	}
	close(w.closedCh)

	var firstErr error
	w.writerErrMu.Lock()
	if w.writerErr != nil {
		firstErr = w.writerErr
	}
	w.writerErrMu.Unlock()
	if w.poisonedErr() == nil && firstErr == nil && !w.opts.readOnly {
		if err := w.persistMetaIfChanged(); err != nil {
			firstErr = err
		}
	}
	// The recovery anchor is a redundant copy: attempt it even if the META
	// write above failed, because either copy can heal the other. | 恢复锚点是
	// 冗余副本：即使上面的 META 写入失败也尝试写入，任一副本都能修复另一份。
	if !w.opts.readOnly && w.poisonedErr() == nil && (w.stateDirty.Load() || w.anchorFile != nil) {
		if err := w.persistAnchorIfChanged(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if w.manifest != nil && !w.opts.readOnly {
		// Always release the shard handle; a poisoned manifest skips compaction
		// internally but must still be closed. | 始终释放分片句柄；poisoned 的
		// MANIFEST 内部跳过压缩，但仍须关闭文件。
		if err := w.manifest.close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if w.meta != nil {
		if err := w.meta.close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if w.anchorFile != nil {
		if err := w.anchorFile.close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	// Wait for any in-flight on-demand sidecar upgrade before releasing the
	// directory lock. | 释放目录锁前等待所有按需侧车升级结束。
	w.idxWriteMu.Lock()
	w.idxWriteMu.Unlock()
	if w.lock != nil {
		if err := w.lock.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	w.closeEngineWhenIdle()
	return firstErr
}

// closeEngineWhenIdle closes read-side resources after every lease ends. | closeEngineWhenIdle
// 在所有租约结束后关闭读侧资源。
func (w *WAL) closeEngineWhenIdle() {
	w.readMu.Lock()
	w.readClosed = true
	idle := w.readLeases == 0
	w.readMu.Unlock()
	if idle {
		w.closeEngine()
	}
}

// closeEngine closes the fd cache, index cache, and I/O engine exactly once. | closeEngine
// 只关闭一次 fd 缓存、索引缓存与 I/O 引擎。
func (w *WAL) closeEngine() {
	w.engineCloseOnce.Do(func() {
		w.fdcache.closeAll()
		w.idxcache.closeAll()
		if w.engine != nil {
			_ = w.engine.Close()
		}
		// Derived key material is no longer needed once every Reader lease ends. | 所有 Reader 租约结束后不再需要派生密钥材料。
		if w.bound != nil {
			w.bound.close()
		}
	})
}

// beginRead takes a read lease; it fails after Close. | beginRead 获取读租约；Close 后失败。
func (w *WAL) beginRead() error {
	w.readMu.Lock()
	if w.readClosed {
		w.readMu.Unlock()
		return ErrClosed
	}
	w.readLeases++
	// Mark the read before flushing so a concurrent commit stops buffering and
	// cannot publish metadata ahead of bytes this reader still cannot see. |
	// 在刷新前标记读取，使并发提交停止缓冲，也不会把元数据发布到该读取器仍看不到
	// 的字节之前。
	w.readersActive.Add(1)
	w.readMu.Unlock()
	if err := w.flushWriteBuf(); err != nil {
		// flushWriteBufLocked discards the userspace buffer on failure, so
		// records already acknowledged under SyncInterval/SyncNever are gone;
		// continuing would append past a hole in the segment. Poison exactly
		// like every other write/sync failure site. | flushWriteBufLocked 失败时
		// 会丢弃用户态缓冲，SyncInterval/SyncNever 下已确认的记录因此丢失；继续
		// 追加会在分段中留下空洞。与其它写/同步失败路径一样 poison。
		w.setPoison(err)
		w.readersActive.Add(-1)
		w.readMu.Lock()
		w.readLeases--
		w.readMu.Unlock()
		return err
	}
	return nil
}

// endRead releases a read lease and closes the engine when idle. | endRead 释放读租约并在空闲时关闭引擎。
func (w *WAL) endRead() {
	w.readMu.Lock()
	if w.readLeases > 0 {
		w.readLeases--
		w.readersActive.Add(-1)
	}
	idle := w.readClosed && w.readLeases == 0
	w.readMu.Unlock()
	if idle {
		w.closeEngine()
	}
}

// notifyFollow broadcasts a new committed snapshot to Follow readers. | notifyFollow
// 向 Follow 读者广播新的已提交快照。
func (w *WAL) notifyFollow() {
	if w.followReaders.Load() == 0 {
		return
	}
	w.notifyMu.Lock()
	w.notifyGen++
	close(w.notifyCh)
	w.notifyCh = make(chan struct{})
	w.notifyMu.Unlock()
}

// followChannel returns the current generation channel and generation. | followChannel
// 返回当前代际通道与代际号。
func (w *WAL) followChannel() (uint64, chan struct{}) {
	w.notifyMu.Lock()
	defer w.notifyMu.Unlock()
	return w.notifyGen, w.notifyCh
}

// notifyCleaner wakes cleaner waiters. | notifyCleaner 唤醒 cleaner 等待者。
func (w *WAL) notifyCleaner() {
	w.cleanerMu.Lock()
	w.cleanerGen++
	close(w.cleanerCh)
	w.cleanerCh = make(chan struct{})
	w.cleanerMu.Unlock()
}

// cleanerChannel returns the current cleaner generation channel. | cleanerChannel
// 返回当前 cleaner 代际通道。
func (w *WAL) cleanerChannel() (uint64, chan struct{}) {
	w.cleanerMu.Lock()
	defer w.cleanerMu.Unlock()
	return w.cleanerGen, w.cleanerCh
}

// backupPendingCount returns the number of unfinished backup items. | backupPendingCount
// 返回未完成备份条目数。
func (w *WAL) backupPendingCount() uint64 {
	w.backupMu.Lock()
	defer w.backupMu.Unlock()
	return uint64(w.backupPendingLocked())
}

// notifyBackup wakes backup waiters. | notifyBackup 唤醒备份等待者。
func (w *WAL) notifyBackup() {
	w.backupMu.Lock()
	w.backupGen++
	close(w.backupCh)
	w.backupCh = make(chan struct{})
	w.backupMu.Unlock()
}

// backupChannel returns the current backup generation channel. | backupChannel
// 返回当前备份代际通道。
func (w *WAL) backupChannel() (uint64, chan struct{}) {
	w.backupMu.Lock()
	defer w.backupMu.Unlock()
	return w.backupGen, w.backupCh
}

// reportAsync invokes ErrorHandler without letting its panic reach a worker. | reportAsync
// 调用 ErrorHandler，并防止其 panic 影响 worker。
func (w *WAL) reportAsync(err error) {
	if w.handler == nil || err == nil {
		return
	}
	func() {
		defer func() { _ = recover() }()
		w.handler(err)
	}()
}

// ensureWorkers starts the worker set on first use. It must not start after
// Close has set the closed flag. | ensureWorkers 在首次使用时启动 worker 集合；
// Close 置位后不得再启动。
func (w *WAL) ensureWorkers() {
	w.workerMu.Lock()
	defer w.workerMu.Unlock()
	if w.workersStarted || w.closedFlag.Load() {
		return
	}
	w.startWorkersLocked()
}

// startWorkers starts the workers eagerly (used for backup reconciliation). |
// startWorkers 立即启动 worker（用于备份对账）。
func (w *WAL) startWorkers() {
	w.workerMu.Lock()
	defer w.workerMu.Unlock()
	if w.workersStarted || w.closedFlag.Load() {
		return
	}
	w.startWorkersLocked()
}

// startWorkersLocked launches writer, checkpoint, cleaner, backup, and
// retention. The caller holds workerMu. | startWorkersLocked 启动 writer、
// checkpoint、cleaner、backup 与 retention；调用方持有 workerMu。
func (w *WAL) startWorkersLocked() {
	w.workersStarted = true
	w.checkpointWG.Add(1)
	go w.checkpointLoop()
	w.cleanerWG.Add(1)
	go w.cleanerLoop()
	if w.opts.backup != nil {
		w.backupTarget = w.opts.backup.Target()
		if v, ok := w.opts.backup.(BackupVerifier); ok {
			w.backupVerify = v
		}
		w.backupCtx, w.backupCancel = context.WithCancel(context.Background())
		for i := 0; i < w.opts.backupWorkers; i++ {
			w.backupWG.Add(1)
			go w.backupLoop()
		}
		w.startBackupReconciliation()
	}
	if w.opts.retentionEnabled {
		w.retentionCtx, w.retentionCancel = context.WithCancel(context.Background())
		w.retentionWG.Add(1)
		go w.retentionLoop()
	}
	go w.writerLoop()
}

// segmentForLSNLocked returns the first live segment whose lastLSN is at or
// above lsn. The caller holds w.mu.RLock. Segment ranges are monotonically
// ordered, so this is a binary search instead of a full scan. | segmentForLSNLocked
// 返回 lastLSN 不低于 lsn 的第一个存活分段。调用方持有 w.mu.RLock；分段 LSN
// 区间单调有序，因此使用二分而不是全表扫描。
func (w *WAL) segmentForLSNLocked(lsn uint64) *segment {
	idx := sort.Search(len(w.segments), func(i int) bool {
		s := w.segments[i]
		s.metaMu.RLock()
		last := s.lastLSN
		s.metaMu.RUnlock()
		return last >= lsn
	})
	if idx == len(w.segments) {
		return nil
	}
	return w.segments[idx]
}

// runtimeOS returns the runtime OS name. | runtimeOS 返回运行时 OS 名称。
func runtimeOS() string { return runtime.GOOS }
