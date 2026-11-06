package wal

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
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
	dir  string
	opts options

	lock     *dirLock
	meta     *metaStore
	manifest *manifest
	engine   IOEngine
	fdcache  *fdCache
	idxcache *indexCache

	counters counters

	mu             sync.RWMutex
	closed         bool
	closedFlag     atomic.Bool
	closing        chan struct{}
	closedCh       chan struct{}
	closeOnce      sync.Once
	closeErr       error
	poison         atomic.Pointer[error]
	segments       []*segment
	segBySeq       map[uint64]*segment
	active         *segment
	walID          [16]byte
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

	keyRing             *KeyRing
	bound               *boundRing
	activeKeyID         uint32
	activeKCV           uint64
	nonce               *nonceGen
	encrypted           bool
	serializableDurable bool
	hashAlg             HashAlgorithm

	dedup            *dedupTable
	idem             *idemTable
	occ              *occState
	indexer          Indexer
	handler          func(error)
	lastTimestamp    int64
	keyIndexOverflow bool
	aadScratch       []byte
	preparedArena    []preparedRecord

	appendQ     chan *appendRequest
	writerDone  chan struct{}
	writerErrMu sync.Mutex
	writerErr   error

	notifyMu      sync.Mutex
	notifyGen     uint64
	notifyCh      chan struct{}
	followReaders atomic.Int64

	checkpointMu      sync.Mutex
	checkpointPending *checkpointJob
	checkpointNotify  chan struct{}
	checkpointStop    chan struct{}
	checkpointWG      sync.WaitGroup
	checkpointBytes   int64
	syncedSize        int64
	syncedLSN         uint64
	syncedRecordCount uint64
	syncedCRC         uint32
	syncedCommitSeq   uint64
	pendingSync       bool

	cleanerMu   sync.Mutex
	cleanerGen  uint64
	cleanerCh   chan struct{}
	cleanerStop chan struct{}
	cleanerWG   sync.WaitGroup
	cleanerQ    []*segment
	cleanerBusy bool

	backupMu     sync.Mutex
	backupGen    uint64
	backupCh     chan struct{}
	backupCtx    context.Context
	backupCancel context.CancelFunc
	backupWG     sync.WaitGroup
	backupItems  map[uint64]*backupItem
	backupTarget string
	backupVerify BackupVerifier

	retentionCtx     context.Context
	retentionCancel  context.CancelFunc
	retentionStop    chan struct{}
	retentionTrigger chan struct{}
	retentionWG      sync.WaitGroup

	readMu          sync.Mutex
	readLeases      int
	readClosed      bool
	readCond        *sync.Cond
	engineCloseOnce sync.Once
	readBufPool     sync.Pool
	readScratchPool sync.Pool
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
		closing:          make(chan struct{}),
		closedCh:         make(chan struct{}),
		segBySeq:         make(map[uint64]*segment),
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
		backupItems:      make(map[uint64]*backupItem),
	}
	w.readCond = sync.NewCond(&w.readMu)
	w.engine = defaultIOEngine(&o)
	if o.ioEngine != nil {
		w.engine = o.ioEngine
	}
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
		_ = lock.Close()
		if w.meta != nil {
			_ = w.meta.close()
		}
		if w.manifest != nil {
			_ = w.manifest.close()
		}
		return nil, err
	}
	if !o.readOnly {
		if err := w.persistMetaIfChanged(); err != nil {
			_ = w.meta.close()
			_ = w.manifest.close()
			_ = lock.Close()
			return nil, err
		}
		w.startWorkers()
	}
	return w, nil
}

// metaCurrent reports whether persisted META already matches the in-memory
// state. | metaCurrent 报告已持久化 META 是否已与内存状态一致。
func (w *WAL) metaCurrent() bool {
	if w.meta == nil || !w.meta.hasState {
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
	return w.meta.write(w.metaSnapshot())
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

// Append writes one record and returns its LSN. | Append 写入一条记录并返回其 LSN。
func (w *WAL) Append(ctx context.Context, rec Record) (uint64, error) {
	if w.opts.readOnly {
		return 0, ErrReadOnly
	}
	if err := w.validateUserRecord(rec, false); err != nil {
		return 0, err
	}
	req := &appendRequest{kind: kindData, recs: []Record{rec}, done: make(chan appendResult, 1)}
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

// AppendBatch writes a batch atomically and returns its last LSN. | AppendBatch
// 原子写入一批记录并返回最后一条 LSN。
func (w *WAL) AppendBatch(ctx context.Context, recs []Record) (uint64, error) {
	if w.opts.readOnly {
		return 0, ErrReadOnly
	}
	if len(recs) == 0 {
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
	req := &appendRequest{kind: kindData, recs: recs, done: make(chan appendResult, 1)}
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
	req := &appendRequest{
		kind:     kindData,
		recs:     []Record{rec},
		once:     true,
		dedupKey: append([]byte(nil), dedupKey...),
		done:     make(chan appendResult, 1),
	}
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

// AppendAsync enqueues one record without waiting for the commit. | AppendAsync
// 入队一条记录而不等待提交完成。
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
	if w.manifest != nil && !w.opts.readOnly && w.poisonedErr() == nil {
		if err := w.manifest.close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if w.meta != nil {
		if err := w.meta.close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
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
	defer w.readMu.Unlock()
	if w.readClosed {
		return ErrClosed
	}
	w.readLeases++
	return nil
}

// endRead releases a read lease and closes the engine when idle. | endRead 释放读租约并在空闲时关闭引擎。
func (w *WAL) endRead() {
	w.readMu.Lock()
	if w.readLeases > 0 {
		w.readLeases--
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
	n := uint64(0)
	for _, item := range w.backupItems {
		if item.state == backupPending || item.state == backupRunning {
			n++
		}
	}
	return n
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

// startWorkers launches writer, checkpoint, cleaner, backup, and retention. | startWorkers
// 启动 writer、checkpoint、cleaner、backup 与 retention。
func (w *WAL) startWorkers() {
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

// runtimeOS returns the runtime OS name. | runtimeOS 返回运行时 OS 名称。
func runtimeOS() string { return runtime.GOOS }
