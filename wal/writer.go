package wal

import (
	"errors"
	"math"
	"os"
	"time"

	"github.com/shibingli/ydx/errs"
)

// reqKind identifies a writer request. | reqKind 标识写入协程请求类型。
type reqKind uint8

const (
	kindData reqKind = iota
	kindTxnCommit
	kindSync
	kindBarrier
	kindRotate
	kindSetActiveKey
	kindTruncate
	kindBackupSnapshot
	kindClose
)

// appendRequest is one unit of work for the single writer. | appendRequest 是单写协程的一个工作单元。
type appendRequest struct {
	txn    *Tx
	future *AppendFuture
	done   chan appendResult

	// Writer-local planning state. | 写入协程本地规划状态。
	plan      *reqPlan
	recs      []Record
	dedupKey  []byte
	dedupBuf  []byte
	one       [1]Record
	beforeLSN uint64

	keyID       uint32
	kind        reqKind
	once        bool
	allowStream bool
	async       bool
	internal    bool
}

// reqPlan carries one request's batch outcome. | reqPlan 保存单个请求在批次中的结果。
type reqPlan struct {
	err             error
	req             *appendRequest
	immediate       *appendResult
	txnInfo         TxnInfo
	winner          int
	txnSeq          uint64
	writeFirst      uint64
	writeLast       uint64
	keyDigest       [32]byte
	contentDigest   [32]byte
	pendingDup      bool
	pendingConflict bool
	txnAccepted     bool
	onceWinner      bool
}

// writerLoop is the single writer goroutine. | writerLoop 是单写协程。
func (w *WAL) writerLoop() {
	defer close(w.writerDone)
	var ageTicker *time.Ticker
	var ageC <-chan time.Time
	if w.opts.segmentMaxAge > 0 {
		d := w.opts.segmentMaxAge / 4
		if d > time.Second {
			d = time.Second
		}
		if d <= 0 {
			d = time.Millisecond
		}
		ageTicker = time.NewTicker(d)
		ageC = ageTicker.C
		defer ageTicker.Stop()
	}
	var syncTicker *time.Ticker
	var syncC <-chan time.Time
	if w.opts.syncPolicy.Mode == SyncModeInterval {
		syncTicker = time.NewTicker(w.opts.syncPolicy.Interval)
		syncC = syncTicker.C
		defer syncTicker.Stop()
	}
	var pending *appendRequest
	for {
		var req *appendRequest
		if pending != nil {
			req = pending
			pending = nil
		} else {
			select {
			case <-ageC:
				if err := w.maybeRotateAge(); err != nil {
					w.setPoison(err)
				}
				continue
			case <-syncC:
				if err := w.flushPendingSync(); err != nil {
					w.setPoison(err)
				}
				continue
			case r := <-w.appendQ:
				req = r
			}
		}
		switch req.kind {
		case kindClose:
			w.finishWriter()
			req.done <- appendResult{}
			return
		case kindData, kindTxnCommit:
			batch, deferred := w.drainBatch(req)
			w.commitBatch(batch)
			pending = deferred
		default:
			w.handleControl(req)
		}
	}
}

// drainBatch collects a group-commit batch and returns the first deferred
// control or over-limit data request. | drainBatch 收集组提交批次，并返回第一个被
// 延后的控制请求或超限数据请求。
func (w *WAL) drainBatch(first *appendRequest) ([]*appendRequest, *appendRequest) {
	if cap(w.batchBuf) == 0 {
		w.batchBuf = make([]*appendRequest, 0, 8)
	}
	batch := w.batchBuf[:0]
	// Clear the backing array so the pool does not pin previous requests. | 清空
	// 底层数组，避免复用区钉住上一批请求。
	full := batch[:cap(batch)]
	for i := range full {
		full[i] = nil
	}
	batch = append(batch, first)
	defer func() { w.batchBuf = batch }()
	records := requestRecordCount(first)
	bytes := requestByteCount(first)
	for len(batch) < w.opts.maxBatchRecords && records < w.opts.maxBatchRecords && bytes < w.opts.maxBatchBytes {
		select {
		case r := <-w.appendQ:
			if r.kind != kindData && r.kind != kindTxnCommit {
				return batch, r
			}
			n := requestRecordCount(r)
			b := requestByteCount(r)
			if records+n > w.opts.maxBatchRecords || bytes+b > w.opts.maxBatchBytes {
				return batch, r
			}
			batch = append(batch, r)
			records += n
			bytes += b
		default:
			return batch, nil
		}
	}
	return batch, nil
}

// requestRecordCount returns the record count used by batch limits. | requestRecordCount
// 返回用于批限制的记录数。
func requestRecordCount(req *appendRequest) int {
	if req.kind == kindTxnCommit && req.txn != nil {
		return len(req.txn.records)
	}
	return len(req.recs)
}

// requestByteCount returns the payload bytes used by batch limits. | requestByteCount
// 返回用于批限制的负载字节数。
func requestByteCount(req *appendRequest) int {
	if req.kind == kindTxnCommit && req.txn != nil {
		return int(req.txn.bytes)
	}
	total := 0
	for _, rec := range req.recs {
		total += len(rec.Key) + len(rec.Data) + recordHeaderSizeEncrypted
	}
	return total
}

// handleControl executes one control request. | handleControl 执行一个控制请求。
func (w *WAL) handleControl(req *appendRequest) {
	res := appendResult{}
	if err := w.poisonedErr(); err != nil && req.kind != kindClose {
		res.err = err
		req.done <- res
		return
	}
	switch req.kind {
	case kindSync:
		res.err = w.flushPendingSync()
	case kindBarrier:
		// Ordering only. | 仅用于排序。
	case kindRotate:
		res.err = w.rotate()
	case kindSetActiveKey:
		res.err = w.setActiveKey(req.keyID)
	case kindTruncate:
		res.segments, res.err = w.truncate(req.beforeLSN)
	case kindBackupSnapshot:
		res.backupSet = w.captureBackupSet()
	default:
		res.err = errs.Detail(ErrInvalidOptions, "unknown writer request %[1]d | 未知写入请求 %[1]d", req.kind)
	}
	if res.err != nil && !benignControlError(res.err) {
		w.setPoison(res.err)
	}
	req.done <- res
}

// benignControlError reports caller-input control errors that must not poison
// the WAL. A bad SetActiveKey ID is not a storage failure and previous state is
// unchanged. | benignControlError 返回不应 poison WAL 的调用方输入错误；错误的
// SetActiveKey ID 不是存储故障，原状态未被改变。
func benignControlError(err error) bool {
	return errors.Is(err, ErrInvalidKey) || errors.Is(err, ErrKeyNotFound) ||
		errors.Is(err, ErrCipherMismatch) || errors.Is(err, ErrInvalidOptions)
}

// finishWriter seals the final segment without writing META. | finishWriter 封存最终分段但不写 META。
func (w *WAL) finishWriter() {
	if w.poisonedErr() != nil {
		if w.active != nil {
			_ = w.engine.Sync(w.active.f)
			w.active.closeWriter()
			w.active = nil
		}
		return
	}
	if err := w.flushPendingSync(); err != nil {
		w.setPoison(err)
		w.setWriterErr(err)
	}
	if w.active != nil {
		if w.active.size > int64(segmentHeaderSize) {
			if err := w.sealSegment(w.active); err != nil {
				w.setPoison(err)
				w.setWriterErr(err)
			} else {
				w.enqueueBackup(w.active)
			}
		}
		w.active.closeWriter()
		w.active = nil
	}
}

// setWriterErr records the first close-time writer error. | setWriterErr 记录首个关闭期写入错误。
func (w *WAL) setWriterErr(err error) {
	if err == nil {
		return
	}
	w.writerErrMu.Lock()
	if w.writerErr == nil {
		w.writerErr = err
	}
	w.writerErrMu.Unlock()
}

// flushPendingSync synchronizes pending writes and advances the checkpoint
// watermark. | flushPendingSync 同步待写入并推进检查点水位。
func (w *WAL) flushPendingSync() error {
	if !w.pendingSync || w.active == nil {
		return nil
	}
	if err := w.engine.Sync(w.active.f); err != nil {
		w.counters.syncErrors.Add(1)
		return wrapStorage("sync data", err)
	}
	w.pendingSync = false
	w.counters.syncs.Add(1)
	w.markSynced()
	return nil
}

// markSynced records the new synced prefix and schedules a checkpoint. | markSynced
// 记录新的已同步前缀并调度检查点。
func (w *WAL) markSynced() {
	if w.active == nil {
		return
	}
	w.active.metaMu.RLock()
	w.syncedSize = w.active.size
	w.syncedLSN = w.active.lastLSN
	w.syncedRecordCount = w.active.recordCount
	w.syncedCRC = w.active.crc
	w.active.metaMu.RUnlock()
	w.syncedCommitSeq = w.commitSeq
	w.maybeCheckpoint()
}

// maybeCheckpoint submits the latest checkpoint snapshot without blocking. | maybeCheckpoint
// 非阻塞投递最新检查点快照。
func (w *WAL) maybeCheckpoint() {
	if w.active == nil || w.syncedSize <= int64(segmentHeaderSize) {
		return
	}
	if w.syncedSize-w.checkpointBytes < w.opts.checkpointBytes {
		return
	}
	w.checkpointBytes = w.syncedSize
	job := w.buildCheckpointJob(w.active)
	if job == nil {
		return
	}
	w.checkpointMu.Lock()
	w.checkpointPending = job
	w.checkpointMu.Unlock()
	select {
	case w.checkpointNotify <- struct{}{}:
	default:
	}
}

// buildCheckpointJob copies the synced prefix index. | buildCheckpointJob 复制已同步前缀索引。
func (w *WAL) buildCheckpointJob(seg *segment) *checkpointJob {
	seg.metaMu.RLock()
	defer seg.metaMu.RUnlock()
	job := &checkpointJob{
		seg:          seg,
		segmentBytes: w.syncedSize,
		lastLSN:      w.syncedLSN,
		recordCount:  w.syncedRecordCount,
		segmentCRC:   w.syncedCRC,
		commitSeq:    w.syncedCommitSeq,
		minTime:      seg.minTime,
		maxTime:      seg.maxTime,
		walID:        seg.walID,
	}
	if seg.sparseComplete || (len(seg.sparse) > 0 && seg.sparse[0].lsn == seg.baseLSN) {
		for _, sp := range seg.sparse {
			if sp.offset < w.syncedSize {
				job.sparse = append(job.sparse, sp)
			}
		}
	}
	job.hasKeyIndex = w.opts.keyIndex && seg.keyIndexComplete && !seg.keyIndexOverflow
	if job.hasKeyIndex && seg.keyIndex != nil {
		job.keyIndex = make(map[string][]uint64, len(seg.keyIndex))
		for k, lsns := range seg.keyIndex {
			for _, lsn := range lsns {
				if lsn <= w.syncedLSN {
					job.keyIndex[k] = append(job.keyIndex[k], lsn)
				}
			}
			if len(job.keyIndex[k]) == 0 {
				delete(job.keyIndex, k)
			}
		}
	}
	job.keyIndexOverflow = seg.keyIndexOverflow
	return job
}

// maybeRotateAge rotates an old active segment. | maybeRotateAge 轮转超龄活动段。
func (w *WAL) maybeRotateAge() error {
	if w.opts.segmentMaxAge <= 0 || w.active == nil || w.active.size <= int64(segmentHeaderSize) {
		return nil
	}
	if time.Since(time.Unix(0, w.active.createdNano)) < w.opts.segmentMaxAge {
		return nil
	}
	return w.rotate()
}

// rotate performs the full rotation sequence. | rotate 执行完整轮转序列。
func (w *WAL) rotate() error {
	if err := w.poisonedErr(); err != nil {
		return err
	}
	old := w.active
	if old == nil || old.size <= int64(segmentHeaderSize) {
		return nil
	}
	if w.nextSeq == math.MaxUint64 {
		return errs.Detail(ErrTooLarge, "WAL segment sequence space is exhausted | WAL 分段序号空间已耗尽")
	}
	if err := w.flushPendingSync(); err != nil {
		return err
	}
	// Step 2: persist commitSeq/firstLSN before writing the full sidecar. | 第 2 步：写完整侧车前持久化 commitSeq/firstLSN。
	if err := w.meta.write(w.metaSnapshot()); err != nil {
		return err
	}
	// Steps 3-4: full sidecar, then the sealed MANIFEST record. | 第 3-4 步：完整侧车，然后追加封段 MANIFEST 记录。
	if err := w.sealSegment(old); err != nil {
		return err
	}
	// Step 5: create the new segment. | 第 5 步：创建新分段。
	seq := w.nextSeq
	base := w.nextLSN
	seg, err := createSegmentFile(w.dir, seq, base, w.walID, w.opts.fileMode, w.preallocateBytes())
	if err != nil {
		return err
	}
	w.nextSeq = seq + 1
	// Step 6: persist segment existence before accepting records. | 第 6 步：在接受记录前持久化分段存在性。
	if w.manifest.enabled {
		if err := w.manifest.append(manifestRecord{
			kind: manifestKindCreated, seq: seq, baseLSN: base, lastLSN: base - 1,
			segmentBytes: uint64(segmentHeaderSize), walID: w.walID, createdNano: seg.createdNano,
		}); err != nil {
			seg.closeWriter()
			return err
		}
	}
	// Step 7: persist nextSeq/nextLSN. | 第 7 步：持久化 nextSeq/nextLSN。
	if err := w.meta.write(w.metaSnapshot()); err != nil {
		seg.closeWriter()
		return err
	}
	// Step 7b: mirror the high-water state into the independent recovery
	// anchor before the new segment can accept records. | 第 7b 步：在新段接受
	// 记录前，把高水位镜像到独立恢复锚点。
	if err := w.persistAnchorIfChanged(); err != nil {
		seg.closeWriter()
		return err
	}
	// Step 8: publish the new active segment. | 第 8 步：发布新的活动段。
	w.mu.Lock()
	w.active = seg
	w.segments = append(w.segments, seg)
	w.segBySeq[seg.seq] = seg
	w.mu.Unlock()
	w.dedup.clear()
	w.syncedSize = int64(segmentHeaderSize)
	w.syncedLSN = seg.baseLSN - 1
	w.syncedRecordCount = 0
	w.syncedCRC = 0
	w.syncedCommitSeq = w.commitSeq
	w.checkpointBytes = 0
	w.pendingSync = false
	w.enqueueBackup(old)
	w.notifyFollow()
	w.triggerRetention()
	return nil
}

// preallocateBytes returns the optional fallocate size. | preallocateBytes 返回可选的 fallocate 大小。
func (w *WAL) preallocateBytes() int64 {
	if w.opts.fastPath.Mode == FastPathCustom && w.opts.fastPath.Preallocate {
		return w.opts.segmentMaxBytes
	}
	return 0
}

// sealSegment writes the full sidecar and the sealed MANIFEST record. | sealSegment
// 写入完整侧车与封段 MANIFEST 记录。
func (w *WAL) sealSegment(seg *segment) error {
	if seg == nil {
		return nil
	}
	seg.checkpointMu.Lock()
	if seg.currentState() != segmentActive {
		seg.checkpointMu.Unlock()
		return nil
	}
	seg.setState(segmentSealing)
	seg.checkpointMu.Unlock()

	data, idxCRC := w.buildFullSidecar(seg)
	if err := writeFileAtomic(seg.idxPath, data, w.opts.fileMode); err != nil {
		return err
	}
	seg.metaMu.Lock()
	seg.idxCRC = idxCRC
	seg.metaMu.Unlock()
	if w.manifest.enabled {
		lastLSN, recordCount, size, minTime, maxTime, crc, _, commitSeq := seg.summarySnapshot()
		if err := w.manifest.append(manifestRecord{
			kind: manifestKindSegment, seq: seg.seq, baseLSN: seg.baseLSN,
			lastLSN: lastLSN, segmentBytes: uint64(size), recordCount: recordCount,
			minTime: minTime, maxTime: maxTime, segmentCRC: crc, idxCRC: idxCRC,
			walID: w.walID, createdNano: seg.createdNano, commitSeq: commitSeq,
		}); err != nil {
			return err
		}
	}
	seg.setState(segmentSealed)
	seg.closeWriter()
	if w.opts.backup == nil {
		w.maybeFadvise(seg)
	}
	return nil
}

// maybeFadvise drops a sealed segment's clean page cache when explicitly
// enabled in FastPathCustom. | maybeFadvise 在 FastPathCustom 显式启用时回收
// 封段的干净页缓存。
func (w *WAL) maybeFadvise(seg *segment) {
	if seg == nil || w.opts.fastPath.Mode != FastPathCustom || !w.opts.fastPath.FadviseDontNeed {
		return
	}
	f, err := os.Open(seg.path)
	if err != nil {
		return
	}
	_ = fadviseDontNeed(f)
	_ = f.Close()
}

// buildFullSidecar encodes a complete .idx. | buildFullSidecar 编码完整 .idx。
func (w *WAL) buildFullSidecar(seg *segment) ([]byte, uint32) {
	seg.metaMu.RLock()
	s := &sidecar{
		seq:          seg.seq,
		baseLSN:      seg.baseLSN,
		lastLSN:      seg.lastLSN,
		recordCount:  seg.recordCount,
		segmentBytes: uint64(seg.size),
		minTime:      seg.minTime,
		maxTime:      seg.maxTime,
		segmentCRC:   seg.crc,
		dedupRefs:    seg.dedupRefs,
		compressed:   seg.compressed,
		walID:        seg.walID,
		commitSeq:    seg.commitSeq,
		hasKeyIndex:  w.opts.keyIndex && seg.keyIndexComplete && !seg.keyIndexOverflow,
	}
	if seg.sparseComplete {
		s.sparse = append([]sparseEntry(nil), seg.sparse...)
	}
	if s.hasKeyIndex && seg.keyIndex != nil {
		s.keyIndex = make(map[string][]uint64, len(seg.keyIndex))
		for k, v := range seg.keyIndex {
			s.keyIndex[k] = append([]uint64(nil), v...)
		}
	}
	seg.metaMu.RUnlock()
	data := encodeSidecar(s)
	return data, checksum(data)
}

// setActiveKey rotates and persists a new active key. | setActiveKey 轮换并持久化新的活动密钥。
func (w *WAL) setActiveKey(id uint32) error {
	if !w.encrypted {
		return errs.Detail(ErrCipherMismatch, "cannot rotate keys on a plaintext WAL | 明文 WAL 不能轮换密钥")
	}
	if id == 0 {
		return errs.Detail(ErrInvalidKey, "key ID 0 is reserved | 密钥 ID 0 为保留值")
	}
	if w.bound == nil {
		return ErrKeyNotFound
	}
	key, err := w.bound.key(id)
	if err != nil {
		return err
	}
	if id == w.activeKeyID {
		return nil
	}
	if w.active != nil && w.active.size > int64(segmentHeaderSize) {
		if err := w.rotate(); err != nil {
			return err
		}
	}
	w.activeKeyID = id
	w.activeKCV = key.kcv
	if err := w.meta.write(w.metaSnapshot()); err != nil {
		return err
	}
	return w.persistAnchorIfChanged()
}

// truncate implements the logical truncation sequence. | truncate 实现逻辑截断序列。
func (w *WAL) truncate(beforeLSN uint64) (int, error) {
	effective := beforeLSN
	if effective > w.nextLSN {
		effective = w.nextLSN
	}
	if effective <= w.firstLSN {
		return 0, nil
	}
	if err := w.poisonedErr(); err != nil {
		return 0, err
	}
	// META below persists the in-memory nextLSN high-water. Under SyncInterval
	// or SyncNever the acknowledged records may still be unsynced; sync them
	// first so a power loss cannot leave META ahead of the recovered segment
	// and make the next Open return ErrCorrupt. | 下面写入 META 的 nextLSN 高水位
	// 来自内存；SyncInterval/SyncNever 下已确认记录可能尚未落盘，必须先同步，
	// 否则掉电后 META 会超前于恢复结果，导致下次 Open 返回 ErrCorrupt。
	if err := w.flushPendingSync(); err != nil {
		return 0, err
	}
	if w.manifest.enabled {
		if err := w.manifest.append(manifestRecord{
			kind: manifestKindTruncate, baseLSN: effective, commitSeq: w.commitSeq, walID: w.walID,
		}); err != nil {
			return 0, err
		}
	}
	st := w.metaSnapshot()
	st.firstLSN = effective
	if err := w.meta.write(st); err != nil {
		return 0, err
	}
	w.mu.Lock()
	w.firstLSN = effective
	w.firstLSNAtomic.Store(effective)
	candidates := make([]*segment, 0, len(w.segments))
	for _, seg := range w.segments {
		if seg == w.active {
			continue
		}
		seg.metaMu.RLock()
		last := seg.lastLSN
		seg.metaMu.RUnlock()
		if last < effective && seg.currentState() == segmentSealed {
			candidates = append(candidates, seg)
		}
	}
	w.mu.Unlock()
	// Persist the truncation watermark in the independent anchor before any
	// segment becomes unreachable, so losing META and MANIFEST cannot resurrect
	// a partially deleted prefix. | 在任一分段变为不可读前，把截断水位写入独立
	// 锚点，使 META 与 MANIFEST 同时丢失也不会复活部分删除的前缀。
	w.gaps.pruneBefore(effective)
	if err := w.persistAnchorIfChanged(); err != nil {
		return 0, err
	}
	count := 0
	for _, seg := range candidates {
		if w.manifest.enabled {
			if err := w.manifest.append(manifestRecord{kind: manifestKindRetire, seq: seg.seq, walID: w.walID}); err != nil {
				return count, err
			}
		}
		w.retireSegment(seg)
		count++
	}
	return count, nil
}

// retireSegment removes a sealed segment from the live set and queues it for
// deletion. | retireSegment 从活动集合移除封段并交给 cleaner 删除。
func (w *WAL) retireSegment(seg *segment) {
	w.mu.Lock()
	if seg.retired {
		w.mu.Unlock()
		return
	}
	seg.retired = true
	for i, s := range w.segments {
		if s == seg {
			w.segments = append(w.segments[:i], w.segments[i+1:]...)
			break
		}
	}
	delete(w.segBySeq, seg.seq)
	w.mu.Unlock()
	w.cleanerMu.Lock()
	w.cleanerQ = append(w.cleanerQ, seg)
	w.cleanerMu.Unlock()
	w.notifyCleaner()
}

// triggerRetention requests an automatic-retention pass. | triggerRetention 请求一次自动保留检查。
func (w *WAL) triggerRetention() {
	if !w.opts.retentionEnabled {
		return
	}
	select {
	case w.retentionTrigger <- struct{}{}:
	default:
	}
}

// syncActive is used by finite shutdown paths. | syncActive 供有限关闭路径使用。
func (w *WAL) syncActive() error {
	if w.active == nil || w.active.f == nil {
		return nil
	}
	if err := w.engine.Sync(w.active.f); err != nil {
		return wrapStorage("sync active segment", err)
	}
	return nil
}

// ensureActive creates the first active segment when needed. | ensureActive 在需要时创建首个活动段。
func (w *WAL) ensureActive() error {
	if w.active != nil {
		return nil
	}
	seq := w.nextSeq
	if seq == 0 || seq == math.MaxUint64 {
		return errs.Detail(ErrTooLarge, "WAL segment sequence space is exhausted | WAL 分段序号空间已耗尽")
	}
	base := w.nextLSN
	seg, err := createSegmentFile(w.dir, seq, base, w.walID, w.opts.fileMode, w.preallocateBytes())
	if err != nil {
		return err
	}
	w.nextSeq = seq + 1
	if w.manifest.enabled {
		if err := w.manifest.append(manifestRecord{
			kind: manifestKindCreated, seq: seq, baseLSN: base, lastLSN: base - 1,
			segmentBytes: uint64(segmentHeaderSize), walID: w.walID, createdNano: seg.createdNano,
		}); err != nil {
			seg.closeWriter()
			return err
		}
	}
	if err := w.meta.write(w.metaSnapshot()); err != nil {
		seg.closeWriter()
		return err
	}
	if err := w.persistAnchorIfChanged(); err != nil {
		seg.closeWriter()
		return err
	}
	w.mu.Lock()
	w.active = seg
	w.segments = append(w.segments, seg)
	w.segBySeq[seg.seq] = seg
	w.mu.Unlock()
	w.syncedSize = int64(segmentHeaderSize)
	w.syncedLSN = seg.baseLSN - 1
	w.syncedRecordCount = 0
	w.syncedCRC = 0
	w.syncedCommitSeq = w.commitSeq
	w.checkpointBytes = 0
	w.pendingSync = false
	w.dedup.clear()
	return nil
}

// fileForSegment returns the writer-side file for the active segment. | fileForSegment
// 返回活动段的写侧文件。
func (w *WAL) fileForSegment(seg *segment) *os.File {
	return seg.f
}
