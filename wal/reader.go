package wal

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"os"
	"sort"
	"sync"

	"github.com/shibingli/ydx/errs"
)

// readerReadAhead is the sequential read-ahead buffer size. | readerReadAhead 是顺序预读缓冲大小。
const readerReadAhead = 256 << 10

// readerOptions is the normalized Reader configuration. | readerOptions 是归一化后的 Reader 配置。
type readerOptions struct {
	from   uint64
	to     uint64
	buffer int
	hasTo  bool
	follow bool
	pinAll bool
}

// ReaderOption customizes a Reader. | ReaderOption 定制 Reader。
type ReaderOption func(*readerOptions)

// From starts a Reader at lsn; zero means FirstLSN. | From 从 lsn 开始读取，0 表示 FirstLSN。
func From(lsn uint64) ReaderOption { return func(o *readerOptions) { o.from = lsn } }

// To bounds a Reader at lsn; zero means no upper bound. | To 把 Reader 上界设为 lsn，0 表示无上界。
func To(lsn uint64) ReaderOption {
	return func(o *readerOptions) {
		o.to = lsn
		o.hasTo = lsn != 0
	}
}

// Follow makes a Reader wait for future commits. | Follow 让 Reader 等待后续提交。
func Follow() ReaderOption { return func(o *readerOptions) { o.follow = true } }

// WithBufferSize sets the Reader buffer size. | WithBufferSize 设置 Reader 缓冲大小。
func WithBufferSize(n int) ReaderOption { return func(o *readerOptions) { o.buffer = n } }

// pinRange pins every segment in the Reader range for its lifetime. | pinRange
// 在 Reader 生命周期内固定范围内的所有分段。
func pinRange() ReaderOption { return func(o *readerOptions) { o.pinAll = true } }

// SnapshotOf bounds a Reader at the snapshot's committed prefix. The bound is
// always active, even when LastLSN is zero. | SnapshotOf 把 Reader 限定在快照的
// 已提交前缀；即使 LastLSN 为零上界也生效。
func SnapshotOf(s Snapshot) ReaderOption {
	return func(o *readerOptions) {
		o.to = s.LastLSN
		o.hasTo = true
	}
}

// Reader sequentially reads committed records. Returned Record views alias an
// internal buffer and expire on the next Next call or on Close; clone them to
// retain. | Reader 顺序读取已提交记录。返回的 Record 视图指向内部缓冲，在下一次
// Next 或 Close 后失效；需要保留请 Clone。
type Reader struct {
	w    *WAL
	cond *sync.Cond

	seg      *segment
	file     *os.File
	br       *bufio.Reader
	done     chan struct{}
	buf      []byte
	scratch  []byte
	pinned   []*segment
	from     uint64
	to       uint64
	inFlight int

	off int64
	// segEnd caches the segment's readable end; it is refreshed only when the
	// reader reaches it. | segEnd 缓存分段的当前可读末尾，仅在读到末尾时刷新。
	segEnd       int64
	lastReturned uint64
	bufSize      int
	closeOnce    sync.Once

	nextMu        sync.Mutex
	stateMu       sync.Mutex
	header        [recordHeaderSizeEncrypted]byte
	hasTo         bool
	follow        bool
	followCounted bool

	closing bool
	pinAll  bool
}

// NewReader opens a Reader. | NewReader 打开一个 Reader。
func (w *WAL) NewReader(opts ...ReaderOption) (*Reader, error) {
	ro := readerOptions{buffer: defaultReaderBuffer}
	for _, fn := range opts {
		if fn != nil {
			fn(&ro)
		}
	}
	if ro.buffer <= 0 {
		ro.buffer = defaultReaderBuffer
	}
	w.mu.RLock()
	if w.closed {
		w.mu.RUnlock()
		return nil, ErrClosed
	}
	if err := w.beginRead(); err != nil {
		w.mu.RUnlock()
		return nil, err
	}
	first := w.firstLSN
	last := w.LastLSN()
	w.mu.RUnlock()
	if ro.from == 0 {
		ro.from = first
	} else if ro.from < first {
		w.endRead()
		return nil, errs.Detail(ErrNotFound, "LSN %[1]d is below FirstLSN %[2]d | LSN %[1]d 小于 FirstLSN %[2]d", ro.from, first)
	}
	r := &Reader{
		w:             w,
		from:          ro.from,
		to:            ro.to,
		hasTo:         ro.hasTo,
		follow:        ro.follow,
		followCounted: ro.follow,
		bufSize:       ro.buffer,
		buf:           make([]byte, 0, ro.buffer),
		pinAll:        ro.pinAll,
		done:          make(chan struct{}),
	}
	r.cond = sync.NewCond(&r.stateMu)
	if ro.follow {
		w.followReaders.Add(1)
	}
	if ro.from > last && !ro.follow {
		r.from = last + 1
	}
	if ro.pinAll {
		w.mu.RLock()
		for _, seg := range w.segments {
			seg.metaMu.RLock()
			base, segLast := seg.baseLSN, seg.lastLSN
			seg.metaMu.RUnlock()
			if segLast < ro.from || (ro.hasTo && base > ro.to) {
				continue
			}
			seg.retain()
			r.pinned = append(r.pinned, seg)
		}
		w.mu.RUnlock()
	}
	return r, nil
}

// Next returns the next committed record or io.EOF. Key and Data alias the
// Reader's reusable buffer and remain valid only until the next Next call; use
// Record.Clone to retain them. | Next 返回下一条已提交记录或 io.EOF。Key 与
// Data 指向 Reader 的复用缓冲，仅在下次 Next 前有效；需要保留请调用
// Record.Clone。
func (r *Reader) Next() (Record, error) {
	return r.NextContext(context.Background())
}

// NextContext is Next with cancellation. | NextContext 是带取消的 Next。
func (r *Reader) NextContext(ctx context.Context) (Record, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	r.nextMu.Lock()
	defer r.nextMu.Unlock()
	r.stateMu.Lock()
	if r.closing {
		r.stateMu.Unlock()
		return Record{}, ErrClosed
	}
	if r.hasTo && r.from > r.to {
		r.stateMu.Unlock()
		return Record{}, io.EOF
	}
	r.inFlight++
	r.stateMu.Unlock()
	defer func() {
		r.stateMu.Lock()
		r.inFlight--
		if r.inFlight == 0 {
			r.cond.Broadcast()
		}
		r.stateMu.Unlock()
	}()
	for {
		select {
		case <-ctx.Done():
			return Record{}, ctx.Err()
		default:
		}
		if r.hasTo && r.lastReturned >= r.to {
			return Record{}, io.EOF
		}
		if r.file == nil {
			if err := r.openAt(ctx); err != nil {
				if err == errNoMoreData {
					if r.follow && !r.w.isClosed() {
						if err := r.wait(ctx); err != nil {
							return Record{}, err
						}
						continue
					}
					return Record{}, io.EOF
				}
				return Record{}, err
			}
		}
		if r.off >= r.segEnd {
			r.segEnd = r.segmentSize()
		}
		if r.off >= r.segEnd {
			next, err := r.advanceSegment(ctx)
			if err != nil {
				return Record{}, err
			}
			if next {
				continue
			}
			if r.follow && !r.w.isClosed() {
				if err := r.wait(ctx); err != nil {
					return Record{}, err
				}
				continue
			}
			return Record{}, io.EOF
		}
		hdr, payload, buf, scratch, err := r.w.decodeRecordStream(r.seg, r.br, r.off, r.segEnd, r.buf, r.scratch, &r.header)
		if err != nil {
			return Record{}, err
		}
		r.buf, r.scratch = buf, scratch
		r.off += int64(hdr.size)
		if hdr.flags&recordFlagCommitMark != 0 || hdr.codec == codecTxnControl {
			continue
		}
		if hdr.lsn < r.from || hdr.lsn < r.w.FirstLSN() {
			continue
		}
		if r.hasTo && hdr.lsn > r.to {
			return Record{}, io.EOF
		}
		rec, nscratch, err := r.w.resolveRecordView(r.seg, r.file, r.off, hdr, payload, r.scratch, &r.header)
		r.scratch = nscratch
		if err != nil {
			return Record{}, err
		}
		r.lastReturned = rec.LSN
		return rec, nil
	}
}

// errNoMoreData is an internal sentinel. | errNoMoreData 是内部哨兵。
var errNoMoreData = errs.New("wal: no more data | wal：没有更多数据")

// openAt opens the first segment covering the Reader position. | openAt 打开覆盖读取位置的第一个分段。
func (r *Reader) openAt(ctx context.Context) error {
	seg, off, err := r.w.locateRead(r.from)
	if err != nil {
		return err
	}
	if seg == nil {
		return errNoMoreData
	}
	f, err := os.Open(seg.path)
	if err != nil {
		seg.release(r.w)
		if os.IsNotExist(err) {
			return errs.Detail(ErrMissingSegment, "segment %[1]d is missing | 分段 %[1]d 缺失", seg.seq)
		}
		return errs.WrapDetail(err, ErrStorage, "open segment %s | 打开分段 %s 失败", seg.path, seg.path)
	}
	if err := validateSegmentIdentity(seg, f); err != nil {
		_ = f.Close()
		seg.release(r.w)
		return err
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		_ = f.Close()
		seg.release(r.w)
		return errs.WrapDetail(err, ErrStorage, "seek segment %s | 定位分段 %s 失败", seg.path, seg.path)
	}
	r.seg, r.file, r.br, r.off = seg, f, bufio.NewReaderSize(f, readerReadAhead), off
	r.segEnd = r.segmentSize()
	return nil
}

// segmentSize returns the current readable end of the current segment. | segmentSize
// 返回当前分段当前可读末尾。
func (r *Reader) segmentSize() int64 {
	r.seg.metaMu.RLock()
	defer r.seg.metaMu.RUnlock()
	return r.seg.size
}

// advanceSegment moves to the next segment, returning true when one was opened. | advanceSegment
// 移动到下一分段；打开成功时返回 true。
func (r *Reader) advanceSegment(ctx context.Context) (bool, error) {
	next := r.w.nextReadSegment(r.seg)
	if next == nil {
		return false, nil
	}
	off := r.w.startOffset(next, r.from)
	f, err := os.Open(next.path)
	if err != nil {
		next.release(r.w)
		if os.IsNotExist(err) {
			return false, errs.Detail(ErrMissingSegment, "segment %[1]d is missing | 分段 %[1]d 缺失", next.seq)
		}
		return false, errs.WrapDetail(err, ErrStorage, "open segment %s | 打开分段 %s 失败", next.path, next.path)
	}
	if err := validateSegmentIdentity(next, f); err != nil {
		_ = f.Close()
		next.release(r.w)
		return false, err
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		_ = f.Close()
		next.release(r.w)
		return false, errs.WrapDetail(err, ErrStorage, "seek segment %s | 定位分段 %s 失败", next.path, next.path)
	}
	oldSeg, oldFile := r.seg, r.file
	r.seg, r.file, r.br, r.off = next, f, bufio.NewReaderSize(f, readerReadAhead), off
	r.segEnd = r.segmentSize()
	if oldFile != nil {
		_ = oldFile.Close()
	}
	if oldSeg != nil {
		oldSeg.release(r.w)
	}
	return true, nil
}

// wait blocks until a new commit, WAL close, Reader close, or ctx cancellation.
// It captures the notification channel before rechecking the committed
// high-water mark, so a commit that lands between the caller's EOF check and
// the select cannot be missed. | wait 阻塞到新提交、WAL 关闭、Reader 关闭或 ctx
// 取消；先捕获通知通道再复查已提交高水位，避免提交恰好发生在 EOF 检查与
// select 之间时丢失唤醒。
func (r *Reader) wait(ctx context.Context) error {
	_, ch := r.w.followChannel()
	if !r.hasTo || r.from <= r.to {
		if snap := r.w.Snapshot(); snap.LastLSN > r.lastReturned && snap.LastLSN >= r.from {
			return nil
		}
	}
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-r.done:
		return ErrClosed
	case <-r.w.closedCh:
		return nil
	}
}

// resolveRecordView resolves deduplication for one decoded record and returns
// the user view plus the (possibly replaced) scratch buffer. It takes explicit
// inputs instead of a Reader so random reads do not allocate a Reader per
// record. | resolveRecordView 解析一条已解码记录的去重引用，返回用户视图与
// （可能被替换的）暂存缓冲；它使用显式参数而非 Reader，避免随机读为每条记录
// 分配一个 Reader。
func (w *WAL) resolveRecordView(seg *segment, f *os.File, refOff int64, hdr recordHeader, payload, scratch []byte, header *[recordHeaderSizeEncrypted]byte) (Record, []byte, error) {
	rec := Record{
		LSN:       hdr.lsn,
		Timestamp: hdr.timestamp,
		TxnID:     hdr.txnID,
		Flags:     recordVisibleFlags(hdr.flags),
	}
	if hdr.flags&recordFlagDedupRef == 0 {
		if len(payload) != int(hdr.keyLen)+int(hdr.dataLen) {
			return Record{}, scratch, errs.Detail(ErrCorrupt, "record payload split failed | 记录负载切分失败")
		}
		rec.Key = payload[:hdr.keyLen]
		rec.Data = payload[hdr.keyLen:]
		return rec, scratch, nil
	}
	key, ref, err := parseDedupRefPayload(payload, int(hdr.keyLen))
	if err != nil {
		return Record{}, scratch, err
	}
	if ref.offset < uint64(segmentHeaderSize) || int64(ref.offset) >= refOff-int64(hdr.size) {
		return Record{}, scratch, errs.Detail(ErrDedupCorrupt, "dedup target offset %[1]d is not before the reference | 去重目标偏移 %[1]d 不在引用之前", ref.offset)
	}
	th, tpayload, tbuf, tscratch, err := w.decodeRecord(seg, f, int64(ref.offset), scratch, nil, header)
	if err != nil {
		return Record{}, scratch, err
	}
	if tscratch != nil {
		scratch = tscratch
	} else {
		scratch = tbuf
	}
	if th.flags&(recordFlagDedupRef|recordFlagCommitMark) != 0 || th.codec == codecTxnControl || th.lsn == 0 {
		return Record{}, scratch, errs.Detail(ErrDedupCorrupt, "dedup target is not a user record | 去重目标不是用户记录")
	}
	if th.keyLen != hdr.keyLen || th.dataLen != hdr.dataLen {
		return Record{}, scratch, errs.Detail(ErrDedupCorrupt, "dedup target length mismatch | 去重目标长度不匹配")
	}
	tkey := tpayload[:th.keyLen]
	tdata := tpayload[th.keyLen:]
	if got := digestKeyData(HashAlgorithm(ref.hashAlg), tkey, tdata); got != ref.digest {
		return Record{}, scratch, errs.Detail(ErrDedupCorrupt, "dedup digest mismatch | 去重摘要不匹配")
	}
	rec.Key = key
	rec.Data = tdata
	return rec, scratch, nil
}

// decompress expands a compressed payload into a new buffer. | decompress 把压缩负载解开到新缓冲。
func (r *Reader) decompress(hdr recordHeader, payload, buf []byte) ([]byte, []byte, error) {
	expected := int(hdr.keyLen) + int(hdr.dataLen)
	if expected > formatHardLimit {
		return nil, buf, errs.Detail(ErrTooLarge, "decompressed record exceeds 1 GiB | 解压记录超过 1 GiB")
	}
	codec, err := r.w.opts.compression.lookup(hdr.codec)
	if err != nil {
		return nil, buf, err
	}
	if codec == nil {
		return nil, buf, errs.Detail(ErrCodecMismatch, "codec %[1]d is not registered | codec %[1]d 未注册", hdr.codec)
	}
	dst := make([]byte, 0, expected)
	out, err := safeDecompress(codec, dst, payload)
	if err != nil {
		return nil, buf, err
	}
	if len(out) != expected {
		return nil, buf, errs.Detail(ErrCorrupt, "decompressed length %[1]d, want %[2]d | 解压长度 %[1]d，期望 %[2]d", len(out), expected)
	}
	return out, out, nil
}

// LSN returns the last LSN returned by Next. | LSN 返回 Next 最后返回的 LSN。
func (r *Reader) LSN() uint64 { return r.lastReturned }

// Close releases the Reader. It may run concurrently with Next. | Close 释放 Reader，可与 Next 并发。
func (r *Reader) Close() error {
	r.closeOnce.Do(func() {
		r.stateMu.Lock()
		r.closing = true
		close(r.done)
		for r.inFlight > 0 {
			r.cond.Wait()
		}
		file := r.file
		seg := r.seg
		r.file, r.br, r.seg = nil, nil, nil
		r.stateMu.Unlock()
		if file != nil {
			_ = file.Close()
		}
		if seg != nil {
			seg.release(r.w)
		}
		for _, pinned := range r.pinned {
			pinned.release(r.w)
		}
		r.pinned = nil
		if r.followCounted {
			r.w.followReaders.Add(-1)
		}
		r.w.endRead()
	})
	return nil
}

// locateRead finds the segment and offset covering lsn. | locateRead 查找覆盖 lsn 的分段与偏移。
func (w *WAL) locateRead(lsn uint64) (*segment, int64, error) {
	w.mu.RLock()
	chosen := w.segmentForLSNLocked(lsn)
	if chosen == nil {
		w.mu.RUnlock()
		return nil, 0, nil
	}
	chosen.retain()
	w.mu.RUnlock()
	off := w.startOffset(chosen, lsn)
	return chosen, off, nil
}

// startOffset returns the first record offset at or before lsn. | startOffset
// 返回不晚于 lsn 的第一条记录偏移。
func (w *WAL) startOffset(seg *segment, lsn uint64) int64 {
	if lsn == 0 || lsn <= seg.baseLSN {
		return int64(segmentHeaderSize)
	}
	seg.metaMu.RLock()
	base := seg.baseLSN
	offsets := seg.offsets
	recordCount := seg.recordCount
	sparse := seg.sparse
	seg.metaMu.RUnlock()
	if idx := lsn - base; len(offsets) > 0 && idx < uint64(len(offsets)) {
		return int64(offsets[idx])
	}
	// Build a dense index only for the newest segment. Older segments use the
	// bounded sparse cache; this keeps dense-index memory O(active segment)
	// instead of O(history). | 只为最新分段构建稠密索引；更旧的分段使用有界
	// 稀疏缓存，使稠密索引内存为 O(活动段) 而非 O(历史)。
	if len(offsets) == 0 && seg.currentState() == segmentSealed && recordCount > 0 && recordCount <= maxDenseRecords && w.isNewestSegment(seg) {
		w.ensureDense(seg)
		seg.metaMu.RLock()
		base = seg.baseLSN
		offsets = seg.offsets
		seg.metaMu.RUnlock()
		if idx := lsn - base; len(offsets) > 0 && idx < uint64(len(offsets)) {
			return int64(offsets[idx])
		}
	}
	if len(sparse) == 0 && seg.currentState() == segmentSealed {
		w.ensureSparse(seg)
		seg.metaMu.RLock()
		sparse = seg.sparse
		seg.metaMu.RUnlock()
	}
	if len(sparse) == 0 {
		return int64(segmentHeaderSize)
	}
	lo, hi := 0, len(sparse)
	for lo < hi {
		mid := (lo + hi) / 2
		if sparse[mid].lsn <= lsn {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo == 0 {
		return int64(segmentHeaderSize)
	}
	return sparse[lo-1].offset
}

// isNewestSegment reports whether seg is the highest-sequence live segment. |
// isNewestSegment 返回 seg 是否为最高序号的存活分段。
func (w *WAL) isNewestSegment(seg *segment) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return len(w.segments) > 0 && w.segments[len(w.segments)-1].seq == seg.seq
}

// ensureDense builds the optional dense LSN-to-offset index for a sealed
// segment. | ensureDense 为封段构建可选的稠密 LSN→偏移索引。
func (w *WAL) ensureDense(seg *segment) {
	seg.metaMu.RLock()
	if seg.denseLoaded || len(seg.offsets) > 0 || seg.recordCount > maxDenseRecords {
		seg.metaMu.RUnlock()
		return
	}
	size := seg.size
	count := seg.recordCount
	seg.metaMu.RUnlock()
	f, err := os.Open(seg.path)
	if err != nil {
		return
	}
	defer f.Close()
	if err := validateSegmentIdentity(seg, f); err != nil {
		return
	}
	offsets := make([]uint64, 0, int(count))
	var hdr [recordHeaderSize]byte
	for off := int64(segmentHeaderSize); off < size; {
		if err := w.readAtFull(f, hdr[:], off); err != nil {
			break
		}
		rh, err := parseRecordHeader(hdr[:])
		if err != nil || off+int64(rh.size) > size {
			break
		}
		if rh.flags&recordFlagCommitMark == 0 && rh.codec != codecTxnControl {
			offsets = append(offsets, uint64(off))
			if len(offsets) >= maxDenseRecords {
				break
			}
		}
		off += int64(rh.size)
	}
	seg.metaMu.Lock()
	if !seg.denseLoaded && len(seg.offsets) == 0 {
		seg.offsets = offsets
		seg.denseLoaded = true
	}
	seg.metaMu.Unlock()
}

// ensureSparse lazily loads a sealed segment's sparse index. | ensureSparse
// 按需加载封段的稀疏索引。
func (w *WAL) ensureSparse(seg *segment) {
	seg.metaMu.RLock()
	loaded := seg.sparseLoaded
	has := len(seg.sparse) > 0
	seg.metaMu.RUnlock()
	if loaded || has {
		return
	}
	seg.metaMu.RLock()
	segSize, segLast := seg.size, seg.lastLSN
	seg.metaMu.RUnlock()
	entry, release, err := w.idxcache.acquire(seg.seq, func() (*indexEntry, error) {
		sc, err := loadSidecar(seg.idxPath)
		if err != nil || sc.seq != seg.seq || sc.baseLSN != seg.baseLSN || sc.walID != seg.walID {
			return nil, nil
		}
		// A checkpoint sidecar can cover only a synced prefix. Loading it for a
		// sealed segment as if it were the full index would silently hide the
		// tail from Key queries and sparse seeks. | 检查点侧车可能只覆盖已同步
		// 前缀；把它当作封段完整索引加载会让 Key 查询和稀疏定位静默漏掉尾部。
		if sc.segmentBytes != uint64(segSize) || sc.lastLSN != segLast {
			return nil, nil
		}
		return &indexEntry{sparse: sc.sparse, keyIndex: sc.keyIndex, hasKeyIndex: sc.hasKeyIndex, keyIndexComplete: sc.keyIndexComplete}, nil
	})
	if err != nil || entry == nil {
		return
	}
	defer release()
	var gen uint64
	seg.metaMu.Lock()
	if !seg.sparseLoaded {
		seg.indexGen++
		gen = seg.indexGen
		seg.sparse = entry.sparse
		seg.sparseComplete = (len(entry.sparse) > 0 && entry.sparse[0].lsn == seg.baseLSN) || seg.recordCount == 0
		if entry.hasKeyIndex && seg.keyIndex == nil {
			seg.keyIndex = entry.keyIndex
			seg.keyIndexLoaded = true
		}
		seg.keyIndexComplete = entry.keyIndexComplete
		seg.sparseLoaded = true
	}
	seg.metaMu.Unlock()
	// Bind after releasing metaMu to preserve the cache -> segment lock order. |
	// 释放 metaMu 后再绑定，保持“缓存 -> 分段”的锁顺序。
	if gen != 0 {
		w.idxcache.bind(entry, seg, gen)
	}
}

// nextReadSegment returns the next non-retired segment after cur. | nextReadSegment
// 返回 cur 之后的下一非退休分段。
func (w *WAL) nextReadSegment(cur *segment) *segment {
	w.mu.RLock()
	defer w.mu.RUnlock()
	idx := sort.Search(len(w.segments), func(i int) bool { return w.segments[i].seq > cur.seq })
	if idx == len(w.segments) {
		return nil
	}
	next := w.segments[idx]
	next.retain()
	return next
}

// decodeRecord reads one record with positional reads. It is used for random
// access and deduplication targets. | decodeRecord 使用位置读取一条记录，用于
// 随机访问与去重目标。
func (w *WAL) decodeRecord(seg *segment, f *os.File, off int64, buf, scratch []byte, local *[recordHeaderSizeEncrypted]byte) (recordHeader, []byte, []byte, []byte, error) {
	if err := w.readAtFull(f, local[:recordHeaderSize], off); err != nil {
		return recordHeader{}, nil, buf, scratch, wrapStorage("read record header", err)
	}
	hdr, err := parseRecordHeader(local[:recordHeaderSize])
	if err != nil {
		return recordHeader{}, nil, buf, scratch, err
	}
	if hdr.headerLen == recordHeaderSizeEncrypted {
		if err := w.readAtFull(f, local[recordHeaderSize:recordHeaderSizeEncrypted], off+recordHeaderSize); err != nil {
			return recordHeader{}, nil, buf, scratch, wrapStorage("read record nonce", err)
		}
	}
	if err := validateRecordHeader(hdr); err != nil {
		return recordHeader{}, nil, buf, scratch, err
	}
	if err := validatePayloadLength(hdr); err != nil {
		return recordHeader{}, nil, buf, scratch, err
	}
	seg.metaMu.RLock()
	size := seg.size
	seg.metaMu.RUnlock()
	if off < int64(segmentHeaderSize) || off+int64(hdr.size) > size {
		return recordHeader{}, nil, buf, scratch, errs.Detail(ErrCorrupt, "record at %[1]d exceeds segment size %[2]d | 偏移 %[1]d 的记录超出分段大小 %[2]d", off, size)
	}
	if hdr.cipher != cipherNone && int(hdr.size) < hdr.headerLen+aeadTagSize {
		return recordHeader{}, nil, buf, scratch, errs.Detail(ErrCorrupt, "encrypted record is shorter than its AEAD tag | 加密记录短于 AEAD tag")
	}
	payloadLen := int(hdr.size) - hdr.headerLen
	buf = ensureCap(buf, payloadLen)
	if payloadLen > 0 {
		if err := w.readAtFull(f, buf[:payloadLen], off+int64(hdr.headerLen)); err != nil {
			return recordHeader{}, nil, buf, scratch, wrapStorage("read record payload", err)
		}
	}
	return w.decodeRecordRaw(seg, off, hdr, local[:hdr.headerLen], buf[:payloadLen], buf, scratch)
}

// decodeRecordWindow reads a small window in one pread; it falls back to the
// exact positional read when the record does not fit. | decodeRecordWindow
// 用一次预读读取小窗口；记录放不下时回退到精确位置读取。
func (w *WAL) decodeRecordWindow(seg *segment, f *os.File, off int64, buf, scratch []byte, header *[recordHeaderSizeEncrypted]byte, window int) (recordHeader, []byte, []byte, []byte, error) {
	seg.metaMu.RLock()
	end := seg.size
	seg.metaMu.RUnlock()
	if off < int64(segmentHeaderSize) || off >= end {
		return recordHeader{}, nil, buf, scratch, errs.Detail(ErrCorrupt, "record offset %[1]d is outside the segment | 记录偏移 %[1]d 超出分段", off)
	}
	n := int64(window)
	if off+n > end {
		n = end - off
	}
	if n < recordHeaderSize {
		return w.decodeRecord(seg, f, off, buf, scratch, header)
	}
	buf = ensureCap(buf, int(n))
	if err := w.readAtFull(f, buf[:n], off); err != nil {
		return recordHeader{}, nil, buf, scratch, wrapStorage("read record window", err)
	}
	hdr, err := parseRecordHeader(buf[:recordHeaderSize])
	if err != nil {
		return recordHeader{}, nil, buf, scratch, err
	}
	if int64(hdr.size) > n {
		return w.decodeRecord(seg, f, off, buf, scratch, header)
	}
	if err := validateRecordHeader(hdr); err != nil {
		return recordHeader{}, nil, buf, scratch, err
	}
	if err := validatePayloadLength(hdr); err != nil {
		return recordHeader{}, nil, buf, scratch, err
	}
	if hdr.cipher != cipherNone && int(hdr.size) < hdr.headerLen+aeadTagSize {
		return recordHeader{}, nil, buf, scratch, errs.Detail(ErrCorrupt, "encrypted record is shorter than its AEAD tag | 加密记录短于 AEAD tag")
	}
	return w.decodeRecordRaw(seg, off, hdr, buf[:hdr.headerLen], buf[hdr.headerLen:hdr.size], buf, scratch)
}

// decodeRecordStream reads one record from a sequential buffered reader. | decodeRecordStream
// 从顺序缓冲读取器读取一条记录。
func (w *WAL) decodeRecordStream(seg *segment, br *bufio.Reader, off, size int64, buf, scratch []byte, local *[recordHeaderSizeEncrypted]byte) (recordHeader, []byte, []byte, []byte, error) {
	if _, err := io.ReadFull(br, local[:recordHeaderSize]); err != nil {
		return recordHeader{}, nil, buf, scratch, errs.WrapDetail(err, ErrCorrupt, "read record header | 读取记录头失败")
	}
	hdr, err := parseRecordHeader(local[:recordHeaderSize])
	if err != nil {
		return recordHeader{}, nil, buf, scratch, err
	}
	if hdr.headerLen == recordHeaderSizeEncrypted {
		if _, err := io.ReadFull(br, local[recordHeaderSize:recordHeaderSizeEncrypted]); err != nil {
			return recordHeader{}, nil, buf, scratch, errs.WrapDetail(err, ErrCorrupt, "read record nonce | 读取记录 nonce 失败")
		}
	}
	if err := validateRecordHeader(hdr); err != nil {
		return recordHeader{}, nil, buf, scratch, err
	}
	if err := validatePayloadLength(hdr); err != nil {
		return recordHeader{}, nil, buf, scratch, err
	}
	if off < int64(segmentHeaderSize) || off+int64(hdr.size) > size {
		return recordHeader{}, nil, buf, scratch, errs.Detail(ErrCorrupt, "record at %[1]d exceeds segment size %[2]d | 偏移 %[1]d 的记录超出分段大小 %[2]d", off, size)
	}
	if hdr.cipher != cipherNone && int(hdr.size) < hdr.headerLen+aeadTagSize {
		return recordHeader{}, nil, buf, scratch, errs.Detail(ErrCorrupt, "encrypted record is shorter than its AEAD tag | 加密记录短于 AEAD tag")
	}
	payloadLen := int(hdr.size) - hdr.headerLen
	buf = ensureCap(buf, payloadLen)
	if payloadLen > 0 {
		if _, err := io.ReadFull(br, buf[:payloadLen]); err != nil {
			return recordHeader{}, nil, buf, scratch, errs.WrapDetail(err, ErrCorrupt, "read record payload | 读取记录负载失败")
		}
	}
	return w.decodeRecordRaw(seg, off, hdr, local[:hdr.headerLen], buf[:payloadLen], buf, scratch)
}

// decodeRecordRaw validates the record CRC and decodes its payload. | decodeRecordRaw
// 校验记录 CRC 并解码负载。
func (w *WAL) decodeRecordRaw(seg *segment, off int64, hdr recordHeader, rawHeader, payload, buf, scratch []byte) (recordHeader, []byte, []byte, []byte, error) {
	crc := checksum(rawHeader[recOffSize:])
	crc = appendCRC(crc, payload)
	if got := binary.LittleEndian.Uint32(rawHeader[recOffCRC:]); got != crc {
		return recordHeader{}, nil, buf, scratch, errs.Detail(ErrCorrupt, "record CRC mismatch at %[1]d | 偏移 %[1]d 的记录 CRC 不匹配", off)
	}
	plain, out, nscratch, err := w.decodePayload(seg, off, hdr, rawHeader, payload, buf, scratch)
	if err != nil {
		return recordHeader{}, nil, buf, scratch, err
	}
	return hdr, plain, out, nscratch, nil
}

// decodePayload decrypts and decompresses one validated record payload. | decodePayload
// 解密并解压一条已校验记录的负载。
func (w *WAL) decodePayload(seg *segment, off int64, hdr recordHeader, rawHeader, payload, buf, scratch []byte) ([]byte, []byte, []byte, error) {
	plain := payload
	if hdr.cipher != cipherNone {
		if !w.encrypted {
			return nil, buf, scratch, errs.Detail(ErrCipherMismatch, "encrypted record in plaintext WAL | 明文 WAL 中出现加密记录")
		}
		bk, err := w.bound.key(hdr.keyID)
		if err != nil {
			return nil, buf, scratch, err
		}
		if hdr.cipher != diskCipher(bk.suite) {
			return nil, buf, scratch, errs.Detail(ErrCipherMismatch, "record cipher does not match key suite | 记录 cipher 与密钥套件不匹配")
		}
		var nonce [nonceSize]byte
		copy(nonce[:], rawHeader[recOffNonce:recordHeaderSizeEncrypted])
		var aadBuf [32 + recordHeaderSizeEncrypted]byte
		aad := buildAAD(aadBuf[:0], w.walID, seg.seq, off, rawHeader[recOffSize:recordHeaderSizeEncrypted])
		plain, err = bk.aead.Open(payload[:0], nonce[:], payload, aad)
		if err != nil {
			return nil, buf, scratch, errs.Wrap(err, ErrAuth)
		}
	} else if w.encrypted {
		return nil, buf, scratch, errs.Detail(ErrCipherMismatch, "plaintext record in encrypted WAL | 加密 WAL 中出现明文记录")
	}
	if hdr.flags&recordFlagCompressed == 0 {
		return plain, buf, scratch, nil
	}
	expected := int(hdr.keyLen) + int(hdr.dataLen)
	if expected > formatHardLimit {
		return nil, buf, scratch, errs.Detail(ErrTooLarge, "decompressed record exceeds 1 GiB | 解压记录超过 1 GiB")
	}
	codec, err := w.opts.compression.lookup(hdr.codec)
	if err != nil {
		return nil, buf, scratch, err
	}
	if codec == nil {
		return nil, buf, scratch, errs.Detail(ErrCodecMismatch, "codec %[1]d is not registered | codec %[1]d 未注册", hdr.codec)
	}
	base := scratch
	if cap(base) < expected {
		base = make([]byte, expected)
	}
	// Codec.Decompress uses cap(dst) as the exact expected plaintext length;
	// a three-index slice makes the capacity exact while retaining the larger
	// backing array for reuse. | Codec.Decompress 把 cap(dst) 当作精确的期望
	// 明文长度；三索引切片让容量精确，同时保留更大的底层数组供复用。
	work := base[:0:expected]
	out, err := safeDecompress(codec, work, plain)
	if err != nil {
		return nil, buf, base, err
	}
	if len(out) != expected {
		return nil, buf, base, errs.Detail(ErrCorrupt, "decompressed length %[1]d, want %[2]d | 解压长度 %[1]d，期望 %[2]d", len(out), expected)
	}
	out = base[:expected]
	return out, buf, out, nil
}

// ensureCap returns a slice of length n with capacity at least n. | ensureCap
// 返回长度 n、容量至少 n 的切片。
func ensureCap(buf []byte, n int) []byte {
	if cap(buf) < n {
		return make([]byte, n)
	}
	return buf[:n]
}
