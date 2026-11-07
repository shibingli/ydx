package wal

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"sort"
	"unsafe"

	"github.com/shibingli/ydx/errs"
)

// Read returns a cloned record. | Read 返回一条记录的克隆。
func (w *WAL) Read(lsn uint64) (Record, error) {
	if w.isClosed() {
		return Record{}, ErrClosed
	}
	first := w.FirstLSN()
	if lsn < first || lsn > w.LastLSN() {
		return Record{}, errs.Detail(ErrNotFound, "LSN %[1]d is outside [FirstLSN,LastLSN] | LSN %[1]d 超出 [FirstLSN,LastLSN]", lsn)
	}
	w.mu.RLock()
	seg := w.segmentForLSNLocked(lsn)
	if seg == nil {
		w.mu.RUnlock()
		return Record{}, ErrNotFound
	}
	seg.retain()
	w.mu.RUnlock()
	defer seg.release(w)
	if err := w.beginRead(); err != nil {
		return Record{}, err
	}
	defer w.endRead()
	fd, err := w.fdcache.acquire(seg.seq)
	if err != nil {
		// The segment may have been retired and deleted by a concurrent
		// Truncate/retention pass after it was pinned. Its records are now
		// below FirstLSN, so the correct answer is ErrNotFound, not a storage
		// error. | 分段可能在固定之后被并发 Truncate/保留策略退休并删除；其记录
		// 已低于 FirstLSN，应返回 ErrNotFound 而不是存储错误。
		if lsn < w.FirstLSN() {
			return Record{}, ErrNotFound
		}
		return Record{}, err
	}
	defer fd.release()
	f := fd.f
	if err := validateSegmentIdentity(seg, f); err != nil {
		return Record{}, err
	}
	poolBuf := w.getReadBuf()
	defer w.putReadBuf(poolBuf)
	scratch := w.getReadScratch()
	defer w.putReadScratch(scratch)
	header := w.getReadHeader()
	defer w.putReadHeader(header)
	rec, _, _, err := w.readRecordView(seg, f, lsn, poolBuf, scratch, header)
	if err != nil {
		return Record{}, err
	}
	return rec.Clone(), nil
}

// readRecordView decodes one record without cloning. The returned Record
// aliases buf/scratch and is valid until the next decode. | readRecordView
// 解码一条记录但不克隆；返回的 Record 指向 buf/scratch，在下一次解码前有效。
func (w *WAL) readRecordView(seg *segment, f *os.File, lsn uint64, buf, scratch []byte, header *[recordHeaderSizeEncrypted]byte) (Record, []byte, []byte, error) {
	off := w.startOffset(seg, lsn)
	seg.metaMu.RLock()
	end := seg.size
	seg.metaMu.RUnlock()
	for off < end {
		hdr, payload, next, nscratch, err := w.decodeRecordWindow(seg, f, off, buf, scratch, header, 4096)
		if err != nil {
			return Record{}, buf, scratch, err
		}
		buf, scratch = next, nscratch
		off += int64(hdr.size)
		if hdr.flags&recordFlagCommitMark != 0 || hdr.codec == codecTxnControl {
			continue
		}
		if hdr.lsn < lsn {
			continue
		}
		if hdr.lsn > lsn {
			return Record{}, buf, scratch, ErrNotFound
		}
		rec, nscratch, err := w.resolveRecordView(seg, f, off, hdr, payload, scratch, header)
		scratch = nscratch
		if err != nil {
			return Record{}, buf, scratch, err
		}
		return rec, buf, scratch, nil
	}
	return Record{}, buf, scratch, ErrNotFound
}

// getReadBuf returns a pooled random-read buffer. | getReadBuf 返回池化的随机读缓冲。
func (w *WAL) getReadBuf() []byte {
	if v := w.readBufPool.Get(); v != nil {
		// A *byte keeps the block alive without boxing a slice header. | *byte
		// 即可保活内存块，且无需装箱切片头。
		return unsafe.Slice(v.(*byte), defaultReaderBuffer)[:0]
	}
	return make([]byte, 0, defaultReaderBuffer)
}

// putReadBuf returns an exact-capacity buffer to the pool. | putReadBuf 把容量精确匹配的缓冲归还池。
func (w *WAL) putReadBuf(buf []byte) {
	if cap(buf) == defaultReaderBuffer {
		w.readBufPool.Put(unsafe.SliceData(buf))
	}
}

// getReadHeader returns a pooled record-header scratch block. Random reads pass
// the header to non-inlined decoders, so keeping it in a per-WAL pool avoids
// one heap allocation per read. | getReadHeader 返回池化的记录头暂存块；随机读
// 会把头传给未内联的解码器，按 WAL 池化可避免每次读取一次堆分配。
func (w *WAL) getReadHeader() *[recordHeaderSizeEncrypted]byte {
	if v := w.readHeaderPool.Get(); v != nil {
		return v.(*[recordHeaderSizeEncrypted]byte)
	}
	return new([recordHeaderSizeEncrypted]byte)
}

// putReadHeader returns a header scratch block to the pool. | putReadHeader 把
// 记录头暂存块归还池。
func (w *WAL) putReadHeader(h *[recordHeaderSizeEncrypted]byte) {
	if h != nil {
		w.readHeaderPool.Put(h)
	}
}

// getReadScratch returns a pooled dedup scratch buffer. | getReadScratch 返回池化的去重暂存缓冲。
func (w *WAL) getReadScratch() []byte {
	if v := w.readScratchPool.Get(); v != nil {
		return unsafe.Slice(v.(*byte), defaultReaderBuffer)[:0]
	}
	return make([]byte, 0, defaultReaderBuffer)
}

// putReadScratch returns an exact-capacity scratch buffer to the pool. | putReadScratch
// 把容量精确匹配的暂存缓冲归还池。
func (w *WAL) putReadScratch(buf []byte) {
	if cap(buf) == defaultReaderBuffer {
		w.readScratchPool.Put(unsafe.SliceData(buf))
	}
}

// ReadInto reads a record into dst, placing Key then Data. It avoids the
// per-call clone performed by Read and returns a record whose Key/Data alias
// dst. | ReadInto 把记录读入 dst，依次放置 Key 与 Data；它避免 Read 的逐次
// 克隆，返回记录的 Key/Data 指向 dst。
func (w *WAL) ReadInto(lsn uint64, dst []byte) (Record, []byte, error) {
	if w.isClosed() {
		return Record{}, nil, ErrClosed
	}
	first := w.FirstLSN()
	if lsn < first || lsn > w.LastLSN() {
		return Record{}, nil, errs.Detail(ErrNotFound, "LSN %[1]d is outside [FirstLSN,LastLSN] | LSN %[1]d 超出 [FirstLSN,LastLSN]", lsn)
	}
	w.mu.RLock()
	seg := w.segmentForLSNLocked(lsn)
	if seg == nil {
		w.mu.RUnlock()
		return Record{}, nil, ErrNotFound
	}
	seg.retain()
	w.mu.RUnlock()
	defer seg.release(w)
	if err := w.beginRead(); err != nil {
		return Record{}, nil, err
	}
	defer w.endRead()
	fd, err := w.fdcache.acquire(seg.seq)
	if err != nil {
		if lsn < w.FirstLSN() {
			return Record{}, nil, ErrNotFound
		}
		return Record{}, nil, err
	}
	defer fd.release()
	if err := validateSegmentIdentity(seg, fd.f); err != nil {
		return Record{}, nil, err
	}
	buf := w.getReadBuf()
	defer w.putReadBuf(buf)
	scratch := w.getReadScratch()
	defer w.putReadScratch(scratch)
	header := w.getReadHeader()
	defer w.putReadHeader(header)
	rec, _, _, err := w.readRecordView(seg, fd.f, lsn, buf, scratch, header)
	if err != nil {
		return Record{}, nil, err
	}
	need := len(rec.Key) + len(rec.Data)
	if len(dst) < need {
		return Record{}, nil, errs.Detail(ErrTooShort, "destination has %[1]d bytes, need %[2]d | 目标缓冲 %[1]d 字节，需要 %[2]d", len(dst), need)
	}
	n := copy(dst, rec.Key)
	copy(dst[n:], rec.Data)
	out := Record{LSN: rec.LSN, Timestamp: rec.Timestamp, TxnID: rec.TxnID, Flags: rec.Flags}
	out.Key = dst[:n]
	out.Data = dst[n:need]
	return out, dst[:need], nil
}

// Scan calls fn for every record in [from,to]. Zero from means FirstLSN and
// zero to means the current committed LastLSN. The Record passed to fn aliases
// a reusable read buffer and is valid only during the callback; call
// Record.Clone before retaining it. | Scan 对 [from,to] 内每条记录调用 fn；
// from 为 0 表示 FirstLSN，to 为 0 表示当前已提交 LastLSN。传给 fn 的 Record
// 指向复用读取缓冲，仅在回调期间有效；需要保留请先调用 Record.Clone。
func (w *WAL) Scan(ctx context.Context, from, to uint64, fn func(Record) error) error {
	if w.isClosed() {
		return ErrClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	snap := w.Snapshot()
	if from == 0 {
		from = w.FirstLSN()
	}
	if to == 0 {
		to = snap.LastLSN
	}
	if from > to {
		return nil
	}
	r, err := w.newRangeReader(from, Snapshot{CommitSeq: snap.CommitSeq, LastLSN: to})
	if err != nil {
		return err
	}
	defer r.Close()
	for {
		rec, err := r.NextContext(ctx)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if fn != nil {
			if err := fn(rec); err != nil {
				return err
			}
		}
	}
}

// Query filters records by LSN, time, Key, and Data substring. The Record
// passed to fn aliases a reusable read buffer and is valid only during the
// callback; call Record.Clone before retaining it. | Query 按 LSN、时间、Key 与
// Data 子串过滤记录。传给 fn 的 Record 指向复用读取缓冲，仅在回调期间有效；
// 需要保留请先调用 Record.Clone。
func (w *WAL) Query(ctx context.Context, q Query, fn func(Record) error) (int, error) {
	if w.isClosed() {
		return 0, ErrClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if q.Limit < 0 {
		return 0, errs.Detail(ErrInvalidOptions, "Query.Limit must not be negative | Query.Limit 不得为负数")
	}
	snap := w.Snapshot()
	from := q.From
	if from == 0 {
		from = w.FirstLSN()
	}
	to := q.To
	if to == 0 {
		to = snap.LastLSN
	}
	if from > to || (!q.Since.IsZero() && !q.Until.IsZero() && q.Since.After(q.Until)) {
		return 0, nil
	}
	// Exact Key lookups use the in-memory Key index when every relevant
	// segment has a complete, non-overflowed index. Otherwise fall back to the
	// linear scan below. | 精确 Key 查询在所有相关分段都有完整且未溢出的索引时
	// 使用内存 Key 索引；否则回退到下面的线性扫描。
	if q.Key != nil && q.Contains == nil && q.Since.IsZero() && q.Until.IsZero() {
		if count, ok, err := w.queryKeyIndex(ctx, q, from, to, fn); ok || err != nil {
			return count, err
		}
	}
	r, err := w.newRangeReader(from, Snapshot{CommitSeq: snap.CommitSeq, LastLSN: to})
	if err != nil {
		return 0, err
	}
	defer r.Close()
	var since, until int64
	if !q.Since.IsZero() {
		since = q.Since.UnixNano()
	}
	if !q.Until.IsZero() {
		until = q.Until.UnixNano()
	}
	count := 0
	for {
		rec, err := r.NextContext(ctx)
		if err == io.EOF {
			return count, nil
		}
		if err != nil {
			return count, err
		}
		if !q.Since.IsZero() && rec.Timestamp < since {
			continue
		}
		if !q.Until.IsZero() && rec.Timestamp > until {
			continue
		}
		if q.Key != nil && !bytes.Equal(rec.Key, q.Key) {
			continue
		}
		if q.Contains != nil && !bytes.Contains(rec.Data, q.Contains) {
			continue
		}
		count++
		if fn != nil {
			if err := fn(rec); err != nil {
				return count, err
			}
		}
		if q.Limit > 0 && count >= q.Limit {
			return count, nil
		}
	}
}

// queryKeyIndex runs an exact-Key Query from per-segment Key indexes. Segments
// whose index is missing or incomplete are scanned individually and then
// upgraded in place, so one legacy segment never forces a full-WAL scan. |
// queryKeyIndex 使用每段 Key 索引执行精确 Key 查询。索引缺失/不完整的段只做
// 单段扫描并就地升级，因此一个旧段不会再触发全 WAL 线性扫描。
func (w *WAL) queryKeyIndex(ctx context.Context, q Query, from, to uint64, fn func(Record) error) (int, bool, error) {
	if !w.opts.keyIndex {
		return 0, false, nil
	}
	// Hold a read lease so Close cannot release the index/fd caches while an
	// on-demand sidecar load or index rebuild is in flight. | 持有读租约，防止
	// Close 在按需侧车加载或索引重建期间释放索引/文件描述符缓存。
	if err := w.beginRead(); err != nil {
		return 0, false, err
	}
	defer w.endRead()
	w.mu.RLock()
	first := sort.Search(len(w.segments), func(i int) bool {
		s := w.segments[i]
		s.metaMu.RLock()
		last := s.lastLSN
		s.metaMu.RUnlock()
		return last >= from
	})
	segs := make([]*segment, 0, len(w.segments)-first)
	for i := first; i < len(w.segments); i++ {
		seg := w.segments[i]
		seg.metaMu.RLock()
		base := seg.baseLSN
		seg.metaMu.RUnlock()
		if base > to {
			break
		}
		seg.retain()
		segs = append(segs, seg)
	}
	w.mu.RUnlock()
	defer func() {
		for _, seg := range segs {
			seg.release(w)
		}
	}()
	key := string(q.Key)
	count := 0
	for _, seg := range segs {
		if q.Limit > 0 && count >= q.Limit {
			break
		}
		if err := ctx.Err(); err != nil {
			return count, true, err
		}
		seg.metaMu.RLock()
		complete := seg.keyIndexComplete && !seg.keyIndexOverflow
		loaded := seg.keyIndexLoaded
		seg.metaMu.RUnlock()
		if seg.currentState() == segmentSealed {
			// Prefer a complete on-disk sidecar; only scan when it is missing,
			// stale, or was written by an old format. | 优先加载完整侧车；只有
			// 侧车缺失、陈旧或旧格式时才扫描。
			if !loaded && !complete {
				w.ensureSparse(seg)
				seg.metaMu.RLock()
				complete = seg.keyIndexComplete && !seg.keyIndexOverflow
				seg.metaMu.RUnlock()
			}
			if !complete {
				var err error
				complete, err = w.ensureKeyIndex(seg)
				if err != nil {
					// The segment may have been retired between retain and the
					// on-disk index rebuild. Skip it only when its whole range
					// is already below FirstLSN. | 分段可能在固定与重建索引之间被
					// 退休；仅当其整个区间都低于 FirstLSN 时跳过。
					if errors.Is(err, ErrMissingSegment) && w.segmentBelowFirstLSN(seg) {
						continue
					}
					return count, true, err
				}
			}
		}
		if complete {
			lsns := w.segmentKeyLSNs(seg, key, from, to)
			n, err := w.readIndexedLSNs(ctx, seg, q.Key, lsns, q.Limit-count, fn)
			count += n
			if err != nil {
				return count, true, err
			}
			continue
		}
		n, err := w.scanSegmentForKey(ctx, seg, q.Key, from, to, q.Limit-count, fn)
		count += n
		if err != nil {
			return count, true, err
		}
	}
	return count, true, nil
}

// segmentKeyLSNs copies one key's LSN list while holding the segment lock. |
// segmentKeyLSNs 在持有分段锁时复制一个 Key 的 LSN 列表。
func (w *WAL) segmentKeyLSNs(seg *segment, key string, from, to uint64) []uint64 {
	seg.metaMu.RLock()
	lsns := seg.keyIndex[key]
	out := make([]uint64, 0, len(lsns))
	for _, lsn := range lsns {
		if lsn >= from && lsn <= to {
			out = append(out, lsn)
		}
	}
	seg.metaMu.RUnlock()
	return out
}

// newRangeReader opens a pinned Reader for a previously computed range. When a
// concurrent Truncate advances FirstLSN past the range start, it restarts at
// the new FirstLSN instead of failing the whole query with ErrNotFound. |
// newRangeReader 为先前计算的范围打开固定 Reader；并发 Truncate 把 FirstLSN
// 推过范围起点时，从新的 FirstLSN 重试，而不是让整个查询以 ErrNotFound 失败。
func (w *WAL) newRangeReader(from uint64, bound Snapshot) (*Reader, error) {
	for {
		r, err := w.NewReader(From(from), SnapshotOf(bound), pinRange())
		if err == nil || !errors.Is(err, ErrNotFound) {
			return r, err
		}
		first := w.FirstLSN()
		if from >= first {
			return nil, err
		}
		from = first
	}
}

// segmentBelowFirstLSN reports whether every record in seg has been truncated
// away. Such a segment may have been deleted concurrently by the cleaner. |
// segmentBelowFirstLSN 判断分段内所有记录是否都已被截断；该分段可能已被 cleaner
// 并发删除。
func (w *WAL) segmentBelowFirstLSN(seg *segment) bool {
	seg.metaMu.RLock()
	last := seg.lastLSN
	seg.metaMu.RUnlock()
	return last < w.FirstLSN()
}

// readIndexedLSNs reads a sorted LSN list with one fd/buffer setup and calls fn
// with a reusable record view. | readIndexedLSNs 用一次 fd/缓冲设置读取有序
// LSN 列表，并把复用记录视图传给 fn。
func (w *WAL) readIndexedLSNs(ctx context.Context, seg *segment, key []byte, lsns []uint64, limit int, fn func(Record) error) (int, error) {
	if len(lsns) == 0 {
		return 0, nil
	}
	if err := w.beginRead(); err != nil {
		return 0, err
	}
	defer w.endRead()
	fd, err := w.fdcache.acquire(seg.seq)
	if err != nil {
		// A concurrent retirement deleted the segment; every indexed record in
		// it is below FirstLSN now. | 并发退休已删除该分段；其索引记录现在都低于
		// FirstLSN。
		if w.segmentBelowFirstLSN(seg) {
			return 0, nil
		}
		return 0, err
	}
	defer fd.release()
	if err := validateSegmentIdentity(seg, fd.f); err != nil {
		return 0, err
	}
	buf := w.getReadBuf()
	defer w.putReadBuf(buf)
	scratch := w.getReadScratch()
	defer w.putReadScratch(scratch)
	header := w.getReadHeader()
	defer w.putReadHeader(header)
	count := 0
	for _, lsn := range lsns {
		if err := ctx.Err(); err != nil {
			return count, err
		}
		if lsn < w.FirstLSN() {
			continue
		}
		rec, nbuf, nscratch, err := w.readRecordView(seg, fd.f, lsn, buf, scratch, header)
		buf, scratch = nbuf, nscratch
		if err != nil {
			if errors.Is(err, ErrNotFound) && lsn < w.FirstLSN() {
				continue
			}
			return count, err
		}
		if !bytes.Equal(rec.Key, key) {
			continue
		}
		count++
		if fn != nil {
			if err := fn(rec); err != nil {
				return count, err
			}
		}
		if limit > 0 && count >= limit {
			break
		}
	}
	return count, nil
}

// scanSegmentForKey scans one segment for an exact key. It is used for active
// segments with an overflowed index and for legacy sealed segments whose index
// cannot be rebuilt completely. | scanSegmentForKey 扫描单个分段查找精确 Key；
// 用于索引溢出的活动段以及无法完整重建索引的旧封段。
func (w *WAL) scanSegmentForKey(ctx context.Context, seg *segment, key []byte, from, to uint64, limit int, fn func(Record) error) (int, error) {
	seg.metaMu.RLock()
	base, last := seg.baseLSN, seg.lastLSN
	seg.metaMu.RUnlock()
	if last < from || base > to {
		return 0, nil
	}
	start := base
	if from > start {
		start = from
	}
	end := last
	if to < end {
		end = to
	}
	if start > end {
		return 0, nil
	}
	w.counters.keyIndexScans.Add(1)
	r, err := w.newRangeReader(start, Snapshot{LastLSN: end})
	if err != nil {
		return 0, err
	}
	defer r.Close()
	count := 0
	for {
		rec, err := r.NextContext(ctx)
		if err == io.EOF {
			return count, nil
		}
		if err != nil {
			return count, err
		}
		if rec.LSN > end {
			return count, nil
		}
		if !bytes.Equal(rec.Key, key) {
			continue
		}
		count++
		if fn != nil {
			if err := fn(rec); err != nil {
				return count, err
			}
		}
		if limit > 0 && count >= limit {
			return count, nil
		}
	}
}

// ensureKeyIndex rebuilds a sealed segment's sparse and Key indexes when they
// are missing or were written by an older sidecar format. It upgrades the
// sidecar on disk and installs the rebuilt index in memory. | ensureKeyIndex
// 在稀疏/Key 索引缺失或来自旧侧车格式时重建封段索引；同时升级磁盘侧车并把
// 重建结果装入内存。
func (w *WAL) ensureKeyIndex(seg *segment) (bool, error) {
	seg.metaMu.RLock()
	complete := seg.keyIndexComplete && !seg.keyIndexOverflow
	size := seg.size
	seg.metaMu.RUnlock()
	if complete {
		return true, nil
	}
	if size <= int64(segmentHeaderSize) {
		seg.metaMu.Lock()
		seg.sparse, seg.sparseLoaded, seg.sparseComplete = nil, true, true
		seg.keyIndex, seg.keyIndexLoaded, seg.keyIndexComplete, seg.keyIndexOverflow = nil, true, true, false
		seg.indexGen++
		seg.metaMu.Unlock()
		return true, nil
	}
	seg.indexMu.Lock()
	defer seg.indexMu.Unlock()
	seg.metaMu.RLock()
	complete = seg.keyIndexComplete && !seg.keyIndexOverflow
	size = seg.size
	seg.metaMu.RUnlock()
	if complete {
		return true, nil
	}
	f, err := os.Open(seg.path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, errs.Detail(ErrMissingSegment, "segment %[1]d is missing | 分段 %[1]d 缺失", seg.seq)
		}
		return false, wrapStorage("open segment for index rebuild", err)
	}
	defer f.Close()
	if err := validateSegmentIdentity(seg, f); err != nil {
		return false, err
	}
	info, err := f.Stat()
	if err != nil {
		return false, wrapStorage("stat segment for index rebuild", err)
	}
	if info.Size() != size {
		return false, errs.Detail(ErrCorrupt, "segment %[1]d size %[2]d does not match summary %[3]d | 分段 %[1]d 大小 %[2]d 与摘要 %[3]d 不一致",
			seg.seq, info.Size(), size)
	}
	out, err := w.scanSegment(seg, f, int64(segmentHeaderSize), size, scanBase{lastLSN: seg.baseLSN - 1, atHeader: true}, false)
	if err != nil {
		return false, err
	}
	seg.metaMu.RLock()
	wantLast, wantCount, wantSize := seg.lastLSN, seg.recordCount, seg.size
	seg.metaMu.RUnlock()
	if out.lastLSN != wantLast || out.recordCount != wantCount || out.size != wantSize {
		return false, errs.Detail(ErrCorrupt, "segment %[1]d index rebuild disagrees with its summary | 分段 %[1]d 索引重建结果与摘要不一致", seg.seq)
	}
	seg.metaMu.Lock()
	seg.indexGen++
	seg.sparse = out.sparse
	seg.sparseLoaded = true
	seg.sparseComplete = out.sparseComplete
	seg.keyIndex = out.keyIndex
	seg.keyIndexLoaded = true
	seg.keyIndexComplete = out.keyIndexComplete
	seg.keyIndexOverflow = out.keyIndexOverflow
	seg.metaMu.Unlock()
	// Drop a stale LRU entry; the generation check prevents it from clearing
	// the index installed above. | 丢弃陈旧 LRU 条目；代次校验会阻止它清除
	// 上面装入的新索引。
	w.idxcache.evict(seg.seq)
	w.counters.keyIndexRebuild.Add(1)
	if !w.opts.readOnly {
		// Serialize with Close: after Close's barrier below, closedFlag is set
		// and no sidecar write may race the next process that takes the
		// directory lock. | 与 Close 串行：Close 经过屏障后 closedFlag 已置位，
		// 侧车写入不会与下一个取得目录锁的进程竞争。
		w.idxWriteMu.Lock()
		if !w.closedFlag.Load() {
			data, idxCRC := w.buildFullSidecar(seg)
			if err := writeFileAtomic(seg.idxPath, data, w.opts.fileMode); err == nil {
				seg.metaMu.Lock()
				seg.idxCRC = idxCRC
				seg.metaMu.Unlock()
			}
		}
		w.idxWriteMu.Unlock()
	}
	return out.keyIndexComplete && !out.keyIndexOverflow, nil
}

// Verify validates every record, commit marker, and transaction control record
// in the current committed prefix. | Verify 校验当前已提交前缀中的每条记录、提交
// 标记与事务控制记录。
func (w *WAL) Verify(ctx context.Context) error {
	if w.isClosed() {
		return ErrClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	snap := w.Snapshot()
	if snap.LastLSN < w.FirstLSN() {
		return nil
	}
	w.mu.RLock()
	pinned := make([]*segment, 0, len(w.segments))
	for _, seg := range w.segments {
		seg.metaMu.RLock()
		last := seg.lastLSN
		seg.metaMu.RUnlock()
		if last < w.firstLSN {
			continue
		}
		seg.retain()
		pinned = append(pinned, seg)
	}
	w.mu.RUnlock()
	defer func() {
		for _, seg := range pinned {
			seg.release(w)
		}
	}()
	for _, seg := range pinned {
		seg.metaMu.RLock()
		base := seg.baseLSN
		size := seg.size
		wantLast := seg.lastLSN
		wantCount := seg.recordCount
		wantCRC := seg.crc
		seg.metaMu.RUnlock()
		if size <= int64(segmentHeaderSize) {
			continue
		}
		f, err := os.Open(seg.path)
		if err != nil {
			if os.IsNotExist(err) {
				return errs.Detail(ErrMissingSegment, "segment %[1]d is missing | 分段 %[1]d 缺失", seg.seq)
			}
			return wrapStorage("open for verify", err)
		}
		if err := validateSegmentIdentity(seg, f); err != nil {
			_ = f.Close()
			return err
		}
		out, err := w.scanSegment(seg, f, int64(segmentHeaderSize), size, scanBase{lastLSN: base - 1, atHeader: true}, false)
		_ = f.Close()
		if err != nil {
			return err
		}
		if out.truncated {
			return errs.Detail(ErrCorrupt, "segment %d has an unconfirmed tail | 分段 %d 存在未确认尾部", seg.seq, seg.seq)
		}
		// The summary drives LastLSN, key-index completeness, and continuity
		// checks. Verify must prove it describes the file, not just that the file
		// is internally consistent. | 摘要决定 LastLSN、Key 索引完整性与连续性
		// 校验；Verify 必须证明摘要描述的就是该文件，而不只是文件自洽。
		if out.lastLSN != wantLast || out.recordCount != wantCount || out.crc != wantCRC {
			return errs.Detail(ErrCorrupt, "segment %[1]d content disagrees with its summary | 分段 %[1]d 内容与摘要不一致", seg.seq)
		}
		if w.encrypted && out.sawPlain {
			return errs.Detail(ErrCipherMismatch, "plaintext record in encrypted WAL | 加密 WAL 中出现明文记录")
		}
		if !w.encrypted && out.sawEncrypted {
			return errs.Detail(ErrCipherMismatch, "encrypted record in plaintext WAL | 明文 WAL 中出现加密记录")
		}
	}
	// Decode every user record through the normal read path so AEAD, compression,
	// and dedup references are verified as well. | 通过正常读取路径解码每条用户
	// 记录，同时校验 AEAD、压缩与去重引用。
	r, err := w.newRangeReader(w.FirstLSN(), snap)
	if err != nil {
		return err
	}
	defer r.Close()
	for {
		if _, err := r.NextContext(ctx); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}
