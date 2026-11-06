package wal

import (
	"bytes"
	"context"
	"io"
	"os"
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
	var seg *segment
	for _, candidate := range w.segments {
		candidate.metaMu.RLock()
		last := candidate.lastLSN
		candidate.metaMu.RUnlock()
		if last < lsn {
			continue
		}
		seg = candidate
		break
	}
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
		return Record{}, err
	}
	defer fd.release()
	f := fd.f
	off := w.startOffset(seg, lsn)
	seg.metaMu.RLock()
	end := seg.size
	seg.metaMu.RUnlock()
	poolBuf := w.getReadBuf()
	defer w.putReadBuf(poolBuf)
	scratch := w.getReadScratch()
	defer w.putReadScratch(scratch)
	buf := poolBuf
	var header [recordHeaderSizeEncrypted]byte
	for off < end {
		hdr, payload, next, err := w.decodeRecordWindow(seg, f, off, buf, &header, 4096)
		if err != nil {
			return Record{}, err
		}
		buf = next
		off += int64(hdr.size)
		if hdr.flags&recordFlagCommitMark != 0 || hdr.codec == codecTxnControl {
			continue
		}
		if hdr.lsn < lsn {
			continue
		}
		if hdr.lsn > lsn {
			return Record{}, ErrNotFound
		}
		rr := Reader{w: w, seg: seg, file: f, off: off, buf: buf, scratch: scratch}
		rec, err := rr.resolveRecord(hdr, payload)
		if err != nil {
			return Record{}, err
		}
		return rec.Clone(), nil
	}
	return Record{}, ErrNotFound
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

// ReadInto reads a record into dst, placing Key then Data. | ReadInto 把记录读入 dst，
// 依次放置 Key 与 Data。
func (w *WAL) ReadInto(lsn uint64, dst []byte) (Record, []byte, error) {
	rec, err := w.Read(lsn)
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
// zero to means the current committed LastLSN. | Scan 对 [from,to] 内每条记录调用
// fn；from 为 0 表示 FirstLSN，to 为 0 表示当前已提交 LastLSN。
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
	r, err := w.NewReader(From(from), SnapshotOf(Snapshot{CommitSeq: snap.CommitSeq, LastLSN: to}), pinRange())
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

// Query filters records by LSN, time, Key, and Data substring. | Query 按 LSN、
// 时间、Key 与 Data 子串过滤记录。
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
	r, err := w.NewReader(From(from), SnapshotOf(Snapshot{CommitSeq: snap.CommitSeq, LastLSN: to}), pinRange())
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
		size := seg.size
		seg.metaMu.RUnlock()
		if size <= int64(segmentHeaderSize) {
			continue
		}
		f, err := os.Open(seg.path)
		if err != nil {
			return wrapStorage("open for verify", err)
		}
		out, err := w.scanSegment(seg, f, int64(segmentHeaderSize), size, seg.baseLSN-1, 0, 0, 0, 0, false)
		_ = f.Close()
		if err != nil {
			return err
		}
		if out.truncated {
			return errs.Detail(ErrCorrupt, "segment %d has an unconfirmed tail | 分段 %d 存在未确认尾部", seg.seq, seg.seq)
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
	r, err := w.NewReader(From(w.FirstLSN()), SnapshotOf(snap), pinRange())
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
