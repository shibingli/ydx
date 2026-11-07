package wal

import (
	"context"
	"time"

	"github.com/shibingli/ydx/errs"
)

// retentionLoop runs automatic retention outside the writer. | retentionLoop
// 在 writer 之外运行自动保留。
func (w *WAL) retentionLoop() {
	defer w.retentionWG.Done()
	for {
		select {
		case <-w.retentionStop:
			return
		case <-w.retentionTrigger:
		}
		if w.retentionCtx.Err() != nil {
			return
		}
		if err := w.runRetention(w.retentionCtx); err != nil {
			w.reportAsync(err)
		}
	}
}

// runRetention evaluates oldest-first retention and enqueues one truncation. | runRetention
// 从最旧段开始评估保留策略并入队一次截断。
func (w *WAL) runRetention(ctx context.Context) error {
	r := w.opts.retention
	if r.MaxAge <= 0 && r.MaxBytes <= 0 {
		return nil
	}
	now := time.Now()
	w.mu.RLock()
	total := int64(0)
	for _, seg := range w.segments {
		seg.metaMu.RLock()
		total += seg.size
		seg.metaMu.RUnlock()
	}
	candidates := make([]*segment, 0, len(w.segments))
	for _, seg := range w.segments {
		if seg.currentState() != segmentSealed || seg.size <= int64(segmentHeaderSize) {
			continue
		}
		seg.retain()
		candidates = append(candidates, seg)
	}
	w.mu.RUnlock()
	defer func() {
		for _, seg := range candidates {
			seg.release(w)
		}
	}()
	// The segment list is ordered by seq. | 分段列表按 seq 有序。
	target := w.FirstLSN()
	removed := int64(0)
	for _, seg := range candidates {
		seg.metaMu.RLock()
		lastLSN, recordCount := seg.lastLSN, seg.recordCount
		size, minTime, maxTime := seg.size, seg.minTime, seg.maxTime
		crc := seg.crc
		created := seg.createdNano
		walID := seg.walID
		baseLSN := seg.baseLSN
		seg.metaMu.RUnlock()
		byAge := false
		if r.MaxAge > 0 {
			t := maxTime
			if t == 0 {
				t = created
			}
			byAge = now.Sub(time.Unix(0, t)) >= r.MaxAge
		}
		byBytes := r.MaxBytes > 0 && total-removed > r.MaxBytes
		if !byAge && !byBytes {
			break
		}
		if w.opts.backup != nil {
			// Verify against the full segment metadata; an incomplete meta would
			// make validBackupMarker compare SegmentCRC with zero and always fail. |
			// 使用完整段元数据校验；缺少 SegmentCRC 会让有效标记永远匹配失败。
			meta := SegmentMeta{
				Seq: seg.seq, BaseLSN: baseLSN, LastLSN: lastLSN, Records: recordCount,
				Bytes: uint64(size), MinTime: minTime, MaxTime: maxTime,
				SegmentCRC: crc, WalID: walID,
			}
			if !validBackupMarker(seg.bakPath, backupTargetID(w.backupTarget), meta) {
				w.counters.retentionSkip.Add(1)
				break
			}
			if w.backupVerify != nil {
				vctx, cancel := context.WithTimeout(ctx, w.opts.retentionVerifyTimeout)
				err := safeVerify(vctx, w.backupVerify, meta)
				cancel()
				if err != nil {
					w.counters.retentionSkip.Add(1)
					break
				}
			}
		}
		if lastLSN+1 > target {
			target = lastLSN + 1
		}
		removed += size
	}
	if target <= w.FirstLSN() {
		return nil
	}
	req := &appendRequest{kind: kindTruncate, beforeLSN: target, internal: true, done: make(chan appendResult, 1)}
	if err := w.admit(ctx, req, false); err != nil {
		if err == ErrClosed || err == context.Canceled {
			return nil
		}
		return err
	}
	res := <-req.done
	if res.err != nil && res.err != ErrClosed {
		return res.err
	}
	return nil
}

// retentionError annotates a retention failure. | retentionError 注解保留失败。
func retentionError(err error) error {
	if err == nil {
		return nil
	}
	return errs.Wrap(err, ErrStorage)
}
