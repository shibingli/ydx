package wal

import (
	"context"
	"os"
	"time"

	"github.com/shibingli/ydx/errs"
)

// Cleaner retry bounds for platform-level unlink failures. | cleaner 针对平台
// 级 unlink 失败的重试边界。
const (
	cleanupRetryMin = 100 * time.Millisecond
	cleanupRetryMax = 5 * time.Second
)

// cleanerLoop is the only goroutine that unlinks segment files. | cleanerLoop
// 是唯一 unlink 分段文件的协程。
func (w *WAL) cleanerLoop() {
	defer w.cleanerWG.Done()
	for {
		w.cleanerMu.Lock()
		if len(w.cleanerQ) == 0 {
			ch := w.cleanerCh
			w.cleanerMu.Unlock()
			select {
			case <-w.cleanerStop:
				return
			case <-ch:
				continue
			}
		}
		seg := w.cleanerQ[0]
		w.cleanerQ = w.cleanerQ[1:]
		w.cleanerBusy = true
		w.cleanerMu.Unlock()

		for {
			w.cleanerMu.Lock()
			if seg.refs.Load() == 0 {
				w.cleanerMu.Unlock()
				break
			}
			ch := w.cleanerCh
			w.cleanerMu.Unlock()
			select {
			case <-w.cleanerStop:
				return
			case <-ch:
			}
		}
		w.fdcache.evict(seg.seq)
		w.idxcache.evict(seg.seq)
		retry := cleanupRetryMin
		for {
			err := os.Remove(seg.path)
			if err == nil || os.IsNotExist(err) {
				if e := removeIfExists(seg.idxPath); e != nil {
					w.counters.cleanupErrors.Add(1)
					w.reportAsync(errs.WrapDetail(e, ErrStorage, "remove sidecar %s | 删除侧车 %s 失败", seg.idxPath, seg.idxPath))
				}
				if e := removeIfExists(seg.bakPath); e != nil {
					w.counters.cleanupErrors.Add(1)
					w.reportAsync(errs.WrapDetail(e, ErrStorage, "remove backup marker %s | 删除备份标记 %s 失败", seg.bakPath, seg.bakPath))
				}
				w.markBackupDeleted(seg.seq)
				break
			}
			// A retired segment can no longer be read. Keep retrying instead of
			// silently leaving files behind (e.g. a Windows sharing violation);
			// Close interrupts the retry loop. | 已退休分段不再可读；不能静默留下
			// 文件（例如 Windows 共享冲突），必须持续重试；Close 可打断重试。
			w.counters.cleanupErrors.Add(1)
			w.reportAsync(errs.WrapDetail(err, ErrStorage, "remove segment %d | 删除分段 %d 失败", seg.seq, seg.seq))
			select {
			case <-w.cleanerStop:
				w.cleanerMu.Lock()
				w.cleanerBusy = false
				w.cleanerMu.Unlock()
				return
			case <-time.After(retry):
			}
			if retry < cleanupRetryMax {
				retry *= 2
				if retry > cleanupRetryMax {
					retry = cleanupRetryMax
				}
			}
		}
		w.cleanerMu.Lock()
		w.cleanerBusy = false
		w.cleanerMu.Unlock()
		w.notifyCleaner()
	}
}

// FlushCleanup waits until the cleaner has retired every queued segment. | FlushCleanup
// 等待 cleaner 处理完当前退休队列。
func (w *WAL) FlushCleanup(ctx context.Context) error {
	if w.opts.readOnly {
		return ErrReadOnly
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		w.cleanerMu.Lock()
		done := len(w.cleanerQ) == 0 && !w.cleanerBusy
		ch := w.cleanerCh
		w.cleanerMu.Unlock()
		if done {
			return nil
		}
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		case <-w.closing:
			return ErrClosed
		case <-w.cleanerStop:
			return ErrClosed
		}
	}
}

// cleanupError identifies a cleanup failure. | cleanupError 标识清理失败。
func cleanupError(err error) error {
	if err == nil {
		return nil
	}
	return errs.Wrap(err, ErrStorage)
}
