package wal

import (
	"context"
	"os"

	"github.com/shibingli/ydx/errs"
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
		if err := os.Remove(seg.path); err == nil || os.IsNotExist(err) {
			_ = removeIfExists(seg.idxPath)
			_ = removeIfExists(seg.bakPath)
			w.markBackupDeleted(seg.seq)
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
