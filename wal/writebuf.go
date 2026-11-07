package wal

import (
	"os"
	"time"
)

// writeParts writes one prepared batch at off, optionally collecting it in the
// userspace buffer. The write buffer exists so a NoSync or interval-sync caller
// pays one large write instead of one syscall per small append; SyncAlways and
// any open read lease bypass it so readers and durability never observe stale
// bytes. The size policy decides the buffer limit and learns the batch-size
// distribution when adaptive sizing is enabled. | writeParts 在 off 处写出一个
// 已准备批次，并可将其收集到用户态缓冲区。写缓冲让 NoSync 或按间隔同步的调用方用
// 一次大写代替每次小追加一次系统调用；SyncAlways 与任何打开的读租约都会绕过它，
// 读者与持久性不会观察到陈旧字节。大小策略决定缓冲上限，并在启用自适应时学习批次
// 大小分布。
func (w *WAL) writeParts(f *os.File, parts [][]byte, off int64, total int, syncNow bool) error {
	w.writeBufMu.Lock()
	defer w.writeBufMu.Unlock()
	if w.policy != nil {
		w.policy.observeBatchSize(total)
	}
	limit := w.writeBufferLimit()
	// Buffering pays only while copying the batch is cheaper than the write
	// calls it replaces. The staging threshold models exactly that trade-off,
	// so it also caps the batches the userspace buffer should absorb. |
	// 只有当复制批次比它替代的写调用更便宜时，缓冲才划算。暂存阈值正好建模了这一
	// 权衡，因此它同时限制用户态缓冲应吸收的批次大小。
	batchMax := w.writeBufferBatchMax(len(parts))
	if !syncNow && limit > 0 && batchMax > 0 && w.readersActive.Load() == 0 && total > 0 &&
		total <= limit && total <= batchMax {
		if len(w.writeBuf) > 0 && w.writeBufFile != f {
			if err := w.flushWriteBufLocked(); err != nil {
				return err
			}
		}
		if len(w.writeBuf)+total > limit {
			if err := w.flushWriteBufLocked(); err != nil {
				return err
			}
		}
		if len(w.writeBuf) == 0 {
			w.writeBufFile = f
			w.writeBufOff = off
		}
		for _, p := range parts {
			w.writeBuf = append(w.writeBuf, p...)
		}
		return nil
	}
	if err := w.flushWriteBufLocked(); err != nil {
		return err
	}
	start := time.Now()
	err := w.engine.WriteAt(f, parts, off, syncNow)
	if d := time.Since(start); !syncNow && w.policy != nil && d >= 4*clockTick() {
		w.policy.observeWriteLatency(d, len(parts))
	}
	return err
}

// flushWriteBuf writes buffered append bytes to their segment. | flushWriteBuf
// 把缓冲的追加字节写入其分段。
func (w *WAL) flushWriteBuf() error {
	w.writeBufMu.Lock()
	defer w.writeBufMu.Unlock()
	return w.flushWriteBufLocked()
}

// flushWriteBufLocked writes buffered bytes while holding writeBufMu. | flushWriteBufLocked
// 在持有 writeBufMu 时写出缓冲字节。
func (w *WAL) flushWriteBufLocked() error {
	if len(w.writeBuf) == 0 {
		return nil
	}
	f := w.writeBufFile
	buf := w.writeBuf
	start := time.Now()
	err := w.engine.WriteAt(f, [][]byte{buf}, w.writeBufOff, false)
	if d := time.Since(start); err == nil && w.policy != nil && d >= 4*clockTick() {
		w.policy.observeWriteLatency(d, 1)
	}
	if err != nil {
		w.writeBuf = w.writeBuf[:0]
		w.writeBufFile = nil
		return wrapStorage("WriteAt", err)
	}
	w.writeBufOff += int64(len(buf))
	w.writeBuf = w.writeBuf[:0]
	w.writeBufFile = nil
	return nil
}
