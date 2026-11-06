package wal

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/shibingli/ydx/buffpool"
	"github.com/shibingli/ydx/errs"
)

// backupState is the lifecycle of one backup item. | backupState 是一个备份条目的生命周期。
type backupState uint8

const (
	backupPending backupState = iota
	backupRunning
	backupDone
	backupDeleted
)

// backupItem tracks one sealed segment. | backupItem 跟踪一个封段。
type backupItem struct {
	seg      *segment
	state    backupState
	attempts int
	nextTry  time.Time
}

// errBackupDeleted marks a segment removed before upload. | errBackupDeleted 标记上传前已删除的分段。
var errBackupDeleted = errs.New("wal: backup segment was deleted | wal：备份分段已删除")

// enqueueBackup adds one sealed segment to the backup queue. | enqueueBackup 把一个封段加入备份队列。
func (w *WAL) enqueueBackup(seg *segment) {
	if w.opts.backup == nil || seg == nil || seg.size <= int64(segmentHeaderSize) {
		return
	}
	w.backupMu.Lock()
	if _, ok := w.backupItems[seg.seq]; ok {
		w.backupMu.Unlock()
		return
	}
	w.backupItems[seg.seq] = &backupItem{seg: seg}
	w.backupMu.Unlock()
	w.counters.backupQueued.Add(1)
	w.notifyBackup()
}

// startBackupReconciliation enqueues every sealed segment; workers skip ones
// with a valid .bak marker. | startBackupReconciliation 把所有封段加入队列；worker
// 会跳过已有有效 .bak 标记的分段。
func (w *WAL) startBackupReconciliation() {
	w.mu.RLock()
	sealed := make([]*segment, 0, len(w.segments))
	for _, seg := range w.segments {
		if seg.currentState() == segmentSealed && seg.size > int64(segmentHeaderSize) {
			sealed = append(sealed, seg)
		}
	}
	w.mu.RUnlock()
	for _, seg := range sealed {
		w.enqueueBackup(seg)
	}
}

// backupLoop runs one backup worker. | backupLoop 运行一个备份 worker。
func (w *WAL) backupLoop() {
	defer w.backupWG.Done()
	for {
		if w.backupCtx.Err() != nil {
			return
		}
		item, waitCh, nextTry := w.takeBackup()
		if item == nil {
			if !nextTry.IsZero() {
				timer := time.NewTimer(time.Until(nextTry))
				select {
				case <-w.backupCtx.Done():
					timer.Stop()
					return
				case <-waitCh:
					timer.Stop()
				case <-timer.C:
				}
				continue
			}
			select {
			case <-w.backupCtx.Done():
				return
			case <-waitCh:
				continue
			}
		}
		err := w.runBackup(item)
		switch {
		case err == nil:
			w.finishBackup(item, backupDone, nil)
		case errors.Is(err, errBackupDeleted):
			w.finishBackup(item, backupDeleted, nil)
		default:
			w.counters.backupFailed.Add(1)
			w.reportAsync(err)
			select {
			case <-w.backupCtx.Done():
				// Leave the item pending for the next Open. | 留给下一次 Open。
				w.backupMu.Lock()
				item.state = backupPending
				w.backupMu.Unlock()
				item.seg.release(w)
				return
			case <-time.After(backoffFor(item)):
			}
			w.finishBackup(item, backupPending, err)
		}
	}
}

// takeBackup removes one eligible pending item and returns the current wake
// channel when the queue is empty. | takeBackup 取出一个可执行的待办条目；队列为空时
// 返回当前唤醒通道。
func (w *WAL) takeBackup() (*backupItem, chan struct{}, time.Time) {
	w.backupMu.Lock()
	defer w.backupMu.Unlock()
	now := time.Now()
	var best *backupItem
	var nextTry time.Time
	for _, item := range w.backupItems {
		if item.state != backupPending {
			continue
		}
		if item.nextTry.After(now) {
			if nextTry.IsZero() || item.nextTry.Before(nextTry) {
				nextTry = item.nextTry
			}
			continue
		}
		if best == nil || item.seg.seq < best.seg.seq {
			best = item
		}
	}
	if best == nil {
		return nil, w.backupCh, nextTry
	}
	best.state = backupRunning
	best.attempts++
	best.seg.retain()
	return best, nil, time.Time{}
}

// backoffFor returns an exponential retry delay. | backoffFor 返回指数退避延迟。
func backoffFor(item *backupItem) time.Duration {
	d := 100 * time.Millisecond
	for i := 1; i < item.attempts && i < 9; i++ {
		d *= 2
	}
	if d > 30*time.Second {
		d = 30 * time.Second
	}
	return d
}

// runBackup uploads one item and writes its .bak marker. | runBackup 上传一个条目并写入 .bak 标记。
func (w *WAL) runBackup(item *backupItem) error {
	seg := item.seg
	if seg.size <= int64(segmentHeaderSize) {
		return nil
	}
	seg.metaMu.RLock()
	meta := SegmentMeta{
		Seq: seg.seq, BaseLSN: seg.baseLSN, LastLSN: seg.lastLSN,
		Records: seg.recordCount, Bytes: uint64(seg.size), MinTime: seg.minTime,
		MaxTime: seg.maxTime, SegmentCRC: seg.crc, WalID: seg.walID,
	}
	seg.metaMu.RUnlock()
	targetID := backupTargetID(w.backupTarget)
	if validBackupMarker(seg.bakPath, targetID, meta) {
		return nil
	}
	f, err := os.Open(seg.path)
	if err != nil {
		if os.IsNotExist(err) {
			return errBackupDeleted
		}
		return errs.WrapDetail(err, ErrBackup, "open %s | 打开 %s 失败", seg.path, seg.path)
	}
	defer f.Close()
	var idx *os.File
	if idf, err := os.Open(seg.idxPath); err == nil {
		idx = idf
		defer idx.Close()
	}
	bundle := SegmentBundle{Meta: meta, Data: f}
	if idx != nil {
		bundle.Index = idx
	}
	if err := safeBackup(w.backupCtx, w.opts.backup, bundle); err != nil {
		return errs.WrapDetail(err, ErrBackup, "backup segment %d | 备份分段 %d 失败", seg.seq, seg.seq)
	}
	if err := writeBackupMarker(seg.bakPath, targetID, meta, w.opts.fileMode); err != nil {
		return err
	}
	return nil
}

// finishBackup records a terminal or retry state. | finishBackup 记录终态或重试状态。
func (w *WAL) finishBackup(item *backupItem, state backupState, cause error) {
	w.backupMu.Lock()
	item.state = state
	if state == backupPending {
		item.nextTry = time.Now().Add(backoffFor(item))
	}
	w.backupMu.Unlock()
	if state == backupDone {
		w.counters.backupDone.Add(1)
	}
	item.seg.release(w)
	w.notifyBackup()
	if state == backupDone {
		w.triggerRetention()
	}
	if cause != nil {
		w.reportAsync(cause)
	}
}

// markBackupDeleted marks an item as deleted by truncation. | markBackupDeleted
// 把条目标记为已被截断删除。
func (w *WAL) markBackupDeleted(seq uint64) {
	w.backupMu.Lock()
	if item, ok := w.backupItems[seq]; ok {
		item.state = backupDeleted
	}
	w.backupMu.Unlock()
	w.notifyBackup()
}

// FlushBackups waits for the backups queued before the barrier. | FlushBackups
// 等待屏障之前入队的备份完成。
func (w *WAL) FlushBackups(ctx context.Context) error {
	if w.opts.readOnly {
		return ErrReadOnly
	}
	if w.opts.backup == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if _, err := w.control(ctx, kindBarrier); err != nil {
		return err
	}
	w.backupMu.Lock()
	seqs := make([]uint64, 0, len(w.backupItems))
	for seq, item := range w.backupItems {
		if item.state == backupPending || item.state == backupRunning {
			seqs = append(seqs, seq)
		}
	}
	w.backupMu.Unlock()
	return w.waitBackups(ctx, seqs, false)
}

// BackupNow rotates the active segment and waits for its backup. | BackupNow
// 轮转活动段并等待其备份完成。
func (w *WAL) BackupNow(ctx context.Context) error {
	if w.opts.readOnly {
		return ErrReadOnly
	}
	if w.opts.backup == nil {
		return nil
	}
	if err := w.Rotate(); err != nil {
		return err
	}
	return w.FlushBackups(ctx)
}

// waitBackups waits for the given sequences to reach a terminal state. | waitBackups
// 等待给定序号进入终态。
func (w *WAL) waitBackups(ctx context.Context, seqs []uint64, strict bool) error {
	if len(seqs) == 0 {
		return nil
	}
	for {
		w.backupMu.Lock()
		done := true
		deleted := false
		for _, seq := range seqs {
			item, ok := w.backupItems[seq]
			if !ok || item.state == backupDone {
				continue
			}
			if item.state == backupDeleted {
				deleted = true
				continue
			}
			done = false
			break
		}
		if done {
			w.backupMu.Unlock()
			if strict && deleted {
				return ErrNotFound
			}
			return nil
		}
		ch := w.backupCh
		w.backupMu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		case <-w.closing:
			return ErrClosed
		case <-w.closedCh:
			return ErrClosed
		}
	}
}

// safeBackup isolates user callback panics. | safeBackup 隔离用户回调 panic。
func safeBackup(ctx context.Context, b Backup, bundle SegmentBundle) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errs.Detail(ErrBackup, "backup callback panicked: %v | 备份回调 panic：%v", r, r)
		}
	}()
	return b.Backup(ctx, bundle)
}

// safeVerify isolates BackupVerifier panics. | safeVerify 隔离 BackupVerifier panic。
func safeVerify(ctx context.Context, v BackupVerifier, meta SegmentMeta) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errs.Detail(ErrBackup, "verifier panicked: %v | 校验器 panic：%v", r, r)
		}
	}()
	return v.Verify(ctx, meta)
}

// Backup marker constants. | 备份标记常量。
const (
	backupMagic      = "YDXBAK01"
	backupVersion    = uint16(1)
	backupHeaderSize = uint32(80)
	backupCRCOffset  = 76
)

// backupTargetID hashes a stable target string. | backupTargetID 对稳定目标字符串做哈希。
func backupTargetID(target string) [16]byte {
	sum := sha256.Sum256([]byte(target))
	var out [16]byte
	copy(out[:], sum[:16])
	return out
}

// writeBackupMarker atomically writes a .bak marker. | writeBackupMarker 原子写入 .bak 标记。
func writeBackupMarker(path string, targetID [16]byte, meta SegmentMeta, mode os.FileMode) error {
	var buf [backupHeaderSize]byte
	copy(buf[0:], backupMagic)
	binary.LittleEndian.PutUint16(buf[8:], backupVersion)
	binary.LittleEndian.PutUint32(buf[12:], backupHeaderSize)
	binary.LittleEndian.PutUint64(buf[16:], meta.Seq)
	binary.LittleEndian.PutUint32(buf[24:], meta.SegmentCRC)
	binary.LittleEndian.PutUint64(buf[32:], uint64(time.Now().UnixNano()))
	copy(buf[40:], targetID[:])
	copy(buf[56:], meta.WalID[:])
	binary.LittleEndian.PutUint32(buf[76:], checksum(buf[:backupCRCOffset]))
	return writeFileAtomic(path, buf[:], mode)
}

// validBackupMarker reports whether path holds a marker for meta. | validBackupMarker
// 返回 path 是否保存了 meta 的有效标记。
func validBackupMarker(path string, targetID [16]byte, meta SegmentMeta) bool {
	data, err := os.ReadFile(path)
	if err != nil || len(data) != int(backupHeaderSize) {
		return false
	}
	if string(data[0:8]) != backupMagic ||
		binary.LittleEndian.Uint16(data[8:]) != backupVersion ||
		binary.LittleEndian.Uint32(data[12:]) != backupHeaderSize {
		return false
	}
	if binary.LittleEndian.Uint32(data[backupCRCOffset:]) != checksum(data[:backupCRCOffset]) {
		return false
	}
	var gotTarget [16]byte
	copy(gotTarget[:], data[40:])
	var gotWAL [16]byte
	copy(gotWAL[:], data[56:])
	return binary.LittleEndian.Uint64(data[16:]) == meta.Seq &&
		binary.LittleEndian.Uint32(data[24:]) == meta.SegmentCRC &&
		gotTarget == targetID && gotWAL == meta.WalID
}

// dirBackup is the built-in local-directory Backup. | dirBackup 是内置的本地目录备份。
type dirBackup struct {
	dir    string
	target string
}

// DirBackup returns a local-directory backup implementation. | DirBackup 返回本地目录备份实现。
func DirBackup(dir string) Backup {
	abs, err := filepath.Abs(dir)
	if err != nil {
		abs = dir
	}
	return &dirBackup{dir: abs, target: "dir:" + abs}
}

// Target returns the stable target identifier. | Target 返回稳定目标标识。
func (b *dirBackup) Target() string { return b.target }

// Backup copies one segment into the target directory. | Backup 把一个分段复制到目标目录。
func (b *dirBackup) Backup(ctx context.Context, bundle SegmentBundle) error {
	if err := ensureDir(b.dir, 0o700); err != nil {
		return err
	}
	walPath := filepath.Join(b.dir, fmt.Sprintf("%020d.wal", bundle.Meta.Seq))
	if info, err := os.Stat(walPath); err != nil || uint64(info.Size()) != bundle.Meta.Bytes {
		if err := copyBackupFile(ctx, walPath, bundle.Data); err != nil {
			return errs.WrapDetail(err, ErrBackup, "copy wal %d | 复制 wal %d 失败", bundle.Meta.Seq, bundle.Meta.Seq)
		}
	}
	if bundle.Index != nil {
		idxPath := filepath.Join(b.dir, fmt.Sprintf("%020d.idx", bundle.Meta.Seq))
		if _, err := os.Stat(idxPath); err != nil {
			if err := copyBackupFile(ctx, idxPath, bundle.Index); err != nil {
				return errs.WrapDetail(err, ErrBackup, "copy idx %d | 复制 idx %d 失败", bundle.Meta.Seq, bundle.Meta.Seq)
			}
		}
	}
	return nil
}

// Verify checks the target segment and its header. | Verify 校验目标分段及其段头。
func (b *dirBackup) Verify(ctx context.Context, meta SegmentMeta) error {
	path := filepath.Join(b.dir, fmt.Sprintf("%020d.wal", meta.Seq))
	info, err := os.Stat(path)
	if err != nil {
		return errs.WrapDetail(err, ErrBackup, "stat %s | 检查 %s 失败", path, path)
	}
	if uint64(info.Size()) != meta.Bytes {
		return errs.Detail(ErrBackup, "backup %[1]s size %[2]d, want %[3]d | 备份 %[1]s 大小 %[2]d，期望 %[3]d",
			path, info.Size(), meta.Bytes)
	}
	h, _, err := readSegmentHeaderFile(path)
	if err != nil {
		return errs.Wrap(err, ErrBackup)
	}
	if h.seq != meta.Seq || h.walID != meta.WalID {
		return errs.Detail(ErrBackup, "backup %s header mismatch | 备份 %s 段头不匹配", path, path)
	}
	return nil
}

// copyBackupFile copies src to dst atomically, preferring reflink. | copyBackupFile
// 原子复制 src 到 dst，优先使用 reflink。
func copyBackupFile(ctx context.Context, dst string, src io.Reader) error {
	tmp := dst + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if srcFile, isFile := src.(*os.File); isFile {
		if err := cloneFile(f, srcFile); err == nil {
			if err := f.Sync(); err != nil {
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
			if err := os.Rename(tmp, dst); err != nil {
				return err
			}
			if err := syncDir(filepath.Dir(dst)); err != nil {
				return err
			}
			ok = true
			return nil
		}
		if _, err := srcFile.Seek(0, io.SeekStart); err != nil {
			return err
		}
		if err := f.Truncate(0); err != nil {
			return err
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return err
		}
	}
	buf := buffpool.Get(64 << 10)
	buf = buf[:64<<10]
	defer buffpool.Put(buf[:0])
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		n, rerr := src.Read(buf)
		if n > 0 {
			if err := writeAll(f, buf[:n]); err != nil {
				return err
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return rerr
		}
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	if err := syncDir(filepath.Dir(dst)); err != nil {
		return err
	}
	ok = true
	return nil
}

// backupFunc adapts a function to Backup. | backupFunc 把函数适配为 Backup。
type backupFunc struct {
	target string
	fn     func(context.Context, SegmentBundle) error
}

// BackupFunc adapts fn to the Backup interface. | BackupFunc 把 fn 适配为 Backup 接口。
func BackupFunc(target string, fn func(context.Context, SegmentBundle) error) Backup {
	return &backupFunc{target: target, fn: fn}
}

// Target returns the stable target identifier. | Target 返回稳定目标标识。
func (b *backupFunc) Target() string { return b.target }

// Backup calls the wrapped function. | Backup 调用包装的函数。
func (b *backupFunc) Backup(ctx context.Context, bundle SegmentBundle) error {
	return b.fn(ctx, bundle)
}
