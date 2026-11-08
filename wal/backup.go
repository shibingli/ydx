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
	"sync"
	"sync/atomic"
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
	nextTry  time.Time
	seg      *segment
	attempts int
	state    backupState
	// deleted is set when Truncate retires the segment before upload. A worker
	// that already took the item checks it before opening or uploading. |
	// Truncate 在上传前退休分段时置位；已取出条目的 worker 在打开或上传前检查。
	deleted atomic.Bool
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
	pending := w.backupPendingLocked()
	warn := w.opts.backupMaxPending > 0 && pending > w.opts.backupMaxPending && !w.backupWarned
	if warn {
		w.backupWarned = true
	}
	w.backupMu.Unlock()
	w.counters.backupQueued.Add(1)
	if warn {
		w.reportAsync(errs.Detail(ErrBackup, "backup backlog %[1]d exceeds %[2]d | 备份积压 %[1]d 超过阈值 %[2]d",
			pending, w.opts.backupMaxPending))
	}
	w.notifyBackup()
}

// backupPendingLocked counts pending/running items; the caller holds backupMu. |
// backupPendingLocked 统计待办/运行中的条目；调用方持有 backupMu。
func (w *WAL) backupPendingLocked() int {
	n := 0
	for _, item := range w.backupItems {
		if item.state == backupPending || item.state == backupRunning {
			n++
		}
	}
	return n
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
			// Schedule a retry without blocking this worker or reporting the
			// error twice; finishBackup sets nextTry and reports once. | 只安排
			// 重试，不阻塞 worker，也不重复上报；finishBackup 设置 nextTry 并
			// 只上报一次。
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
	if item.deleted.Load() {
		return errBackupDeleted
	}
	seg := item.seg
	if seg.size <= int64(segmentHeaderSize) {
		return nil
	}
	seg.metaMu.RLock()
	meta := SegmentMeta{
		Seq: seg.seq, BaseLSN: seg.baseLSN, LastLSN: seg.lastLSN,
		Records: seg.recordCount, Bytes: uint64(seg.size), MinTime: seg.minTime,
		MaxTime: seg.maxTime, SegmentCRC: seg.crc, IdxCRC: seg.idxCRC,
		CommitSeq: seg.commitSeq, CreatedNano: seg.createdNano, WalID: seg.walID,
	}
	seg.metaMu.RUnlock()
	targetID := backupTargetID(w.backupTarget)
	if validBackupMarker(seg.bakPath, targetID, meta) {
		// A marker only proves this WAL once observed success. When the target
		// implements BackupVerifier, confirm the object still exists there before
		// trusting it; otherwise a lost remote object would never be re-uploaded.
		// | 标记只证明本 WAL 曾观察到成功。目标实现 BackupVerifier 时必须确认
		// 远端对象仍存在才可信任标记，否则丢失的远端对象永远不会被重传。
		v, ok := w.opts.backup.(BackupVerifier)
		if !ok {
			return nil
		}
		vctx, cancel := context.WithTimeout(w.backupCtx, w.opts.backupVerifyTimeout)
		verr := safeVerify(vctx, v, meta)
		cancel()
		if verr == nil {
			return nil
		}
		// The marker is stale or the object is gone. Re-upload instead of trusting
		// an unverifiable marker: returning an error here would only retry the
		// verification forever and never repair the target. A transient verify
		// failure costs one re-upload; a real target loss is repaired. | 标记已陈旧
		// 或对象已丢失。不能信任无法校验的标记，应重新上传：在此返回错误只会永远
		// 重试校验而不会修复目标。校验的瞬时失败只多一次上传；目标确实丢失时则被
		// 修复。
	}
	f, err := os.Open(seg.path)
	if err != nil {
		if os.IsNotExist(err) {
			return errBackupDeleted
		}
		return errs.WrapDetail(err, ErrBackup, "open %s | 打开 %s 失败", seg.path, seg.path)
	}
	defer f.Close()
	if err := validateSegmentIdentity(seg, f); err != nil {
		return err
	}
	// validateSegmentIdentity performs a positional read. On Windows blocking
	// handles that advances the shared file cursor, so rewind before exposing the
	// file to a sequential Backup implementation; otherwise the uploaded object
	// silently loses its 64-byte header. | validateSegmentIdentity 执行位置读；
	// Windows 阻塞句柄上这会推进共享文件游标。交给顺序读取的 Backup 实现前必须
	// 回退，否则上传对象会静默丢失 64 字节段头。
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return errs.WrapDetail(err, ErrBackup, "seek segment %s to start | 定位分段 %s 到起点失败", seg.path, seg.path)
	}
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
	} else {
		// Done/deleted items need no durable in-memory record; the .bak marker
		// is the durable evidence. Keeping every historical item would pin
		// segments and make takeBackup O(total segments). | 完成/已删除条目无需
		// 常驻内存；.bak 标记是持久证据。保留全部历史条目会钉住分段并使
		// takeBackup 退化为 O(总段数)。
		delete(w.backupItems, item.seg.seq)
	}
	if w.opts.backupMaxPending > 0 && w.backupPendingLocked() <= w.opts.backupMaxPending {
		w.backupWarned = false
	}
	w.backupMu.Unlock()
	if state == backupDone {
		w.counters.backupDone.Add(1)
	}
	if state == backupDone {
		// Drop page cache before retention can delete the segment. | 在保留策略
		// 可能删除分段前回收页缓存。
		w.maybeFadvise(item.seg)
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

// markBackupDeleted marks an item as deleted by truncation. Pending items are
// removed from the queue immediately; a running item keeps its in-flight
// reference and observes the flag before its next upload step. | markBackupDeleted
// 把条目标记为已被截断删除。待办条目立即出队；运行中的条目保留在途引用，
// 并在下一步上传前观察到该标志。
func (w *WAL) markBackupDeleted(seq uint64) {
	w.backupMu.Lock()
	if item, ok := w.backupItems[seq]; ok {
		item.deleted.Store(true)
		if item.state == backupPending {
			item.state = backupDeleted
			delete(w.backupItems, seq)
		}
	}
	if w.opts.backupMaxPending > 0 && w.backupPendingLocked() <= w.opts.backupMaxPending {
		w.backupWarned = false
	}
	w.backupMu.Unlock()
	w.notifyBackup()
}

// BackupConfigured reports whether a backup target was configured at Open. |
// BackupConfigured 报告 Open 时是否配置了备份目标。
func (w *WAL) BackupConfigured() bool {
	return w.opts.backup != nil
}

// SupportsSnapshotBackup reports whether the configured backup target
// implements SnapshotBackup, which BackupNow requires. | SupportsSnapshotBackup
// 报告配置的备份目标是否实现 BackupNow 所需的 SnapshotBackup。
func (w *WAL) SupportsSnapshotBackup() bool {
	if w.opts.backup == nil {
		return false
	}
	_, ok := w.opts.backup.(SnapshotBackup)
	return ok
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

// BackupNow rotates the active segment, waits for every referenced segment,
// and atomically publishes a restore-complete BackupSet. Targets that do not
// implement SnapshotBackup return ErrUnsupported. | BackupNow 轮转活动段、等待
// 所有引用分段完成备份，并原子发布可完整恢复的 BackupSet；未实现
// SnapshotBackup 的目标返回 ErrUnsupported。
func (w *WAL) BackupNow(ctx context.Context) error {
	if w.opts.readOnly {
		return ErrReadOnly
	}
	if w.opts.backup == nil {
		return nil
	}
	sb, ok := w.opts.backup.(SnapshotBackup)
	if !ok {
		return errs.Detail(ErrUnsupported, "BackupNow requires a SnapshotBackup target | BackupNow 需要支持 SnapshotBackup 的备份目标")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := w.Rotate(); err != nil {
		return err
	}
	if err := w.FlushBackups(ctx); err != nil {
		return err
	}
	res, err := w.control(ctx, kindBackupSnapshot)
	if err != nil {
		return err
	}
	set := res.backupSet
	if set == nil {
		return errs.Detail(ErrBackup, "no backup set was captured | 未捕获到备份集")
	}
	if err := w.waitBackups(ctx, backupSetSeqs(set), true); err != nil {
		return err
	}
	if err := w.verifyBackupSet(ctx, set); err != nil {
		return err
	}
	if err := safeSnapshotBackup(ctx, sb, *set); err != nil {
		w.counters.backupSnapshotErr.Add(1)
		return errs.WrapDetail(err, ErrBackup, "publish backup snapshot | 发布备份快照失败")
	}
	w.counters.backupSnapshots.Add(1)
	return nil
}

// backupSetSeqs returns the set's segment sequences. | backupSetSeqs 返回集合的
// 分段序号。
func backupSetSeqs(set *BackupSet) []uint64 {
	seqs := make([]uint64, 0, len(set.Segments))
	for _, m := range set.Segments {
		seqs = append(seqs, m.Seq)
	}
	return seqs
}

// verifyBackupSet proves that every segment in the set has a durable .bak
// marker and, when the target implements BackupVerifier, still exists at the
// target. | verifyBackupSet 证明集合内每个分段都有持久 .bak 标记；目标实现
// BackupVerifier 时还要证明目标对象仍存在。
func (w *WAL) verifyBackupSet(ctx context.Context, set *BackupSet) error {
	targetID := backupTargetID(w.backupTarget)
	for _, m := range set.Segments {
		if !validBackupMarker(backupPath(w.dir, m.Seq), targetID, m) {
			return errs.Detail(ErrBackup, "segment %[1]d has no valid backup marker | 分段 %[1]d 没有有效备份标记", m.Seq)
		}
	}
	if v, ok := w.opts.backup.(BackupVerifier); ok {
		for _, m := range set.Segments {
			vctx, cancel := context.WithTimeout(ctx, w.opts.backupVerifyTimeout)
			err := safeVerify(vctx, v, m)
			cancel()
			if err != nil {
				return errs.WrapDetail(err, ErrBackup, "verify segment %d at backup target | 在备份目标校验分段 %d 失败", m.Seq, m.Seq)
			}
		}
	}
	return nil
}

// safeSnapshotBackup isolates user callback panics. | safeSnapshotBackup 隔离
// 用户回调 panic。
func safeSnapshotBackup(ctx context.Context, b SnapshotBackup, set BackupSet) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errs.Detail(ErrBackup, "snapshot backup callback panicked: %v | 快照备份回调 panic：%v", r, r)
		}
	}()
	return b.BackupSnapshot(ctx, set)
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
	// snapshotMu serializes BACKUP.snap publication. Concurrent BackupNow calls
	// share the fixed BACKUP.snap.tmp path, so an unlocked write could mix two
	// snapshots and publish a corrupt commit point. | snapshotMu 串行化
	// BACKUP.snap 发布；并发 BackupNow 共用固定的 BACKUP.snap.tmp 路径，未加锁
	// 的写入可能混合两份快照并发布损坏的提交点。
	snapshotMu sync.Mutex
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
	copyNeeded := true
	if info, err := os.Stat(walPath); err == nil && uint64(info.Size()) == bundle.Meta.Bytes {
		// A same-size destination is only trustworthy when its CRC matches the
		// source summary; otherwise retention could delete the only good copy. |
		// 只有 CRC 与源摘要一致时才能信任同尺寸目标；否则保留策略可能删掉唯一
		// 的好副本。
		if crc, err := segmentFileCRC(ctx, walPath); err == nil && crc == bundle.Meta.SegmentCRC {
			copyNeeded = false
		}
	}
	if copyNeeded {
		if err := copyBackupFile(ctx, walPath, bundle.Data); err != nil {
			return errs.WrapDetail(err, ErrBackup, "copy wal %d | 复制 wal %d 失败", bundle.Meta.Seq, bundle.Meta.Seq)
		}
	}
	if bundle.Index != nil {
		idxPath := filepath.Join(b.dir, fmt.Sprintf("%020d.idx", bundle.Meta.Seq))
		copyIdx := true
		if data, err := os.ReadFile(idxPath); err == nil && bundle.Meta.IdxCRC != 0 && checksum(data) == bundle.Meta.IdxCRC {
			copyIdx = false
		}
		if copyIdx {
			if err := copyBackupFile(ctx, idxPath, bundle.Index); err != nil {
				return errs.WrapDetail(err, ErrBackup, "copy idx %d | 复制 idx %d 失败", bundle.Meta.Seq, bundle.Meta.Seq)
			}
		}
	}
	return nil
}

// BackupSnapshot verifies every referenced segment and atomically publishes
// BACKUP.snap. The verification makes the snapshot the commit point of a
// restore-complete set: a partially uploaded segment can never be referenced. |
// BackupSnapshot 校验每个引用分段并原子发布 BACKUP.snap。校验使快照成为完整
// 恢复集的提交点：未完整上传的分段永远不会被引用。
func (b *dirBackup) BackupSnapshot(ctx context.Context, set BackupSet) error {
	b.snapshotMu.Lock()
	defer b.snapshotMu.Unlock()
	if err := ensureDir(b.dir, 0o700); err != nil {
		return err
	}
	for _, m := range set.Segments {
		path := filepath.Join(b.dir, fmt.Sprintf("%020d.wal", m.Seq))
		info, err := os.Stat(path)
		if err != nil {
			return errs.WrapDetail(err, ErrBackup, "stat backup segment %d | 检查备份分段 %d 失败", m.Seq, m.Seq)
		}
		if uint64(info.Size()) != m.Bytes {
			return errs.Detail(ErrBackup, "backup segment %[1]d size %[2]d, want %[3]d | 备份分段 %[1]d 大小 %[2]d，期望 %[3]d",
				m.Seq, info.Size(), m.Bytes)
		}
		crc, err := segmentFileCRC(ctx, path)
		if err != nil {
			return errs.WrapDetail(err, ErrBackup, "checksum backup segment %d | 校验备份分段 %d 失败", m.Seq, m.Seq)
		}
		if crc != m.SegmentCRC {
			return errs.Detail(ErrBackup, "backup segment %[1]d CRC mismatch | 备份分段 %[1]d CRC 不匹配", m.Seq)
		}
		if m.IdxCRC != 0 {
			idxPath := filepath.Join(b.dir, fmt.Sprintf("%020d.idx", m.Seq))
			if data, err := os.ReadFile(idxPath); err == nil && checksum(data) != m.IdxCRC {
				return errs.Detail(ErrBackup, "backup sidecar %[1]d CRC mismatch | 备份侧车 %[1]d CRC 不匹配", m.Seq)
			}
		}
	}
	data, err := EncodeBackupSet(set)
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(b.dir, "BACKUP.snap"), data, 0o600)
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
	crc, err := segmentFileCRC(ctx, path)
	if err != nil {
		return errs.WrapDetail(err, ErrBackup, "checksum backup %s | 校验备份 %s 失败", path, path)
	}
	if crc != meta.SegmentCRC {
		return errs.Detail(ErrBackup, "backup %[1]s CRC mismatch | 备份 %[1]s CRC 不匹配", path)
	}
	return nil
}

// segmentFileCRC computes the segment CRC over [64, size), honoring ctx during
// the read so a verifier timeout can interrupt a large target. | segmentFileCRC
// 计算 [64, size) 区间的分段 CRC 并在读取期间响应 ctx，使校验超时可中断大文件。
func segmentFileCRC(ctx context.Context, path string) (uint32, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	size := info.Size()
	buf := buffpool.Get(64 << 10)
	buf = buf[:64<<10]
	defer buffpool.Put(buf[:0])
	crc := uint32(0)
	for off := int64(segmentHeaderSize); off < size; {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		n := int64(len(buf))
		if off+n > size {
			n = size - off
		}
		if err := readFullAt(f, buf[:n], off); err != nil {
			return 0, err
		}
		crc = appendCRC(crc, buf[:n])
		off += n
	}
	return crc, nil
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
	fn     func(context.Context, SegmentBundle) error
	target string
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
