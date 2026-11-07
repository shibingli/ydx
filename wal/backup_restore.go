package wal

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/shibingli/ydx/errs"
)

// RestoreDir restores a restore-complete backup set into walDir. The
// destination must not exist or must be an empty directory. Segments, META,
// the recovery anchor, and (when present) sidecars are written into a private
// sibling directory and published with one rename, so an interrupted restore
// never leaves a half-valid WAL. | RestoreDir 把完整恢复集还原到 walDir；
// 目标必须不存在或为空目录。分段、META、恢复锚点与（存在时）侧车先写入私有
// 兄弟目录，再用一次 rename 发布；中途失败不会留下半有效 WAL。
func RestoreDir(ctx context.Context, backupDir, walDir string) error {
	if backupDir == "" || walDir == "" {
		return errs.Detail(ErrInvalidOptions, "backup and WAL directories must not be empty | 备份目录与 WAL 目录不得为空")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	data, err := os.ReadFile(filepath.Join(backupDir, "BACKUP.snap"))
	if err != nil {
		if os.IsNotExist(err) {
			return errs.Detail(ErrNotFound, "backup snapshot is missing in %s | 备份目录 %s 缺少 BACKUP.snap", backupDir, backupDir)
		}
		return errs.WrapDetail(err, ErrStorage, "read backup snapshot | 读取备份快照失败")
	}
	set, err := DecodeBackupSet(data)
	if err != nil {
		return err
	}
	if info, statErr := os.Stat(walDir); statErr == nil {
		if !info.IsDir() {
			return errs.Detail(ErrInvalidOptions, "%s is not a directory | %s 不是目录", walDir, walDir)
		}
		entries, readErr := os.ReadDir(walDir)
		if readErr != nil {
			return errs.WrapDetail(readErr, ErrStorage, "read destination directory | 读取目标目录失败")
		}
		if len(entries) != 0 {
			return errs.Detail(ErrInvalidOptions, "destination %s is not empty | 目标目录 %s 非空", walDir, walDir)
		}
	} else if !os.IsNotExist(statErr) {
		return errs.WrapDetail(statErr, ErrStorage, "stat destination | 检查目标目录失败")
	}
	parent := filepath.Dir(walDir)
	if err := ensureDir(parent, 0o700); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(parent, filepath.Base(walDir)+".restore-")
	if err != nil {
		return errs.WrapDetail(err, ErrStorage, "create restore temp directory | 创建恢复临时目录失败")
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.RemoveAll(tmp)
		}
	}()
	for _, m := range set.Segments {
		src := filepath.Join(backupDir, zeroPad20(m.Seq)+".wal")
		dst := filepath.Join(tmp, zeroPad20(m.Seq)+".wal")
		if err := copyBackupSegment(ctx, src, dst, m); err != nil {
			return err
		}
		idxSrc := filepath.Join(backupDir, zeroPad20(m.Seq)+".idx")
		idxDst := filepath.Join(tmp, zeroPad20(m.Seq)+".idx")
		if err := copyBackupIndex(ctx, idxSrc, idxDst, m.IdxCRC); err != nil {
			return err
		}
	}
	if err := writeRestoredMetadata(tmp, set); err != nil {
		return err
	}
	if err := syncDir(tmp); err != nil {
		return errs.WrapDetail(err, ErrStorage, "sync restored directory | 同步恢复目录失败")
	}
	if info, statErr := os.Stat(walDir); statErr == nil {
		entries, readErr := os.ReadDir(walDir)
		if readErr != nil {
			return errs.WrapDetail(readErr, ErrStorage, "recheck destination | 复查目标目录失败")
		}
		if !info.IsDir() || len(entries) != 0 {
			return errs.Detail(ErrInvalidOptions, "destination %s changed during restore | 恢复期间目标目录 %s 发生变化", walDir, walDir)
		}
		if err := os.Remove(walDir); err != nil {
			return errs.WrapDetail(err, ErrStorage, "remove empty destination | 删除空目标目录失败")
		}
	}
	if err := os.Rename(tmp, walDir); err != nil {
		return errs.WrapDetail(err, ErrStorage, "publish restored directory | 发布恢复目录失败")
	}
	keep = true
	if err := syncDir(parent); err != nil {
		return errs.WrapDetail(err, ErrStorage, "sync restore parent directory | 同步恢复父目录失败")
	}
	return nil
}

// RestoreBackup restores backupDir into walDir and opens the result. | RestoreBackup
// 把 backupDir 还原到 walDir 并打开结果。
func RestoreBackup(ctx context.Context, backupDir, walDir string, opts ...Option) (*WAL, error) {
	if err := RestoreDir(ctx, backupDir, walDir); err != nil {
		return nil, err
	}
	return Open(walDir, opts...)
}

// copyBackupSegment copies one .wal file and verifies its size and CRC. | copyBackupSegment
// 复制一个 .wal 文件并校验大小与 CRC。
func copyBackupSegment(ctx context.Context, src, dst string, m SegmentMeta) error {
	in, err := os.Open(src)
	if err != nil {
		return errs.WrapDetail(err, ErrBackup, "open backup segment %d | 打开备份分段 %d 失败", m.Seq, m.Seq)
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return errs.WrapDetail(err, ErrStorage, "stat backup segment | 检查备份分段失败")
	}
	if uint64(info.Size()) != m.Bytes {
		return errs.Detail(ErrBackup, "backup segment %[1]d size %[2]d, want %[3]d | 备份分段 %[1]d 大小 %[2]d，期望 %[3]d",
			m.Seq, info.Size(), m.Bytes)
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return errs.WrapDetail(err, ErrStorage, "create restored segment | 创建恢复分段失败")
	}
	ok := false
	defer func() {
		_ = out.Close()
		if !ok {
			_ = os.Remove(dst)
		}
	}()
	buf := make([]byte, 64<<10)
	var off int64
	var crc uint32
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, rerr := in.Read(buf)
		if n > 0 {
			if err := writeAll(out, buf[:n]); err != nil {
				return errs.WrapDetail(err, ErrStorage, "write restored segment | 写入恢复分段失败")
			}
			if off+int64(n) > int64(segmentHeaderSize) {
				start := 0
				if off < int64(segmentHeaderSize) {
					start = int(int64(segmentHeaderSize) - off)
				}
				crc = appendCRC(crc, buf[start:n])
			}
			off += int64(n)
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return errs.WrapDetail(rerr, ErrStorage, "read backup segment | 读取备份分段失败")
		}
	}
	if off != int64(m.Bytes) || crc != m.SegmentCRC {
		return errs.Detail(ErrBackup, "backup segment %[1]d failed size/CRC verification | 备份分段 %[1]d 大小/CRC 校验失败", m.Seq)
	}
	if err := out.Sync(); err != nil {
		return errs.WrapDetail(err, ErrStorage, "sync restored segment | 同步恢复分段失败")
	}
	if err := out.Close(); err != nil {
		return errs.WrapDetail(err, ErrStorage, "close restored segment | 关闭恢复分段失败")
	}
	ok = true
	return nil
}

// copyBackupIndex copies an optional sidecar and verifies its CRC. | copyBackupIndex
// 复制可选侧车并校验其 CRC。
func copyBackupIndex(ctx context.Context, src, dst string, wantCRC uint32) error {
	data, err := os.ReadFile(src)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return errs.WrapDetail(err, ErrStorage, "read backup sidecar | 读取备份侧车失败")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if wantCRC == 0 {
		// The backup set carries no sidecar checksum. Publishing an
		// unverifiable index would let a damaged sparse table steer reads to
		// wrong offsets; a missing sidecar is rebuilt from the verified segment
		// instead. | 备份集没有侧车校验和时，发布不可校验的索引会让损坏的偏移表
		// 把读取引向错误位置；缺失的侧车会从已校验分段重建，因此直接跳过。
		return nil
	}
	if checksum(data) != wantCRC {
		return errs.Detail(ErrBackup, "backup sidecar %s CRC mismatch | 备份侧车 %s CRC 不匹配", src, src)
	}
	return writeFileAtomic(dst, data, 0o600)
}

// writeRestoredMetadata writes META, META.mirror, and the recovery anchor
// reconstructed from the backup set. | writeRestoredMetadata 根据备份集重建并
// 写入 META、META.mirror 与恢复锚点。
func writeRestoredMetadata(dir string, set BackupSet) error {
	var flags uint16
	if set.Encrypted {
		flags |= metaFlagEncrypted
	}
	if set.Serializable {
		flags |= metaFlagSerializable
		flags |= (uint16(set.HashAlgorithm) & metaFlagHashMask) << metaFlagHashShift
	}
	created := set.CreatedNano
	if created == 0 {
		created = time.Now().UnixNano()
	}
	gapSet := newGapSet()
	for _, g := range set.Gaps {
		gapSet.add(g.Start, g.End)
	}
	gapEnd := gapSet.maxEnd()
	gaps := gapSet.snapshot()
	st := metaState{
		generation: 1, nextSeq: set.NextSeq, nextLSN: set.NextLSN, createdNano: created,
		firstLSN: set.FirstLSN, commitSeq: set.CommitSeq, gapFloor: gapEnd,
		activeKeyKCV: set.ActiveKeyKCV, walID: set.WalID, activeKeyID: set.ActiveKeyID,
		flags: flags,
	}
	var slot [metaSlotSize]byte
	encodeMetaSlot(slot[:], st)
	buf := make([]byte, metaFileSize)
	copy(buf[:metaSlotSize], slot[:])
	if err := writeFileAtomic(filepath.Join(dir, "META"), buf, 0o600); err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(dir, "META.mirror"), buf, 0o600); err != nil {
		return err
	}
	// Publish the lock file with the restored directory so a later read-only
	// open takes a shared lock instead of racing a writer that creates it. |
	// 随恢复目录一起发布锁文件，使之后的只读打开获取共享锁，而不是与创建锁文件
	// 的写者竞争。
	if err := writeFileAtomic(filepath.Join(dir, "wal.lock"), nil, 0o600); err != nil {
		return err
	}
	anchor := anchorState{
		generation: 1, flags: flags, walID: set.WalID, createdNano: created,
		nextSeq: set.NextSeq, nextLSN: set.NextLSN, firstLSN: set.FirstLSN,
		commitSeq: set.CommitSeq, activeKeyID: set.ActiveKeyID, activeKeyKCV: set.ActiveKeyKCV,
		gaps: gaps,
	}
	return writeAnchorFile(anchorPath(dir), anchor, 0o600)
}
