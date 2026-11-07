package wal

import (
	"encoding/binary"
	"math"
	"sort"

	"github.com/shibingli/ydx/errs"
)

// Backup snapshot wire format. The set metadata is written last by a
// SnapshotBackup implementation, so its presence is the commit point of a
// restore-complete backup. | 备份快照线格式。集合元数据由 SnapshotBackup 实现
// 最后写入，因此它的存在就是完整恢复集的提交点。
const (
	backupSnapshotMagic      = "YDXBSN01"
	backupSnapshotVersion    = uint16(1)
	backupSnapshotHeaderSize = uint32(104)
	backupSegmentEntrySize   = 80
	backupGapEntrySize       = 16
	backupSnapshotTrailer    = 4
)

// Backup snapshot header offsets. | 备份快照头字段偏移。
const (
	bsOffMagic        = 0
	bsOffVersion      = 8
	bsOffFlags        = 10
	bsOffHeaderSize   = 12
	bsOffWalID        = 16
	bsOffCreatedNano  = 32
	bsOffFirstLSN     = 40
	bsOffLastLSN      = 48
	bsOffNextLSN      = 56
	bsOffNextSeq      = 64
	bsOffCommitSeq    = 72
	bsOffActiveKeyID  = 80
	bsOffSegmentCount = 84
	bsOffActiveKCV    = 88
	bsOffGapCount     = 96
	bsOffReserved     = 100
)

// validateBackupSet checks the invariants required for a restore-complete set. |
// validateBackupSet 校验完整恢复集必须满足的不变量。
func validateBackupSet(set BackupSet) error {
	if set.WalID == ([16]byte{}) {
		return errs.Detail(ErrCorrupt, "backup set has zero walID | 备份集 walID 为零")
	}
	if set.FirstLSN == 0 || set.LastLSN < set.FirstLSN-1 {
		return errs.Detail(ErrCorrupt, "backup set LSN range is invalid | 备份集 LSN 区间非法")
	}
	if set.LastLSN == math.MaxUint64 {
		return errs.Detail(ErrCorrupt, "backup set LastLSN is exhausted | 备份集 LastLSN 已耗尽")
	}
	if set.NextLSN != set.LastLSN+1 {
		return errs.Detail(ErrCorrupt, "backup set NextLSN %[1]d is not LastLSN+1 (%[2]d) | 备份集 NextLSN %[1]d 不是 LastLSN+1（%[2]d）",
			set.NextLSN, set.LastLSN+1)
	}
	if set.NextSeq == 0 {
		return errs.Detail(ErrCorrupt, "backup set NextSeq is zero | 备份集 NextSeq 为零")
	}
	if set.Encrypted != (set.ActiveKeyID != 0) {
		return errs.Detail(ErrCipherMismatch, "backup set encryption flag and key ID disagree | 备份集加密标志与密钥 ID 不一致")
	}
	if !set.Serializable && set.HashAlgorithm != HashSHA256 {
		return errs.Detail(ErrCorrupt, "backup set hash algorithm set without serializable durability | 备份集未启用可串行化持久化却设置哈希算法")
	}
	if set.HashAlgorithm > HashSM3 {
		return errs.Detail(ErrCorrupt, "backup set hash algorithm %[1]d is invalid | 备份集哈希算法 %[1]d 非法", set.HashAlgorithm)
	}
	coversGap := func(start, end uint64) bool {
		for _, g := range set.Gaps {
			if g.Start <= start && g.End >= end {
				return true
			}
		}
		return false
	}
	var maxSeq, maxLast uint64
	prevSeq := uint64(0)
	for i, m := range set.Segments {
		if m.Seq == 0 || m.BaseLSN == 0 || m.LastLSN < m.BaseLSN-1 ||
			m.Bytes < uint64(segmentHeaderSize) {
			return errs.Detail(ErrCorrupt, "backup segment entry %[1]d is invalid | 备份分段条目 %[1]d 非法", i)
		}
		if i > 0 && m.Seq <= prevSeq {
			return errs.Detail(ErrCorrupt, "backup segments are not strictly ordered | 备份分段未严格排序")
		}
		if m.WalID != ([16]byte{}) && m.WalID != set.WalID {
			return errs.Detail(ErrCorrupt, "backup segment walID mismatch | 备份分段 walID 不匹配")
		}
		prevSeq = m.Seq
		if m.Seq > maxSeq {
			maxSeq = m.Seq
		}
		if m.LastLSN > maxLast {
			maxLast = m.LastLSN
		}
	}
	if len(set.Segments) == 0 {
		if set.LastLSN != set.FirstLSN-1 {
			return errs.Detail(ErrCorrupt, "empty backup set has records | 空备份集却声明了记录")
		}
	} else {
		if set.LastLSN != maxLast {
			return errs.Detail(ErrCorrupt, "backup LastLSN %[1]d does not match segments %[2]d | 备份 LastLSN %[1]d 与分段 %[2]d 不一致",
				set.LastLSN, maxLast)
		}
		if set.FirstLSN > set.LastLSN || set.Segments[0].LastLSN < set.FirstLSN {
			return errs.Detail(ErrCorrupt, "backup segments do not cover FirstLSN %[1]d | 备份分段未覆盖 FirstLSN %[1]d", set.FirstLSN)
		}
		if set.Segments[0].BaseLSN > set.FirstLSN {
			if !coversGap(set.FirstLSN, set.Segments[0].BaseLSN-1) {
				return errs.Detail(ErrCorrupt, "backup head gap is not recorded | 备份头部缺口未记录")
			}
		}
		for i := 1; i < len(set.Segments); i++ {
			prev := set.Segments[i-1].LastLSN
			base := set.Segments[i].BaseLSN
			if base > prev+1 && !coversGap(prev+1, base-1) {
				return errs.Detail(ErrCorrupt, "backup segment gap after %[1]d is not recorded | 备份在 %[1]d 之后的分段缺口未记录", prev)
			}
		}
		if set.NextSeq <= maxSeq {
			return errs.Detail(ErrCorrupt, "backup NextSeq %[1]d does not exceed segment %[2]d | 备份 NextSeq %[1]d 未超过分段 %[2]d",
				set.NextSeq, maxSeq)
		}
	}
	var prevEnd uint64
	for i, g := range set.Gaps {
		if g.Start == 0 || g.Start > g.End || g.Start < set.FirstLSN || g.End > set.LastLSN ||
			(i > 0 && g.Start <= prevEnd) {
			return errs.Detail(ErrCorrupt, "backup gap entry %[1]d is invalid | 备份缺口条目 %[1]d 非法", i)
		}
		prevEnd = g.End
	}
	return nil
}

// EncodeBackupSet encodes a restore-complete set. The trailing CRC covers
// every preceding byte. | EncodeBackupSet 编码完整恢复集；尾部 CRC 覆盖之前
// 全部字节。
func EncodeBackupSet(set BackupSet) ([]byte, error) {
	if err := validateBackupSet(set); err != nil {
		return nil, err
	}
	size := int(backupSnapshotHeaderSize) + len(set.Segments)*backupSegmentEntrySize +
		len(set.Gaps)*backupGapEntrySize + backupSnapshotTrailer
	buf := make([]byte, size)
	copy(buf[bsOffMagic:], backupSnapshotMagic)
	binary.LittleEndian.PutUint16(buf[bsOffVersion:], backupSnapshotVersion)
	var flags uint16
	if set.Encrypted {
		flags |= metaFlagEncrypted
	}
	if set.Serializable {
		flags |= metaFlagSerializable
		flags |= (uint16(set.HashAlgorithm) & metaFlagHashMask) << metaFlagHashShift
	}
	binary.LittleEndian.PutUint16(buf[bsOffFlags:], flags)
	binary.LittleEndian.PutUint32(buf[bsOffHeaderSize:], backupSnapshotHeaderSize)
	copy(buf[bsOffWalID:], set.WalID[:])
	binary.LittleEndian.PutUint64(buf[bsOffCreatedNano:], uint64(set.CreatedNano))
	binary.LittleEndian.PutUint64(buf[bsOffFirstLSN:], set.FirstLSN)
	binary.LittleEndian.PutUint64(buf[bsOffLastLSN:], set.LastLSN)
	binary.LittleEndian.PutUint64(buf[bsOffNextLSN:], set.NextLSN)
	binary.LittleEndian.PutUint64(buf[bsOffNextSeq:], set.NextSeq)
	binary.LittleEndian.PutUint64(buf[bsOffCommitSeq:], set.CommitSeq)
	binary.LittleEndian.PutUint32(buf[bsOffActiveKeyID:], set.ActiveKeyID)
	binary.LittleEndian.PutUint32(buf[bsOffSegmentCount:], uint32(len(set.Segments)))
	binary.LittleEndian.PutUint64(buf[bsOffActiveKCV:], set.ActiveKeyKCV)
	binary.LittleEndian.PutUint32(buf[bsOffGapCount:], uint32(len(set.Gaps)))
	off := int(backupSnapshotHeaderSize)
	for _, m := range set.Segments {
		e := buf[off : off+backupSegmentEntrySize]
		binary.LittleEndian.PutUint64(e[0:], m.Seq)
		binary.LittleEndian.PutUint64(e[8:], m.BaseLSN)
		binary.LittleEndian.PutUint64(e[16:], m.LastLSN)
		binary.LittleEndian.PutUint64(e[24:], m.Records)
		binary.LittleEndian.PutUint64(e[32:], m.Bytes)
		binary.LittleEndian.PutUint64(e[40:], uint64(m.MinTime))
		binary.LittleEndian.PutUint64(e[48:], uint64(m.MaxTime))
		binary.LittleEndian.PutUint32(e[56:], m.SegmentCRC)
		binary.LittleEndian.PutUint32(e[60:], m.IdxCRC)
		binary.LittleEndian.PutUint64(e[64:], m.CommitSeq)
		binary.LittleEndian.PutUint64(e[72:], uint64(m.CreatedNano))
		off += backupSegmentEntrySize
	}
	for _, g := range set.Gaps {
		e := buf[off : off+backupGapEntrySize]
		binary.LittleEndian.PutUint64(e[0:], g.Start)
		binary.LittleEndian.PutUint64(e[8:], g.End)
		off += backupGapEntrySize
	}
	binary.LittleEndian.PutUint32(buf[off:], checksum(buf[:off]))
	return buf, nil
}

// DecodeBackupSet decodes and validates a restore-complete set. | DecodeBackupSet
// 解码并校验完整恢复集。
func DecodeBackupSet(data []byte) (BackupSet, error) {
	if len(data) < int(backupSnapshotHeaderSize)+backupSnapshotTrailer {
		return BackupSet{}, errs.Detail(ErrCorrupt, "backup snapshot is only %[1]d bytes | 备份快照仅 %[1]d 字节", len(data))
	}
	if string(data[bsOffMagic:bsOffMagic+8]) != backupSnapshotMagic {
		return BackupSet{}, errs.Detail(ErrCorrupt, "bad backup snapshot magic | 备份快照 magic 非法")
	}
	if binary.LittleEndian.Uint16(data[bsOffVersion:]) != backupSnapshotVersion ||
		binary.LittleEndian.Uint32(data[bsOffHeaderSize:]) != backupSnapshotHeaderSize {
		return BackupSet{}, errs.Detail(ErrUnsupported, "unsupported backup snapshot version/layout | 不支持的备份快照版本/布局")
	}
	body := data[:len(data)-backupSnapshotTrailer]
	if got, want := binary.LittleEndian.Uint32(data[len(data)-backupSnapshotTrailer:]), checksum(body); got != want {
		return BackupSet{}, errs.Detail(ErrCorrupt, "backup snapshot CRC mismatch | 备份快照 CRC 不匹配")
	}
	segCount := int(binary.LittleEndian.Uint32(data[bsOffSegmentCount:]))
	gapCount := int(binary.LittleEndian.Uint32(data[bsOffGapCount:]))
	remaining := len(body) - int(backupSnapshotHeaderSize)
	// Bound each count before multiplying so a crafted count cannot overflow a
	// 32-bit int and make the size check pass. | 先限制计数再相乘，避免构造的计数
	// 在 32 位 int 上溢出并骗过长度校验。
	if segCount < 0 || gapCount < 0 || remaining < 0 ||
		segCount > remaining/backupSegmentEntrySize ||
		gapCount > (remaining-segCount*backupSegmentEntrySize)/backupGapEntrySize ||
		int(backupSnapshotHeaderSize)+segCount*backupSegmentEntrySize+gapCount*backupGapEntrySize != len(body) {
		return BackupSet{}, errs.Detail(ErrCorrupt, "backup snapshot section sizes do not match the file | 备份快照各段长度与文件不匹配")
	}
	flags := binary.LittleEndian.Uint16(data[bsOffFlags:])
	if flags&^metaKnownFlags != 0 {
		return BackupSet{}, errs.Detail(ErrCorrupt, "unknown backup snapshot flags 0x%[1]04x | 未知备份快照 flags 0x%[1]04x", flags)
	}
	set := BackupSet{
		CreatedNano:   int64(binary.LittleEndian.Uint64(data[bsOffCreatedNano:])),
		FirstLSN:      binary.LittleEndian.Uint64(data[bsOffFirstLSN:]),
		LastLSN:       binary.LittleEndian.Uint64(data[bsOffLastLSN:]),
		NextLSN:       binary.LittleEndian.Uint64(data[bsOffNextLSN:]),
		NextSeq:       binary.LittleEndian.Uint64(data[bsOffNextSeq:]),
		CommitSeq:     binary.LittleEndian.Uint64(data[bsOffCommitSeq:]),
		Encrypted:     flags&metaFlagEncrypted != 0,
		Serializable:  flags&metaFlagSerializable != 0,
		HashAlgorithm: HashAlgorithm((flags >> metaFlagHashShift) & metaFlagHashMask),
		ActiveKeyID:   binary.LittleEndian.Uint32(data[bsOffActiveKeyID:]),
		ActiveKeyKCV:  binary.LittleEndian.Uint64(data[bsOffActiveKCV:]),
	}
	copy(set.WalID[:], data[bsOffWalID:])
	off := int(backupSnapshotHeaderSize)
	set.Segments = make([]SegmentMeta, segCount)
	for i := 0; i < segCount; i++ {
		e := body[off : off+backupSegmentEntrySize]
		set.Segments[i] = SegmentMeta{
			Seq:         binary.LittleEndian.Uint64(e[0:]),
			BaseLSN:     binary.LittleEndian.Uint64(e[8:]),
			LastLSN:     binary.LittleEndian.Uint64(e[16:]),
			Records:     binary.LittleEndian.Uint64(e[24:]),
			Bytes:       binary.LittleEndian.Uint64(e[32:]),
			MinTime:     int64(binary.LittleEndian.Uint64(e[40:])),
			MaxTime:     int64(binary.LittleEndian.Uint64(e[48:])),
			SegmentCRC:  binary.LittleEndian.Uint32(e[56:]),
			IdxCRC:      binary.LittleEndian.Uint32(e[60:]),
			CommitSeq:   binary.LittleEndian.Uint64(e[64:]),
			CreatedNano: int64(binary.LittleEndian.Uint64(e[72:])),
			WalID:       set.WalID,
		}
		off += backupSegmentEntrySize
	}
	set.Gaps = make([]BackupGap, gapCount)
	for i := 0; i < gapCount; i++ {
		e := body[off : off+backupGapEntrySize]
		set.Gaps[i] = BackupGap{
			Start: binary.LittleEndian.Uint64(e[0:]),
			End:   binary.LittleEndian.Uint64(e[8:]),
		}
		off += backupGapEntrySize
	}
	if err := validateBackupSet(set); err != nil {
		return BackupSet{}, err
	}
	return set, nil
}

// captureBackupSet builds a consistent set at the current writer boundary. It
// runs on the writer goroutine and never calls user code. | captureBackupSet
// 在写入协程边界构建一致集合；运行于写协程，不调用用户代码。
func (w *WAL) captureBackupSet() *BackupSet {
	w.mu.RLock()
	defer w.mu.RUnlock()
	hash := HashSHA256
	if w.serializableDurable {
		hash = w.hashAlg
	}
	set := &BackupSet{
		WalID: w.walID, CreatedNano: w.createdNano, FirstLSN: w.firstLSN,
		Encrypted: w.encrypted, Serializable: w.serializableDurable,
		HashAlgorithm: hash, ActiveKeyID: w.activeKeyID, ActiveKeyKCV: w.activeKCV,
	}
	var maxSeq, maxLast uint64
	for _, seg := range w.segments {
		if seg.currentState() != segmentSealed || seg.size <= int64(segmentHeaderSize) {
			continue
		}
		seg.metaMu.RLock()
		m := SegmentMeta{
			Seq: seg.seq, BaseLSN: seg.baseLSN, LastLSN: seg.lastLSN, Records: seg.recordCount,
			Bytes: uint64(seg.size), MinTime: seg.minTime, MaxTime: seg.maxTime,
			SegmentCRC: seg.crc, IdxCRC: seg.idxCRC, CommitSeq: seg.commitSeq,
			CreatedNano: seg.createdNano, WalID: seg.walID,
		}
		seg.metaMu.RUnlock()
		set.Segments = append(set.Segments, m)
		if m.Seq > maxSeq {
			maxSeq = m.Seq
		}
		if m.LastLSN > maxLast {
			maxLast = m.LastLSN
		}
		if m.CommitSeq > set.CommitSeq {
			set.CommitSeq = m.CommitSeq
		}
	}
	sort.Slice(set.Segments, func(i, j int) bool { return set.Segments[i].Seq < set.Segments[j].Seq })
	if len(set.Segments) == 0 {
		set.LastLSN = set.FirstLSN - 1
		set.NextSeq = w.nextSeq
		if set.NextSeq == 0 {
			set.NextSeq = 1
		}
	} else {
		set.LastLSN = maxLast
		set.NextSeq = maxSeq + 1
	}
	set.NextLSN = set.LastLSN + 1
	for _, iv := range w.gaps.snapshot() {
		start, end := iv.Start, iv.End
		if start < set.FirstLSN {
			start = set.FirstLSN
		}
		if end > set.LastLSN {
			end = set.LastLSN
		}
		if start <= end {
			set.Gaps = append(set.Gaps, BackupGap{Start: start, End: end})
		}
	}
	return set
}
