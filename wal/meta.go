package wal

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"sort"

	"github.com/shibingli/ydx/errs"
)

// META layout constants. | META 布局常量。
const (
	metaMagic      = "YDXMETA1"
	metaVersion    = uint16(1)
	metaHeaderSize = uint32(128)
	metaSlotSize   = 128
	metaFileSize   = 256
	metaCRCOffset  = 124

	metaFlagEncrypted    = uint16(1 << 0)
	metaFlagSerializable = uint16(1 << 1)
	metaFlagHashShift    = 2
	metaFlagHashMask     = uint16(0x3)
	metaKnownFlags       = uint16(0x0F)
)

// META field offsets inside one 128-byte slot. | 单个 128 字节槽内的字段偏移。
const (
	metaOffMagic        = 0
	metaOffVersion      = 8
	metaOffFlags        = 10
	metaOffHeaderSize   = 12
	metaOffGeneration   = 16
	metaOffNextSeq      = 24
	metaOffNextLSN      = 32
	metaOffWalID        = 40
	metaOffActiveKeyID  = 56
	metaOffCreatedNano  = 60
	metaOffFirstLSN     = 68
	metaOffCommitSeq    = 76
	metaOffGapFloor     = 84
	metaOffActiveKeyKCV = 92
	metaOffReserved     = 100
)

// metaState is the complete META state. | metaState 是完整的 META 状态。
type metaState struct {
	generation   uint64
	nextSeq      uint64
	nextLSN      uint64
	createdNano  int64
	firstLSN     uint64
	commitSeq    uint64
	gapFloor     uint64
	activeKeyKCV uint64
	walID        [16]byte
	activeKeyID  uint32
	flags        uint16
}

// encrypted reports the WAL encryption policy. | encrypted 返回 WAL 加密策略。
func (m metaState) encrypted() bool { return m.flags&metaFlagEncrypted != 0 }

// serializable reports whether write-key digests are persisted. | serializable
// 返回是否持久化写键摘要。
func (m metaState) serializable() bool { return m.flags&metaFlagSerializable != 0 }

// hashAlgorithm returns the persisted write-key digest algorithm. | hashAlgorithm
// 返回持久化的写键摘要算法。
func (m metaState) hashAlgorithm() HashAlgorithm {
	return HashAlgorithm((m.flags >> metaFlagHashShift) & metaFlagHashMask)
}

// setHashAlgorithm stores the write-key digest algorithm in flags. | setHashAlgorithm
// 把写键摘要算法写入 flags。
func (m *metaState) setHashAlgorithm(h HashAlgorithm) {
	m.flags &^= metaFlagHashMask << metaFlagHashShift
	m.flags |= (uint16(h) & metaFlagHashMask) << metaFlagHashShift
}

// encodeMetaSlot encodes one slot and computes its CRC. | encodeMetaSlot 编码一个槽并计算 CRC。
func encodeMetaSlot(dst []byte, st metaState) {
	for i := range dst[:metaSlotSize] {
		dst[i] = 0
	}
	copy(dst[metaOffMagic:], metaMagic)
	binary.LittleEndian.PutUint16(dst[metaOffVersion:], metaVersion)
	binary.LittleEndian.PutUint16(dst[metaOffFlags:], st.flags)
	binary.LittleEndian.PutUint32(dst[metaOffHeaderSize:], metaHeaderSize)
	binary.LittleEndian.PutUint64(dst[metaOffGeneration:], st.generation)
	binary.LittleEndian.PutUint64(dst[metaOffNextSeq:], st.nextSeq)
	binary.LittleEndian.PutUint64(dst[metaOffNextLSN:], st.nextLSN)
	copy(dst[metaOffWalID:], st.walID[:])
	binary.LittleEndian.PutUint32(dst[metaOffActiveKeyID:], st.activeKeyID)
	binary.LittleEndian.PutUint64(dst[metaOffCreatedNano:], uint64(st.createdNano))
	binary.LittleEndian.PutUint64(dst[metaOffFirstLSN:], st.firstLSN)
	binary.LittleEndian.PutUint64(dst[metaOffCommitSeq:], st.commitSeq)
	binary.LittleEndian.PutUint64(dst[metaOffGapFloor:], st.gapFloor)
	binary.LittleEndian.PutUint64(dst[metaOffActiveKeyKCV:], st.activeKeyKCV)
	binary.LittleEndian.PutUint32(dst[metaCRCOffset:], checksum(dst[:metaCRCOffset]))
}

// decodeMetaSlot decodes one slot. A valid=false slot is torn or zero-filled
// and may be ignored; an error means the slot is structurally unsupported or
// corrupt. | decodeMetaSlot 解码一个槽。valid=false 表示槽是撕裂或全零，可忽略；
// 返回错误表示槽结构不受支持或已损坏。
func decodeMetaSlot(slot []byte) (metaState, bool, error) {
	if len(slot) < metaSlotSize {
		return metaState{}, false, nil
	}
	if bytes.Equal(slot[:metaSlotSize], make([]byte, metaSlotSize)) {
		return metaState{}, false, nil
	}
	if string(slot[metaOffMagic:metaOffMagic+8]) != metaMagic {
		return metaState{}, false, nil
	}
	version := binary.LittleEndian.Uint16(slot[metaOffVersion:])
	headerSize := binary.LittleEndian.Uint32(slot[metaOffHeaderSize:])
	if version != metaVersion || headerSize != metaHeaderSize {
		return metaState{}, false, errs.Detail(ErrUnsupported, "META version %[1]d header %[2]d | META 版本 %[1]d 头长度 %[2]d",
			version, headerSize)
	}
	if got, want := binary.LittleEndian.Uint32(slot[metaCRCOffset:]), checksum(slot[:metaCRCOffset]); got != want {
		return metaState{}, false, nil
	}
	var st metaState
	st.flags = binary.LittleEndian.Uint16(slot[metaOffFlags:])
	st.generation = binary.LittleEndian.Uint64(slot[metaOffGeneration:])
	st.nextSeq = binary.LittleEndian.Uint64(slot[metaOffNextSeq:])
	st.nextLSN = binary.LittleEndian.Uint64(slot[metaOffNextLSN:])
	copy(st.walID[:], slot[metaOffWalID:])
	st.activeKeyID = binary.LittleEndian.Uint32(slot[metaOffActiveKeyID:])
	st.createdNano = int64(binary.LittleEndian.Uint64(slot[metaOffCreatedNano:]))
	st.firstLSN = binary.LittleEndian.Uint64(slot[metaOffFirstLSN:])
	st.commitSeq = binary.LittleEndian.Uint64(slot[metaOffCommitSeq:])
	st.gapFloor = binary.LittleEndian.Uint64(slot[metaOffGapFloor:])
	st.activeKeyKCV = binary.LittleEndian.Uint64(slot[metaOffActiveKeyKCV:])
	if st.flags&^metaKnownFlags != 0 {
		return metaState{}, false, errs.Detail(ErrUnsupported, "unknown META flags 0x%[1]04x | 未知 META flags 0x%[1]04x", st.flags)
	}
	hashAlg := (st.flags >> metaFlagHashShift) & metaFlagHashMask
	if st.flags&metaFlagSerializable == 0 && hashAlg != 0 {
		return metaState{}, false, errs.Detail(ErrCorrupt, "META hash algorithm set without serializable durability | META 未启用可串行化持久化却设置了哈希算法")
	}
	if hashAlg > uint16(HashSM3) {
		return metaState{}, false, errs.Detail(ErrCorrupt, "unknown META hash algorithm %[1]d | 未知 META 哈希算法 %[1]d", hashAlg)
	}
	if (st.flags&metaFlagEncrypted != 0) != (st.activeKeyID != 0) {
		return metaState{}, false, errs.Detail(ErrCipherMismatch, "META encryption flag and activeKeyID disagree | META 加密标志与 activeKeyID 不一致")
	}
	if st.generation == 0 || st.nextSeq == 0 || st.firstLSN == 0 {
		return metaState{}, false, errs.Detail(ErrCorrupt, "META has zero generation/nextSeq/firstLSN | META 的 generation/nextSeq/firstLSN 为零")
	}
	if st.nextLSN < st.firstLSN {
		return metaState{}, false, errs.Detail(ErrCorrupt, "META nextLSN %[1]d is below firstLSN %[2]d | META nextLSN %[1]d 小于 firstLSN %[2]d",
			st.nextLSN, st.firstLSN)
	}
	if st.walID == ([16]byte{}) {
		return metaState{}, false, errs.Detail(ErrCorrupt, "META walID is zero | META walID 为零")
	}
	return st, true, nil
}

// metaSlotRecord is one valid slot found during Open. | metaSlotRecord 是 Open 期间发现的一个有效槽。
type metaSlotRecord struct {
	state metaState
	raw   [metaSlotSize]byte
	file  int
	slot  int
}

// metaFile is one of META or META.mirror. | metaFile 是 META 或 META.mirror 之一。
type metaFile struct {
	path     string
	f        *os.File
	exists   bool
	hasValid bool
	current  int
	state    metaState
}

// metaStore owns the two mirrored META files. It is written by exactly one
// goroutine at a time. | metaStore 管理两个镜像 META 文件；同一时刻只有一个协程写入。
type metaStore struct {
	dir      string
	files    [2]*metaFile
	state    metaState
	hasState bool
	fileMode os.FileMode
}

// openMetaStore reads both META files and selects the newest valid generation. | openMetaStore
// 读取两个 META 文件并选择最新的有效代。
func openMetaStore(dir string, fileMode os.FileMode) (*metaStore, error) {
	s := &metaStore{
		dir:      dir,
		fileMode: fileMode,
		files: [2]*metaFile{
			{path: filepath.Join(dir, "META")},
			{path: filepath.Join(dir, "META.mirror")},
		},
	}
	var records []metaSlotRecord
	for i, mf := range s.files {
		data, err := os.ReadFile(mf.path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, errs.WrapDetail(err, ErrStorage, "read %s | 读取 %s 失败", mf.path, mf.path)
		}
		mf.exists = true
		if len(data) > metaFileSize {
			return nil, errs.Detail(ErrCorrupt, "%[1]s has %[2]d bytes, want at most %[3]d | %[1]s 有 %[2]d 字节，最多 %[3]d",
				mf.path, len(data), metaFileSize)
		}
		var localBest *metaSlotRecord
		for slot := 0; slot < 2; slot++ {
			off := slot * metaSlotSize
			if off+metaSlotSize > len(data) {
				continue
			}
			state, valid, err := decodeMetaSlot(data[off : off+metaSlotSize])
			if err != nil {
				return nil, err
			}
			if !valid {
				continue
			}
			rec := metaSlotRecord{state: state, file: i, slot: slot}
			copy(rec.raw[:], data[off:off+metaSlotSize])
			records = append(records, rec)
			if localBest == nil || state.generation > localBest.state.generation {
				c := rec
				localBest = &c
			}
		}
		if localBest != nil {
			mf.hasValid = true
			mf.current = localBest.slot
			mf.state = localBest.state
		}
	}
	if len(records) == 0 {
		return s, nil
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].state.generation != records[j].state.generation {
			return records[i].state.generation > records[j].state.generation
		}
		if records[i].file != records[j].file {
			return records[i].file < records[j].file
		}
		return records[i].slot < records[j].slot
	})
	top := records[0]
	for i := 0; i < len(records); {
		j := i + 1
		for j < len(records) && records[j].state.generation == records[i].state.generation {
			j++
		}
		for k := i + 1; k < j; k++ {
			if !bytes.Equal(records[k].raw[:], records[i].raw[:]) {
				return nil, errs.Detail(ErrCorrupt, "META slots at generation %[1]d differ | generation %[1]d 的 META 槽内容不一致",
					records[i].state.generation)
			}
		}
		i = j
	}
	for i := 1; i < len(records); i++ {
		if records[i].state.generation < top.state.generation {
			if err := checkMetaTransition(top.state, records[i].state); err != nil {
				return nil, err
			}
			break
		}
	}
	s.state = top.state
	s.hasState = true
	return s, nil
}

// checkMetaTransition rejects generation/high-water rollback. | checkMetaTransition
// 拒绝代次/高水位回退。
func checkMetaTransition(newer, older metaState) error {
	if newer.walID != older.walID {
		return errs.Detail(ErrCorrupt, "META walID changed across generations | META walID 跨代改变")
	}
	if newer.flags != older.flags {
		enableSerializable := older.flags&metaFlagSerializable == 0 && newer.flags&metaFlagSerializable != 0
		enableEncryption := older.flags&metaFlagEncrypted == 0 && newer.flags&metaFlagEncrypted != 0
		empty := newer.nextLSN == older.nextLSN && newer.firstLSN == older.firstLSN && newer.commitSeq == older.commitSeq
		if (!enableSerializable && !enableEncryption) || !empty {
			return errs.Detail(ErrCorrupt, "META flags changed across generations | META flags 跨代改变")
		}
	}
	if newer.nextSeq < older.nextSeq || newer.nextLSN < older.nextLSN ||
		newer.firstLSN < older.firstLSN || newer.commitSeq < older.commitSeq ||
		newer.gapFloor < older.gapFloor {
		return errs.Detail(ErrCorrupt, "META high-water mark rolled back | META 高水位回退")
	}
	return nil
}

// write persists st with a new generation. | write 以新 generation 持久化 st。
func (s *metaStore) write(st metaState) error {
	if s.hasState {
		if err := checkMetaTransition(st, s.state); err != nil {
			return err
		}
		if st.generation <= s.state.generation {
			st.generation = s.state.generation + 1
		}
	} else if st.generation == 0 {
		st.generation = 1
	}
	if st.walID == ([16]byte{}) {
		return errs.Detail(ErrCorrupt, "refusing to persist zero walID | 拒绝持久化全零 walID")
	}
	var slot [metaSlotSize]byte
	encodeMetaSlot(slot[:], st)
	var firstErr error
	committed := false
	for _, mf := range s.files {
		var err error
		if mf.hasValid {
			err = s.writeSlot(mf, slot[:])
		} else {
			err = s.createMetaFile(mf, slot[:])
		}
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		mf.hasValid = true
		mf.state = st
		if !committed {
			s.state = st
			s.hasState = true
			committed = true
		}
	}
	return firstErr
}

// writeSlot writes one slot in place and synchronizes the file. | writeSlot 原位写入一个槽并同步文件。
func (s *metaStore) writeSlot(mf *metaFile, slot []byte) error {
	if mf.f == nil {
		f, err := os.OpenFile(mf.path, os.O_RDWR, s.fileMode)
		if err != nil {
			return errs.WrapDetail(err, ErrStorage, "open %s | 打开 %s 失败", mf.path, mf.path)
		}
		mf.f = f
	}
	target := 1 - mf.current
	if _, err := mf.f.WriteAt(slot, int64(target*metaSlotSize)); err != nil {
		return errs.WrapDetail(err, ErrStorage, "write %s slot %d | 写入 %s 槽 %d 失败", mf.path, target, mf.path, target)
	}
	if err := mf.f.Sync(); err != nil {
		return errs.WrapDetail(err, ErrStorage, "sync %s | 同步 %s 失败", mf.path, mf.path)
	}
	mf.current = target
	return nil
}

// createMetaFile atomically creates a missing or slot-less META file. | createMetaFile
// 原子创建缺失或无有效槽的 META 文件。
func (s *metaStore) createMetaFile(mf *metaFile, slot []byte) error {
	var buf [metaFileSize]byte
	copy(buf[:metaSlotSize], slot)
	if err := writeFileAtomic(mf.path, buf[:], s.fileMode); err != nil {
		return err
	}
	mf.exists = true
	mf.current = 0
	if mf.f != nil {
		_ = mf.f.Close()
		mf.f = nil
	}
	f, err := os.OpenFile(mf.path, os.O_RDWR, s.fileMode)
	if err != nil {
		return errs.WrapDetail(err, ErrStorage, "open %s | 打开 %s 失败", mf.path, mf.path)
	}
	mf.f = f
	return nil
}

// close releases the META file handles. | close 释放 META 文件句柄。
func (s *metaStore) close() error {
	var first error
	for _, mf := range s.files {
		if mf.f != nil {
			if err := mf.f.Close(); err != nil && first == nil {
				first = err
			}
			mf.f = nil
		}
	}
	return first
}
