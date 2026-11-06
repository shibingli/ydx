package wal

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
)

// scanOutcome is the result of scanning one segment. | scanOutcome 是一个分段的扫描结果。
type scanOutcome struct {
	lastLSN      uint64
	recordCount  uint64
	size         int64
	minTime      int64
	maxTime      int64
	crc          uint32
	commitSeq    uint64
	lastKeyID    uint32
	verifiedEnd  int64
	truncateTo   int64
	truncated    bool
	corrupt      bool
	sawPlain     bool
	sawEncrypted bool
	sparse       []sparseEntry
	offsets      []uint64
	keyIndex     map[string][]uint64
}

// txnPending tracks an open transaction block inside a scan. | txnPending 跟踪扫描中的未闭合事务块。
type txnPending struct {
	active   bool
	txnID    uint64
	first    uint64
	last     uint64
	count    uint64
	bytes    uint64
	startOff int64
}

// recover restores the WAL state. | recover 恢复 WAL 状态。
func (w *WAL) recover() error {
	if !w.opts.readOnly {
		if err := cleanTempFiles(w.dir); err != nil {
			return err
		}
	}
	meta, err := openMetaStore(w.dir, w.opts.fileMode)
	if err != nil {
		return err
	}
	w.meta = meta
	man, manExists, manCorrupt, err := openManifest(w.dir, w.opts.manifestEnabled, w.opts.manifestShardRecords,
		w.opts.manifestCompactRatio, w.opts.fileMode)
	if err != nil {
		return err
	}
	w.manifest = man

	metaValid := meta.hasState
	state := meta.state
	usedDirScan := false
	var segs map[uint64]*segment
	var retired map[uint64]bool
	var maxSeq, maxCreatedSeq uint64
	var manRetired map[uint64]bool
	var manSegs map[uint64]*segment
	var manMaxSeq, manMaxCreated uint64

	if w.opts.manifestEnabled && manExists && !manCorrupt {
		data := man.snapshot()
		segs = data.segments
		retired = data.retired
		maxSeq = data.maxSeq
		maxCreatedSeq = data.maxCreatedSeq
		manRetired = data.retired
		manSegs = data.segments
		manMaxSeq = data.maxSeq
		manMaxCreated = data.maxCreatedSeq
		if !metaValid {
			if data.firstLSN > state.firstLSN {
				state.firstLSN = data.firstLSN
			}
			if data.commitSeq > state.commitSeq {
				state.commitSeq = data.commitSeq
			}
			if data.walIDSet {
				state.walID = data.walID
			}
		}
		// Validate the fast path; any inconsistency falls back to a full readdir. | 校验快速路径；任何不一致回退全目录扫描。
		if metaValid {
			if data.walIDSet && data.walID != state.walID {
				return errs.Detail(ErrCorrupt, "MANIFEST walID does not match META | MANIFEST walID 与 META 不一致")
			}
			if data.firstLSN > state.firstLSN {
				state.firstLSN = data.firstLSN
			}
			if data.commitSeq > state.commitSeq {
				state.commitSeq = data.commitSeq
			}
		} else if data.walIDSet {
			state.walID = data.walID
		}
		needScan := false
		for seq, seg := range segs {
			if retired[seq] {
				continue
			}
			info, err := os.Stat(seg.path)
			if err != nil {
				needScan = true
				break
			}
			if seg.currentState() == segmentSealed && seg.size != info.Size() {
				needScan = true
				break
			}
		}
		if !needScan && hasSequenceGap(segs, retired) {
			needScan = true
		}
		if needScan {
			usedDirScan = true
		}
	} else {
		usedDirScan = true
	}
	if usedDirScan {
		dirSegs, dirRetired, dirMax, dirCreated, err := w.scanDirectory()
		if err != nil {
			return err
		}
		segs = dirSegs
		retired = dirRetired
		maxSeq = dirMax
		maxCreatedSeq = dirCreated
		// Preserve manifest retirement and high-water evidence. | 保留 MANIFEST 的退休与高水位证据。
		for seq := range manRetired {
			retired[seq] = true
		}
		maxSeq = maxU64(maxSeq, manMaxSeq)
		maxCreatedSeq = maxU64(maxCreatedSeq, manMaxCreated)
		if w.opts.manifestEnabled && manCorrupt {
			// Rebuild below. | 下方重建。
		}
	}
	if segs == nil {
		segs = make(map[uint64]*segment)
	}
	if retired == nil {
		retired = make(map[uint64]bool)
	}
	// Probe META.nextSeq and nextSeq-1; manifest entries can lag file creation. | 探测 META.nextSeq 与 nextSeq-1；MANIFEST 可能滞后于建段。
	if metaValid {
		for _, seq := range []uint64{state.nextSeq, state.nextSeq - 1} {
			if seq == 0 {
				continue
			}
			if _, ok := segs[seq]; ok {
				continue
			}
			path := segmentPath(w.dir, seq)
			info, err := os.Stat(path)
			if err != nil {
				continue
			}
			seg, err := w.summaryFromFile(seq, info.Size())
			if err != nil {
				return err
			}
			segs[seq] = seg
			if seq > maxSeq {
				maxSeq = seq
			}
		}
	}
	// Determine the WAL ID and first LSN. | 确定 WAL ID 与 firstLSN。
	walID := state.walID
	walIDSet := metaValid
	if !walIDSet {
		if state.walID != ([16]byte{}) {
			walID = state.walID
			walIDSet = true
		}
	}
	if !walIDSet && len(segs) > 0 {
		seqs := sortedSeqs(segs)
		h, _, err := readSegmentHeaderFile(segs[seqs[0]].path)
		if err != nil {
			return errs.WrapDetail(err, ErrCorrupt, "read first segment header | 读取首个分段头失败")
		}
		walID = h.walID
		walIDSet = true
		if state.firstLSN == 0 {
			state.firstLSN = h.baseLSN
		}
	}
	if !walIDSet {
		var err error
		walID, err = randomWALID()
		if err != nil {
			return err
		}
	}
	if state.firstLSN == 0 {
		state.firstLSN = 1
	}
	// Bind keys and publish the WAL ID before scanning encrypted controls. | 在扫描加密控制记录前绑定密钥并发布 WAL ID。
	w.walID = walID
	if w.opts.keyRing != nil && w.bound == nil {
		bound, err := w.opts.keyRing.bind(walID)
		if err != nil {
			return err
		}
		w.bound = bound
	}
	// Validate every discovered header and apply retirement. | 校验每个分段头并应用退休。
	for seq, seg := range segs {
		if seg.missing {
			continue
		}
		h, _, err := readSegmentHeaderFile(seg.path)
		if err != nil {
			if os.IsNotExist(err) {
				seg.missing = true
				continue
			}
			return errs.WrapDetail(err, ErrCorrupt, "read segment %d header | 读取分段 %d 头失败", seq, seq)
		}
		if h.seq != seq || h.walID != walID {
			return errs.Detail(ErrCorrupt, "segment %d header identity mismatch | 分段 %d 段头身份不匹配", seq, seq)
		}
		if seg.baseLSN == 0 {
			seg.baseLSN = h.baseLSN
		}
	}
	// Tail and highest-created-sequence gaps. | 尾部与最高创建序号缺口。
	maxFileSeq := uint64(0)
	for seq := range segs {
		if seq > maxFileSeq {
			maxFileSeq = seq
		}
	}
	if maxCreatedSeq > maxFileSeq && !retired[maxCreatedSeq] {
		var evidence *segment
		if manSegs != nil {
			evidence = manSegs[maxCreatedSeq]
		}
		if evidence != nil && evidence.lastLSN >= evidence.baseLSN && w.opts.allowLSNGaps {
			state.nextLSN = maxU64(state.nextLSN, evidence.lastLSN+1)
		} else {
			return errs.Detail(ErrMissingSegment, "highest created segment %[1]d is missing | 最高创建分段 %[1]d 缺失", maxCreatedSeq)
		}
	}
	if state.nextSeq > 0 && maxSeq > 0 && state.nextSeq > maxSeq+1 {
		return errs.Detail(ErrMissingSegment, "META.nextSeq %[1]d exceeds known segments %[2]d | META.nextSeq %[1]d 超出已知分段 %[2]d", state.nextSeq, maxSeq)
	}
	// Zero-segment rebuild gate. | 零段重建门禁。
	if len(segs) == 0 {
		if !metaValid {
			switch {
			case w.opts.manifestEnabled && manExists:
				if maxCreatedSeq > 0 && !retired[maxCreatedSeq] {
					return errs.Detail(ErrMissingSegment, "highest created segment %[1]d has no retirement record | 最高创建分段 %[1]d 没有退休记录", maxCreatedSeq)
				}
				if state.firstLSN == 0 {
					state.firstLSN = 1
				}
				if state.nextLSN == 0 {
					state.nextLSN = state.firstLSN
				}
				if state.nextSeq == 0 {
					state.nextSeq = maxCreatedSeq + 1
				}
				if state.walID == ([16]byte{}) {
					state.walID = walID
				}
			case w.opts.manifestEnabled:
				if _, err := os.Stat(filepath.Join(w.dir, "manifest")); err == nil {
					return errs.Detail(ErrCorrupt, "manifest directory exists without valid records | MANIFEST 目录存在但没有有效记录")
				}
				state.firstLSN, state.nextLSN, state.nextSeq = 1, 1, 1
				state.commitSeq = 0
				state.walID = walID
			default:
				state.firstLSN, state.nextLSN, state.nextSeq = 1, 1, 1
				state.commitSeq = 0
				state.walID = walID
			}
		} else if state.firstLSN < state.nextLSN {
			return errs.Detail(ErrMissingSegment, "META expects records but no segment exists | META 期望记录但不存在任何分段")
		}
	}

	// Retire logically truncated segments. | 退休逻辑上已截断的分段。
	firstLSN := state.firstLSN
	if firstLSN == 0 {
		firstLSN = 1
	}
	seqs := sortedSeqs(segs)
	for _, seq := range seqs {
		seg := segs[seq]
		seg.metaMu.RLock()
		last := seg.lastLSN
		seg.metaMu.RUnlock()
		if seg.missing {
			if retired[seq] {
				delete(segs, seq)
				continue
			}
			continue
		}
		if last != 0 && last < firstLSN && !(seg.size <= int64(segmentHeaderSize) && seg.baseLSN == firstLSN) {
			retired[seq] = true
			if !w.opts.readOnly && w.manifest.enabled {
				if err := w.manifest.append(manifestRecord{kind: manifestKindRetire, seq: seq, walID: walID}); err != nil {
					return err
				}
			}
			if !w.opts.readOnly {
				_ = os.Remove(seg.path)
				_ = removeIfExists(seg.idxPath)
				_ = removeIfExists(seg.bakPath)
			}
			delete(segs, seq)
		}
	}
	seqs = sortedSeqs(segs)
	// Scan non-last segments that lack a complete summary. | 扫描缺少完整摘要的非最后分段。
	for i := 0; i+1 < len(seqs); i++ {
		seq := seqs[i]
		seg := segs[seq]
		if retired[seq] || seg.missing {
			continue
		}
		if seg.currentState() == segmentSealed && seg.recordCount >= 0 && seg.size > int64(segmentHeaderSize) {
			// A manifest kind=1 or a full sidecar already supplied a summary. | MANIFEST kind=1 或完整侧车已提供摘要。
			if seg.lastLSN != 0 || seg.baseLSN == seg.lastLSN+1 {
				continue
			}
		}
		info, statErr := os.Stat(seg.path)
		if statErr != nil {
			return errs.WrapDetail(statErr, ErrStorage, "stat segment %d | 检查分段 %d 失败", seq, seq)
		}
		f, err := os.Open(seg.path)
		if err != nil {
			return errs.WrapDetail(err, ErrStorage, "open segment %d | 打开分段 %d 失败", seq, seq)
		}
		out, err := w.scanSegment(seg, f, int64(segmentHeaderSize), info.Size(), seg.baseLSN-1, 0, 0, 0, 0, false)
		_ = f.Close()
		if err != nil {
			return err
		}
		w.applyScan(seg, out, false)
		seg.setState(segmentSealed)
	}
	// Open and validate the last segment. | 打开并校验最后一段。
	var lastKeyID uint32
	var active *segment
	if len(seqs) > 0 {
		lastSeq := seqs[len(seqs)-1]
		last := segs[lastSeq]
		if last.missing {
			if retired[lastSeq] {
				delete(segs, lastSeq)
			} else {
				return errs.Detail(ErrMissingSegment, "last segment %[1]d is missing | 最后分段 %[1]d 缺失", lastSeq)
			}
		} else {
			var err error
			active, lastKeyID, state.commitSeq, state.firstLSN, err = w.openLastSegment(last, state, walID, firstLSN, metaValid)
			if err != nil {
				return err
			}
			firstLSN = state.firstLSN
		}
	}
	// Rebuild the final segment list and validate continuity. | 重建最终分段列表并校验连续性。
	seqs = sortedSeqs(segs)
	live := make([]*segment, 0, len(seqs))
	for _, seq := range seqs {
		seg := segs[seq]
		if retired[seq] || seg.missing {
			continue
		}
		live = append(live, seg)
	}
	sort.Slice(live, func(i, j int) bool { return live[i].seq < live[j].seq })
	live, err = w.validateContinuity(live, &firstLSN, &state)
	if err != nil {
		return err
	}
	state.firstLSN = firstLSN
	// Determine nextLSN/nextSeq/commitSeq. | 确定 nextLSN/nextSeq/commitSeq。
	observedNext := firstLSN
	highestLast := uint64(0)
	for _, seg := range live {
		seg.metaMu.RLock()
		last, recordCount, size, minTime, maxTime, crc, idxCRC, commitSeq :=
			seg.lastLSN, seg.recordCount, seg.size, seg.minTime, seg.maxTime, seg.crc, seg.idxCRC, seg.commitSeq
		base := seg.baseLSN
		seg.metaMu.RUnlock()
		if last+1 > observedNext {
			observedNext = last + 1
		}
		if base > observedNext {
			observedNext = base
		}
		if last > highestLast {
			highestLast = last
		}
		if commitSeq > state.commitSeq {
			state.commitSeq = commitSeq
		}
		_ = recordCount
		_ = size
		_ = minTime
		_ = maxTime
		_ = crc
		_ = idxCRC
	}
	if w.active != nil {
		w.active.metaMu.RLock()
		if w.active.baseLSN > observedNext {
			observedNext = w.active.baseLSN
		}
		w.active.metaMu.RUnlock()
	}
	if metaValid && state.nextLSN > observedNext {
		if len(live) != 0 || state.firstLSN != state.nextLSN {
			return errs.Detail(ErrCorrupt, "META.nextLSN %[1]d is ahead of recovered records %[2]d | META.nextLSN %[1]d 超前于已恢复记录 %[2]d",
				state.nextLSN, observedNext)
		}
	}
	state.nextLSN = maxU64(state.nextLSN, observedNext)
	state.nextLSN = maxU64(state.nextLSN, state.firstLSN)
	if maxSeq == 0 {
		for _, seg := range live {
			if seg.seq > maxSeq {
				maxSeq = seg.seq
			}
		}
	}
	state.nextSeq = maxU64(state.nextSeq, maxSeq+1)
	if state.nextSeq == 0 {
		state.nextSeq = 1
	}
	if state.nextSeq < 1 {
		state.nextSeq = 1
	}
	// Resolve encryption and serializable durability. | 解析加密与可串行化持久化。
	if err := w.resolveEncryption(state, metaValid, walID, lastKeyID, live); err != nil {
		return err
	}
	if err := w.resolveSerializable(state, metaValid, live, highestLast); err != nil {
		return err
	}
	// Publish the state. | 发布状态。
	w.walID = walID
	w.createdNano = state.createdNano
	if w.createdNano == 0 {
		w.createdNano = time.Now().UnixNano()
	}
	w.firstLSN = state.firstLSN
	w.firstLSNAtomic.Store(state.firstLSN)
	w.nextLSN = state.nextLSN
	w.nextSeq = state.nextSeq
	w.commitSeq = state.commitSeq
	w.gapFloor = state.gapFloor
	w.segments = live
	w.segBySeq = make(map[uint64]*segment, len(live))
	for _, seg := range live {
		w.segBySeq[seg.seq] = seg
	}
	w.active = active
	lastCommitted := uint64(0)
	if highestLast > 0 {
		lastCommitted = highestLast
	} else if w.firstLSN > 0 {
		lastCommitted = w.firstLSN - 1
	}
	w.publishSnapshot(w.commitSeq, lastCommitted)
	if len(live) > 0 {
		last := live[len(live)-1]
		last.metaMu.RLock()
		w.lastTimestamp = last.maxTime
		last.metaMu.RUnlock()
	}
	// Rewrite the manifest when the fast path was unusable. | 快速路径不可用时重建 MANIFEST。
	if !w.opts.readOnly && w.manifest.enabled && (usedDirScan || manCorrupt || !manExists) {
		data := buildManifestData(live, retired, firstLSN, state.commitSeq, walID)
		if err := w.manifest.rewrite(data); err != nil {
			return err
		}
	}
	return nil
}

// cleanTempFiles removes interrupted atomic-write files. | cleanTempFiles 清理中断的原子写临时文件。
func cleanTempFiles(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".tmp") {
			continue
		}
		_ = os.Remove(filepath.Join(dir, e.Name()))
	}
	manifestDir := filepath.Join(dir, "manifest")
	if entries, err := os.ReadDir(manifestDir); err == nil {
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".tmp") {
				continue
			}
			_ = os.Remove(filepath.Join(manifestDir, e.Name()))
		}
	}
	return nil
}

// scanDirectory rebuilds segment summaries by reading the directory. | scanDirectory
// 通过读取目录重建分段摘要。
func (w *WAL) scanDirectory() (map[uint64]*segment, map[uint64]bool, uint64, uint64, error) {
	segs := make(map[uint64]*segment)
	retired := make(map[uint64]bool)
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return nil, nil, 0, 0, errs.WrapDetail(err, ErrStorage, "read directory | 读取目录失败")
	}
	var maxSeq uint64
	for _, e := range entries {
		seq, ok := parseSequence(e.Name(), ".wal")
		if !ok {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		seg, err := w.summaryFromFile(seq, info.Size())
		if err != nil {
			return nil, nil, 0, 0, err
		}
		segs[seq] = seg
		if seq > maxSeq {
			maxSeq = seq
		}
	}
	return segs, retired, maxSeq, maxSeq, nil
}

// summaryFromFile builds a summary from a .wal file, preferring its sidecar. | summaryFromFile
// 优先使用侧车从 .wal 文件构建摘要。
func (w *WAL) summaryFromFile(seq uint64, size int64) (*segment, error) {
	path := segmentPath(w.dir, seq)
	h, _, err := readSegmentHeaderFile(path)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrCorrupt, "read segment %d | 读取分段 %d 失败", seq, seq)
	}
	seg := newSegmentSummary(seq, h.baseLSN, h.baseLSN-1, size, h.walID, w.dir)
	seg.createdNano = h.createdNano
	if sc, err := loadSidecar(seg.idxPath); err == nil && sc.seq == seq && sc.baseLSN == h.baseLSN && sc.walID == h.walID {
		if !sc.checkpoint && sc.segmentBytes == uint64(size) {
			seg.lastLSN = sc.lastLSN
			seg.recordCount = sc.recordCount
			seg.minTime = sc.minTime
			seg.maxTime = sc.maxTime
			seg.crc = sc.segmentCRC
			seg.commitSeq = sc.commitSeq
			seg.setState(segmentSealed)
		}
	}
	return seg, nil
}

// openLastSegment validates, scans, and seals or reuses the last segment. | openLastSegment
// 校验、扫描并封存或复用最后分段。
func (w *WAL) openLastSegment(seg *segment, state metaState, walID [16]byte, firstLSN uint64, metaValid bool) (*segment, uint32, uint64, uint64, error) {
	f, err := os.OpenFile(seg.path, os.O_RDWR, w.opts.fileMode)
	if err != nil {
		return nil, 0, state.commitSeq, state.firstLSN, errs.WrapDetail(err, ErrStorage, "open last segment | 打开最后分段失败")
	}
	stat, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, state.commitSeq, state.firstLSN, err
	}
	fileSize := stat.Size()
	// An incomplete header is a segment that crashed during creation. | 不完整段头是创建期崩溃的分段。
	if fileSize < int64(segmentHeaderSize) {
		_ = f.Close()
		seg.missing = true
		if w.opts.readOnly {
			return nil, 0, state.commitSeq, state.firstLSN, nil
		}
		if w.manifest.enabled {
			if err := w.manifest.append(manifestRecord{kind: manifestKindRetire, seq: seg.seq, walID: walID}); err != nil {
				return nil, 0, state.commitSeq, state.firstLSN, err
			}
		}
		_ = os.Remove(seg.path)
		return nil, 0, state.commitSeq, state.firstLSN, nil
	}
	// Reuse the already-open handle instead of opening the path again. | 复用已打开的
	// 句柄，避免再按路径打开一次。
	var hdrBuf [segmentHeaderSize]byte
	if err := readFullAt(f, hdrBuf[:], 0); err != nil {
		_ = f.Close()
		return nil, 0, state.commitSeq, state.firstLSN, err
	}
	h, err := decodeSegmentHeader(hdrBuf[:])
	if err != nil {
		_ = f.Close()
		return nil, 0, state.commitSeq, state.firstLSN, err
	}
	if h.walID != walID || h.seq != seg.seq {
		_ = f.Close()
		return nil, 0, state.commitSeq, state.firstLSN, errs.Detail(ErrCorrupt, "last segment header mismatch | 最后分段段头不匹配")
	}
	start := int64(segmentHeaderSize)
	baseLast := seg.baseLSN - 1
	baseCount := uint64(0)
	baseCRC := uint32(0)
	baseMin, baseMax := int64(0), int64(0)
	trusted := false
	// Use the MANIFEST summary as a trusted full description or a checkpoint prefix
	// when the sidecar is missing. | 侧车缺失时使用 MANIFEST 摘要作为完整描述或检查点前缀。
	if metaValid {
		if seg.size > fileSize && seg.size > int64(segmentHeaderSize) {
			_ = f.Close()
			return nil, 0, state.commitSeq, state.firstLSN, errs.Detail(ErrCorrupt, "MANIFEST segmentBytes exceeds the file | MANIFEST segmentBytes 超过文件大小")
		}
		if seg.currentState() == segmentSealed && seg.size == fileSize {
			_ = f.Close()
			if !w.opts.readOnly {
				w.enqueueBackup(seg)
			}
			return nil, 0, seg.commitSeq, state.firstLSN, nil
		}
		if seg.size > int64(segmentHeaderSize) && seg.size < fileSize {
			start = seg.size
			baseLast = seg.lastLSN
			baseCount = seg.recordCount
			baseCRC = seg.crc
			baseMin, baseMax = seg.minTime, seg.maxTime
			trusted = true
		}
	}
	if sc, err := loadSidecar(seg.idxPath); err == nil && metaValid && sc.seq == seg.seq && sc.baseLSN == h.baseLSN && sc.walID == walID {
		if sc.segmentBytes > uint64(fileSize) {
			_ = f.Close()
			return nil, 0, state.commitSeq, state.firstLSN, errs.Detail(ErrCorrupt, "checkpoint sidecar exceeds segment size | 检查点侧车超过分段大小")
		}
		if !sc.checkpoint && sc.segmentBytes == uint64(fileSize) {
			seg.metaMu.Lock()
			seg.lastLSN = sc.lastLSN
			seg.recordCount = sc.recordCount
			seg.size = fileSize
			seg.minTime = sc.minTime
			seg.maxTime = sc.maxTime
			seg.crc = sc.segmentCRC
			seg.commitSeq = sc.commitSeq
			seg.metaMu.Unlock()
			seg.setState(segmentSealed)
			_ = f.Close()
			if !w.opts.readOnly {
				w.enqueueBackup(seg)
			}
			return nil, 0, sc.commitSeq, state.firstLSN, nil
		}
		start = int64(sc.segmentBytes)
		baseLast = sc.lastLSN
		baseCount = sc.recordCount
		baseCRC = sc.segmentCRC
		baseMin, baseMax = sc.minTime, sc.maxTime
		trusted = true
	}
	out, err := w.scanSegment(seg, f, start, fileSize, baseLast, baseCount, baseCRC, baseMin, baseMax, true)
	if err != nil {
		_ = f.Close()
		return nil, 0, state.commitSeq, state.firstLSN, err
	}
	if !trusted && out.verifiedEnd < int64(segmentHeaderSize) {
		out.truncateTo = int64(segmentHeaderSize)
	}
	if metaValid {
		if state.encrypted() && out.sawPlain {
			_ = f.Close()
			return nil, 0, state.commitSeq, state.firstLSN, errs.Detail(ErrCipherMismatch, "plaintext record in encrypted WAL | 加密 WAL 中出现明文记录")
		}
		if !state.encrypted() && out.sawEncrypted {
			_ = f.Close()
			return nil, 0, state.commitSeq, state.firstLSN, errs.Detail(ErrCipherMismatch, "encrypted record in plaintext WAL | 明文 WAL 中出现加密记录")
		}
	} else if out.sawPlain && out.sawEncrypted {
		_ = f.Close()
		return nil, 0, state.commitSeq, state.firstLSN, errs.Detail(ErrCipherMismatch, "WAL mixes plaintext and encrypted records | WAL 混用明文与加密记录")
	}
	w.applyScan(seg, out, true)
	if out.truncated {
		if !w.opts.readOnly {
			// Invalidate the sidecar before truncating; otherwise a crash in between
			// leaves segmentBytes > fileSize and makes the WAL unopenable. | 先失效侧车
			// 再截断；否则中途崩溃会留下 segmentBytes > fileSize 使 WAL 无法打开。
			if trusted {
				_ = removeIfExists(seg.idxPath)
				_ = syncDir(w.dir)
			}
			if err := f.Truncate(out.truncateTo); err != nil {
				_ = f.Close()
				return nil, 0, state.commitSeq, state.firstLSN, wrapStorage("truncate segment", err)
			}
			if err := f.Sync(); err != nil {
				_ = f.Close()
				return nil, 0, state.commitSeq, state.firstLSN, wrapStorage("sync truncated segment", err)
			}
		}
		w.counters.recTruncated.Add(fileSize - out.truncateTo)
	}
	empty := out.lastLSN == seg.baseLSN-1 && out.recordCount == 0 && out.truncateTo <= int64(segmentHeaderSize)
	if empty {
		emptyBase := maxU64(seg.baseLSN, state.nextLSN)
		if emptyBase < firstLSN {
			emptyBase = firstLSN
		}
		if emptyBase < seg.baseLSN {
			emptyBase = seg.baseLSN
		}
		seg.baseLSN = emptyBase
		seg.lastLSN = emptyBase - 1
		seg.size = int64(segmentHeaderSize)
		seg.crc = 0
		seg.recordCount = 0
		seg.commitSeq = state.commitSeq
		seg.minTime, seg.maxTime = 0, 0
		if !w.opts.readOnly && emptyBase != h.baseLSN {
			h.baseLSN = emptyBase
			h.createdNano = time.Now().UnixNano()
			if err := rewriteSegmentHeader(f, h); err != nil {
				_ = f.Close()
				return nil, 0, state.commitSeq, state.firstLSN, err
			}
		}
		if !w.opts.readOnly {
			_ = removeIfExists(seg.idxPath)
			_ = removeIfExists(seg.bakPath)
		}
		seg.setState(segmentActive)
		seg.f = f
		return seg, 0, state.commitSeq, state.firstLSN, nil
	}
	// A non-empty last segment is immutable. | 非空最后分段不可变。
	seg.setState(segmentSealing)
	if !w.opts.readOnly {
		data, idxCRC := w.buildFullSidecar(seg)
		if err := writeFileAtomic(seg.idxPath, data, w.opts.fileMode); err != nil {
			_ = f.Close()
			return nil, 0, state.commitSeq, state.firstLSN, err
		}
		seg.metaMu.Lock()
		seg.idxCRC = idxCRC
		seg.metaMu.Unlock()
		if w.manifest.enabled {
			lastLSN, recordCount, size, minTime, maxTime, crc, _, commitSeq := seg.summarySnapshot()
			if err := w.manifest.append(manifestRecord{
				kind: manifestKindSegment, seq: seg.seq, baseLSN: seg.baseLSN,
				lastLSN: lastLSN, segmentBytes: uint64(size), recordCount: recordCount,
				minTime: minTime, maxTime: maxTime, segmentCRC: crc, idxCRC: idxCRC,
				walID: walID, createdNano: seg.createdNano, commitSeq: commitSeq,
			}); err != nil {
				_ = f.Close()
				return nil, 0, state.commitSeq, state.firstLSN, err
			}
		}
	}
	seg.setState(segmentSealed)
	_ = f.Close()
	if !w.opts.readOnly {
		w.enqueueBackup(seg)
	}
	return nil, out.lastKeyID, state.commitSeq, state.firstLSN, nil
}

// applyScan installs a scan outcome on a segment. | applyScan 把扫描结果安装到分段。
func (w *WAL) applyScan(seg *segment, out scanOutcome, last bool) {
	seg.metaMu.Lock()
	seg.lastLSN = out.lastLSN
	seg.recordCount = out.recordCount
	seg.size = out.truncateTo
	seg.minTime = out.minTime
	seg.maxTime = out.maxTime
	seg.crc = out.crc
	seg.commitSeq = out.commitSeq
	seg.sparse = out.sparse
	seg.sparseLoaded = true
	seg.offsets = out.offsets
	seg.denseLoaded = true
	if out.keyIndex != nil {
		seg.keyIndex = out.keyIndex
		seg.keyIndexLoaded = true
	}
	seg.metaMu.Unlock()
	if last {
		seg.setState(segmentSealed)
	}
}

// validateContinuity checks head and adjacent LSN coverage. | validateContinuity
// 校验头部与相邻 LSN 覆盖。
func (w *WAL) validateContinuity(live []*segment, firstLSN *uint64, state *metaState) ([]*segment, error) {
	allow := w.opts.allowLSNGaps
	if len(live) == 0 {
		return live, nil
	}
	filtered := live[:0]
	for _, seg := range live {
		seg.metaMu.RLock()
		base, last := seg.baseLSN, seg.lastLSN
		seg.metaMu.RUnlock()
		if last < *firstLSN && !(last == base-1 && *firstLSN == base) {
			seg.retired = true
			continue
		}
		filtered = append(filtered, seg)
	}
	live = filtered
	if len(live) == 0 {
		return live, nil
	}
	prevLast := uint64(0)
	for i, seg := range live {
		seg.metaMu.RLock()
		base, last := seg.baseLSN, seg.lastLSN
		seg.metaMu.RUnlock()
		if i == 0 {
			if *firstLSN < base {
				gap := base - *firstLSN
				if !allow && base-1 > state.gapFloor {
					return nil, errs.Detail(ErrMissingSegment, "head segment starts at %[1]d but FirstLSN is %[2]d | 首个分段从 %[1]d 开始但 FirstLSN 为 %[2]d",
						base, *firstLSN)
				}
				if allow {
					*firstLSN = base
					state.gapFloor = maxU64(state.gapFloor, base-1)
					w.counters.recMissingLSNs.Add(gap)
				}
			}
		} else if base != prevLast+1 {
			if base > prevLast+1 {
				gapEnd := base - 1
				if !allow && gapEnd > state.gapFloor {
					return nil, errs.Detail(ErrMissingSegment, "LSN gap after %[1]d up to %[2]d | %[1]d 之后到 %[2]d 存在 LSN 缺口", prevLast, gapEnd)
				}
				if allow {
					state.gapFloor = maxU64(state.gapFloor, gapEnd)
					w.counters.recMissingLSNs.Add(base - prevLast - 1)
				}
			}
		}
		prevLast = last
	}
	return live, nil
}

// resolveEncryption binds keys and applies the encryption policy. | resolveEncryption
// 绑定密钥并应用加密策略。
func (w *WAL) resolveEncryption(state metaState, metaValid bool, walID [16]byte, lastKeyID uint32, live []*segment) error {
	empty := state.firstLSN == state.nextLSN && state.commitSeq == 0
	for _, seg := range live {
		seg.metaMu.RLock()
		rc := seg.recordCount
		seg.metaMu.RUnlock()
		if rc > 0 {
			empty = false
			break
		}
	}
	if w.opts.keyRing != nil && w.bound == nil {
		bound, err := w.opts.keyRing.bind(walID)
		if err != nil {
			return err
		}
		w.bound = bound
	}
	switch {
	case metaValid && state.encrypted():
		if w.bound == nil {
			return ErrKeyNotFound
		}
		id := state.activeKeyID
		if lastKeyID != 0 && lastKeyID != id {
			id = lastKeyID
		}
		key, err := w.bound.key(id)
		if err != nil {
			return err
		}
		w.encrypted = true
		w.activeKeyID = id
		w.activeKCV = key.kcv
		if !w.opts.skipKeyCheck && state.activeKeyKCV != key.kcv {
			return errs.Detail(ErrAuth, "META KCV does not match the active key | META KCV 与活动密钥不匹配")
		}
	case metaValid && !state.encrypted():
		if lastKeyID != 0 && w.bound != nil {
			key, err := w.bound.key(lastKeyID)
			if err != nil {
				return err
			}
			w.encrypted = true
			w.activeKeyID = lastKeyID
			w.activeKCV = key.kcv
			break
		}
		if w.bound != nil && !empty && !w.opts.allowPlaintext {
			return errs.Detail(ErrCipherMismatch, "plaintext WAL opened with encryption keys | 带密钥打开明文 WAL")
		}
		if w.bound != nil && empty {
			id := w.opts.keyRing.SuggestedActiveID()
			key, err := w.bound.key(id)
			if err != nil {
				return err
			}
			w.encrypted = true
			w.activeKeyID = id
			w.activeKCV = key.kcv
		}
	case !metaValid:
		id := lastKeyID
		if id == 0 && !empty {
			id = w.lastNonEmptyKeyID(live)
		}
		if id != 0 {
			if w.bound == nil {
				return ErrKeyNotFound
			}
			key, err := w.bound.key(id)
			if err != nil {
				return err
			}
			w.encrypted = true
			w.activeKeyID = id
			w.activeKCV = key.kcv
		} else if w.bound != nil && empty {
			id = w.opts.keyRing.SuggestedActiveID()
			key, err := w.bound.key(id)
			if err != nil {
				return err
			}
			w.encrypted = true
			w.activeKeyID = id
			w.activeKCV = key.kcv
		}
	}
	if w.encrypted {
		nonce, err := newNonceGen()
		if err != nil {
			return err
		}
		w.nonce = nonce
	}
	return nil
}

// resolveSerializable applies serializable-durability policy and rebuilds OCC. | resolveSerializable
// 应用可串行化持久化策略并重建 OCC。
func (w *WAL) resolveSerializable(state metaState, metaValid bool, live []*segment, highestLast uint64) error {
	if metaValid && state.serializable() {
		w.serializableDurable = true
		w.hashAlg = state.hashAlgorithm()
		if w.opts.hashAlgorithm != w.hashAlg {
			return errs.Detail(ErrInvalidOptions, "WithHashAlgorithm does not match META | WithHashAlgorithm 与 META 不一致")
		}
		return w.rebuildOCC(live)
	}
	if !metaValid {
		// A rebuilt META may need to infer the flag from persisted write keys. | 重建 META 时可能需要从持久化写键推断标志。
		hasKeys, hashAlg, err := w.scanSerializableEvidence(live)
		if err != nil {
			return err
		}
		if hasKeys {
			w.serializableDurable = true
			w.hashAlg = hashAlg
			if w.opts.hashAlgorithm != hashAlg {
				return errs.Detail(ErrInvalidOptions, "WithHashAlgorithm does not match persisted write keys | WithHashAlgorithm 与持久化写键不一致")
			}
			return w.rebuildOCC(live)
		}
	}
	if w.opts.serializableDurability {
		if state.commitSeq > 0 {
			return errs.Detail(ErrInvalidOptions, "SerializableDurability must be enabled when the WAL is created | 可串行化持久化必须在创建 WAL 时启用")
		}
		w.serializableDurable = true
		w.hashAlg = w.opts.hashAlgorithm
	}
	return nil
}

// lastNonEmptyKeyID scans backward to find the last encrypted record key ID. | lastNonEmptyKeyID
// 向前回溯最后一个加密记录的密钥 ID。
func (w *WAL) lastNonEmptyKeyID(live []*segment) uint32 {
	for i := len(live) - 1; i >= 0; i-- {
		seg := live[i]
		seg.metaMu.RLock()
		count, size := seg.recordCount, seg.size
		seg.metaMu.RUnlock()
		if count == 0 || size <= int64(segmentHeaderSize) {
			continue
		}
		start := int64(segmentHeaderSize)
		if sc, err := loadSidecar(seg.idxPath); err == nil && len(sc.sparse) > 0 {
			start = sc.sparse[len(sc.sparse)-1].offset
		}
		f, err := os.Open(seg.path)
		if err != nil {
			continue
		}
		var id uint32
		var buf []byte
		for off := start; off < size; {
			hdr, _, _, newBuf, err := readRawRecord(f, off, size, buf)
			buf = newBuf
			if err != nil {
				break
			}
			if hdr.cipher != cipherNone {
				id = hdr.keyID
			}
			off += int64(hdr.size)
		}
		_ = f.Close()
		if id != 0 {
			return id
		}
	}
	return 0
}

// scanSerializableEvidence scans control records for persisted write keys. | scanSerializableEvidence
// 扫描控制记录中的持久化写键。
func (w *WAL) scanSerializableEvidence(live []*segment) (bool, HashAlgorithm, error) {
	budget := w.opts.txnConflictScanBytes
	alg := HashSHA256
	found := false
	for i := len(live) - 1; i >= 0 && budget > 0; i-- {
		seg := live[i]
		seg.metaMu.RLock()
		size := seg.size
		seg.metaMu.RUnlock()
		f, err := os.Open(seg.path)
		if err != nil {
			continue
		}
		ev, err := w.scanTxnControls(f, seg, int64(segmentHeaderSize), size, &budget)
		_ = f.Close()
		if err != nil {
			return false, alg, err
		}
		for _, e := range ev {
			if len(e.keys) > 0 {
				a := HashAlgorithm(e.hashAlg)
				if found && alg != a {
					return false, alg, errs.Detail(ErrCorrupt, "mixed transaction hash algorithms | 事务哈希算法混用")
				}
				found = true
				alg = a
			}
		}
	}
	return found, alg, nil
}

// txnEvidence is one control record observation. | txnEvidence 是一次控制记录观察。
type txnEvidence struct {
	commitSeq uint64
	keys      [][32]byte
	hashAlg   byte
}

// rebuildOCC scans recent segments and rebuilds the conflict window. | rebuildOCC
// 扫描近期分段并重建冲突窗口。
func (w *WAL) rebuildOCC(live []*segment) error {
	budget := w.opts.txnConflictScanBytes
	var all []txnEvidence
	for i := len(live) - 1; i >= 0 && budget > 0; i-- {
		seg := live[i]
		seg.metaMu.RLock()
		size := seg.size
		seg.metaMu.RUnlock()
		f, err := os.Open(seg.path)
		if err != nil {
			continue
		}
		ev, err := w.scanTxnControls(f, seg, int64(segmentHeaderSize), size, &budget)
		_ = f.Close()
		if err != nil {
			return err
		}
		all = append(all, ev...)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].commitSeq < all[j].commitSeq })
	for _, e := range all {
		w.occ.apply(e.commitSeq, e.keys)
	}
	if len(all) > 0 && all[0].commitSeq > w.occ.minSeq {
		// Snapshots older than the oldest scanned commit may miss a key. | 早于
		// 最旧扫描提交的快照可能漏掉键。
		w.occ.minSeq = all[0].commitSeq
	}
	return nil
}

// scanTxnControls scans transaction control records. | scanTxnControls 扫描事务控制记录。
func (w *WAL) scanTxnControls(f *os.File, seg *segment, start, limit int64, budget *int64) ([]txnEvidence, error) {
	var out []txnEvidence
	var buf []byte
	for off := start; off < limit; {
		hdr, rawHeader, payload, newBuf, err := readRawRecord(f, off, limit, buf)
		buf = newBuf
		if err != nil {
			break
		}
		*budget -= int64(hdr.size)
		if hdr.codec == codecTxnControl {
			plain, err := w.plainControl(seg, off, hdr, rawHeader[:hdr.headerLen], payload)
			if err != nil {
				return nil, err
			}
			tc, err := parseTxnControlPayload(plain)
			if err != nil {
				return nil, err
			}
			out = append(out, txnEvidence{commitSeq: tc.commitSeq, keys: tc.writeKeys, hashAlg: tc.hashAlg})
		}
		off += int64(hdr.size)
		if *budget <= 0 {
			break
		}
	}
	return out, nil
}

// randomWALID generates a directory-unique identifier. | randomWALID 生成目录唯一标识。
func randomWALID() ([16]byte, error) {
	var id [16]byte
	if _, err := cryptoRandRead(id[:]); err != nil {
		return id, errs.Wrap(err, ErrRandomSource)
	}
	return id, nil
}

// sortedSeqs returns the sorted segment map keys. | sortedSeqs 返回排序后的分段序号。
func sortedSeqs(segs map[uint64]*segment) []uint64 {
	out := make([]uint64, 0, len(segs))
	for seq := range segs {
		out = append(out, seq)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// hasSequenceGap reports a non-retired sequence hole. | hasSequenceGap 报告非退休序号空洞。
func hasSequenceGap(segs map[uint64]*segment, retired map[uint64]bool) bool {
	seqs := sortedSeqs(segs)
	prev := uint64(0)
	for _, seq := range seqs {
		if retired[seq] {
			continue
		}
		if prev != 0 && seq != prev+1 {
			return true
		}
		prev = seq
	}
	return false
}

// parseSequence parses a fixed-name file. | parseSequence 解析固定命名文件。
func parseSequence(name, suffix string) (uint64, bool) {
	if !strings.HasSuffix(name, suffix) {
		return 0, false
	}
	base := strings.TrimSuffix(name, suffix)
	if len(base) == 0 || len(base) > 20 {
		return 0, false
	}
	var seq uint64
	for i := 0; i < len(base); i++ {
		if base[i] < '0' || base[i] > '9' {
			return 0, false
		}
		seq = seq*10 + uint64(base[i]-'0')
	}
	return seq, seq > 0
}

// maxU64 returns the larger value. | maxU64 返回较大值。
func maxU64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

// buildManifestData builds a manifest snapshot from recovered segments. | buildManifestData
// 从恢复的分段构建 MANIFEST 快照。
func buildManifestData(live []*segment, retired map[uint64]bool, firstLSN, commitSeq uint64, walID [16]byte) manifestData {
	data := newManifestData()
	data.firstLSN = firstLSN
	data.commitSeq = commitSeq
	data.walID = walID
	data.walIDSet = true
	for _, seg := range live {
		seg.metaMu.RLock()
		c := newSegmentSummary(seg.seq, seg.baseLSN, seg.lastLSN, seg.size, seg.walID, filepath.Dir(seg.path))
		c.recordCount = seg.recordCount
		c.minTime = seg.minTime
		c.maxTime = seg.maxTime
		c.crc = seg.crc
		c.idxCRC = seg.idxCRC
		c.commitSeq = seg.commitSeq
		c.createdNano = seg.createdNano
		seg.metaMu.RUnlock()
		c.setState(seg.currentState())
		data.segments[seg.seq] = c
		if seg.seq > data.maxSeq {
			data.maxSeq = seg.seq
		}
		if seg.seq > data.maxCreatedSeq {
			data.maxCreatedSeq = seg.seq
		}
	}
	for seq := range retired {
		data.retired[seq] = true
		if seq > data.maxSeq {
			data.maxSeq = seq
		}
		if seq > data.maxCreatedSeq {
			data.maxCreatedSeq = seq
		}
	}
	return data
}

// plainControl decrypts a control record payload. | plainControl 解密控制记录负载。
func (w *WAL) plainControl(seg *segment, off int64, hdr recordHeader, rawHeader, payload []byte) ([]byte, error) {
	if hdr.cipher == cipherNone {
		return payload, nil
	}
	if w.bound == nil {
		return nil, ErrKeyNotFound
	}
	bk, err := w.bound.key(hdr.keyID)
	if err != nil {
		return nil, err
	}
	var nonce [nonceSize]byte
	copy(nonce[:], rawHeader[recOffNonce:recordHeaderSizeEncrypted])
	var aadBuf [32 + recordHeaderSizeEncrypted]byte
	aad := buildAAD(aadBuf[:0], w.walID, seg.seq, off, rawHeader[recOffSize:recordHeaderSizeEncrypted])
	plain, err := bk.aead.Open(nil, nonce[:], payload, aad)
	if err != nil {
		return nil, errs.Wrap(err, ErrAuth)
	}
	return plain, nil
}

// readRawRecord reads one record without decrypting it. | readRawRecord 读取一条记录但不解密。
func readRawRecord(f *os.File, off, limit int64, buf []byte) (recordHeader, [recordHeaderSizeEncrypted]byte, []byte, []byte, error) {
	var raw [recordHeaderSizeEncrypted]byte
	if err := readAtFull(f, raw[:recordHeaderSize], off); err != nil {
		return recordHeader{}, raw, nil, buf, err
	}
	hdr, err := parseRecordHeader(raw[:recordHeaderSize])
	if err != nil {
		return recordHeader{}, raw, nil, buf, err
	}
	if hdr.headerLen == recordHeaderSizeEncrypted {
		if err := readAtFull(f, raw[recordHeaderSize:recordHeaderSizeEncrypted], off+recordHeaderSize); err != nil {
			return recordHeader{}, raw, nil, buf, err
		}
	}
	if off < 0 || int64(hdr.size) > limit-off {
		return recordHeader{}, raw, nil, buf, errs.Detail(ErrCorrupt, "record at %[1]d exceeds limit | 偏移 %[1]d 的记录超出上限", off)
	}
	if err := validateRecordHeader(hdr); err != nil {
		return recordHeader{}, raw, nil, buf, err
	}
	if err := validatePayloadLength(hdr); err != nil {
		return recordHeader{}, raw, nil, buf, err
	}
	payloadLen := int(hdr.size) - hdr.headerLen
	buf = ensureCap(buf, payloadLen)
	if payloadLen > 0 {
		if err := readAtFull(f, buf[:payloadLen], off+int64(hdr.headerLen)); err != nil {
			return recordHeader{}, raw, nil, buf, err
		}
	}
	crc := checksum(raw[recOffSize:hdr.headerLen])
	crc = appendCRC(crc, buf[:payloadLen])
	if got := binary.LittleEndian.Uint32(raw[recOffCRC:]); got != crc {
		return recordHeader{}, raw, nil, buf, errs.Detail(ErrCorrupt, "record CRC mismatch at %[1]d | 偏移 %[1]d 的记录 CRC 不匹配", off)
	}
	return hdr, raw, buf[:payloadLen], buf, nil
}

// scanSegment verifies records and markers from start to limit. | scanSegment
// 从 start 到 limit 校验记录与提交标记。
func (w *WAL) scanSegment(seg *segment, f *os.File, start, limit int64, baseLast, baseCount uint64, baseCRC uint32, baseMin, baseMax int64, allowTruncate bool) (scanOutcome, error) {
	out := scanOutcome{
		lastLSN: baseLast, recordCount: baseCount, size: limit, minTime: baseMin, maxTime: baseMax,
		crc: baseCRC, verifiedEnd: start, truncateTo: start,
	}
	var buf []byte
	var pending txnPending
	firstUser := true
	if baseCount > 0 {
		firstUser = false
	}
	for off := start; off < limit; {
		hdr, raw, payload, newBuf, err := readRawRecord(f, off, limit, buf)
		buf = newBuf
		if err != nil {
			out.corrupt = true
			break
		}
		crcBefore := out.crc
		out.crc = appendCRC(out.crc, raw[:hdr.headerLen])
		out.crc = appendCRC(out.crc, payload)
		if hdr.cipher == cipherNone {
			out.sawPlain = true
		} else {
			out.sawEncrypted = true
			out.lastKeyID = hdr.keyID
		}
		switch {
		case hdr.flags&recordFlagCommitMark != 0:
			plain, err := w.plainControl(seg, off, hdr, raw[:hdr.headerLen], payload)
			if err != nil {
				return out, err
			}
			m, err := parseCommitMarkerPayload(plain)
			if err != nil {
				out.corrupt = true
				break
			}
			if pending.active && pending.startOff < out.verifiedEnd {
				return out, errs.Detail(ErrCorrupt, "transaction block missing its control record | 事务块缺少控制记录")
			}
			if m.committedEnd != uint64(off) || m.lastLSN != out.lastLSN || m.recordCount != out.recordCount || m.segmentCRC != crcBefore {
				out.corrupt = true
				break
			}
			if m.committedEnd <= uint64(out.verifiedEnd) || m.lastLSN < baseLast || m.recordCount < baseCount {
				out.corrupt = true
				break
			}
			out.verifiedEnd = off + int64(hdr.size)
			out.truncateTo = out.verifiedEnd
			pending = txnPending{}
		case hdr.codec == codecTxnControl:
			plain, err := w.plainControl(seg, off, hdr, raw[:hdr.headerLen], payload)
			if err != nil {
				return out, err
			}
			tc, err := parseTxnControlPayload(plain)
			if err != nil {
				return out, err
			}
			if pending.active {
				if hdr.txnID != pending.txnID || tc.commitSeq != pending.txnID ||
					tc.firstLSN != pending.first || tc.lastLSN != pending.last ||
					tc.recordCount != pending.count || tc.bytes != pending.bytes {
					return out, errs.Detail(ErrCorrupt, "transaction control does not match its data block | 事务控制与数据块不匹配")
				}
				pending = txnPending{}
			} else if tc.recordCount != 0 || tc.firstLSN != 0 || tc.lastLSN != 0 || tc.bytes != 0 {
				return out, errs.Detail(ErrCorrupt, "transaction control has no data block | 事务控制缺少数据块")
			}
			if tc.commitSeq > out.commitSeq {
				out.commitSeq = tc.commitSeq
			}
		default:
			if hdr.lsn != out.lastLSN+1 {
				return out, errs.Detail(ErrCorrupt, "LSN %[1]d follows %[2]d | LSN %[1]d 跟在 %[2]d 之后", hdr.lsn, out.lastLSN)
			}
			if hdr.txnID != 0 {
				if !pending.active {
					pending = txnPending{active: true, txnID: hdr.txnID, first: hdr.lsn, startOff: off}
				} else if pending.txnID != hdr.txnID {
					return out, errs.Detail(ErrCorrupt, "transaction IDs interleave | 事务 ID 交错")
				}
				pending.last = hdr.lsn
				pending.count++
				pending.bytes += uint64(hdr.keyLen) + uint64(hdr.dataLen)
			} else if pending.active {
				return out, errs.Detail(ErrCorrupt, "non-transaction record inside a transaction block | 事务块中出现非事务记录")
			}
			out.lastLSN = hdr.lsn
			out.recordCount++
			if firstUser || hdr.timestamp < out.minTime {
				out.minTime = hdr.timestamp
			}
			if firstUser || hdr.timestamp > out.maxTime {
				out.maxTime = hdr.timestamp
			}
			firstUser = false
			if len(out.sparse) == 0 || off-out.sparse[len(out.sparse)-1].offset >= int64(w.opts.indexIntervalBytes) ||
				hdr.lsn-out.sparse[len(out.sparse)-1].lsn >= defaultIndexRecordsPerEntry {
				out.sparse = append(out.sparse, sparseEntry{lsn: hdr.lsn, offset: off, timestamp: hdr.timestamp})
			}
			if len(out.offsets) < maxDenseRecords {
				out.offsets = append(out.offsets, uint64(off))
			}
			if w.opts.keyIndex && hdr.keyLen > 0 {
				key, err := w.userKey(hdr, raw[:hdr.headerLen], payload)
				if err != nil {
					return out, err
				}
				if len(key) <= w.opts.keyIndexMaxKeyBytes && len(out.keyIndex) < w.opts.keyIndexMaxEntries {
					if out.keyIndex == nil {
						out.keyIndex = make(map[string][]uint64)
					}
					out.keyIndex[string(key)] = append(out.keyIndex[string(key)], hdr.lsn)
				}
			}
		}
		off += int64(hdr.size)
		if out.corrupt {
			break
		}
	}
	if pending.active && pending.startOff < out.verifiedEnd {
		return out, errs.Detail(ErrCorrupt, "transaction block has no control record | 事务块没有控制记录")
	}
	if out.truncateTo < start {
		out.truncateTo = start
	}
	if out.truncateTo < limit {
		if !allowTruncate {
			return out, errs.Detail(ErrCorrupt, "sealed segment has an unconfirmed tail | 封段存在未确认尾部")
		}
		out.truncated = true
	}
	out.size = out.truncateTo
	if out.lastLSN < seg.baseLSN-1 {
		out.lastLSN = seg.baseLSN - 1
	}
	return out, nil
}

// userKey returns a user record's key for the Key index. | userKey 返回用户记录的 Key 供索引使用。
func (w *WAL) userKey(hdr recordHeader, rawHeader, payload []byte) ([]byte, error) {
	plain := payload
	if hdr.cipher != cipherNone {
		var nonce [nonceSize]byte
		copy(nonce[:], rawHeader[recOffNonce:recordHeaderSizeEncrypted])
		var aadBuf [32 + recordHeaderSizeEncrypted]byte
		aad := buildAAD(aadBuf[:0], w.walID, 0, 0, rawHeader[recOffSize:recordHeaderSizeEncrypted])
		_ = aad
		_ = nonce
		return nil, nil
	}
	if len(plain) < int(hdr.keyLen) {
		return nil, errs.Detail(ErrCorrupt, "record shorter than key length | 记录短于 Key 长度")
	}
	return plain[:hdr.keyLen], nil
}

// scanError annotates a scan failure. | scanError 注解扫描失败。
func scanError(err error) error {
	if err == nil {
		return nil
	}
	return errs.Wrap(err, ErrCorrupt)
}

// recoverySummary is used for diagnostics. | recoverySummary 用于诊断。
func recoverySummary(live []*segment) string {
	return fmt.Sprintf("%d segments", len(live))
}

var _ = binary.LittleEndian
var _ = scanError
var _ = recoverySummary
