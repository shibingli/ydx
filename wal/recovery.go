package wal

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
)

// scanOutcome is the result of scanning one segment. | scanOutcome 是一个分段的扫描结果。
type scanOutcome struct {
	keyIndex     map[string][]uint64
	sparse       []sparseEntry
	offsets      []uint64
	lastLSN      uint64
	recordCount  uint64
	size         int64
	minTime      int64
	maxTime      int64
	commitSeq    uint64
	verifiedEnd  int64
	truncateTo   int64
	crc          uint32
	lastKeyID    uint32
	truncated    bool
	corrupt      bool
	sawPlain     bool
	sawEncrypted bool
	// Completeness flags describe whether an index covers the whole segment
	// from its header, not only the scanned tail. A partial index must never be
	// persisted as a full sidecar or used as a dense LSN-to-offset table. |
	// 完整标志表示索引是否覆盖从段头开始的整个分段，而不只是扫描尾部。部分索引
	// 不得作为完整侧车持久化，也不得当作稠密 LSN→偏移表使用。
	sparseComplete   bool
	offsetsComplete  bool
	keyIndexComplete bool
	keyIndexOverflow bool
}

// scanBase is the trusted prefix state for a segment scan. A zero-value base
// scans from the segment header and produces complete indexes. | scanBase 是
// 分段扫描的可信前缀状态；零值表示从段头扫描并生成完整索引。
type scanBase struct {
	keyIndex         map[string][]uint64
	sparse           []sparseEntry
	lastLSN          uint64
	recordCount      uint64
	commitSeq        uint64
	minTime          int64
	maxTime          int64
	crc              uint32
	keyIndexOverflow bool
	keyIndexComplete bool
	atHeader         bool
}

// scanCommit is the committed state at the last verified commit marker. | scanCommit
// 是最近一个已验证提交标记处的已提交状态。
type scanCommit struct {
	lastLSN       uint64
	recordCount   uint64
	crc           uint32
	commitSeq     uint64
	minTime       int64
	maxTime       int64
	sparseLen     int
	offsetsLen    int
	keyIndexLimit uint64
	sawPlain      bool
	sawEncrypted  bool
	lastKeyID     uint32
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
	// Leftover atomic-write .tmp files are ignored by recovery and truncated by
	// the next write to the same path; cleanup is opportunistic inside the
	// directory scans instead of two extra readdirs on every clean Open. |
	// 残留的原子写 .tmp 会被恢复忽略，并会被同一路径的下一次写覆盖；清理改为
	// 目录扫描中的机会式动作，避免每次干净 Open 多两次 readdir。
	meta, err := openMetaStore(w.dir, w.opts.fileMode)
	if err != nil {
		return err
	}
	w.meta = meta
	man, manExists, manCorrupt, err := openManifest(w.dir, w.opts.manifestEnabled, w.opts.manifestShardRecords,
		w.opts.manifestCompactRatio, w.opts.fileMode, w.opts.readOnly)
	if err != nil {
		return err
	}
	w.manifest = man
	metaValid := meta.hasState
	state := meta.state
	manifestUsable := w.opts.manifestEnabled && manExists && !manCorrupt
	var anchor anchorState
	anchorValid := false
	// Read the anchor only when META is unusable, a gap exists, or MANIFEST
	// cannot corroborate the truncation watermark. A clean default open then
	// skips one file read entirely. | 仅在 META 不可用、存在缺口或 MANIFEST
	// 无法佐证截断水位时读取锚点；干净的默认打开因此完全跳过该文件读取。
	if !metaValid || state.gapFloor > 0 || !manifestUsable {
		anchorFile, err := openAnchorStore(anchorPath(w.dir), w.opts.fileMode)
		if err != nil {
			return err
		}
		w.anchorFile = anchorFile
		anchor = anchorFile.state
		anchorValid = anchorFile.has
		w.anchorPersisted = anchorFile.has
		if anchorValid {
			w.anchor = &anchorFile.state
		}
	}
	// A valid META is authoritative over the redundant anchor; a mismatch
	// means the anchor was copied from another WAL. | 有效 META 优先于冗余锚点；
	// walID 不一致说明锚点来自另一个 WAL。
	if metaValid && anchorValid && anchor.walID != state.walID {
		anchorValid = false
		w.anchor = nil
	}
	stateFromAnchor := false
	usedDirScan := false
	manifestRecovered := false
	var segs map[uint64]*segment
	var retired *retiredSet
	var maxSeq, maxCreatedSeq uint64
	var manRetired *retiredSet
	var manSegs map[uint64]*segment
	var manMaxSeq, manMaxCreated uint64

	if w.opts.manifestEnabled && manExists && !manCorrupt {
		data := man.snapshot()
		segs = data.segments
		retired = &retiredSet{floor: data.retireFloor, m: data.retired}
		maxSeq = data.maxSeq
		maxCreatedSeq = data.maxCreatedSeq
		manRetired = retired
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
		// Do not stat or open every segment: sealed summaries are trusted and
		// their headers/files are validated on the first read. Missing manifest
		// entries are probed per sequence up to ManifestGapProbeMax; only a
		// probe overflow or an ambiguous head falls back to a directory scan. |
		// 不逐段 stat/打开：封段摘要可信，段头与文件在首次读取时校验；MANIFEST
		// 缺失条目按序号探测至 ManifestGapProbeMax，只有探测超限或头部不明确
		// 才回退目录扫描。
		if !usedDirScan {
			recovered, ok := w.probeUnsealedManifest(segs, retired, &maxSeq, &maxCreatedSeq)
			manifestRecovered = manifestRecovered || recovered
			if !ok {
				usedDirScan = true
			}
		}
		if !usedDirScan && (hasSequenceGap(segs, retired) || hasManifestHeadGap(segs, retired, state.firstLSN)) {
			recovered, ok := w.probeManifestGaps(segs, retired, state.firstLSN, &maxSeq, &maxCreatedSeq)
			manifestRecovered = manifestRecovered || recovered
			if !ok {
				usedDirScan = true
			}
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
		retired.union(manRetired)
		maxSeq = maxU64(maxSeq, manMaxSeq)
		maxCreatedSeq = maxU64(maxCreatedSeq, manMaxCreated)
		if w.opts.manifestEnabled && manCorrupt {
			// Rebuild below. | 下方重建。
		}
	}
	// Validate the anchor against the directory truth before trusting its
	// high-water marks. With a valid META the walID was already checked; with
	// only MANIFEST/segment headers, compare against those. | 在信任锚点高水位前
	// 先与目录事实核对；有 META 时已校验 walID，这里用 MANIFEST/段头核对。
	if anchorValid && !metaValid {
		expected := state.walID
		if expected == ([16]byte{}) && len(segs) > 0 {
			if id, ok := firstSegmentWALID(segs); ok {
				expected = id
			}
		}
		if expected != ([16]byte{}) && expected != anchor.walID {
			anchorValid = false
			w.anchor = nil
		}
	}
	if anchorValid {
		state.firstLSN = maxU64(state.firstLSN, anchor.firstLSN)
		state.nextSeq = maxU64(state.nextSeq, anchor.nextSeq)
		state.nextLSN = maxU64(state.nextLSN, anchor.nextLSN)
		state.commitSeq = maxU64(state.commitSeq, anchor.commitSeq)
		if state.createdNano == 0 {
			state.createdNano = anchor.createdNano
		}
		if state.walID == ([16]byte{}) {
			state.walID = anchor.walID
		}
		if !metaValid {
			// The anchor is the only policy evidence when META is gone. |
			// META 丢失时锚点是唯一的策略证据。
			state.flags = anchor.flags
			state.activeKeyID = anchor.activeKeyID
			state.activeKeyKCV = anchor.activeKeyKCV
			stateFromAnchor = true
			w.recoveredFromAnchor = true
		} else {
			if state.activeKeyID == 0 {
				state.activeKeyID = anchor.activeKeyID
				state.activeKeyKCV = anchor.activeKeyKCV
			}
			if state.flags != anchor.flags {
				empty := state.firstLSN == state.nextLSN && state.commitSeq == 0
				if empty && (anchor.flags&^state.flags)&(metaFlagEncrypted|metaFlagSerializable) != 0 {
					state.flags = anchor.flags
				}
			}
		}
		state.gapFloor = maxU64(state.gapFloor, gapsMaxEnd(anchor.gaps))
		w.gaps.merge(anchor.gaps)
	}
	if !anchorValid && state.gapFloor > 0 {
		// v1 WAL: gapFloor is a single upper bound; seed its exact interval. |
		// v1 WAL：gapFloor 是单一上界；以精确区间播种子。
		w.gaps.add(state.gapFloor, state.gapFloor)
	}
	stateTrusted := metaValid || anchorValid
	if !stateTrusted && len(segs) > 0 && !manifestUsable {
		// B2: without META, anchor, or a usable MANIFEST the directory is the
		// only evidence. Auto repair rebuilds high-water marks from segment
		// headers/sidecars and records any unavoidable gap. | B2：没有 META、
		// 锚点或可用 MANIFEST 时，目录是唯一证据；自动修复从段头/侧车重建
		// 高水位，并记录无法避免的缺口。
		if !w.opts.autoRepair {
			return errs.Detail(ErrCorrupt, "segments exist without a valid META slot, recovery anchor, or usable MANIFEST | 分段存在但没有有效 META 槽、恢复锚点或可用 MANIFEST")
		}
		w.autoRepaired = true
		w.queueRecoveryReport(errs.Detail(ErrCorrupt, "rebuilt high-water metadata from segment headers and sidecars | 已从段头与侧车重建高水位元数据"))
	}
	if segs == nil {
		segs = make(map[uint64]*segment)
	}
	if retired == nil {
		retired = newRetiredSet()
	}
	// Probe the durable nextSeq and nextSeq-1; manifest entries can lag file
	// creation. | 探测持久 nextSeq 与 nextSeq-1；MANIFEST 可能滞后于建段。
	if stateTrusted {
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
			if info.Size() < int64(segmentHeaderSize) {
				// META.nextSeq can name a segment whose header write was torn by
				// a crash. It never accepted records, so the only safe action is
				// to discard the partial file; a shorter active predecessor or a
				// non-retired known segment is corruption. | META.nextSeq 可能
				// 指向头写入被崩溃撕裂的分段；它从未接受记录，只能丢弃残缺文件；
				// 更低的或已知未退休分段缺头则属于损坏。
				if seq != state.nextSeq {
					if retired.has(seq) {
						continue
					}
					return errs.Detail(ErrCorrupt, "segment %[1]d has an incomplete header | 分段 %[1]d 的段头不完整", seq)
				}
				if w.opts.readOnly {
					continue
				}
				if err := removeIfExists(path); err != nil {
					return errs.WrapDetail(err, ErrStorage, "remove partial segment %d | 删除残缺分段 %d 失败", seq, seq)
				}
				_ = removeIfExists(sidecarPath(w.dir, seq))
				_ = removeIfExists(backupPath(w.dir, seq))
				if err := syncDir(w.dir); err != nil {
					return errs.WrapDetail(err, ErrStorage, "sync directory after removing partial segment | 删除残缺分段后同步目录失败")
				}
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
	walIDSet := walID != ([16]byte{})
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
	// Directory-scanned summaries are validated eagerly; manifest fast-path
	// summaries defer header validation to the first read. | 目录扫描得到的摘要
	// 立即校验；MANIFEST 快速路径的摘要把段头校验推迟到首次读取。
	if usedDirScan {
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
	}
	// Tail and highest-created-sequence gaps. | 尾部与最高创建序号缺口。
	maxFileSeq := uint64(0)
	for seq := range segs {
		if seq > maxFileSeq {
			maxFileSeq = seq
		}
	}
	if maxCreatedSeq > maxFileSeq && !retired.has(maxCreatedSeq) {
		var evidence *segment
		if manSegs != nil {
			evidence = manSegs[maxCreatedSeq]
		}
		if evidence != nil && evidence.lastLSN >= evidence.baseLSN && (w.opts.allowLSNGaps || w.opts.autoRepair) {
			if evidence.lastLSN == math.MaxUint64 {
				return errs.Detail(ErrCorrupt, "highest created segment %[1]d exhausted the LSN space | 最高创建分段 %[1]d 已耗尽 LSN 空间", maxCreatedSeq)
			}
			state.nextLSN = maxU64(state.nextLSN, evidence.lastLSN+1)
			w.queueRecoveryReport(errs.Detail(ErrMissingSegment, "highest created segment %[1]d is missing; resuming after its recorded lastLSN %[2]d | 最高创建分段 %[1]d 缺失，按其记录的 lastLSN %[2]d 继续",
				maxCreatedSeq, evidence.lastLSN))
		} else {
			return errs.Detail(ErrMissingSegment, "highest created segment %[1]d is missing | 最高创建分段 %[1]d 缺失", maxCreatedSeq)
		}
	}
	if state.nextSeq > 0 && maxSeq > 0 && state.nextSeq > maxSeq+1 {
		return errs.Detail(ErrMissingSegment, "META.nextSeq %[1]d exceeds known segments %[2]d | META.nextSeq %[1]d 超出已知分段 %[2]d", state.nextSeq, maxSeq)
	}
	// Zero-segment rebuild gate. | 零段重建门禁。
	if len(segs) == 0 {
		initEmpty := func() {
			state.firstLSN, state.nextLSN, state.nextSeq = 1, 1, 1
			state.commitSeq = 0
			state.walID = walID
		}
		if !stateTrusted {
			switch {
			case w.opts.manifestEnabled && manExists:
				if manCorrupt {
					if !w.opts.autoRepair {
						return errs.Detail(ErrCorrupt, "MANIFEST is corrupt and no valid META slot exists | MANIFEST 损坏且没有有效 META 槽")
					}
					w.autoRepaired = true
					w.queueRecoveryReport(errs.Detail(ErrCorrupt, "MANIFEST is corrupt; initializing an empty WAL | MANIFEST 损坏，初始化为空 WAL"))
					initEmpty()
					break
				}
				if maxCreatedSeq > 0 && !retired.has(maxCreatedSeq) {
					// A created-but-unretired segment is missing. Without a
					// persisted lastLSN we cannot know its high water. | 最高创建
					// 段缺失且没有持久 lastLSN 时无法得知其高水位。
					evidence := manSegs[maxCreatedSeq]
					if evidence == nil || evidence.lastLSN < evidence.baseLSN {
						return errs.Detail(ErrMissingSegment, "highest created segment %[1]d has no retirement record or lastLSN evidence | 最高创建分段 %[1]d 没有退休记录或 lastLSN 证据", maxCreatedSeq)
					}
					if evidence.lastLSN == math.MaxUint64 {
						return errs.Detail(ErrCorrupt, "highest created segment %[1]d exhausted the LSN space | 最高创建分段 %[1]d 已耗尽 LSN 空间", maxCreatedSeq)
					}
					state.nextLSN = maxU64(state.nextLSN, evidence.lastLSN+1)
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
				if _, err := os.Stat(filepath.Join(w.dir, "manifest")); err == nil && !w.opts.autoRepair {
					return errs.Detail(ErrCorrupt, "manifest directory exists without valid records | MANIFEST 目录存在但没有有效记录")
				}
				if w.opts.autoRepair {
					w.autoRepaired = true
					w.queueRecoveryReport(errs.Detail(ErrCorrupt, "no readable metadata; initializing an empty WAL | 没有可读元数据，初始化为空 WAL"))
				}
				initEmpty()
			default:
				initEmpty()
			}
		} else if state.firstLSN < state.nextLSN {
			if !w.opts.autoRepair {
				return errs.Detail(ErrMissingSegment, "META expects records but no segment exists | META 期望记录但不存在任何分段")
			}
			// The durable high water is known, so continuing at nextLSN never
			// reuses an LSN. Record the missing prefix as an accepted gap. |
			// 持久高水位已知，从 nextLSN 继续不会复用 LSN；把缺失前缀记录为
			// 已接受缺口。
			w.gaps.add(state.firstLSN, state.nextLSN-1)
			state.gapFloor = maxU64(state.gapFloor, state.nextLSN-1)
			state.firstLSN = state.nextLSN
			w.autoRepaired = true
			w.queueRecoveryReport(errs.Detail(ErrMissingSegment, "all segments are missing; continuing at LSN %[1]d | 所有分段缺失，从 LSN %[1]d 继续", state.nextLSN))
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
			if retired.has(seq) {
				delete(segs, seq)
				continue
			}
			continue
		}
		if last != 0 && last < firstLSN && !(seg.size <= int64(segmentHeaderSize) && seg.baseLSN == firstLSN) {
			retired.mark(seq)
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
		if retired.has(seq) || seg.missing {
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
			if os.IsNotExist(err) {
				return errs.Detail(ErrMissingSegment, "segment %[1]d is missing | 分段 %[1]d 缺失", seq)
			}
			return errs.WrapDetail(err, ErrStorage, "open segment %d | 打开分段 %d 失败", seq, seq)
		}
		if err := validateSegmentIdentity(seg, f); err != nil {
			_ = f.Close()
			return err
		}
		out, err := w.scanSegment(seg, f, int64(segmentHeaderSize), info.Size(), scanBase{lastLSN: seg.baseLSN - 1, atHeader: true}, false)
		_ = f.Close()
		if err != nil {
			return err
		}
		w.applyScan(seg, out, false)
		seg.setState(segmentSealed)
		// Persist the recovered full summary as a sealed MANIFEST record. | 把
		// 恢复出的完整摘要补写为封段 MANIFEST 记录。
		manifestRecovered = true
	}
	// A retired highest sequence must never become the active segment. This can
	// happen if a retire watermark outlives a cleaner failure. | 已退休的最高
	// 序号绝不能成为活动段；清理失败时退休水位可能仍覆盖它。
	for len(seqs) > 0 && retired.has(seqs[len(seqs)-1]) {
		delete(segs, seqs[len(seqs)-1])
		seqs = seqs[:len(seqs)-1]
	}
	// Open and validate the last segment. | 打开并校验最后一段。
	var lastKeyID uint32
	var active *segment
	if len(seqs) > 0 {
		lastSeq := seqs[len(seqs)-1]
		last := segs[lastSeq]
		if last.missing {
			if retired.has(lastSeq) {
				delete(segs, lastSeq)
			} else {
				return errs.Detail(ErrMissingSegment, "last segment %[1]d is missing | 最后分段 %[1]d 缺失", lastSeq)
			}
		} else {
			var err error
			active, lastKeyID, state.commitSeq, state.firstLSN, err = w.openLastSegment(last, state, walID, firstLSN, stateTrusted)
			if err != nil {
				return err
			}
			// Publish the writer handle early so abortOpen can close it if a
			// later continuity check fails. | 提前发布写侧句柄，使后续连续性
			// 校验失败时 abortOpen 能关闭它。
			w.active = active
			firstLSN = state.firstLSN
		}
	}
	// Rebuild the final segment list and validate continuity. | 重建最终分段列表并校验连续性。
	seqs = sortedSeqs(segs)
	live := make([]*segment, 0, len(seqs))
	for _, seq := range seqs {
		seg := segs[seq]
		if retired.has(seq) || seg.missing {
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
		if last == math.MaxUint64 {
			return errs.Detail(ErrCorrupt, "segment %[1]d exhausted the LSN space | 分段 %[1]d 已耗尽 LSN 空间", seg.seq)
		}
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
	if stateTrusted && state.nextLSN > observedNext {
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
	if state.nextLSN == 0 || state.nextSeq == 0 {
		return errs.Detail(ErrCorrupt, "recovered LSN or sequence high-water is zero | 恢复出的 LSN 或序号高水位为零")
	}
	// Resolve encryption and serializable durability. | 解析加密与可串行化持久化。
	if err := w.resolveEncryption(state, stateTrusted, walID, lastKeyID, live); err != nil {
		return err
	}
	if err := w.resolveSerializable(state, stateTrusted, stateFromAnchor, live, highestLast); err != nil {
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
	if !w.opts.readOnly && w.manifest.enabled && (usedDirScan || manCorrupt || !manExists || manifestRecovered) {
		data := buildManifestData(live, retired, firstLSN, state.commitSeq, walID)
		if err := w.manifest.rewrite(data); err != nil {
			return err
		}
	}
	return nil
}

// sweepOrphanSidecars removes .idx/.bak files whose .wal no longer exists. The
// cleaner unlinks the segment first and its sidecars best-effort afterwards, so
// a crash between the unlinks leaves an orphan that recovery would otherwise
// ignore forever. | sweepOrphanSidecars 删除没有对应 .wal 的 .idx/.bak 文件。
// cleaner 先删除分段、再尽力删除侧车，两次 unlink 之间崩溃会留下恢复永远忽略
// 的孤儿文件。
func (w *WAL) sweepOrphanSidecars() {
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		w.counters.cleanupErrors.Add(1)
		return
	}
	live := make(map[uint64]struct{}, len(entries))
	for _, e := range entries {
		if seq, ok := parseSequence(e.Name(), ".wal"); ok {
			live[seq] = struct{}{}
		}
	}
	removed := false
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		seq, ok := parseSequence(e.Name(), ".idx")
		if !ok {
			seq, ok = parseSequence(e.Name(), ".bak")
		}
		if !ok {
			continue
		}
		if _, exists := live[seq]; exists {
			continue
		}
		if err := os.Remove(filepath.Join(w.dir, e.Name())); err != nil && !os.IsNotExist(err) {
			w.counters.cleanupErrors.Add(1)
			continue
		}
		removed = true
	}
	if removed {
		if err := syncDir(w.dir); err != nil {
			w.counters.cleanupErrors.Add(1)
		}
	}
}

// scanDirectory rebuilds segment summaries by reading the directory. | scanDirectory
// 通过读取目录重建分段摘要。
func (w *WAL) scanDirectory() (map[uint64]*segment, *retiredSet, uint64, uint64, error) {
	segs := make(map[uint64]*segment)
	retired := newRetiredSet()
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return nil, nil, 0, 0, errs.WrapDetail(err, ErrStorage, "read directory | 读取目录失败")
	}
	var maxSeq uint64
	var shortSeqs []uint64
	for _, e := range entries {
		if !w.opts.readOnly && !e.IsDir() && strings.HasSuffix(e.Name(), ".tmp") {
			_ = os.Remove(filepath.Join(w.dir, e.Name()))
			continue
		}
		seq, ok := parseSequence(e.Name(), ".wal")
		if !ok {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.Size() < int64(segmentHeaderSize) {
			// A file shorter than the segment header is a creation that crashed
			// before its header became durable. It never accepted a record, so the
			// highest such file can be discarded; anything else is corruption. |
			// 短于段头的文件是段头尚未持久化就崩溃的创建过程，从未接受记录；
			// 仅最高序号的这种文件可丢弃，其它情况属于损坏。
			shortSeqs = append(shortSeqs, seq)
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
	if len(shortSeqs) > 0 {
		if len(shortSeqs) > 1 || (maxSeq > 0 && shortSeqs[0] < maxSeq) {
			return nil, nil, 0, 0, errs.Detail(ErrCorrupt, "incomplete segment %[1]d is not the newest segment | 不完整分段 %[1]d 不是最高序号分段", shortSeqs[0])
		}
		if !w.opts.readOnly {
			seq := shortSeqs[0]
			_ = removeIfExists(segmentPath(w.dir, seq))
			_ = removeIfExists(sidecarPath(w.dir, seq))
			_ = removeIfExists(backupPath(w.dir, seq))
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
	seg.validated.Store(true)
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
func (w *WAL) openLastSegment(seg *segment, state metaState, walID [16]byte, firstLSN uint64, stateTrusted bool) (*segment, uint32, uint64, uint64, error) {
	// A sealed last segment with a matching size needs no open at all; its
	// records were synced before the sealing MANIFEST record. | 已封且大小匹配的
	// 最后分段无需打开；其记录在封段 MANIFEST 记录之前已同步。
	if stateTrusted && seg.currentState() == segmentSealed && seg.size > int64(segmentHeaderSize) {
		info, statErr := os.Stat(seg.path)
		switch {
		case statErr == nil && info.Size() == seg.size:
			if !w.opts.readOnly {
				w.enqueueBackup(seg)
			}
			return nil, 0, seg.commitSeq, state.firstLSN, nil
		case os.IsNotExist(statErr):
			if !w.opts.allowLSNGaps {
				return nil, 0, state.commitSeq, state.firstLSN, errs.Detail(ErrMissingSegment, "last segment %[1]d is missing | 最后分段 %[1]d 缺失", seg.seq)
			}
			return nil, 0, seg.commitSeq, state.firstLSN, nil
		case statErr != nil:
			return nil, 0, state.commitSeq, state.firstLSN, wrapStorage("stat last segment", statErr)
		}
	}
	flags := os.O_RDWR
	if w.opts.readOnly {
		flags = os.O_RDONLY
	}
	f, err := os.OpenFile(seg.path, flags, w.opts.fileMode)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, state.commitSeq, state.firstLSN, errs.Detail(ErrMissingSegment, "last segment %[1]d is missing | 最后分段 %[1]d 缺失", seg.seq)
		}
		if w.opts.readOnly && os.IsPermission(err) {
			return nil, 0, state.commitSeq, state.firstLSN, errs.WrapDetail(err, ErrStorage, "open last segment read-only | 只读打开最后分段失败")
		}
		return nil, 0, state.commitSeq, state.firstLSN, errs.WrapDetail(err, ErrStorage, "open last segment | 打开最后分段失败")
	}
	stat, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, state.commitSeq, state.firstLSN, err
	}
	fileSize := stat.Size()
	// Creation crashes at state.nextSeq are discarded by the earlier probe or by
	// a directory scan. Reaching this point means a manifest-known segment lost
	// its header; never emit a retire floor here, because the floor is a prefix
	// watermark and would retire lower live sequences. | 创建期崩溃已由前面的
	// nextSeq 探测或目录扫描处理；到这里说明 MANIFEST 已知的分段丢失段头。绝不能
	// 写退休水位：水位是前缀语义，会连带退休更低的存活序号。
	if fileSize < int64(segmentHeaderSize) {
		_ = f.Close()
		seg.missing = true
		return nil, 0, state.commitSeq, state.firstLSN,
			errs.Detail(ErrCorrupt, "segment %[1]d has an incomplete header | 分段 %[1]d 的段头不完整", seg.seq)
	}
	// Reuse the already-open handle instead of opening the path again. | 复用已打开的
	// 句柄，避免再按路径打开一次。
	var hdrBuf [segmentHeaderSize]byte
	if err := w.readAtFull(f, hdrBuf[:], 0); err != nil {
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
	seg.validated.Store(true)
	start := int64(segmentHeaderSize)
	base := scanBase{lastLSN: seg.baseLSN - 1, atHeader: true}
	trusted := false
	// Use the MANIFEST summary as a trusted full description or a checkpoint prefix
	// when the sidecar is missing. | 侧车缺失时使用 MANIFEST 摘要作为完整描述或检查点前缀。
	if stateTrusted {
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
			base = scanBase{
				lastLSN: seg.lastLSN, recordCount: seg.recordCount, crc: seg.crc,
				commitSeq: seg.commitSeq, minTime: seg.minTime, maxTime: seg.maxTime,
				atHeader: false,
			}
			trusted = true
		}
	}
	staleSidecar := false
	if sc, err := loadSidecar(seg.idxPath); err == nil && stateTrusted && sc.seq == seg.seq && sc.baseLSN == h.baseLSN && sc.walID == walID {
		if sc.segmentBytes > uint64(fileSize) {
			// B5: a crash before the sidecar invalidation can leave a sidecar that
			// claims bytes past the current file end. Do not trust it as a prefix;
			// scan from the header (or MANIFEST prefix) and accept only when the
			// committed waterline reaches the file end, after which the normal
			// non-empty path rewrites the sidecar. | B5：侧车失效前崩溃可能留下
			// segmentBytes 超过当前文件大小的侧车。不得把它当作可信前缀；从段头
			// （或 MANIFEST 前缀）扫描，仅当已提交水位到达文件末尾时接受，随后正常的
			// 非空路径会重写侧车。
			staleSidecar = true
		} else if !sc.checkpoint && sc.segmentBytes == uint64(fileSize) {
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
		if !staleSidecar {
			// The sidecar prefix carries the sparse/key index and commitSeq. It is at
			// least as new as the MANIFEST summary and keeps the indexes complete, so
			// prefer it. | 侧车前缀携带稀疏/Key 索引与 commitSeq，不旧于 MANIFEST 摘要
			// 且能保持索引完整，因此优先使用。
			start = int64(sc.segmentBytes)
			base = scanBase{
				lastLSN: sc.lastLSN, recordCount: sc.recordCount, crc: sc.segmentCRC,
				commitSeq: sc.commitSeq, minTime: sc.minTime, maxTime: sc.maxTime,
				sparse: sc.sparse, keyIndex: sc.keyIndex, keyIndexComplete: sc.keyIndexComplete,
				atHeader: false,
			}
			trusted = true
		}
	}
	out, err := w.scanSegment(seg, f, start, fileSize, base, true)
	if err != nil {
		_ = f.Close()
		return nil, 0, state.commitSeq, state.firstLSN, err
	}
	if !trusted && out.verifiedEnd < int64(segmentHeaderSize) {
		out.truncateTo = int64(segmentHeaderSize)
	}
	if staleSidecar && out.truncateTo != fileSize {
		_ = f.Close()
		return nil, 0, state.commitSeq, state.firstLSN,
			errs.Detail(ErrCorrupt, "stale segment sidecar exceeds the file and the scan does not reach its end | 陈旧分段侧车超过文件大小且扫描水位未达文件末尾")
	}
	if stateTrusted {
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
			// The segment is empty, so replace the whole file with a fresh header
			// instead of rewriting it in place: rename is atomic, while a torn
			// 64-byte in-place write would leave an unreadable header. |
			// 分段为空，因此用全新段头原子替换整个文件，而不是原位重写：rename
			// 是原子的，撕裂的 64 字节原位写会留下无法读取的段头。
			h.baseLSN = emptyBase
			h.createdNano = time.Now().UnixNano()
			_ = f.Close()
			var hdr [segmentHeaderSize]byte
			encodeSegmentHeader(hdr[:], h)
			if err := writeFileAtomic(seg.path, hdr[:], w.opts.fileMode); err != nil {
				return nil, 0, state.commitSeq, state.firstLSN, err
			}
			nf, err := os.OpenFile(seg.path, os.O_RDWR, w.opts.fileMode)
			if err != nil {
				return nil, 0, state.commitSeq, state.firstLSN, errs.WrapDetail(err, ErrStorage, "reopen rewritten empty segment | 重新打开重写后的空分段失败")
			}
			f = nf
			seg.createdNano = h.createdNano
		}
		if !w.opts.readOnly {
			_ = removeIfExists(seg.idxPath)
			_ = removeIfExists(seg.bakPath)
		}
		seg.sparseComplete = true
		seg.keyIndexComplete = true
		seg.sparseLoaded = true
		seg.keyIndexLoaded = true
		if w.opts.readOnly {
			// Read-only recovery never writes; do not keep an active writer
			// handle. | 只读恢复从不写入，不保留活动写句柄。
			_ = f.Close()
			seg.setState(segmentSealed)
			return nil, 0, state.commitSeq, state.firstLSN, nil
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
	seg.sparseComplete = out.sparseComplete
	if out.offsetsComplete {
		seg.offsets = out.offsets
	} else {
		// A partial scan only saw the tail. Never expose such offsets as an
		// LSN-indexed dense table; the sparse index (when complete) or a lazy
		// full scan governs random reads. | 部分扫描只看到尾部，绝不能把尾部偏移
		// 当作按 LSN 索引的稠密表；随机读使用完整稀疏索引或按需全段扫描。
		seg.offsets = nil
	}
	seg.denseLoaded = true
	if out.keyIndex != nil {
		seg.keyIndex = out.keyIndex
		seg.keyIndexLoaded = true
	}
	seg.keyIndexComplete = out.keyIndexComplete
	seg.keyIndexOverflow = out.keyIndexOverflow
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
	auto := w.opts.autoRepair
	acceptGap := func(start, end uint64) error {
		if w.gaps.covers(start, end) {
			return nil
		}
		if !allow && !auto {
			return errs.Detail(ErrMissingSegment, "missing LSN range [%[1]d,%[2]d] has no persisted acceptance | LSN 区间 [%[1]d,%[2]d] 缺失且没有持久化接受记录",
				start, end)
		}
		// Explicit lossy recovery without auto repair keeps the B7 rule: a new
		// lower-address gap is never accepted. | 未开启自动修复的显式有损
		// 恢复仍保留 B7：绝不接受新出现的低地址缺口。
		if allow && !auto && end < state.gapFloor {
			return errs.Detail(ErrMissingSegment, "new lower LSN gap [%[1]d,%[2]d] | 出现新的低地址 LSN 缺口 [%[1]d,%[2]d]", start, end)
		}
		changed := w.gaps.add(start, end)
		if changed {
			w.queueRecoveryReport(errs.Detail(ErrMissingSegment, "accepted missing LSN range [%[1]d,%[2]d] | 已接受缺失 LSN 区间 [%[1]d,%[2]d]",
				start, end))
		}
		if w.gaps.maxEnd() > state.gapFloor {
			state.gapFloor = w.gaps.maxEnd()
		}
		return nil
	}
	prevLast := uint64(0)
	for i, seg := range live {
		seg.metaMu.RLock()
		base, last := seg.baseLSN, seg.lastLSN
		seg.metaMu.RUnlock()
		if i == 0 {
			if *firstLSN < base {
				if err := acceptGap(*firstLSN, base-1); err != nil {
					return nil, errs.Detail(ErrMissingSegment, "head segment starts at %[1]d but FirstLSN is %[2]d: %[3]v | 首个分段从 %[1]d 开始但 FirstLSN 为 %[2]d：%[3]v",
						base, *firstLSN, err)
				}
				w.counters.recMissingLSNs.Add(base - *firstLSN)
				*firstLSN = base
			}
		} else if base != prevLast+1 {
			if base > prevLast+1 {
				if err := acceptGap(prevLast+1, base-1); err != nil {
					return nil, errs.Detail(ErrMissingSegment, "LSN gap after %[1]d up to %[2]d: %[3]v | %[1]d 之后到 %[2]d 存在 LSN 缺口：%[3]v",
						prevLast, base-1, err)
				}
				w.counters.recMissingLSNs.Add(base - prevLast - 1)
			} else {
				// base <= prevLast: two segments claim overlapping LSN ranges. |
				// base <= prevLast：两个分段声明了重叠的 LSN 区间。
				return nil, errs.Detail(ErrCorrupt, "segment %[1]d starts at LSN %[2]d, overlapping previous last LSN %[3]d | 分段 %[1]d 从 LSN %[2]d 开始，与前段 lastLSN %[3]d 重叠",
					seg.seq, base, prevLast)
			}
		}
		prevLast = last
	}
	state.gapFloor = maxU64(state.gapFloor, w.gaps.maxEnd())
	return live, nil
}

// resolveEncryption binds keys and applies the encryption policy. | resolveEncryption
// 绑定密钥并应用加密策略。
func (w *WAL) resolveEncryption(state metaState, trusted bool, walID [16]byte, lastKeyID uint32, live []*segment) error {
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
	case trusted && state.encrypted():
		if w.bound == nil {
			return ErrKeyNotFound
		}
		id := state.activeKeyID
		fromRecord := false
		if lastKeyID != 0 && lastKeyID != id {
			id = lastKeyID
			fromRecord = true
		}
		key, err := w.bound.key(id)
		if err != nil {
			return err
		}
		w.encrypted = true
		w.activeKeyID = id
		w.activeKCV = key.kcv
		// The KCV in META authenticates only META.activeKeyID. When the last
		// record names a different key (a rotation/crash boundary), the record
		// header is authoritative and comparing it with the old KCV would
		// reject a valid WAL. | META 的 KCV 只认证 META.activeKeyID。最后一条记录
		// 指向另一个密钥时（轮换/崩溃边界），以记录头为准；拿它和旧 KCV 比较会
		// 误拒一个有效 WAL。
		if !w.opts.skipKeyCheck && !fromRecord && state.activeKeyKCV != key.kcv {
			return errs.Detail(ErrAuth, "META KCV does not match the active key | META KCV 与活动密钥不匹配")
		}
	case trusted && !state.encrypted():
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
	case !trusted:
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
		} else if w.bound != nil {
			if !empty && !w.opts.allowPlaintext {
				// Without META the on-disk policy must be inferred from records.
				// A non-empty plaintext WAL opened with encryption keys is a
				// downgrade, not an empty WAL that may adopt a suggested key. |
				// META 缺失时只能从记录推断磁盘策略。带密钥打开非空明文 WAL 属于
				// 加密降级，绝不能当作“可用建议密钥初始化的空 WAL”。
				return errs.Detail(ErrCipherMismatch, "plaintext WAL opened with encryption keys | 带密钥打开明文 WAL")
			}
			if empty {
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
func (w *WAL) resolveSerializable(state metaState, trusted, infer bool, live []*segment, highestLast uint64) error {
	if trusted && state.serializable() {
		w.serializableDurable = true
		w.hashAlg = state.hashAlgorithm()
		if w.opts.hashAlgorithmSet && w.opts.hashAlgorithm != w.hashAlg {
			return errs.Detail(ErrInvalidOptions, "WithHashAlgorithm does not match META | WithHashAlgorithm 与 META 不一致")
		}
		return w.rebuildOCC(live)
	}
	if !trusted || infer {
		// A rebuilt or anchor-derived META may need to infer the flag from
		// persisted write keys. | 重建或由锚点推导的 META 可能需要从持久化写键推断标志。
		hasKeys, hashAlg, err := w.scanSerializableEvidence(live)
		if err != nil {
			return err
		}
		if hasKeys {
			w.serializableDurable = true
			w.hashAlg = hashAlg
			if w.opts.hashAlgorithmSet && w.opts.hashAlgorithm != hashAlg {
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
			hdr, _, _, newBuf, err := w.readRawRecord(f, off, size, buf)
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
	keys      [][32]byte
	commitSeq uint64
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
		hdr, rawHeader, payload, newBuf, err := w.readRawRecord(f, off, limit, buf)
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

// firstSegmentWALID reads the WAL ID from the lowest readable segment header.
// It is used to validate a recovery anchor before trusting it. | firstSegmentWALID
// 从最低可读段头读取 WAL ID，用于在信任恢复锚点前校验它。
func firstSegmentWALID(segs map[uint64]*segment) ([16]byte, bool) {
	for _, seq := range sortedSeqs(segs) {
		seg := segs[seq]
		if seg.missing {
			continue
		}
		h, _, err := readSegmentHeaderFile(seg.path)
		if err == nil {
			return h.walID, true
		}
	}
	return [16]byte{}, false
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

// hasManifestHeadGap reports whether the first live manifest segment starts
// after META.firstLSN; a directory fallback may recover an omitted head
// segment file. | hasManifestHeadGap 报告首个非退休 MANIFEST 分段是否晚于
// META.firstLSN；目录回退可能找回遗漏的头部段文件。
func hasManifestHeadGap(segs map[uint64]*segment, retired *retiredSet, firstLSN uint64) bool {
	if firstLSN == 0 {
		return false
	}
	var first *segment
	for seq, seg := range segs {
		if retired.has(seq) {
			continue
		}
		if first == nil || seq < first.seq {
			first = seg
		}
	}
	if first == nil {
		return false
	}
	first.metaMu.RLock()
	base := first.baseLSN
	first.metaMu.RUnlock()
	return firstLSN < base
}

// probeUnsealedManifest upgrades created-only (kind=5) summaries whose file
// already contains a complete sidecar. Without this, a lost kind=1 record
// would leave the segment looking empty for the whole run. | probeUnsealedManifest
// 升级“仅有 kind=5、但文件已有完整侧车”的摘要；否则丢失的 kind=1 会让该段在
// 整个运行期看似为空。
func (w *WAL) probeUnsealedManifest(segs map[uint64]*segment, retired *retiredSet, maxSeq, maxCreatedSeq *uint64) (recovered, ok bool) {
	maxProbe := w.opts.manifestGapProbeMax
	if maxProbe <= 0 {
		return false, false
	}
	lastSeq := uint64(0)
	for seq := range segs {
		if !retired.has(seq) && seq > lastSeq {
			lastSeq = seq
		}
	}
	probes := 0
	for seq, seg := range segs {
		if retired.has(seq) || seg.currentState() == segmentSealed {
			continue
		}
		if seq == lastSeq {
			// openLastSegment owns the newest segment's summary, scan, and
			// seal; only a missing highest created file needs the directory
			// fallback here. | 最新分段的摘要、扫描与封段由 openLastSegment 负责；
			// 这里只需对缺失的最高创建文件回退目录扫描。
			if _, err := os.Stat(seg.path); err != nil && os.IsNotExist(err) && seq >= *maxCreatedSeq {
				return recovered, false
			}
			continue
		}
		probes++
		if probes > maxProbe {
			return recovered, false
		}
		info, err := os.Stat(seg.path)
		if err != nil {
			if os.IsNotExist(err) && seq >= *maxCreatedSeq {
				// The highest created segment could have accepted records. Force
				// the directory fallback so the tail-gap gate can report
				// ErrMissingSegment. | 最高创建分段可能已接受记录；强制回退目录
				// 扫描，让尾部缺口门禁报告 ErrMissingSegment。
				return recovered, false
			}
			continue // Missing files are handled by continuity/openLastSegment.
		}
		if info.Size() == seg.size {
			continue
		}
		fresh, err := w.summaryFromFile(seq, info.Size())
		if err != nil {
			return recovered, false
		}
		segs[seq] = fresh
		if seq > *maxSeq {
			*maxSeq = seq
		}
		if seq > *maxCreatedSeq {
			*maxCreatedSeq = seq
		}
		if fresh.currentState() == segmentSealed {
			recovered = true
		}
	}
	return recovered, true
}

// probeManifestGaps recovers segment files that exist on disk but are missing
// from the MANIFEST. It returns recovered=true when at least one summary was
// added and ok=false when the caller must fall back to a full directory scan. |
// probeManifestGaps 找回磁盘存在但 MANIFEST 缺失的分段；recovered 表示加入了
// 至少一个摘要，ok=false 表示调用方必须回退全目录扫描。
func (w *WAL) probeManifestGaps(segs map[uint64]*segment, retired *retiredSet, firstLSN uint64, maxSeq, maxCreatedSeq *uint64) (recovered, ok bool) {
	maxProbe := w.opts.manifestGapProbeMax
	if maxProbe <= 0 {
		return false, false
	}
	probes := 0
	live := make([]uint64, 0, len(segs))
	for seq := range segs {
		if !retired.has(seq) {
			live = append(live, seq)
		}
	}
	sort.Slice(live, func(i, j int) bool { return live[i] < live[j] })
	add := func(seq uint64, info os.FileInfo) bool {
		seg, err := w.summaryFromFile(seq, info.Size())
		if err != nil {
			return false
		}
		segs[seq] = seg
		if seq > *maxSeq {
			*maxSeq = seq
		}
		if seq > *maxCreatedSeq {
			*maxCreatedSeq = seq
		}
		recovered = true
		return true
	}
	for i := 1; i < len(live); i++ {
		for seq := live[i-1] + 1; seq < live[i]; seq++ {
			probes++
			if probes > maxProbe {
				return recovered, false
			}
			info, err := os.Stat(segmentPath(w.dir, seq))
			if err != nil {
				continue
			}
			if !add(seq, info) {
				return recovered, false
			}
		}
	}
	if firstLSN > 0 && len(live) > 0 {
		first := live[0]
		base := segmentBaseLSN(segs[first])
		for base > firstLSN {
			if first == 0 {
				return recovered, false
			}
			seq := first - 1
			probes++
			if probes > maxProbe {
				return recovered, false
			}
			info, err := os.Stat(segmentPath(w.dir, seq))
			if err != nil {
				// Ambiguous head: confirm with one directory scan. | 头部不明确：
				// 用一次目录扫描确认。
				return recovered, false
			}
			if !add(seq, info) {
				return recovered, false
			}
			first = seq
			base = segmentBaseLSN(segs[first])
		}
	}
	return recovered, true
}

// segmentBaseLSN reads a segment's base LSN under its lock. | segmentBaseLSN
// 在分段锁下读取 baseLSN。
func segmentBaseLSN(seg *segment) uint64 {
	seg.metaMu.RLock()
	defer seg.metaMu.RUnlock()
	return seg.baseLSN
}

// hasSequenceGap reports a non-retired sequence hole. | hasSequenceGap 报告非退休序号空洞。
func hasSequenceGap(segs map[uint64]*segment, retired *retiredSet) bool {
	seqs := sortedSeqs(segs)
	prev := uint64(0)
	for _, seq := range seqs {
		if retired.has(seq) {
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
func buildManifestData(live []*segment, retired *retiredSet, firstLSN, commitSeq uint64, walID [16]byte) manifestData {
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
	data.retireFloor = retired.floor
	for seq := range retired.m {
		data.retired[seq] = true
		if seq > data.maxSeq {
			data.maxSeq = seq
		}
		if seq > data.maxCreatedSeq {
			data.maxCreatedSeq = seq
		}
	}
	if retired.floor > data.maxSeq {
		data.maxSeq = retired.floor
	}
	if retired.floor > data.maxCreatedSeq {
		data.maxCreatedSeq = retired.floor
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
func (w *WAL) readRawRecord(f *os.File, off, limit int64, buf []byte) (recordHeader, [recordHeaderSizeEncrypted]byte, []byte, []byte, error) {
	var raw [recordHeaderSizeEncrypted]byte
	if err := w.readAtFull(f, raw[:recordHeaderSize], off); err != nil {
		return recordHeader{}, raw, nil, buf, err
	}
	hdr, err := parseRecordHeader(raw[:recordHeaderSize])
	if err != nil {
		return recordHeader{}, raw, nil, buf, err
	}
	if hdr.headerLen == recordHeaderSizeEncrypted {
		if err := w.readAtFull(f, raw[recordHeaderSize:recordHeaderSizeEncrypted], off+recordHeaderSize); err != nil {
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
		if err := w.readAtFull(f, buf[:payloadLen], off+int64(hdr.headerLen)); err != nil {
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

// scanSegment verifies records and markers from start to limit. base carries a
// trusted prefix when start is a checkpoint rather than the segment header. |
// scanSegment 从 start 到 limit 校验记录与提交标记；start 为检查点而非段头时，
// base 携带可信前缀。
func (w *WAL) scanSegment(seg *segment, f *os.File, start, limit int64, base scanBase, allowTruncate bool) (scanOutcome, error) {
	out := scanOutcome{
		lastLSN: base.lastLSN, recordCount: base.recordCount, size: limit,
		minTime: base.minTime, maxTime: base.maxTime, crc: base.crc,
		commitSeq: base.commitSeq, verifiedEnd: start, truncateTo: start,
		sparseComplete:   base.atHeader || (len(base.sparse) > 0 && base.sparse[0].lsn == seg.baseLSN),
		offsetsComplete:  base.atHeader,
		keyIndexComplete: base.atHeader || base.keyIndexComplete,
	}
	if len(base.sparse) > 0 {
		out.sparse = append([]sparseEntry(nil), base.sparse...)
	}
	if base.keyIndex != nil {
		out.keyIndex = make(map[string][]uint64, len(base.keyIndex))
		for k, lsns := range base.keyIndex {
			out.keyIndex[k] = append([]uint64(nil), lsns...)
		}
	}
	out.keyIndexOverflow = base.keyIndexOverflow
	committed := scanCommit{
		lastLSN: out.lastLSN, recordCount: out.recordCount, crc: out.crc,
		commitSeq: out.commitSeq, minTime: out.minTime, maxTime: out.maxTime,
		sparseLen: len(out.sparse), offsetsLen: len(out.offsets),
		keyIndexLimit: out.lastLSN,
	}
	var buf []byte
	var pending txnPending
	var corruptOff, corruptEnd int64
	firstUser := base.recordCount == 0
	for off := start; off < limit; {
		hdr, raw, payload, newBuf, err := w.readRawRecord(f, off, limit, buf)
		buf = newBuf
		if err != nil {
			// A corrupt record followed by a self-CRC-valid commit marker means
			// an acknowledged batch sits after the damage. Truncating would
			// silently discard confirmed data; report corruption instead. |
			// 损坏记录之后若存在自身 CRC 有效的提交标记，说明后面还有已确认批次；
			// 截断会静默丢弃已确认数据，必须报告损坏。
			if allowTruncate {
				after, scanErr := w.hasValidCommitMarkerAfter(f, off, limit)
				if scanErr != nil {
					return out, scanErr
				}
				if after {
					return out, errs.Detail(ErrCorrupt, "corrupt record at offset %[1]d precedes a valid commit marker | 偏移 %[1]d 的损坏记录之后存在有效提交标记", off)
				}
			}
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
				out.corrupt, corruptOff, corruptEnd = true, off, off+int64(hdr.size)
				break
			}
			if pending.active && pending.startOff < out.verifiedEnd {
				return out, errs.Detail(ErrCorrupt, "transaction block missing its control record | 事务块缺少控制记录")
			}
			if m.committedEnd != uint64(off) || m.lastLSN != out.lastLSN || m.recordCount != out.recordCount || m.segmentCRC != crcBefore {
				out.corrupt, corruptOff, corruptEnd = true, off, off+int64(hdr.size)
				break
			}
			if m.committedEnd <= uint64(out.verifiedEnd) || m.lastLSN < base.lastLSN || m.recordCount < base.recordCount {
				out.corrupt, corruptOff, corruptEnd = true, off, off+int64(hdr.size)
				break
			}
			out.verifiedEnd = off + int64(hdr.size)
			out.truncateTo = out.verifiedEnd
			pending = txnPending{}
			// Everything before this marker is committed; remember the exact
			// state to roll back to if the tail is torn. | 此标记之前均已提交；
			// 记录状态，以便尾部撕裂时精确回滚。
			committed = scanCommit{
				lastLSN: out.lastLSN, recordCount: out.recordCount, crc: out.crc,
				commitSeq: out.commitSeq, minTime: out.minTime, maxTime: out.maxTime,
				sparseLen: len(out.sparse), offsetsLen: len(out.offsets),
				keyIndexLimit: out.lastLSN,
				sawPlain:      out.sawPlain, sawEncrypted: out.sawEncrypted, lastKeyID: out.lastKeyID,
			}
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
			} else {
				// The record header TxnID must equal the control payload
				// CommitSeq even for an empty transaction. | 即使是空事务，记录头
				// TxnID 也必须等于控制记录 payload 的 CommitSeq。
				if hdr.txnID != tc.commitSeq {
					return out, errs.Detail(ErrCorrupt, "transaction control header does not match its commit sequence | 事务控制记录头与提交序号不匹配")
				}
				if tc.recordCount != 0 || tc.firstLSN != 0 || tc.lastLSN != 0 || tc.bytes != 0 {
					return out, errs.Detail(ErrCorrupt, "transaction control has no data block | 事务控制缺少数据块")
				}
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
			if w.opts.keyIndex {
				key, err := w.userKey(hdr, raw[:hdr.headerLen], payload, seg.seq, off)
				if err != nil {
					return out, err
				}
				if len(key) != int(hdr.keyLen) {
					return out, errs.Detail(ErrCorrupt, "record key length mismatch | 记录 Key 长度不匹配")
				}
				if len(key) > w.opts.keyIndexMaxKeyBytes || len(out.keyIndex) >= w.opts.keyIndexMaxEntries {
					// The index is incomplete; never present it as complete. | 索引
					// 不完整，绝不能当作完整索引持久化。
					out.keyIndexOverflow = true
					out.keyIndexComplete = false
				} else {
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
	if out.corrupt && allowTruncate && corruptEnd > corruptOff {
		// A structurally valid but inconsistent commit marker is still damage.
		// If another valid marker follows it, acknowledged batches exist after
		// the damage and truncation would discard them. | 结构合法但内容不一致的
		// 提交标记仍是损坏；若其后还有有效标记，说明损坏之后存在已确认批次，
		// 截断会丢弃这些数据。
		after, scanErr := w.hasValidCommitMarkerAfter(f, corruptEnd, limit)
		if scanErr != nil {
			return out, scanErr
		}
		if after {
			return out, errs.Detail(ErrCorrupt, "corrupt commit marker at offset %[1]d precedes a valid commit marker | 偏移 %[1]d 的损坏提交标记之后存在有效提交标记", corruptOff)
		}
	}
	if out.truncateTo < start {
		out.truncateTo = start
	}
	if out.truncateTo < limit {
		if !allowTruncate {
			return out, errs.Detail(ErrCorrupt, "sealed segment has an unconfirmed tail | 封段存在未确认尾部")
		}
		out.truncated = true
		// The bytes after the last marker were never acknowledged. Restore the
		// committed state and indices; otherwise LastLSN/nextLSN would advance
		// past records that do not exist in the truncated file. | 标记之后的字节
		// 从未确认；恢复已提交状态与索引，否则 LastLSN/nextLSN 会越过截断文件中
		// 不存在的记录。
		out.lastLSN = committed.lastLSN
		out.recordCount = committed.recordCount
		out.crc = committed.crc
		out.commitSeq = committed.commitSeq
		out.minTime, out.maxTime = committed.minTime, committed.maxTime
		out.sawPlain, out.sawEncrypted, out.lastKeyID = committed.sawPlain, committed.sawEncrypted, committed.lastKeyID
		if len(out.sparse) > committed.sparseLen {
			out.sparse = out.sparse[:committed.sparseLen]
		}
		if len(out.offsets) > committed.offsetsLen {
			out.offsets = out.offsets[:committed.offsetsLen]
		}
		trimKeyIndex(out.keyIndex, committed.keyIndexLimit)
	}
	out.size = out.truncateTo
	if out.lastLSN < seg.baseLSN-1 {
		out.lastLSN = seg.baseLSN - 1
	}
	return out, nil
}

// hasValidCommitMarkerAfter scans the tail after a bad record for a commit
// marker whose own CRC is valid. Such a marker proves that acknowledged data
// follows the damage, so the caller must not truncate it as a torn tail. |
// hasValidCommitMarkerAfter 在坏记录之后扫描自身 CRC 有效的提交标记；它证明
// 损坏之后仍有已确认数据，调用方不得把它当作撕裂尾截断。
func (w *WAL) hasValidCommitMarkerAfter(f *os.File, off, limit int64) (bool, error) {
	const chunk = 1 << 20
	overlap := int64(recordHeaderSizeEncrypted - 1)
	buf := make([]byte, chunk+recordHeaderSizeEncrypted)
	for pos := off; pos < limit; {
		n := limit - pos
		if n > int64(len(buf)) {
			n = int64(len(buf))
		}
		if err := w.readAtFull(f, buf[:n], pos); err != nil {
			return false, wrapStorage("scan after corrupt record", err)
		}
		for i := recOffFlags; i < int(n); i++ {
			if buf[i]&byte(recordFlagCommitMark) == 0 {
				continue
			}
			start := pos + int64(i-recOffFlags)
			if start < off || start+int64(recordHeaderSize) > limit {
				continue
			}
			hdrOff := i - recOffFlags
			if hdrOff < 0 || hdrOff+recordHeaderSize > int(n) {
				// The next overlapping chunk re-examines headers that cross this
				// chunk's end (the overlap is at least one maximal header). A
				// header that cannot extend past limit is rejected above. |
				// 跨块头由下一重叠块重新检查（重叠长度不小于最大头长）；越界头
				// 已在上方拒绝。
				continue
			}
			if !plausibleCommitMarkerHeader(buf[hdrOff:]) {
				continue
			}
			size := int64(binary.LittleEndian.Uint32(buf[hdrOff+recOffSize:]))
			if size > limit-start {
				continue
			}
			hdr, _, _, _, err := w.readRawRecord(f, start, limit, nil)
			if err != nil {
				continue
			}
			if hdr.flags&recordFlagCommitMark != 0 {
				return true, nil
			}
		}
		if n <= overlap {
			break
		}
		pos += n - overlap
	}
	return false, nil
}

// plausibleCommitMarkerHeader performs cheap structural checks on a candidate
// header inside the scan buffer. It lets recovery reject repetitive garbage
// (for example all 0xFF bytes) without one positional read per candidate. |
// plausibleCommitMarkerHeader 对扫描缓冲中的候选头做廉价结构校验，使恢复无需
// 为每个候选做一次位置读取即可排除重复垃圾字节（例如全 0xFF）。
func plausibleCommitMarkerHeader(h []byte) bool {
	if len(h) < recordHeaderSize {
		return false
	}
	flags := binary.LittleEndian.Uint16(h[recOffFlags:])
	if flags&recordFlagCommitMark == 0 ||
		flags&(recordFlagCompressed|recordFlagDedupRef) != 0 ||
		flags>>recordUserFlagShift != 0 {
		return false
	}
	if h[recOffCipher] > cipherSM4GCM || h[recOffCodec] != codecNone {
		return false
	}
	if binary.LittleEndian.Uint64(h[recOffLSN:]) != 0 ||
		binary.LittleEndian.Uint64(h[recOffTxnID:]) != 0 ||
		binary.LittleEndian.Uint32(h[recOffKeyLen:]) != 0 ||
		binary.LittleEndian.Uint32(h[recOffDataLen:]) != 0 {
		return false
	}
	size := binary.LittleEndian.Uint32(h[recOffSize:])
	return size >= recordHeaderSize && size <= formatHardLimit
}

// trimKeyIndex drops LSNs above limit from a partially built key index. | trimKeyIndex
// 从部分构建的 Key 索引中删除大于 limit 的 LSN。
func trimKeyIndex(idx map[string][]uint64, limit uint64) {
	for k, lsns := range idx {
		n := sort.Search(len(lsns), func(i int) bool { return lsns[i] > limit })
		switch {
		case n == 0:
			delete(idx, k)
		case n < len(lsns):
			idx[k] = lsns[:n]
		}
	}
}

// userKey returns a user record's key for the Key index. | userKey 返回用户记录的 Key 供索引使用。
func (w *WAL) userKey(hdr recordHeader, rawHeader, payload []byte, seq uint64, off int64) ([]byte, error) {
	plain := payload
	if hdr.cipher != cipherNone {
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
		aad := buildAAD(aadBuf[:0], w.walID, seq, off, rawHeader[recOffSize:recordHeaderSizeEncrypted])
		plain, err = bk.aead.Open(nil, nonce[:], payload, aad)
		if err != nil {
			return nil, errs.Wrap(err, ErrAuth)
		}
	}
	if hdr.flags&recordFlagCompressed != 0 {
		codec, err := w.opts.compression.lookup(hdr.codec)
		if err != nil {
			return nil, err
		}
		if codec == nil {
			return nil, errs.Detail(ErrCodecMismatch, "codec %[1]d is not registered | codec %[1]d 未注册", hdr.codec)
		}
		expected := int(hdr.keyLen) + int(hdr.dataLen)
		out := make([]byte, 0, expected)
		out, err = safeDecompress(codec, out, plain)
		if err != nil {
			return nil, err
		}
		if len(out) != expected {
			return nil, errs.Detail(ErrCorrupt, "decompressed length %[1]d, want %[2]d | 解压长度 %[1]d，期望 %[2]d", len(out), expected)
		}
		plain = out
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
