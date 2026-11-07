package wal

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/shibingli/ydx/errs"
)

// Recovery anchor layout. The anchor is an independent, low-frequency copy of
// the durable high-water state. It exists so that losing META and MANIFEST at
// the same time cannot force a refusal to open: segment headers, sidecars and
// the anchor together always reconstruct a safe next LSN/sequence. | 恢复锚点
// 布局。锚点是持久高水位状态的独立低频副本；META 与 MANIFEST 同时丢失时，
// 段头、侧车与锚点仍能重建安全的 nextLSN/nextSeq，避免拒绝打开。
const (
	anchorMagic       = "YDXREC01"
	anchorVersion     = uint16(1)
	anchorHeaderSize  = uint32(100)
	anchorTrailerSize = 4
	anchorMaxGaps     = 1024

	// The anchor uses two fixed-size slots written in place, mirroring META.
	// In-place slot updates avoid the Windows rename/AV interference that a
	// tmp+rename scheme sees on every rotation, and a torn slot leaves the
	// other generation intact. | 锚点使用两个固定大小槽原位写入，与 META 一致。
	// 原位槽更新避免每次轮转都遇到 Windows rename/杀软干扰；撕裂槽不会破坏
	// 另一代。
	anchorSlotMaxSize  = int(anchorHeaderSize) + anchorMaxGaps*ancGapSize + anchorTrailerSize
	anchorFileSize     = 2 * anchorSlotMaxSize
	anchorFileMaxBytes = int64(anchorFileSize)
)

// Anchor field offsets. | 锚点字段偏移。
const (
	ancOffMagic       = 0
	ancOffVersion     = 8
	ancOffFlags       = 10
	ancOffHeaderSize  = 12
	ancOffGeneration  = 16
	ancOffWalID       = 24
	ancOffCreatedNano = 40
	ancOffNextSeq     = 48
	ancOffNextLSN     = 56
	ancOffFirstLSN    = 64
	ancOffCommitSeq   = 72
	ancOffActiveKeyID = 80
	ancOffGapCount    = 84
	ancOffActiveKCV   = 88
	ancOffReserved    = 96
	ancGapSize        = 16
)

// lsnGap is one accepted missing LSN interval, inclusive. | lsnGap 是一个已接受
// 的缺失 LSN 闭区间。
type lsnGap struct {
	Start uint64
	End   uint64
}

// gapSet is a sorted, merged set of accepted LSN gaps. It replaces the v1
// single gapFloor upper bound, which could not distinguish a known gap from a
// new lower gap. | gapSet 是排序并合并后的已接受 LSN 缺口集合，替代 v1 的
// 单 gapFloor 上界——后者无法区分已知缺口与新出现的低地址缺口。
type gapSet struct {
	intervals []lsnGap
	mu        sync.Mutex
	degraded  bool
}

// newGapSet returns an empty gap set. | newGapSet 返回空缺口集合。
func newGapSet() *gapSet { return &gapSet{} }

// covers reports whether [start,end] is already inside one accepted interval. |
// covers 返回 [start,end] 是否已包含在某个已接受区间内。
func (g *gapSet) covers(start, end uint64) bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.coversLocked(start, end)
}

// coversLocked is the lock-free form. | coversLocked 是无锁形式。
func (g *gapSet) coversLocked(start, end uint64) bool {
	if start > end {
		return false
	}
	for _, iv := range g.intervals {
		if iv.Start <= start && iv.End >= end {
			return true
		}
	}
	return false
}

// add merges [start,end] into the set and reports whether the set changed. |
// add 把 [start,end] 合并进集合，并返回集合是否变化。
func (g *gapSet) add(start, end uint64) bool {
	if g == nil || start > end {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.addLocked(start, end)
}

// addLocked is the lock-free form. | addLocked 是无锁形式。
func (g *gapSet) addLocked(start, end uint64) bool {
	if g.degraded {
		// Once collapsed to [1,floor], only a higher floor changes the set. |
		// 坍缩为 [1,floor] 后，只有更高的上界会改变集合。
		if len(g.intervals) == 0 {
			g.intervals = []lsnGap{{Start: 1, End: end}}
			return true
		}
		if end > g.intervals[0].End {
			g.intervals[0].End = end
			return true
		}
		return false
	}
	if g.coversLocked(start, end) {
		return false
	}
	out := make([]lsnGap, 0, len(g.intervals)+1)
	for _, iv := range g.intervals {
		disjoint := iv.End < start && start-iv.End > 1 || end < iv.Start && iv.Start-end > 1
		if disjoint {
			out = append(out, iv)
			continue
		}
		if iv.Start < start {
			start = iv.Start
		}
		if iv.End > end {
			end = iv.End
		}
	}
	out = append(out, lsnGap{Start: start, End: end})
	// The merge loop may have widened start/end after an interval was
	// appended; sort and merge once more to keep the invariant exact. | 合并
	// 可能在后追加区间后继续扩大范围；再排序合并一次，严格保持不重叠。
	sort.Slice(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	g.intervals = mergeGaps(out)
	if len(g.intervals) > anchorMaxGaps {
		// Severe loss: collapse to a floor and mark the set degraded. This is
		// reported through Stats; it is deliberately the last resort. | 严重
		// 丢失：坍缩为水位并标记降级，通过 Stats 报告；这是最后手段。
		g.intervals = []lsnGap{{Start: 1, End: g.intervals[len(g.intervals)-1].End}}
		g.degraded = true
	}
	return true
}

// merge merges another set. | merge 合并另一个集合。
func (g *gapSet) merge(other []lsnGap) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, iv := range other {
		if iv.Start > iv.End {
			continue
		}
		g.addLocked(iv.Start, iv.End)
	}
}

// maxEnd returns the highest accepted gap end. | maxEnd 返回已接受缺口的最高上界。
func (g *gapSet) maxEnd() uint64 {
	if g == nil {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.intervals) == 0 {
		return 0
	}
	return g.intervals[len(g.intervals)-1].End
}

// count returns the interval count. | count 返回区间数量。
func (g *gapSet) count() int {
	if g == nil {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.intervals)
}

// isDegraded reports whether the set collapsed to a floor. | isDegraded 返回集合
// 是否已坍缩为水位。
func (g *gapSet) isDegraded() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.degraded
}

// pruneBefore drops or clamps intervals below first, which is no longer
// readable. | pruneBefore 删除或裁剪低于 first 的区间，这些 LSN 已不可读。
func (g *gapSet) pruneBefore(first uint64) {
	if g == nil || first == 0 {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.intervals) == 0 {
		return
	}
	out := g.intervals[:0]
	for _, iv := range g.intervals {
		if iv.End < first {
			continue
		}
		if iv.Start < first {
			iv.Start = first
		}
		out = append(out, iv)
	}
	g.intervals = out
}

// snapshot returns a copy of the intervals. | snapshot 返回区间副本。
func (g *gapSet) snapshot() []lsnGap {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]lsnGap(nil), g.intervals...)
}

// mergeGaps merges sorted, possibly adjacent intervals. | mergeGaps 合并排序后的
// 相邻/重叠区间。
func mergeGaps(in []lsnGap) []lsnGap {
	if len(in) == 0 {
		return nil
	}
	out := make([]lsnGap, 0, len(in))
	cur := in[0]
	for _, iv := range in[1:] {
		if iv.Start <= cur.End+1 {
			if iv.End > cur.End {
				cur.End = iv.End
			}
			continue
		}
		out = append(out, cur)
		cur = iv
	}
	out = append(out, cur)
	return out
}

// anchorState is the decoded recovery anchor. | anchorState 是解码后的恢复锚点。
type anchorState struct {
	gaps         []lsnGap
	generation   uint64
	createdNano  int64
	nextSeq      uint64
	nextLSN      uint64
	firstLSN     uint64
	commitSeq    uint64
	activeKeyKCV uint64
	activeKeyID  uint32
	flags        uint16
	walID        [16]byte
}

// metaState converts the anchor to the META view used by recovery. The META
// generation is intentionally left zero so the first healed write assigns a
// fresh generation. | metaState 把锚点转换为恢复使用的 META 视图；META
// generation 故意留零，让第一次自愈写入分配新代次。
func (a *anchorState) metaState() metaState {
	if a == nil {
		return metaState{}
	}
	return metaState{
		nextSeq: a.nextSeq, nextLSN: a.nextLSN, createdNano: a.createdNano,
		firstLSN: a.firstLSN, commitSeq: a.commitSeq, gapFloor: gapsMaxEnd(a.gaps),
		activeKeyKCV: a.activeKeyKCV, walID: a.walID, activeKeyID: a.activeKeyID,
		flags: a.flags,
	}
}

// gapsMaxEnd returns the highest end. | gapsMaxEnd 返回最高上界。
func gapsMaxEnd(g []lsnGap) uint64 {
	if len(g) == 0 {
		return 0
	}
	return g[len(g)-1].End
}

// anchorPath returns the anchor file path. | anchorPath 返回锚点文件路径。
func anchorPath(dir string) string { return filepath.Join(dir, "RECOVERY") }

// encodeAnchor encodes one anchor with a trailing CRC. | encodeAnchor 编码一个
// 带尾部 CRC 的锚点。
func encodeAnchor(a anchorState) []byte {
	size := int(anchorHeaderSize) + len(a.gaps)*ancGapSize + anchorTrailerSize
	buf := make([]byte, size)
	copy(buf[ancOffMagic:], anchorMagic)
	binary.LittleEndian.PutUint16(buf[ancOffVersion:], anchorVersion)
	binary.LittleEndian.PutUint16(buf[ancOffFlags:], a.flags)
	binary.LittleEndian.PutUint32(buf[ancOffHeaderSize:], anchorHeaderSize)
	binary.LittleEndian.PutUint64(buf[ancOffGeneration:], a.generation)
	copy(buf[ancOffWalID:], a.walID[:])
	binary.LittleEndian.PutUint64(buf[ancOffCreatedNano:], uint64(a.createdNano))
	binary.LittleEndian.PutUint64(buf[ancOffNextSeq:], a.nextSeq)
	binary.LittleEndian.PutUint64(buf[ancOffNextLSN:], a.nextLSN)
	binary.LittleEndian.PutUint64(buf[ancOffFirstLSN:], a.firstLSN)
	binary.LittleEndian.PutUint64(buf[ancOffCommitSeq:], a.commitSeq)
	binary.LittleEndian.PutUint32(buf[ancOffActiveKeyID:], a.activeKeyID)
	binary.LittleEndian.PutUint32(buf[ancOffGapCount:], uint32(len(a.gaps)))
	binary.LittleEndian.PutUint64(buf[ancOffActiveKCV:], a.activeKeyKCV)
	off := int(anchorHeaderSize)
	for _, iv := range a.gaps {
		binary.LittleEndian.PutUint64(buf[off:], iv.Start)
		binary.LittleEndian.PutUint64(buf[off+8:], iv.End)
		off += ancGapSize
	}
	binary.LittleEndian.PutUint32(buf[off:], checksum(buf[:off]))
	return buf
}

// decodeAnchor decodes and validates one anchor. A CRC or magic failure is
// reported as absent (valid=false) because the anchor is redundant state; an
// unsupported version is an error so an older binary never overwrites a newer
// format. | decodeAnchor 解码并校验锚点。CRC/magic 失败按“不存在”处理
// （锚点是冗余状态）；未知版本返回错误，避免旧二进制覆盖新格式。
func decodeAnchor(data []byte) (anchorState, bool, error) {
	if len(data) < int(anchorHeaderSize)+anchorTrailerSize {
		return anchorState{}, false, nil
	}
	if string(data[ancOffMagic:ancOffMagic+8]) != anchorMagic {
		return anchorState{}, false, nil
	}
	version := binary.LittleEndian.Uint16(data[ancOffVersion:])
	if version != anchorVersion {
		if version > anchorVersion {
			return anchorState{}, false, errs.Detail(ErrUnsupported, "recovery anchor version %[1]d is newer than %[2]d | 恢复锚点版本 %[1]d 高于 %[2]d",
				version, anchorVersion)
		}
		return anchorState{}, false, nil
	}
	if binary.LittleEndian.Uint32(data[ancOffHeaderSize:]) != anchorHeaderSize {
		return anchorState{}, false, nil
	}
	body := data[:len(data)-anchorTrailerSize]
	if got, want := binary.LittleEndian.Uint32(data[len(data)-anchorTrailerSize:]), checksum(body); got != want {
		return anchorState{}, false, nil
	}
	gapCount := int(binary.LittleEndian.Uint32(data[ancOffGapCount:]))
	if gapCount < 0 || gapCount > anchorMaxGaps || int(anchorHeaderSize)+gapCount*ancGapSize != len(body) {
		return anchorState{}, false, nil
	}
	a := anchorState{
		flags:        binary.LittleEndian.Uint16(data[ancOffFlags:]),
		generation:   binary.LittleEndian.Uint64(data[ancOffGeneration:]),
		createdNano:  int64(binary.LittleEndian.Uint64(data[ancOffCreatedNano:])),
		nextSeq:      binary.LittleEndian.Uint64(data[ancOffNextSeq:]),
		nextLSN:      binary.LittleEndian.Uint64(data[ancOffNextLSN:]),
		firstLSN:     binary.LittleEndian.Uint64(data[ancOffFirstLSN:]),
		commitSeq:    binary.LittleEndian.Uint64(data[ancOffCommitSeq:]),
		activeKeyID:  binary.LittleEndian.Uint32(data[ancOffActiveKeyID:]),
		activeKeyKCV: binary.LittleEndian.Uint64(data[ancOffActiveKCV:]),
	}
	copy(a.walID[:], data[ancOffWalID:])
	if a.flags&^metaKnownFlags != 0 || a.generation == 0 || a.nextSeq == 0 ||
		a.firstLSN == 0 || a.nextLSN < a.firstLSN || a.walID == ([16]byte{}) {
		return anchorState{}, false, nil
	}
	if (a.flags&metaFlagEncrypted != 0) != (a.activeKeyID != 0) {
		return anchorState{}, false, nil
	}
	hashAlg := (a.flags >> metaFlagHashShift) & metaFlagHashMask
	if a.flags&metaFlagSerializable == 0 && hashAlg != 0 {
		return anchorState{}, false, nil
	}
	if hashAlg > uint16(HashSM3) {
		return anchorState{}, false, nil
	}
	off := int(anchorHeaderSize)
	var prevEnd uint64
	for i := 0; i < gapCount; i++ {
		g := lsnGap{
			Start: binary.LittleEndian.Uint64(body[off:]),
			End:   binary.LittleEndian.Uint64(body[off+8:]),
		}
		off += ancGapSize
		if g.Start == 0 || g.Start > g.End || g.End >= a.nextLSN || (i > 0 && g.Start <= prevEnd+1) {
			return anchorState{}, false, nil
		}
		prevEnd = g.End
		a.gaps = append(a.gaps, g)
	}
	return a, true, nil
}

// decodeAnchorSlot decodes the variable-length anchor stored at the start of
// one fixed slot. | decodeAnchorSlot 解码固定槽起始处的变长锚点。
func decodeAnchorSlot(data []byte) (anchorState, bool, error) {
	if len(data) < int(anchorHeaderSize) {
		return anchorState{}, false, nil
	}
	gapCount := int(binary.LittleEndian.Uint32(data[ancOffGapCount:]))
	if gapCount < 0 || gapCount > anchorMaxGaps {
		return anchorState{}, false, nil
	}
	encLen := int(anchorHeaderSize) + gapCount*ancGapSize + anchorTrailerSize
	if encLen > len(data) {
		return anchorState{}, false, nil
	}
	return decodeAnchor(data[:encLen])
}

// anchorStore owns the two-slot recovery anchor file. Writes alternate slots
// and are synchronized in place, so a torn slot never destroys the previous
// generation. | anchorStore 管理双槽恢复锚点文件；写入交替使用两个槽并原位
// 同步，因此撕裂槽不会破坏上一代。
type anchorStore struct {
	f     *os.File
	path  string
	state anchorState
	slot  int
	mu    sync.Mutex
	mode  os.FileMode
	has   bool
}

// openAnchorStore reads both anchor slots. A missing file is an empty store. |
// openAnchorStore 读取两个锚点槽；文件缺失时返回空存储。
func openAnchorStore(path string, mode os.FileMode) (*anchorStore, error) {
	s := &anchorStore{path: path, mode: mode, slot: -1}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, errs.WrapDetail(err, ErrStorage, "read recovery anchor | 读取恢复锚点失败")
	}
	if len(data) > anchorFileSize {
		data = data[:anchorFileSize]
	}
	for slot := 0; slot < 2; slot++ {
		off := slot * anchorSlotMaxSize
		if off >= len(data) {
			continue
		}
		st, ok, err := decodeAnchorSlot(data[off:])
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		if !s.has || st.generation > s.state.generation {
			s.state = st
			s.has = true
			s.slot = slot
		}
	}
	return s, nil
}

// write stores st in the slot not holding the current generation. | write 把 st
// 写入不持有当前代的槽。
func (s *anchorStore) write(st anchorState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	newFile := false
	if s.f == nil {
		if _, statErr := os.Stat(s.path); os.IsNotExist(statErr) {
			newFile = true
		}
		f, err := os.OpenFile(s.path, os.O_CREATE|os.O_RDWR, s.mode)
		if err != nil {
			return errs.WrapDetail(err, ErrStorage, "open recovery anchor for write | 打开恢复锚点写入失败")
		}
		s.f = f
	}
	info, err := s.f.Stat()
	if err != nil {
		return errs.WrapDetail(err, ErrStorage, "stat recovery anchor | 检查恢复锚点失败")
	}
	if info.Size() < int64(anchorFileSize) {
		if err := s.f.Truncate(int64(anchorFileSize)); err != nil {
			return errs.WrapDetail(err, ErrStorage, "size recovery anchor | 扩展恢复锚点失败")
		}
	}
	slot := 0
	if s.has {
		slot = 1 - s.slot
	}
	data := encodeAnchor(st)
	if _, err := s.f.WriteAt(data, int64(slot*anchorSlotMaxSize)); err != nil {
		return errs.WrapDetail(err, ErrStorage, "write recovery anchor | 写入恢复锚点失败")
	}
	if err := syncMetaFile(s.f); err != nil {
		return errs.WrapDetail(err, ErrStorage, "sync recovery anchor | 同步恢复锚点失败")
	}
	if newFile {
		if err := syncDir(filepath.Dir(s.path)); err != nil {
			return errs.WrapDetail(err, ErrStorage, "sync recovery anchor directory | 同步恢复锚点目录失败")
		}
	}
	s.slot = slot
	s.state = st
	s.has = true
	return nil
}

// close releases the anchor handle. | close 释放锚点句柄。
func (s *anchorStore) close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f != nil {
		err := s.f.Close()
		s.f = nil
		return err
	}
	return nil
}

// loadAnchor reads the anchor file. A missing or corrupt anchor is absent. |
// loadAnchor 读取锚点文件；缺失或损坏视为不存在。
func loadAnchor(dir string) (anchorState, bool, error) {
	s, err := openAnchorStore(anchorPath(dir), defaultFileMode)
	if err != nil {
		return anchorState{}, false, err
	}
	defer s.close()
	return s.state, s.has, nil
}

// writeAnchorFile creates a fresh two-slot anchor file, used by restore. |
// writeAnchorFile 创建全新的双槽锚点文件，供恢复使用。
func writeAnchorFile(path string, st anchorState, mode os.FileMode) error {
	data := make([]byte, anchorFileSize)
	copy(data[:anchorSlotMaxSize], encodeAnchor(st))
	return writeFileAtomic(path, data, mode)
}

// anchorSnapshot builds the current durable state for the recovery anchor. |
// anchorSnapshot 构建恢复锚点所需的当前持久状态。
func (w *WAL) anchorSnapshot() anchorState {
	meta := w.metaSnapshot()
	return anchorState{
		flags:        meta.flags &^ metaFlagAnchor,
		walID:        w.walID,
		createdNano:  w.createdNano,
		nextSeq:      w.nextSeq,
		nextLSN:      w.nextLSN,
		firstLSN:     w.firstLSN,
		commitSeq:    w.commitSeq,
		activeKeyID:  w.activeKeyID,
		activeKeyKCV: w.activeKCV,
		gaps:         w.gaps.snapshot(),
	}
}

// persistAnchorIfChanged writes the recovery anchor when the durable state
// differs from the last copy. It is called only from the single writer,
// Open, and Close. | persistAnchorIfChanged 在持久状态与上一份副本不同时写入
// 恢复锚点；只由单写协程、Open 与 Close 调用。
func (w *WAL) persistAnchorIfChanged() error {
	if w.opts.readOnly || w.dir == "" {
		return nil
	}
	cur := w.anchorSnapshot()
	if cur.firstLSN == 0 || cur.nextLSN < cur.firstLSN || cur.walID == ([16]byte{}) {
		return errs.Detail(ErrCorrupt, "refusing to persist an incomplete recovery anchor | 拒绝持久化不完整的恢复锚点")
	}
	w.anchorMu.Lock()
	defer w.anchorMu.Unlock()
	if w.anchorFile == nil {
		st, err := openAnchorStore(anchorPath(w.dir), w.opts.fileMode)
		if err != nil {
			return err
		}
		w.anchorFile = st
		if st.has {
			w.anchor = &st.state
		}
	}
	if w.anchorFile.has && w.anchorFile.state.walID == cur.walID {
		// Never overwrite a newer anchor with older high-water values when the
		// clean open deferred the anchor read. | 干净打开延迟读取锚点时，绝不能用
		// 更旧的高水位覆盖更新的锚点。
		a := w.anchorFile.state
		cur.firstLSN = maxU64(cur.firstLSN, a.firstLSN)
		cur.nextLSN = maxU64(cur.nextLSN, a.nextLSN)
		cur.nextSeq = maxU64(cur.nextSeq, a.nextSeq)
		cur.commitSeq = maxU64(cur.commitSeq, a.commitSeq)
		if cur.createdNano == 0 {
			cur.createdNano = a.createdNano
		}
		if cur.activeKeyID == 0 {
			cur.activeKeyID = a.activeKeyID
			cur.activeKeyKCV = a.activeKeyKCV
		}
		gaps := newGapSet()
		gaps.merge(cur.gaps)
		gaps.merge(a.gaps)
		cur.gaps = gaps.snapshot()
	}
	if w.anchor != nil && anchorEqual(*w.anchor, cur) {
		w.anchorPersisted = true
		w.stateDirty.Store(false)
		return nil
	}
	if w.anchorFile.has {
		cur.generation = w.anchorFile.state.generation + 1
	} else {
		cur.generation = 1
	}
	if err := w.anchorFile.write(cur); err != nil {
		return err
	}
	w.anchor = &w.anchorFile.state
	w.anchorPersisted = true
	w.stateDirty.Store(false)
	return nil
}

// queueRecoveryReport records a recovery event for the ErrorHandler. Reports
// are delivered after Open completes, never from inside the recovery scan. |
// queueRecoveryReport 记录一个恢复事件交给 ErrorHandler；在 Open 完成后投递，
// 绝不在恢复扫描内部调用用户回调。
func (w *WAL) queueRecoveryReport(err error) {
	if err != nil {
		w.recoveryReports = append(w.recoveryReports, err)
	}
}

// flushRecoveryReports delivers queued recovery events. | flushRecoveryReports
// 投递排队的恢复事件。
func (w *WAL) flushRecoveryReports() {
	for _, err := range w.recoveryReports {
		w.reportAsync(err)
	}
	w.recoveryReports = nil
}

// anchorEqual reports whether two anchors carry the same durable state. The
// generation is deliberately ignored. | anchorEqual 返回两个锚点是否携带相同
// 持久状态；generation 故意忽略。
func anchorEqual(a, b anchorState) bool {
	if a.flags != b.flags || a.walID != b.walID || a.createdNano != b.createdNano ||
		a.nextSeq != b.nextSeq || a.nextLSN != b.nextLSN || a.firstLSN != b.firstLSN ||
		a.commitSeq != b.commitSeq || a.activeKeyID != b.activeKeyID ||
		a.activeKeyKCV != b.activeKeyKCV || len(a.gaps) != len(b.gaps) {
		return false
	}
	for i := range a.gaps {
		if a.gaps[i] != b.gaps[i] {
			return false
		}
	}
	return true
}
