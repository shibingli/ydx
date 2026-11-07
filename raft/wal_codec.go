package raft

import (
	"encoding/binary"
	"hash/crc32"

	"github.com/shibingli/ydx/errs"
)

const (
	// maxWALRecord is the largest encoded batch stored in one ydx/wal record. |
	// maxWALRecord 是单条 ydx/wal 记录中存储的编码批次上限。
	maxWALRecord     = 256 << 20
	walFlagState     = 1 << 0
	walFlagTrunc     = 1 << 1
	walFlagEntry     = 1 << 2
	walFlagSnap      = 1 << 3
	walFlagSnapReset = 1 << 4
	walKnownFlags    = walFlagState | walFlagTrunc | walFlagEntry | walFlagSnap | walFlagSnapReset
)

// castagnoli is the CRC32C table shared by WAL batches, hard state and snapshot
// images. | castagnoli 是 WAL 批次、硬状态与快照镜像共用的 CRC32C 表。
var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// walBatch is the decoded payload of one WAL record. | walBatch 是一条 WAL 记录的
// 解码载荷。
type walBatch struct {
	hs          *HardState
	entries     []Entry
	truncate    uint64
	snapIndex   uint64
	snapTerm    uint64
	hasSnapshot bool
	snapReset   bool
}

// snapshotMarker is the newest snapshot referenced by the WAL. | snapshotMarker
// 是 WAL 引用的最新快照。
type snapshotMarker struct {
	index uint64
	term  uint64
	found bool
}

// walRecovery is the reconstructed state. | walRecovery 是重建后的状态。
type walRecovery struct {
	entries  []Entry
	hs       HardState
	base     uint64
	sawState bool
}

// apply merges one decoded record into the recovery state. | apply 将一条解码记录合并
// 进恢复状态。
func (rec *walRecovery) apply(b walBatch) error {
	if b.hs != nil {
		rec.hs = *b.hs
		rec.sawState = true
	}
	if b.truncate > 0 {
		cut := len(rec.entries)
		for cut > 0 && rec.entries[cut-1].Index >= b.truncate {
			cut--
		}
		rec.entries = rec.entries[:cut]
	}
	if b.hasSnapshot {
		// Markers advance the log base. Entries collected from earlier segments
		// that the new base covers are dropped here rather than retained until
		// the final snapshot is known. The snapshot file itself is opened after
		// the scan, so a marker without a durable image still fails recovery.
		// | 标记推进日志基点。此前分段中已被新基点覆盖的日志项在此丢弃，而不是保留到
		// 最终快照确定。快照文件在扫描后打开，因此缺少持久镜像的标记仍会让恢复失败。
		if b.snapIndex >= rec.base {
			rec.base = b.snapIndex
			cut := 0
			for cut < len(rec.entries) && rec.entries[cut].Index <= rec.base {
				cut++
			}
			if cut > 0 {
				rec.entries = append([]Entry(nil), rec.entries[cut:]...)
			}
		}
		if b.snapReset && b.snapIndex >= rec.base {
			// InstallSnapshot makes every older entry stale, including entries
			// scanned from records that precede the marker. | InstallSnapshot 使
			// 所有更旧日志项失效，包括标记之前记录中已扫描到的日志项。
			rec.entries = nil
		}
	}
	for i := range b.entries {
		e := b.entries[i]
		if e.Index <= rec.base {
			continue
		}
		if len(rec.entries) == 0 {
			if e.Index != rec.base+1 {
				return errs.Detail(ErrCorrupt, "WAL gap: entry %d after snapshot %d", e.Index, rec.base)
			}
			rec.entries = append(rec.entries, e)
			continue
		}
		last := rec.entries[len(rec.entries)-1]
		switch {
		case e.Index == last.Index+1:
			rec.entries = append(rec.entries, e)
		case e.Index <= last.Index:
			cut := int(e.Index - rec.entries[0].Index)
			if cut < 0 {
				return errs.Detail(ErrCorrupt, "WAL entry %d before base", e.Index)
			}
			if cut < len(rec.entries) && rec.entries[cut].Term == e.Term {
				continue
			}
			if cut < len(rec.entries) {
				rec.entries = rec.entries[:cut]
			}
			rec.entries = append(rec.entries, e)
		default:
			return errs.Detail(ErrCorrupt, "WAL gap: entry %d after %d", e.Index, last.Index)
		}
	}
	return nil
}

// encodeWALBatch serializes one durable batch. | encodeWALBatch 序列化一个持久批次。
func encodeWALBatch(dst []byte, batch PersistBatch) []byte {
	dst = appendWALBatchMeta(dst, batch)
	if len(batch.Entries) > 0 {
		dst = appendEntries(dst, batch.Entries)
	}
	return dst
}

// appendWALBatchMeta writes flags, hard state, truncate, snapshot metadata and
// the entry count. Entry headers and payloads follow separately. |
// appendWALBatchMeta 写入标志、硬状态、截断、快照元数据与日志项数量；日志项头部与
// 负载随后单独写入。
func appendWALBatchMeta(dst []byte, batch PersistBatch) []byte {
	flags := byte(0)
	if batch.HardState != nil {
		flags |= walFlagState
	}
	if batch.Truncate > 0 {
		flags |= walFlagTrunc
	}
	if len(batch.Entries) > 0 {
		flags |= walFlagEntry
	}
	if batch.Snapshot != nil {
		flags |= walFlagSnap
		if batch.SnapshotReplacesLog {
			flags |= walFlagSnapReset
		}
	}
	dst = append(dst, flags)
	if batch.HardState != nil {
		dst = binary.AppendUvarint(dst, batch.HardState.Term)
		dst = binary.AppendUvarint(dst, uint64(batch.HardState.Vote))
		dst = binary.AppendUvarint(dst, batch.HardState.Commit)
	}
	if batch.Truncate > 0 {
		dst = binary.AppendUvarint(dst, batch.Truncate)
	}
	if batch.Snapshot != nil {
		dst = binary.AppendUvarint(dst, batch.Snapshot.Index)
		dst = binary.AppendUvarint(dst, batch.Snapshot.Term)
	}
	return dst
}

// decodeWALBatch parses one durable batch. | decodeWALBatch 解析一个持久批次。
func decodeWALBatch(data []byte) (walBatch, error) {
	d := decoder{src: data, allowDuplicateIndex: true}
	flags := d.byte()
	if d.err != nil {
		return walBatch{}, d.err
	}
	if flags == 0 || flags&^walKnownFlags != 0 {
		return walBatch{}, errs.Detail(ErrCorrupt, "WAL flags %d", flags)
	}
	var out walBatch
	if flags&walFlagState != 0 {
		hs := HardState{
			Term:   d.uvarint(),
			Vote:   NodeID(d.uvarint()),
			Commit: d.uvarint(),
		}
		out.hs = &hs
	}
	if flags&walFlagTrunc != 0 {
		out.truncate = d.uvarint()
	}
	if flags&walFlagSnap != 0 {
		out.hasSnapshot = true
		out.snapReset = flags&walFlagSnapReset != 0
		out.snapIndex = d.uvarint()
		out.snapTerm = d.uvarint()
	}
	if flags&walFlagEntry != 0 {
		out.entries = d.entries()
	}
	if d.err != nil {
		return walBatch{}, d.err
	}
	if d.pos != len(data) {
		return walBatch{}, errs.Detail(ErrCorrupt, "trailing WAL bytes %d", len(data)-d.pos)
	}
	return out, nil
}
