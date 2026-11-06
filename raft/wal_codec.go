package raft

import (
	"encoding/binary"

	"github.com/shibingli/ydx/errs"
)

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
