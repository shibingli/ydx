package raft

import (
	"encoding/binary"
	"hash/crc32"
)

// maxWALWritevParts bounds the iovec count. Unix IOV_MAX is commonly 1024;
// 512 leaves ample headroom and still covers the common large-entry case. |
// maxWALWritevParts 限制 iovec 数量。Unix 的 IOV_MAX 通常为 1024；512 留出充足
// 余量，同时覆盖常见的大日志项场景。
const maxWALWritevParts = 512

// minWALWritevBytes is the payload size above which avoiding the copy into the
// WAL buffer is worthwhile. | minWALWritevBytes 是值得避免复制进 WAL 缓冲区的
// 负载大小阈值。
const minWALWritevBytes = 64 << 10

// encodeWALRecordParts builds one complete WAL record as an ordered list of
// byte slices: record header/type/meta, then each entry header and data. It
// never copies entry payloads. The concatenation is byte-identical to the
// buffered encoder. | encodeWALRecordParts 将一条完整 WAL 记录构建为有序字节切片
// 列表：记录头/类型/元数据，随后每个日志项的头部与数据。它从不复制日志项负载；
// 拼接结果与缓冲区编码逐字节一致。
func encodeWALRecordParts(batch PersistBatch) ([][]byte, bool) {
	if batch.Snapshot != nil || len(batch.Entries) == 0 {
		return nil, false
	}
	meta := appendWALBatchMeta(nil, batch)
	meta = binary.AppendUvarint(meta, uint64(len(batch.Entries)))
	head := make([]byte, 0, 8+1+len(meta))
	head = append(head, 0, 0, 0, 0, 0, 0, 0, 0, walRecBatch)
	head = append(head, meta...)
	headers := make([]byte, 0, len(batch.Entries)*32)
	parts := make([][]byte, 0, len(batch.Entries)*2+1)
	parts = append(parts, head)
	var prev uint64
	for i := range batch.Entries {
		e := &batch.Entries[i]
		start := len(headers)
		if i == 0 {
			headers = binary.AppendUvarint(headers, e.Index)
		} else {
			headers = binary.AppendUvarint(headers, e.Index-prev)
		}
		headers = binary.AppendUvarint(headers, e.Term)
		headers = append(headers, byte(e.Type))
		headers = binary.AppendUvarint(headers, uint64(len(e.Data)))
		parts = append(parts, headers[start:], e.Data)
		prev = e.Index
	}
	payloadLen := len(head) - 8
	for i := 1; i < len(parts); i++ {
		payloadLen += len(parts[i])
	}
	if payloadLen == 0 || payloadLen > maxWALRecord {
		return nil, false
	}
	binary.LittleEndian.PutUint32(head[0:4], uint32(payloadLen))
	crc := crc32.New(castagnoli)
	_, _ = crc.Write(head[8:])
	for i := 1; i < len(parts); i++ {
		if len(parts[i]) > 0 {
			_, _ = crc.Write(parts[i])
		}
	}
	binary.LittleEndian.PutUint32(head[4:8], crc.Sum32())
	return parts, true
}

// walWritevParts returns the encoded parts, total length and whether the
// zero-copy path is applicable for batch. | walWritevParts 返回编码分段、总长度
// 以及该批次是否适用零拷贝路径。
func walWritevParts(batch PersistBatch) ([][]byte, int, bool) {
	if len(batch.Entries) == 0 || batch.Snapshot != nil {
		return nil, 0, false
	}
	if len(batch.Entries)*2+1 > maxWALWritevParts {
		return nil, 0, false
	}
	total := 0
	for i := range batch.Entries {
		total += len(batch.Entries[i].Data)
	}
	if total < minWALWritevBytes {
		return nil, 0, false
	}
	parts, ok := encodeWALRecordParts(batch)
	if !ok {
		return nil, 0, false
	}
	size := 0
	for _, part := range parts {
		size += len(part)
	}
	return parts, size, true
}

// writeWALParts writes a pre-encoded record with one vectored write. | writeWALParts
// 通过一次向量写写入预编码记录。
func (w *wal) writeWALParts(parts [][]byte, size int) error {
	if w.active == nil || w.active.file == nil {
		if err := w.rotateLocked(); err != nil {
			return err
		}
	}
	if err := writevFile(w.active.file, parts); err != nil {
		return err
	}
	w.active.size += int64(size)
	return w.syncLocked()
}
