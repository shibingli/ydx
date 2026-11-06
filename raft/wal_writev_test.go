package raft

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"testing"
)

// canonicalWALRecord builds the byte-for-byte record used by the buffered WAL
// path. The zero-copy parts must concatenate to exactly this sequence. |
// canonicalWALRecord 构建缓冲 WAL 路径逐字节相同的记录；零拷贝分段拼接后必须与
// 其完全一致。
func canonicalWALRecord(batch PersistBatch) []byte {
	payload := append([]byte{walRecBatch}, encodeWALBatch(nil, batch)...)
	rec := make([]byte, 8+len(payload))
	copy(rec[8:], payload)
	binary.LittleEndian.PutUint32(rec[0:4], uint32(len(payload)))
	binary.LittleEndian.PutUint32(rec[4:8], crc32.Checksum(payload, castagnoli))
	return rec
}

// TestWALRecordPartsMatchContiguous verifies the split iovec encoding is
// identical to the contiguous WAL encoding for a representative batch. |
// TestWALRecordPartsMatchContiguous 验证代表性批次的分段 iovec 编码与连续 WAL
// 编码完全一致。
func TestWALRecordPartsMatchContiguous(t *testing.T) {
	hs := HardState{Term: 7, Vote: 2, Commit: 99}
	batch := PersistBatch{
		HardState: &hs,
		Truncate:  5,
		Entries: []Entry{
			{Index: 5, Term: 6, Type: EntryNormal, Data: []byte("hello")},
			{Index: 6, Term: 7, Type: EntryNormal, Data: nil},
			{Index: 7, Term: 7, Type: EntryBootstrap, Data: bytes.Repeat([]byte("x"), 300)},
		},
	}
	parts, ok := encodeWALRecordParts(batch)
	if !ok {
		t.Fatal("encodeWALRecordParts declined a valid batch")
	}
	var got []byte
	for _, part := range parts {
		got = append(got, part...)
	}
	want := canonicalWALRecord(batch)
	if !bytes.Equal(got, want) {
		t.Fatalf("split record differs from canonical record:\n got %x\nwant %x", got, want)
	}
}

// TestFileStorageLargeEntryRecovery verifies a large entry taking the zero-copy
// WAL path (when available) still recovers exactly. |
// TestFileStorageLargeEntryRecovery 验证走零拷贝 WAL 路径（可用时）的大日志项仍能
// 精确恢复。
func TestFileStorageLargeEntryRecovery(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte("large-entry-"), 16*1024)
	hs := HardState{Term: 3, Commit: 2}
	batch := PersistBatch{HardState: &hs, Entries: []Entry{
		{Index: 1, Term: 1, Type: EntryBootstrap, Data: []byte("bootstrap")},
		{Index: 2, Term: 3, Type: EntryNormal, Data: data},
	}}
	if err := s.Persist(batch); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	rec, err := reopened.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Entries) != 2 || !bytes.Equal(rec.Entries[1].Data, data) {
		t.Fatalf("recovered %d entries, data match=%v", len(rec.Entries),
			len(rec.Entries) > 1 && bytes.Equal(rec.Entries[1].Data, data))
	}
	if rec.HardState.Term != 3 || rec.HardState.Commit != 2 {
		t.Fatalf("hard state = %+v", rec.HardState)
	}
}
