package wal

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// seedCommittedWAL writes one committed batch per record and returns the
// directory and the record count. Each Sync forces a commit marker, so every
// record is acknowledged by its own marker. | 每条记录一个已确认批次并返回目录
// 与记录数；每次 Sync 都会写入提交标记，因此每条记录都有独立标记确认。
func seedCommittedWAL(t *testing.T, records int) string {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	w, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < records; i++ {
		if _, err := w.Append(ctx, Record{
			Key:  []byte{'k', byte('0' + i)},
			Data: bytes.Repeat([]byte{byte('a' + i)}, 96),
		}); err != nil {
			t.Fatal(err)
		}
		if err := w.Sync(); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return dir
}

// prepareScanCopy copies a seeded WAL and removes the sidecar and MANIFEST so
// reopening must scan the segment instead of trusting a summary. | 复制种子 WAL
// 并删除侧车与 MANIFEST，使重新打开必须扫描分段而不是信任摘要。
func prepareScanCopy(t *testing.T, src string) string {
	t.Helper()
	dir := copyWALDirForTest(t, src)
	if err := os.Remove(sidecarPath(dir, 1)); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(dir, "manifest")); err != nil {
		t.Fatal(err)
	}
	return dir
}

// firstRecordHeader reads the first record header after the segment header. |
// firstRecordHeader 读取段头之后的第一条记录头。
func firstRecordHeader(t *testing.T, f *os.File) (recordHeader, int64) {
	t.Helper()
	var raw [recordHeaderSize]byte
	if err := readAtFull(f, raw[:], int64(segmentHeaderSize)); err != nil {
		t.Fatal(err)
	}
	hdr, err := parseRecordHeader(raw[:])
	if err != nil {
		t.Fatal(err)
	}
	return hdr, int64(segmentHeaderSize)
}

// TestCorruptRecordBeforeCommitMarkerIsCorrupt verifies that a damaged record
// followed by an acknowledged commit marker is reported as corruption instead
// of being silently truncated with every later committed batch. | 验证损坏记录
// 之后仍存在已确认提交标记时，打开必须报告损坏，而不是连同后续已确认批次一起
// 静默截断。
func TestCorruptRecordBeforeCommitMarkerIsCorrupt(t *testing.T) {
	src := seedCommittedWAL(t, 4)
	dir := prepareScanCopy(t, src)
	path := segmentPath(dir, 1)
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	hdr, off := firstRecordHeader(t, f)
	if hdr.flags&recordFlagCommitMark != 0 {
		_ = f.Close()
		t.Fatal("first record is a commit marker")
	}
	if plainPayloadLen(hdr) < 3 {
		_ = f.Close()
		t.Fatalf("payload too short: %d", plainPayloadLen(hdr))
	}
	pos := off + int64(hdr.headerLen) + 1
	var one [1]byte
	if err := readAtFull(f, one[:], pos); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	one[0] ^= 0xff
	if _, err := f.WriteAt(one[:], pos); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	_ = f.Close()

	if _, err := Open(dir); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Open err = %v, want ErrCorrupt (committed data after damage must not be truncated)", err)
	}
}

// commitMarkerOffsets returns the offsets of every commit marker in a segment.
// | commitMarkerOffsets 返回分段内全部提交标记的偏移。
func commitMarkerOffsets(t *testing.T, f *os.File) []int64 {
	t.Helper()
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	var out []int64
	for pos := int64(segmentHeaderSize); pos < info.Size(); {
		var raw [recordHeaderSize]byte
		if err := readAtFull(f, raw[:], pos); err != nil {
			t.Fatal(err)
		}
		hdr, err := parseRecordHeader(raw[:])
		if err != nil {
			t.Fatal(err)
		}
		if hdr.flags&recordFlagCommitMark != 0 {
			out = append(out, pos)
		}
		pos += int64(hdr.size)
	}
	return out
}

// TestCorruptMarkerBeforeLaterMarkerIsCorrupt verifies the semantic marker
// path: a commit marker whose CRC is valid but whose summary disagrees with the
// scanned prefix must not be truncated when a later valid marker exists. |
// 验证语义损坏路径：提交标记自身 CRC 有效但与扫描前缀不一致时，若其后还有有效
// 标记，不得截断已确认数据。
func TestCorruptMarkerBeforeLaterMarkerIsCorrupt(t *testing.T) {
	src := seedCommittedWAL(t, 3)
	dir := prepareScanCopy(t, src)
	path := segmentPath(dir, 1)
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	markers := commitMarkerOffsets(t, f)
	if len(markers) < 2 {
		_ = f.Close()
		t.Fatalf("commit markers = %d, want at least 2", len(markers))
	}
	target := markers[0]
	var raw [recordHeaderSize]byte
	if err := readAtFull(f, raw[:], target); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	markerHdr, err := parseRecordHeader(raw[:])
	if err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	record := make([]byte, markerHdr.size)
	if err := readAtFull(f, record, target); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	// Corrupt lastLSN inside the marker payload and recompute the record CRC so
	// the marker stays structurally valid but semantically inconsistent. | 篡改
	// 标记负载中的 lastLSN 并重算记录 CRC，使标记结构合法但语义不一致。
	payload := record[markerHdr.headerLen:]
	binary.LittleEndian.PutUint64(payload[markerOffLastLSN:], 999999)
	fillRecordCRC(record)
	if _, err := f.WriteAt(record, target); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	_ = f.Close()

	if _, err := Open(dir); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Open err = %v, want ErrCorrupt (later marker proves committed data)", err)
	}
}

// TestCorruptAcknowledgedFinalMarkerIsCorrupt verifies that a damaged final
// marker is not treated as a torn tail when durable metadata already says the
// batch was acknowledged. Truncating it would silently lose committed data. |
// 验证持久元数据已确认最后一批时，损坏的末尾标记不得按撕裂尾截断；截断会
// 静默丢失已提交数据。
func TestCorruptAcknowledgedFinalMarkerIsCorrupt(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	w, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := w.Append(ctx, Record{Key: []byte{'k', byte('0' + i)}, Data: bytes.Repeat([]byte("z"), 64)}); err != nil {
			t.Fatal(err)
		}
		if err := w.Sync(); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	copyDir := prepareScanCopy(t, dir)
	path := segmentPath(copyDir, 1)
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	markers := commitMarkerOffsets(t, f)
	if len(markers) == 0 {
		_ = f.Close()
		t.Fatal("no commit marker found")
	}
	lastMarker := markers[len(markers)-1]
	var lastRaw [recordHeaderSize]byte
	if err := readAtFull(f, lastRaw[:], lastMarker); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	hdr, err := parseRecordHeader(lastRaw[:])
	if err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	record := make([]byte, hdr.size)
	if err := readAtFull(f, record, lastMarker); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	binary.LittleEndian.PutUint64(record[hdr.headerLen+markerOffLastLSN:], 999999)
	fillRecordCRC(record)
	if _, err := f.WriteAt(record, lastMarker); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	_ = f.Close()

	w2, err := Open(copyDir)
	if !errors.Is(err, ErrCorrupt) {
		if err == nil {
			_ = w2.Close()
		}
		t.Fatalf("Open err = %v, want ErrCorrupt (durable META.nextLSN acknowledges the damaged batch)", err)
	}
}

// TestGarbageTailAfterLastMarkerIsTruncated verifies that a long tail of
// repetitive garbage after the last commit marker is discarded as an
// unacknowledged tail and that the committed prefix remains readable. |
// 验证最后一个提交标记之后的长串重复垃圾会作为未确认尾被截断，已确认前缀仍可读。
func TestGarbageTailAfterLastMarkerIsTruncated(t *testing.T) {
	src := seedCommittedWAL(t, 3)
	dir := prepareScanCopy(t, src)
	f, err := os.OpenFile(segmentPath(dir, 1), os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(bytes.Repeat([]byte{0xFF}, 1<<20)); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	_ = f.Close()

	w, err := Open(dir)
	if err != nil {
		t.Fatalf("Open with repetitive garbage tail: %v", err)
	}
	defer w.Close()
	if got := w.LastLSN(); got != 3 {
		t.Fatalf("LastLSN = %d, want 3", got)
	}
	for lsn := uint64(1); lsn <= 3; lsn++ {
		if _, err := w.Read(lsn); err != nil {
			t.Fatalf("read committed LSN %d: %v", lsn, err)
		}
	}
}
