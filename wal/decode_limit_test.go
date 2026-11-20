package wal

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"runtime"
	"testing"
	"time"
)

// countingReader counts the bytes a decoder consumed. | countingReader 统计解码器读取的字节数。
type countingReader struct {
	r io.Reader
	n int
}

// Read implements io.Reader. | Read 实现 io.Reader。
func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// oversizedCompressedRecord builds a structurally valid record that declares
// keyLen+dataLen above the decode limit while carrying only a tiny payload. |
// oversizedCompressedRecord 构造一条结构合法、声明 keyLen+dataLen 超过解码上限但
// 实际负载很小的记录。
func oversizedCompressedRecord(t *testing.T, keyLen uint32, dataLen uint32) []byte {
	t.Helper()
	payload := []byte{0x01, 0x02, 0x03, 0x04}
	record := make([]byte, recordHeaderSize+len(payload))
	encodeRecordHeader(record, uint32(len(record)), 1, time.Now().UnixNano(), 0,
		keyLen, dataLen, recordFlagCompressed, cipherNone, codecFlate, 0)
	copy(record[recordHeaderSize:], payload)
	fillRecordCRC(record)
	return record
}

// TestDecodeStreamRejectsOversizedDeclaredLength verifies the read path applies
// the maxRecordBytes limit before reading or decompressing a record. |
// TestDecodeStreamRejectsOversizedDeclaredLength 验证读取路径在读取或解压记录之前
// 应用 maxRecordBytes 上限。
func TestDecodeStreamRejectsOversizedDeclaredLength(t *testing.T) {
	if defaultMaxRecordBytes != 16<<20 {
		t.Fatalf("defaultMaxRecordBytes = %d, 期望 16 MiB", defaultMaxRecordBytes)
	}
	w := &WAL{opts: options{maxRecordBytes: defaultMaxRecordBytes}}
	record := oversizedCompressedRecord(t, formatHardLimit, 0)

	var local [recordHeaderSizeEncrypted]byte
	tracked := &countingReader{r: bytes.NewReader(record)}
	br := bufio.NewReaderSize(tracked, recordHeaderSize)

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, _, _, _, err := w.decodeRecordStream(&segment{}, br, int64(segmentHeaderSize),
		int64(segmentHeaderSize)+int64(len(record)), nil, nil, &local)
	runtime.ReadMemStats(&after)

	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("超大声明长度错误 = %v, 期望 ErrTooLarge", err)
	}
	if tracked.n > recordHeaderSize {
		t.Fatalf("读取了 %d 字节，期望在读取负载前拒绝（仅头 %d 字节）", tracked.n, recordHeaderSize)
	}
	if delta := after.TotalAlloc - before.TotalAlloc; delta > 8<<20 {
		t.Fatalf("解码分配 %d 字节，期望有界（< 8 MiB）", delta)
	}
}

// TestDecodePayloadHonoursConfiguredLimit verifies a configured maxRecordBytes
// bounds decompression as well. | TestDecodePayloadHonoursConfiguredLimit 验证
// 配置的 maxRecordBytes 同样限制解压。
func TestDecodePayloadHonoursConfiguredLimit(t *testing.T) {
	w := &WAL{opts: options{maxRecordBytes: 128}}
	hdr := recordHeader{
		flags:     recordFlagCompressed,
		codec:     codecFlate,
		keyLen:    100,
		dataLen:   64,
		headerLen: recordHeaderSize,
	}
	_, _, _, err := w.decodePayload(nil, 0, hdr, nil, nil, nil, nil)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("decodePayload 错误 = %v, 期望 ErrTooLarge", err)
	}
}
