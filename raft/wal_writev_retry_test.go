//go:build darwin || linux || openbsd || illumos

package raft

import (
	"bytes"
	"io"
	"testing"
)

// TestWritevLoopEmptyRemainderSucceeds verifies a short write that ends exactly
// before a trailing empty part does not issue a zero-length writev and does not
// report a storage failure. This is the shape produced when the WAL record ends
// with an entry whose data is empty. | TestWritevLoopEmptyRemainderSucceeds 验证
// 恰好停在尾部空分段之前的短写不会再发出零长度 writev，也不会报存储失败。WAL
// 记录以空 Data 日志项结尾时正是这种形状。
func TestWritevLoopEmptyRemainderSucceeds(t *testing.T) {
	parts := [][]byte{[]byte("head"), []byte("payload"), {}}
	calls := 0
	err := writevLoop(parts, func(vec [][]byte) (int, error) {
		calls++
		if calls == 1 {
			// Short write: all non-empty bytes, leaving only the empty tail. |
			// 短写：写入全部非空字节，只剩尾部空分段。
			return len("head") + len("payload"), nil
		}
		return 0, nil
	})
	if err != nil {
		t.Fatalf("writevLoop: %v", err)
	}
	if calls != 1 {
		t.Fatalf("write calls = %d, want 1 (empty remainder must not reach writev)", calls)
	}
}

// TestWritevLoopShortWritesRetryRemainder verifies subsequent short writes are
// retried with only the remaining bytes. | TestWritevLoopShortWritesRetryRemainder
// 验证后续短写仅携带剩余字节重试。
func TestWritevLoopShortWritesRetryRemainder(t *testing.T) {
	parts := [][]byte{[]byte("abc"), []byte("def")}
	var got [][]byte
	calls := 0
	err := writevLoop(parts, func(vec [][]byte) (int, error) {
		calls++
		joined := bytes.Join(vec, nil)
		got = append(got, joined)
		switch calls {
		case 1:
			return 2, nil
		case 2:
			return 1, nil
		default:
			return len(joined), nil
		}
	})
	if err != nil {
		t.Fatalf("writevLoop: %v", err)
	}
	if calls != 3 {
		t.Fatalf("write calls = %d, want 3", calls)
	}
	if string(got[0]) != "abcdef" || string(got[1]) != "cdef" || string(got[2]) != "def" {
		t.Fatalf("write payloads = %q", got)
	}
}

// TestWritevLoopAllEmptyPartsSucceeds verifies an empty record is a no-op. |
// TestWritevLoopAllEmptyPartsSucceeds 验证空记录是无操作。
func TestWritevLoopAllEmptyPartsSucceeds(t *testing.T) {
	if err := writevLoop([][]byte{{}, {}}, func([][]byte) (int, error) {
		t.Fatal("writev must not be called for empty parts")
		return 0, nil
	}); err != nil {
		t.Fatalf("writevLoop: %v", err)
	}
}

// TestWritevLoopZeroWriteWithDataFails verifies a zero-byte result with data
// pending remains a storage failure. | TestWritevLoopZeroWriteWithDataFails 验证
// 仍有数据待写时返回零字节仍是存储失败。
func TestWritevLoopZeroWriteWithDataFails(t *testing.T) {
	err := writevLoop([][]byte{[]byte("abc")}, func([][]byte) (int, error) {
		return 0, nil
	})
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("wrote 0 bytes")) {
		t.Fatalf("error = %v, want zero-byte storage failure", err)
	}
}

// TestWritevLoopPropagatesWriteError verifies write errors are preserved. |
// TestWritevLoopPropagatesWriteError 验证写错误被保留。
func TestWritevLoopPropagatesWriteError(t *testing.T) {
	err := writevLoop([][]byte{[]byte("abc")}, func([][]byte) (int, error) {
		return 0, io.ErrClosedPipe
	})
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte(io.ErrClosedPipe.Error())) {
		t.Fatalf("error = %v, want wrapped closed pipe", err)
	}
}
