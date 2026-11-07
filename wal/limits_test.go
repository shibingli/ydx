package wal

import (
	"context"
	"errors"
	"math"
	"testing"
)

// TestLSNExhaustionReturnsTooLarge verifies that the writer refuses a batch
// before the LSN counter can wrap to zero. | 验证写入协程在 LSN 计数器回绕为零
// 之前拒绝批次。
func TestLSNExhaustionReturnsTooLarge(t *testing.T) {
	w, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	// No worker has started yet, so direct writes to the high-water fields are
	// race-free. | worker 尚未启动，直接写入高水位字段不存在竞争。
	w.nextLSN = math.MaxUint64 - 1
	if _, err := w.Append(context.Background(), Record{Data: []byte("last")}); err != nil {
		t.Fatalf("Append at MaxUint64-1: %v", err)
	}
	if got := w.LastLSN(); got != math.MaxUint64-1 {
		t.Fatalf("LastLSN = %d, want %d", got, uint64(math.MaxUint64-1))
	}
	if _, err := w.Append(context.Background(), Record{Data: []byte("overflow")}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Append beyond MaxUint64-1 err = %v, want ErrTooLarge", err)
	}
	if got := w.LastLSN(); got != math.MaxUint64-1 {
		t.Fatalf("LastLSN changed after refused append: %d", got)
	}
}

// TestSequenceExhaustionReturnsTooLarge verifies the segment-sequence guard. |
// 验证分段序号耗尽保护。
func TestSequenceExhaustionReturnsTooLarge(t *testing.T) {
	w, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	w.nextSeq = math.MaxUint64
	if _, err := w.Append(context.Background(), Record{Data: []byte("x")}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Append with exhausted sequence space err = %v, want ErrTooLarge", err)
	}
}

// TestBackupSetRejectsExhaustedLastLSN verifies the backup decoder cannot turn
// LastLSN+1 into zero and publish an unopenable restore set. | 验证备份解码器
// 不会把 LastLSN+1 回绕为零并发布无法打开的恢复集。
func TestBackupSetRejectsExhaustedLastLSN(t *testing.T) {
	set := BackupSet{
		WalID: [16]byte{1}, CreatedNano: 1, FirstLSN: math.MaxUint64,
		LastLSN: math.MaxUint64, NextLSN: 0, NextSeq: 2,
		Segments: []SegmentMeta{{
			Seq: 1, BaseLSN: math.MaxUint64, LastLSN: math.MaxUint64,
			Bytes: uint64(segmentHeaderSize), SegmentCRC: 1, WalID: [16]byte{1},
		}},
	}
	if _, err := EncodeBackupSet(set); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("EncodeBackupSet err = %v, want ErrCorrupt", err)
	}
}

// TestEmptyAppendBatchObservesLifecycle verifies that a zero-record batch on a
// closed WAL reports ErrClosed instead of looking successful. | 验证已关闭 WAL 上
// 的空批次返回 ErrClosed，而不是伪装成功。
func TestEmptyAppendBatchObservesLifecycle(t *testing.T) {
	w, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := w.AppendBatch(context.Background(), nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("AppendBatch(nil) after Close err = %v, want ErrClosed", err)
	}
}
