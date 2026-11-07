package wal

import (
	"bytes"
	"context"
	"testing"
	"time"
)

// TestAppendAsyncCompletes verifies that an asynchronous append publishes its
// LSN after the record is readable and that Result is repeatable. | 验证异步
// 追加在记录可读后发布 LSN，且 Result 可重复调用。
func TestAppendAsyncCompletes(t *testing.T) {
	w, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	data := bytes.Repeat([]byte("async-"), 64)
	future, err := w.AppendAsync(Record{Key: []byte("k"), Data: data})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-future.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("async append did not complete")
	}
	lsn, err := future.Result()
	if err != nil {
		t.Fatal(err)
	}
	if lsn != 1 {
		t.Fatalf("async LSN = %d, want 1", lsn)
	}
	rec, err := w.Read(lsn)
	if err != nil || !bytes.Equal(rec.Data, data) {
		t.Fatalf("read async record: %q/%v", rec.Data, err)
	}
	again, err := future.Result()
	if err != nil || again != lsn {
		t.Fatalf("repeated Result = %d/%v, want %d/nil", again, err, lsn)
	}
	waitCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	waited, err := future.Wait(waitCtx)
	if err != nil || waited != lsn {
		t.Fatalf("Wait = %d/%v, want %d/nil", waited, err, lsn)
	}
}
