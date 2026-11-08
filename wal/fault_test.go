package wal

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shibingli/ydx/errs"
)

// faultEngine injects write/sync failures and counts every engine call. |
// faultEngine 注入写/同步失败并统计每次引擎调用。
type faultEngine struct {
	writeCalls atomic.Int64
	syncCalls  atomic.Int64
	readCalls  atomic.Int64
	failWrite  atomic.Int64
	failSync   atomic.Int64
}

func (e *faultEngine) take(calls, failAt *atomic.Int64) bool {
	n := calls.Add(1)
	want := failAt.Load()
	return want > 0 && n == want
}

func (e *faultEngine) WriteAt(f *os.File, parts [][]byte, off int64, syncData bool) error {
	if e.take(&e.writeCalls, &e.failWrite) {
		return errs.Wrap(errors.New("injected write fault"), ErrStorage)
	}
	if err := writePartsSequential(f, parts, off); err != nil {
		return wrapStorage("fault engine write", err)
	}
	if syncData {
		return e.Sync(f)
	}
	return nil
}

func (e *faultEngine) Sync(f *os.File) error {
	if e.take(&e.syncCalls, &e.failSync) {
		return errs.Wrap(errors.New("injected sync fault"), ErrStorage)
	}
	return syncDataFile(f, true)
}

func (e *faultEngine) ReadAt(f *os.File, dst []byte, off int64) (int, error) {
	e.readCalls.Add(1)
	total := 0
	for total < len(dst) {
		n, err := readAtOnce(f, dst[total:], off+int64(total))
		total += n
		if err != nil {
			if err == io.EOF && total == len(dst) {
				return total, nil
			}
			return total, err
		}
		if n == 0 {
			return total, io.ErrNoProgress
		}
	}
	return total, nil
}

func (e *faultEngine) Close() error { return nil }

// TestReadUsesIOEngine proves that random reads are routed through the
// configured engine, not around it. | 验证随机读经过配置的引擎，而不是绕过它。
func TestReadUsesIOEngine(t *testing.T) {
	engine := &faultEngine{}
	dir := t.TempDir()
	w, err := Open(dir, WithIOEngine(engine))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(context.Background(), Record{Data: []byte("engine")}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Read(1); err != nil {
		t.Fatal(err)
	}
	if engine.readCalls.Load() == 0 {
		t.Fatal("Read bypassed the IOEngine.ReadAt")
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestFaultWritePoisonsWithoutPartialBatch verifies that an injected write
// failure poisons the WAL and never leaves a partially visible batch. |
// 验证注入的写失败会 poison WAL，且不会留下部分可见批次。
func TestFaultWritePoisonsWithoutPartialBatch(t *testing.T) {
	engine := &faultEngine{}
	engine.failWrite.Store(2)
	dir := t.TempDir()
	w, err := Open(dir, WithIOEngine(engine))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := w.Append(ctx, Record{Data: []byte("first")}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(ctx, Record{Data: []byte("second")}); !errors.Is(err, ErrStorage) {
		t.Fatalf("second append err = %v, want ErrStorage", err)
	}
	if _, err := w.Append(ctx, Record{Data: []byte("third")}); !errors.Is(err, ErrStorage) {
		t.Fatalf("append after poison err = %v, want ErrStorage", err)
	}
	if !w.Stats().Poisoned {
		t.Fatal("WAL was not poisoned")
	}
	_ = w.Close()
	w2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer w2.Close()
	if err := w2.Verify(ctx); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got := w2.LastLSN(); got != 1 {
		t.Fatalf("LastLSN = %d, want 1", got)
	}
	rec, err := w2.Read(1)
	if err != nil || !bytes.Equal(rec.Data, []byte("first")) {
		t.Fatalf("Read = %q, %v", rec.Data, err)
	}
}

// TestFaultReadFlushFailurePoisons verifies that a read lease whose write
// buffer flush fails poisons the WAL instead of silently losing acknowledged
// records and later appending past a hole. | 验证读租约的写缓冲刷新失败会 poison
// WAL，而不是静默丢失已确认记录并在之后跨越空洞追加。
func TestFaultReadFlushFailurePoisons(t *testing.T) {
	engine := &faultEngine{}
	engine.failWrite.Store(1)
	w, _ := openBufferedWAL(t, WithIOEngine(engine))
	ctx := context.Background()
	if _, err := w.Append(ctx, Record{Data: []byte("buffered")}); err != nil {
		t.Fatal(err)
	}
	if len(w.writeBuf) == 0 {
		t.Fatal("append was not buffered")
	}
	if _, err := w.NewReader(); !errors.Is(err, ErrStorage) {
		t.Fatalf("NewReader with failing flush err = %v, want ErrStorage", err)
	}
	if !w.Stats().Poisoned {
		t.Fatal("flush failure during a read lease did not poison the WAL")
	}
	if _, err := w.Append(ctx, Record{Data: []byte("after")}); !errors.Is(err, ErrStorage) {
		t.Fatalf("Append after poisoned flush err = %v, want ErrStorage", err)
	}
}

// TestFaultSyncKeepsBatchAtomic verifies the commit-marker rule: a batch whose
// fsync failed is either fully visible or fully absent after reopen. | 验证
// 提交标记规则：fsync 失败的批次在重开后要么完整可见，要么完全不存在。
func TestFaultSyncKeepsBatchAtomic(t *testing.T) {
	for round := 0; round < 10; round++ {
		engine := &faultEngine{}
		engine.failSync.Store(1)
		dir := t.TempDir()
		w, err := Open(dir, WithIOEngine(engine))
		if err != nil {
			t.Fatal(err)
		}
		batch := []Record{
			{Data: []byte("a")}, {Data: []byte("b")}, {Data: []byte("c")},
		}
		if _, err := w.AppendBatch(context.Background(), batch); !errors.Is(err, ErrStorage) {
			t.Fatalf("round %d: err = %v, want ErrStorage", round, err)
		}
		_ = w.Close()
		w2, err := Open(dir)
		if err != nil {
			t.Fatalf("round %d: reopen: %v", round, err)
		}
		if err := w2.Verify(context.Background()); err != nil {
			t.Fatalf("round %d: verify: %v", round, err)
		}
		last := w2.LastLSN()
		if last != 0 && last != 3 {
			t.Fatalf("round %d: LastLSN = %d, want 0 or 3", round, last)
		}
		if last == 3 {
			for lsn := uint64(1); lsn <= 3; lsn++ {
				if _, err := w2.Read(lsn); err != nil {
					t.Fatalf("round %d: Read(%d): %v", round, lsn, err)
				}
			}
		}
		if err := w2.Close(); err != nil {
			t.Fatalf("round %d: close: %v", round, err)
		}
	}
}

// TestFaultConcurrentAppendsNoDeadlock injects a failure while many goroutines
// write; every caller must finish and the recovered WAL must verify. | 在多协程
// 写入时注入失败；每个调用方都必须返回，恢复后的 WAL 必须通过校验。
func TestFaultConcurrentAppendsNoDeadlock(t *testing.T) {
	engine := &faultEngine{}
	engine.failWrite.Store(40)
	dir := t.TempDir()
	w, err := Open(dir, WithIOEngine(engine))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	var wg sync.WaitGroup
	errsCh := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if _, err := w.Append(ctx, Record{Data: []byte{byte(id), byte(j)}}); err != nil {
					errsCh <- err
					return
				}
			}
		}(i)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("concurrent appends deadlocked")
	}
	close(errsCh)
	for err := range errsCh {
		if !errors.Is(err, ErrStorage) && !errors.Is(err, ErrClosed) {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	_ = w.Close()
	w2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer w2.Close()
	if err := w2.Verify(ctx); err != nil {
		t.Fatalf("verify: %v", err)
	}
}
