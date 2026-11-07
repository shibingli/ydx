package wal

import (
	"bytes"
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestConcurrentLifecycleNoDeadlock hammers append, read, scan, query, rotate,
// truncate, and close concurrently under a watchdog. | 在看门狗下并发压测追加、
// 读取、扫描、查询、轮转、截断与关闭。
func TestConcurrentLifecycleNoDeadlock(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir,
		WithSegmentMaxBytes(4<<10),
		WithSyncPolicy(SyncInterval(time.Millisecond)),
		WithRetention(Retention{MaxBytes: 32 << 10}),
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var opErr atomic.Pointer[error]

	record := func(err error) {
		if err == nil || errors.Is(err, ErrNotFound) || errors.Is(err, ErrMissingSegment) ||
			errors.Is(err, ErrClosed) || errors.Is(err, context.Canceled) {
			return
		}
		opErr.CompareAndSwap(nil, &err)
	}

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			payload := bytes.Repeat([]byte{byte('a' + id)}, 40)
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := w.Append(ctx, Record{Key: []byte{byte(id)}, Data: payload}); err != nil {
					record(err)
					return
				}
			}
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			last := w.LastLSN()
			if last > 0 {
				_, err := w.Read(uint64(time.Now().UnixNano())%last + 1)
				record(err)
			}
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			err := w.Scan(ctx, 0, 0, func(Record) error { return nil })
			if errors.Is(err, ErrNotFound) || errors.Is(err, ErrMissingSegment) || errors.Is(err, ErrClosed) {
				continue
			}
			record(err)
			if err != nil {
				return
			}
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := w.Query(ctx, Query{Contains: []byte("a")}, nil); err != nil {
				record(err)
				return
			}
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if err := w.Rotate(); err != nil {
				record(err)
				return
			}
			if last := w.LastLSN(); last > 2 {
				_, _ = w.Truncate(last / 2)
			}
		}
	}()

	time.AfterFunc(750*time.Millisecond, func() { close(stop) })
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("concurrent lifecycle deadlocked")
	}
	if p := opErr.Load(); p != nil {
		t.Fatalf("concurrent operation failed: %v", *p)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	w2, err := Open(dir, WithSegmentMaxBytes(4<<10))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer w2.Close()
	if err := w2.Verify(ctx); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// TestFollowReadersSeeCommittedPrefix verifies that concurrent Follow readers
// never observe a half batch and always see contiguous LSNs. | 验证并发 Follow
// 读者不会看到半批数据，且看到的 LSN 连续。
func TestFollowReadersSeeCommittedPrefix(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir, WithSyncPolicy(SyncNever()))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	var wg sync.WaitGroup
	stop := make(chan struct{})
	var failure atomic.Pointer[string]

	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reader, err := w.NewReader(Follow())
			if err != nil {
				msg := err.Error()
				failure.CompareAndSwap(nil, &msg)
				return
			}
			defer reader.Close()
			next := uint64(1)
			for {
				select {
				case <-stop:
					return
				default:
				}
				if reader.LSN() >= 400 {
					return
				}
				rec, err := reader.NextContext(ctx)
				if err == context.Canceled {
					return
				}
				if err != nil {
					msg := err.Error()
					failure.CompareAndSwap(nil, &msg)
					return
				}
				if rec.LSN != next {
					msg := "non-contiguous LSN"
					failure.CompareAndSwap(nil, &msg)
					return
				}
				next++
			}
		}()
	}
	for i := 0; i < 80; i++ {
		batch := make([]Record, 5)
		for j := range batch {
			batch[j] = Record{Data: []byte{byte(i), byte(j)}}
		}
		if _, err := w.AppendBatch(ctx, batch); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("follow readers deadlocked")
	}
	if p := failure.Load(); p != nil {
		t.Fatalf("follow reader failed: %s", *p)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestNoGoroutineLeakAfterClose verifies that Open/Append/Close cycles release
// their workers. | 验证 Open/Append/Close 循环释放 worker。
func TestNoGoroutineLeakAfterClose(t *testing.T) {
	baseline := runtime.NumGoroutine()
	for i := 0; i < 5; i++ {
		dir := t.TempDir()
		w, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Append(context.Background(), Record{Data: []byte("x")}); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= baseline+3 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("goroutines after Close = %d, baseline %d", runtime.NumGoroutine(), baseline)
}
