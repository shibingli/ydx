//go:build linux && (amd64 || arm64)

package uring

import (
	"bytes"
	"errors"
	"os"
	"sync"
	"testing"
	"unsafe"
)

// TestRingLayout pins the kernel ABI offsets; a field reorder would corrupt
// every submission. | TestRingLayout 固定内核 ABI 偏移；字段重排会破坏每次提交。
func TestRingLayout(t *testing.T) {
	var s sqe
	if got := unsafe.Sizeof(s); got != 64 {
		t.Fatalf("sqe size = %d, want 64", got)
	}
	offsets := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"opcode", unsafe.Offsetof(s.opcode), 0},
		{"flags", unsafe.Offsetof(s.flags), 1},
		{"ioprio", unsafe.Offsetof(s.ioprio), 2},
		{"fd", unsafe.Offsetof(s.fd), 4},
		{"off", unsafe.Offsetof(s.off), 8},
		{"addr", unsafe.Offsetof(s.addr), 16},
		{"length", unsafe.Offsetof(s.length), 24},
		{"rwFlags", unsafe.Offsetof(s.rwFlags), 28},
		{"userData", unsafe.Offsetof(s.userData), 32},
		{"bufIndex", unsafe.Offsetof(s.bufIndex), 40},
		{"personality", unsafe.Offsetof(s.personality), 42},
		{"spliceFD", unsafe.Offsetof(s.spliceFD), 44},
	}
	for _, o := range offsets {
		if o.got != o.want {
			t.Fatalf("sqe.%s offset = %d, want %d", o.name, o.got, o.want)
		}
	}
	var c cqe
	if got := unsafe.Sizeof(c); got != 16 {
		t.Fatalf("cqe size = %d, want 16", got)
	}
	if unsafe.Offsetof(c.userData) != 0 || unsafe.Offsetof(c.res) != 8 || unsafe.Offsetof(c.flags) != 12 {
		t.Fatalf("cqe offsets = %d/%d/%d", unsafe.Offsetof(c.userData), unsafe.Offsetof(c.res), unsafe.Offsetof(c.flags))
	}
}

// ioEngineContract mirrors wal.IOEngine without importing the wal module. |
// ioEngineContract 在不 import wal 模块的前提下镜像 wal.IOEngine。
type ioEngineContract interface {
	WriteAt(f *os.File, parts [][]byte, off int64, syncData bool) error
	ReadAt(f *os.File, dst []byte, off int64) (int, error)
	Sync(f *os.File) error
	Close() error
}

var _ ioEngineContract = (*Engine)(nil)

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	if !Supported() {
		t.Skip("io_uring is not available on this kernel")
	}
	e, err := New(WithQueueDepth(32))
	if err != nil {
		if errors.Is(err, ErrUnsupported) {
			t.Skipf("io_uring setup unsupported: %v", err)
		}
		t.Fatal(err)
	}
	return e
}

// TestWriteReadSync exercises WRITEV, READ, and FSYNC. | 覆盖 WRITEV、READ 与
// FSYNC。
func TestWriteReadSync(t *testing.T) {
	e := newTestEngine(t)
	defer e.Close()
	f, err := os.CreateTemp(t.TempDir(), "uring")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	parts := [][]byte{[]byte("hello "), nil, []byte("io_uring")}
	if err := e.WriteAt(f, parts, 0, true); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	want := []byte("hello io_uring")
	dst := make([]byte, len(want))
	n, err := e.ReadAt(f, dst, 0)
	if err != nil || n != len(want) {
		t.Fatalf("ReadAt n=%d err=%v", n, err)
	}
	if !bytes.Equal(dst, want) {
		t.Fatalf("ReadAt = %q, want %q", dst, want)
	}
	if err := e.Sync(f); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	// A read at EOF reports io.EOF. | 在 EOF 读取返回 io.EOF。
	_, err = e.ReadAt(f, make([]byte, 1), int64(len(want)))
	if err == nil {
		t.Fatal("ReadAt at EOF returned nil error")
	}
}

// TestChunkedWrite exercises more than one iovec chunk. | 覆盖多 iovec 分块写入。
func TestChunkedWrite(t *testing.T) {
	e := newTestEngine(t)
	defer e.Close()
	f, err := os.CreateTemp(t.TempDir(), "uring-chunks")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	const parts = 1500
	data := make([][]byte, parts)
	var want []byte
	for i := range data {
		data[i] = bytes.Repeat([]byte{byte(i)}, 8)
		want = append(want, data[i]...)
	}
	if err := e.WriteAt(f, data, 0, false); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	dst := make([]byte, len(want))
	if n, err := e.ReadAt(f, dst, 0); err != nil || n != len(want) {
		t.Fatalf("ReadAt n=%d err=%v", n, err)
	}
	if !bytes.Equal(dst, want) {
		t.Fatal("chunked data mismatch")
	}
}

// TestConcurrentReads verifies the ring mutex serializes concurrent readers. |
// 验证 ring 互斥量串行化并发读者。
func TestConcurrentReads(t *testing.T) {
	e := newTestEngine(t)
	defer e.Close()
	f, err := os.CreateTemp(t.TempDir(), "uring-reads")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	want := bytes.Repeat([]byte("0123456789abcdef"), 64)
	if err := e.WriteAt(f, [][]byte{want}, 0, true); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(off int) {
			defer wg.Done()
			dst := make([]byte, 32)
			for j := 0; j < 100; j++ {
				n, err := e.ReadAt(f, dst, int64((off+j)%(len(want)-len(dst))))
				if err != nil || n != len(dst) {
					t.Errorf("ReadAt n=%d err=%v", n, err)
					return
				}
			}
		}(i * 7)
	}
	wg.Wait()
}

// TestCloseIdempotent verifies repeated Close calls are safe. | 验证重复 Close 安全。
func TestCloseIdempotent(t *testing.T) {
	e := newTestEngine(t)
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
}
