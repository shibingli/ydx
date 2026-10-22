package reqlog

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shibingli/ydx/router"
)

// TestCaptureCountsStatusAndBytes proves Begin wraps the writer and End restores
// it while status and bytes are observable. | TestCaptureCountsStatusAndBytes 证明
// Begin 包装写入器、End 恢复写入器，并能观察状态码与字节数。
func TestCaptureCountsStatusAndBytes(t *testing.T) {
	rec := httptest.NewRecorder()
	c := &router.Ctx{Writer: rec}
	cap := Begin(c)
	if c.Writer != cap {
		t.Fatal("Begin did not install the capture writer")
	}
	cap.WriteHeader(http.StatusCreated)
	n, err := cap.Write([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if cap.Status() != http.StatusCreated {
		t.Fatalf("status = %d, want 201", cap.Status())
	}
	if cap.Bytes() != int64(n) {
		t.Fatalf("bytes = %d, want %d", cap.Bytes(), n)
	}
	End(c, cap)
	if c.Writer != rec {
		t.Fatal("End did not restore the original writer")
	}
}

// TestCapturePoolResetsState proves a reused capture starts at zero. |
// TestCapturePoolResetsState 证明复用的捕获器从零状态开始。
func TestCapturePoolResetsState(t *testing.T) {
	c := &router.Ctx{Writer: httptest.NewRecorder()}
	first := Begin(c)
	first.WriteHeader(http.StatusTeapot)
	_, _ = first.Write([]byte("abc"))
	End(c, first)

	second := Begin(c)
	if second.Status() != 0 || second.Bytes() != 0 {
		t.Fatalf("reused capture status=%d bytes=%d, want 0/0", second.Status(), second.Bytes())
	}
	End(c, second)
}

// readFromRecorder exposes io.ReaderFrom and records that the fast path was taken. |
// readFromRecorder 暴露 io.ReaderFrom 并记录快路径确实被使用。
type readFromRecorder struct {
	*httptest.ResponseRecorder
	used bool
}

func (w *readFromRecorder) ReadFrom(r io.Reader) (int64, error) {
	w.used = true
	return io.Copy(w.ResponseRecorder, r)
}

// TestCaptureReadFromCountsBytes proves ReadFrom delegates to the fast path when
// available and counts bytes in both cases. | TestCaptureReadFromCountsBytes 证明
// ReadFrom 在可用时委托快路径，并在两种情况下都正确计数。
func TestCaptureReadFromCountsBytes(t *testing.T) {
	const body = "reader-from-body"

	plain := httptest.NewRecorder()
	cap := &Capture{ResponseWriter: plain}
	n, err := cap.ReadFrom(strings.NewReader(body))
	if err != nil || n != int64(len(body)) {
		t.Fatalf("ReadFrom = (%d, %v), want (%d, nil)", n, err, len(body))
	}
	if cap.Bytes() != n || cap.Status() != http.StatusOK || plain.Body.String() != body {
		t.Fatalf("bytes=%d status=%d body=%q", cap.Bytes(), cap.Status(), plain.Body.String())
	}

	fast := &readFromRecorder{ResponseRecorder: httptest.NewRecorder()}
	cap = &Capture{ResponseWriter: fast}
	n, err = cap.ReadFrom(strings.NewReader(body))
	if err != nil || n != int64(len(body)) || !fast.used || cap.Bytes() != n {
		t.Fatalf("fast path: n=%d err=%v used=%v bytes=%d", n, err, fast.used, cap.Bytes())
	}
}

// TestCaptureKeepsOptionalInterfaces proves Flush and Unwrap pass through. |
// TestCaptureKeepsOptionalInterfaces 证明 Flush 与 Unwrap 透传。
func TestCaptureKeepsOptionalInterfaces(t *testing.T) {
	rec := httptest.NewRecorder()
	cap := &Capture{ResponseWriter: rec}
	cap.Flush()
	if !rec.Flushed {
		t.Fatal("Flush did not reach the underlying recorder")
	}
	if cap.Unwrap() != rec {
		t.Fatal("Unwrap did not return the original writer")
	}
}
