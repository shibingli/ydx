package router

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
)

// TestAdaptRunsMiddlewareAroundPlainHandler proves the chain order is
// middleware 1 → middleware 2 → handler. | TestAdaptRunsMiddlewareAroundPlainHandler
// 证明调用顺序是中间件 1 → 中间件 2 → 处理器。
func TestAdaptRunsMiddlewareAroundPlainHandler(t *testing.T) {
	var order []string
	mw := func(name string) Middleware {
		return func(c *Ctx) {
			order = append(order, name)
			c.Next()
		}
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		order = append(order, "handler")
		w.WriteHeader(http.StatusNoContent)
	})

	adapted := Adapt(h, mw("mw1"), mw("mw2"))
	rec := httptest.NewRecorder()
	adapted.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	want := []string{"mw1", "mw2", "handler"}
	if len(order) != len(want) {
		t.Fatalf("order = %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("order = %v, want %v", order, want)
		}
	}
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

// TestAdaptAbortSkipsNext proves Abort stops the chain before the handler. |
// TestAdaptAbortSkipsNext 证明 Abort 会在处理器之前终止链。
func TestAdaptAbortSkipsNext(t *testing.T) {
	called := false
	h := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })
	mw := func(c *Ctx) {
		c.Abort()
		c.SetHeader("X-Aborted", "1")
	}

	rec := httptest.NewRecorder()
	Adapt(h, mw).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if called {
		t.Fatal("handler must not run after Abort")
	}
	if got := rec.Header().Get("X-Aborted"); got != "1" {
		t.Fatalf("X-Aborted = %q, want 1", got)
	}
}

// TestAdaptPanicPropagates proves a panic is re-raised after the Ctx is
// returned to the pool, and the next request is unaffected. |
// TestAdaptPanicPropagates 证明 panic 在 Ctx 归还池后原样重抛，且下一次请求不受影响。
func TestAdaptPanicPropagates(t *testing.T) {
	sentinel := errors.New("boom")
	panicOnce := true
	h := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		if panicOnce {
			panicOnce = false
			panic(sentinel)
		}
	})
	adapted := Adapt(h)

	func() {
		defer func() {
			if got := recover(); got != sentinel {
				t.Fatalf("recovered %v, want %v", got, sentinel)
			}
		}()
		adapted.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	}()

	// The context must be clean after the panic path. | panic 路径之后上下文必须干净。
	adapted.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
}

// TestAdaptConcurrentReuseIsIsolated proves concurrent requests do not share
// Ctx keys. | TestAdaptConcurrentReuseIsIsolated 证明并发请求不共享 Ctx 键。
func TestAdaptConcurrentReuseIsIsolated(t *testing.T) {
	const n = 128
	var wg sync.WaitGroup
	var mismatches int64
	wg.Add(n)
	adapted := Adapt(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}),
		func(c *Ctx) {
			// Each request writes its own path; a leaked Ctx key would show up
			// as a mismatch in the next middleware. | 每个请求写入自己的路径；Ctx
			// 键泄漏会在下一个中间件中表现为不匹配。
			c.Set("id", c.Request.URL.Path)
			c.Next()
		},
		func(c *Ctx) {
			got, _ := c.Get("id")
			if got != c.Request.URL.Path {
				atomic.AddInt64(&mismatches, 1)
			}
			c.Next()
		},
	)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			path := "/req/" + strconv.Itoa(i)
			adapted.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, nil))
		}(i)
	}
	wg.Wait()
	if mismatches != 0 {
		t.Fatalf("Ctx keys leaked across concurrent requests: %d mismatches", mismatches)
	}
}

// TestAdaptResponseWriterInterfaces proves the original writer (and therefore
// its optional interfaces) reaches the handler unchanged. |
// TestAdaptResponseWriterInterfaces 证明原始写入器（及其可选接口）原样到达处理器。
func TestAdaptResponseWriterInterfaces(t *testing.T) {
	underlying := &interfaceWriter{header: make(http.Header)}
	sawSame := false
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if w != underlying {
			t.Errorf("writer = %T, want the original *interfaceWriter", w)
		}
		if _, ok := w.(http.Flusher); !ok {
			t.Error("writer lost http.Flusher")
		}
		if _, ok := w.(http.Hijacker); !ok {
			t.Error("writer lost http.Hijacker")
		}
		sawSame = true
	})
	Adapt(h).ServeHTTP(underlying, httptest.NewRequest(http.MethodGet, "/", nil))
	if !sawSame {
		t.Fatal("handler did not run")
	}
}

// interfaceWriter is a minimal writer that also exposes Flusher and Hijacker. |
// interfaceWriter 是一个同时暴露 Flusher 与 Hijacker 的最小写入器。
type interfaceWriter struct {
	header http.Header
	code   int
}

func (w *interfaceWriter) Header() http.Header         { return w.header }
func (w *interfaceWriter) WriteHeader(code int)        { w.code = code }
func (w *interfaceWriter) Write(p []byte) (int, error) { return len(p), nil }
func (w *interfaceWriter) Flush()                      {}
func (w *interfaceWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, errors.New("not supported")
}
