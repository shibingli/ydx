package router

import (
	"net/http"
	"net/http/httptest"
	"testing"

	. "github.com/shibingli/ydx/router"
)

// discardWriter is a zero-allocation response writer for adapter benchmarks. |
// discardWriter 是适配器基准使用的零分配响应写入器。
type discardWriter struct {
	header http.Header
}

func (w *discardWriter) Header() http.Header         { return w.header }
func (w *discardWriter) WriteHeader(int)             {}
func (w *discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// BenchmarkAdapt measures the native adapter overhead against a direct handler
// and with zero, one and two middleware. | BenchmarkAdapt 测量原生适配器相对直连
// 处理器、以及零/一/两个中间件时的开销。
func BenchmarkAdapt(b *testing.B) {
	terminal := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	pass := func(c *Ctx) { c.Next() }
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := &discardWriter{header: make(http.Header)}

	cases := []struct {
		name    string
		handler http.Handler
	}{
		{"direct", terminal},
		{"adapt-0", Adapt(terminal)},
		{"adapt-1", Adapt(terminal, pass)},
		{"adapt-2", Adapt(terminal, pass, pass)},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				tc.handler.ServeHTTP(w, req)
			}
		})
	}
}
