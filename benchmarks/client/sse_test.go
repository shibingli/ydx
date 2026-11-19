package client_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	ydxclient "github.com/shibingli/ydx/client"
)

var benchmarkSSEStream = bytes.Repeat([]byte("id: 1\nevent: tick\ndata: hello world\n\n"), 512)

// BenchmarkSSEEventReader measures parsing a 512-event stream with a fresh reader. | BenchmarkSSEEventReader
// 测量使用新 reader 解析 512 个事件的性能。
func BenchmarkSSEEventReader(b *testing.B) {
	b.SetBytes(int64(len(benchmarkSSEStream)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader := ydxclient.NewEventReader(bytes.NewReader(benchmarkSSEStream))
		for {
			if _, err := reader.Next(); err != nil {
				if err == io.EOF {
					break
				}
				b.Fatal(err)
			}
		}
	}
}

// BenchmarkSSEForward measures Handler forwarding a 32-event SSE response. | BenchmarkSSEForward
// 测量 Handler 转发 32 个事件 SSE 响应的性能。
func BenchmarkSSEForward(b *testing.B) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		for i := 0; i < 32; i++ {
			_, _ = io.WriteString(w, "data: hello\n\n")
		}
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
	}))
	defer upstream.Close()
	client, err := ydxclient.New(ydxclient.WithHosts(upstream.URL), ydxclient.WithoutCookieJar())
	if err != nil {
		b.Fatal(err)
	}
	defer client.Close()
	handler := client.Handler()
	request := httptest.NewRequest(http.MethodGet, "/events", nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request.Clone(context.Background()))
		if recorder.Code != http.StatusOK {
			b.Fatalf("status %d", recorder.Code)
		}
	}
}
