package client_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	ydxclient "github.com/shibingli/ydx/client"
)

// BenchmarkCoalesceParallel measures parallel requests with distinct keys
// through the coalescing flight group. | BenchmarkCoalesceParallel 测量不同键的
// 并行请求经过合并 flight group 的性能。
func BenchmarkCoalesceParallel(b *testing.B) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	client, err := ydxclient.New(
		ydxclient.WithHosts(srv.URL),
		ydxclient.WithCoalesce(ydxclient.CoalescePolicy{}),
		ydxclient.WithoutCookieJar(),
	)
	if err != nil {
		b.Fatal(err)
	}
	defer client.Close()
	var next atomic.Int64
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		url := fmt.Sprintf("%s/x?k=%d", srv.URL, next.Add(1))
		ctx := context.Background()
		for pb.Next() {
			resp, err := client.Get(ctx, url)
			if err != nil {
				b.Error(err)
				return
			}
			if err := resp.Discard(); err != nil {
				b.Error(err)
				return
			}
		}
	})
}
