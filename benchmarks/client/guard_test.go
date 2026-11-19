package client_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	ydxclient "github.com/shibingli/ydx/client"
)

// BenchmarkGuardCheckCached measures repeated AccessPolicy checks for one host,
// exercising the DNS TTL cache. | BenchmarkGuardCheckCached 测量同一 Host 的重复
// AccessPolicy 检查，覆盖 DNS TTL 缓存。
func BenchmarkGuardCheckCached(b *testing.B) {
	policy := &ydxclient.AccessPolicy{BlockPrivateIPs: true}
	request := httptest.NewRequest(http.MethodGet, "http://localhost/x", nil)
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decision, err := policy.Check(ctx, request)
		if err != nil {
			b.Fatal(err)
		}
		if decision.Allowed {
			b.Fatal("loopback host allowed")
		}
	}
}
