package i18n

import (
	"net/http"
	"strings"
	"testing"

	"github.com/shibingli/ydx/router"
)

// TestMiddlewareMergesVary asserts the middleware preserves an existing Vary
// (for example the CORS Origin) and appends the i18n request headers without
// duplicates. | TestMiddlewareMergesVary 断言中间件保留既有 Vary（例如 CORS 的
// Origin），并追加 i18n 依赖的请求头且不产生重复项。
func TestMiddlewareMergesVary(t *testing.T) {
	b := newFixtureBundle(t)
	r := router.New()
	r.Use(func(c *router.Ctx) {
		c.AddHeader("Vary", "Origin")
		c.AddHeader("Vary", "Accept-Encoding")
		c.Next()
	})
	r.Use(Middleware(b, Options{HeaderName: "X-Lang"}))
	r.GET("/", func(c *router.Ctx) {
		_ = c.String(http.StatusOK, "ok")
	})

	rec := doRequest(r, "/", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d, 期望 200", rec.Code)
	}
	vary := rec.Header().Get("Vary")
	for _, want := range []string{"Origin", "Accept-Encoding", AcceptLanguageHeader, "X-Lang", "Cookie"} {
		if !strings.Contains(vary, want) {
			t.Fatalf("Vary = %q, 缺少 %q", vary, want)
		}
	}
	parts := strings.Split(vary, ",")
	if len(parts) != 5 {
		t.Fatalf("Vary = %q, 期望 5 个去重后的字段", vary)
	}
}
