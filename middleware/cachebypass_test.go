package middleware

import (
	"net/http"
	"testing"

	"github.com/shibingli/ydx/cache"
	"github.com/shibingli/ydx/router"
)

// TestCacheBypassMarksMatchingRequests proves only the matching path gets the
// bypass marker and the handler sees it on the request context. |
// TestCacheBypassMarksMatchingRequests 证明只有匹配路径获得旁路标记，且处理器能从请求上下文
// 看到它。
func TestCacheBypassMarksMatchingRequests(t *testing.T) {
	r := router.New()
	r.Use(CacheBypass(func(req *http.Request) bool { return req.URL.Path == "/sensitive" }))
	var got bool
	r.GET("/sensitive", func(c *router.Ctx) { got = cache.Bypass(c.Request.Context()) })
	r.GET("/normal", func(c *router.Ctx) { got = cache.Bypass(c.Request.Context()) })

	if rec := doReq(r, http.MethodGet, "/sensitive", nil, ""); rec.Code != http.StatusOK || !got {
		t.Fatalf("sensitive request: status=%d bypass=%v | 敏感请求：状态=%d 旁路=%v", rec.Code, got, rec.Code, got)
	}
	if rec := doReq(r, http.MethodGet, "/normal", nil, ""); rec.Code != http.StatusOK || got {
		t.Fatalf("normal request: status=%d bypass=%v | 普通请求：状态=%d 旁路=%v", rec.Code, got, rec.Code, got)
	}
}

// TestCacheBypassNilMatchIsNoop proves a nil predicate never panics. | TestCacheBypassNilMatchIsNoop
// 证明 nil 判定函数不会 panic。
func TestCacheBypassNilMatchIsNoop(t *testing.T) {
	r := router.New()
	r.Use(CacheBypass(nil))
	var got bool
	r.GET("/", func(c *router.Ctx) { got = cache.Bypass(c.Request.Context()) })
	if rec := doReq(r, http.MethodGet, "/", nil, ""); rec.Code != http.StatusOK || got {
		t.Fatalf("nil match: status=%d bypass=%v | nil 判定：状态=%d 旁路=%v", rec.Code, got, rec.Code, got)
	}
}
