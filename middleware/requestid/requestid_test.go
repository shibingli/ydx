package requestid

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shibingli/ydx/regexpx"
	"github.com/shibingli/ydx/router"
)

// doReq runs one request through r with the given headers and body. | doReq 携带指定请求头与
// 请求体，把请求送入 r 执行一次。
func doReq(r *router.Router, method, target string, hdr map[string]string, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// uuidV4Pattern matches the canonical lowercase RFC 4122 version 4 textual form. | uuidV4Pattern 匹配 RFC 4122 版本 4 的标准小写文本形式。
var uuidV4Pattern = regexpx.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestRequestIDFromHeaderAndGenerated(t *testing.T) {
	t.Run("回显请求头中的 ID", func(t *testing.T) {
		var seen string
		r := router.New()
		r.Use(RequestID(""))
		r.GET("/x", func(c *router.Ctx) {
			seen = FromContext(c)
			_ = c.NoContent()
		})

		rec := doReq(r, http.MethodGet, "/x", map[string]string{"X-Request-Id": "abc-123"}, "")
		if seen != "abc-123" {
			t.Errorf("ctx 中的 request id = %q, 期望 abc-123", seen)
		}
		if got := rec.Header().Get("X-Request-Id"); got != "abc-123" {
			t.Errorf("响应头 X-Request-Id = %q, 期望 abc-123", got)
		}
	})

	t.Run("缺失时生成 UUIDv4", func(t *testing.T) {
		ids := make([]string, 0, 2)
		r := router.New()
		r.Use(RequestID(""))
		r.GET("/x", func(c *router.Ctx) {
			ids = append(ids, FromContext(c))
			_ = c.NoContent()
		})

		var respIDs []string
		for i := 0; i < 2; i++ {
			rec := doReq(r, http.MethodGet, "/x", nil, "")
			respIDs = append(respIDs, rec.Header().Get("X-Request-Id"))
		}
		for i, id := range ids {
			if !uuidV4Pattern.MatchString(id) {
				t.Fatalf("第 %d 个生成的 id = %q, 不是合法 UUIDv4", i, id)
			}
			if respIDs[i] != id {
				t.Fatalf("第 %d 个响应头 id = %q, 与 ctx 中的 %q 不一致", i, respIDs[i], id)
			}
		}
		if ids[0] == ids[1] {
			t.Fatalf("两次生成的 id 相同: %q", ids[0])
		}
	})

	t.Run("自定义请求头名", func(t *testing.T) {
		var seen string
		r := router.New()
		r.Use(RequestID("X-Trace-Id"))
		r.GET("/x", func(c *router.Ctx) {
			seen = FromContext(c)
			_ = c.NoContent()
		})

		rec := doReq(r, http.MethodGet, "/x", map[string]string{"X-Trace-Id": "trace-9"}, "")
		if seen != "trace-9" {
			t.Errorf("ctx 中的 request id = %q, 期望 trace-9", seen)
		}
		if got := rec.Header().Get("X-Trace-Id"); got != "trace-9" {
			t.Errorf("响应头 X-Trace-Id = %q, 期望 trace-9", got)
		}
		if got := rec.Header().Get("X-Request-Id"); got != "" {
			t.Errorf("未配置的 X-Request-Id 不应被写入, 实际 %q", got)
		}
	})
}

// TestMiddlewareSetsHeaderOnPlainHandler proves the native entry point assigns and echoes
// an id around a plain net/http handler. | TestMiddlewareSetsHeaderOnPlainHandler 证明原生
// 入口能为普通 net/http 处理器分配并回显 ID。
func TestMiddlewareSetsHeaderOnPlainHandler(t *testing.T) {
	called := false
	h := Middleware("")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if !called {
		t.Fatal("handler did not run")
	}
	if rec.Header().Get("X-Request-Id") == "" {
		t.Fatal("X-Request-Id was not echoed")
	}
}

// The generated UUID must carry the version/variant bits required by RFC 4122. | 生成的 UUID 必须带有 RFC 4122 要求的版本位与变体位。
func TestGeneratedUUIDVersionAndVariantBits(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 64; i++ {
		id := newUUIDv4()
		if !uuidV4Pattern.MatchString(id) {
			t.Fatalf("newUUIDv4() = %q, 不是合法 UUIDv4", id)
		}
		if seen[id] {
			t.Fatalf("newUUIDv4() 产生重复值: %q", id)
		}
		seen[id] = true
	}
}
