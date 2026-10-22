package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

func TestChainRunsInOrder(t *testing.T) {
	var order []string
	r := router.New()
	r.Use(Chain(
		func(*router.Ctx) { order = append(order, "a") },
		nil,
		func(*router.Ctx) { order = append(order, "b") },
	))
	r.GET("/x", func(c *router.Ctx) {
		order = append(order, "h")
		_ = c.String(http.StatusOK, "ok")
	})

	rec := doReq(r, http.MethodGet, "/x", nil, "")
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("code=%d body=%q", rec.Code, rec.Body.String())
	}
	if got := strings.Join(order, ","); got != "a,b,h" {
		t.Fatalf("执行顺序 = %q, 期望 %q", got, "a,b,h")
	}
}

func TestChainEmptyPassesThrough(t *testing.T) {
	r := router.New()
	r.Use(Chain())
	r.GET("/x", func(c *router.Ctx) { _ = c.String(http.StatusOK, "ok") })

	if rec := doReq(r, http.MethodGet, "/x", nil, ""); rec.Body.String() != "ok" {
		t.Fatalf("body = %q, 期望 ok", rec.Body.String())
	}
}

func TestChainAbortStopsRemaining(t *testing.T) {
	var order []string
	r := router.New()
	r.Use(Chain(
		func(c *router.Ctx) {
			order = append(order, "a")
			_ = c.String(http.StatusForbidden, "denied")
			c.Abort()
		},
		func(*router.Ctx) { order = append(order, "b") },
	))
	r.GET("/x", func(c *router.Ctx) {
		order = append(order, "h")
		_ = c.String(http.StatusOK, "ok")
	})

	rec := doReq(r, http.MethodGet, "/x", nil, "")
	if rec.Code != http.StatusForbidden || rec.Body.String() != "denied" {
		t.Fatalf("code=%d body=%q, 期望 403 denied", rec.Code, rec.Body.String())
	}
	if got := strings.Join(order, ","); got != "a" {
		t.Fatalf("执行顺序 = %q, 期望 %q", got, "a")
	}
}

func TestChainAsRouteMiddleware(t *testing.T) {
	var order []string
	r := router.New()
	r.GET("/x", func(c *router.Ctx) {
		order = append(order, "h")
		_ = c.String(http.StatusOK, "ok")
	}, Chain(
		func(*router.Ctx) { order = append(order, "a") },
		func(*router.Ctx) { order = append(order, "b") },
	))

	doReq(r, http.MethodGet, "/x", nil, "")
	if got := strings.Join(order, ","); got != "a,b,h" {
		t.Fatalf("执行顺序 = %q, 期望 %q", got, "a,b,h")
	}
}
