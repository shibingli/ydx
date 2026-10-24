package router

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/go-chi/chi/v5"
	"github.com/julienschmidt/httprouter"

	ydxrouter "github.com/shibingli/ydx/router"
)

// benchParamSink keeps extracted path parameters observable. | benchParamSink 让提取出的路径参数保持可观测。
var benchParamSink string

// benchRouterEntry is one router implementation under comparison. | benchRouterEntry 是一个参与对比的路由器实现。
type benchRouterEntry struct {
	name    string
	handler http.Handler
}

// benchCompareRouters registers the same three routes on every implementation. The route table is
// built once per process, so each benchmark measures dispatch rather than registration. |
// benchCompareRouters 在每个实现上注册相同的三条路由。路由表每个进程只构建一次，因此每个基准
// 测量的是分发而不是注册。
func benchCompareRouters() []benchRouterEntry {
	ydxR := ydxrouter.New()
	// A fully static route uses the context-free registration, which is the documented fast path
	// for exactly this shape; the parameterised and wildcard routes keep the normal Ctx path. |
	// 完全静态路由使用无上下文注册，这是该形态的文档化快路径；参数与通配路由仍走常规 Ctx 路径。
	ydxR.GETRaw("/api/v1/users", func(http.ResponseWriter, *http.Request) {})
	ydxR.GET("/api/v1/users/:id/profile", func(c *ydxrouter.Ctx) { benchParamSink = c.Param("id") })
	ydxR.GET("/files/*filepath", func(c *ydxrouter.Ctx) { benchParamSink = c.Param("filepath") })

	stdMux := http.NewServeMux()
	stdMux.HandleFunc("/api/v1/users", func(http.ResponseWriter, *http.Request) {})
	stdMux.HandleFunc("/api/v1/users/{id}/profile", func(_ http.ResponseWriter, r *http.Request) {
		benchParamSink = r.PathValue("id")
	})
	stdMux.HandleFunc("/files/{path...}", func(_ http.ResponseWriter, r *http.Request) {
		benchParamSink = r.PathValue("path")
	})

	httpRouter := httprouter.New()
	httpRouter.GET("/api/v1/users", func(http.ResponseWriter, *http.Request, httprouter.Params) {})
	httpRouter.GET("/api/v1/users/:id/profile", func(_ http.ResponseWriter, _ *http.Request, ps httprouter.Params) {
		benchParamSink = ps.ByName("id")
	})
	httpRouter.GET("/files/*filepath", func(_ http.ResponseWriter, _ *http.Request, ps httprouter.Params) {
		benchParamSink = ps.ByName("filepath")
	})

	chiRouter := chi.NewRouter()
	chiRouter.Get("/api/v1/users", func(http.ResponseWriter, *http.Request) {})
	chiRouter.Get("/api/v1/users/{id}/profile", func(_ http.ResponseWriter, r *http.Request) {
		benchParamSink = chi.URLParam(r, "id")
	})
	chiRouter.Get("/files/*", func(_ http.ResponseWriter, r *http.Request) {
		benchParamSink = chi.URLParam(r, "*")
	})

	gin.SetMode(gin.ReleaseMode)
	ginRouter := gin.New()
	ginRouter.GET("/api/v1/users", func(*gin.Context) {})
	ginRouter.GET("/api/v1/users/:id/profile", func(c *gin.Context) { benchParamSink = c.Param("id") })
	ginRouter.GET("/files/*filepath", func(c *gin.Context) { benchParamSink = c.Param("filepath") })

	return []benchRouterEntry{
		{name: "ydx", handler: ydxR},
		{name: "stdlib", handler: stdMux},
		{name: "httprouter", handler: httpRouter},
		{name: "chi", handler: chiRouter},
		{name: "gin", handler: ginRouter},
	}
}

// TestRoutersDispatch proves that every implementation reaches the intended handler and extracts
// the path parameter, so the benchmark compares equivalent dispatch work. |
// TestRoutersDispatch 证明每个实现都命中预期处理器并提取路径参数，使基准比较的是等价分发工作。
func TestRoutersDispatch(t *testing.T) {
	cases := []struct {
		name       string
		target     string
		wantStatus int
		wantParam  bool
	}{
		{name: "static", target: "/api/v1/users", wantStatus: http.StatusOK},
		{name: "param", target: "/api/v1/users/42/profile", wantStatus: http.StatusOK, wantParam: true},
		{name: "wildcard", target: "/files/a/b/c.txt", wantStatus: http.StatusOK, wantParam: true},
		{name: "miss", target: "/nope", wantStatus: http.StatusNotFound},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, c.target, nil)
		for _, r := range benchCompareRouters() {
			t.Run(c.name+"/"+r.name, func(t *testing.T) {
				benchParamSink = ""
				rec := httptest.NewRecorder()
				r.handler.ServeHTTP(rec, req)
				if rec.Code != c.wantStatus {
					t.Fatalf("status = %d, want %d | 状态码 = %d，期望 %d", rec.Code, c.wantStatus, rec.Code, c.wantStatus)
				}
				if c.wantParam && benchParamSink == "" {
					t.Fatalf("path parameter was not extracted | 未提取路径参数")
				}
			})
		}
	}
}

// BenchmarkRouterCompare compares static, parameterised, wildcard and miss dispatch across ydx,
// net/http's ServeMux, httprouter, chi and gin. The same request is reused for every iteration;
// the response writer discards the response so the measurement isolates dispatch. |
// BenchmarkRouterCompare 对比 ydx、net/http ServeMux、httprouter、chi 与 gin 的静态、参数、通配与
// 未命中分发。同一请求在每轮复用；响应写入器丢弃响应，使测量聚焦于分发。
func BenchmarkRouterCompare(b *testing.B) {
	routers := benchCompareRouters()
	cases := []struct {
		name   string
		target string
	}{
		{name: "static", target: "/api/v1/users"},
		{name: "param", target: "/api/v1/users/42/profile"},
		{name: "wildcard", target: "/files/a/b/c.txt"},
		{name: "miss", target: "/nope"},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, c.target, nil)
		for _, r := range routers {
			b.Run(c.name+"/"+r.name, func(b *testing.B) {
				w := &discardWriter{header: make(http.Header)}
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					r.handler.ServeHTTP(w, req)
				}
			})
		}
	}
}
