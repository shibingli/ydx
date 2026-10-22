package ydrouter

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shibingli/ydx/openapi"
	"github.com/shibingli/ydx/router"
)

// newTestRouter registers one route of every pattern shape the converter must handle.
// | newTestRouter 注册转换器必须处理的每种模式形态各一条路由。
func newTestRouter() *router.Router {
	r := router.New()
	r.GET("/users/:id", func(*router.Ctx) {})
	r.GET("/report/:id-xx.png", func(*router.Ctx) {})
	r.GET("/static/*filepath", func(*router.Ctx) {})
	return r
}

// TestFromRouterConvertsPatterns proves router patterns reach the document as OpenAPI path
// templates with their path parameters declared. | TestFromRouterConvertsPatterns 证明路由模式以
// OpenAPI 路径模板进入文档，并声明了对应的路径参数。
func TestFromRouterConvertsPatterns(t *testing.T) {
	doc := FromRouter(newTestRouter(), openapi.Info{Title: "Demo", Version: "1.0.0"}, openapi.Options{})
	for _, want := range []string{"/users/{id}", "/report/{id}-xx.png", "/static/{filepath}"} {
		if _, ok := doc.Paths[want]; !ok {
			t.Fatalf("missing path %q | 缺少路径 %q: %v", want, want, doc.Paths)
		}
	}
	op := doc.Paths["/users/{id}"].Get
	if op == nil {
		t.Fatal("missing GET operation | 缺少 GET 操作")
	}
	found := false
	for _, p := range op.Parameters {
		if p.Name == "id" && p.In == "path" && p.Required {
			found = true
		}
	}
	if !found {
		t.Fatalf("path parameter id is not declared | 未声明路径参数 id: %+v", op.Parameters)
	}
	wildcard := doc.Paths["/static/{filepath}"].Get
	if wildcard == nil || len(wildcard.Parameters) != 1 || wildcard.Parameters[0].Name != "filepath" {
		t.Fatalf("wildcard parameter not declared | 未声明通配参数: %+v", wildcard)
	}
}

// TestFromRouterWithAnnotationsReportsCoverage proves annotation keys use the converted path
// templates, so a hand written @Router block matches the route tree. |
// TestFromRouterWithAnnotationsReportsCoverage 证明注解键使用转换后的路径模板，手写 @Router 注解能与路由树对上。
func TestFromRouterWithAnnotationsReportsCoverage(t *testing.T) {
	annots := map[string]openapi.Annotation{
		"GET /users/{id}": {Summary: "Get user | 获取用户"},
		"GET /legacy":     {Summary: "Legacy | 遗留"},
	}
	report := &openapi.Report{}
	doc := FromRouterWithAnnotations(newTestRouter(), openapi.Info{Title: "Demo", Version: "1.0.0"},
		openapi.Options{}, annots, report)

	if got := doc.Paths["/users/{id}"].Get.Summary; got != "Get user | 获取用户" {
		t.Fatalf("summary = %q | 注解未合并", got)
	}
	if len(report.Matched) != 1 || report.Matched[0] != "GET /users/{id}" {
		t.Fatalf("matched = %v | Matched 统计不正确", report.Matched)
	}
	if len(report.Orphan) != 1 || report.Orphan[0] != "GET /legacy" {
		t.Fatalf("orphan = %v | Orphan 统计不正确", report.Orphan)
	}
	if len(report.Missing) != 2 {
		t.Fatalf("missing = %v | 未注解路由必须计入 Missing", report.Missing)
	}
}

// TestFromRouterNilRouterStillBuilds keeps a disabled or unbuilt route table from crashing the
// documentation endpoint. | TestFromRouterNilRouterStillBuilds 保证路由表为空或未装配时文档端点不会崩溃。
func TestFromRouterNilRouterStillBuilds(t *testing.T) {
	doc := FromRouter(nil, openapi.Info{Title: "Demo"}, openapi.Options{})
	if doc == nil || doc.Info.Title != "Demo" {
		t.Fatalf("doc = %+v | 空路由表仍应生成文档", doc)
	}
}

// TestHandlerServesDocumentViewerAndAssets proves the adapter mounts on the router and serves
// all four payloads from the configured endpoints. | TestHandlerServesDocumentViewerAndAssets
// 证明适配器可挂到路由上，并从配置的端点提供全部四种载荷。
func TestHandlerServesDocumentViewerAndAssets(t *testing.T) {
	r := newTestRouter()
	opts := openapi.Options{
		Path:       "/api/openapi.json",
		DocsPath:   "/docs",
		AssetsPath: "/docs/assets/",
	}
	h := Handler(FromRouter(r, openapi.Info{Title: "Demo", Version: "1.0.0"}, opts), opts)
	r.GET(opts.Path, h)
	r.GET(opts.DocsPath, h)
	r.GET(opts.AssetsPath+"*filepath", h)

	cases := []struct {
		path        string
		contentType string
		want        string
	}{
		{opts.Path, "application/json", `"openapi"`},
		{opts.DocsPath, "text/html", opts.AssetsPath + openapi.ViewerScriptName},
		{opts.AssetsPath + openapi.ViewerScriptName, "application/javascript", "route-group"},
		{opts.AssetsPath + openapi.ViewerCSSName, "text/css", "--field"},
		{opts.AssetsPath + openapi.ViewerIconsName, "image/svg+xml", "<svg"},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status = %d, want 200 | %s 状态码应为 200", tc.path, rec.Code, tc.path)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, tc.contentType) {
			t.Errorf("%s content type = %q, want %q | 内容类型不正确", tc.path, ct, tc.contentType)
		}
		if !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("%s body lacks %q | %s 响应缺少 %q", tc.path, tc.want, tc.path, tc.want)
		}
	}
}

// TestHandlerKeepsRouterStatus makes sure the adapter does not bypass the router's own status
// bookkeeping: a second write after the handler returns must not change the recorded status. |
// TestHandlerKeepsRouterStatus 保证适配器不绕过路由自身的状态记录：处理器返回后的写入不得改变已记录的状态。
func TestHandlerKeepsRouterStatus(t *testing.T) {
	r := router.New()
	opts := openapi.Options{Path: "/openapi.json", DocsPath: "/docs", AssetsPath: "/assets/"}
	h := Handler(FromRouter(nil, openapi.Info{Title: "Demo"}, opts), opts)
	var got int
	r.GET(opts.Path, func(c *router.Ctx) {
		h(c)
		got = c.StatusCode()
	})
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, opts.Path, nil))
	if got != http.StatusOK {
		t.Fatalf("router status = %d, want 200 | 路由记录的状态码应为 200", got)
	}
}
