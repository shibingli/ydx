package openapi

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/shibingli/ydx/json"
	"go.yaml.in/yaml/v3"
)

// testAddress is a nested struct used to verify schema generation. | testAddress 是用于校验 Schema 生成的嵌套结构体。
type testAddress struct {
	City string `json:"city"`
	Zip  string `json:"zip,omitempty"`
}

// testUser exercises json tags, omitempty, slices, maps and pointers. | testUser 覆盖 json tag、omitempty、切片、map 与指针。
type testUser struct {
	ID       int64             `json:"id"`
	Name     string            `json:"name"`
	Nick     string            `json:"nick,omitempty"`
	Age      int               `json:"age"`
	Active   bool              `json:"active"`
	Score    float64           `json:"score,omitempty"`
	Tags     []string          `json:"tags"`
	Address  *testAddress      `json:"address"`
	Extra    map[string]string `json:"extra,omitempty"`
	Ignored  string            `json:"-"`
	Nickname string
}

// serve performs one request against a handler and returns the recorder. | serve 对处理器发起一次
// 请求并返回记录器。
func serve(h http.Handler, method, target string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
	return rec
}

// pathParam builds the required string path parameter used by route fixtures. | pathParam 构造路由
// 夹具使用的必填字符串路径参数。
func pathParam(name string) Parameter {
	return Parameter{Name: name, In: "path", Required: true, Schema: &Schema{Type: "string"}}
}

// findParam returns the parameter with the given name, or nil. | findParam 返回指定名称的参数，找不到时返回 nil。
func findParam(params []Parameter, name string) *Parameter {
	for i := range params {
		if params[i].Name == name {
			return &params[i]
		}
	}
	return nil
}

// operationsOf returns every non-nil operation of a path item. | operationsOf 返回路径项中所有非空操作。
func operationsOf(pi PathItem) []*Operation {
	return []*Operation{pi.Get, pi.Post, pi.Put, pi.Patch, pi.Delete, pi.Head, pi.Options, pi.Trace}
}

// hasString reports whether the slice contains want. | hasString 报告切片是否包含 want。
func hasString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// normalizeNumbers rewrites YAML-decoded integers to float64 so that they can be
// compared with JSON-decoded values. | normalizeNumbers 把 YAML 解出的整数改写为 float64，
// 以便与 JSON 解出的值比较。
func normalizeNumbers(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = normalizeNumbers(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = normalizeNumbers(val)
		}
		return out
	case int:
		return float64(t)
	case int64:
		return float64(t)
	case uint64:
		return float64(t)
	default:
		return v
	}
}

func TestFromRoutesUsesPreconvertedPaths(t *testing.T) {
	doc := FromRoutes([]Route{{
		Method: "GET",
		Path:   "/report/{id}-xx.png",
		Params: []Parameter{pathParam("id")},
	}}, Info{Title: "Demo", Version: "1.0.0"}, Options{})

	if _, ok := doc.Paths["/report/:id-xx.png"]; ok {
		t.Fatalf("raw pattern leaked into paths | 原始模式不应出现在 paths 中: %v", doc.Paths)
	}
	item, ok := doc.Paths["/report/{id}-xx.png"]
	if !ok {
		t.Fatalf("missing converted path | 缺少转换后的路径: %v", doc.Paths)
	}
	if item.Get == nil {
		t.Fatalf("missing GET operation | 缺少 GET 操作")
	}
	p := findParam(item.Get.Parameters, "id")
	if p == nil {
		t.Fatalf("missing id parameter | 缺少 id 参数: %+v", item.Get.Parameters)
	}
	if p.In != "path" {
		t.Errorf("param in = %q, want path | 参数位置应为 path", p.In)
	}
	if !p.Required {
		t.Errorf("path param must be required | 路径参数必须必填")
	}
}

// TestFromRoutesSkipsCoverageForConfiguredPrefixes 验证 SkipPrefixes 中的路由不计入 missing。
// TestFromRoutesSkipsCoverageForConfiguredPrefixes verifies routes under SkipPrefixes never count as missing.
//
// 静态文件挂载不是 API 操作；把它算进缺失覆盖率会让每个生成项目启动时都报告 missing=1。文档里仍保留
// 该路径（它确实是可访问的端点），只是覆盖统计不再要求它有注解。| A static file mount is not an API
// operation; counting it as missing makes every generated project report missing=1 at startup. The path stays
// in the document (it really is reachable); only coverage reporting stops requiring an annotation.
func TestFromRoutesSkipsCoverageForConfiguredPrefixes(t *testing.T) {
	report := &Report{}
	doc := FromRoutesWithAnnotations([]Route{
		{Method: "GET", Path: "/api/users"},
		{Method: "GET", Path: "/static/{filepath}", Params: []Parameter{pathParam("filepath")}},
	}, Info{Title: "Demo", Version: "1.0.0"},
		Options{SkipPrefixes: []string{"/static/"}},
		nil, report)

	for _, key := range report.Missing {
		if strings.HasPrefix(key, "GET /static/") {
			t.Errorf("静态路由不应计入 missing: %v", report.Missing)
		}
	}
	foundAPI := false
	for _, key := range report.Missing {
		if key == "GET /api/users" {
			foundAPI = true
		}
	}
	if !foundAPI {
		t.Errorf("普通 API 路由仍应计入 missing: %v", report.Missing)
	}
	if _, ok := doc.Paths["/static/{filepath}"]; !ok {
		t.Errorf("静态路径仍应保留在文档中: %v", doc.Paths)
	}
}

func TestJSONHasOpenAPIVersion(t *testing.T) {
	if SpecVersion != "3.0.3" {
		t.Fatalf("SpecVersion = %q, want 3.0.3 | 版本号必须为 3.0.3", SpecVersion)
	}

	doc := NewBuilder(Info{Title: "Demo", Version: "1.0.0"}).Build()
	raw, err := doc.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["openapi"] != "3.0.3" {
		t.Errorf("openapi = %v, want 3.0.3 | openapi 字段应为 3.0.3", got["openapi"])
	}
	if got["paths"] == nil {
		t.Errorf("paths must always be present | paths 必须始终存在")
	}

	fresh := &Document{}
	raw, err = fresh.JSON()
	if err != nil {
		t.Fatalf("zero value JSON: %v", err)
	}
	var zero map[string]any
	if err := json.Unmarshal(raw, &zero); err != nil {
		t.Fatalf("unmarshal zero: %v", err)
	}
	if zero["openapi"] != "3.0.3" {
		t.Errorf("zero value openapi = %v, want 3.0.3 | 零值文档也应补齐版本号", zero["openapi"])
	}
}

func TestSchemaFromStruct(t *testing.T) {
	b := NewBuilder(Info{Title: "Demo", Version: "1.0.0"})
	ref := b.RegisterSchema("User", &testUser{})
	if ref != "#/components/schemas/User" {
		t.Fatalf("ref = %q, want #/components/schemas/User | 引用格式不正确", ref)
	}
	doc := b.Build()
	s := doc.Components.Schemas["User"]
	if s == nil {
		t.Fatalf("schema not registered | Schema 未注册")
	}
	if s.Type != "object" {
		t.Fatalf("type = %q, want object | 顶层类型应为 object", s.Type)
	}

	id := s.Properties["id"]
	if id == nil || id.Type != "integer" || id.Format != "int64" {
		t.Errorf("id schema = %+v, want integer/int64 | id 应为 integer/int64", id)
	}
	tags := s.Properties["tags"]
	if tags == nil || tags.Type != "array" || tags.Items == nil || tags.Items.Type != "string" {
		t.Errorf("tags schema = %+v, want array of string | tags 应为 string 数组", tags)
	}
	addr := s.Properties["address"]
	if addr == nil || addr.Type != "object" || addr.Properties["city"] == nil {
		t.Errorf("address schema = %+v, want nested object | address 应为嵌套对象", addr)
	}
	if extra := s.Properties["extra"]; extra == nil || extra.Type != "object" {
		t.Errorf("extra schema = %+v, want object | map 字段应为 object", extra)
	}
	if _, ok := s.Properties["-"]; ok {
		t.Errorf(`json:"-" field leaked into schema | json:"-" 字段不应出现`)
	}
	if _, ok := s.Properties["Ignored"]; ok {
		t.Errorf("ignored field leaked into schema | 被忽略字段不应出现")
	}
	if _, ok := s.Properties["Nickname"]; !ok {
		t.Errorf("untagged field must keep its Go name | 无 tag 字段应保留 Go 字段名")
	}
	if s.Properties["city"] != nil {
		t.Errorf("nested properties must not be flattened | 嵌套字段不应被提升")
	}

	for _, want := range []string{"id", "name", "age", "active", "tags", "Nickname"} {
		if !hasString(s.Required, want) {
			t.Errorf("required missing %q | required 缺少 %q: %v", want, want, s.Required)
		}
	}
	for _, unwanted := range []string{"nick", "score", "address", "extra"} {
		if hasString(s.Required, unwanted) {
			t.Errorf("required must not contain %q | required 不应包含 %q: %v", unwanted, unwanted, s.Required)
		}
	}
}

func TestViewerHTMLHasNoExternalCDN(t *testing.T) {
	doc := NewBuilder(Info{Title: "Demo", Version: "1.0.0"}).Build()
	h := HTTPHandler(doc, Options{})

	rec := serve(h, http.MethodGet, DefaultDocsPath)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 | 状态码应为 200", rec.Code)
	}
	body := strings.ToLower(rec.Body.String())
	for _, bad := range []string{
		`src="http`, `src='http`, `href="http`, `href='http`,
		`url(http`, `@import`,
	} {
		if strings.Contains(body, bad) {
			t.Errorf("viewer must not reference external assets | 查看器不得引用外部资源: %q", bad)
		}
	}
	for _, want := range []string{
		`/openapi/assets/yd-openapi-viewer.js`,
		`/openapi/assets/index.css`,
		`/openapi/assets/icons.svg`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("viewer must load the same-origin asset %q | 查看器必须加载同源资源 %q", want, want)
		}
	}
	if strings.Count(body, "<script src=") != 1 {
		t.Errorf("viewer must load exactly one external script | 查看器只能加载一个外部脚本")
	}
	if !strings.Contains(body, "<!doctype html") {
		t.Errorf("viewer must be a complete HTML page | 查看器必须是完整 HTML 页面")
	}
}

func TestYAMLValid(t *testing.T) {
	b := NewBuilder(Info{Title: "Demo", Version: "1.2.3", Description: "示例文档 | sample document"})
	b.AddServer(Server{URL: "https://api.example.com", Description: "prod"})
	ref := b.RegisterSchema("User", &testUser{})
	b.AddRoute("GET", "/users/:id", Operation{
		Summary: "Get user | 获取用户",
		Tags:    []string{"users"},
		Parameters: []Parameter{
			{Name: "verbose", In: "query", Schema: &Schema{Type: "boolean"}},
		},
		Responses: map[string]Response{
			"200": {
				Description: "OK",
				Content: map[string]MediaType{
					"application/json": {Schema: &Schema{Ref: ref, Example: 3}},
				},
			},
		},
	})
	doc := b.Build()

	yraw, err := doc.YAML()
	if err != nil {
		t.Fatalf("YAML: %v", err)
	}
	var fromYAML any
	if err := yaml.Unmarshal(yraw, &fromYAML); err != nil {
		t.Fatalf("yaml.Unmarshal: %v\n%s", err, yraw)
	}

	jraw, err := doc.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var fromJSON any
	if err := json.Unmarshal(jraw, &fromJSON); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if !reflect.DeepEqual(normalizeNumbers(fromYAML), fromJSON) {
		t.Errorf("YAML and JSON documents differ\nYAML: %v\nJSON: %v", fromYAML, fromJSON)
	}
	if !strings.Contains(string(yraw), "$ref: '#/components/schemas/User'") &&
		!strings.Contains(string(yraw), "$ref: \"#/components/schemas/User\"") {
		t.Errorf("YAML must keep $ref keys | YAML 必须保留 $ref 键:\n%s", yraw)
	}
}

func TestHandlerServesDocAndViewer(t *testing.T) {
	doc := NewBuilder(Info{Title: "Demo", Version: "1.0.0"}).Build()

	t.Run("default paths | 默认路径", func(t *testing.T) {
		h := HTTPHandler(doc, Options{})

		rec := serve(h, http.MethodGet, DefaultPath)
		if rec.Code != http.StatusOK {
			t.Fatalf("doc status = %d, want 200 | 文档状态码应为 200", rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
			t.Errorf("doc content-type = %q | 文档 Content-Type 不正确", ct)
		}
		var got map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("unmarshal served doc: %v", err)
		}
		if got["openapi"] != "3.0.3" {
			t.Errorf("served openapi = %v | 提供的文档版本号不正确", got["openapi"])
		}

		rec = serve(h, http.MethodGet, DefaultDocsPath)
		if rec.Code != http.StatusOK {
			t.Fatalf("viewer status = %d, want 200 | 查看器状态码应为 200", rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
			t.Errorf("viewer content-type = %q | 查看器 Content-Type 不正确", ct)
		}
		if body := rec.Body.String(); !strings.Contains(body, "Demo") {
			t.Errorf("viewer must show the document title | 查看器应展示文档标题")
		}
	})

	t.Run("custom paths | 自定义路径", func(t *testing.T) {
		h := HTTPHandler(doc, Options{Path: "/api/spec.json", DocsPath: "/api/docs"})

		if rec := serve(h, http.MethodGet, "/api/spec.json"); rec.Code != http.StatusOK {
			t.Errorf("custom doc status = %d | 自定义文档路径状态码不正确", rec.Code)
		}
		if rec := serve(h, http.MethodGet, "/api/docs"); rec.Code != http.StatusOK {
			t.Errorf("custom viewer status = %d | 自定义查看器路径状态码不正确", rec.Code)
		}
	})
}

// TestHTTPHandlerServesDocumentViewerAndAsset 验证标准 net/http 入口独立提供文档、查看器与内嵌脚本。
// TestHTTPHandlerServesDocumentViewerAndAsset verifies the standard net/http entry serves the document,
// the viewer and the embedded script without any framework static filesystem.
func TestHTTPHandlerServesDocumentViewerAndAsset(t *testing.T) {
	doc := NewBuilder(Info{Title: "Demo", Version: "1.0.0"}).Build()
	h := HTTPHandler(doc, Options{})

	get := func(target string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
		return rec
	}

	if rec := get(DefaultPath); rec.Code != http.StatusOK {
		t.Fatalf("doc status = %d, want 200 | 文档状态码应为 200", rec.Code)
	}
	viewer := get(DefaultDocsPath)
	if viewer.Code != http.StatusOK {
		t.Fatalf("viewer status = %d, want 200 | 查看器状态码应为 200", viewer.Code)
	}
	if body := viewer.Body.String(); !strings.Contains(body, `/openapi/assets/yd-openapi-viewer.js`) ||
		!strings.Contains(body, `/openapi/assets/index.css`) ||
		!strings.Contains(body, `/openapi/assets/icons.svg`) {
		t.Errorf("viewer must load the embedded assets | 查看器必须加载内嵌资源:\n%s", body)
	}

	cases := []struct {
		path        string
		contentType string
		want        []byte
	}{
		{"/openapi/assets/yd-openapi-viewer.js", "javascript", ViewerScript()},
		{"/openapi/assets/index.css", "text/css", ViewerCSS()},
		{"/openapi/assets/icons.svg", "image/svg+xml", ViewerIcons()},
	}
	for _, tc := range cases {
		asset := get(tc.path)
		if asset.Code != http.StatusOK {
			t.Fatalf("%s status = %d, want 200 | %s 状态码应为 200", tc.path, asset.Code, tc.path)
		}
		if ct := asset.Header().Get("Content-Type"); !strings.Contains(ct, tc.contentType) {
			t.Errorf("%s content-type = %q | %s Content-Type 不正确", tc.path, ct, tc.path)
		}
		if !bytes.Equal(asset.Body.Bytes(), tc.want) {
			t.Errorf("%s differs from its accessor | %s 与访问器返回的内容不一致", tc.path, tc.path)
		}
	}

	if rec := get("/openapi/assets/missing.js"); rec.Code != http.StatusNotFound {
		t.Errorf("missing asset status = %d, want 404 | 缺失资源状态码应为 404", rec.Code)
	}
}

// TestCustomAssetsPathKeepsViewerSelfContained 验证自定义资源前缀会同时作用于页面与脚本端点。
// TestCustomAssetsPathKeepsViewerSelfContained verifies a custom asset prefix drives both the page and the
// script endpoint.
func TestCustomAssetsPathKeepsViewerSelfContained(t *testing.T) {
	doc := NewBuilder(Info{Title: "Demo", Version: "1.0.0"}).Build()
	h := HTTPHandler(doc, Options{AssetsPath: "assets"})

	viewer := httptest.NewRecorder()
	h.ServeHTTP(viewer, httptest.NewRequest(http.MethodGet, DefaultDocsPath, nil))
	for _, want := range []string{
		`/assets/yd-openapi-viewer.js`,
		`/assets/index.css`,
		`/assets/icons.svg`,
	} {
		if body := viewer.Body.String(); !strings.Contains(body, want) {
			t.Errorf("viewer asset URL %q did not follow AssetsPath | 查看器资源地址 %q 未跟随 AssetsPath", want, want)
		}
	}

	for _, target := range []string{
		"/assets/yd-openapi-viewer.js",
		"/assets/index.css",
		"/assets/icons.svg",
	} {
		asset := httptest.NewRecorder()
		h.ServeHTTP(asset, httptest.NewRequest(http.MethodGet, target, nil))
		if asset.Code != http.StatusOK {
			t.Errorf("%s status = %d, want 200 | %s 状态码应为 200", target, asset.Code, target)
		}
	}
}

// TestViewerHTMLIsEmbedded 验证独立查看器页面模板 index.html 随模块发布。
// TestViewerHTMLIsEmbedded verifies the standalone viewer template index.html ships with the module.
func TestViewerHTMLIsEmbedded(t *testing.T) {
	raw := ViewerHTML()
	if !bytes.HasPrefix(raw, []byte("<!doctype html")) {
		t.Fatal("ViewerHTML() is not a complete HTML document | ViewerHTML() 不是完整 HTML 文档")
	}
	for _, placeholder := range []string{
		"__YD_OPENAPI_TITLE__",
		"__YD_OPENAPI_DATA__",
		"__YD_VIEWER_SCRIPT__",
		"__YD_VIEWER_CSS__",
		"__YD_VIEWER_ICONS__",
	} {
		if !bytes.Contains(raw, []byte(placeholder)) {
			t.Errorf("ViewerHTML() lost placeholder %q | ViewerHTML() 缺少占位符 %q", placeholder, placeholder)
		}
	}
}

// TestViewerScriptIsEmbedded 验证查看器脚本、样式表与图标 sprite 随模块发布。
// TestViewerScriptIsEmbedded verifies the viewer script, stylesheet and icon sprite ship with the module.
func TestViewerScriptIsEmbedded(t *testing.T) {
	raw := ViewerScript()
	if len(raw) == 0 {
		t.Fatal("ViewerScript() is empty | ViewerScript() 为空")
	}
	if !bytes.Contains(raw, []byte("yd-openapi-viewer.js")) {
		t.Errorf("ViewerScript() does not look like the viewer | ViewerScript() 不像是查看器脚本")
	}
	if css := ViewerCSS(); len(css) == 0 || !bytes.Contains(css, []byte("--bg")) {
		t.Errorf("ViewerCSS() is empty or does not look like the viewer stylesheet | ViewerCSS() 为空或不像查看器样式表")
	}
	if icons := ViewerIcons(); len(icons) == 0 || !bytes.Contains(icons, []byte("i-lucide-sun")) {
		t.Errorf("ViewerIcons() is empty or lacks the theme icons | ViewerIcons() 为空或缺少主题图标")
	}
}

// TestViewerPageIsStandalone 验证查看器页面可以写成静态文件，并由任意文件服务器独立托管。
// TestViewerPageIsStandalone verifies the viewer page can be written to disk and served by any static
// file server without this module's HTTP handler or any framework runtime.
func TestViewerPageIsStandalone(t *testing.T) {
	doc := NewBuilder(Info{Title: "Static Demo", Version: "1.0.0"}).Build()
	page, err := ViewerPage(doc, Options{
		ViewerScript: "./yd-openapi-viewer.js",
		ViewerCSS:    "./index.css",
		ViewerIcons:  "./icons.svg",
	})
	if err != nil {
		t.Fatalf("ViewerPage: %v", err)
	}
	if !bytes.Contains(page, []byte("<!doctype html")) {
		t.Fatal("ViewerPage did not return a complete HTML document | ViewerPage 未返回完整 HTML 文档")
	}
	for _, want := range []string{"./yd-openapi-viewer.js", "./index.css", "./icons.svg"} {
		if !bytes.Contains(page, []byte(want)) {
			t.Errorf("ViewerPage did not honour %q | ViewerPage 未使用 %q", want, want)
		}
	}

	dir := t.TempDir()
	files := map[string][]byte{
		"index.html":           page,
		"yd-openapi-viewer.js": ViewerScript(),
		"index.css":            ViewerCSS(),
		"icons.svg":            ViewerIcons(),
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	srv := httptest.NewServer(http.FileServer(http.Dir(dir)))
	defer srv.Close()

	for target := range files {
		target = "/" + target
		if target == "/index.html" {
			target = "/"
		}
		resp, err := http.Get(srv.URL + target)
		if err != nil {
			t.Fatalf("GET %s: %v", target, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || len(body) == 0 {
			t.Errorf("GET %s status = %d, bytes = %d | GET %s 状态 = %d，字节数 = %d", target, resp.StatusCode, len(body), target, resp.StatusCode, len(body))
		}
	}
}

func TestBlockedReturnsNotFound(t *testing.T) {
	doc := NewBuilder(Info{Title: "Demo", Version: "1.0.0"}).Build()
	h := HTTPHandler(doc, Options{Blocked: true})

	for _, target := range []string{
		DefaultPath,
		DefaultDocsPath,
		DefaultAssetsPath + ViewerScriptName,
		DefaultAssetsPath + ViewerCSSName,
		DefaultAssetsPath + ViewerIconsName,
	} {
		if rec := serve(h, http.MethodGet, target); rec.Code != http.StatusNotFound {
			t.Errorf("%s status = %d, want 404 | %s 状态码应为 404", target, rec.Code, target)
		}
	}
}
