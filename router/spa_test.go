package router

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/shibingli/ydx/afs"
	ylog "github.com/shibingli/ydx/log"
	"github.com/spf13/afero"
)

// spaAssets builds the minimal build output used by the SPA tests. | spaAssets 构造 SPA 测试用的最小构建产物。
func spaAssets(t *testing.T) afero.Fs {
	t.Helper()
	fsys := afero.NewMemMapFs()
	spaWrite(t, fsys, "index.html", "<!doctype html><div id=app></div>")
	spaWrite(t, fsys, "assets/app.js", "console.log('app')")
	return fsys
}

// spaWrite writes one file into fsys. | spaWrite 向 fsys 写入一个文件。
func spaWrite(t *testing.T, fsys afero.Fs, name, body string) {
	t.Helper()
	if err := afero.WriteFile(fsys, name, []byte(body), 0o644); err != nil {
		t.Fatalf("写入 %s 失败: %v", name, err)
	}
}

func TestSPAHistoryFallbackServesIndex(t *testing.T) {
	r := New()
	r.SPAFS("/", spaAssets(t))

	rec := do(r, http.MethodGet, "/users/1", nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, 期望 200", rec.Code)
	}
	if body := rec.Body.String(); body != "<!doctype html><div id=app></div>" {
		t.Fatalf("body = %q", body)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("Content-Type = %q", ct)
	}
}

func TestSPAServesExistingAsset(t *testing.T) {
	r := New()
	r.SPAFS("/", spaAssets(t))

	rec := do(r, http.MethodGet, "/assets/app.js", nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, 期望 200", rec.Code)
	}
	if body := rec.Body.String(); body != "console.log('app')" {
		t.Fatalf("body = %q", body)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Fatalf("Content-Type = %q", ct)
	}
	if lm := rec.Header().Get("Last-Modified"); lm == "" {
		t.Fatal("静态资源响应缺少 Last-Modified")
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q, 期望 nosniff", got)
	}
}

func TestSPAMissingAssetDoesNotFallBackToIndex(t *testing.T) {
	r := New()
	r.SPAFS("/", spaAssets(t))

	rec := do(r, http.MethodGet, "/assets/missing.js", nil, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("code = %d, 期望 404", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "id=app") {
		t.Fatalf("缺失资源错误地回退到了 index.html: %q", rec.Body.String())
	}
}

func TestSPAExcludeKeepsAPIPathsOut(t *testing.T) {
	r := New(WithNotFound(func(c *Ctx) {
		_ = c.String(http.StatusNotFound, "custom-404")
	}))
	r.SPAFS("/", spaAssets(t), WithSPAExclude("/api"))

	rec := do(r, http.MethodGet, "/api/missing", nil, "")
	if rec.Code != http.StatusNotFound || rec.Body.String() != "custom-404" {
		t.Fatalf("排除前缀 code=%d body=%q, 期望 404 custom-404", rec.Code, rec.Body.String())
	}

	rec = do(r, http.MethodGet, "/apiary", nil, "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "id=app") {
		t.Fatalf("非边界前缀不应被排除: code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestSPADefaultCacheControl(t *testing.T) {
	fsys := spaAssets(t)
	spaWrite(t, fsys, "assets/app-4f3a2b1c.js", "hashed")
	r := New()
	r.SPAFS("/", fsys)

	rec := do(r, http.MethodGet, "/users/1", nil, "")
	if got := rec.Header().Get("Cache-Control"); got != "no-cache" {
		t.Fatalf("index Cache-Control = %q, 期望 no-cache", got)
	}

	rec = do(r, http.MethodGet, "/assets/app.js", nil, "")
	if got := rec.Header().Get("Cache-Control"); got != "" {
		t.Fatalf("未哈希资源 Cache-Control = %q, 期望为空", got)
	}

	rec = do(r, http.MethodGet, "/assets/app-4f3a2b1c.js", nil, "")
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
		t.Fatalf("哈希资源 Cache-Control = %q", got)
	}
}

func TestSPACacheControlOptions(t *testing.T) {
	fsys := spaAssets(t)
	spaWrite(t, fsys, "assets/app-4f3a2b1c.js", "hashed")
	r := New()
	r.SPAFS("/", fsys,
		WithSPAIndexCacheControl("no-store"),
		WithSPAAssetCacheControl("public, max-age=60"))

	rec := do(r, http.MethodGet, "/users/1", nil, "")
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("index Cache-Control = %q, 期望 no-store", got)
	}
	rec = do(r, http.MethodGet, "/assets/app-4f3a2b1c.js", nil, "")
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=60" {
		t.Fatalf("资源 Cache-Control = %q, 期望覆盖值", got)
	}
}

func TestSPACustomIndexDocument(t *testing.T) {
	fsys := spaAssets(t)
	spaWrite(t, fsys, "app.html", "custom-shell")
	r := New()
	r.SPAFS("/", fsys, WithSPAIndex("app.html"))

	rec := do(r, http.MethodGet, "/users/1", nil, "")
	if rec.Code != http.StatusOK || rec.Body.String() != "custom-shell" {
		t.Fatalf("code=%d body=%q, 期望自定义入口", rec.Code, rec.Body.String())
	}
}

func TestSPAETagAndConditionalRequest(t *testing.T) {
	r := New()
	r.SPAFS("/", spaAssets(t))

	rec := do(r, http.MethodGet, "/assets/app.js", nil, "")
	etag := rec.Header().Get("ETag")
	if etag == "" {
		t.Fatal("静态资源响应缺少 ETag")
	}
	rec = do(r, http.MethodGet, "/assets/app.js", map[string]string{"If-None-Match": etag}, "")
	if rec.Code != http.StatusNotModified {
		t.Fatalf("条件请求 code = %d, 期望 304", rec.Code)
	}
}

func TestSPAIfModifiedSince(t *testing.T) {
	r := New()
	r.SPAFS("/", spaAssets(t))

	rec := do(r, http.MethodGet, "/assets/app.js", nil, "")
	lastModified := rec.Header().Get("Last-Modified")
	if lastModified == "" {
		t.Fatal("静态资源响应缺少 Last-Modified")
	}
	rec = do(r, http.MethodGet, "/assets/app.js", map[string]string{"If-Modified-Since": lastModified}, "")
	if rec.Code != http.StatusNotModified {
		t.Fatalf("If-Modified-Since code = %d, 期望 304", rec.Code)
	}
}

func TestSPAHeadConditionalRequest(t *testing.T) {
	r := New()
	r.SPAFS("/", spaAssets(t))

	rec := do(r, http.MethodHead, "/assets/app.js", nil, "")
	etag := rec.Header().Get("ETag")
	if etag == "" {
		t.Fatal("HEAD 响应缺少 ETag")
	}
	rec = do(r, http.MethodHead, "/assets/app.js", map[string]string{"If-None-Match": etag}, "")
	if rec.Code != http.StatusNotModified {
		t.Fatalf("HEAD 条件请求 code = %d, 期望 304", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("HEAD 304 不应有正文: %q", rec.Body.String())
	}
}

func TestSPARangeRequest(t *testing.T) {
	r := New()
	r.SPAFS("/", spaAssets(t))

	rec := do(r, http.MethodGet, "/assets/app.js", map[string]string{"Range": "bytes=0-6"}, "")
	if rec.Code != http.StatusPartialContent {
		t.Fatalf("code = %d, 期望 206", rec.Code)
	}
	if body := rec.Body.String(); body != "console" {
		t.Fatalf("body = %q, 期望 console", body)
	}
}

func TestSPAPrefixMount(t *testing.T) {
	r := New()
	r.SPAFS("/app", spaAssets(t))

	rec := do(r, http.MethodGet, "/app/users/1", nil, "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "id=app") {
		t.Fatalf("前缀深链 code=%d body=%q", rec.Code, rec.Body.String())
	}

	rec = do(r, http.MethodGet, "/app/assets/app.js", nil, "")
	if rec.Code != http.StatusOK || rec.Body.String() != "console.log('app')" {
		t.Fatalf("前缀资源 code=%d body=%q", rec.Code, rec.Body.String())
	}

	rec = do(r, http.MethodGet, "/users/1", nil, "")
	if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "id=app") {
		t.Fatalf("前缀外路径不应由 SPA 应答: code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestSPAPrefixRootRedirectsToTrailingSlash(t *testing.T) {
	r := New()
	r.SPAFS("/app", spaAssets(t))

	rec := do(r, http.MethodGet, "/app?x=1", nil, "")
	if rec.Code != http.StatusMovedPermanently {
		t.Fatalf("code = %d, 期望 301", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/app/?x=1" {
		t.Fatalf("Location = %q, 期望 /app/?x=1", loc)
	}

	rec = do(r, http.MethodGet, "/app/", nil, "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "id=app") {
		t.Fatalf("挂载根 code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestSPADirectoryIndexAndNoListing(t *testing.T) {
	fsys := spaAssets(t)
	spaWrite(t, fsys, "docs/index.html", "docs-shell")
	r := New()
	r.SPAFS("/", fsys)

	rec := do(r, http.MethodGet, "/docs/", nil, "")
	if rec.Code != http.StatusOK || rec.Body.String() != "docs-shell" {
		t.Fatalf("目录入口 code=%d body=%q", rec.Code, rec.Body.String())
	}

	rec = do(r, http.MethodGet, "/docs", nil, "")
	if rec.Code != http.StatusMovedPermanently || rec.Header().Get("Location") != "/docs/" {
		t.Fatalf("目录重定向 code=%d Location=%q", rec.Code, rec.Header().Get("Location"))
	}

	spaWrite(t, fsys, "empty/keep.txt", "x")
	rec = do(r, http.MethodGet, "/empty/", nil, "")
	if strings.Contains(rec.Body.String(), "keep.txt") {
		t.Fatalf("目录被列举: %q", rec.Body.String())
	}
}

func TestSPARegisteredRoutesWin(t *testing.T) {
	fsys := spaAssets(t)
	spaWrite(t, fsys, "api/app.js", "from-disk")
	r := New()
	r.SPAFS("/", fsys, WithSPAExclude("/api"))
	r.GET("/api/health", func(c *Ctx) { _ = c.String(http.StatusOK, "healthy") })

	rec := do(r, http.MethodGet, "/api/health", nil, "")
	if rec.Code != http.StatusOK || rec.Body.String() != "healthy" {
		t.Fatalf("路由应优先: code=%d body=%q", rec.Code, rec.Body.String())
	}
	rec = do(r, http.MethodGet, "/api/app.js", nil, "")
	if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "from-disk") {
		t.Fatalf("排除前缀不应读取磁盘: code=%d body=%q", rec.Code, rec.Body.String())
	}
	rec = do(r, http.MethodPost, "/api/health", nil, "")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("已注册 GET 的 POST code = %d, 期望 405", rec.Code)
	}
}

func TestSPAAnswersOnlyGetAndHead(t *testing.T) {
	r := New()
	r.SPAFS("/", spaAssets(t))

	rec := do(r, http.MethodPost, "/users/1", nil, "")
	if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "id=app") {
		t.Fatalf("POST 深链 code=%d body=%q, 期望 404", rec.Code, rec.Body.String())
	}

	rec = do(r, http.MethodHead, "/users/1", nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("HEAD code = %d, 期望 200", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("HEAD 不应有正文: %q", rec.Body.String())
	}
	if cl := rec.Header().Get("Content-Length"); cl == "" || cl == "0" {
		t.Fatalf("HEAD Content-Length = %q", cl)
	}
}

func TestSPARejectsPathTraversal(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("top-secret"), 0o644); err != nil {
		t.Fatalf("准备外部文件失败: %v", err)
	}
	fsys := afs.NewOS(root)
	if err := afero.WriteFile(fsys, "index.html", []byte("app"), 0o644); err != nil {
		t.Fatalf("写入入口失败: %v", err)
	}
	r := New()
	r.SPAFS("/", fsys)

	escape := "/../" + filepath.Base(outside) + "/secret.txt"
	rec := do(r, http.MethodGet, escape, nil, "")
	if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "top-secret") {
		t.Fatalf("路径穿越 code=%d body=%q", rec.Code, rec.Body.String())
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.URL.Path = "/../" + filepath.Base(outside) + "/secret.txt"
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "top-secret") {
		t.Fatalf("原始路径穿越 code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestNewSPAHandlerNative(t *testing.T) {
	h := NewSPAHandler(spaAssets(t))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/users/1", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "id=app") {
		t.Fatalf("原生入口 code=%d body=%q", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/assets/missing.js", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("原生入口缺失资源 code = %d, 期望 404", rec.Code)
	}
}

func TestSPANilFSIsWiringError(t *testing.T) {
	r := New()
	r.SPAFS("/", nil)
	if err := r.Validate(); !errors.Is(err, ErrSPANilFS) {
		t.Fatalf("Validate = %v, 期望 ErrSPANilFS", err)
	}
	if rec := do(r, http.MethodGet, "/", nil, ""); rec.Code != http.StatusInternalServerError {
		t.Fatalf("损坏路由 code = %d, 期望 500", rec.Code)
	}
}

func TestSPADuplicateMountIsWiringError(t *testing.T) {
	r := New()
	r.SPAFS("/", spaAssets(t))
	r.SPAFS("/app", spaAssets(t))
	if err := r.Validate(); !errors.Is(err, ErrSPAConflict) {
		t.Fatalf("Validate = %v, 期望 ErrSPAConflict", err)
	}
	if rec := do(r, http.MethodGet, "/", nil, ""); rec.Code != http.StatusInternalServerError {
		t.Fatalf("损坏路由 code = %d, 期望 500", rec.Code)
	}
}

func TestSPAMissingIndexFallsThrough(t *testing.T) {
	r := New()
	r.SPAFS("/", afero.NewMemMapFs())

	rec := do(r, http.MethodGet, "/users/1", nil, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("缺失入口 code = %d, 期望 404", rec.Code)
	}
}

func TestSPARunsGlobalMiddleware(t *testing.T) {
	r := New()
	r.Use(func(c *Ctx) {
		c.SetHeader("X-MW", "1")
		c.Next()
	})
	r.SPAFS("/", spaAssets(t), WithSPAExclude("/api"))

	for _, target := range []string{"/users/1", "/assets/missing.js", "/api/missing"} {
		rec := do(r, http.MethodGet, target, nil, "")
		if rec.Header().Get("X-MW") != "1" {
			t.Fatalf("%s 未经过全局中间件: X-MW=%q", target, rec.Header().Get("X-MW"))
		}
	}
}

func TestSPADiskDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("disk-shell"), 0o644); err != nil {
		t.Fatalf("写入入口失败: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "assets"), 0o755); err != nil {
		t.Fatalf("创建目录失败: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "assets", "app.js"), []byte("disk-js"), 0o644); err != nil {
		t.Fatalf("写入资源失败: %v", err)
	}

	r := New()
	r.SPA("/", dir)

	rec := do(r, http.MethodGet, "/users/1", nil, "")
	if rec.Code != http.StatusOK || rec.Body.String() != "disk-shell" {
		t.Fatalf("深链 code=%d body=%q", rec.Code, rec.Body.String())
	}
	rec = do(r, http.MethodGet, "/assets/app.js", nil, "")
	if rec.Code != http.StatusOK || rec.Body.String() != "disk-js" {
		t.Fatalf("资源 code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestSPAHashedAssetNameRule(t *testing.T) {
	hashed := []string{
		"assets/app-4f3a2b1c.js",
		"assets/main.4f3a2b1c.chunk.js",
		"assets/index-DiwrgTda.js",
		"assets/chunk-a1b2c3d4e5.js",
	}
	plain := []string{
		"assets/app.js",
		"assets/jquery-3.7.10.min.js",
		"assets/some-very-long-name.js",
		"assets/react-dom.production.min.js",
		"assets/vendor-polyfills.js",
		"assets/open-source-something.js",
		"assets/my-application-components.js",
		"index.html",
	}
	for _, name := range hashed {
		if !hashedAssetName(name) {
			t.Errorf("%q 应识别为哈希资源", name)
		}
	}
	for _, name := range plain {
		if hashedAssetName(name) {
			t.Errorf("%q 不应识别为哈希资源", name)
		}
	}
}

func TestSPADirectoryRedirectStaysLocal(t *testing.T) {
	fsys := spaAssets(t)
	spaWrite(t, fsys, "docs/index.html", "docs-shell")
	r := New()
	r.SPAFS("/", fsys)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.URL.Path = "//docs"
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusMovedPermanently {
		t.Fatalf("code = %d, 期望 301", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/docs/" {
		t.Fatalf("Location = %q, 期望 /docs/（不得成为协议相对地址）", loc)
	}
}

func TestSPADirectoryRedirectEscapesBackslash(t *testing.T) {
	h := &spaHandler{}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.URL.Path = `/\evil`
	rec := httptest.NewRecorder()
	h.redirectDir(rec, req)
	if loc := rec.Header().Get("Location"); strings.Contains(loc, `\`) {
		t.Fatalf("Location = %q 含未转义反斜杠", loc)
	}
}

func TestSPAIndexOptionAcceptsLeadingSlash(t *testing.T) {
	fsys := spaAssets(t)
	spaWrite(t, fsys, "app.html", "custom-shell")
	r := New()
	r.SPAFS("/", fsys, WithSPAIndex("/app.html"))

	rec := do(r, http.MethodGet, "/users/1", nil, "")
	if rec.Code != http.StatusOK || rec.Body.String() != "custom-shell" {
		t.Fatalf("code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestNewSPAHandlerNilFS(t *testing.T) {
	rec := httptest.NewRecorder()
	NewSPAHandler(nil).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("code = %d, 期望 404", rec.Code)
	}
}

func TestSPARecordsCtxResponseState(t *testing.T) {
	type snapshot struct {
		status  int
		written bool
	}
	var seen []snapshot
	r := New()
	r.Use(func(c *Ctx) {
		c.Next()
		seen = append(seen, snapshot{status: c.StatusCode(), written: c.Written()})
	})
	fsys := spaAssets(t)
	spaWrite(t, fsys, "docs/index.html", "docs-shell")
	r.SPAFS("/", fsys)

	rec := do(r, http.MethodGet, "/users/1", nil, "")
	etag := rec.Header().Get("ETag")
	rec = do(r, http.MethodGet, "/users/1", map[string]string{"If-None-Match": etag}, "")
	if rec.Code != http.StatusNotModified {
		t.Fatalf("条件请求 code = %d, 期望 304", rec.Code)
	}
	rec = do(r, http.MethodGet, "/docs", nil, "")
	if rec.Code != http.StatusMovedPermanently {
		t.Fatalf("目录重定向 code = %d, 期望 301", rec.Code)
	}
	rec = do(r, http.MethodGet, "/assets/missing.js", nil, "")

	want := []snapshot{
		{status: http.StatusOK, written: true},
		{status: http.StatusNotModified, written: true},
		{status: http.StatusMovedPermanently, written: true},
		{status: http.StatusNotFound, written: true},
	}
	if len(seen) != len(want) {
		t.Fatalf("middleware 观察到 %d 次响应, 期望 %d", len(seen), len(want))
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Errorf("第 %d 次响应 = %+v, 期望 %+v", i+1, seen[i], want[i])
		}
	}
}

func TestSPAExcludeIsRelativeToMountPrefix(t *testing.T) {
	r := New()
	r.SPAFS("/app", spaAssets(t), WithSPAExclude("/api"))

	rec := do(r, http.MethodGet, "/app/api/users", nil, "")
	if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "id=app") {
		t.Fatalf("前缀挂载下排除失效: code=%d body=%q", rec.Code, rec.Body.String())
	}

	rec = do(r, http.MethodGet, "/app/users", nil, "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "id=app") {
		t.Fatalf("普通深链 code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestSPAIndexOptionIgnoresInvalidNames(t *testing.T) {
	for _, name := range []string{"/", ".", ".."} {
		r := New()
		r.SPAFS("/", spaAssets(t), WithSPAIndex(name))
		rec := do(r, http.MethodGet, "/users/1", nil, "")
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "id=app") {
			t.Fatalf("WithSPAIndex(%q) code=%d body=%q, 期望回退默认入口", name, rec.Code, rec.Body.String())
		}
	}
}

func TestSPANormalizesMountPrefix(t *testing.T) {
	r := New()
	r.SPAFS("//app/", spaAssets(t))

	rec := do(r, http.MethodGet, "/app/users/1", nil, "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "id=app") {
		t.Fatalf("规范化前缀 code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestSPANestedIndexUsesIndexCacheControl(t *testing.T) {
	fsys := spaAssets(t)
	spaWrite(t, fsys, "docs/index.html", "docs-shell")
	r := New()
	r.SPAFS("/", fsys)

	rec := do(r, http.MethodGet, "/docs/", nil, "")
	if got := rec.Header().Get("Cache-Control"); got != "no-cache" {
		t.Fatalf("子目录入口 Cache-Control = %q, 期望 no-cache", got)
	}
}

func TestSPAMissingIndexLogsWarning(t *testing.T) {
	prev := ylog.Default()
	var buf bytes.Buffer
	ylog.SetDefault(ylog.New(ylog.Options{Writer: &buf, Level: ylog.WarnLevel}))
	defer ylog.SetDefault(prev)

	New().SPAFS("/", afero.NewMemMapFs())
	if !strings.Contains(buf.String(), "index.html") {
		t.Fatalf("缺少入口文档时未记录告警: %q", buf.String())
	}
}

func TestSPAServesEmbeddedFS(t *testing.T) {
	files := fstest.MapFS{
		"index.html":    &fstest.MapFile{Data: []byte("embed-shell")},
		"assets/app.js": &fstest.MapFile{Data: []byte("embed-js")},
	}
	r := New()
	r.SPAFS("/", afs.NewEmbed(files))

	rec := do(r, http.MethodGet, "/users/1", nil, "")
	if rec.Code != http.StatusOK || rec.Body.String() != "embed-shell" {
		t.Fatalf("内嵌入口 code=%d body=%q", rec.Code, rec.Body.String())
	}
	rec = do(r, http.MethodGet, "/assets/app.js", nil, "")
	if rec.Code != http.StatusOK || rec.Body.String() != "embed-js" {
		t.Fatalf("内嵌资源 code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestSPARawRouteWins(t *testing.T) {
	r := New()
	r.GETRaw("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	r.SPAFS("/", spaAssets(t))

	rec := do(r, http.MethodGet, "/health", nil, "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("raw 路由 code = %d, 期望 204", rec.Code)
	}
}

func TestStaticFSCtxResponseState(t *testing.T) {
	type snapshot struct {
		status  int
		written bool
	}
	var seen []snapshot
	r := New()
	r.Use(func(c *Ctx) {
		c.Next()
		seen = append(seen, snapshot{status: c.StatusCode(), written: c.Written()})
	})
	mem := afero.NewMemMapFs()
	spaWrite(t, mem, "css/app.css", "body{}")
	r.StaticFS("/static", mem)

	do(r, http.MethodGet, "/static/css/app.css", nil, "")
	do(r, http.MethodGet, "/static/css/missing.css", nil, "")

	want := []snapshot{
		{status: http.StatusOK, written: true},
		{status: http.StatusNotFound, written: true},
	}
	if len(seen) != len(want) {
		t.Fatalf("middleware 观察到 %d 次响应, 期望 %d", len(seen), len(want))
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Errorf("第 %d 次响应 = %+v, 期望 %+v", i+1, seen[i], want[i])
		}
	}
}

// TestSPARejectsMountRelativeTraversal pins that a prefixed mount never serves a path that climbs
// out of the mount with "..", even when the file system would clean the path back into its root. |
// TestSPARejectsMountRelativeTraversal 固化前缀挂载绝不输出用 ".." 爬出挂载的路径，即使文件系统会把
// 该路径清理回根目录之内。
func TestSPARejectsMountRelativeTraversal(t *testing.T) {
	fsys := spaAssets(t)
	spaWrite(t, fsys, "secret.txt", "top-secret")
	r := New()
	r.SPAFS("/app", fsys)

	for _, target := range []string{"/app/../secret.txt", "/app/%2e%2e/secret.txt"} {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		req.URL.Path = target
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%q: code = %d, 期望 404", target, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "top-secret") {
			t.Fatalf("%q 泄露了挂载根之外的文件", target)
		}
	}
}

// TestSPARejectsEncodedPathSeparators pins that encoded slashes cannot smuggle a traversal or
// bypass WithSPAExclude: routing matches the raw escaped path while the file lookup must not
// reinterpret %2F as a segment separator. |
// TestSPARejectsEncodedPathSeparators 固化编码斜杠不能夹带目录穿越或绕过 WithSPAExclude：路由按原始
// 转义路径匹配，文件查找不得把 %2F 重新解释为分段分隔符。
func TestSPARejectsEncodedPathSeparators(t *testing.T) {
	fsys := spaAssets(t)
	spaWrite(t, fsys, "secret.txt", "top-secret")
	r := New()
	r.SPAFS("/app", fsys, WithSPAExclude("/api"))

	for _, target := range []string{
		"http://example.com/app%2F..%2Fsecret.txt",
		"http://example.com/app%2f..%2fsecret.txt",
		"http://example.com/app%2F..%2Fapi%2Fmissing",
	} {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%q: code = %d body = %q, 期望 404", target, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "top-secret") || strings.Contains(rec.Body.String(), "id=app") {
			t.Fatalf("%q 仍命中了 SPA: body = %q", target, rec.Body.String())
		}
	}
}

// TestSPAServesEncodedSpaceInFileName keeps the separator guard narrow: ordinary escaped bytes
// such as %20 must still resolve to their file name. |
// TestSPAServesEncodedSpaceInFileName 保证分隔符防护范围足够窄：%20 这类普通转义字节仍应解析到文件名。
func TestSPAServesEncodedSpaceInFileName(t *testing.T) {
	fsys := spaAssets(t)
	spaWrite(t, fsys, "a b.js", "space")
	r := New()
	r.SPAFS("/app", fsys)

	rec := do(r, http.MethodGet, "/app/a%20b.js", nil, "")
	if rec.Code != http.StatusOK || rec.Body.String() != "space" {
		t.Fatalf("code = %d body = %q, 期望 200 space", rec.Code, rec.Body.String())
	}
}

// TestSPAHiddenFiles pins the default denial of dot-prefixed path segments (except .well-known)
// and the explicit opt-in that restores the old behaviour. |
// TestSPAHiddenFiles 固化默认拒绝点号开头的路径分段（.well-known 除外）以及恢复旧行为的显式开关。
func TestSPAHiddenFiles(t *testing.T) {
	fsys := spaAssets(t)
	spaWrite(t, fsys, ".env", "TOKEN=1")
	spaWrite(t, fsys, ".git/config", "[core]")
	spaWrite(t, fsys, "assets/.secret", "hidden")
	spaWrite(t, fsys, ".well-known/acme-challenge/token", "acme")

	r := New()
	r.SPAFS("/", fsys)
	for _, target := range []string{"/.env", "/.git/config", "/assets/.secret"} {
		if rec := do(r, http.MethodGet, target, nil, ""); rec.Code != http.StatusNotFound {
			t.Fatalf("%q: code = %d, 期望 404", target, rec.Code)
		}
	}
	if rec := do(r, http.MethodGet, "/.well-known/acme-challenge/token", nil, ""); rec.Code != http.StatusOK {
		t.Fatalf("ACME 路径 code = %d, 期望 200", rec.Code)
	}

	open := New()
	open.SPAFS("/", fsys, WithSPAAllowHiddenFiles(true))
	if rec := do(open, http.MethodGet, "/.env", nil, ""); rec.Code != http.StatusOK {
		t.Fatalf("显式允许后 code = %d, 期望 200", rec.Code)
	}
}
