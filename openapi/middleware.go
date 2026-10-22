package openapi

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"

	"github.com/shibingli/ydx/router"
)

// Handler returns the router handler serving the JSON document, the built-in viewer and the
// embedded viewer assets. | Handler 返回提供 JSON 文档、内置查看器与内嵌查看器资源的路由处理器。
//
// Mount the same handler on every configured endpoint: | 请把同一个处理器挂载到全部配置端点上：
//
//	h := openapi.Handler(doc, opts)
//	r.GET(opts.Path, h)
//	r.GET(opts.DocsPath, h)
//	r.GET(opts.AssetsPath+"*filepath", h)
//
// Requests for any other path receive 404, so the handler may also be mounted on a
// catch-all route. | 其他路径的请求会返回 404，因此该处理器也可以挂在通配路由上。
//
// Options.Blocked answers every endpoint with 404, which is how production switches the
// documentation off. | Options.Blocked 会让所有端点都以 404 应答，生产环境据此关闭文档。
//
// The handler is safe for concurrent use: the document is serialized once on first use and
// every payload is then served from that snapshot with a strong ETag, so repeated requests
// neither re-encode the document nor observe a half-mutated one. Mutate the document only
// before the first request. | 该处理器可安全并发使用：文档在首次使用时序列化一次，此后所有载荷
// 都从该快照提供并带强 ETag，因此重复请求既不重新编码文档，也不会观察到改到一半的状态。
// 请只在首次请求之前修改文档。
//
// The whole package stays silent: no logging is emitted, and nothing is written to
// stdout. | 本包保持静默：不输出任何日志，也不向 stdout 写入内容。
func Handler(d *Document, o Options) router.HandlerFunc {
	s := newHandlerState(d, o)
	return func(c *router.Ctx) {
		s.ServeHTTP(ctxResponseWriter{c: c}, c.Request)
	}
}

// HTTPHandler returns a standard net/http handler serving the same three endpoints. |
// HTTPHandler 返回提供同样三个端点的标准 net/http 处理器。
//
// The caller mounts it on Options.Path, Options.DocsPath and Options.AssetsPath: | 调用方把它
// 挂载到 Options.Path、Options.DocsPath 与 Options.AssetsPath：
//
//	h := openapi.HTTPHandler(doc, openapi.Options{})
//	mux.Handle("/openapi.json", h)
//	mux.Handle("/docs", h)
//	mux.Handle("/openapi/assets/", h)
//
// The viewer script is embedded in this module; the third mount makes the default
// Options.ViewerScript reachable without any framework static filesystem. | 查看器脚本内嵌在
// 本模块中；第三个挂载让默认的 Options.ViewerScript 无需任何框架静态文件系统即可访问。
func HTTPHandler(d *Document, o Options) http.Handler {
	return newHandlerState(d, o)
}

// newHandlerState snapshots the options and the embedded asset. | newHandlerState 快照化选项与
// 内嵌资源。
func newHandlerState(d *Document, o Options) *handlerState {
	if d == nil {
		d = &Document{}
	}
	s := &handlerState{doc: d, opts: o.withDefaults()}
	s.asset = ViewerScript()
	s.assetETag = etagOf(s.asset)
	return s
}

// handlerState memoizes the serialized document and viewer page. | handlerState 缓存序列化后的
// 文档与查看器页面。
type handlerState struct {
	err error

	doc *Document

	raw  []byte
	page []byte

	asset []byte

	jsonETag  string
	pageETag  string
	assetETag string

	opts Options

	once sync.Once
}

// ServeHTTP implements http.Handler. | ServeHTTP 实现 http.Handler。
func (s *handlerState) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.opts.Blocked {
		http.NotFound(w, r)
		return
	}
	switch r.URL.Path {
	case s.opts.Path:
		s.serveJSON(w, r)
	case s.opts.DocsPath:
		s.serveViewer(w, r)
	case s.opts.AssetsPath + ViewerScriptName:
		s.serveAsset(w, r)
	default:
		http.NotFound(w, r)
	}
}

// prepare serializes both payloads exactly once. | prepare 只序列化两个载荷一次。
func (s *handlerState) prepare() {
	s.once.Do(func() {
		doc := s.doc.normalized()
		s.raw, s.err = doc.JSON()
		if s.err != nil {
			return
		}
		s.jsonETag = etagOf(s.raw)
		s.page, s.err = renderViewerWithJSON(doc, s.opts, s.raw)
		if s.err != nil {
			return
		}
		s.pageETag = etagOf(s.page)
	})
}

// serveJSON writes the JSON document, honouring If-None-Match. | serveJSON 写出 JSON 文档，
// 并遵循 If-None-Match。
func (s *handlerState) serveJSON(w http.ResponseWriter, r *http.Request) {
	s.prepare()
	if s.err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	if notModified(w, r, s.jsonETag) {
		return
	}
	w.Header().Set("ETag", s.jsonETag)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(s.raw)
}

// serveViewer writes the built-in viewer, honouring If-None-Match. | serveViewer 写出内置查看器，
// 并遵循 If-None-Match。
func (s *handlerState) serveViewer(w http.ResponseWriter, r *http.Request) {
	s.prepare()
	if s.err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	if notModified(w, r, s.pageETag) {
		return
	}
	w.Header().Set("ETag", s.pageETag)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(s.page)
}

// serveAsset writes the embedded viewer script. | serveAsset 写出内嵌查看器脚本。
func (s *handlerState) serveAsset(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=86400")
	if notModified(w, r, s.assetETag) {
		return
	}
	w.Header().Set("ETag", s.assetETag)
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(s.asset)
}

// ctxResponseWriter adapts a router context to http.ResponseWriter while keeping the router's
// status bookkeeping intact. | ctxResponseWriter 把路由上下文适配为 http.ResponseWriter，同时保留
// 路由的状态记录。
//
// Header goes straight to the underlying writer; WriteHeader goes through Ctx.WriteHeader so
// access logs and the router's written flag observe the final status. | Header 直接写入底层
// 响应；WriteHeader 经过 Ctx.WriteHeader，使访问日志与路由的「已写出」标记看到最终状态。
type ctxResponseWriter struct {
	c *router.Ctx
}

// Header implements http.ResponseWriter. | Header 实现 http.ResponseWriter。
func (w ctxResponseWriter) Header() http.Header { return w.c.Writer.Header() }

// Write implements http.ResponseWriter. | Write 实现 http.ResponseWriter。
func (w ctxResponseWriter) Write(p []byte) (int, error) { return w.c.Writer.Write(p) }

// WriteHeader implements http.ResponseWriter. | WriteHeader 实现 http.ResponseWriter。
func (w ctxResponseWriter) WriteHeader(code int) { w.c.WriteHeader(code) }

// notModified writes 304 and reports true when the request's If-None-Match matches etag. |
// notModified 在请求的 If-None-Match 与 etag 匹配时写出 304 并返回 true。
func notModified(w http.ResponseWriter, r *http.Request, etag string) bool {
	if etag == "" || r == nil || !etagMatches(r.Header.Get("If-None-Match"), etag) {
		return false
	}
	w.Header().Set("ETag", etag)
	w.WriteHeader(http.StatusNotModified)
	return true
}

// etagMatches reports whether an If-None-Match header contains etag, accepting the "*" form
// and weak validators. | etagMatches 报告 If-None-Match 是否包含 etag，接受 "*" 形式与弱校验器。
func etagMatches(header, etag string) bool {
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if part == "*" || part == etag || strings.TrimPrefix(part, "W/") == etag {
			return true
		}
	}
	return false
}

// etagOf builds a strong ETag from the SHA-256 digest of the payload, which is computed once
// per handler when the document is snapshotted. | etagOf 依据载荷的 SHA-256 摘要构造强 ETag，
// 每个处理器只在文档快照时计算一次。
func etagOf(payload []byte) string {
	sum := sha256.Sum256(payload)
	return `"` + hex.EncodeToString(sum[:]) + `"`
}
