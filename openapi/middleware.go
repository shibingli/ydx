package openapi

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
)

// HTTPHandler returns a standard net/http handler serving the JSON document, the built-in
// viewer and the embedded viewer assets. | HTTPHandler 返回提供 JSON 文档、内置查看器与内嵌查看器
// 资源的标准 net/http 处理器。
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
	s.assets = map[string]servedAsset{
		ViewerScriptName: {body: ViewerScript(), contentType: "application/javascript; charset=utf-8"},
		ViewerCSSName:    {body: ViewerCSS(), contentType: "text/css; charset=utf-8"},
		ViewerIconsName:  {body: ViewerIcons(), contentType: "image/svg+xml"},
	}
	for name, asset := range s.assets {
		asset.etag = etagOf(asset.body)
		s.assets[name] = asset
	}
	return s
}

// servedAsset is one embedded viewer asset and its response metadata. | servedAsset 是一个内嵌
// 查看器资源及其响应元数据。
type servedAsset struct {
	body        []byte
	etag        string
	contentType string
}

// handlerState memoizes the serialized document and viewer page. | handlerState 缓存序列化后的
// 文档与查看器页面。
type handlerState struct {
	err error

	doc *Document

	raw  []byte
	page []byte

	assets map[string]servedAsset

	jsonETag string
	pageETag string

	opts Options

	once sync.Once
}

// ServeHTTP implements http.Handler. | ServeHTTP 实现 http.Handler。
func (s *handlerState) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.opts.Blocked {
		http.NotFound(w, r)
		return
	}
	switch {
	case r.URL.Path == s.opts.Path:
		s.serveJSON(w, r)
	case r.URL.Path == s.opts.DocsPath:
		s.serveViewer(w, r)
	case strings.HasPrefix(r.URL.Path, s.opts.AssetsPath):
		asset, ok := s.assets[strings.TrimPrefix(r.URL.Path, s.opts.AssetsPath)]
		if !ok {
			http.NotFound(w, r)
			return
		}
		s.serveAsset(w, r, asset)
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

// serveAsset writes one embedded viewer asset. | serveAsset 写出一个内嵌查看器资源。
func (s *handlerState) serveAsset(w http.ResponseWriter, r *http.Request, asset servedAsset) {
	w.Header().Set("Cache-Control", "public, max-age=86400")
	if notModified(w, r, asset.etag) {
		return
	}
	w.Header().Set("ETag", asset.etag)
	w.Header().Set("Content-Type", asset.contentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(asset.body)
}

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
