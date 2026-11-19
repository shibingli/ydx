package router

import (
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/shibingli/ydx/afs"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/log"
	"github.com/spf13/afero"
)

// SPA wiring errors, declared once at package level. | SPA 装配错误，在包级声明一次。
var (
	// ErrSPANilFS indicates SPAFS was given a nil file system. | ErrSPANilFS 表示 SPAFS 收到了 nil 文件系统。
	ErrSPANilFS = errs.New("router: SPA file system is nil | router：SPA 文件系统为 nil")
	// ErrSPAConflict indicates a second SPA mount on the same router. | ErrSPAConflict 表示同一路由器上重复挂载 SPA。
	ErrSPAConflict = errs.New("router: SPA is already mounted | router：SPA 已挂载")
)

// SPAImmutableCacheControl is the one-year cache policy applied to content-hashed file names. |
// SPAImmutableCacheControl 是作用于内容哈希文件名的、为期一年的缓存策略。
const SPAImmutableCacheControl = "public, max-age=31536000, immutable"

// SPAOption configures SPA hosting. | SPAOption 配置 SPA 托管。
type SPAOption func(*spaConfig)

// spaConfig is the resolved SPA configuration. | spaConfig 是解析后的 SPA 配置。
type spaConfig struct {
	index             string
	indexCacheControl string
	assetCacheControl string
	exclude           []string
}

// defaultSPAConfig returns the configuration used when no option overrides it. | defaultSPAConfig
// 返回没有任何选项覆盖时使用的配置。
func defaultSPAConfig() spaConfig {
	return spaConfig{index: "index.html", indexCacheControl: "no-cache"}
}

// WithSPAIndex sets the fallback document, relative to the mounted root. | WithSPAIndex 设置回退文档，
// 路径相对于挂载根。
//
// Leading slashes are trimmed and the name is cleaned. Empty names, ".", ".." and paths that
// climb out of the root are ignored, so the default "index.html" stays in effect instead of
// silently disabling the fallback. | 前导斜杠会被去除，名称会被清理。空名、"."、".." 以及爬出
// 根目录的路径会被忽略，因此默认的 "index.html" 继续生效，而不是静默关闭回退。
func WithSPAIndex(name string) SPAOption {
	return func(c *spaConfig) {
		name = path.Clean(strings.TrimLeft(name, "/"))
		if name == "." || name == ".." || strings.HasPrefix(name, "../") {
			return
		}
		c.index = name
	}
}

// WithSPAIndexCacheControl sets the Cache-Control of index responses. | WithSPAIndexCacheControl
// 设置入口文档响应的 Cache-Control。
//
// The default "no-cache" forces revalidation, so a new deployment is visible on the next
// navigation instead of after a browser cache expiry. | 默认值 "no-cache" 强制回源校验，
// 新部署在下一次导航即可见，而不必等待浏览器缓存过期。
func WithSPAIndexCacheControl(value string) SPAOption {
	return func(c *spaConfig) { c.indexCacheControl = value }
}

// WithSPAAssetCacheControl sets the Cache-Control of non-index files. | WithSPAAssetCacheControl
// 设置非入口文件的 Cache-Control。
//
// When set, it overrides the automatic policy, which leaves unhashed files without a
// Cache-Control header and marks content-hashed names with SPAImmutableCacheControl. | 设置后
// 会覆盖自动策略：自动策略不给未哈希文件发送 Cache-Control，并对内容哈希文件名使用
// SPAImmutableCacheControl。
func WithSPAAssetCacheControl(value string) SPAOption {
	return func(c *spaConfig) { c.assetCacheControl = value }
}

// WithSPAExclude makes urlPrefixes skip the SPA entirely. | WithSPAExclude 让 urlPrefixes 完全绕过 SPA。
//
// Prefixes match on segment boundaries: "/api" covers "/api" and "/api/users" but not
// "/apiary". They are matched against both the full request path and, for a prefixed mount,
// the path relative to the mount, so "/api" excludes the backend prefix under either entry
// point. Excluded paths never fall back to the index document and are never served from the
// SPA file system; they continue to the router's custom 404 or the default 404. The root
// prefix is ignored because excluding everything would make the mount meaningless. | 前缀按
// 分段边界匹配："/api" 覆盖 "/api" 与 "/api/users"，但不覆盖 "/apiary"。匹配同时针对完整请求
// 路径与（前缀挂载时的）挂载相对路径，因此 "/api" 在两种入口下都排除后端前缀。被排除的路径既不
// 回退到入口文档，也不从 SPA 文件系统输出，而是继续交给路由自定义 404 或默认 404。根前缀会被
// 忽略，因为排除一切会让挂载失去意义。
func WithSPAExclude(urlPrefixes ...string) SPAOption {
	return func(c *spaConfig) {
		for _, p := range urlPrefixes {
			if p = normalizeSPAPrefix(p); p != "" {
				c.exclude = append(c.exclude, p)
			}
		}
	}
}

// spaHandler serves one SPA deployment: static files first, then the history fallback. | spaHandler
// 托管一套 SPA 部署：先输出静态文件，再回退到 history 入口。
type spaHandler struct {
	files             http.FileSystem
	prefix            string
	index             string
	indexCacheControl string
	assetCacheControl string
	exclude           []string
}

// SPAFS mounts fsys as a single-page application rooted at urlPrefix. | SPAFS 把 fsys 作为单页应用挂载在 urlPrefix。
//
// Files are served exactly as they exist; a GET/HEAD request that matches no file and carries
// no file extension falls back to the index document (history mode). The SPA is consulted only
// when no route matches, so registered routes always win. Only one SPA can be mounted per
// router; a second call, like a nil file system, is a wiring error that marks the router
// broken, after which every request is refused with 500 until the wiring is fixed. | 文件按原样
// 输出；未命中文件且最后一段不含扩展名的 GET/HEAD 请求回退到入口文档（history 模式）。只有没有
// 任何路由命中时才查询 SPA，因此已注册路由始终优先。每个路由器只能挂载一套 SPA；第二次调用与
// nil 文件系统一样属于装配错误，会把路由器标记为损坏，修复装配前所有请求都以 500 拒绝。
func (r *Router) SPAFS(urlPrefix string, fsys afero.Fs, opts ...SPAOption) {
	if fsys == nil {
		r.recordWiringError(ErrSPANilFS)
		return
	}
	h := buildSPAHandler(fsys, urlPrefix, opts)
	if f, err := h.files.Open("/" + h.index); err != nil {
		// A typo in the dist path would otherwise turn every deep link into a silent 404.
		// Recording a wiring error would be harsher than the failure itself, so the mount is
		// kept and the misconfiguration is surfaced once, here. | 否则 dist 路径中的笔误会让所有
		// 深链变成静默 404。登记装配错误会比问题本身更严厉，因此保留挂载并在此处一次性暴露配置
		// 错误。
		log.Default().Warn("router: SPA index document is missing | router：SPA 入口文档缺失",
			log.Str("prefix", h.prefix), log.Str("index", h.index))
	} else {
		_ = f.Close()
	}
	r.mu.Lock()
	conflict := r.spa != nil
	if !conflict {
		r.spa = h
		r.publishStateLocked()
	}
	r.mu.Unlock()
	if conflict {
		r.recordWiringError(ErrSPAConflict)
	}
}

// SPA mounts the local directory dir as a single-page application rooted at urlPrefix. | SPA 把
// 本地目录 dir 作为单页应用挂载在 urlPrefix。
//
// dir is confined by afs.NewOS: ".." cannot climb out, and "" or "." serves the current working
// directory. | dir 由 afs.NewOS 约束：".." 无法爬出根目录，空串或 "." 表示当前工作目录。
func (r *Router) SPA(urlPrefix, dir string, opts ...SPAOption) {
	r.SPAFS(urlPrefix, afs.NewOS(dir), opts...)
}

// NewSPAHandler returns a standalone SPA handler for plain net/http servers. | NewSPAHandler
// 返回可独立用于原生 net/http 服务器的 SPA 处理器。
//
// The handler maps the request path directly onto the file system root; mount it under a prefix
// with http.StripPrefix in the usual way. Requests the SPA does not own (non-GET/HEAD, excluded
// prefixes, missing assets) receive a plain 404. A nil file system never panics: every request
// is answered with 404. Directory redirects are built from the stripped path, so an SPA mounted
// under "/app" with StripPrefix would redirect "/app/docs" to "/docs/"; use Router.SPAFS for
// prefix mounts that need correct redirects and the router's middleware/404 integration. |
// 处理器把请求路径直接映射到文件系统根；按常规方式配合 http.StripPrefix 挂载到前缀下。SPA
// 不负责的请求（非 GET/HEAD、排除前缀、缺失资源）得到纯 404。nil 文件系统不会 panic：所有请求
// 都以 404 应答。目录重定向基于剥离后的路径生成，因此用 StripPrefix 挂在 "/app" 下的 SPA 会把
// "/app/docs" 重定向到 "/docs/"；需要正确重定向以及路由中间件/404 集成的前缀挂载应使用
// Router.SPAFS。
func NewSPAHandler(fsys afero.Fs, opts ...SPAOption) http.Handler {
	if fsys == nil {
		return nilSPAHandler{}
	}
	return buildSPAHandler(fsys, "", opts)
}

// nilSPAHandler answers every request with 404. | nilSPAHandler 对每个请求应答 404。
type nilSPAHandler struct{}

// ServeHTTP implements http.Handler. | ServeHTTP 实现 http.Handler。
func (nilSPAHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }

// buildSPAHandler resolves opts and constructs the handler. | buildSPAHandler 解析 opts 并构造处理器。
func buildSPAHandler(fsys afero.Fs, urlPrefix string, opts []SPAOption) *spaHandler {
	cfg := defaultSPAConfig()
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return &spaHandler{
		files:             afs.NewHTTPFileSystem(fsys),
		exclude:           cfg.exclude,
		prefix:            normalizeSPAPrefix(urlPrefix),
		index:             cfg.index,
		indexCacheControl: cfg.indexCacheControl,
		assetCacheControl: cfg.assetCacheControl,
	}
}

// ServeHTTP implements http.Handler for direct net/http use. | ServeHTTP 为原生 net/http 直用实现
// http.Handler。
func (s *spaHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !s.serve(w, r) {
		http.NotFound(w, r)
	}
}

// normalizeSPAPrefix keeps a URL prefix in the form "/a/b"; root is "". | normalizeSPAPrefix
// 把 URL 前缀整理为 "/a/b" 形式；根路径为空串。
func normalizeSPAPrefix(prefix string) string {
	if prefix == "" {
		return ""
	}
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	prefix = path.Clean(prefix)
	if prefix == "/" {
		return ""
	}
	return prefix
}

// relativePath maps the request path to a file path under the mount prefix. | relativePath 把请求路径
// 映射为挂载前缀下的文件路径。
func (s *spaHandler) relativePath(urlPath string) (string, bool) {
	if s.prefix == "" {
		return strings.TrimPrefix(urlPath, "/"), true
	}
	if urlPath == s.prefix {
		return "", true
	}
	if strings.HasPrefix(urlPath, s.prefix+"/") {
		return urlPath[len(s.prefix)+1:], true
	}
	return "", false
}

// serve answers the request when the SPA owns it and reports whether it wrote a response. | serve
// 在 SPA 负责该请求时应答，并报告是否写出了响应。
func (s *spaHandler) serve(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	rel, ok := s.relativePath(r.URL.Path)
	if !ok {
		return false
	}
	if s.excluded(r.URL.Path) {
		return false
	}
	f, info, ok := s.open(rel)
	if ok {
		if info.IsDir() {
			_ = f.Close()
			// Directories keep normal file-server semantics: a missing trailing slash gets one
			// redirect, and the directory's own index document (when present) answers the
			// request. Listings are never produced. | 目录保持常规文件服务器语义：缺少尾斜杠时
			// 重定向一次，目录自带的入口文档（若存在）应答请求。绝不输出目录列举。
			if !strings.HasSuffix(r.URL.Path, "/") {
				s.redirectDir(w, r)
				return true
			}
			if name := path.Join(rel, s.index); name != "" {
				if df, dinfo, dok := s.open(name); dok && !dinfo.IsDir() {
					s.writeFile(w, r, df, dinfo, s.cacheControl(name))
					return true
				}
			}
		} else {
			s.writeFile(w, r, f, info, s.cacheControl(rel))
			return true
		}
	}
	// A path whose last segment carries an extension is an asset request. Answering it with
	// index.html would turn a broken bundle reference into a silent 200 of the wrong type. |
	// 最后一段带扩展名的路径是资源请求。用 index.html 应答它会让损坏的打包引用变成类型错误的
	// 静默 200。
	if hasFileExtension(rel) {
		return false
	}
	return s.writeIndex(w, r)
}

// open resolves rel to a file or directory. Callers must close the file. | open 把 rel 解析为文件
// 或目录。调用方必须关闭返回的文件。
func (s *spaHandler) open(rel string) (http.File, fs.FileInfo, bool) {
	f, err := s.files.Open("/" + rel)
	if err != nil {
		return nil, nil, false
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, false
	}
	return f, info, true
}

// redirectDir sends a directory request to its trailing-slash form. | redirectDir 把目录请求
// 重定向到带尾斜杠的形式。
//
// The target is cleaned before it reaches the Location header: a request for "//host/path"
// would otherwise produce a protocol-relative redirect that points at another host. | 目标在
// 写入 Location 之前会被清理：否则 "//host/path" 这类请求会产生指向其他主机的协议相对重定向。
func (s *spaHandler) redirectDir(w http.ResponseWriter, r *http.Request) {
	target := path.Clean(r.URL.EscapedPath())
	if target == "" || target == "." {
		target = "/"
	}
	if !strings.HasPrefix(target, "/") {
		target = "/" + target
	}
	target = strings.TrimSuffix(target, "/") + "/"
	if q := r.URL.RawQuery; q != "" {
		target += "?" + q
	}
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}

// writeFile streams f with Range, conditional-request and HEAD semantics. | writeFile 按 Range、
// 条件请求与 HEAD 语义输出 f。
func (s *spaHandler) writeFile(w http.ResponseWriter, r *http.Request, f http.File, info fs.FileInfo, cacheControl string) {
	defer func() { _ = f.Close() }()
	h := w.Header()
	if cacheControl != "" {
		h.Set("Cache-Control", cacheControl)
	}
	// The type may be inferred from the extension or content, so never let a browser
	// second-guess it. | 类型可能由扩展名或内容推断，因此绝不让浏览器再猜一次。
	h.Set("X-Content-Type-Options", "nosniff")
	// Derive a strong validator from size and mtime exactly like Download does, so conditional
	// GETs revalidate without downloading the body. | 与 Download 一样由大小与修改时间派生强验证器，
	// 使条件 GET 无需下载正文即可完成校验。
	if h.Get("ETag") == "" && !info.ModTime().IsZero() {
		h.Set("ETag", quoteETag(derivedETag(info.ModTime(), info.Size())))
	}
	http.ServeContent(w, r, info.Name(), info.ModTime(), f)
}

// cacheControl resolves the Cache-Control for one file. | cacheControl 解析单个文件的 Cache-Control。
func (s *spaHandler) cacheControl(rel string) string {
	if s.isIndex(rel) {
		return s.indexCacheControl
	}
	if s.assetCacheControl != "" {
		return s.assetCacheControl
	}
	if hashedAssetName(rel) {
		return SPAImmutableCacheControl
	}
	return ""
}

// isIndex reports whether rel names an entry document, including nested ones. | isIndex 报告 rel
// 是否为入口文档（包括子目录中的入口）。
func (s *spaHandler) isIndex(rel string) bool {
	return s.index != "" && (rel == s.index || strings.HasSuffix(rel, "/"+s.index))
}

// hashedAssetName reports whether the file name looks content-hashed. | hashedAssetName 报告文件名
// 是否看起来带内容哈希。
//
// The rule is deliberately narrow: the extension-less last segment must contain a separator
// followed by at least eight alphanumerics that include a digit or mix upper and lower case
// (for example "app-4f3a2b1c.js", "index-DiwrgTda.js" or "main.4f3a2b1c.chunk.js"). Ordinary
// build names such as "react-dom.production.min.js", "vendor-polyfills.js" or
// "jquery-3.7.10.min.js" never match, because their runs are all lower case with no digit. |
// 规则刻意保持狭窄：去掉扩展名的最后一段必须包含一个分隔符以及至少八个字母数字字符，且其中
// 含数字或大小写混合（例如 "app-4f3a2b1c.js"、"index-DiwrgTda.js" 或
// "main.4f3a2b1c.chunk.js"）。"react-dom.production.min.js"、"vendor-polyfills.js" 或
// "jquery-3.7.10.min.js" 这类常见构建名不会命中，因为它们的分段全为小写且不含数字。
func hashedAssetName(rel string) bool {
	base := rel
	if i := strings.LastIndexByte(base, '/'); i >= 0 {
		base = base[i+1:]
	}
	if dot := strings.LastIndexByte(base, '.'); dot >= 0 {
		base = base[:dot]
	}
	for i := 0; i < len(base); i++ {
		if base[i] != '-' && base[i] != '.' && base[i] != '_' {
			continue
		}
		j := i + 1
		for j < len(base) && isHashByte(base[j]) {
			j++
		}
		if looksLikeHashRun(base[i+1 : j]) {
			return true
		}
	}
	return false
}

// looksLikeHashRun reports whether run has the shape of a content hash rather than a word. | looksLikeHashRun
// 报告 run 是否具有内容哈希而不是普通单词的形态。
func looksLikeHashRun(run string) bool {
	if len(run) < 8 {
		return false
	}
	var upper, lower, digit bool
	for i := 0; i < len(run); i++ {
		b := run[i]
		switch {
		case b >= '0' && b <= '9':
			digit = true
		case b >= 'A' && b <= 'Z':
			upper = true
		case b >= 'a' && b <= 'z':
			lower = true
		}
	}
	return digit || (upper && lower)
}

// isHashByte reports whether b is an alphanumeric base64url byte. Separators are deliberately
// excluded so that a run of dash-joined words can never be mistaken for a hash. | isHashByte
// 报告 b 是否为 base64url 字母表中的字母或数字。分隔符被刻意排除，使由连字符连接的普通单词
// 绝不会被误判为哈希。
func isHashByte(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

// excluded reports whether urlPath falls under one of the configured prefixes. | excluded 报告
// urlPath 是否落在已配置的前缀之下。
//
// The full request path and the mount-relative path are both checked, so an exclusion behaves
// the same whether the SPA is mounted at the root or under a prefix. | 完整请求路径与挂载相对
// 路径都会被检查，因此无论 SPA 挂在根路径还是前缀下，排除规则的含义都一致。
func (s *spaHandler) excluded(urlPath string) bool {
	rel, ok := s.relativePath(urlPath)
	for _, p := range s.exclude {
		if prefixMatches(urlPath, p) {
			return true
		}
		if ok && prefixMatches("/"+rel, p) {
			return true
		}
	}
	return false
}

// prefixMatches reports whether urlPath equals prefix or lies beneath it. | prefixMatches 报告
// urlPath 是否等于 prefix 或位于其下。
func prefixMatches(urlPath, prefix string) bool {
	return urlPath == prefix || strings.HasPrefix(urlPath, prefix+"/")
}

// writeIndex answers with the fallback document. | writeIndex 用回退文档应答。
func (s *spaHandler) writeIndex(w http.ResponseWriter, r *http.Request) bool {
	f, err := s.files.Open("/" + s.index)
	if err != nil {
		return false
	}
	info, err := f.Stat()
	if err != nil || info.IsDir() {
		_ = f.Close()
		return false
	}
	s.writeFile(w, r, f, info, s.indexCacheControl)
	return true
}

// hasFileExtension reports whether the last path segment contains a dot. | hasFileExtension 报告
// 路径最后一段是否含点号。
func hasFileExtension(rel string) bool {
	rel = strings.TrimSuffix(rel, "/")
	if i := strings.LastIndexByte(rel, '/'); i >= 0 {
		rel = rel[i+1:]
	}
	return strings.ContainsRune(rel, '.')
}
