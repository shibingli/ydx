package transport

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
	"github.com/shibingli/ydx/router"
)

// Default HTTP handler values. | HTTP 处理器默认值。
const (
	// DefaultHandlerPrefix is the default mount path. | DefaultHandlerPrefix 是默认挂载路径。
	DefaultHandlerPrefix = "/captcha"
	// DefaultMaxBodyBytes is the default JSON request body limit. | DefaultMaxBodyBytes 是默认 JSON 请求正文上限。
	DefaultMaxBodyBytes = 64 << 10
	// maxHandlerBodyBytes is the hard body limit regardless of configuration. | maxHandlerBodyBytes 是无论配置如何的硬正文上限。
	maxHandlerBodyBytes = 1 << 20
)

// HandlerOptions configures the native and YD HTTP entry points. | HandlerOptions 配置原生与 YD HTTP 入口。
type HandlerOptions struct {
	// Prefix is the mount path; empty means /captcha. | Prefix 是挂载路径；空值表示 /captcha。
	Prefix string
	// TrustedProxies overrides the manager's trusted proxy list when non-empty. | TrustedProxies 非空时覆盖管理器的可信代理列表。
	TrustedProxies []netip.Prefix
	// MaxBodyBytes is the JSON body limit; non-positive means 64 KiB. | MaxBodyBytes 是 JSON 正文上限；非正值表示 64 KiB。
	MaxBodyBytes int64
	// DisableAssets disables the embedded SDK asset endpoint. | DisableAssets 关闭嵌入 SDK 资源端点。
	DisableAssets bool
	// LocaleQuery is the language query parameter; empty means lang. | LocaleQuery 是语言查询参数；空值为 lang。
	LocaleQuery string
	// LocaleHeader is the language header; empty means X-Lang. | LocaleHeader 是语言请求头；空值为 X-Lang。
	LocaleHeader string
}

// Handler serves the captcha HTTP API and embedded frontend assets. | Handler 提供验证码 HTTP API 与嵌入前端资源。
type Handler struct {
	manager      Manager
	prefix       string
	trusted      []netip.Prefix
	maxBody      int64
	assets       bool
	localeQuery  string
	localeHeader string
}

// newHandler builds a native net/http handler for one manager. | newHandler 为一个管理器构建原生 net/http 处理器。
func newHandler(manager Manager, options HandlerOptions) *Handler {
	prefix := normalizePrefix(options.Prefix)
	maxBody := options.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = DefaultMaxBodyBytes
	}
	if maxBody > maxHandlerBodyBytes {
		maxBody = maxHandlerBodyBytes
	}
	trusted := options.TrustedProxies
	if len(trusted) == 0 && manager != nil {
		trusted = manager.TrustedProxies()
	}
	localeQuery := strings.TrimSpace(options.LocaleQuery)
	if localeQuery == "" {
		localeQuery = "lang"
	}
	localeHeader := strings.TrimSpace(options.LocaleHeader)
	if localeHeader == "" {
		localeHeader = "X-Lang"
	}
	return &Handler{
		manager:      manager,
		prefix:       prefix,
		maxBody:      maxBody,
		assets:       !options.DisableAssets,
		trusted:      append([]netip.Prefix(nil), trusted...),
		localeQuery:  localeQuery,
		localeHeader: localeHeader,
	}
}

// Prefix returns the normalized mount path. | Prefix 返回规范化挂载路径。
func (h *Handler) Prefix() string {
	if h == nil {
		return ""
	}
	return h.prefix
}

// ServeHTTP implements http.Handler. | ServeHTTP 实现 http.Handler。
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.manager == nil {
		writeAPIError(w, ErrClosed)
		return
	}
	if r == nil || w == nil {
		return
	}
	path := r.URL.Path
	if path != h.prefix && !strings.HasPrefix(path, h.prefix+"/") {
		http.NotFound(w, r)
		return
	}
	rest := strings.TrimPrefix(path, h.prefix)
	locale := h.locale(r)
	w.Header().Set("Content-Language", locale)
	addVary(w, "Accept-Language", h.localeHeader)
	if r.Method == http.MethodOptions {
		setCORSHeaders(w, r.Header.Get("Origin"), h.manager.AllowedOrigins(), r.Header.Get("Access-Control-Request-Headers"))
		w.WriteHeader(http.StatusNoContent)
		return
	}
	switch {
	case strings.HasPrefix(rest, "/image/"):
		h.serveImage(w, r, strings.TrimPrefix(rest, "/image/"))
		return
	case strings.HasPrefix(rest, "/assets/"):
		if !h.assets {
			http.NotFound(w, r)
			return
		}
		h.serveAsset(w, r, strings.TrimPrefix(rest, "/assets/"))
		return
	}
	origin := r.Header.Get("Origin")
	allowedOrigins := h.manager.AllowedOrigins()
	if origin != "" && len(allowedOrigins) > 0 {
		if _, ok := corsOrigin(origin, allowedOrigins); !ok {
			h.writeError(w, ErrOriginNotAllowed, locale)
			return
		}
	}
	setCORSHeaders(w, origin, allowedOrigins)
	if r.Method != http.MethodPost {
		w.Header()["Allow"] = []string{http.MethodPost}
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{OK: false, Error: &apiError{Code: "method_not_allowed", Message: "POST required | 需要 POST"}})
		return
	}
	if contentType := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type"))); contentType != "" && !strings.HasPrefix(contentType, "application/json") {
		h.writeError(w, ErrUnsupportedMediaType, locale)
		return
	}
	switch rest {
	case "/challenge":
		var req CreateRequest
		if err := h.decode(w, r, &req); err != nil {
			h.writeError(w, err, locale)
			return
		}
		req.Meta = h.meta(r)
		if locale = h.useBodyLocale(w, req.Locale, locale); req.Locale == "" {
			req.Locale = locale
		}
		challenge, err := h.manager.Create(r.Context(), req)
		if err != nil {
			h.writeError(w, err, locale)
			return
		}
		writeChallenge(w, challenge)
	case "/verify":
		var req VerifyRequest
		if err := h.decode(w, r, &req); err != nil {
			h.writeError(w, err, locale)
			return
		}
		req.Meta = h.meta(r)
		result, err := h.manager.Verify(r.Context(), req)
		if err != nil {
			h.writeError(w, err, locale)
			return
		}
		writeResult(w, result)
	case "/send":
		var req SendRequest
		if err := h.decode(w, r, &req); err != nil {
			h.writeError(w, err, locale)
			return
		}
		req.Meta = h.meta(r)
		if locale = h.useBodyLocale(w, req.Locale, locale); req.Locale == "" {
			req.Locale = locale
		}
		challenge, err := h.manager.SendCode(r.Context(), req)
		if err != nil {
			h.writeError(w, err, locale)
			return
		}
		writeChallenge(w, challenge)
	case "/token/consume":
		var req struct {
			Token  string `json:"token"`
			Action string `json:"action"`
		}
		if err := h.decode(w, r, &req); err != nil {
			h.writeError(w, err, locale)
			return
		}
		claims, err := h.manager.ConsumeToken(r.Context(), req.Token, req.Action)
		if err != nil {
			h.writeError(w, err, locale)
			return
		}
		writeClaims(w, claims)
	default:
		http.NotFound(w, r)
	}
}

// localeFromRequest resolves the default language sources for middleware. | localeFromRequest 为中间件解析默认语言来源。
func localeFromRequest(m Manager, r *http.Request) string {
	if m == nil || r == nil {
		return ""
	}
	if value := strings.TrimSpace(r.URL.Query().Get("lang")); value != "" {
		return m.NormalizeLocale(value)
	}
	if value := strings.TrimSpace(r.Header.Get("X-Lang")); value != "" {
		return m.NormalizeLocale(value)
	}
	return m.NormalizeLocale(r.Header.Get("Accept-Language"))
}

// locale resolves the request language from query, header, then Accept-Language. | locale 依次从查询参数、请求头与 Accept-Language 解析语言。
func (h *Handler) locale(r *http.Request) string {
	if h == nil || h.manager == nil {
		return ""
	}
	if value := strings.TrimSpace(r.URL.Query().Get(h.localeQuery)); value != "" {
		return h.manager.NormalizeLocale(value)
	}
	if value := strings.TrimSpace(r.Header.Get(h.localeHeader)); value != "" {
		return h.manager.NormalizeLocale(value)
	}
	return h.manager.NormalizeLocale(r.Header.Get("Accept-Language"))
}

// useBodyLocale prefers an explicit body locale and updates response headers. | useBodyLocale 优先使用请求体语言并更新响应头。
func (h *Handler) useBodyLocale(w http.ResponseWriter, bodyLocale, current string) string {
	if strings.TrimSpace(bodyLocale) == "" || h.manager == nil {
		return current
	}
	locale := h.manager.NormalizeLocale(bodyLocale)
	if locale != current {
		w.Header().Set("Content-Language", locale)
	}
	return locale
}

// writeError writes a localized API error. | writeError 写出本地化 API 错误。
func (h *Handler) writeError(w http.ResponseWriter, err error, locale string) {
	if h == nil || h.manager == nil {
		writeAPIError(w, err)
		return
	}
	writeAPIErrorWith(w, err, h.manager.ErrorMessage(locale, err))
}

// addVary appends unique Vary values. | addVary 追加去重的 Vary 值。
func addVary(w http.ResponseWriter, values ...string) {
	header := w.Header()
	existing := header.Values("Vary")
	seen := make(map[string]struct{}, len(existing)+len(values))
	for _, value := range existing {
		for _, item := range strings.Split(value, ",") {
			item = strings.TrimSpace(item)
			if item != "" {
				seen[item] = struct{}{}
			}
		}
	}
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		header.Add("Vary", value)
		seen[value] = struct{}{}
	}
}

// decode reads a bounded JSON body. | decode 读取有界 JSON 正文。
func (h *Handler) decode(w http.ResponseWriter, r *http.Request, value any) error {
	if r.Body == nil {
		return ErrInvalidRequest
	}
	body := http.MaxBytesReader(w, r.Body, h.maxBody)
	payload, err := io.ReadAll(body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return ErrRequestTooLarge
		}
		return errs.Wrap(err, ErrInvalidRequest)
	}
	if len(payload) == 0 {
		return ErrInvalidRequest
	}
	if err := json.Unmarshal(payload, value); err != nil {
		return errs.Wrap(err, ErrInvalidRequest)
	}
	return nil
}

// meta extracts the authoritative transport context. | meta 提取权威传输上下文。
func (h *Handler) meta(r *http.Request) Meta {
	var ctx router.Ctx
	ctx.Request = r
	return Meta{
		IP:        ctx.ClientIP(h.trusted),
		UserAgent: r.UserAgent(),
		Origin:    r.Header.Get("Origin"),
		RequestID: r.Header.Get("X-Request-ID"),
	}
}

// serveImage writes one stored challenge image. | serveImage 写出一张已存储的挑战图片。
func (h *Handler) serveImage(w http.ResponseWriter, r *http.Request, key string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header()["Allow"] = []string{http.MethodGet, http.MethodHead}
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{OK: false, Error: &apiError{Code: "method_not_allowed", Message: "GET required | 需要 GET"}})
		return
	}
	if key == "" || strings.Contains(key, "/") {
		http.NotFound(w, r)
		return
	}
	data, mime, ok, err := h.manager.Image(r.Context(), key)
	if err != nil {
		h.writeError(w, err, h.locale(r))
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	setCORSHeaders(w, r.Header.Get("Origin"), h.manager.AllowedOrigins())
	header := w.Header()
	header["Content-Type"] = []string{mime}
	header["Cache-Control"] = []string{"private, max-age=60"}
	header["X-Content-Type-Options"] = []string{"nosniff"}
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// contextWithClaims returns a request context carrying verified claims. | contextWithClaims 返回携带已验证载荷的请求上下文。
func contextWithClaims(ctx context.Context, claims *TokenClaims) context.Context {
	return context.WithValue(ctx, claimsContextKey{}, claims)
}

// claimsContextKey is the private context key for verified claims. | claimsContextKey 是已验证载荷的私有上下文键。
type claimsContextKey struct{}

// ClaimsFromContext returns verified claims from a request context. | ClaimsFromContext 从请求上下文返回已验证载荷。
func ClaimsFromContext(ctx context.Context) (*TokenClaims, bool) {
	if ctx == nil {
		return nil, false
	}
	claims, ok := ctx.Value(claimsContextKey{}).(*TokenClaims)
	return claims, ok
}

// normalizePrefix normalizes a mount path. | normalizePrefix 规范化挂载路径。
func normalizePrefix(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" || prefix == "/" {
		return DefaultHandlerPrefix
	}
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	prefix = strings.TrimRight(prefix, "/")
	if prefix == "" {
		return DefaultHandlerPrefix
	}
	return prefix
}
