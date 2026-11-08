package kms

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/shibingli/ydx/errs"
)

// allowMethods is the CORS method allowlist used by preflight responses. | allowMethods 是预检响应
// 使用的 CORS 方法允许列表。
const allowMethods = "GET, POST, PATCH, DELETE, OPTIONS"

// allowHeaders is the fallback CORS request-header allowlist. | allowHeaders 是回退的 CORS 请求头允许列表。
const allowHeaders = "Authorization, Content-Type, X-CSRF-Token, X-Request-ID"

// preflightMaxAge is the preflight cache lifetime in seconds. | preflightMaxAge 是预检缓存秒数。
const preflightMaxAge = "600"

// serverSecurity holds the normalized browser-facing guards. | serverSecurity 保存规范化后的浏览器
// 侧防护配置。
type serverSecurity struct {
	// allowedOrigins holds normalized cross-origin allowlist entries. | allowedOrigins 保存规范化后的跨域允许列表。
	allowedOrigins map[string]struct{}
	// allowAnyOrigin is true when AllowedOrigins contains "*". | allowAnyOrigin 在 AllowedOrigins 含 "*" 时为 true。
	allowAnyOrigin bool
	// allowedHosts holds normalized Host allowlist entries. | allowedHosts 保存规范化后的 Host 允许列表。
	allowedHosts map[string]struct{}
	// allowAnyHost is true when AllowedHosts contains "*". | allowAnyHost 在 AllowedHosts 含 "*" 时为 true。
	allowAnyHost bool
	// requireSameOrigin enforces same-origin evidence on unsafe methods. | requireSameOrigin 在非安全
	// 方法上强制同源证据。
	requireSameOrigin bool
	// cookieAuth marks deployments that authenticate with cookies. | cookieAuth 标记使用 Cookie 认证的部署。
	cookieAuth bool
	// csrfCheck is the optional application CSRF validator. | csrfCheck 是可选的应用 CSRF 校验器。
	csrfCheck func(*http.Request) error
}

// newServerSecurity normalizes and validates the browser-facing configuration. | newServerSecurity
// 规范化并校验浏览器侧配置。
func newServerSecurity(config ServerConfig) (serverSecurity, error) {
	security := serverSecurity{
		requireSameOrigin: config.RequireSameOrigin,
		cookieAuth:        config.CookieAuth,
		csrfCheck:         config.CSRFCheck,
	}
	for _, raw := range config.AllowedOrigins {
		origin := strings.TrimSpace(raw)
		if origin == "" {
			continue
		}
		if origin == "*" {
			if config.CookieAuth {
				return serverSecurity{}, errs.Detail(ErrInvalidConfig, "wildcard AllowedOrigins is unsafe with CookieAuth | CookieAuth 下使用通配 AllowedOrigins 不安全")
			}
			security.allowAnyOrigin = true
			continue
		}
		normalized, err := normalizeOrigin(origin)
		if err != nil {
			return serverSecurity{}, errs.WrapDetail(err, ErrInvalidConfig, "invalid allowed origin %[1]q | 允许来源 %[1]q 非法", raw)
		}
		if security.allowedOrigins == nil {
			security.allowedOrigins = make(map[string]struct{})
		}
		security.allowedOrigins[normalized] = struct{}{}
	}
	for _, raw := range config.AllowedHosts {
		host := strings.TrimSpace(raw)
		if host == "" {
			continue
		}
		if host == "*" {
			security.allowAnyHost = true
			continue
		}
		normalized, err := normalizeHost(host)
		if err != nil {
			return serverSecurity{}, errs.WrapDetail(err, ErrInvalidConfig, "invalid allowed host %[1]q | 允许主机 %[1]q 非法", raw)
		}
		if security.allowedHosts == nil {
			security.allowedHosts = make(map[string]struct{})
		}
		security.allowedHosts[normalized] = struct{}{}
	}
	return security, nil
}

// normalizeOrigin parses an origin URL and returns scheme://host with default ports removed. | normalizeOrigin
// 解析来源 URL，返回移除默认端口后的 scheme://host。
func normalizeOrigin(raw string) (string, error) {
	if raw == "null" {
		return "", errs.Detail(ErrInvalidConfig, "opaque origin is not allowed | 不允许不透明来源")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", errs.WrapDetail(err, ErrInvalidConfig, "parse origin | 解析来源")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", errs.Detail(ErrInvalidConfig, "origin scheme must be http or https | 来源 scheme 必须为 http 或 https")
	}
	if parsed.Host == "" || parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errs.Detail(ErrInvalidConfig, "origin must contain only scheme and host | 来源只能包含 scheme 与主机")
	}
	return parsed.Scheme + "://" + normalizeHostPort(parsed.Host, parsed.Scheme), nil
}

// normalizeHost validates and normalizes a Host allowlist entry. | normalizeHost 校验并规范化 Host
// 允许列表条目。
func normalizeHost(raw string) (string, error) {
	if strings.ContainsAny(raw, "/?#@") || strings.ContainsAny(raw, " \t\r\n") {
		return "", errs.Detail(ErrInvalidConfig, "host must not contain a path, credentials or whitespace | 主机不得包含路径、凭据或空白")
	}
	host := canonicalHost(raw)
	if host == "" {
		return "", errs.Detail(ErrInvalidConfig, "host is empty | 主机为空")
	}
	return host, nil
}

// normalizeHostPort lowercases host and removes the default port for scheme. | normalizeHostPort 把
// 主机转小写并移除 scheme 对应默认端口。
func normalizeHostPort(host, scheme string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	switch {
	case scheme == "https" && strings.HasSuffix(host, ":443"):
		return strings.TrimSuffix(host, ":443")
	case scheme == "http" && strings.HasSuffix(host, ":80"):
		return strings.TrimSuffix(host, ":80")
	}
	return host
}

// canonicalHost lowercases host and strips a default HTTP or HTTPS port. | canonicalHost 把主机转小写
// 并移除默认 HTTP 或 HTTPS 端口。
func canonicalHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimSuffix(host, ":443")
	host = strings.TrimSuffix(host, ":80")
	return host
}

// disabled reports whether no browser-facing guard is configured. | disabled 报告是否未配置任何浏览器
// 侧防护。
func (s *serverSecurity) disabled() bool {
	return len(s.allowedOrigins) == 0 && !s.allowAnyOrigin && len(s.allowedHosts) == 0 &&
		!s.allowAnyHost && !s.requireSameOrigin && !s.cookieAuth && s.csrfCheck == nil
}

// enforcesSameOrigin reports whether unsafe methods require same-origin evidence. | enforcesSameOrigin
// 报告非安全方法是否要求同源证据。
func (s *serverSecurity) enforcesSameOrigin() bool {
	return s.requireSameOrigin || s.cookieAuth || s.csrfCheck != nil
}

// hostAllowed checks the request Host against the allowlist. | hostAllowed 用允许列表校验请求 Host。
func (s *serverSecurity) hostAllowed(host string) bool {
	if len(s.allowedHosts) == 0 || s.allowAnyHost {
		return true
	}
	_, ok := s.allowedHosts[canonicalHost(host)]
	return ok
}

// originAllowed checks a parsed cross-origin against the allowlist. | originAllowed 用允许列表校验
// 解析后的跨域来源。
func (s *serverSecurity) originAllowed(origin string) bool {
	if s.allowAnyOrigin {
		return true
	}
	_, ok := s.allowedOrigins[origin]
	return ok
}

// sameOrigin reports whether origin matches the request scheme and Host. | sameOrigin 报告来源是否
// 匹配请求 scheme 与 Host。
func (s *serverSecurity) sameOrigin(r *http.Request, origin string) bool {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	} else if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); forwarded == "http" || forwarded == "https" {
		scheme = forwarded
	}
	return origin == scheme+"://"+normalizeHostPort(r.Host, scheme)
}

// applySecurity enforces Host, Origin, CORS preflight and CSRF rules. It returns false when it has
// already written a response. | applySecurity 执行 Host、Origin、CORS 预检与 CSRF 规则。已写出响应
// 时返回 false。
func (s *Server) applySecurity(w http.ResponseWriter, r *http.Request) bool {
	security := &s.security
	if security.disabled() {
		if r.Method == http.MethodOptions {
			writeAllow(w)
			return false
		}
		return true
	}
	if !security.hostAllowed(r.Host) {
		writeError(w, errs.Detail(ErrForbidden, "host %[1]q is not allowed | 主机 %[1]q 不被允许", r.Host))
		return false
	}
	originHeader := strings.TrimSpace(r.Header.Get("Origin"))
	origin := ""
	cross := false
	if originHeader != "" {
		parsed, err := normalizeOrigin(originHeader)
		if err != nil {
			writeError(w, errs.WrapDetail(err, ErrForbidden, "origin %[1]q is not allowed | 来源 %[1]q 不被允许", originHeader))
			return false
		}
		if !security.sameOrigin(r, parsed) {
			cross = true
			if !security.originAllowed(parsed) {
				writeError(w, errs.Detail(ErrForbidden, "origin %[1]q is not allowed | 来源 %[1]q 不被允许", parsed))
				return false
			}
			w.Header().Set("Access-Control-Allow-Origin", parsed)
			w.Header().Add("Vary", "Origin")
			if security.cookieAuth {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}
		}
		origin = parsed
	}
	if r.Method == http.MethodOptions {
		if originHeader != "" && r.Header.Get("Access-Control-Request-Method") != "" {
			writePreflight(w, r)
			return false
		}
		writeAllow(w)
		return false
	}
	if security.enforcesSameOrigin() && isUnsafeMethod(r.Method) {
		if err := security.checkCSRF(r, origin, cross); err != nil {
			writeError(w, err)
			return false
		}
	}
	return true
}

// checkCSRF validates state-changing browser requests. | checkCSRF 校验会改变状态的浏览器请求。
//
// A configured hook decides by itself. Otherwise a cross-origin request is denied; a same-origin
// Origin or Sec-Fetch-Site "same-origin"/"none" is accepted; requests without browser evidence are
// denied because a cookie-authenticated caller could be a forged browser request. | 配置钩子时由其
// 自行决定。否则拒绝跨域请求；接受同源 Origin 或 Sec-Fetch-Site 的 "same-origin"/"none"；缺少
// 浏览器证据的请求被拒绝，因为 Cookie 认证调用可能来自伪造的浏览器请求。
func (s *serverSecurity) checkCSRF(r *http.Request, origin string, cross bool) error {
	if s.csrfCheck != nil {
		if err := s.csrfCheck(r); err != nil {
			return errs.WrapDetail(err, ErrForbidden, "CSRF validation failed | CSRF 校验失败")
		}
		return nil
	}
	if cross {
		return errs.Detail(ErrForbidden, "cross-origin state-changing request without CSRF validation | 跨域状态变更请求未经 CSRF 校验")
	}
	if origin != "" {
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))) {
	case "same-origin", "none":
		return nil
	case "":
		return errs.Detail(ErrForbidden, "missing Origin or Sec-Fetch-Site for cookie-authenticated request | Cookie 认证请求缺少 Origin 或 Sec-Fetch-Site")
	default:
		return errs.Detail(ErrForbidden, "Sec-Fetch-Site %[1]q is not same-origin | Sec-Fetch-Site %[1]q 不是同源", r.Header.Get("Sec-Fetch-Site"))
	}
}

// isUnsafeMethod reports whether method may change server state. | isUnsafeMethod 报告方法是否可能
// 改变服务器状态。
func isUnsafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return false
	default:
		return true
	}
}

// writeAllow writes a non-CORS OPTIONS response. | writeAllow 写出非 CORS OPTIONS 响应。
func writeAllow(w http.ResponseWriter) {
	w.Header().Set("Allow", allowMethods)
	w.WriteHeader(http.StatusNoContent)
}

// writePreflight writes a validated CORS preflight response. | writePreflight 写出已校验的 CORS
// 预检响应。
func writePreflight(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Methods", allowMethods)
	requested := strings.TrimSpace(r.Header.Get("Access-Control-Request-Headers"))
	if requested == "" {
		requested = allowHeaders
	}
	w.Header().Set("Access-Control-Allow-Headers", sanitizeHeaderList(requested))
	w.Header().Set("Access-Control-Max-Age", preflightMaxAge)
	w.Header().Add("Vary", "Access-Control-Request-Method")
	w.Header().Add("Vary", "Access-Control-Request-Headers")
	w.WriteHeader(http.StatusNoContent)
}

// sanitizeHeaderList keeps only comma-separated HTTP token names. | sanitizeHeaderList 只保留逗号分隔
// 的 HTTP 令牌名称。
func sanitizeHeaderList(value string) string {
	allowed := make([]string, 0, 4)
	for _, item := range strings.Split(value, ",") {
		name := strings.TrimSpace(item)
		if name == "" || len(name) > 64 {
			continue
		}
		valid := true
		for _, ch := range name {
			if !isTokenChar(ch) {
				valid = false
				break
			}
		}
		if valid {
			allowed = append(allowed, name)
		}
	}
	if len(allowed) == 0 {
		return allowHeaders
	}
	return strings.Join(allowed, ", ")
}

// isTokenChar reports whether ch is valid in an HTTP token. | isTokenChar 报告 ch 是否为合法 HTTP 令牌字符。
func isTokenChar(ch rune) bool {
	switch {
	case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch >= '0' && ch <= '9':
		return true
	}
	switch ch {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	}
	return false
}
