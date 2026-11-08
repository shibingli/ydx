package cas

import (
	"context"
	"html"
	"net/http"
	"net/url"
	"strings"
)

// DefaultMaxFrontChannelLogoutServices is the default cap of distinct front-channel logout URLs on
// one browser logout page. | DefaultMaxFrontChannelLogoutServices 是单个浏览器登出页面上不同前端
// 登出 URL 的默认上限。
const DefaultMaxFrontChannelLogoutServices = 10

// frontChannelLogoutURLs resolves the front-channel logout URLs of the given service sessions. Only
// services that are still accepted by the registry and URLs that are still absolute http(s) URLs are
// returned, so a stale session or a rogue resolver cannot inject an open redirect. Duplicate URLs are
// collapsed and the result is capped by MaxFrontChannelLogoutServices. | frontChannelLogoutURLs 解析
// 给定服务会话的前端登出 URL。只返回仍被注册表接受的服务与仍是绝对 http(s) URL 的地址，因此过期会话
// 或恶意校验器都无法注入开放重定向。重复 URL 会被合并，结果受 MaxFrontChannelLogoutServices 限制。
func (s *Server) frontChannelLogoutURLs(ctx context.Context, sessions []*ServiceSession) []string {
	if s == nil || s.frontChannel == nil || len(sessions) == 0 {
		return nil
	}
	limit := s.config.MaxFrontChannelLogoutServices
	if limit <= 0 {
		limit = DefaultMaxFrontChannelLogoutServices
	}
	seen := make(map[string]struct{}, len(sessions))
	targets := make([]string, 0, len(sessions))
	for _, session := range sessions {
		if len(targets) >= limit {
			break
		}
		if session == nil || session.Service == "" {
			continue
		}
		if !s.allowsService(ctx, session.Service) {
			continue
		}
		logoutURL, ok := s.frontChannel.FrontChannelLogoutURL(ctx, session.Service)
		if !ok || !validServiceURL(logoutURL) {
			continue
		}
		if _, duplicate := seen[logoutURL]; duplicate {
			continue
		}
		seen[logoutURL] = struct{}{}
		targets = append(targets, logoutURL)
	}
	return targets
}

// renderFrontChannelLogoutPage writes a page that loads one hidden frame per registered service so
// the browser visits every front-channel logout endpoint. All URLs are HTML-escaped and a Content
// Security Policy restricts frames to their origins. When continueURL is non-empty it becomes an
// escaped link the user can follow after the frames have started loading. | renderFrontChannelLogoutPage
// 写出为每个已注册服务加载一个隐藏框架的页面，使浏览器访问每个前端登出端点。所有 URL 都经过 HTML
// 转义，且 Content Security Policy 把框架限制在各自源。continueURL 非空时作为用户可在框架开始加载
// 后点击的转义链接。
func (s *Server) renderFrontChannelLogoutPage(w http.ResponseWriter, targets []string, continueURL string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", frontChannelPolicy(targets))
	w.WriteHeader(http.StatusOK)
	var b strings.Builder
	b.Grow(768 + len(targets)*96)
	b.WriteString("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
	b.WriteString("<title>Signed out | 已退出</title><style>")
	b.WriteString("body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#f4f6f8;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center}")
	b.WriteString("main{background:#fff;padding:2rem;border-radius:8px;box-shadow:0 2px 12px rgba(0,0,0,.12);width:min(26rem,90vw);text-align:center}")
	b.WriteString("a{display:inline-block;margin-top:1rem;color:#1f6feb}")
	b.WriteString(".meta{color:#5b6470;font-size:.75rem;margin-top:1rem}")
	b.WriteString("</style></head><body><main>")
	b.WriteString("<h1>Signed out | 已退出</h1>")
	b.WriteString("<p>You have been signed out of the central authentication service. Other services are being signed out too. | 你已退出中央认证服务，其它服务也正在退出。</p>")
	for _, target := range targets {
		b.WriteString("<iframe src=\"")
		b.WriteString(html.EscapeString(target))
		b.WriteString("\" title=\"Sign out | 退出\" referrerpolicy=\"no-referrer\" aria-hidden=\"true\" style=\"display:none\"></iframe>")
	}
	if continueURL != "" {
		b.WriteString("<p><a href=\"")
		b.WriteString(html.EscapeString(continueURL))
		b.WriteString("\">Continue | 继续</a></p>")
	}
	if s.config.Issuer != "" {
		b.WriteString("<p class=\"meta\">")
		b.WriteString(html.EscapeString(s.config.Issuer))
		b.WriteString("</p>")
	}
	b.WriteString("</main></body></html>")
	_, _ = w.Write([]byte(b.String()))
}

// frontChannelPolicy builds the Content Security Policy of a front-channel logout page. Frames are
// restricted to the scheme://host origins of the registered URLs; an origin containing characters
// that could terminate the header value is skipped rather than emitted. | frontChannelPolicy 构建前端
// 登出页面的 Content Security Policy。框架被限制在已注册 URL 的 scheme://host 源；包含可能终止头部
// 取值的字符的源会被跳过而不写出。
func frontChannelPolicy(targets []string) string {
	policy := "default-src 'none'; style-src 'unsafe-inline'"
	origins := make([]string, 0, len(targets))
	for _, target := range targets {
		parsed, err := url.Parse(target)
		if err != nil || parsed.Host == "" {
			continue
		}
		origin := strings.ToLower(parsed.Scheme) + "://" + parsed.Host
		if strings.ContainsAny(origin, " ;\"'<>") {
			continue
		}
		origins = append(origins, origin)
	}
	if len(origins) > 0 {
		policy += "; frame-src " + strings.Join(origins, " ")
	}
	return policy
}
