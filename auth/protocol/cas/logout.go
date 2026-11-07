package cas

import (
	"errors"
	"html"
	"net/http"
	"strings"

	"github.com/shibingli/ydx/errs"
)

// Logout serves GET /logout and POST /logout. | Logout 提供 GET /logout 与 POST /logout。
//
// Browser logout (no logoutRequest parameter) destroys the TGT carried by the TGC cookie, every
// ticket derived from it, and every recorded service session, then expires the cookie. When the
// optional service or url parameter names a registered service, the browser is redirected there;
// an unregistered target is ignored rather than followed. | 浏览器登出（不带 logoutRequest 参数）销毁
// TGC Cookie 携带的 TGT、由它派生的全部票据以及全部已记录的服务会话，然后过期 Cookie。可选的 service
// 或 url 参数指向已注册服务时，浏览器随后被重定向到该地址；未注册的目标会被忽略而不是跟随。
//
// Back-channel logout (a logoutRequest parameter, sent by a service as SAML 1.1 LogoutRequest POST)
// revokes the named session family and notifies the other participating services. See
// handleLogoutRequest for the response contract. | 后端登出（服务以 SAML 1.1 LogoutRequest POST 发送的
// logoutRequest 参数）撤销指定会话族并通知其它参与服务。响应约定见 handleLogoutRequest。
func (s *Server) Logout(w http.ResponseWriter, r *http.Request) {
	if !s.methodAllowed(w, r, http.MethodGet, http.MethodPost) {
		return
	}
	if r.Method == http.MethodPost {
		// Bound the form before parsing so an oversized logoutRequest cannot exhaust memory. | 解析
		// 前限制表单大小，避免超大的 logoutRequest 耗尽内存。
		r.Body = http.MaxBytesReader(w, r.Body, maxProtocolBody)
		if err := r.ParseForm(); err != nil {
			status := http.StatusBadRequest
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				status = http.StatusRequestEntityTooLarge
			}
			s.fail(w, r, status, errs.WrapDetail(err, ErrInvalidRequest, "cannot parse logout form | 无法解析登出表单"))
			return
		}
	}
	if value, ok := logoutRequestValue(r); ok {
		s.handleLogoutRequest(w, r, value)
		return
	}
	var sessions []*ServiceSession
	if tgt, ok := s.ticketFromRequest(r); ok {
		sessions = s.destroyTGT(r.Context(), tgt.ID)
	}
	http.SetCookie(w, s.clearTGCCookie())
	_ = s.DeliverLogoutRequests(r.Context(), sessions, "")
	target := strings.TrimSpace(r.URL.Query().Get("service"))
	if target == "" {
		target = strings.TrimSpace(r.URL.Query().Get("url"))
	}
	if r.Method == http.MethodPost {
		if target == "" {
			target = strings.TrimSpace(r.PostForm.Get("service"))
		}
		if target == "" {
			target = strings.TrimSpace(r.PostForm.Get("url"))
		}
	}
	if target != "" && s.allowsService(r.Context(), target) {
		http.Redirect(w, r, target, http.StatusFound)
		return
	}
	s.renderLoggedOutPage(w)
}

// renderLoggedOutPage writes the built-in sign-out confirmation page. | renderLoggedOutPage 写出内置的退出确认页面。
func (s *Server) renderLoggedOutPage(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	var b strings.Builder
	b.WriteString("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
	b.WriteString("<title>Signed out | 已退出</title><style>")
	b.WriteString("body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#f4f6f8;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center}")
	b.WriteString("main{background:#fff;padding:2rem;border-radius:8px;box-shadow:0 2px 12px rgba(0,0,0,.12);width:min(22rem,90vw);text-align:center}")
	if s.config.Issuer != "" {
		b.WriteString(".meta{color:#5b6470;font-size:.75rem;margin-top:1rem}")
	}
	b.WriteString("</style></head><body><main>")
	b.WriteString("<h1>Signed out | 已退出</h1>")
	b.WriteString("<p>You have been signed out of the central authentication service. | 你已退出中央认证服务。</p>")
	if s.config.Issuer != "" {
		b.WriteString("<p class=\"meta\">")
		b.WriteString(html.EscapeString(s.config.Issuer))
		b.WriteString("</p>")
	}
	b.WriteString("</main></body></html>")
	_, _ = w.Write([]byte(b.String()))
}
