package cas

import (
	"html"
	"net/http"
	"strings"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/errs"
)

// csrfField is the login form field holding the CSRF token. | csrfField 是保存 CSRF 令牌的登录表单字段。
const csrfField = "csrf_token"

// Login serves GET /login and POST /login. | Login 提供 GET /login 与 POST /login。
//
// GET renders the login form, or redirects with a fresh service ticket when a valid TGC is present.
// POST verifies the submitted credentials, rotates the TGT, sets the TGC cookie and redirects to
// the service with a ticket parameter. gateway=true returns to the service without a ticket when no
// valid TGT exists; renew=true forces re-authentication. | GET 渲染登录表单，或在存在有效 TGC 时携带
// 新的服务票据重定向。POST 校验提交的凭据、轮换 TGT、设置 TGC Cookie，并携带 ticket 参数重定向到服务。
// gateway=true 在没有有效 TGT 时返回服务而不带票据；renew=true 强制重新认证。
func (s *Server) Login(w http.ResponseWriter, r *http.Request) {
	if !s.methodAllowed(w, r, http.MethodGet, http.MethodPost) {
		return
	}
	if r.Method == http.MethodPost {
		s.loginSubmit(w, r)
		return
	}
	s.loginPage(w, r)
}

// loginParams holds the protocol parameters of a login request. | loginParams 保存登录请求的协议参数。
type loginParams struct {
	service  string
	username string
	password string
	renew    bool
	gateway  bool
	warn     bool
	remember bool
}

// paramsFromRequest reads the login parameters from the query and, for a POST, the form body. |
// paramsFromRequest 从查询参数与（POST 时的）表单正文读取登录参数。
func paramsFromRequest(r *http.Request, form bool) loginParams {
	values := r.URL.Query()
	if form {
		values = r.Form
	}
	return loginParams{
		service:  strings.TrimSpace(values.Get("service")),
		renew:    parseBoolParam(values.Get("renew")),
		gateway:  parseBoolParam(values.Get("gateway")),
		warn:     parseBoolParam(values.Get("warn")),
		remember: parseBoolParam(values.Get("rememberMe")),
		username: strings.TrimSpace(values.Get("username")),
		password: values.Get("password"),
	}
}

// loginPage handles GET /login. | loginPage 处理 GET /login。
func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	params := paramsFromRequest(r, false)
	if params.service != "" && !s.allowsService(r.Context(), params.service) {
		s.fail(w, r, http.StatusBadRequest, errs.Detail(ErrServiceNotRegistered, "service is not registered | 服务未注册"))
		return
	}
	tgt, hasTGT := s.ticketFromRequest(r)
	if hasTGT && !params.renew {
		if params.service == "" {
			s.renderLoginPage(w, r, &LoginPageData{
				Status:    http.StatusOK,
				LoggedIn:  true,
				Principal: tgt.Principal.Clone(),
				Issuer:    s.config.Issuer,
				Service:   params.service,
			})
			return
		}
		// The ticket comes from the existing SSO session, never from a credential presentation,
		// so it must not inherit the TGT's renewal marker. | 该票据来自既有单点登录会话而非凭据提交，
		// 因此不得继承 TGT 的重新认证标记。
		st, err := s.issueTicket(r.Context(), TicketST, tgt.Principal, tgt.UserID, params.service, tgt, s.config.ServiceTicketTimeout, false, tgt.RememberMe)
		if err != nil {
			s.fail(w, r, http.StatusInternalServerError, errs.Wrap(err, ErrTicketGeneration))
			return
		}
		s.redirectToService(w, r, params.service, st.ID)
		return
	}
	// A gateway request never prompts: without a reusable SSO session (including a forced renewal)
	// the service is told that no ticket was issued. | 网关请求从不提示：没有可复用的单点登录会话
	// （包括被强制重新认证）时告知服务未签发票据。
	if params.gateway && params.service != "" && (!hasTGT || params.renew) {
		http.Redirect(w, r, params.service, http.StatusFound)
		return
	}
	s.renderLoginPage(w, r, &LoginPageData{
		Status:     http.StatusOK,
		Action:     s.loginAction(r),
		Service:    params.service,
		Renew:      params.renew,
		Gateway:    params.gateway,
		Warn:       params.warn,
		RememberMe: params.remember,
		CSRF:       s.csrfToken(r),
		Issuer:     s.config.Issuer,
	})
}

// loginSubmit handles POST /login. | loginSubmit 处理 POST /login。
func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxProtocolBody)
	if err := r.ParseForm(); err != nil {
		s.fail(w, r, http.StatusBadRequest, errs.WrapDetail(err, ErrInvalidRequest, "cannot parse login form | 无法解析登录表单"))
		return
	}
	params := paramsFromRequest(r, true)
	if params.service != "" && !s.allowsService(r.Context(), params.service) {
		s.fail(w, r, http.StatusBadRequest, errs.Detail(ErrServiceNotRegistered, "service is not registered | 服务未注册"))
		return
	}
	if s.config.CSRFProtector != nil && !s.config.CSRFProtector.Verify(r) {
		s.renderLoginError(w, r, params, http.StatusForbidden, "The form expired, please try again | 表单已过期，请重试")
		return
	}
	if params.username == "" || params.password == "" {
		s.renderLoginError(w, r, params, http.StatusUnauthorized, loginErrorMessage(ErrInvalidCredentials))
		return
	}
	// A forced re-authentication must not silently reuse the previous SSO session. | 强制重新认证不得
	// 静默复用之前的单点登录会话。
	previous, hadPrevious := s.ticketFromRequest(r)
	principal, err := s.config.Authenticator.Authenticate(r.Context(), &LoginRequest{
		Username:       params.username,
		Password:       params.password,
		Service:        params.service,
		Renew:          params.renew,
		Gateway:        params.gateway,
		RememberMe:     params.remember,
		Warn:           params.warn,
		Request:        r,
		ResponseWriter: w,
	})
	if err != nil {
		if isAuthFailure(err) {
			s.renderLoginError(w, r, params, http.StatusUnauthorized, loginErrorMessage(err))
			return
		}
		s.logWarn("cas: login failed | cas：登录失败", err)
		s.fail(w, r, http.StatusInternalServerError, errs.Wrap(err, ErrInvalidCredentials))
		return
	}
	userID := principalUserID(principal)
	if principal == nil || userID == "" {
		s.fail(w, r, http.StatusInternalServerError, errs.Detail(ErrPrincipalMissing, "authenticator returned no principal | 认证器未返回主体"))
		return
	}
	// Rotate the ticket family after a successful login so a planted TGC cannot survive
	// authentication. Service sessions of the old family are notified through back-channel logout. |
	// 登录成功后轮换票据族，使预先植入的 TGC 无法在认证后继续存在。旧票据族的服务会话通过后端登出
	// 得到通知。
	if hadPrevious {
		previousSessions := s.destroyTGT(r.Context(), previous.ID)
		_ = s.DeliverLogoutRequests(r.Context(), previousSessions, "")
	}
	tgt, err := s.issueTicket(r.Context(), TicketTGT, principal, userID, "", nil, s.config.TGTTimeout, params.renew, params.remember)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, errs.Wrap(err, ErrTicketGeneration))
		return
	}
	http.SetCookie(w, s.tgcCookie(tgt, params.remember))
	if params.service == "" {
		http.Redirect(w, r, r.URL.Path, http.StatusFound)
		return
	}
	// The ST reflects the login request: only an explicit renew makes it satisfy renew validation. |
	// ST 反映登录请求：只有显式 renew 才使其满足 renew 校验。
	st, err := s.issueTicket(r.Context(), TicketST, principal, userID, params.service, tgt, s.config.ServiceTicketTimeout, params.renew, tgt.RememberMe)
	if err != nil {
		s.destroyTGT(r.Context(), tgt.ID)
		s.fail(w, r, http.StatusInternalServerError, errs.Wrap(err, ErrTicketGeneration))
		return
	}
	s.redirectToService(w, r, params.service, st.ID)
}

// renderLoginError renders the login form with an error message. | renderLoginError 渲染带错误提示的登录表单。
func (s *Server) renderLoginError(w http.ResponseWriter, r *http.Request, params loginParams, status int, message string) {
	s.renderLoginPage(w, r, &LoginPageData{
		Status:     status,
		Action:     s.loginAction(r),
		Service:    params.service,
		Renew:      params.renew,
		Gateway:    params.gateway,
		Warn:       params.warn,
		RememberMe: params.remember,
		Username:   params.username,
		Error:      message,
		CSRF:       s.csrfToken(r),
		Issuer:     s.config.Issuer,
	})
}

// loginAction returns the login form target. | loginAction 返回登录表单目标。
func (s *Server) loginAction(r *http.Request) string {
	if s.config.LoginURL != "" {
		return s.config.LoginURL
	}
	return r.URL.Path
}

// csrfToken returns the current CSRF token, or an empty string when protection is disabled. |
// csrfToken 返回当前 CSRF 令牌；保护关闭时返回空串。
func (s *Server) csrfToken(r *http.Request) string {
	if s.config.CSRFProtector == nil {
		return ""
	}
	return s.config.CSRFProtector.Token(r)
}

// renderLoginPage renders data through the configured renderer or the built-in page. | renderLoginPage
// 通过配置的渲染器或内置页面渲染 data。
func (s *Server) renderLoginPage(w http.ResponseWriter, r *http.Request, data *LoginPageData) {
	if data.Status == 0 {
		data.Status = http.StatusOK
	}
	if s.config.LoginPageRenderer != nil {
		s.config.LoginPageRenderer(w, data)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(data.Status)
	if data.LoggedIn {
		s.writeLoggedInPage(w, data)
		return
	}
	s.writeLoginForm(w, data)
}

// writeLoginForm writes the built-in bilingual login page. | writeLoginForm 写出内置中英双语登录页面。
func (s *Server) writeLoginForm(w http.ResponseWriter, data *LoginPageData) {
	var b strings.Builder
	b.WriteString("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
	b.WriteString("<title>Sign in | 登录</title><style>")
	b.WriteString("body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#f4f6f8;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center}")
	b.WriteString("main{background:#fff;padding:2rem;border-radius:8px;box-shadow:0 2px 12px rgba(0,0,0,.12);width:min(22rem,90vw)}")
	b.WriteString("h1{font-size:1.25rem;margin:0 0 1rem}label{display:block;font-size:.875rem;margin:.75rem 0 .25rem}")
	b.WriteString("input[type=text],input[type=password]{width:100%;box-sizing:border-box;padding:.5rem;border:1px solid #c4c9cf;border-radius:4px}")
	b.WriteString("button{width:100%;margin-top:1.25rem;padding:.6rem;border:0;border-radius:4px;background:#1f6feb;color:#fff;font-size:1rem;cursor:pointer}")
	b.WriteString(".error{background:#fdecea;color:#8a1c1c;padding:.6rem;border-radius:4px;font-size:.875rem;margin-bottom:.5rem}")
	b.WriteString(".meta{color:#5b6470;font-size:.75rem;margin-top:1rem}</style></head><body><main>")
	b.WriteString("<h1>Sign in | 登录</h1>")
	if data.Issuer != "" {
		b.WriteString("<p class=\"meta\">")
		b.WriteString(html.EscapeString(data.Issuer))
		b.WriteString("</p>")
	}
	if data.Error != "" {
		b.WriteString("<p class=\"error\">")
		b.WriteString(html.EscapeString(data.Error))
		b.WriteString("</p>")
	}
	action := data.Action
	if action == "" {
		action = "/login"
	}
	b.WriteString("<form method=\"post\" action=\"")
	b.WriteString(html.EscapeString(action))
	b.WriteString("\">")
	writeHiddenInput(&b, "service", data.Service)
	if data.Renew {
		writeHiddenInput(&b, "renew", "true")
	}
	if data.Gateway {
		writeHiddenInput(&b, "gateway", "true")
	}
	if data.Warn {
		writeHiddenInput(&b, "warn", "true")
	}
	if data.CSRF != "" {
		writeHiddenInput(&b, csrfField, data.CSRF)
	}
	b.WriteString("<label for=\"username\">Username | 用户名</label>")
	b.WriteString("<input id=\"username\" name=\"username\" type=\"text\" autocomplete=\"username\" autofocus required value=\"")
	b.WriteString(html.EscapeString(data.Username))
	b.WriteString("\">")
	b.WriteString("<label for=\"password\">Password | 口令</label>")
	b.WriteString("<input id=\"password\" name=\"password\" type=\"password\" autocomplete=\"current-password\" required>")
	b.WriteString("<label><input name=\"rememberMe\" type=\"checkbox\" value=\"true\"")
	if data.RememberMe {
		b.WriteString(" checked")
	}
	b.WriteString("> Remember me | 保持登录</label>")
	b.WriteString("<button type=\"submit\">Sign in | 登录</button>")
	b.WriteString("</form></main></body></html>")
	_, _ = w.Write([]byte(b.String()))
}

// writeLoggedInPage writes the built-in already-signed-in page. | writeLoggedInPage 写出内置已登录页面。
func (s *Server) writeLoggedInPage(w http.ResponseWriter, data *LoginPageData) {
	name := ""
	if data.Principal != nil {
		name = data.Principal.DisplayName
		if name == "" {
			name = userIdentifier(data.Principal)
		}
	}
	var b strings.Builder
	b.WriteString("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
	b.WriteString("<title>Signed in | 已登录</title><style>")
	b.WriteString("body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#f4f6f8;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center}")
	b.WriteString("main{background:#fff;padding:2rem;border-radius:8px;box-shadow:0 2px 12px rgba(0,0,0,.12);width:min(22rem,90vw);text-align:center}")
	b.WriteString("a{display:inline-block;margin-top:1rem;color:#1f6feb}</style></head><body><main>")
	b.WriteString("<h1>Signed in | 已登录</h1>")
	if name != "" {
		b.WriteString("<p>")
		b.WriteString(html.EscapeString(name))
		b.WriteString("</p>")
	}
	b.WriteString("<a href=\"logout\">Sign out | 退出登录</a>")
	b.WriteString("</main></body></html>")
	_, _ = w.Write([]byte(b.String()))
}

// writeHiddenInput writes an escaped hidden form input. | writeHiddenInput 写出转义后的隐藏表单字段。
func writeHiddenInput(b *strings.Builder, name, value string) {
	if value == "" {
		return
	}
	b.WriteString("<input type=\"hidden\" name=\"")
	b.WriteString(html.EscapeString(name))
	b.WriteString("\" value=\"")
	b.WriteString(html.EscapeString(value))
	b.WriteString("\">")
}

// principalUserID returns the ticket owner identifier of p. | principalUserID 返回 p 的票据属主标识。
func principalUserID(p *auth.Principal) string {
	if p == nil {
		return ""
	}
	if p.Subject != "" {
		return p.Subject
	}
	return p.Username
}
