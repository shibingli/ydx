package oauth2

import (
	"crypto/sha256"
	"errors"
	htmlstd "html"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
)

// errResponseWritten stops the handler after a nested handler already wrote the response. | errResponseWritten
// 在嵌套处理器已写入响应后终止当前处理器。
var errResponseWritten = errs.New("oauth2: response already written | oauth2：响应已写入")

// Authorize is the authorization endpoint. | Authorize 是授权端点。
//
// It is a router.HandlerFuncRaw and an http.HandlerFunc at the same time, so it mounts directly on
// ydx/router and on net/http. | 它同时是 router.HandlerFuncRaw 与 http.HandlerFunc，因此可直接挂载到
// ydx/router 与 net/http。
func (s *Server) Authorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		s.writeOAuthError(w, r, errs.Detail(ErrInvalidRequest, "method %[1]s not allowed | 不允许方法 %[1]s", r.Method))
		return
	}
	if r.Method == http.MethodPost {
		limitFormBody(w, r)
	}
	req, err := s.loadAuthorizationRequest(r)
	if err != nil {
		s.writeOAuthError(w, r, err)
		return
	}
	if err := s.validateAuthorizationRequest(req); err != nil {
		s.writeAuthorizationError(w, r, req, err)
		return
	}
	principal, err := s.authorizeUser(w, r, req)
	if err != nil {
		if errors.Is(err, errResponseWritten) {
			return
		}
		s.writeAuthorizationError(w, r, req, err)
		return
	}
	scopes, err := s.consent(w, r, req, principal)
	if err != nil {
		if errors.Is(err, errResponseWritten) {
			return
		}
		s.writeAuthorizationError(w, r, req, err)
		return
	}
	req.Scopes = scopes
	if err := s.issueAuthorizationResponse(w, r, req, principal); err != nil {
		if errors.Is(err, errResponseWritten) {
			return
		}
		s.writeAuthorizationError(w, r, req, err)
	}
}

// loadAuthorizationRequest reads direct or pushed authorization parameters. | loadAuthorizationRequest
// 读取直接或推送的授权参数。
func (s *Server) loadAuthorizationRequest(r *http.Request) (*AuthorizationRequest, error) {
	raw, err := authorizationValues(r)
	if err != nil {
		return nil, err
	}
	// RFC 9101 request objects are verified before any outer parameter is trusted; the returned
	// set contains only the signed parameters. | 在任何外层参数被信任之前先校验 RFC 9101 请求对象；
	// 返回集合只包含已签名参数。
	resolved, err := s.resolveRequestObjectValues(r.Context(), raw)
	if err != nil {
		return nil, err
	}
	raw = resolved
	requestURI := strings.TrimSpace(raw.Get("request_uri"))
	if requestURI == "" {
		return parseAuthorizationValues(r.Context(), raw, s.config.Clients, s.config.Scopes)
	}
	clientID := strings.TrimSpace(raw.Get("client_id"))
	if clientID == "" {
		return nil, errs.Detail(ErrInvalidRequest, "client_id is required with request_uri | 使用 request_uri 时必须提供 client_id")
	}
	pushed, err := s.config.Store.ConsumePAR(r.Context(), requestURI, s.Now())
	if err != nil {
		return nil, err
	}
	if pushed.ClientID != clientID {
		return nil, errs.Detail(ErrInvalidRequest, "request_uri belongs to another client | request_uri 属于其他客户端")
	}
	params := cloneValues(pushed.Params)
	params.Set("client_id", clientID)
	// A PAR record may itself contain a signed request object when it was stored by another
	// implementation; verify it instead of silently rejecting the consumption. | 其他实现保存的
	// PAR 记录本身可能包含已签名请求对象；此处校验它而不是在消费后静默拒绝。
	params, err = s.resolveRequestObjectValues(r.Context(), params)
	if err != nil {
		return nil, err
	}
	return parseAuthorizationValues(r.Context(), params, s.config.Clients, s.config.Scopes)
}

// authorizationValues extracts GET or form parameters without mutating the request. | authorizationValues
// 提取 GET 或表单参数且不修改请求。
func authorizationValues(r *http.Request) (url.Values, error) {
	switch r.Method {
	case http.MethodGet:
		return r.URL.Query(), nil
	case http.MethodPost:
		contentType := strings.ToLower(r.Header.Get("Content-Type"))
		if !strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
			return nil, errs.Detail(ErrInvalidRequest, "authorization POST requires application/x-www-form-urlencoded | 授权 POST 需要 application/x-www-form-urlencoded")
		}
		if err := r.ParseForm(); err != nil {
			return nil, errs.Wrap(err, ErrInvalidRequest)
		}
		return r.PostForm, nil
	default:
		return nil, errs.Detail(ErrInvalidRequest, "method %[1]s not allowed | 不允许方法 %[1]s", r.Method)
	}
}

// validateAuthorizationRequest applies server policy to a parsed request. | validateAuthorizationRequest
// 对已解析请求应用服务器策略。
func (s *Server) validateAuthorizationRequest(req *AuthorizationRequest) error {
	client := req.Client
	if client == nil {
		return ErrInvalidClient
	}
	if responseTypeHas(req.ResponseType, ResponseCode) && len(client.GrantTypes) > 0 && !client.AllowsGrant(GrantAuthorizationCode) {
		return ErrUnauthorizedClient
	}
	if responseTypeHas(req.ResponseType, ResponseToken) && !s.config.AllowImplicit {
		return errs.Detail(ErrUnsupportedResponseType, "implicit flow is disabled | 隐式流程已禁用")
	}
	if responseTypeHas(req.ResponseType, ResponseIDToken) && s.config.AuthorizationEnricher == nil {
		return errs.Detail(ErrUnsupportedResponseType, "id_token responses need an authorization enricher | id_token 响应需要授权增强器")
	}
	if responseTypeHas(req.ResponseType, ResponseCode) {
		needsPKCE := !s.config.DisablePKCEEnforcement
		if needsPKCE && req.CodeChallenge == "" {
			return errs.Detail(ErrInvalidRequest, "PKCE is required | 必须使用 PKCE")
		}
		if req.CodeChallenge != "" && req.CodeChallengeMethod == PKCEPlain && !s.config.AllowPKCEPlain {
			return errs.Detail(ErrInvalidRequest, "plain PKCE is disabled | 明文 PKCE 已禁用")
		}
	}
	if _, jarm := jarmBaseMode(req.ResponseMode, req.ResponseType); jarm && s.config.AuthorizationResponseSigner == nil {
		return errs.Detail(ErrUnsupportedResponseType, "JARM response modes need an authorization response signer | JARM 响应模式需要授权响应签名器")
	}
	if len(s.config.AllowedResources) > 0 && len(req.Resource) > 0 {
		allowed := make(map[string]bool, len(s.config.AllowedResources))
		for _, resource := range s.config.AllowedResources {
			allowed[resource] = true
		}
		for _, resource := range req.Resource {
			if !allowed[resource] {
				return ErrInvalidTarget
			}
		}
	}
	if _, err := s.dpopForAuthorization(req); err != nil {
		return err
	}
	return nil
}

// authorizeUser resolves the resource owner. | authorizeUser 解析资源所有者。
func (s *Server) authorizeUser(w http.ResponseWriter, r *http.Request, req *AuthorizationRequest) (*auth.Principal, error) {
	if s.config.Authenticator == nil {
		return nil, errs.Detail(ErrLoginRequired, "no authenticator configured | 未配置认证器")
	}
	principal, err := s.config.Authenticator.Authenticate(r.Context(), w, r, req)
	if err != nil {
		if errors.Is(err, ErrLoginRequired) {
			return nil, s.handleLoginRequired(w, r, req)
		}
		return nil, err
	}
	if principal == nil {
		return nil, s.handleLoginRequired(w, r, req)
	}
	if req.MaxAge != nil && !principal.AuthTime.IsZero() {
		if s.Now().After(principal.AuthTime.Add(time.Duration(*req.MaxAge) * time.Second)) {
			return nil, s.handleLoginRequired(w, r, req)
		}
	}
	return principal, nil
}

// handleLoginRequired redirects to the login page or renders it. | handleLoginRequired 跳转到登录页或渲染它。
func (s *Server) handleLoginRequired(w http.ResponseWriter, r *http.Request, req *AuthorizationRequest) error {
	if req.HasPrompt("none") {
		return NewError(ErrorLoginRequired, "login is required | 需要登录")
	}
	if s.config.LoginHandler != nil {
		s.config.LoginHandler(w, r)
		return errResponseWritten
	}
	if s.config.LoginURL != "" {
		location, err := url.Parse(s.config.LoginURL)
		if err != nil {
			return errs.Wrap(err, ErrInvalidConfig)
		}
		// Rebuild the return target from the parameters actually received: a POST authorization
		// request carries them in the form body, not in the URL, and the mounted path must include
		// an explicit PathPrefix. | 用实际收到的参数重建返回目标：POST 授权请求的参数位于表单正文
		// 而非 URL，且挂载路径必须包含显式 PathPrefix。
		raw, err := authorizationValues(r)
		if err != nil {
			return err
		}
		returnTo := s.Endpoint(s.config.AuthorizationPath)
		if encoded := raw.Encode(); encoded != "" {
			returnTo += "?" + encoded
		}
		query := location.Query()
		query.Set("return_to", returnTo)
		location.RawQuery = query.Encode()
		http.Redirect(w, r, location.String(), http.StatusFound)
		return errResponseWritten
	}
	return NewError(ErrorLoginRequired, "login is required | 需要登录")
}

// consent applies the consent handler and returns the granted scopes. | consent 应用同意处理器并返回授予作用域。
func (s *Server) consent(w http.ResponseWriter, r *http.Request, req *AuthorizationRequest, principal *auth.Principal) ([]string, error) {
	if s.config.Consent == nil || req.Client.SkipConsent {
		return req.Scopes, nil
	}
	granted, err := s.config.Consent.Consent(r.Context(), w, r, req, principal)
	if err != nil {
		if errors.Is(err, ErrConsentRequired) && req.HasPrompt("none") {
			return nil, NewError(ErrorConsentRequired, "consent is required | 需要授权同意")
		}
		return nil, err
	}
	if len(granted) == 0 {
		return nil, ErrAccessDenied
	}
	intersection := IntersectScopes(granted, req.Scopes)
	if len(intersection) != len(granted) {
		return nil, errs.Detail(ErrInvalidScope, "consent granted a scope that was not requested | 同意授予了未请求的作用域")
	}
	return intersection, nil
}

// issueAuthorizationResponse writes the code, token or none response. | issueAuthorizationResponse
// 写入授权码、令牌或 none 响应。
func (s *Server) issueAuthorizationResponse(w http.ResponseWriter, r *http.Request, req *AuthorizationRequest, principal *auth.Principal) error {
	grant := s.newGrant(req, principal, r)
	params := make(url.Values)
	if responseTypeHas(req.ResponseType, ResponseCode) {
		rawCode, err := auth.RandomToken(32)
		if err != nil {
			return err
		}
		code := &AuthorizationCode{
			CodeHash:            auth.HashToken(rawCode),
			ClientID:            req.Client.ID,
			RedirectURI:         req.RedirectURI,
			RedirectURIProvided: strings.TrimSpace(req.Raw.Get("redirect_uri")) != "",
			Scopes:              req.Scopes,
			UserID:              grant.UserID,
			Subject:             grant.Subject,
			Nonce:               req.Nonce,
			CodeChallenge:       req.CodeChallenge,
			CodeChallengeMethod: req.CodeChallengeMethod,
			AuthTime:            grant.AuthTime,
			ACR:                 grant.ACR,
			AMR:                 grant.AMR,
			SessionID:           grant.SessionID,
			Resource:            grant.Audience,
			Claims:              req.Claims,
			Principal:           principal.Clone(),
			DPoPJKT:             grant.DPoPJKT,
			CertThumbprint:      grant.CertThumbprint,
			CreatedAt:           s.Now(),
			ExpiresAt:           s.Now().Add(s.codeTTL(req.Client)),
		}
		if err := s.config.Store.SaveAuthorizationCode(r.Context(), code); err != nil {
			return err
		}
		params.Set("code", rawCode)
	}
	if responseTypeHas(req.ResponseType, ResponseToken) {
		response, err := s.issueTokens(r.Context(), grant, s.shouldIssueRefresh(grant))
		if err != nil {
			return err
		}
		params.Set("access_token", response.AccessToken)
		params.Set("token_type", response.TokenType)
		if response.ExpiresIn > 0 {
			params.Set("expires_in", itoa(int(response.ExpiresIn)))
		}
		if response.Scope != "" {
			params.Set("scope", response.Scope)
		}
		if response.IDToken != "" {
			params.Set("id_token", response.IDToken)
		}
	}
	// A pure id_token response (implicit or hybrid without an access token) needs the token
	// enricher. When a code is returned too, the authorization enricher builds the ID token
	// because only it can bind c_hash and session_state; using both would sign it twice. | 纯
	// id_token 响应（不含访问令牌的隐式或混合流程）需要令牌增强器。若同时返回授权码，则由授权
	// 增强器构建 ID 令牌，因为只有它能绑定 c_hash 与 session_state；两者并用会重复签名。
	if req.State != "" {
		params.Set("state", req.State)
	}
	if s.config.AuthorizationEnricher != nil {
		if err := s.config.AuthorizationEnricher.EnrichAuthorization(r.Context(), grant, params); err != nil {
			return err
		}
	}
	// The authorization enricher normally supplies id_token, including c_hash for hybrid
	// flows. Fall back to the token enricher only when it did not, so a generic enricher still
	// supports id_token response types without double signing. | 授权增强器通常提供 id_token
	// （混合流程还包含 c_hash）。仅当它未提供时才回退到令牌增强器，使通用增强器也能支持
	// id_token 响应类型且不会重复签名。
	if responseTypeHas(req.ResponseType, ResponseIDToken) && params.Get("id_token") == "" {
		if s.config.TokenEnricher == nil {
			return errs.Detail(ErrUnsupportedResponseType, "id_token response is not configured | 未配置 id_token 响应")
		}
		response := &TokenResponse{}
		if err := s.config.TokenEnricher.EnrichToken(r.Context(), grant, response); err != nil {
			return err
		}
		if response.IDToken == "" {
			return errs.Detail(ErrServerError, "enricher produced no id_token | 增强器未生成 id_token")
		}
		params.Set("id_token", response.IDToken)
	}
	return s.writeAuthorizationResponse(w, r, req, params)
}

// newGrant builds the normalized grant from an authorization request. | newGrant 从授权请求构建规范化许可。
func (s *Server) newGrant(req *AuthorizationRequest, principal *auth.Principal, r *http.Request) *Grant {
	now := s.Now()
	authTime := principal.AuthTime
	if authTime.IsZero() {
		authTime = now
	}
	audience := append([]string(nil), req.Resource...)
	if len(audience) == 0 {
		audience = append([]string(nil), s.config.DefaultAudience...)
	}
	jkt := strings.TrimSpace(req.Raw.Get("dpop_jkt"))
	if jkt == "" && principal.Attributes != nil {
		jkt = principal.Attributes["dpop_jkt"]
	}
	return &Grant{
		Client:         req.Client,
		Principal:      principal,
		UserID:         principal.Subject,
		Subject:        principal.Subject,
		Scopes:         append([]string(nil), req.Scopes...),
		Audience:       audience,
		AuthTime:       authTime,
		ACR:            principal.ACR,
		AMR:            append([]string(nil), principal.AMR...),
		SessionID:      principal.SessionID,
		Nonce:          req.Nonce,
		ResponseType:   req.ResponseType,
		DPoPJKT:        jkt,
		CertThumbprint: certThumbprint(r),
		GrantID:        auth.NewID("grant"),
		IssuedAt:       now,
		Claims:         req.Claims,
	}
}

// codeTTL returns the authorization-code lifetime for client. | codeTTL 返回 client 的授权码寿命。
func (s *Server) codeTTL(client *Client) time.Duration {
	if client != nil && client.AuthorizationCodeTTL > 0 {
		return client.AuthorizationCodeTTL
	}
	return s.config.AuthorizationCodeTTL
}

// shouldIssueRefresh reports whether the grant should carry a refresh token. | shouldIssueRefresh 报告许可是否应携带刷新令牌。
func (s *Server) shouldIssueRefresh(grant *Grant) bool {
	if grant == nil || grant.Client == nil {
		return false
	}
	if len(grant.Client.GrantTypes) > 0 && !grant.Client.AllowsGrant(GrantRefreshToken) {
		return false
	}
	if HasScope(grant.Scopes, ScopeOpenID) && !HasOfflineAccess(grant.Scopes, s.config.Scopes) {
		return false
	}
	return true
}

// certThumbprint returns the RFC 8705 x5t#S256 thumbprint of the peer certificate. | certThumbprint
// 返回对端证书的 RFC 8705 x5t#S256 指纹。
func certThumbprint(r *http.Request) string {
	if r == nil || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return ""
	}
	sum := sha256.Sum256(r.TLS.PeerCertificates[0].Raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// writeAuthorizationResponse delivers params using the requested response mode. | writeAuthorizationResponse
// 使用请求的响应模式投递 params。
func (s *Server) writeAuthorizationResponse(w http.ResponseWriter, r *http.Request, req *AuthorizationRequest, params url.Values) error {
	if !s.config.DisableIssuerParameter {
		params.Set("iss", s.Issuer())
	}
	mode, jarm := jarmBaseMode(req.ResponseMode, req.ResponseType)
	if jarm {
		if s.config.AuthorizationResponseSigner == nil {
			return errs.Detail(ErrUnsupportedResponseType, "JARM response modes need an authorization response signer | JARM 响应模式需要授权响应签名器")
		}
		jwt, err := s.config.AuthorizationResponseSigner.SignAuthorizationResponse(r.Context(), s.Issuer(), req.Client, params)
		if err != nil {
			return err
		}
		if jwt == "" {
			return errs.Detail(ErrServerError, "authorization response signer returned an empty JWT | 授权响应签名器返回空 JWT")
		}
		// Every original parameter travels inside the signed JWT; the outer encoding carries only
		// the response parameter. | 所有原始参数都在已签名 JWT 内传输；外层编码只携带 response 参数。
		params = url.Values{"response": []string{jwt}}
	}
	switch mode {
	case ResponseModeFormPost:
		return writeFormPost(w, req.RedirectURI, params)
	case ResponseModeFragment:
		location, err := url.Parse(req.RedirectURI)
		if err != nil {
			return errs.Wrap(err, ErrInvalidRequest)
		}
		// Assign Fragment rather than RawFragment: URL.String ignores RawFragment when Fragment
		// is empty, which would silently drop every implicit/hybrid response parameter. | 赋值
		// Fragment 而非 RawFragment：当 Fragment 为空时 URL.String 会忽略 RawFragment，
		// 从而静默丢弃所有隐式/混合响应参数。
		location.Fragment = params.Encode()
		http.Redirect(w, r, location.String(), http.StatusFound)
		return errResponseWritten
	default:
		location, err := url.Parse(req.RedirectURI)
		if err != nil {
			return errs.Wrap(err, ErrInvalidRequest)
		}
		query := location.Query()
		for key, values := range params {
			for _, value := range values {
				query.Set(key, value)
			}
		}
		location.RawQuery = query.Encode()
		http.Redirect(w, r, location.String(), http.StatusFound)
		return errResponseWritten
	}
}

// writeFormPost writes an auto-submitting HTML form. | writeFormPost 写入自动提交的 HTML 表单。
func writeFormPost(w http.ResponseWriter, action string, params url.Values) error {
	var b strings.Builder
	b.WriteString("<!doctype html><html><head><meta charset=\"utf-8\"><title>Continue</title></head><body>")
	b.WriteString("<form id=\"f\" method=\"post\" action=\"")
	b.WriteString(htmlstd.EscapeString(action))
	b.WriteString("\">")
	for key, values := range params {
		for _, value := range values {
			b.WriteString("<input type=\"hidden\" name=\"")
			b.WriteString(htmlstd.EscapeString(key))
			b.WriteString("\" value=\"")
			b.WriteString(htmlstd.EscapeString(value))
			b.WriteString("\">")
		}
	}
	b.WriteString("</form><script>document.getElementById('f').submit()</script></body></html>")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.String()))
	return errResponseWritten
}

// writeAuthorizationError redirects an error to the client when the redirect URI is trustworthy. | writeAuthorizationError
// 在重定向 URI 可信时把错误重定向给客户端。
func (s *Server) writeAuthorizationError(w http.ResponseWriter, r *http.Request, req *AuthorizationRequest, err error) {
	if req == nil || req.Client == nil || req.RedirectURI == "" || !req.Client.AllowsRedirect(req.RedirectURI) {
		s.writeOAuthError(w, r, err)
		return
	}
	oauthErr := normalizeError(err)
	params := make(url.Values)
	params.Set("error", oauthErr.Code)
	if oauthErr.Description != "" {
		params.Set("error_description", oauthErr.Description)
	}
	if oauthErr.URI != "" {
		params.Set("error_uri", oauthErr.URI)
	}
	if req.State != "" {
		params.Set("state", req.State)
	}
	if writeErr := s.writeAuthorizationResponse(w, r, req, params); writeErr != nil && !errors.Is(writeErr, errResponseWritten) {
		s.writeOAuthError(w, r, writeErr)
	}
}
