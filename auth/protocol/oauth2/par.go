package oauth2

import (
	"net/http"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/errs"
)

// PARRequestURIPrefix is the RFC 9126 request URI prefix. | PARRequestURIPrefix 是 RFC 9126 请求 URI 前缀。
const PARRequestURIPrefix = "urn:ietf:params:oauth:request_uri:"

// PAR is the RFC 9126 pushed authorization request endpoint. | PAR 是 RFC 9126 推送授权请求端点。
func (s *Server) PAR(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		s.writeOAuthError(w, r, errs.Detail(ErrInvalidRequest, "method %[1]s not allowed | 不允许方法 %[1]s", r.Method))
		return
	}
	if err := r.ParseForm(); err != nil {
		s.writeOAuthError(w, r, errs.Wrap(err, ErrInvalidRequest))
		return
	}
	form := r.PostForm
	if form.Get("request_uri") != "" {
		s.writeOAuthError(w, r, errs.Detail(ErrInvalidRequest, "request_uri is not allowed in PAR | PAR 中不允许 request_uri"))
		return
	}
	client, err := s.authenticateClient(r.Context(), r, form)
	if err != nil {
		s.writeOAuthError(w, r, err)
		return
	}
	params := cloneValues(form)
	params.Set("client_id", client.ID)
	// RFC 9101 permits a signed request object inside a pushed authorization request; verify it
	// now so the stored parameters are exactly the signed set. | RFC 9101 允许在推送授权请求中携带
	// 已签名请求对象；此时立即校验，使保存的参数恰好是已签名集合。
	params, err = s.resolveRequestObjectValues(r.Context(), params)
	if err != nil {
		s.writeOAuthError(w, r, err)
		return
	}
	req, err := parseAuthorizationValues(r.Context(), params, s.config.Clients, s.config.Scopes)
	if err != nil {
		s.writeOAuthError(w, r, err)
		return
	}
	if req.Client.ID != client.ID {
		s.writeOAuthError(w, r, errs.Detail(ErrInvalidClient, "client_id does not match the authenticated client | client_id 与已认证客户端不匹配"))
		return
	}
	if err := s.validateAuthorizationRequest(req); err != nil {
		s.writeOAuthError(w, r, err)
		return
	}
	// Persist the normalized parameters so the later authorization request cannot smuggle a
	// different redirect URI or scope through the request_uri. Client credentials are never
	// persisted: the authorization endpoint does not need them and the store must not hold
	// secrets at rest. | 保存规范化参数，使后续授权请求无法通过 request_uri 夹带不同的重定向
	// URI 或作用域。客户端凭据绝不持久化：授权端点不需要它们，存储也不应保存明文密钥。
	stored := cloneValues(params)
	stored.Del("client_secret")
	stored.Del("client_assertion")
	stored.Del("client_assertion_type")
	stored.Set("client_id", req.ClientID)
	stored.Set("redirect_uri", req.RedirectURI)
	stored.Set("response_type", req.ResponseType)
	if len(req.Scopes) > 0 {
		stored.Set("scope", req.ScopeString())
	}
	if req.State != "" {
		stored.Set("state", req.State)
	}
	if req.Nonce != "" {
		stored.Set("nonce", req.Nonce)
	}
	if req.CodeChallenge != "" {
		stored.Set("code_challenge", req.CodeChallenge)
		stored.Set("code_challenge_method", req.CodeChallengeMethod)
	}
	if req.ResponseMode != "" {
		stored.Set("response_mode", req.ResponseMode)
	}
	requestURIValue, err := auth.RandomToken(32)
	if err != nil {
		s.writeOAuthError(w, r, errs.Wrap(err, ErrServerError))
		return
	}
	requestURI := PARRequestURIPrefix + requestURIValue
	now := s.Now()
	record := &PARRequest{
		RequestURI: requestURI,
		ClientID:   client.ID,
		Params:     stored,
		CreatedAt:  now,
		ExpiresAt:  now.Add(s.config.PARTTL),
	}
	if err := s.config.Store.SavePAR(r.Context(), record); err != nil {
		s.writeOAuthError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"request_uri": requestURI,
		"expires_in":  int64(s.config.PARTTL / time.Second),
	})
}
