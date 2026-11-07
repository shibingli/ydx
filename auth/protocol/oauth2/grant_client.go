package oauth2

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/errs"
)

// grantClientCredentials issues a token for the client itself. | grantClientCredentials 为客户端自身签发令牌。
func (s *Server) grantClientCredentials(r *http.Request, client *Client, form url.Values) (*TokenResponse, error) {
	if client.Public || registeredAuthMethod(client) == ClientAuthNone {
		// RFC 6749 section 4.4 restricts this grant to confidential clients. | RFC 6749 第 4.4 节
		// 将该授权限定为机密客户端。
		return nil, errs.Detail(ErrUnauthorizedClient, "public clients cannot use the client-credentials grant | 公共客户端不能使用客户端凭据授权")
	}
	if len(client.GrantTypes) > 0 && !client.AllowsGrant(GrantClientCredentials) {
		return nil, errs.Detail(ErrUnauthorizedClient, "client cannot use the client-credentials grant | 客户端不能使用客户端凭据授权")
	}
	scopes, err := s.grantScopes(client, ParseScope(form.Get("scope")))
	if err != nil {
		return nil, err
	}
	if len(scopes) == 0 {
		scopes = append([]string(nil), client.Scopes...)
	}
	audience, err := s.grantAudience(form["resource"], s.config.DefaultAudience)
	if err != nil {
		return nil, err
	}
	jkt, err := s.dpopForTokenRequest(r.Context(), r, "", "")
	if err != nil {
		return nil, err
	}
	grant := &Grant{
		Client:         client,
		Subject:        client.ID,
		Scopes:         scopes,
		Audience:       audience,
		DPoPJKT:        jkt,
		CertThumbprint: certThumbprint(r),
		GrantID:        auth.NewID("grant"),
		IssuedAt:       s.Now(),
	}
	return s.issueTokens(r.Context(), grant, false)
}

// grantPassword performs the deprecated resource-owner-password grant. | grantPassword 执行已弃用的资源所有者口令授权。
func (s *Server) grantPassword(r *http.Request, client *Client, form url.Values) (*TokenResponse, error) {
	if !s.config.AllowPasswordGrant || s.config.PasswordAuthenticator == nil {
		return nil, errs.Detail(ErrUnsupportedGrantType, "password grant is disabled | 口令授权已禁用")
	}
	if len(client.GrantTypes) > 0 && !client.AllowsGrant(GrantPassword) {
		return nil, errs.Detail(ErrUnauthorizedClient, "client cannot use the password grant | 客户端不能使用口令授权")
	}
	username := form.Get("username")
	password := form.Get("password")
	if username == "" || password == "" {
		return nil, errs.Detail(ErrInvalidRequest, "username and password are required | 用户名与口令必填")
	}
	principal, err := s.config.PasswordAuthenticator.AuthenticatePassword(r.Context(), username, password)
	if err != nil {
		// Invalid resource-owner credentials are invalid_grant per RFC 6749 section 5.2, not
		// invalid_client or server_error. Genuine backend failures keep their own sentinel. |
		// 资源所有者凭据无效按 RFC 6749 第 5.2 节返回 invalid_grant，而不是 invalid_client 或
		// server_error；真正的后端故障保留原哨兵。
		if errors.Is(err, auth.ErrUnauthorized) || errors.Is(err, auth.ErrSessionExpired) ||
			errors.Is(err, auth.ErrSessionRevoked) {
			return nil, errs.Wrap(err, ErrInvalidGrant)
		}
		return nil, err
	}
	if principal == nil {
		return nil, ErrInvalidGrant
	}
	scopes, err := s.grantScopes(client, ParseScope(form.Get("scope")))
	if err != nil {
		return nil, err
	}
	if len(scopes) == 0 {
		scopes = append([]string(nil), client.Scopes...)
	}
	audience, err := s.grantAudience(form["resource"], s.config.DefaultAudience)
	if err != nil {
		return nil, err
	}
	jkt, err := s.dpopForTokenRequest(r.Context(), r, "", "")
	if err != nil {
		return nil, err
	}
	grant := &Grant{
		Client:         client,
		Principal:      principal,
		UserID:         principal.Subject,
		Subject:        principal.Subject,
		Scopes:         scopes,
		Audience:       audience,
		AuthTime:       ensureTime(principal.AuthTime, s.Now()),
		ACR:            principal.ACR,
		AMR:            append([]string(nil), principal.AMR...),
		SessionID:      principal.SessionID,
		DPoPJKT:        jkt,
		CertThumbprint: certThumbprint(r),
		GrantID:        auth.NewID("grant"),
		IssuedAt:       s.Now(),
	}
	return s.issueTokens(r.Context(), grant, s.shouldIssueRefresh(grant))
}
