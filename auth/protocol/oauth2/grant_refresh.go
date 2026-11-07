package oauth2

import (
	"net/http"
	"net/url"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/errs"
)

// grantRefreshToken rotates or exchanges a refresh token. | grantRefreshToken 轮换或兑换刷新令牌。
func (s *Server) grantRefreshToken(r *http.Request, client *Client, form url.Values) (*TokenResponse, error) {
	if len(client.GrantTypes) > 0 && !client.AllowsGrant(GrantRefreshToken) {
		return nil, errs.Detail(ErrUnauthorizedClient, "client cannot use the refresh-token grant | 客户端不能使用刷新令牌授权")
	}
	raw := form.Get("refresh_token")
	if raw == "" {
		return nil, errs.Detail(ErrInvalidRequest, "refresh_token is required | refresh_token 必填")
	}
	record, err := s.config.Store.GetRefreshToken(r.Context(), auth.HashToken(raw))
	if err != nil {
		return nil, err
	}
	if record.ClientID != client.ID {
		return nil, errs.Detail(ErrInvalidGrant, "refresh token belongs to another client | 刷新令牌属于其他客户端")
	}
	if record.Revoked {
		return nil, errs.Detail(ErrInvalidGrant, "refresh token revoked | 刷新令牌已撤销")
	}
	if record.Used {
		// Reuse of a rotated token is a strong signal of theft. | 已轮换令牌再次出现是强烈的被盗信号。
		_ = s.config.Store.RevokeRefreshToken(r.Context(), record.TokenHash, true)
		return nil, errs.Detail(ErrInvalidGrant, "refresh token replay detected | 检测到刷新令牌重放")
	}
	if !record.ExpiresAt.IsZero() && !s.Now().Before(record.ExpiresAt) {
		return nil, errs.Detail(ErrInvalidGrant, "refresh token expired | 刷新令牌已过期")
	}
	jkt, err := s.dpopForTokenRequest(r.Context(), r, record.DPoPJKT, "")
	if err != nil {
		return nil, err
	}
	scopes := append([]string(nil), record.Scopes...)
	if requested := ParseScope(form.Get("scope")); len(requested) > 0 {
		validated, err := s.grantScopes(client, requested)
		if err != nil {
			return nil, err
		}
		if !isSubset(validated, record.Scopes) {
			return nil, errs.Detail(ErrInvalidScope, "scope is broader than the original grant | 作用域超出原始许可")
		}
		scopes = validated
	}
	audience := append([]string(nil), record.Audience...)
	requestedAudience, err := s.grantAudience(form["resource"], nil)
	if err != nil {
		return nil, err
	}
	if len(requestedAudience) > 0 {
		if len(record.Audience) > 0 && !isSubset(requestedAudience, record.Audience) {
			return nil, errs.Detail(ErrInvalidTarget, "resource is broader than the original grant | 资源超出原始许可")
		}
		audience = requestedAudience
	}
	cert := record.CertThumbprint
	if cert == "" {
		cert = certThumbprint(r)
	}
	principal := record.Principal.Clone()
	if principal == nil {
		principal = &auth.Principal{
			Subject:   record.Subject,
			AuthTime:  record.AuthTime,
			ACR:       record.ACR,
			AMR:       append([]string(nil), record.AMR...),
			SessionID: record.SessionID,
		}
	}
	grant := &Grant{
		Client:         client,
		Principal:      principal,
		UserID:         record.UserID,
		Subject:        record.Subject,
		Scopes:         scopes,
		Audience:       audience,
		AuthTime:       record.AuthTime,
		ACR:            record.ACR,
		AMR:            append([]string(nil), record.AMR...),
		SessionID:      record.SessionID,
		ResponseType:   ResponseCode,
		RefreshToken:   record,
		DPoPJKT:        jkt,
		CertThumbprint: cert,
		GrantID:        record.FamilyID,
		IssuedAt:       s.Now(),
	}
	return s.issueTokens(r.Context(), grant, true)
}
