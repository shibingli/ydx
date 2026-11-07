package oauth2

import (
	"net/http"
	"net/url"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/errs"
)

// grantAuthorizationCode redeems an authorization code. | grantAuthorizationCode 兑换授权码。
func (s *Server) grantAuthorizationCode(r *http.Request, client *Client, form url.Values) (*TokenResponse, error) {
	if len(client.GrantTypes) > 0 && !client.AllowsGrant(GrantAuthorizationCode) {
		return nil, errs.Detail(ErrUnauthorizedClient, "client cannot use the authorization-code grant | 客户端不能使用授权码授权")
	}
	raw := form.Get("code")
	if raw == "" {
		return nil, errs.Detail(ErrInvalidRequest, "code is required | code 必填")
	}
	record, err := s.config.Store.ConsumeAuthorizationCode(r.Context(), auth.HashToken(raw), s.Now())
	if err != nil {
		return nil, err
	}
	if record.ClientID != client.ID {
		return nil, errs.Detail(ErrInvalidGrant, "authorization code belongs to another client | 授权码属于其他客户端")
	}
	redirectURI := form.Get("redirect_uri")
	if record.RedirectURIProvided && redirectURI == "" {
		// RFC 6749 section 4.1.3: redirect_uri is REQUIRED when it was included in the
		// authorization request. | RFC 6749 第 4.1.3 节：授权请求包含 redirect_uri 时，令牌
		// 请求必须提供该参数。
		return nil, errs.Detail(ErrInvalidGrant, "redirect_uri is required | redirect_uri 必填")
	}
	if redirectURI != "" && redirectURI != record.RedirectURI {
		return nil, errs.Detail(ErrInvalidGrant, "redirect_uri does not match the authorization request | redirect_uri 与授权请求不匹配")
	}
	if record.CodeChallenge != "" {
		verifier := form.Get("code_verifier")
		if verifier == "" {
			return nil, errs.Detail(ErrInvalidGrant, "code_verifier is required | code_verifier 必填")
		}
		if !VerifyPKCE(verifier, record.CodeChallenge, record.CodeChallengeMethod) {
			return nil, errs.Detail(ErrInvalidGrant, "PKCE verification failed | PKCE 校验失败")
		}
	} else if client.Public && !s.config.DisablePKCEEnforcement {
		return nil, errs.Detail(ErrInvalidGrant, "public client authorization code has no PKCE binding | 公共客户端授权码没有 PKCE 绑定")
	}
	jkt, err := s.dpopForTokenRequest(r.Context(), r, record.DPoPJKT, "")
	if err != nil {
		return nil, err
	}
	audience := append([]string(nil), record.Resource...)
	requestedAudience, err := s.grantAudience(form["resource"], nil)
	if err != nil {
		return nil, err
	}
	if len(requestedAudience) > 0 {
		if len(record.Resource) > 0 && !isSubset(requestedAudience, record.Resource) {
			return nil, errs.Detail(ErrInvalidTarget, "resource is broader than the authorization grant | 资源超出授权许可")
		}
		audience = requestedAudience
	}
	scopes := append([]string(nil), record.Scopes...)
	if requested := ParseScope(form.Get("scope")); len(requested) > 0 {
		validated, err := s.grantScopes(client, requested)
		if err != nil {
			return nil, err
		}
		if !isSubset(validated, record.Scopes) {
			return nil, errs.Detail(ErrInvalidScope, "scope is broader than the authorization grant | 作用域超出授权许可")
		}
		scopes = validated
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
		Nonce:          record.Nonce,
		ResponseType:   ResponseCode,
		Code:           record,
		DPoPJKT:        jkt,
		CertThumbprint: cert,
		GrantID:        auth.NewID("grant"),
		IssuedAt:       s.Now(),
		Claims:         record.Claims,
	}
	if grant.AuthTime.IsZero() {
		grant.AuthTime = s.Now()
	}
	return s.issueTokens(r.Context(), grant, s.shouldIssueRefresh(grant))
}

// isSubset reports whether every value in want appears in allowed. | isSubset 报告 want 中每个值是否都出现在 allowed。
func isSubset(want, allowed []string) bool {
	if len(want) == 0 {
		return true
	}
	set := make(map[string]bool, len(allowed))
	for _, value := range allowed {
		set[value] = true
	}
	for _, value := range want {
		if !set[value] {
			return false
		}
	}
	return true
}

// ensureTime returns t or now when t is zero. | ensureTime 在 t 为零时返回 now。
func ensureTime(t, now time.Time) time.Time {
	if t.IsZero() {
		return now
	}
	return t
}
