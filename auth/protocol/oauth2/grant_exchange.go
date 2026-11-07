package oauth2

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/errs"
)

// timeUnix converts a NumericDate to UTC time. | timeUnix 把 NumericDate 转换为 UTC 时间。
func timeUnix(seconds int64) time.Time { return time.Unix(seconds, 0).UTC() }

// grantTokenExchange performs RFC 8693 token exchange. | grantTokenExchange 执行 RFC 8693 令牌交换。
func (s *Server) grantTokenExchange(r *http.Request, client *Client, form url.Values) (*TokenResponse, error) {
	if !s.config.EnableTokenExchange {
		return nil, errs.Detail(ErrUnsupportedGrantType, "token exchange is disabled | 令牌交换已禁用")
	}
	if len(client.GrantTypes) > 0 && !client.AllowsGrant(GrantTokenExchange) {
		return nil, errs.Detail(ErrUnauthorizedClient, "client cannot use token exchange | 客户端不能使用令牌交换")
	}
	subjectToken := form.Get("subject_token")
	subjectType := form.Get("subject_token_type")
	if subjectToken == "" || subjectType == "" {
		return nil, errs.Detail(ErrInvalidRequest, "subject_token and subject_token_type are required | subject_token 与 subject_token_type 必填")
	}
	principal, err := s.validateSubjectToken(r.Context(), subjectType, subjectToken)
	if err != nil {
		// A rejected subject token is invalid_grant, matching the actor-token and JWT-bearer
		// paths, instead of surfacing as a server_error. | 主体令牌被拒绝属于 invalid_grant，
		// 与 actor 令牌及 JWT 承载路径一致，而不是暴露为 server_error。
		return nil, errs.Wrap(err, ErrInvalidGrant)
	}
	if principal == nil {
		return nil, errs.Detail(ErrInvalidGrant, "subject token produced no principal | 主体令牌未产生主体")
	}
	if actor := form.Get("actor_token"); actor != "" {
		actorType := form.Get("actor_token_type")
		if actorType == "" {
			return nil, errs.Detail(ErrInvalidRequest, "actor_token_type is required with actor_token | actor_token 必须带 actor_token_type")
		}
		if _, err := s.validateSubjectToken(r.Context(), actorType, actor); err != nil {
			return nil, errs.Wrap(err, ErrInvalidGrant)
		}
	}
	scopes := append([]string(nil), principal.Scopes...)
	if requested := ParseScope(form.Get("scope")); len(requested) > 0 {
		validated, err := s.grantScopes(client, requested)
		if err != nil {
			return nil, err
		}
		if len(principal.Scopes) > 0 && !isSubset(validated, principal.Scopes) {
			return nil, errs.Detail(ErrInvalidScope, "scope is broader than the subject token | 作用域超出主体令牌")
		}
		scopes = validated
	}
	audienceValues := append([]string(nil), form["audience"]...)
	audienceValues = append(audienceValues, form["resource"]...)
	audience, err := s.grantAudience(audienceValues, s.config.DefaultAudience)
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
	requestedType := form.Get("requested_token_type")
	if requestedType == "" {
		requestedType = SubjectTokenAccessToken
	}
	switch requestedType {
	case SubjectTokenAccessToken:
		response, err := s.issueTokens(r.Context(), grant, false)
		if err != nil {
			return nil, err
		}
		response.IssuedTokenType = SubjectTokenAccessToken
		return response, nil
	case SubjectTokenJWT:
		if s.config.TokenFormat != TokenFormatJWT {
			return nil, errs.Detail(ErrInvalidRequest, "JWT access tokens are not enabled | 未启用 JWT 访问令牌")
		}
		response, err := s.issueTokens(r.Context(), grant, false)
		if err != nil {
			return nil, err
		}
		response.IssuedTokenType = SubjectTokenJWT
		return response, nil
	case SubjectTokenIDToken:
		if s.config.TokenEnricher == nil {
			return nil, errs.Detail(ErrInvalidRequest, "ID tokens are not enabled | 未启用 ID 令牌")
		}
		if !HasScope(grant.Scopes, ScopeOpenID) {
			grant.Scopes = append(grant.Scopes, ScopeOpenID)
		}
		response, err := s.issueTokens(r.Context(), grant, false)
		if err != nil {
			return nil, err
		}
		if response.IDToken == "" {
			return nil, errs.Detail(ErrServerError, "enricher produced no ID token | 增强器未生成 ID 令牌")
		}
		response.IssuedTokenType = SubjectTokenIDToken
		return response, nil
	default:
		return nil, errs.Detail(ErrInvalidRequest, "unsupported requested_token_type | 不支持的 requested_token_type")
	}
}

// validateSubjectToken validates an RFC 8693 subject token. | validateSubjectToken 校验 RFC 8693 主体令牌。
func (s *Server) validateSubjectToken(ctx context.Context, tokenType, token string) (*auth.Principal, error) {
	if s.config.SubjectTokenValidator != nil {
		return s.config.SubjectTokenValidator.ValidateSubjectToken(ctx, tokenType, token)
	}
	switch tokenType {
	case SubjectTokenAccessToken:
		access, err := s.ValidateAccessToken(ctx, token)
		if err != nil {
			return nil, errs.Wrap(err, ErrInvalidGrant)
		}
		return &auth.Principal{
			Subject:   access.Subject,
			ClientID:  access.ClientID,
			Scopes:    append([]string(nil), access.Scopes...),
			Audience:  append([]string(nil), access.Audience...),
			AuthTime:  access.AuthTime,
			ACR:       access.ACR,
			AMR:       append([]string(nil), access.AMR...),
			SessionID: access.SessionID,
		}, nil
	case SubjectTokenJWT, SubjectTokenIDToken:
		if s.config.AccessTokenVerifier == nil {
			return nil, errs.Detail(ErrInvalidGrant, "JWT subject tokens need an access-token verifier | JWT 主体令牌需要访问令牌校验器")
		}
		claims, err := s.config.AccessTokenVerifier.VerifyAccessToken(ctx, token)
		if err != nil {
			return nil, errs.Wrap(err, ErrInvalidGrant)
		}
		var authTime = s.Now()
		if claims.AuthTime > 0 {
			authTime = timeUnix(claims.AuthTime)
		}
		return &auth.Principal{
			Subject:  claims.Subject,
			ClientID: claims.ClientID,
			Scopes:   ParseScope(claims.Scope),
			Audience: append([]string(nil), claims.Audience...),
			AuthTime: authTime,
			ACR:      claims.ACR,
			AMR:      append([]string(nil), claims.AMR...),
		}, nil
	default:
		return nil, errs.Detail(ErrInvalidGrant, "unsupported subject_token_type %[1]q | 不支持 subject_token_type %[1]q", tokenType)
	}
}

// grantJWTBearer performs the RFC 7523 JWT-bearer grant. | grantJWTBearer 执行 RFC 7523 JWT 承载授权。
func (s *Server) grantJWTBearer(r *http.Request, client *Client, form url.Values) (*TokenResponse, error) {
	if !s.config.EnableJWTBearer || s.config.JWTBearerValidator == nil {
		return nil, errs.Detail(ErrUnsupportedGrantType, "JWT bearer grant is disabled | JWT 承载授权已禁用")
	}
	if len(client.GrantTypes) > 0 && !client.AllowsGrant(GrantJWTBearer) {
		return nil, errs.Detail(ErrUnauthorizedClient, "client cannot use the JWT bearer grant | 客户端不能使用 JWT 承载授权")
	}
	assertion := form.Get("assertion")
	if assertion == "" {
		return nil, errs.Detail(ErrInvalidRequest, "assertion is required | assertion 必填")
	}
	principal, err := s.config.JWTBearerValidator.ValidateJWTBearer(r.Context(), assertion)
	if err != nil {
		return nil, errs.Wrap(err, ErrInvalidGrant)
	}
	if principal == nil {
		return nil, ErrInvalidGrant
	}
	scopes := append([]string(nil), principal.Scopes...)
	if requested := ParseScope(form.Get("scope")); len(requested) > 0 {
		validated, err := s.grantScopes(client, requested)
		if err != nil {
			return nil, err
		}
		scopes = validated
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
