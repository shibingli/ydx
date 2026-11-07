package oauth2

import (
	"context"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/errs"
)

// accessTTL returns the access-token lifetime for client. | accessTTL 返回 client 的访问令牌寿命。
func (s *Server) accessTTL(client *Client) time.Duration {
	if client != nil && client.AccessTokenTTL > 0 {
		return client.AccessTokenTTL
	}
	return s.config.AccessTokenTTL
}

// refreshTTL returns the refresh-token lifetime for client. | refreshTTL 返回 client 的刷新令牌寿命。
func (s *Server) refreshTTL(client *Client) time.Duration {
	if client != nil && client.RefreshTokenTTL > 0 {
		return client.RefreshTokenTTL
	}
	return s.config.RefreshTokenTTL
}

// issueTokens issues an access token and, optionally, a refresh token. | issueTokens 签发访问令牌，并可选签发刷新令牌。
func (s *Server) issueTokens(ctx context.Context, grant *Grant, includeRefresh bool) (*TokenResponse, error) {
	if grant == nil || grant.Client == nil {
		return nil, errs.Detail(ErrServerError, "grant or client is nil | 许可或客户端为空")
	}
	now := s.Now()
	if grant.IssuedAt.IsZero() {
		grant.IssuedAt = now
	}
	if s.config.DPoPRequired && grant.DPoPJKT == "" {
		return nil, errs.Detail(ErrInvalidDPoPProof, "DPoP-bound token required | 必须使用 DPoP 绑定令牌")
	}
	tokenType := TokenTypeBearer
	if grant.DPoPJKT != "" {
		tokenType = TokenTypeDPoP
	}
	ttl := s.accessTTL(grant.Client)
	expiresAt := now.Add(ttl)
	jti := auth.NewID("at")
	var accessToken string
	if s.config.TokenFormat == TokenFormatJWT {
		claims := &AccessTokenClaims{
			Issuer:    s.Issuer(),
			Subject:   grant.Subject,
			Audience:  append([]string(nil), grant.Audience...),
			ExpiresAt: expiresAt.Unix(),
			IssuedAt:  now.Unix(),
			JTI:       jti,
			ClientID:  grant.Client.ID,
			Scope:     ScopeString(grant.Scopes),
			ACR:       grant.ACR,
			AMR:       append([]string(nil), grant.AMR...),
			CNF:       confirmationClaim(grant),
		}
		if !grant.AuthTime.IsZero() {
			claims.AuthTime = grant.AuthTime.Unix()
		}
		signed, err := s.config.AccessTokenIssuer.SignAccessToken(ctx, claims)
		if err != nil {
			return nil, errs.Wrap(err, ErrServerError)
		}
		accessToken = signed
	} else {
		raw, err := auth.RandomToken(32)
		if err != nil {
			return nil, err
		}
		accessToken = raw
	}
	stored := &AccessToken{
		TokenHash:      auth.HashToken(accessToken),
		ClientID:       grant.Client.ID,
		UserID:         grant.UserID,
		Subject:        grant.Subject,
		Scopes:         append([]string(nil), grant.Scopes...),
		Audience:       append([]string(nil), grant.Audience...),
		Principal:      grant.Principal.Clone(),
		AuthTime:       grant.AuthTime,
		ACR:            grant.ACR,
		AMR:            append([]string(nil), grant.AMR...),
		SessionID:      grant.SessionID,
		IssuedAt:       now,
		ExpiresAt:      expiresAt,
		JTI:            jti,
		DPoPJKT:        grant.DPoPJKT,
		CertThumbprint: grant.CertThumbprint,
		GrantID:        grant.GrantID,
	}
	if err := s.config.Store.SaveAccessToken(ctx, stored); err != nil {
		return nil, err
	}
	response := &TokenResponse{
		AccessToken: accessToken,
		TokenType:   tokenType,
		ExpiresIn:   int64(ttl / time.Second),
		Scope:       ScopeString(grant.Scopes),
	}
	if includeRefresh {
		if err := s.issueRefreshToken(ctx, grant, response, now); err != nil {
			return nil, err
		}
	}
	if s.config.TokenEnricher != nil {
		if err := s.config.TokenEnricher.EnrichToken(ctx, grant, response); err != nil {
			return nil, errs.Wrap(err, ErrServerError)
		}
	}
	return response, nil
}

// issueRefreshToken adds a refresh token to response. | issueRefreshToken 向 response 添加刷新令牌。
func (s *Server) issueRefreshToken(ctx context.Context, grant *Grant, response *TokenResponse, now time.Time) error {
	raw, err := auth.RandomToken(40)
	if err != nil {
		return err
	}
	familyID := grant.GrantID
	if familyID == "" {
		familyID = auth.NewID("family")
	}
	parentHash := ""
	if grant.RefreshToken != nil {
		if grant.RefreshToken.FamilyID != "" {
			familyID = grant.RefreshToken.FamilyID
		}
		parentHash = grant.RefreshToken.TokenHash
	}
	token := &RefreshToken{
		TokenHash:  auth.HashToken(raw),
		FamilyID:   familyID,
		ParentHash: parentHash,
		ClientID:   grant.Client.ID,
		UserID:     grant.UserID,
		Subject:    grant.Subject,
		Principal:  grant.Principal.Clone(),
		Scopes:     append([]string(nil), grant.Scopes...),
		Audience:   append([]string(nil), grant.Audience...),
		AuthTime:   grant.AuthTime,
		ACR:        grant.ACR,
		AMR:        append([]string(nil), grant.AMR...),
		SessionID:  grant.SessionID,
		DPoPJKT:    grant.DPoPJKT,
		CreatedAt:  now,
		ExpiresAt:  now.Add(s.refreshTTL(grant.Client)),
	}
	if grant.RefreshToken == nil {
		if err := s.config.Store.SaveRefreshToken(ctx, token); err != nil {
			return err
		}
		response.RefreshToken = raw
		return nil
	}
	if s.config.RefreshTokenRotationDisabled {
		if err := s.config.Store.SaveRefreshToken(ctx, token); err != nil {
			return err
		}
		response.RefreshToken = raw
		return nil
	}
	rotated, err := s.config.Store.RotateRefreshToken(ctx, grant.RefreshToken.TokenHash, token, now)
	if err != nil {
		return err
	}
	if !rotated {
		// A refresh token that was already rotated is a replay. Revoke the whole family so a stolen
		// token cannot outlive the legitimate rotation. | 已轮换的刷新令牌再次出现即为重放。撤销整个家族，
		// 使被盗令牌不能比合法轮换存活更久。
		_ = s.config.Store.RevokeRefreshToken(ctx, grant.RefreshToken.TokenHash, true)
		return errs.Detail(ErrInvalidGrant, "refresh token replay detected | 检测到刷新令牌重放")
	}
	response.RefreshToken = raw
	return nil
}

// confirmationClaim returns the RFC 7800 cnf claim for a grant. | confirmationClaim 返回许可的 RFC 7800 cnf 声明。
func confirmationClaim(grant *Grant) map[string]any {
	if grant == nil {
		return nil
	}
	out := make(map[string]any, 2)
	if grant.DPoPJKT != "" {
		out["jkt"] = grant.DPoPJKT
	}
	if grant.CertThumbprint != "" {
		out["x5t#S256"] = grant.CertThumbprint
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
