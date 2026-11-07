package oidc

import (
	"net/http"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/auth/protocol/oauth2"
	"github.com/shibingli/ydx/auth/token/jose"
	"github.com/shibingli/ydx/json"
)

// UserInfo serves the OpenID Connect UserInfo endpoint. | UserInfo 提供 OpenID Connect UserInfo 端点。
func (p *Provider) UserInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		writeError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed | 方法不允许")
		return
	}
	raw, err := auth.BearerToken(r)
	if err != nil {
		unauthorized(w, "bearer token is missing | 缺少承载令牌")
		return
	}
	access, err := p.oauth.ValidateAccessTokenRequest(r.Context(), r, raw)
	if err != nil {
		unauthorized(w, "access token is invalid | 访问令牌无效")
		return
	}
	if !oauth2.HasScope(access.Scopes, ScopeOpenID) {
		// UserInfo is an OpenID Connect endpoint: only access tokens issued for the openid
		// scope may call it (RFC 6750 section 3.3 insufficient_scope). | UserInfo 是 OpenID
		// Connect 端点：只有为 openid 作用域签发的访问令牌可以调用（RFC 6750 第 3.3 节
		// insufficient_scope）。
		w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="openid"`)
		writeError(w, http.StatusForbidden, "insufficient_scope", "openid scope is required | 需要 openid 作用域")
		return
	}
	client, err := p.oauth.Config().Clients.GetClient(r.Context(), access.ClientID)
	if err != nil {
		unauthorized(w, "access token client is unknown | 访问令牌客户端未知")
		return
	}
	principal := access.Principal.Clone()
	if principal == nil {
		principal = &auth.Principal{
			Subject:   access.Subject,
			ClientID:  access.ClientID,
			Scopes:    append([]string(nil), access.Scopes...),
			AuthTime:  access.AuthTime,
			ACR:       access.ACR,
			AMR:       append([]string(nil), access.AMR...),
			SessionID: access.SessionID,
			ExpiresAt: access.ExpiresAt,
			IssuedAt:  access.IssuedAt,
		}
	}
	principal.ClientID = access.ClientID
	claims, err := p.claims.UserInfoClaims(r.Context(), principal, access.Scopes)
	if err != nil {
		invalidConfig(w, err)
		return
	}
	if claims == nil {
		claims = make(map[string]any)
	}
	claims["sub"] = p.subjectForClient(client, access.Subject)
	if client.UserInfoSignedResponseAlg == "" {
		writeJSON(w, http.StatusOK, claims)
		return
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		invalidConfig(w, err)
		return
	}
	signingKey, err := p.signingKeyFor(client.UserInfoSignedResponseAlg)
	if err != nil {
		invalidConfig(w, err)
		return
	}
	signed, err := jose.Sign(payload, signingKey, jose.SignOptions{
		Alg: client.UserInfoSignedResponseAlg,
		Kid: signingKey.Kid,
		Typ: "JWT",
	})
	if err != nil {
		invalidConfig(w, err)
		return
	}
	body := []byte(signed)
	contentType := "application/jwt"
	if client.UserInfoEncryptedResponseAlg != "" {
		enc := client.UserInfoEncryptedResponseEnc
		if enc == "" {
			enc = "A256GCM"
		}
		key, err := p.clientEncryptionKey(r.Context(), client)
		if err != nil {
			invalidConfig(w, err)
			return
		}
		encrypted, err := jose.Encrypt(body, key, jose.EncryptOptions{
			Alg: client.UserInfoEncryptedResponseAlg,
			Enc: enc,
			Typ: "JWT",
			Cty: "JWT",
		})
		if err != nil {
			invalidConfig(w, err)
			return
		}
		body = []byte(encrypted)
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
