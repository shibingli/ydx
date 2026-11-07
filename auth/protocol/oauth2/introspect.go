package oauth2

import (
	"net/http"
	"strings"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/errs"
)

// Introspect is the RFC 7662 introspection endpoint. The token_type_hint value narrows which
// store is consulted: a wrong hint can therefore return active=false instead of falling back to
// the other token type. | Introspect 是 RFC 7662 自省端点。token_type_hint 会收窄查询的存储，
// 因此错误提示可能返回 active=false，而不会回退到另一种令牌类型。
func (s *Server) Introspect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		s.writeOAuthError(w, r, errs.Detail(ErrInvalidRequest, "method %[1]s not allowed | 不允许方法 %[1]s", r.Method))
		return
	}
	if err := r.ParseForm(); err != nil {
		s.writeOAuthError(w, r, errs.Wrap(err, ErrInvalidRequest))
		return
	}
	client, err := s.authenticateClient(r.Context(), r, r.PostForm)
	if err != nil {
		s.writeOAuthError(w, r, err)
		return
	}
	raw := r.PostForm.Get("token")
	if raw == "" {
		s.writeOAuthError(w, r, errs.Detail(ErrInvalidRequest, "token is required | token 必填"))
		return
	}
	hint := strings.TrimSpace(r.PostForm.Get("token_type_hint"))
	if hint != "refresh_token" {
		if access, err := s.ValidateAccessToken(r.Context(), raw); err == nil {
			if s.config.AllowCrossClientIntrospection || access.ClientID == client.ID {
				writeJSON(w, http.StatusOK, s.accessIntrospection(access))
				return
			}
		}
	}
	if hint != "access_token" {
		if refresh, err := s.config.Store.GetRefreshToken(r.Context(), auth.HashToken(raw)); err == nil {
			if s.config.AllowCrossClientIntrospection || refresh.ClientID == client.ID {
				writeJSON(w, http.StatusOK, s.refreshIntrospection(refresh))
				return
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"active": false})
}

// accessIntrospection renders an access token per RFC 7662. | accessIntrospection 按 RFC 7662 渲染访问令牌。
func (s *Server) accessIntrospection(access *AccessToken) map[string]any {
	out := make(map[string]any, 16)
	active := !access.Revoked && (access.ExpiresAt.IsZero() || s.Now().Before(access.ExpiresAt))
	out["active"] = active
	if !active {
		return out
	}
	if len(access.Scopes) > 0 {
		out["scope"] = ScopeString(access.Scopes)
	}
	if access.ClientID != "" {
		out["client_id"] = access.ClientID
	}
	if access.Subject != "" {
		out["sub"] = access.Subject
		out["username"] = access.Subject
	}
	tokenType := TokenTypeBearer
	if access.DPoPJKT != "" || access.CertThumbprint != "" {
		tokenType = TokenTypeDPoP
	}
	out["token_type"] = tokenType
	if len(access.Audience) > 0 {
		out["aud"] = append([]string(nil), access.Audience...)
	}
	out["iss"] = s.Issuer()
	if !access.IssuedAt.IsZero() {
		out["iat"] = access.IssuedAt.Unix()
	}
	if !access.ExpiresAt.IsZero() {
		out["exp"] = access.ExpiresAt.Unix()
	}
	if access.JTI != "" {
		out["jti"] = access.JTI
	}
	if cnf := confirmationClaim(&Grant{DPoPJKT: access.DPoPJKT, CertThumbprint: access.CertThumbprint}); cnf != nil {
		out["cnf"] = cnf
	}
	if access.ACR != "" {
		out["acr"] = access.ACR
	}
	if len(access.AMR) > 0 {
		out["amr"] = append([]string(nil), access.AMR...)
	}
	if !access.AuthTime.IsZero() {
		out["auth_time"] = access.AuthTime.Unix()
	}
	return out
}

// refreshIntrospection renders a refresh token per RFC 7662. | refreshIntrospection 按 RFC 7662 渲染刷新令牌。
func (s *Server) refreshIntrospection(refresh *RefreshToken) map[string]any {
	out := make(map[string]any, 16)
	active := !refresh.Revoked && !refresh.Used && (refresh.ExpiresAt.IsZero() || s.Now().Before(refresh.ExpiresAt))
	out["active"] = active
	if !active {
		return out
	}
	out["token_type"] = "refresh_token"
	if len(refresh.Scopes) > 0 {
		out["scope"] = ScopeString(refresh.Scopes)
	}
	if refresh.ClientID != "" {
		out["client_id"] = refresh.ClientID
	}
	if refresh.Subject != "" {
		out["sub"] = refresh.Subject
		out["username"] = refresh.Subject
	}
	if len(refresh.Audience) > 0 {
		out["aud"] = append([]string(nil), refresh.Audience...)
	}
	out["iss"] = s.Issuer()
	if !refresh.CreatedAt.IsZero() {
		out["iat"] = refresh.CreatedAt.Unix()
	}
	if !refresh.ExpiresAt.IsZero() {
		out["exp"] = refresh.ExpiresAt.Unix()
	}
	if cnf := confirmationClaim(&Grant{DPoPJKT: refresh.DPoPJKT, CertThumbprint: refresh.CertThumbprint}); cnf != nil {
		out["cnf"] = cnf
	}
	if refresh.ACR != "" {
		out["acr"] = refresh.ACR
	}
	if len(refresh.AMR) > 0 {
		out["amr"] = append([]string(nil), refresh.AMR...)
	}
	if !refresh.AuthTime.IsZero() {
		out["auth_time"] = refresh.AuthTime.Unix()
	}
	return out
}
