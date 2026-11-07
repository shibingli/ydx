package oauth2

import (
	"net/http"
	"strings"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/errs"
)

// Revoke is the RFC 7009 revocation endpoint. | Revoke 是 RFC 7009 撤销端点。
//
// A successful or unknown-token revocation always returns 200, as the RFC requires; a token that
// belongs to another client is silently ignored so the endpoint does not become an existence
// oracle. | 成功或未知令牌的撤销始终返回 200（RFC 要求）；属于其他客户端的令牌被静默忽略，使端点
// 不会成为存在性预言机。
func (s *Server) Revoke(w http.ResponseWriter, r *http.Request) {
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
	hash := auth.HashToken(raw)
	if hint != "access_token" {
		if refresh, err := s.config.Store.GetRefreshToken(r.Context(), hash); err == nil && refresh.ClientID == client.ID {
			_ = s.config.Store.RevokeRefreshToken(r.Context(), hash, true)
		}
	}
	if hint != "refresh_token" {
		if access, err := s.config.Store.GetAccessToken(r.Context(), hash); err == nil && access.ClientID == client.ID {
			_ = s.config.Store.RevokeAccessToken(r.Context(), hash)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}
