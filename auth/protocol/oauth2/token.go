package oauth2

import (
	"net/http"
	"strings"

	"github.com/shibingli/ydx/errs"
)

// Token is the token endpoint. | Token 是令牌端点。
//
// It is a router.HandlerFuncRaw and an http.HandlerFunc at the same time. | 它同时是 router.HandlerFuncRaw
// 与 http.HandlerFunc。
func (s *Server) Token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		s.writeOAuthError(w, r, errs.Detail(ErrInvalidRequest, "method %[1]s not allowed | 不允许方法 %[1]s", r.Method))
		return
	}
	contentType := strings.ToLower(r.Header.Get("Content-Type"))
	if !strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
		s.writeOAuthError(w, r, errs.Detail(ErrInvalidRequest, "token endpoint requires application/x-www-form-urlencoded | 令牌端点需要 application/x-www-form-urlencoded"))
		return
	}
	limitFormBody(w, r)
	if err := r.ParseForm(); err != nil {
		s.writeOAuthError(w, r, errs.Wrap(err, ErrInvalidRequest))
		return
	}
	form := r.PostForm
	client, err := s.authenticateClient(r.Context(), r, form, s.config.TokenPath)
	if err != nil {
		s.writeOAuthError(w, r, err)
		return
	}
	grantType := strings.TrimSpace(form.Get("grant_type"))
	if grantType == "" {
		s.writeOAuthError(w, r, errs.Detail(ErrInvalidRequest, "grant_type is required | grant_type 必填"))
		return
	}
	var response *TokenResponse
	switch grantType {
	case GrantAuthorizationCode:
		response, err = s.grantAuthorizationCode(r, client, form)
	case GrantRefreshToken:
		response, err = s.grantRefreshToken(r, client, form)
	case GrantClientCredentials:
		response, err = s.grantClientCredentials(r, client, form)
	case GrantPassword:
		response, err = s.grantPassword(r, client, form)
	case GrantDeviceCode:
		response, err = s.grantDeviceCode(r, client, form)
	case GrantTokenExchange:
		response, err = s.grantTokenExchange(r, client, form)
	case GrantJWTBearer:
		response, err = s.grantJWTBearer(r, client, form)
	default:
		err = errs.Detail(ErrUnsupportedGrantType, "grant_type %[1]q | grant_type %[1]q", grantType)
	}
	if err != nil {
		s.writeOAuthError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

// grantScopes validates a token-endpoint scope request. | grantScopes 校验令牌端点作用域请求。
func (s *Server) grantScopes(client *Client, requested []string) ([]string, error) {
	if len(requested) == 0 {
		return nil, nil
	}
	if s.config.Scopes != nil {
		return s.config.Scopes.Validate(requested, client)
	}
	for _, scope := range requested {
		if !client.AllowsScope(scope) {
			return nil, errs.Detail(ErrInvalidScope, "scope %[1]q is not allowed | 不允许作用域 %[1]q", scope)
		}
	}
	return requested, nil
}

// grantAudience resolves and validates resource indicators for a token request. | grantAudience
// 解析并校验令牌请求的资源指示器。
func (s *Server) grantAudience(values []string, fallback []string) ([]string, error) {
	resources, err := parseResources(values)
	if err != nil {
		return nil, err
	}
	if len(resources) == 0 {
		return append([]string(nil), fallback...), nil
	}
	if len(s.config.AllowedResources) > 0 {
		allowed := make(map[string]bool, len(s.config.AllowedResources))
		for _, resource := range s.config.AllowedResources {
			allowed[resource] = true
		}
		for _, resource := range resources {
			if !allowed[resource] {
				return nil, ErrInvalidTarget
			}
		}
	}
	return resources, nil
}
