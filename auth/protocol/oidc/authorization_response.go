package oidc

import (
	"context"
	"net/url"
	"strconv"
	"strings"

	"github.com/shibingli/ydx/auth/token/jose"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
)

// AuthorizationResponse is a parsed authorization response. | AuthorizationResponse 是已解析的授权响应。
type AuthorizationResponse struct {
	// Params are the response parameters, either taken from the JWT or the outer values. | Params
	// 是响应参数，取自 JWT 或外层取值。
	Params url.Values
	// JWT is the compact JARM response JWT, empty for an unsigned response. | JWT 是紧凑 JARM
	// 响应 JWT，无签名响应时为空。
	JWT string
	// Signed reports whether a JARM response JWT was present and verified. | Signed 报告是否携带并
	// 校验了 JARM 响应 JWT。
	Signed bool
}

// Param returns the first value of name. | Param 返回 name 的第一个取值。
func (r *AuthorizationResponse) Param(name string) string {
	if r == nil || r.Params == nil {
		return ""
	}
	return r.Params.Get(name)
}

// ParseAuthorizationResponse parses an unsigned or JARM authorization response. | ParseAuthorizationResponse
// 解析无签名或 JARM 授权响应。
//
// For a JARM response the JWT signature is verified against the provider JWKS, and iss, aud and exp
// must match the discovery issuer, the registered client and the current clock. The outer encoding
// must carry only the response parameter. | 对 JARM 响应，使用提供方 JWKS 校验 JWT 签名，且 iss、
// aud 与 exp 必须匹配发现文档签发方、已注册客户端与当前时钟。外层编码只能携带 response 参数。
func (rp *RelyingParty) ParseAuthorizationResponse(ctx context.Context, values url.Values) (*AuthorizationResponse, error) {
	if values == nil {
		return nil, errs.Detail(ErrInvalidRequest, "authorization response is empty | 授权响应为空")
	}
	rawJWT := values.Get("response")
	if rawJWT == "" {
		return &AuthorizationResponse{Params: cloneRPValues(values)}, nil
	}
	if len(values["response"]) != 1 || len(values) != 1 {
		// JARM section 2.4 puts every parameter inside the JWT; an outer parameter next to the
		// signed response would be unauthenticated. | JARM 第 2.4 节把全部参数放入 JWT；在已签名
		// 响应之外携带外层参数会使该参数失去认证保护。
		return nil, errs.Detail(ErrInvalidRequest, "JARM response must not carry outer parameters | JARM 响应不得携带外层参数")
	}
	opts := jose.VerifyOptions{
		ValidAlgs:      append([]string(nil), rp.discovery.AuthorizationSigningAlgValuesSupported...),
		Leeway:         rp.config.Leeway,
		Now:            rp.config.Now,
		ValidateClaims: true,
		RequireExp:     true,
		Issuer:         rp.discovery.Issuer,
		Audience:       rp.config.ClientID,
	}
	verified, err := jose.VerifyContext(ctx, rawJWT, rp.resolver(), opts)
	if err != nil {
		return nil, errs.Wrap(err, ErrInvalidToken)
	}
	var claims map[string]any
	if err := json.Unmarshal(verified.Claims, &claims); err != nil {
		return nil, errs.Wrap(err, ErrInvalidToken)
	}
	params := make(url.Values, len(claims))
	for name, value := range claims {
		switch name {
		case "aud", "exp", "iat", "nbf", "jti":
			continue
		}
		text, ok := authorizationResponseValue(value)
		if !ok {
			return nil, errs.Detail(ErrInvalidToken, "JARM claim %[1]q has an unsupported type | JARM 声明 %[1]q 类型不受支持", name)
		}
		params.Set(name, text)
	}
	return &AuthorizationResponse{Params: params, JWT: rawJWT, Signed: true}, nil
}

// authorizationResponseValue renders one JARM claim as a response parameter. | authorizationResponseValue
// 把一个 JARM 声明渲染为响应参数。
func authorizationResponseValue(value any) (string, bool) {
	switch typed := value.(type) {
	case string:
		return typed, true
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64), true
	case json.Number:
		return typed.String(), true
	case bool:
		return strconv.FormatBool(typed), true
	case []any:
		items := make([]string, 0, len(typed))
		for _, item := range typed {
			text, ok := authorizationResponseValue(item)
			if !ok {
				return "", false
			}
			items = append(items, text)
		}
		return strings.Join(items, " "), true
	default:
		return "", false
	}
}

// cloneRPValues copies url.Values. | cloneRPValues 复制 url.Values。
func cloneRPValues(values url.Values) url.Values {
	out := make(url.Values, len(values))
	for key, items := range values {
		out[key] = append([]string(nil), items...)
	}
	return out
}
