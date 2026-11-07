package oidc

import (
	"context"
	"net/url"
	"strconv"
	"time"

	"github.com/shibingli/ydx/auth/protocol/oauth2"
	"github.com/shibingli/ydx/auth/token/jose"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
)

// jarmResponseTTL is the maximum lifetime of an authorization response JWT. JARM recommends a
// value no greater than ten minutes. | jarmResponseTTL 是授权响应 JWT 的最长寿命。JARM 建议不超过
// 10 分钟。
const jarmResponseTTL = 5 * time.Minute

// SignAuthorizationResponse signs a JARM authorization response for client. | SignAuthorizationResponse
// 为 client 签名 JARM 授权响应。
//
// The JWT carries iss, aud, exp and iat plus every parameter in params. The client's registered
// authorization_signed_response_alg selects the algorithm; otherwise RS256 is used, falling back to
// the provider signing algorithm when the key set has no RSA signing key. | JWT 携带 iss、aud、exp、
// iat 以及 params 中的每个参数。客户端注册的 authorization_signed_response_alg 选择算法；未注册时
// 使用 RS256，密钥集没有 RSA 签名密钥时回退到提供方签名算法。
func (p *Provider) SignAuthorizationResponse(_ context.Context, issuer string, client *oauth2.Client, params url.Values) (string, error) {
	if client == nil {
		return "", errs.Detail(ErrInvalidConfig, "JARM response needs a client | JARM 响应需要客户端")
	}
	alg := client.AuthorizationSignedResponseAlg
	if alg == "none" {
		// JARM forbids an unsigned authorization response even if registration requested it. |
		// 即使注册请求了无签名授权响应，JARM 也禁止该算法。
		return "", errs.Detail(ErrInvalidConfig, "JARM must not use alg none | JARM 不得使用 none 算法")
	}
	if alg == "" {
		alg = "RS256"
	}
	key, err := p.signingKeyFor(alg)
	if err != nil && client.AuthorizationSignedResponseAlg == "" && p.signingAlg != "" {
		// The provider may only hold a non-RSA signing key; use its configured algorithm rather
		// than failing every default JARM response. | 提供方可能只持有非 RSA 签名密钥；此时使用其
		// 配置算法，而不是让所有默认 JARM 响应失败。
		alg = p.signingAlg
		key, err = p.signingKeyFor(alg)
	}
	if err != nil {
		return "", errs.Wrap(err, ErrInvalidConfig)
	}
	if alg == "" {
		return "", errs.Detail(ErrInvalidConfig, "JARM signing algorithm is empty | JARM 签名算法为空")
	}
	now := p.Now()
	claims := make(map[string]any, len(params)+4)
	for name, values := range params {
		if len(values) == 0 {
			continue
		}
		if name == "expires_in" {
			if seconds, convErr := strconv.ParseInt(values[0], 10, 64); convErr == nil {
				claims[name] = seconds
				continue
			}
		}
		claims[name] = values[0]
	}
	if issuer == "" {
		issuer = p.config.Issuer
	}
	claims["iss"] = issuer
	claims["aud"] = client.ID
	claims["exp"] = now.Add(jarmResponseTTL).Unix()
	claims["iat"] = now.Unix()
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", errs.Wrap(err, ErrInvalidConfig)
	}
	signed, err := jose.Sign(payload, key, jose.SignOptions{
		Alg: alg,
		Kid: key.Kid,
		Typ: "JWT",
	})
	if err != nil {
		return "", errs.Wrap(err, ErrInvalidConfig)
	}
	return signed, nil
}

// AuthorizationSigningAlgValuesSupported returns the JARM algorithms this provider can sign. |
// AuthorizationSigningAlgValuesSupported 返回此提供方可签名的 JARM 算法。
func (p *Provider) AuthorizationSigningAlgValuesSupported() []string {
	algs := p.signingAlgs()
	out := make([]string, 0, len(algs))
	for _, alg := range algs {
		if alg == "" || alg == "none" {
			continue
		}
		out = append(out, alg)
	}
	return out
}
