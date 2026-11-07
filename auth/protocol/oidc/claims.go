package oidc

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"hash"
	"strings"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/auth/token/jose"
	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
)

// IDTokenVerifyOptions configures ID token verification. | IDTokenVerifyOptions 配置 ID 令牌校验。
type IDTokenVerifyOptions struct {
	// Issuer is the required iss value. | Issuer 是必需的 iss 取值。
	Issuer string
	// Audience is the required client_id contained in aud. | Audience 是 aud 中必需的 client_id。
	Audience string
	// Nonce, when non-empty, must match the nonce claim in constant time. | Nonce 非空时必须与 nonce 声明常量时间匹配。
	Nonce string
	// AccessToken, when non-empty, must match at_hash. | AccessToken 非空时必须匹配 at_hash。
	AccessToken string
	// Code, when non-empty, must match c_hash. | Code 非空时必须匹配 c_hash。
	Code string
	// MaxAge, when positive, requires auth_time within the window. | MaxAge 为正时要求 auth_time 在窗口内。
	MaxAge time.Duration
	// Leeway is the clock tolerance. | Leeway 是时钟容差。
	Leeway time.Duration
	// Now overrides the clock. | Now 替换时钟。
	Now func() time.Time
	// ValidAlgs restricts accepted JWS algorithms. | ValidAlgs 限定可接受的 JWS 算法。
	ValidAlgs []string
	// AllowHMAC permits HSxxx ID tokens; it is unsafe for public clients and off by default. | AllowHMAC 允许 HSxxx ID 令牌；对公共客户端不安全，默认关闭。
	AllowHMAC bool
}

// VerifyIDToken verifies the signature and claims of a compact ID token. | VerifyIDToken 校验紧凑 ID 令牌的签名与声明。
func VerifyIDToken(ctx context.Context, raw string, resolver jose.KeyResolver, opts IDTokenVerifyOptions) (*IDToken, error) {
	if resolver == nil {
		return nil, errs.Detail(ErrInvalidConfig, "nil key resolver | 密钥解析器为空")
	}
	if opts.Issuer == "" || opts.Audience == "" {
		return nil, errs.Detail(ErrInvalidConfig, "issuer and audience are required | issuer 与 audience 必填")
	}
	algs := opts.ValidAlgs
	if len(algs) == 0 {
		algs = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}
		if opts.AllowHMAC {
			algs = append(algs, "HS256", "HS384", "HS512")
		}
	}
	verified, err := jose.VerifyContext(ctx, raw, resolver, jose.VerifyOptions{
		ValidAlgs: algs,
		Leeway:    opts.Leeway,
		Now:       opts.Now,
	})
	if err != nil {
		return nil, errs.Wrap(err, ErrInvalidToken)
	}
	if !verified.IsJSON() {
		return nil, errs.Detail(ErrInvalidToken, "payload is not a JSON object | 载荷不是 JSON 对象")
	}
	var claims Claims
	if err := json.Unmarshal(verified.Claims, &claims); err != nil {
		return nil, errs.Wrap(err, ErrInvalidToken)
	}
	rawClaims := make(map[string]any)
	if err := json.Unmarshal(verified.Claims, &rawClaims); err != nil {
		return nil, errs.Wrap(err, ErrInvalidToken)
	}
	claims.Extra = extraClaims(rawClaims)
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	at := now().UTC()
	leeway := opts.Leeway
	if claims.Issuer == "" || claims.Issuer != opts.Issuer {
		return nil, errs.Detail(ErrInvalidIssuer, "iss=%[1]q want %[2]q | iss=%[1]q 期望 %[2]q", claims.Issuer, opts.Issuer)
	}
	if claims.Subject == "" {
		return nil, errs.Detail(ErrInvalidToken, "sub is missing | 缺少 sub")
	}
	if !claims.Audience.Contains(opts.Audience) {
		return nil, errs.Detail(ErrInvalidAudience, "aud does not contain %[1]q | aud 不包含 %[1]q", opts.Audience)
	}
	if len(claims.Audience) > 1 {
		if claims.AZP == "" || claims.AZP != opts.Audience {
			return nil, errs.Detail(ErrInvalidAudience, "azp must equal the client id for multiple audiences | 多受众时 azp 必须等于客户端标识")
		}
	} else if claims.AZP != "" && claims.AZP != opts.Audience {
		return nil, errs.Detail(ErrInvalidAudience, "azp mismatch | azp 不匹配")
	}
	if claims.Expiry == 0 {
		return nil, errs.Detail(ErrInvalidToken, "exp is missing | 缺少 exp")
	}
	if claims.IssuedAt == 0 {
		// OpenID Connect Core section 2 requires iat in every ID token. | OpenID Connect Core
		// 第 2 节要求每个 ID 令牌都携带 iat。
		return nil, errs.Detail(ErrInvalidToken, "iat is missing | 缺少 iat")
	}
	if at.Add(-leeway).After(time.Unix(claims.Expiry, 0).UTC()) {
		return nil, ErrTokenExpired
	}
	if claims.NotBefore != 0 && at.Add(leeway).Before(time.Unix(claims.NotBefore, 0).UTC()) {
		return nil, ErrTokenNotYetValid
	}
	if at.Add(leeway).Before(time.Unix(claims.IssuedAt, 0).UTC()) {
		return nil, errs.Detail(ErrInvalidToken, "iat is in the future | iat 位于未来")
	}
	if opts.Nonce != "" {
		if subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(opts.Nonce)) != 1 {
			return nil, ErrInvalidNonce
		}
	}
	if opts.MaxAge > 0 {
		if claims.AuthTime == 0 {
			return nil, errs.Detail(ErrInvalidToken, "auth_time is required with max_age | max_age 要求 auth_time")
		}
		if at.Add(-leeway).After(time.Unix(claims.AuthTime, 0).UTC().Add(opts.MaxAge)) {
			return nil, errs.Detail(ErrInvalidToken, "authentication is older than max_age | 认证时间超过 max_age")
		}
	}
	alg := verified.Header.Alg
	token := &IDToken{Claims: claims, Raw: rawClaims, Header: verified.RawHeader, RawToken: raw}
	if opts.AccessToken != "" {
		// When the caller supplies the access token issued alongside the ID token, at_hash is
		// mandatory: an ID token that omits it is not bound to that access token. | 调用方提供了与
		// ID 令牌一同签发的访问令牌时，at_hash 是必需的：省略它意味着 ID 令牌没有绑定该访问令牌。
		if claims.AccessTokenHash == "" {
			return nil, errs.Detail(ErrInvalidAtHash, "at_hash is missing | 缺少 at_hash")
		}
		want, err := halfHash(alg, opts.AccessToken)
		if err != nil {
			return nil, err
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(claims.AccessTokenHash)) != 1 {
			return nil, ErrInvalidAtHash
		}
	}
	if opts.Code != "" {
		// c_hash is equally mandatory for the authorization-code flow. | 授权码流程同样强制要求 c_hash。
		if claims.CodeHash == "" {
			return nil, errs.Detail(ErrInvalidCHash, "c_hash is missing | 缺少 c_hash")
		}
		want, err := halfHash(alg, opts.Code)
		if err != nil {
			return nil, err
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(claims.CodeHash)) != 1 {
			return nil, ErrInvalidCHash
		}
	}
	return token, nil
}

// halfHash returns the base64url left-half hash used by at_hash and c_hash. | halfHash 返回 at_hash
// 与 c_hash 使用的 base64url 左半哈希。
func halfHash(alg, value string) (string, error) {
	var h hash.Hash
	switch strings.ToUpper(alg) {
	case "RS256", "PS256", "ES256", "HS256", "EDDSA":
		h = sha256.New()
	case "RS384", "PS384", "ES384", "HS384":
		h = sha512.New384()
	case "RS512", "PS512", "ES512", "HS512":
		h = sha512.New()
	default:
		return "", errs.Detail(ErrInvalidToken, "unsupported alg %[1]q for at_hash | 不支持 alg %[1]q 的 at_hash", alg)
	}
	h.Write([]byte(value))
	sum := h.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2]), nil
}

// ValidateAccessTokenHash reports whether accessToken matches the ID token at_hash. | ValidateAccessTokenHash
// 报告 accessToken 是否匹配 ID 令牌 at_hash。
func (t *IDToken) ValidateAccessTokenHash(accessToken string) error {
	if t == nil || t.Claims.AccessTokenHash == "" {
		return errs.Detail(ErrInvalidAtHash, "at_hash is missing | 缺少 at_hash")
	}
	alg, _ := t.Header["alg"].(string)
	want, err := halfHash(alg, accessToken)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(want), []byte(t.Claims.AccessTokenHash)) != 1 {
		return ErrInvalidAtHash
	}
	return nil
}

// ValidateCodeHash reports whether code matches the ID token c_hash. | ValidateCodeHash 报告 code
// 是否匹配 ID 令牌 c_hash。
func (t *IDToken) ValidateCodeHash(code string) error {
	if t == nil || t.Claims.CodeHash == "" {
		return errs.Detail(ErrInvalidCHash, "c_hash is missing | 缺少 c_hash")
	}
	alg, _ := t.Header["alg"].(string)
	want, err := halfHash(alg, code)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(want), []byte(t.Claims.CodeHash)) != 1 {
		return ErrInvalidCHash
	}
	return nil
}

// extraClaims returns the non-standard claims from raw. | extraClaims 返回 raw 中的非标准声明。
func extraClaims(raw map[string]any) map[string]any {
	if len(raw) == 0 {
		return nil
	}
	known := map[string]bool{
		"iss": true, "sub": true, "aud": true, "exp": true, "iat": true, "nbf": true,
		"nonce": true, "auth_time": true, "acr": true, "amr": true, "azp": true,
		"jti": true, "sid": true, "at_hash": true, "c_hash": true, "s_hash": true,
		"name": true, "given_name": true, "family_name": true, "middle_name": true,
		"nickname": true, "preferred_username": true, "profile": true, "picture": true,
		"website": true, "gender": true, "birthdate": true, "zoneinfo": true,
		"locale": true, "updated_at": true, "email": true, "email_verified": true,
		"phone_number": true, "phone_number_verified": true, "address": true,
	}
	out := make(map[string]any)
	for key, value := range raw {
		if !known[key] {
			out[key] = value
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// claimsFromPrincipal builds standard claims from a principal. | claimsFromPrincipal 从主体构建标准声明。
func claimsFromPrincipal(principal *auth.Principal, scopes []string) *Claims {
	if principal == nil {
		return &Claims{}
	}
	claims := &Claims{
		Subject:           principal.Subject,
		Name:              principal.DisplayName,
		PreferredUsername: principal.Username,
		Email:             principal.Email,
		AMR:               append([]string(nil), principal.AMR...),
		ACR:               principal.ACR,
	}
	if principal.Email != "" {
		verified := principal.EmailVerified
		claims.EmailVerified = &verified
	}
	if !principal.AuthTime.IsZero() {
		claims.AuthTime = principal.AuthTime.Unix()
	}
	if principal.Attributes != nil {
		if value := principal.Attributes["given_name"]; value != "" {
			claims.GivenName = value
		}
		if value := principal.Attributes["family_name"]; value != "" {
			claims.FamilyName = value
		}
		if value := principal.Attributes["picture"]; value != "" {
			claims.Picture = value
		}
		if value := principal.Attributes["locale"]; value != "" {
			claims.Locale = value
		}
		if value := principal.Attributes["zoneinfo"]; value != "" {
			claims.Zoneinfo = value
		}
		if value := principal.Attributes["phone_number"]; value != "" {
			claims.PhoneNumber = value
		}
		if value := principal.Attributes["phone_number_verified"]; value == "true" {
			verified := true
			claims.PhoneNumberVerified = &verified
		}
	}
	_ = scopes
	return claims
}
