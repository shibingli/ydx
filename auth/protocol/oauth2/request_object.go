package oauth2

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/shibingli/ydx/auth/token/jose"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
)

// defaultRequestObjectSigningAlgs are the asymmetric algorithms accepted for RFC 9101 request
// objects. Symmetric algorithms are omitted because the client's JWKS only publishes public keys.
// | defaultRequestObjectSigningAlgs 是 RFC 9101 请求对象接受的 非对称算法。省略对称算法，因为
// 客户端 JWKS 只发布公钥。
var defaultRequestObjectSigningAlgs = []string{
	"RS256", "RS384", "RS512",
	"PS256", "PS384", "PS512",
	"ES256", "ES384", "ES512",
	"EdDSA",
}

// RequestObjectConfig configures RFC 9101 signed request objects. | RequestObjectConfig 配置
// RFC 9101 已签名请求对象。
type RequestObjectConfig struct {
	// Enabled accepts the request parameter. When false the authorization endpoint returns
	// request_not_supported for a request parameter. | Enabled 接受 request 参数。为 false 时授权
	// 端点对 request 参数返回 request_not_supported。
	Enabled bool
	// SigningAlgs restricts accepted JWS algorithms; nil uses asymmetric defaults. A client's
	// registered request_object_signing_alg further narrows the allow list. | SigningAlgs 限定
	// 接受的 JWS 算法；空值使用非对称默认集。客户端注册的 request_object_signing_alg 会进一步
	// 收窄白名单。
	SigningAlgs []string
	// MaxLifetime bounds exp - iat (or exp - now when iat is absent); zero means five minutes. |
	// MaxLifetime 限定 exp - iat（缺少 iat 时为 exp - now）；零值表示 5 分钟。
	MaxLifetime time.Duration
	// Leeway is the clock tolerance applied to exp, nbf and iat. | Leeway 是应用于 exp、nbf 与 iat
	// 的时钟容差。
	Leeway time.Duration
	// Replay rejects reused jti values. It is optional; when set, request objects carrying a jti
	// are deduplicated until exp. | Replay 拒绝重复的 jti。该项可选；设置后，携带 jti 的请求对象
	// 在 exp 之前会被去重。
	Replay DPoPReplayStore
	// RequireJTI rejects request objects without jti when Replay is set. | RequireJTI 在设置
	// Replay 时拒绝缺少 jti 的请求对象。
	RequireJTI bool
}

// RequestURIConfig configures RFC 9101 by-reference request objects. | RequestURIConfig 配置
// RFC 9101 按引用传递的请求对象。
type RequestURIConfig struct {
	// Enabled accepts external request_uri values. PAR-issued request URIs remain available
	// independently of this switch. | Enabled 接受外部 request_uri。PAR 签发的 request URI 不受此
	// 开关影响。
	Enabled bool
	// RequireRegistration requires request_uri to exactly match one of the client's registered
	// request_uris values. | RequireRegistration 要求 request_uri 与客户端注册的 request_uris 之一
	// 完全匹配。
	RequireRegistration bool
	// AllowedHosts restricts external request_uri hosts when RequireRegistration is false. It must
	// be non-empty in that mode. | 当 RequireRegistration 为 false 时，AllowedHosts 限制外部
	// request_uri 主机，且必须非空。
	AllowedHosts []string
	// AllowLoopback permits loopback hosts (including plain HTTP) for development and tests. |
	// AllowLoopback 允许回环主机（包括明文 HTTP），供开发与测试使用。
	AllowLoopback bool
	// HTTPClient fetches request object URIs. Redirects are always refused. | HTTPClient 抓取请求
	// 对象 URI。始终拒绝重定向。
	HTTPClient *http.Client
	// Timeout bounds a fetch when HTTPClient is nil; zero means five seconds. | Timeout 在
	// HTTPClient 为空时限定抓取时间；零值表示 5 秒。
	Timeout time.Duration
	// MaxSize bounds the request object body; zero means one mebibyte. | MaxSize 限定请求对象正文
	// 大小；零值表示 1 MiB。
	MaxSize int64
	// MaxURILength bounds the request_uri string; zero means 2048 bytes. | MaxURILength 限定
	// request_uri 字符串长度；零值表示 2048 字节。
	MaxURILength int
	// CacheTTL caches fetched request objects; zero means five minutes and a negative value
	// disables caching. | CacheTTL 缓存已抓取的请求对象；零值表示 5 分钟，负值禁用缓存。
	CacheTTL time.Duration
	// SingleUse rejects every request_uri after its first use for CacheTTL. | SingleUse 在 CacheTTL
	// 内拒绝每个 request_uri 的再次使用。
	SingleUse bool
}

// AuthorizationResponseSigner signs a JARM authorization response. | AuthorizationResponseSigner
// 签名 JARM 授权响应。
//
// The returned compact JWT becomes the response parameter. Implementations must include iss, aud
// and exp plus every entry in params. | 返回的紧凑 JWT 会成为 response 参数。实现必须包含 iss、aud、
// exp 以及 params 中的每个条目。
type AuthorizationResponseSigner interface {
	// SignAuthorizationResponse signs params for client. | SignAuthorizationResponse 为 client 签名 params。
	SignAuthorizationResponse(ctx context.Context, issuer string, client *Client, params url.Values) (string, error)
}

// AuthorizationSigningAlgProvider optionally reports the JARM algorithms a signer supports. |
// AuthorizationSigningAlgProvider 可选地报告签名器支持的 JARM 算法。
type AuthorizationSigningAlgProvider interface {
	// AuthorizationSigningAlgValuesSupported returns the advertised JWS algorithms. |
	// AuthorizationSigningAlgValuesSupported 返回公布的 JWS 算法。
	AuthorizationSigningAlgValuesSupported() []string
}

// requestObjectVerifier verifies RFC 9101 request objects. | requestObjectVerifier 校验 RFC 9101
// 请求对象。
type requestObjectVerifier struct {
	keys   *PrivateKeyJWTVerifier
	config RequestObjectConfig
	now    func() time.Time
}

// newRequestObjectVerifier returns a verifier sharing the server clock and HTTP client. |
// newRequestObjectVerifier 返回共享服务器时钟与 HTTP 客户端的校验器。
func newRequestObjectVerifier(config RequestObjectConfig, httpClient *http.Client, now func() time.Time) *requestObjectVerifier {
	if len(config.SigningAlgs) == 0 {
		config.SigningAlgs = append([]string(nil), defaultRequestObjectSigningAlgs...)
	}
	if config.MaxLifetime <= 0 {
		config.MaxLifetime = 5 * time.Minute
	}
	if config.Leeway < 0 {
		config.Leeway = 0
	}
	if now == nil {
		now = time.Now
	}
	keys := NewPrivateKeyJWTVerifier(PrivateKeyJWTConfig{
		HTTPClient: httpClient,
		Now:        now,
		ValidAlgs:  append([]string(nil), config.SigningAlgs...),
	})
	return &requestObjectVerifier{keys: keys, config: config, now: now}
}

// verify checks the request object signature and registered claims, then returns its authorization
// parameters. | verify 校验请求对象签名与登记声明，然后返回其授权参数。
func (v *requestObjectVerifier) verify(ctx context.Context, client *Client, raw, issuer string) (url.Values, error) {
	if client == nil {
		return nil, NewError(ErrorInvalidRequestObject, "request object client is unknown | 请求对象客户端未知")
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, NewError(ErrorInvalidRequestObject, "request object is empty | 请求对象为空")
	}
	algs := append([]string(nil), v.config.SigningAlgs...)
	if client.RequestObjectSigningAlg != "" {
		if !requestObjectAlgAllowed(algs, client.RequestObjectSigningAlg) {
			return nil, NewError(ErrorInvalidRequestObject, "request object algorithm is not allowed | 不允许请求对象算法")
		}
		algs = []string{client.RequestObjectSigningAlg}
	}
	set, err := v.keys.clientKeySet(ctx, client)
	if err != nil {
		return nil, NewError(ErrorInvalidRequestObject, "request object keys are unavailable | 请求对象密钥不可用")
	}
	verified, err := jose.VerifyContext(ctx, raw, set.Resolver(), jose.VerifyOptions{
		ValidAlgs: algs,
		Leeway:    v.config.Leeway,
		Now:       v.now,
	})
	if err != nil || !verified.IsJSON() {
		return nil, NewError(ErrorInvalidRequestObject, "request object signature is invalid | 请求对象签名无效")
	}
	var claims map[string]any
	if err := json.Unmarshal(verified.Claims, &claims); err != nil {
		return nil, NewError(ErrorInvalidRequestObject, "request object payload is invalid | 请求对象载荷无效")
	}
	if err := v.validateClaims(ctx, client, claims, issuer); err != nil {
		return nil, err
	}
	params, err := requestObjectValues(claims, client.ID)
	if err != nil {
		return nil, err
	}
	return params, nil
}

// validateClaims applies the RFC 9101 registered-claim rules. | validateClaims 应用 RFC 9101
// 登记声明规则。
func (v *requestObjectVerifier) validateClaims(ctx context.Context, client *Client, claims map[string]any, issuer string) error {
	if _, ok := claims["request"]; ok {
		return NewError(ErrorInvalidRequestObject, "request object must not contain request | 请求对象不得包含 request")
	}
	if _, ok := claims["request_uri"]; ok {
		return NewError(ErrorInvalidRequestObject, "request object must not contain request_uri | 请求对象不得包含 request_uri")
	}
	claimClientID, ok := claims["client_id"].(string)
	if !ok || claimClientID == "" {
		return errs.Detail(ErrInvalidRequest, "request object client_id is required | 请求对象缺少 client_id")
	}
	if claimClientID != client.ID {
		// RFC 9101 section 5: the outer client_id and the claim must be identical, and a mismatch
		// is an RFC 6749 error, not invalid_request_object. | RFC 9101 第 5 节：外层 client_id 与
		// 声明必须一致，不匹配属于 RFC 6749 错误，而不是 invalid_request_object。
		return errs.Detail(ErrInvalidRequest, "request object client_id does not match | 请求对象 client_id 不匹配")
	}
	issuerClaim, _ := claims["iss"].(string)
	if issuerClaim == "" || issuerClaim != client.ID {
		return NewError(ErrorInvalidRequestObject, "request object iss must equal client_id | 请求对象 iss 必须等于 client_id")
	}
	audience, err := requestObjectAudience(claims["aud"])
	if err != nil || !audience.Contains(issuer) {
		return NewError(ErrorInvalidRequestObject, "request object aud does not contain the issuer | 请求对象 aud 不包含签发方")
	}
	now := v.now().UTC()
	expiry, ok := requestObjectTime(claims["exp"])
	if !ok || expiry == 0 {
		return NewError(ErrorInvalidRequestObject, "request object exp is required | 请求对象缺少 exp")
	}
	expiresAt := time.Unix(expiry, 0)
	if !now.Add(-v.config.Leeway).Before(expiresAt) {
		return NewError(ErrorInvalidRequestObject, "request object has expired | 请求对象已过期")
	}
	if expiresAt.After(now.Add(v.config.Leeway + v.config.MaxLifetime)) {
		return NewError(ErrorInvalidRequestObject, "request object lifetime is too long | 请求对象有效时长过长")
	}
	if raw, exists := claims["nbf"]; exists {
		notBefore, ok := requestObjectTime(raw)
		if !ok {
			return NewError(ErrorInvalidRequestObject, "request object nbf is invalid | 请求对象 nbf 非法")
		}
		if now.Add(v.config.Leeway).Before(time.Unix(notBefore, 0)) {
			return NewError(ErrorInvalidRequestObject, "request object is not valid yet | 请求对象尚未生效")
		}
	}
	if raw, exists := claims["iat"]; exists {
		issuedAt, ok := requestObjectTime(raw)
		if !ok {
			return NewError(ErrorInvalidRequestObject, "request object iat is invalid | 请求对象 iat 非法")
		}
		issued := time.Unix(issuedAt, 0)
		if now.Add(v.config.Leeway).Before(issued) {
			return NewError(ErrorInvalidRequestObject, "request object iat is in the future | 请求对象 iat 位于未来")
		}
		if expiresAt.Sub(issued) > v.config.MaxLifetime+v.config.Leeway {
			return NewError(ErrorInvalidRequestObject, "request object lifetime is too long | 请求对象有效时长过长")
		}
	}
	jti, hasJTI := claims["jti"]
	if hasJTI {
		value, ok := jti.(string)
		if !ok || value == "" {
			return NewError(ErrorInvalidRequestObject, "request object jti is invalid | 请求对象 jti 非法")
		}
		if v.config.Replay != nil {
			fresh, err := v.config.Replay.Accept(ctx, value, expiresAt)
			if err != nil {
				return errs.Wrap(err, ErrInvalidRequestObject)
			}
			if !fresh {
				return NewError(ErrorInvalidRequestObject, "request object replay detected | 检测到请求对象重放")
			}
		}
	} else if v.config.Replay != nil && v.config.RequireJTI {
		return NewError(ErrorInvalidRequestObject, "request object jti is required | 请求对象缺少 jti")
	}
	return nil
}

// requestObjectValues converts request object claims into authorization parameters. | requestObjectValues
// 把请求对象声明转换为授权参数。
func requestObjectValues(claims map[string]any, clientID string) (url.Values, error) {
	params := make(url.Values, len(claims))
	for name, value := range claims {
		switch name {
		case "iss", "aud", "exp", "nbf", "iat", "jti":
			// Registered JWT claims are not authorization parameters. | 登记 JWT 声明不是授权参数。
			continue
		case "client_id":
			params.Set(name, clientID)
			continue
		}
		values, err := requestObjectParamValues(value)
		if err != nil {
			return nil, NewError(ErrorInvalidRequestObject, "request object parameter is invalid | 请求对象参数非法")
		}
		for _, item := range values {
			params.Add(name, item)
		}
	}
	return params, nil
}

// requestObjectParamValues normalizes one request object parameter value. | requestObjectParamValues
// 规范化单个请求对象参数取值。
func requestObjectParamValues(value any) ([]string, error) {
	switch typed := value.(type) {
	case string:
		return []string{typed}, nil
	case float64:
		return []string{strconv.FormatFloat(typed, 'f', -1, 64)}, nil
	case json.Number:
		return []string{typed.String()}, nil
	case bool:
		return nil, errs.Detail(ErrInvalidRequestObject, "boolean request object parameter | 布尔请求对象参数")
	case []any:
		items := make([]string, 0, len(typed))
		allStrings := true
		for _, item := range typed {
			text, ok := item.(string)
			if !ok {
				allStrings = false
				break
			}
			items = append(items, text)
		}
		if allStrings {
			return items, nil
		}
		raw, err := json.Marshal(typed)
		if err != nil {
			return nil, errs.Wrap(err, ErrInvalidRequestObject)
		}
		return []string{string(raw)}, nil
	case map[string]any:
		raw, err := json.Marshal(typed)
		if err != nil {
			return nil, errs.Wrap(err, ErrInvalidRequestObject)
		}
		return []string{string(raw)}, nil
	default:
		return nil, errs.Detail(ErrInvalidRequestObject, "unsupported request object parameter type | 不支持的请求对象参数类型")
	}
}

// requestObjectAudience normalizes an aud claim. | requestObjectAudience 规范化 aud 声明。
func requestObjectAudience(value any) (audienceClaim, error) {
	switch typed := value.(type) {
	case string:
		return audienceClaim{typed}, nil
	case []any:
		out := make(audienceClaim, 0, len(typed))
		for _, item := range typed {
			text, ok := item.(string)
			if !ok {
				return nil, errs.Detail(ErrInvalidRequestObject, "aud contains a non-string value | aud 包含非字符串值")
			}
			out = append(out, text)
		}
		return out, nil
	case []string:
		return audienceClaim(typed), nil
	default:
		return nil, errs.Detail(ErrInvalidRequestObject, "aud is invalid | aud 非法")
	}
}

// requestObjectTime reads a numeric JWT time claim. | requestObjectTime 读取数值型 JWT 时间声明。
func requestObjectTime(value any) (int64, bool) {
	switch typed := value.(type) {
	case float64:
		return int64(typed), typed == float64(int64(typed))
	case json.Number:
		n, err := typed.Int64()
		return n, err == nil
	case int64:
		return typed, true
	case int:
		return int64(typed), true
	default:
		return 0, false
	}
}

// requestObjectAlgAllowed reports whether algs contains alg. | requestObjectAlgAllowed 报告 algs 是否包含 alg。
func requestObjectAlgAllowed(algs []string, alg string) bool {
	for _, candidate := range algs {
		if candidate == alg {
			return true
		}
	}
	return false
}
