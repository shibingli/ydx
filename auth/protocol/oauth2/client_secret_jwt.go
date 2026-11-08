package oauth2

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/auth/token/jose"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
)

// The declared client-assertion sentinels. Every verification failure also wraps
// ErrInvalidClient so HTTP handlers answer invalid_client without leaking the internal
// classification. | 客户端断言哨兵错误。每个校验失败同时包装 ErrInvalidClient，使 HTTP 处理器返回
// invalid_client 而不泄露内部分类。
var (
	// ErrClientSecretJWTDisabled reports that client_secret_jwt has no configured verifier. |
	// ErrClientSecretJWTDisabled 表示 client_secret_jwt 未配置校验器。
	ErrClientSecretJWTDisabled = errs.New("oauth2: client_secret_jwt is not enabled | oauth2：未启用 client_secret_jwt")
	// ErrClientSecretUnavailable reports that the deployment could not supply the client's secret. |
	// ErrClientSecretUnavailable 表示部署无法提供客户端密钥。
	ErrClientSecretUnavailable = errs.New("oauth2: client secret is unavailable | oauth2：客户端密钥不可用")
	// ErrInvalidClientAssertion reports a malformed, mismatched or unverifiable client assertion. |
	// ErrInvalidClientAssertion 表示客户端断言格式非法、取值不匹配或无法校验。
	ErrInvalidClientAssertion = errs.New("oauth2: invalid client assertion | oauth2：客户端断言无效")
	// ErrClientAssertionReplay reports a client assertion whose jti was already accepted. |
	// ErrClientAssertionReplay 表示客户端断言的 jti 已被接受过。
	ErrClientAssertionReplay = errs.New("oauth2: client assertion replay | oauth2：客户端断言重放")
)

// ClientSecretResolver returns the plaintext secret of a registered client so that a
// client_secret_jwt assertion can be verified. Client.SecretHash only stores a one-way hash and
// cannot verify an HMAC, so the deployment must source the plaintext from a secret manager or an
// equivalent trusted store. Implementations must be concurrency-safe. |
// ClientSecretResolver 返回已注册客户端的明文密钥，用于校验 client_secret_jwt 断言。
// Client.SecretHash 只保存单向哈希，无法校验 HMAC，因此部署必须从密钥管理器或等效的可信存储取得
// 明文。实现必须并发安全。
type ClientSecretResolver interface {
	// ClientSecret returns the plaintext secret for client. | ClientSecret 返回 client 的明文密钥。
	ClientSecret(ctx context.Context, client *Client) (string, error)
}

// ClientSecretResolverFunc adapts a function to ClientSecretResolver. | ClientSecretResolverFunc 把函数适配为 ClientSecretResolver。
type ClientSecretResolverFunc func(ctx context.Context, client *Client) (string, error)

// ClientSecret calls f. | ClientSecret 调用 f。
func (f ClientSecretResolverFunc) ClientSecret(ctx context.Context, client *Client) (string, error) {
	return f(ctx, client)
}

// ClientSecretRegistrar records a secret issued by dynamic registration so the configured
// ClientSecretResolver can return it later. Implementations must persist the value in a secret
// manager or another trusted store; the client store itself intentionally keeps only a hash. |
// ClientSecretRegistrar 记录动态注册签发的密钥，使已配置的 ClientSecretResolver 之后能返回它。
// 实现必须把该值保存到密钥管理器或其它可信存储；客户端存储本身有意只保留哈希。
type ClientSecretRegistrar interface {
	// RegisterClientSecret stores secret for clientID. | RegisterClientSecret 为 clientID 保存 secret。
	RegisterClientSecret(ctx context.Context, clientID, secret string) error
}

// ClientSecretRegistrarFunc adapts a function to ClientSecretRegistrar. | ClientSecretRegistrarFunc 把函数适配为 ClientSecretRegistrar。
type ClientSecretRegistrarFunc func(ctx context.Context, clientID, secret string) error

// RegisterClientSecret calls f. | RegisterClientSecret 调用 f。
func (f ClientSecretRegistrarFunc) RegisterClientSecret(ctx context.Context, clientID, secret string) error {
	return f(ctx, clientID, secret)
}

// ClientSecretJWTConfig configures RFC 7523 client_secret_jwt authentication. A non-nil
// ServerConfig.ClientSecretJWT enables the method; a nil value keeps it rejected. |
// ClientSecretJWTConfig 配置 RFC 7523 client_secret_jwt 认证。ServerConfig.ClientSecretJWT 非空时
// 启用该方法；空值继续拒绝。
type ClientSecretJWTConfig struct {
	// Resolver supplies plaintext client secrets; it is required. | Resolver 提供客户端明文密钥；必填。
	Resolver ClientSecretResolver
	// Registrar receives secrets issued by dynamic registration. When nil, registration using
	// client_secret_jwt is refused because no resolver could learn the issued secret; clients
	// must be preconfigured instead. | Registrar 接收动态注册签发的密钥。为空时拒绝使用
	// client_secret_jwt 的注册，因为解析器无法获知签发的密钥；此时必须预配置客户端。
	Registrar ClientSecretRegistrar
	// Replay rejects reused jti values; nil uses a fresh memory store. | Replay 拒绝重复 jti；
	// 空值使用新的内存存储。
	Replay DPoPReplayStore
	// Now overrides the clock. | Now 替换时钟。
	Now func() time.Time
	// Leeway is the clock tolerance. | Leeway 是时钟容差。
	Leeway time.Duration
	// MaxLifetime bounds the assertion validity period; zero means five minutes. | MaxLifetime
	// 限定断言有效时长；零值表示 5 分钟。
	MaxLifetime time.Duration
	// ValidAlgs restricts assertion algorithms to HS256, HS384 and/or HS512; nil accepts all
	// three. Any other algorithm is a configuration error. | ValidAlgs 把断言算法限定为 HS256、
	// HS384 与/或 HS512；空值接受全部三种。其它算法属于配置错误。
	ValidAlgs []string
}

// ClientSecretJWTVerifier verifies RFC 7523 client_secret_jwt assertions with HS256, HS384 or
// HS512. It implements ClientAssertionVerifier and is installed through
// ServerConfig.ClientSecretJWT. | ClientSecretJWTVerifier 使用 HS256、HS384 或 HS512 校验 RFC 7523
// client_secret_jwt 断言。它实现 ClientAssertionVerifier，并经 ServerConfig.ClientSecretJWT 安装。
type ClientSecretJWTVerifier struct {
	config    ClientSecretJWTConfig
	replay    DPoPReplayStore
	validAlgs []string
}

// NewClientSecretJWTVerifier returns a client_secret_jwt verifier. | NewClientSecretJWTVerifier 返回
// client_secret_jwt 校验器。
func NewClientSecretJWTVerifier(config ClientSecretJWTConfig) (*ClientSecretJWTVerifier, error) {
	if config.Resolver == nil {
		return nil, errs.Detail(ErrInvalidConfig, "client_secret_jwt needs a secret resolver | client_secret_jwt 需要密钥解析器")
	}
	algs := config.ValidAlgs
	if len(algs) == 0 {
		algs = []string{"HS256", "HS384", "HS512"}
	}
	accepted := make([]string, 0, len(algs))
	seen := make(map[string]bool, len(algs))
	for _, alg := range algs {
		if !isHMACJWSAlg(alg) {
			return nil, errs.Detail(ErrInvalidConfig, "client_secret_jwt algorithm %[1]q must be HS256, HS384 or HS512 | client_secret_jwt 算法 %[1]q 必须是 HS256、HS384 或 HS512", alg)
		}
		if seen[alg] {
			continue
		}
		seen[alg] = true
		accepted = append(accepted, alg)
	}
	if len(accepted) == 0 {
		return nil, errs.Detail(ErrInvalidConfig, "client_secret_jwt has no accepted algorithm | client_secret_jwt 没有可接受的算法")
	}
	if config.Replay == nil {
		store := NewMemoryDPoPReplayStore()
		// The default store must share the verifier clock; otherwise a fixed deployment clock
		// would let it prune every entry as expired and accept replayed jti values. | 默认存储必须
		// 与校验器共用时钟；否则固定部署时钟会让它把每个条目视为已过期并接受重放的 jti。
		if config.Now != nil {
			store.now = config.Now
		}
		config.Replay = store
	}
	if config.MaxLifetime <= 0 {
		config.MaxLifetime = 5 * time.Minute
	}
	config.ValidAlgs = append([]string(nil), accepted...)
	return &ClientSecretJWTVerifier{config: config, replay: config.Replay, validAlgs: accepted}, nil
}

// SigningAlgs returns the accepted client_secret_jwt signing algorithms. | SigningAlgs 返回接受的
// client_secret_jwt 签名算法。
func (v *ClientSecretJWTVerifier) SigningAlgs() []string {
	if v == nil {
		return nil
	}
	return append([]string(nil), v.validAlgs...)
}

// VerifyClientAssertion verifies an HS256, HS384 or HS512 assertion for client at audience. It
// checks the signature in constant time through crypto/hmac, requires iss and sub to equal the
// client identifier, requires aud to contain audience, enforces exp, nbf, iat and the maximum
// lifetime, and rejects a reused jti. | VerifyClientAssertion 在 audience 处为 client 校验
// HS256、HS384 或 HS512 断言。它通过 crypto/hmac 以常量时间校验签名，要求 iss 与 sub 等于客户端
// 标识、aud 包含 audience，强制 exp、nbf、iat 与最大有效时长，并拒绝重复的 jti。
func (v *ClientSecretJWTVerifier) VerifyClientAssertion(ctx context.Context, client *Client, assertion, audience string) error {
	if v == nil || v.config.Resolver == nil {
		return errs.Wrap(errs.Detail(ErrClientSecretJWTDisabled, "client_secret_jwt verifier is not configured | 未配置 client_secret_jwt 校验器"), ErrInvalidClient)
	}
	if client == nil {
		return errs.Detail(ErrInvalidClient, "client is nil | 客户端为空")
	}
	if registeredAuthMethod(client) != ClientSecretJWT {
		return invalidClientAssertion("client %[1]q is not registered for client_secret_jwt | 客户端 %[1]q 未注册 client_secret_jwt", client.ID)
	}
	if strings.TrimSpace(assertion) == "" {
		return invalidClientAssertion("client assertion is empty | 客户端断言为空")
	}
	secret, err := v.config.Resolver.ClientSecret(ctx, client)
	if err != nil {
		return errs.Wrap(errs.WrapDetail(err, ErrClientSecretUnavailable, "client %[1]q secret lookup failed | 客户端 %[1]q 密钥查询失败", client.ID), ErrInvalidClient)
	}
	if secret == "" {
		return errs.Wrap(errs.Detail(ErrClientSecretUnavailable, "client %[1]q has no resolvable secret | 客户端 %[1]q 没有可解析的密钥", client.ID), ErrInvalidClient)
	}
	// A registered hash pins the resolver result to the secret this client was issued. Clients
	// that predate client_secret_jwt may have no hash; the resolver is then the only source. |
	// 已注册的哈希把解析结果固定到签发给该客户端的密钥。早于 client_secret_jwt 的客户端可能没有
	// 哈希，此时解析器是唯一来源。
	if client.SecretHash != "" && !auth.TokenHashMatches(client.SecretHash, secret) {
		return errs.Wrap(errs.Detail(ErrClientSecretUnavailable, "resolved secret does not match the registered secret | 解析出的密钥与已注册密钥不匹配"), ErrInvalidClient)
	}
	validAlgs := v.validAlgs
	if registered := strings.TrimSpace(client.TokenEndpointAuthSigningAlg); registered != "" {
		if !isHMACJWSAlg(registered) {
			return invalidClientAssertion("registered token_endpoint_auth_signing_alg %[1]q is not an HS algorithm | 注册的 token_endpoint_auth_signing_alg %[1]q 不是 HS 算法", registered)
		}
		if !containsAlg(v.validAlgs, registered) {
			return invalidClientAssertion("registered token_endpoint_auth_signing_alg %[1]q is disabled by server configuration | 注册的 token_endpoint_auth_signing_alg %[1]q 被服务器配置禁用", registered)
		}
		validAlgs = []string{registered}
	}
	key, err := jose.FromHMAC("", []byte(secret))
	if err != nil {
		return errs.WrapDetail(err, ErrInvalidClient, "client secret cannot form an HMAC key | 客户端密钥无法构成 HMAC 密钥")
	}
	now := time.Now
	if v.config.Now != nil {
		now = v.config.Now
	}
	verified, err := jose.VerifyContext(ctx, assertion, jose.KeyResolverFunc(func(context.Context, jose.Header) (*jose.Key, error) {
		return key, nil
	}), jose.VerifyOptions{
		ValidAlgs: validAlgs,
		Leeway:    v.config.Leeway,
		Now:       now,
	})
	if err != nil {
		if isAlgNotAllowed(err) {
			return errs.Wrap(errs.WrapDetail(err, ErrInvalidClientAssertion, "assertion alg is not allowed for client_secret_jwt | 断言 alg 不被 client_secret_jwt 允许"), ErrInvalidClient)
		}
		return errs.Wrap(errs.WrapDetail(err, ErrInvalidClientAssertion, "assertion signature is invalid | 断言签名无效"), ErrInvalidClient)
	}
	var claims struct {
		Issuer    string        `json:"iss"`
		Subject   string        `json:"sub"`
		Audience  audienceClaim `json:"aud"`
		Expiry    int64         `json:"exp"`
		NotBefore int64         `json:"nbf"`
		IssuedAt  int64         `json:"iat"`
		JTI       string        `json:"jti"`
	}
	if err := json.Unmarshal(verified.Payload, &claims); err != nil {
		return errs.Wrap(errs.WrapDetail(err, ErrInvalidClientAssertion, "assertion payload is not a JSON object | 断言载荷不是 JSON 对象"), ErrInvalidClient)
	}
	if claims.Issuer != client.ID {
		return invalidClientAssertion("assertion iss does not equal the client id | 断言 iss 不等于客户端标识")
	}
	if claims.Subject != client.ID {
		return invalidClientAssertion("assertion sub does not equal the client id | 断言 sub 不等于客户端标识")
	}
	if audience != "" && !claims.Audience.Contains(audience) {
		return invalidClientAssertion("assertion audience does not match %[1]q | 断言受众不匹配 %[1]q", audience)
	}
	if claims.Expiry == 0 {
		return invalidClientAssertion("assertion exp is missing | 断言缺少 exp")
	}
	at := now().UTC()
	expiry := time.Unix(claims.Expiry, 0)
	if at.Add(v.config.Leeway).After(expiry) {
		return invalidClientAssertion("assertion expired | 断言已过期")
	}
	if expiry.After(at.Add(v.config.MaxLifetime + v.config.Leeway)) {
		return invalidClientAssertion("assertion lifetime is too long | 断言有效时长过长")
	}
	if claims.NotBefore != 0 {
		if at.Add(v.config.Leeway).Before(time.Unix(claims.NotBefore, 0)) {
			return invalidClientAssertion("assertion nbf is in the future | 断言 nbf 位于未来")
		}
	}
	if claims.IssuedAt != 0 {
		issuedAt := time.Unix(claims.IssuedAt, 0)
		if at.Add(v.config.Leeway).Before(issuedAt) {
			return invalidClientAssertion("assertion iat is in the future | 断言 iat 位于未来")
		}
		if expiry.Sub(issuedAt) > v.config.MaxLifetime {
			return invalidClientAssertion("assertion lifetime is too long | 断言有效时长过长")
		}
	}
	if claims.JTI == "" {
		return invalidClientAssertion("assertion jti is missing | 断言缺少 jti")
	}
	fresh, err := v.replay.Accept(ctx, claims.JTI, expiry)
	if err != nil {
		return errs.WrapDetail(err, ErrInvalidClient, "assertion replay store failed | 断言重放存储失败")
	}
	if !fresh {
		return errs.Wrap(errs.Detail(ErrClientAssertionReplay, "assertion jti was already accepted | 断言 jti 已被接受"), ErrInvalidClient)
	}
	return nil
}

// invalidClientAssertion attaches detail to both ErrInvalidClientAssertion and ErrInvalidClient. |
// invalidClientAssertion 把细节同时附加到 ErrInvalidClientAssertion 与 ErrInvalidClient。
func invalidClientAssertion(format string, args ...any) error {
	return errs.Wrap(errs.Detail(ErrInvalidClientAssertion, format, args...), ErrInvalidClient)
}

// isHMACJWSAlg reports whether alg is one of the JWS HMAC algorithms. | isHMACJWSAlg 报告 alg 是否为
// JWS HMAC 算法之一。
func isHMACJWSAlg(alg string) bool {
	switch alg {
	case "HS256", "HS384", "HS512":
		return true
	default:
		return false
	}
}

// isAlgNotAllowed reports whether err came from the JOSE algorithm allow list. | isAlgNotAllowed
// 报告 err 是否来自 JOSE 算法白名单。
func isAlgNotAllowed(err error) bool {
	return errors.Is(err, jose.ErrAlgNotAllowed)
}

// containsAlg reports whether values contains want. | containsAlg 报告 values 是否包含 want。
func containsAlg(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
