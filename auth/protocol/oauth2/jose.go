package oauth2

import (
	"context"
	"crypto/sha256"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/auth/token/jose"
	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
)

// DPoPReplayStore rejects replayed DPoP proof identifiers. | DPoPReplayStore 拒绝重放的 DPoP 证明标识。
type DPoPReplayStore interface {
	// Accept records jti until expiresAt and reports whether it was fresh. | Accept 记录 jti 到 expiresAt 并报告是否为新鲜值。
	Accept(ctx context.Context, jti string, expiresAt time.Time) (bool, error)
}

// MemoryDPoPReplayStore is a concurrency-safe in-process replay store. | MemoryDPoPReplayStore 是并发安全的内存重放存储。
type MemoryDPoPReplayStore struct {
	mu   sync.Mutex
	seen map[string]time.Time
	now  func() time.Time
}

// NewMemoryDPoPReplayStore returns an empty replay store. | NewMemoryDPoPReplayStore 返回空重放存储。
func NewMemoryDPoPReplayStore() *MemoryDPoPReplayStore {
	return &MemoryDPoPReplayStore{seen: make(map[string]time.Time), now: time.Now}
}

// Accept records jti and reports whether it was fresh. | Accept 记录 jti 并报告是否为新鲜值。
func (s *MemoryDPoPReplayStore) Accept(_ context.Context, jti string, expiresAt time.Time) (bool, error) {
	if jti == "" {
		return false, errs.Detail(ErrInvalidDPoPProof, "jti is empty | jti 为空")
	}
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, expiry := range s.seen {
		if !now.Before(expiry) {
			delete(s.seen, key)
		}
	}
	if _, exists := s.seen[jti]; exists {
		return false, nil
	}
	s.seen[jti] = expiresAt
	return true, nil
}

// DPoPVerifierConfig configures a DPoP proof verifier. | DPoPVerifierConfig 配置 DPoP 证明校验器。
type DPoPVerifierConfig struct {
	// Replay rejects reused jti values; nil uses a fresh memory store. | Replay 拒绝重复 jti；空值使用新的内存存储。
	Replay DPoPReplayStore
	// Now overrides the clock. | Now 替换时钟。
	Now func() time.Time
	// ProofWindow is the accepted iat window; zero means five minutes. | ProofWindow 是可接受的 iat 窗口；零值表示 5 分钟。
	ProofWindow time.Duration
	// Leeway is the clock tolerance. | Leeway 是时钟容差。
	Leeway time.Duration
	// ValidAlgs restricts proof algorithms; nil allows asymmetric RFC 7518 algorithms. | ValidAlgs 限定证明算法；空值允许 RFC 7518 非对称算法。
	ValidAlgs []string
}

// DPoPProofVerifier verifies RFC 9449 DPoP proofs. | DPoPProofVerifier 校验 RFC 9449 DPoP 证明。
type DPoPProofVerifier struct {
	config DPoPVerifierConfig
}

// NewDPoPProofVerifier returns a DPoP verifier. | NewDPoPProofVerifier 返回 DPoP 校验器。
func NewDPoPProofVerifier(config DPoPVerifierConfig) *DPoPProofVerifier {
	if config.Replay == nil {
		config.Replay = NewMemoryDPoPReplayStore()
	}
	if config.ProofWindow <= 0 {
		config.ProofWindow = 5 * time.Minute
	}
	if len(config.ValidAlgs) == 0 {
		config.ValidAlgs = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}
	}
	return &DPoPProofVerifier{config: config}
}

// VerifyProof validates proof for method and target. | VerifyProof 为 method 与 target 校验 proof。
func (v *DPoPProofVerifier) VerifyProof(ctx context.Context, proof, method, target, accessToken string) (string, error) {
	if proof == "" {
		return "", errs.Detail(ErrInvalidDPoPProof, "proof is empty | 证明为空")
	}
	var proofKey *jose.Key
	resolver := jose.KeyResolverFunc(func(_ context.Context, header jose.Header) (*jose.Key, error) {
		raw, ok := header["jwk"]
		if !ok {
			return nil, errs.Detail(ErrInvalidDPoPProof, "jwk header is missing | 缺少 jwk 头部")
		}
		data, err := json.Marshal(raw)
		if err != nil {
			return nil, errs.Wrap(err, ErrInvalidDPoPProof)
		}
		key, err := jose.ParseKey(data)
		if err != nil {
			return nil, errs.Wrap(err, ErrInvalidDPoPProof)
		}
		if key.D != "" || key.P != "" || key.Q != "" || key.K != "" {
			return nil, errs.Detail(ErrInvalidDPoPProof, "jwk must not contain private material | jwk 不得包含私钥材料")
		}
		proofKey = key.Public()
		return proofKey, nil
	})
	now := time.Now
	if v.config.Now != nil {
		now = v.config.Now
	}
	verified, err := jose.VerifyContext(ctx, proof, resolver, jose.VerifyOptions{
		ValidAlgs: v.config.ValidAlgs,
		Typ:       "dpop+jwt",
		Leeway:    v.config.Leeway,
		Now:       now,
	})
	if err != nil {
		return "", errs.Wrap(err, ErrInvalidDPoPProof)
	}
	if proofKey == nil {
		return "", errs.Detail(ErrInvalidDPoPProof, "proof key was not resolved | 证明密钥未解析")
	}
	var claims map[string]any
	if err := json.Unmarshal(verified.Payload, &claims); err != nil {
		return "", errs.Wrap(err, ErrInvalidDPoPProof)
	}
	htm, _ := claims["htm"].(string)
	if !strings.EqualFold(htm, method) {
		return "", errs.Detail(ErrInvalidDPoPProof, "htm mismatch | htm 不匹配")
	}
	htu, _ := claims["htu"].(string)
	if !sameHTU(htu, target) {
		return "", errs.Detail(ErrInvalidDPoPProof, "htu mismatch | htu 不匹配")
	}
	iat, ok := numericClaim(claims["iat"])
	if !ok {
		return "", errs.Detail(ErrInvalidDPoPProof, "iat is missing | 缺少 iat")
	}
	at := now().UTC()
	if at.Add(v.config.Leeway).Before(time.Unix(iat, 0)) || at.Add(-v.config.ProofWindow).After(time.Unix(iat, 0)) {
		return "", errs.Detail(ErrInvalidDPoPProof, "proof is outside the accepted window | 证明超出接受窗口")
	}
	jti, _ := claims["jti"].(string)
	if jti == "" {
		return "", errs.Detail(ErrInvalidDPoPProof, "jti is missing | 缺少 jti")
	}
	if accessToken != "" {
		ath, _ := claims["ath"].(string)
		sum := sha256.Sum256([]byte(accessToken))
		want := base64.RawURLEncoding.EncodeToString(sum[:])
		if ath == "" || !auth.SecureEqual(ath, want) {
			return "", errs.Detail(ErrInvalidDPoPProof, "ath mismatch | ath 不匹配")
		}
	}
	// Keep the jti for at least one full window from now: a proof near the end of the accepted
	// iat window must not age out of the replay cache while it is still acceptable. | 从当前
	// 时间起至少保留一个完整窗口：接近 iat 接受窗口末尾的证明不能在仍可接受时被重放缓存淘汰。
	expiry := time.Unix(iat, 0).Add(v.config.ProofWindow + v.config.Leeway)
	if minimum := at.Add(v.config.ProofWindow + v.config.Leeway); expiry.Before(minimum) {
		expiry = minimum
	}
	fresh, err := v.config.Replay.Accept(ctx, jti, expiry)
	if err != nil {
		return "", err
	}
	if !fresh {
		return "", errs.Detail(ErrInvalidDPoPProof, "proof replay detected | 检测到证明重放")
	}
	thumbprint, err := proofKey.Thumbprint()
	if err != nil {
		return "", errs.Wrap(err, ErrInvalidDPoPProof)
	}
	return thumbprint, nil
}

// sameHTU compares two HTTP targets without query or fragment. | sameHTU 比较去掉查询与片段的两个 HTTP 目标。
func sameHTU(a, b string) bool {
	normalize := func(raw string) string {
		parsed, err := url.Parse(raw)
		if err != nil {
			return raw
		}
		parsed.RawQuery = ""
		parsed.Fragment = ""
		parsed.RawFragment = ""
		return parsed.String()
	}
	return normalize(a) == normalize(b)
}

// numericClaim reads a NumericDate claim. | numericClaim 读取 NumericDate 声明。
func numericClaim(value any) (int64, bool) {
	switch n := value.(type) {
	case float64:
		return int64(n), true
	case int64:
		return n, true
	case int:
		return int64(n), true
	default:
		return 0, false
	}
}

// JWTAccessTokenIssuer signs RFC 9068 access tokens with a JOSE key. | JWTAccessTokenIssuer 使用 JOSE 密钥签发 RFC 9068 访问令牌。
type JWTAccessTokenIssuer struct {
	key *jose.Key
	alg string
}

// NewJWTAccessTokenIssuer returns a JWT access-token issuer. | NewJWTAccessTokenIssuer 返回 JWT 访问令牌签发器。
func NewJWTAccessTokenIssuer(key *jose.Key, alg string) (*JWTAccessTokenIssuer, error) {
	if key == nil {
		return nil, errs.Detail(ErrInvalidConfig, "signing key is nil | 签名密钥为空")
	}
	if alg == "" {
		alg = key.Alg
	}
	if alg == "" {
		return nil, errs.Detail(ErrInvalidConfig, "signing alg is empty | 签名算法为空")
	}
	return &JWTAccessTokenIssuer{key: key, alg: alg}, nil
}

// SignAccessToken signs claims. | SignAccessToken 签发 claims。
func (i *JWTAccessTokenIssuer) SignAccessToken(_ context.Context, claims *AccessTokenClaims) (string, error) {
	if claims == nil {
		return "", errs.Detail(ErrServerError, "claims are nil | 声明为空")
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", errs.Wrap(err, ErrServerError)
	}
	token, err := jose.Sign(payload, i.key, jose.SignOptions{
		Alg: i.alg,
		Kid: i.key.Kid,
		Typ: AccessTokenTypeJWT,
	})
	if err != nil {
		return "", errs.Wrap(err, ErrServerError)
	}
	return token, nil
}

// JWTAccessTokenVerifier verifies RFC 9068 access tokens. | JWTAccessTokenVerifier 校验 RFC 9068 访问令牌。
type JWTAccessTokenVerifier struct {
	keys     *jose.KeySet
	issuer   string
	audience string
	leeway   time.Duration
	now      func() time.Time
}

// NewJWTAccessTokenVerifier returns a JWT access-token verifier. | NewJWTAccessTokenVerifier 返回 JWT 访问令牌校验器。
func NewJWTAccessTokenVerifier(keys *jose.KeySet, issuer, audience string) (*JWTAccessTokenVerifier, error) {
	if keys == nil {
		return nil, errs.Detail(ErrInvalidConfig, "key set is nil | 密钥集为空")
	}
	if issuer == "" {
		return nil, errs.Detail(ErrInvalidConfig, "issuer is empty | issuer 为空")
	}
	return &JWTAccessTokenVerifier{keys: keys, issuer: issuer, audience: audience}, nil
}

// SetClock overrides the verifier clock. | SetClock 替换校验器时钟。
func (v *JWTAccessTokenVerifier) SetClock(now func() time.Time) { v.now = now }

// VerifyAccessToken verifies a compact JWT access token. | VerifyAccessToken 校验紧凑 JWT 访问令牌。
func (v *JWTAccessTokenVerifier) VerifyAccessToken(ctx context.Context, token string) (*AccessTokenClaims, error) {
	verified, err := jose.VerifyContext(ctx, token, v.keys.Resolver(), jose.VerifyOptions{
		ValidAlgs:      []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"},
		Typ:            AccessTokenTypeJWT,
		ValidateClaims: true,
		RequireExp:     true,
		Issuer:         v.issuer,
		Audience:       v.audience,
		Leeway:         v.leeway,
		Now:            v.now,
	})
	if err != nil {
		return nil, errs.Wrap(err, ErrInvalidGrant)
	}
	var claims AccessTokenClaims
	if err := json.Unmarshal(verified.Payload, &claims); err != nil {
		return nil, errs.Wrap(err, ErrInvalidGrant)
	}
	return &claims, nil
}

// PrivateKeyJWTVerifier verifies RFC 7523 private_key_jwt client assertions. | PrivateKeyJWTVerifier
// 校验 RFC 7523 private_key_jwt 客户端断言。
type PrivateKeyJWTVerifier struct {
	client      *http.Client
	replay      DPoPReplayStore
	now         func() time.Time
	cache       map[string]cachedKeySet
	leeway      time.Duration
	maxLifetime time.Duration
	cacheTTL    time.Duration
	validAlgs   []string
	mu          sync.Mutex
}

// cachedKeySet is a parsed client JWKS with its cache deadline. | cachedKeySet 是带缓存期限的已解析客户端 JWKS。
type cachedKeySet struct {
	set     *jose.KeySet
	expires time.Time
}

// PrivateKeyJWTConfig configures PrivateKeyJWTVerifier. | PrivateKeyJWTConfig 配置 PrivateKeyJWTVerifier。
type PrivateKeyJWTConfig struct {
	// HTTPClient fetches a client's jwks_uri. | HTTPClient 获取客户端的 jwks_uri。
	HTTPClient *http.Client
	// Replay rejects reused jti values. | Replay 拒绝重复 jti。
	Replay DPoPReplayStore
	// Now overrides the clock. | Now 替换时钟。
	Now func() time.Time
	// Leeway is the clock tolerance. | Leeway 是时钟容差。
	Leeway time.Duration
	// MaxLifetime bounds the assertion validity period; zero means five minutes. | MaxLifetime
	// 限定断言有效时长；零值表示 5 分钟。
	MaxLifetime time.Duration
	// JWKSCacheTTL caches fetched client key sets; zero means five minutes and a negative value
	// disables caching. | JWKSCacheTTL 缓存抓取的客户端密钥集；零值表示 5 分钟，负值禁用缓存。
	JWKSCacheTTL time.Duration
	// ValidAlgs restricts assertion algorithms. | ValidAlgs 限定断言算法。
	ValidAlgs []string
}

// NewPrivateKeyJWTVerifier returns a private_key_jwt verifier. | NewPrivateKeyJWTVerifier 返回 private_key_jwt 校验器。
func NewPrivateKeyJWTVerifier(config PrivateKeyJWTConfig) *PrivateKeyJWTVerifier {
	if config.Replay == nil {
		config.Replay = NewMemoryDPoPReplayStore()
	}
	if config.HTTPClient == nil {
		config.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if config.MaxLifetime <= 0 {
		config.MaxLifetime = 5 * time.Minute
	}
	if config.JWKSCacheTTL == 0 {
		config.JWKSCacheTTL = 5 * time.Minute
	}
	if len(config.ValidAlgs) == 0 {
		config.ValidAlgs = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}
	}
	return &PrivateKeyJWTVerifier{
		client:      config.HTTPClient,
		replay:      config.Replay,
		now:         config.Now,
		cache:       make(map[string]cachedKeySet),
		leeway:      config.Leeway,
		maxLifetime: config.MaxLifetime,
		cacheTTL:    config.JWKSCacheTTL,
		validAlgs:   config.ValidAlgs,
	}
}

// VerifyClientAssertion verifies assertion for client at audience. | VerifyClientAssertion 在 audience 处为 client 校验 assertion。
func (v *PrivateKeyJWTVerifier) VerifyClientAssertion(ctx context.Context, client *Client, assertion, audience string) error {
	if client == nil {
		return ErrInvalidClient
	}
	set, err := v.clientKeySet(ctx, client)
	if err != nil {
		return err
	}
	verified, err := jose.VerifyContext(ctx, assertion, set.Resolver(), jose.VerifyOptions{
		ValidAlgs: v.validAlgs,
		Leeway:    v.leeway,
		Now:       v.now,
	})
	if err != nil {
		return errs.Wrap(err, ErrInvalidClient)
	}
	var claims struct {
		Issuer   string        `json:"iss"`
		Subject  string        `json:"sub"`
		Audience audienceClaim `json:"aud"`
		Expiry   int64         `json:"exp"`
		IssuedAt int64         `json:"iat"`
		JTI      string        `json:"jti"`
	}
	if err := json.Unmarshal(verified.Payload, &claims); err != nil {
		return errs.Wrap(err, ErrInvalidClient)
	}
	if claims.Issuer != client.ID || claims.Subject != client.ID {
		return errs.Detail(ErrInvalidClient, "iss and sub must equal the client id | iss 与 sub 必须等于客户端标识")
	}
	if audience != "" && !claims.Audience.Contains(audience) {
		return errs.Detail(ErrInvalidClient, "assertion audience mismatch | 断言受众不匹配")
	}
	if claims.Expiry == 0 {
		return errs.Detail(ErrInvalidClient, "assertion exp is missing | 断言缺少 exp")
	}
	now := time.Now
	if v.now != nil {
		now = v.now
	}
	at := now().UTC()
	if at.Add(v.leeway).After(time.Unix(claims.Expiry, 0)) {
		return errs.Detail(ErrInvalidClient, "assertion expired | 断言已过期")
	}
	if time.Unix(claims.Expiry, 0).After(at.Add(v.maxLifetime + v.leeway)) {
		return errs.Detail(ErrInvalidClient, "assertion lifetime is too long | 断言有效时长过长")
	}
	if claims.IssuedAt != 0 {
		if at.Add(v.leeway).Before(time.Unix(claims.IssuedAt, 0)) {
			return errs.Detail(ErrInvalidClient, "assertion iat is in the future | 断言 iat 位于未来")
		}
		if time.Unix(claims.Expiry, 0).Sub(time.Unix(claims.IssuedAt, 0)) > v.maxLifetime {
			return errs.Detail(ErrInvalidClient, "assertion lifetime is too long | 断言有效时长过长")
		}
	}
	if claims.JTI == "" {
		return errs.Detail(ErrInvalidClient, "assertion jti is missing | 断言缺少 jti")
	}
	fresh, err := v.replay.Accept(ctx, claims.JTI, time.Unix(claims.Expiry, 0))
	if err != nil {
		return err
	}
	if !fresh {
		return errs.Detail(ErrInvalidClient, "assertion replay detected | 检测到断言重放")
	}
	return nil
}

// audienceClaim accepts a string or array aud claim. | audienceClaim 接受字符串或数组 aud 声明。
type audienceClaim []string

// UnmarshalJSON accepts both aud encodings. | UnmarshalJSON 接受两种 aud 编码。
func (a *audienceClaim) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = audienceClaim{single}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return err
	}
	*a = audienceClaim(many)
	return nil
}

// Contains reports whether the audience contains value. | Contains 报告受众是否包含 value。
func (a audienceClaim) Contains(value string) bool {
	for _, item := range a {
		if item == value {
			return true
		}
	}
	return false
}

// clientKeySet resolves a client's registered JWKS. | clientKeySet 解析客户端注册的 JWKS。
func (v *PrivateKeyJWTVerifier) clientKeySet(ctx context.Context, client *Client) (*jose.KeySet, error) {
	if len(client.JWKS) > 0 {
		return jose.ParseKeySet(client.JWKS)
	}
	if client.JWKSURI == "" {
		return nil, errs.Detail(ErrInvalidClient, "client has no JWKS | 客户端没有 JWKS")
	}
	parsed, err := url.Parse(client.JWKSURI)
	if err != nil {
		return nil, errs.Wrap(err, ErrInvalidClient)
	}
	// Only encrypted transport is dereferenced; loopback HTTP stays available to local tests and
	// native development servers, while arbitrary http URLs cannot become an SSRF primitive. | 只
	// 抓取加密传输；回环 HTTP 供本地测试与原生开发服务器使用，任意 http 地址不能成为 SSRF 手段。
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname())) {
		return nil, errs.Detail(ErrInvalidClient, "client jwks_uri must use https | 客户端 jwks_uri 必须使用 https")
	}
	now := time.Now
	if v.now != nil {
		now = v.now
	}
	cacheKey := client.ID + "\x00" + client.JWKSURI
	if v.cacheTTL > 0 {
		v.mu.Lock()
		cached, ok := v.cache[cacheKey]
		v.mu.Unlock()
		if ok && now().UTC().Before(cached.expires) {
			return cached.set, nil
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, client.JWKSURI, nil)
	if err != nil {
		return nil, errs.Wrap(err, ErrInvalidClient)
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, errs.Wrap(err, ErrInvalidClient)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, errs.Detail(ErrInvalidClient, "client JWKS returned HTTP %[1]d | 客户端 JWKS 返回 HTTP %[1]d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, errs.Wrap(err, ErrInvalidClient)
	}
	set, err := jose.ParseKeySet(body)
	if err != nil {
		return nil, errs.Wrap(err, ErrInvalidClient)
	}
	if v.cacheTTL > 0 {
		v.mu.Lock()
		v.cache[cacheKey] = cachedKeySet{set: set, expires: now().UTC().Add(v.cacheTTL)}
		v.mu.Unlock()
	}
	return set, nil
}
