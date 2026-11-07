package federation

import (
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth/token/jose"
	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/json"
)

const (
	// oidcFixtureClientID and oidcFixtureClientSecret are obvious fixed test credentials.
	// oidcFixtureClientID 与 oidcFixtureClientSecret 是明显的固定测试凭据。
	oidcFixtureClientID     = "oidc-client"
	oidcFixtureClientSecret = "oidc-client-secret"
	oidcFixtureAccessToken  = "oidc-access-token"
	oidcFixtureUserInfoBody = `{"sub":"oidc-subject","name":"UserInfo Name","email":"userinfo@example.com","email_verified":true,"picture":"https://example.com/userinfo.png"}`
)

// oidcFixtureKeys holds the shared signing keys used by every OIDC fixture. | oidcFixtureKeys
// 保存所有 OIDC fixture 共享的签名密钥。
var oidcFixtureKeys struct {
	once    sync.Once
	err     error
	primary *jose.Key
	rotated *jose.Key
	rogue   *jose.Key
	ec      *jose.Key
}

// sharedOIDCKeys generates the fixture keys once per test binary. | sharedOIDCKeys 在每个测试
// 二进制中只生成一次 fixture 密钥。
func sharedOIDCKeys(t *testing.T) (primary, rotated, rogue, ec *jose.Key) {
	t.Helper()
	oidcFixtureKeys.once.Do(func() {
		keys := &oidcFixtureKeys
		if keys.primary, keys.err = jose.GenerateKey("RS256", 2048); keys.err != nil {
			return
		}
		if keys.rotated, keys.err = jose.GenerateKey("RS256", 2048); keys.err != nil {
			return
		}
		if keys.rogue, keys.err = jose.GenerateKey("RS256", 2048); keys.err != nil {
			return
		}
		keys.ec, keys.err = jose.GenerateKey("ES256", 0)
	})
	if oidcFixtureKeys.err != nil {
		t.Fatalf("generate OIDC fixture keys: %v", oidcFixtureKeys.err)
	}
	return oidcFixtureKeys.primary, oidcFixtureKeys.rotated, oidcFixtureKeys.rogue, oidcFixtureKeys.ec
}

// publicJWK returns an alg-less public JWK with the given kid. Clearing alg lets verification
// reach the key-family check instead of the key-alg check. | publicJWK 返回指定 kid 的无算法
// 公钥 JWK；清空 alg 可使校验进入密钥族检查而不是密钥算法检查。
func publicJWK(key *jose.Key, kid string) *jose.Key {
	out := key.Public()
	out.Kid = kid
	out.Alg = ""
	out.Use = "sig"
	return out
}

// oidcFixtureConfig is the mutable behavior of the local OpenID Provider. | oidcFixtureConfig
// 是本地 OpenID 提供方的可变行为配置。
type oidcFixtureConfig struct {
	discoveryStatus        int
	discoveryIssuer        string
	discoveryBody          []byte
	discoveryAlgs          []string
	omitDiscoveryEndpoints bool
	omitJWKS               bool
	// discoveryDelay delays discovery responses so concurrent callers overlap.
	// discoveryDelay 延迟发现响应，使并发调用方重叠。
	discoveryDelay time.Duration
	// discovery*URL override published endpoints when non-empty. | discovery*URL 非空时
	// 覆盖发布的端点。
	discoveryAuthURL     string
	discoveryTokenURL    string
	discoveryUserInfoURL string
	discoveryJWKSURL     string

	jwksStatus int
	jwksBody   []byte
	keys       []*jose.Key

	tokenStatus int
	tokenBody   []byte
	accessToken string

	includeIDToken bool
	idTokenRaw     string
	signKey        *jose.Key
	signKid        string
	signAlg        string
	// issuer is the iss claim of signed tokens; empty defaults to the fixture URL.
	// issuer 是签名令牌的 iss 声明；为空时使用 fixture URL。
	issuer string
	claims map[string]any

	userInfoStatus int
	userInfoBody   string
}

// oidcFixture is an httptest OpenID Provider covering discovery, JWKS, token and UserInfo.
// oidcFixture 是覆盖发现、JWKS、令牌与 UserInfo 的 httptest OpenID 提供方。
type oidcFixture struct {
	server *httptest.Server
	issuer string

	mu sync.Mutex
	// cfg is the current provider behavior. | cfg 是当前提供方行为。
	cfg oidcFixtureConfig
	// Counters and captured requests are guarded by mu as well. | 计数与捕获的请求同样由 mu 保护。
	discoveryCalls int
	jwksCalls      int
	tokenCalls     int
	userInfoCalls  int
	lastTokenForm  url.Values
	lastTokenHead  http.Header
	lastUserInfo   http.Header
}

// newOIDCFixture starts a local OpenID Provider. | newOIDCFixture 启动本地 OpenID 提供方。
func newOIDCFixture(t *testing.T) *oidcFixture {
	t.Helper()
	primary, _, _, _ := sharedOIDCKeys(t)
	fixture := &oidcFixture{
		cfg: oidcFixtureConfig{
			discoveryStatus: http.StatusOK,
			discoveryAlgs:   []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"},
			jwksStatus:      http.StatusOK,
			tokenStatus:     http.StatusOK,
			accessToken:     oidcFixtureAccessToken,
			includeIDToken:  true,
			signKey:         primary,
			signKid:         "rsa-1",
			signAlg:         "RS256",
			keys:            []*jose.Key{publicJWK(primary, "rsa-1")},
			claims:          map[string]any{},
			userInfoStatus:  http.StatusOK,
			userInfoBody:    oidcFixtureUserInfoBody,
		},
	}
	fixture.server = httptest.NewServer(http.HandlerFunc(fixture.serveHTTP))
	fixture.issuer = fixture.server.URL
	t.Cleanup(fixture.server.Close)
	return fixture
}

// set mutates the provider behavior under the fixture lock. | set 在 fixture 锁内修改提供方行为。
func (f *oidcFixture) set(mutate func(*oidcFixtureConfig)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	mutate(&f.cfg)
}

// counts returns the request counters. | counts 返回请求计数。
func (f *oidcFixture) counts() (discovery, jwks, token, userInfo int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.discoveryCalls, f.jwksCalls, f.tokenCalls, f.userInfoCalls
}

// lastTokenRequest returns the captured token form and headers. | lastTokenRequest 返回捕获的
// 令牌表单与请求头。
func (f *oidcFixture) lastTokenRequest() (url.Values, http.Header) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return cloneForm(f.lastTokenForm), f.lastTokenHead.Clone()
}

// lastUserInfoRequest returns the captured UserInfo headers. | lastUserInfoRequest 返回捕获的
// UserInfo 请求头。
func (f *oidcFixture) lastUserInfoRequest() http.Header {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastUserInfo.Clone()
}

// provider returns a provider with explicit endpoints. | provider 返回使用显式端点的提供方。
func (f *oidcFixture) provider(name string, options ...ProviderOption) *Provider {
	p := NewProvider(ProviderConfig{
		Name:         name,
		ClientID:     oidcFixtureClientID,
		ClientSecret: oidcFixtureClientSecret,
		RedirectURL:  "https://app.example/auth/" + name + "/callback",
		AuthURL:      f.server.URL + "/authorize",
		TokenURL:     f.server.URL + "/token",
		UserInfoURL:  f.server.URL + "/userinfo",
		JWKSURL:      f.server.URL + "/jwks",
		Issuer:       f.issuer,
		UseOIDC:      true,
		Nonce:        true,
		HTTPClient:   f.server.Client(),
	})
	applyOptions(p, options)
	return p
}

// discoveryProvider returns a provider that must discover every endpoint. | discoveryProvider
// 返回必须通过发现文档获取全部端点的提供方。
func (f *oidcFixture) discoveryProvider(name string, options ...ProviderOption) *Provider {
	p := NewProvider(ProviderConfig{
		Name:         name,
		ClientID:     oidcFixtureClientID,
		ClientSecret: oidcFixtureClientSecret,
		RedirectURL:  "https://app.example/auth/" + name + "/callback",
		Issuer:       f.issuer,
		UseOIDC:      true,
		Nonce:        true,
		HTTPClient:   f.server.Client(),
	})
	applyOptions(p, options)
	return p
}

// serveHTTP routes fixture requests. | serveHTTP 路由 fixture 请求。
func (f *oidcFixture) serveHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		f.serveDiscovery(w, r)
	case "/jwks":
		f.serveJWKS(w, r)
	case "/token":
		f.serveToken(w, r)
	case "/token-v2":
		f.serveToken(w, r)
	case "/userinfo":
		f.serveUserInfo(w, r)
	default:
		http.NotFound(w, r)
	}
}

// snapshotLocked copies the mutable config. The caller must hold f.mu. | snapshotLocked 复制可变
// 配置；调用方必须持有 f.mu。
func (f *oidcFixture) snapshotLocked() oidcFixtureConfig {
	out := f.cfg
	out.keys = append([]*jose.Key(nil), f.cfg.keys...)
	out.discoveryAlgs = append([]string(nil), f.cfg.discoveryAlgs...)
	out.claims = make(map[string]any, len(f.cfg.claims))
	for key, value := range f.cfg.claims {
		out.claims[key] = value
	}
	return out
}

// serveDiscovery serves the discovery document. | serveDiscovery 提供发现文档。
func (f *oidcFixture) serveDiscovery(w http.ResponseWriter, _ *http.Request) {
	f.mu.Lock()
	f.discoveryCalls++
	cfg := f.snapshotLocked()
	f.mu.Unlock()

	if cfg.discoveryDelay > 0 {
		time.Sleep(cfg.discoveryDelay)
	}
	if cfg.discoveryStatus != http.StatusOK {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(cfg.discoveryStatus)
		if cfg.discoveryBody != nil {
			_, _ = w.Write(cfg.discoveryBody)
			return
		}
		_, _ = w.Write([]byte(`{"error":"discovery_secret"}`))
		return
	}
	if cfg.discoveryBody != nil {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(cfg.discoveryBody)
		return
	}
	issuer := cfg.discoveryIssuer
	if issuer == "" {
		issuer = f.issuer
	}
	document := map[string]any{
		"issuer":                                issuer,
		"id_token_signing_alg_values_supported": cfg.discoveryAlgs,
	}
	if !cfg.omitDiscoveryEndpoints {
		authURL := cfg.discoveryAuthURL
		if authURL == "" {
			authURL = f.server.URL + "/authorize"
		}
		tokenURL := cfg.discoveryTokenURL
		if tokenURL == "" {
			tokenURL = f.server.URL + "/token"
		}
		userInfoURL := cfg.discoveryUserInfoURL
		if userInfoURL == "" {
			userInfoURL = f.server.URL + "/userinfo"
		}
		document["authorization_endpoint"] = authURL
		document["token_endpoint"] = tokenURL
		document["userinfo_endpoint"] = userInfoURL
	}
	if !cfg.omitJWKS {
		jwksURL := cfg.discoveryJWKSURL
		if jwksURL == "" {
			jwksURL = f.server.URL + "/jwks"
		}
		document["jwks_uri"] = jwksURL
	}
	body, err := json.Marshal(document)
	if err != nil {
		http.Error(w, "fixture discovery marshal", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// serveJWKS serves the published public key set. | serveJWKS 提供已发布的公钥集合。
func (f *oidcFixture) serveJWKS(w http.ResponseWriter, _ *http.Request) {
	f.mu.Lock()
	f.jwksCalls++
	cfg := f.snapshotLocked()
	f.mu.Unlock()

	if cfg.jwksStatus != http.StatusOK {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(cfg.jwksStatus)
		if cfg.jwksBody != nil {
			_, _ = w.Write(cfg.jwksBody)
			return
		}
		_, _ = w.Write([]byte(`{"error":"jwks_secret"}`))
		return
	}
	body := cfg.jwksBody
	if body == nil {
		set := &jose.KeySet{Keys: cfg.keys}
		encoded, err := set.Marshal()
		if err != nil {
			http.Error(w, "fixture JWKS marshal", http.StatusInternalServerError)
			return
		}
		body = encoded
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// serveToken issues a token response with a locally signed ID token. | serveToken 签发带本地签名
// ID 令牌的令牌响应。
func (f *oidcFixture) serveToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "fixture token form", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.tokenCalls++
	f.lastTokenForm = cloneForm(r.PostForm)
	f.lastTokenHead = r.Header.Clone()
	cfg := f.snapshotLocked()
	f.mu.Unlock()
	if cfg.issuer == "" {
		cfg.issuer = f.issuer
	}

	if cfg.tokenStatus != http.StatusOK || cfg.tokenBody != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(cfg.tokenStatus)
		if cfg.tokenBody != nil {
			_, _ = w.Write(cfg.tokenBody)
			return
		}
		_, _ = w.Write([]byte(`{"error":"server_error"}`))
		return
	}

	response := map[string]any{
		"access_token":  cfg.accessToken,
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": "oidc-refresh-token",
	}
	if cfg.includeIDToken {
		idToken := cfg.idTokenRaw
		if idToken == "" {
			signed, err := cfg.signIDToken()
			if err != nil {
				http.Error(w, "fixture signing failed", http.StatusInternalServerError)
				return
			}
			idToken = signed
		}
		response["id_token"] = idToken
	}
	body, err := json.Marshal(response)
	if err != nil {
		http.Error(w, "fixture token marshal", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// signIDToken signs the configured claim set. | signIDToken 签名配置的声明集合。
func (c oidcFixtureConfig) signIDToken() (string, error) {
	now := time.Now()
	claims := map[string]any{
		"iss":                c.issuer,
		"sub":                "oidc-subject",
		"aud":                oidcFixtureClientID,
		"exp":                now.Add(5 * time.Minute).Unix(),
		"iat":                now.Add(-10 * time.Second).Unix(),
		"email":              "oidc@example.com",
		"email_verified":     true,
		"name":               "OIDC Subject",
		"preferred_username": "oidc-user",
		"picture":            "https://example.com/oidc-subject.png",
	}
	if c.accessToken != "" {
		claims["at_hash"] = oidcHalfHash(c.signAlg, c.accessToken)
	}
	for key, value := range c.claims {
		if value == nil {
			delete(claims, key)
			continue
		}
		claims[key] = value
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	return jose.Sign(payload, c.signKey, jose.SignOptions{Alg: c.signAlg, Kid: c.signKid, Typ: "JWT"})
}

// serveUserInfo serves the UserInfo response. | serveUserInfo 提供 UserInfo 响应。
func (f *oidcFixture) serveUserInfo(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.userInfoCalls++
	f.lastUserInfo = r.Header.Clone()
	cfg := f.snapshotLocked()
	f.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(cfg.userInfoStatus)
	_, _ = w.Write([]byte(cfg.userInfoBody))
}

// oidcHalfHash computes the at_hash left-half digest for the fixture algs. | oidcHalfHash 计算
// fixture 所用算法的 at_hash 左半摘要。
func oidcHalfHash(alg, value string) string {
	var h hash.Hash
	switch alg {
	case "RS384", "PS384", "ES384":
		h = sha512.New384()
	case "RS512", "PS512", "ES512":
		h = sha512.New()
	default:
		h = sha256.New()
	}
	_, _ = h.Write([]byte(value))
	sum := h.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}

// craftCompactJWS builds a compact JWS with an arbitrary header and signature segment.
// craftCompactJWS 使用任意头部与签名段构建紧凑 JWS。
func craftCompactJWS(t *testing.T, header, claims map[string]any) string {
	t.Helper()
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	signature := base64.RawURLEncoding.EncodeToString([]byte("fixture-signature"))
	return base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON) + "." + signature
}
