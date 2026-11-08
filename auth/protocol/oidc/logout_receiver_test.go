package oidc

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth/token/jose"
	"github.com/shibingli/ydx/json"
)

// signLogoutClaimsWithKey signs logout claims with an arbitrary key. | signLogoutClaimsWithKey
// 使用任意密钥签发登出声明。
func signLogoutClaimsWithKey(t *testing.T, key *jose.Key, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := jose.Sign(payload, key, jose.SignOptions{
		Alg: "RS256",
		Kid: key.Kid,
		Typ: "logout+jwt",
	})
	if err != nil {
		t.Fatalf("sign logout claims: %v", err)
	}
	return signed
}

// externalLogoutKey generates an RSA logout-token signing key. | externalLogoutKey 生成 RSA 登出
// 令牌签名密钥。
func externalLogoutKey(t *testing.T, kid string) *jose.Key {
	t.Helper()
	key, err := jose.GenerateKey("RS256", 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	key.Kid = kid
	key.Alg = "RS256"
	key.Use = "sig"
	return key
}

// externalLogoutClaims returns a valid logout claim set for issuer. | externalLogoutClaims 返回
// issuer 的合法登出声明集。
func externalLogoutClaims(issuer, jti string) map[string]any {
	return map[string]any{
		"iss":    issuer,
		"aud":    []string{"web"},
		"iat":    time.Now().Unix(),
		"jti":    jti,
		"sid":    "sid-1",
		"events": map[string]any{BackchannelLogoutEvent: map[string]any{}},
	}
}

// postLogoutToken delivers a logout token to a provider's back-channel receiver. |
// postLogoutToken 把登出令牌投递到提供方的后端登出接收端。
func postLogoutToken(provider *Provider, raw string) int {
	form := url.Values{"logout_token": {raw}}
	req := httptest.NewRequest(http.MethodPost, BackchannelLogoutPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	provider.BackchannelLogout(recorder, req)
	return recorder.Code
}

// TestFrontchannelLogoutClientBinding verifies the front-channel receiver binds requests to its
// configured client and rejects incomplete requests. | TestFrontchannelLogoutClientBinding 校验
// 前端登出接收端把请求绑定到配置的客户端并拒绝不完整请求。
func TestFrontchannelLogoutClientBinding(t *testing.T) {
	fixture := newOIDCFixture(t, false)
	provider := fixture.provider
	call := func(method, query string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/frontchannel?"+query, nil)
		recorder := httptest.NewRecorder()
		provider.FrontchannelLogout(recorder, req)
		return recorder
	}
	issuer := fixture.server.URL

	if w := call(http.MethodPost, url.Values{"iss": {issuer}, "sid": {"sid-1"}}.Encode()); w.Code != http.StatusMethodNotAllowed ||
		w.Header().Get("Allow") != "GET" {
		t.Fatalf("POST = %d allow=%q | POST = %d，Allow = %q", w.Code, w.Header().Get("Allow"), w.Code, w.Header().Get("Allow"))
	}
	if w := call(http.MethodGet, url.Values{"iss": {issuer}, "client_id": {"web"}}.Encode()); w.Code != http.StatusBadRequest {
		t.Fatalf("missing sid/sub = %d | 缺少 sid/sub = %d", w.Code, w.Code)
	}
	if w := call(http.MethodGet, url.Values{"iss": {issuer}, "client_id": {"other"}, "sid": {"sid-1"}}.Encode()); w.Code != http.StatusBadRequest {
		t.Fatalf("other client_id = %d | 其他 client_id = %d", w.Code, w.Code)
	}
	if w := call(http.MethodGet, url.Values{"iss": {issuer}, "aud": {"other"}, "sid": {"sid-1"}}.Encode()); w.Code != http.StatusBadRequest {
		t.Fatalf("other aud = %d | 其他 aud = %d", w.Code, w.Code)
	}
	if w := call(http.MethodGet, url.Values{"iss": {issuer}, "aud": {"other web"}, "sid": {"sid-1"}}.Encode()); w.Code != http.StatusOK {
		t.Fatalf("matching aud = %d body=%s | 匹配 aud = %d，正文 = %s", w.Code, w.Body.String(), w.Code, w.Body.String())
	}
	if w := call(http.MethodGet, url.Values{"iss": {issuer}, "client_id": {"web"}, "sid": {"sid-1"}}.Encode()); w.Code != http.StatusOK {
		t.Fatalf("matching client_id = %d | 匹配 client_id = %d", w.Code, w.Code)
	}
	if w := call(http.MethodGet, url.Values{"iss": {issuer}, "client_id": {"web"}, "sub": {"user-1"}}.Encode()); w.Code != http.StatusOK ||
		!strings.Contains(w.Body.String(), "sub=user-1") {
		t.Fatalf("sub only = %d body=%s | 仅 sub = %d，正文 = %s", w.Code, w.Body.String(), w.Code, w.Body.String())
	}

	provider.config.FrontchannelLogoutClientID = ""
	if w := call(http.MethodGet, url.Values{"iss": {issuer}, "sid": {"sid-1"}}.Encode()); w.Code != http.StatusInternalServerError {
		t.Fatalf("unconfigured receiver = %d | 未配置接收端 = %d", w.Code, w.Code)
	}
}

// TestBackchannelLogoutExternalIssuerJWKS verifies a receiver accepts logout tokens signed by a
// third-party OP through its JWKS, selects keys by kid, and caches the fetched key set. |
// TestBackchannelLogoutExternalIssuerJWKS 校验接收端通过第三方 OP 的 JWKS 接受其签发的登出令牌、
// 按 kid 选择密钥并缓存获取的密钥集。
func TestBackchannelLogoutExternalIssuerJWKS(t *testing.T) {
	firstKey := externalLogoutKey(t, "ext-1")
	secondKey := externalLogoutKey(t, "ext-2")
	keySet := &jose.KeySet{}
	if err := keySet.Add(firstKey); err != nil {
		t.Fatal(err)
	}
	if err := keySet.Add(secondKey); err != nil {
		t.Fatal(err)
	}
	var fetches atomic.Int64
	external := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		body, err := keySet.Public().Marshal()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write(body)
	}))
	defer external.Close()

	fixture := newOIDCFixture(t, false, func(config *ProviderConfig) {
		config.BackchannelLogoutIssuer = external.URL
		config.BackchannelLogoutJWKSURI = external.URL + "/jwks"
	})
	provider := fixture.provider

	// The first token is signed by the second key so an implementation that ignores kid and uses
	// the first key in the set cannot pass. | 首个令牌由第二个密钥签发，忽略 kid 而使用集合首密钥的
	// 实现无法通过。
	if code := postLogoutToken(provider, signLogoutClaimsWithKey(t, secondKey, externalLogoutClaims(external.URL, "ext-jti-1"))); code != http.StatusOK {
		t.Fatalf("external token = %d | 外部令牌 = %d", code, code)
	}
	if code := postLogoutToken(provider, signLogoutClaimsWithKey(t, firstKey, externalLogoutClaims(external.URL, "ext-jti-2"))); code != http.StatusOK {
		t.Fatalf("external first key = %d | 外部首密钥 = %d", code, code)
	}
	if got := fetches.Load(); got != 1 {
		t.Fatalf("JWKS fetches = %d, want 1 | JWKS 获取次数 = %d，期望 1", got, got)
	}

	// A token claiming this provider as issuer is rejected even when signed by the external key. |
	// 即使由外部密钥签名，声明本提供方为签发方的令牌仍会被拒绝。
	wrongIssuer := externalLogoutClaims(external.URL, "wrong-issuer")
	wrongIssuer["iss"] = fixture.server.URL
	if code := postLogoutToken(provider, signLogoutClaimsWithKey(t, secondKey, wrongIssuer)); code != http.StatusBadRequest {
		t.Fatalf("wrong issuer = %d | 错误签发方 = %d", code, code)
	}
	// A token signed by this provider's key under the external issuer is rejected. | 以外部签发方
	// 声明但由本提供方密钥签名的令牌会被拒绝。
	if code := postLogoutToken(provider, signLogoutClaims(t, provider, externalLogoutClaims(external.URL, "own-key"))); code != http.StatusBadRequest {
		t.Fatalf("wrong signing key = %d | 错误签名密钥 = %d", code, code)
	}

	// Concurrent validations share the cached key set. Tokens are signed before the goroutines
	// start because testing.T methods must not be called from them. | 并发校验共享缓存的密钥集。
	// 令牌在启动协程前签发，因为不得从协程调用 testing.T 方法。
	const concurrency = 16
	tokens := make([]string, concurrency)
	for i := range tokens {
		key := firstKey
		if i%2 == 0 {
			key = secondKey
		}
		tokens[i] = signLogoutClaimsWithKey(t, key, externalLogoutClaims(external.URL, "concurrent-jti-"+strconv.Itoa(i)))
	}
	var wait sync.WaitGroup
	statuses := make([]int, concurrency)
	for i := 0; i < concurrency; i++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			statuses[index] = postLogoutToken(provider, tokens[index])
		}(i)
	}
	wait.Wait()
	for i, status := range statuses {
		if status != http.StatusOK {
			t.Fatalf("concurrent status[%d] = %d | 并发状态[%d] = %d", i, status, i, status)
		}
	}
	if got := fetches.Load(); got != 1 {
		t.Fatalf("concurrent JWKS fetches = %d, want 1 | 并发 JWKS 获取次数 = %d，期望 1", got, got)
	}
}

// TestBackchannelLogoutExternalIssuerKeySources verifies static key sets and custom resolvers can
// verify third-party logout tokens. | TestBackchannelLogoutExternalIssuerKeySources 校验静态密钥集
// 与自定义解析器可校验第三方登出令牌。
func TestBackchannelLogoutExternalIssuerKeySources(t *testing.T) {
	key := externalLogoutKey(t, "static-1")
	keySet := &jose.KeySet{}
	if err := keySet.Add(key); err != nil {
		t.Fatal(err)
	}
	const externalIssuer = "https://op.external.example"
	sources := []struct {
		name      string
		configure func(*ProviderConfig)
	}{
		{name: "key set", configure: func(config *ProviderConfig) { config.BackchannelLogoutKeySet = keySet }},
		{name: "key resolver", configure: func(config *ProviderConfig) { config.BackchannelLogoutKeyResolver = keySet.Resolver() }},
	}
	for _, source := range sources {
		t.Run(source.name, func(t *testing.T) {
			fixture := newOIDCFixture(t, false, func(config *ProviderConfig) {
				config.BackchannelLogoutIssuer = externalIssuer
				source.configure(config)
			})
			raw := signLogoutClaimsWithKey(t, key, externalLogoutClaims(externalIssuer, "static-jti"))
			if code := postLogoutToken(fixture.provider, raw); code != http.StatusOK {
				t.Fatalf("external token = %d | 外部令牌 = %d", code, code)
			}
			local := externalLogoutClaims(externalIssuer, "local-jti")
			local["iss"] = fixture.server.URL
			if code := postLogoutToken(fixture.provider, signLogoutClaimsWithKey(t, key, local)); code != http.StatusBadRequest {
				t.Fatalf("wrong issuer = %d | 错误签发方 = %d", code, code)
			}
		})
	}
}

// TestBackchannelLogoutConfigValidation verifies the receiver rejects ambiguous or incomplete
// third-party key configuration. | TestBackchannelLogoutConfigValidation 校验接收端拒绝含糊或不
// 完整的第三方密钥配置。
func TestBackchannelLogoutConfigValidation(t *testing.T) {
	fixture := newOIDCFixture(t, false)
	keySet := &jose.KeySet{}
	cases := []struct {
		name   string
		config ProviderConfig
	}{
		{
			name:   "external issuer without keys",
			config: ProviderConfig{BackchannelLogoutIssuer: "https://op.external.example"},
		},
		{
			name:   "keys without explicit issuer",
			config: ProviderConfig{BackchannelLogoutKeySet: keySet},
		},
		{
			name: "multiple key sources",
			config: ProviderConfig{
				BackchannelLogoutIssuer:      "https://op.external.example",
				BackchannelLogoutKeySet:      keySet,
				BackchannelLogoutJWKSURI:     "https://op.external.example/jwks",
				BackchannelLogoutKeyResolver: keySet.Resolver(),
			},
		},
		{
			name:   "relative external issuer",
			config: ProviderConfig{BackchannelLogoutIssuer: "op.example", BackchannelLogoutKeySet: keySet},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := tc.config
			config.OAuth = fixture.oauth
			if _, err := NewProvider(config); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("error = %v, want ErrInvalidConfig | 错误 = %v，期望 ErrInvalidConfig", err, err)
			}
		})
	}
}

// TestDiscoveryDoesNotAdvertiseClientSecretJWT verifies OIDC discovery stays consistent with the
// OAuth metadata and the receiver's client_secret_jwt rejection. | TestDiscoveryDoesNotAdvertiseClientSecretJWT
// 校验 OIDC 发现文档与 OAuth 元数据以及接收端对 client_secret_jwt 的拒绝保持一致。
func TestDiscoveryDoesNotAdvertiseClientSecretJWT(t *testing.T) {
	fixture := newOIDCFixture(t, false)
	document := fixture.provider.DiscoveryDocument()
	lists := map[string][]string{
		"token":         document.TokenEndpointAuthMethodsSupported,
		"revocation":    document.RevocationEndpointAuthMethodsSupported,
		"introspection": document.IntrospectionEndpointAuthMethodsSupported,
	}
	for endpoint, methods := range lists {
		if len(methods) == 0 {
			t.Fatalf("%s authentication methods are empty | %s 认证方法为空", endpoint, endpoint)
		}
		for _, method := range methods {
			if method == "client_secret_jwt" {
				t.Fatalf("%s discovery advertises unsupported client_secret_jwt | %s 发现文档公布了不支持的 client_secret_jwt", endpoint, endpoint)
			}
		}
	}
}
