package oidc

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth/protocol/oauth2"
	"github.com/shibingli/ydx/auth/token/jose"
	"github.com/shibingli/ydx/json"
	"github.com/shibingli/ydx/router"
)

// testClientSecretJWTSecret is an obvious fixed test secret with enough bytes for HS512. |
// testClientSecretJWTSecret 是明显的固定测试密钥，字节数足以支持 HS512。
const testClientSecretJWTSecret = "test-client-secret-jwt-0123456789-abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ"

// oidcClientSecretStore is a concurrency-safe resolver and registrar for tests. |
// oidcClientSecretStore 是测试使用的并发安全解析器与注册器。
type oidcClientSecretStore struct {
	mu      sync.Mutex
	secrets map[string]string
	fail    error
}

// ClientSecret implements oauth2.ClientSecretResolver. | ClientSecret 实现 oauth2.ClientSecretResolver。
func (s *oidcClientSecretStore) ClientSecret(_ context.Context, client *oauth2.Client) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return "", s.fail
	}
	return s.secrets[client.ID], nil
}

// RegisterClientSecret implements oauth2.ClientSecretRegistrar. | RegisterClientSecret 实现
// oauth2.ClientSecretRegistrar。
func (s *oidcClientSecretStore) RegisterClientSecret(_ context.Context, clientID, secret string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return s.fail
	}
	if s.secrets == nil {
		s.secrets = make(map[string]string)
	}
	s.secrets[clientID] = secret
	return nil
}

// secret returns the stored secret for clientID. | secret 返回 clientID 的已保存密钥。
func (s *oidcClientSecretStore) secret(clientID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.secrets[clientID]
}

// setSecret seeds the resolver for a preconfigured client. | setSecret 为预配置客户端预置解析器密钥。
func (s *oidcClientSecretStore) setSecret(clientID, secret string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.secrets == nil {
		s.secrets = make(map[string]string)
	}
	s.secrets[clientID] = secret
}

// newClientSecretJWTOIDCFixture starts an OP whose OAuth server enables client_secret_jwt. When
// persist is true the registrar can accept dynamically issued secrets. |
// newClientSecretJWTOIDCFixture 启动 OAuth 服务器启用 client_secret_jwt 的 OP。persist 为真时，
// 注册器可接收动态签发的密钥。
func newClientSecretJWTOIDCFixture(t *testing.T, registration, persist bool) (*oidcFixture, *oidcClientSecretStore) {
	t.Helper()
	var handler = http.NotFoundHandler()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)

	signingKey, err := jose.GenerateKey("RS256", 2048)
	if err != nil {
		t.Fatalf("generate key: %v | 生成密钥：%v", err, err)
	}
	signingKey.Kid = "sig-1"
	signingKey.Alg = "RS256"
	signingKey.Use = "sig"
	keys := &jose.KeySet{}
	if err := keys.Add(signingKey); err != nil {
		t.Fatalf("add key: %v | 添加密钥：%v", err, err)
	}
	store := &oidcClientSecretStore{}
	secretConfig := &oauth2.ClientSecretJWTConfig{Resolver: store}
	if persist {
		secretConfig.Registrar = store
	}
	oauthServer, err := oauth2.NewServer(oauth2.ServerConfig{
		Issuer:          ts.URL,
		Clients:         oauth2.NewMemoryClientStore(),
		Store:           oauth2.NewMemoryStore(),
		Scopes:          oauth2.DefaultScopes(),
		ClientSecretJWT: secretConfig,
	})
	if err != nil {
		t.Fatalf("oauth server: %v | OAuth 服务器：%v", err, err)
	}
	provider, err := NewProvider(ProviderConfig{
		OAuth:              oauthServer,
		Keys:               keys,
		SigningKey:         signingKey,
		SigningAlg:         "RS256",
		EnableRegistration: registration,
		EnableLogout:       true,
	})
	if err != nil {
		t.Fatalf("provider: %v | 提供方：%v", err, err)
	}
	r := router.New()
	oauthServer.Register(r)
	provider.Register(r)
	handler = r
	return &oidcFixture{server: ts, oauth: oauthServer, provider: provider}, store
}

// signOIDCClientAssertion signs an RFC 7523 assertion for the OAuth server. |
// signOIDCClientAssertion 为 OAuth 服务器签发 RFC 7523 断言。
func signOIDCClientAssertion(t *testing.T, secret, alg, clientID, audience string, mutate func(map[string]any)) string {
	t.Helper()
	now := time.Now().UTC()
	claims := map[string]any{
		"iss": clientID,
		"sub": clientID,
		"aud": audience,
		"exp": now.Add(2 * time.Minute).Unix(),
		"iat": now.Unix(),
		"jti": "jti-" + clientID + "-" + alg + "-" + now.Format("150405.000000000"),
	}
	if mutate != nil {
		mutate(claims)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal assertion: %v | 编码断言：%v", err, err)
	}
	key, err := jose.FromHMAC("", []byte(secret))
	if err != nil {
		t.Fatalf("hmac key: %v | HMAC 密钥：%v", err, err)
	}
	assertion, err := jose.Sign(payload, key, jose.SignOptions{Alg: alg})
	if err != nil {
		t.Fatalf("sign assertion: %v | 签发断言：%v", err, err)
	}
	return assertion
}

// postClientSecretJWTToken performs a client_credentials token request with an assertion. |
// postClientSecretJWTToken 使用断言执行 client_credentials 令牌请求。
func postClientSecretJWTToken(t *testing.T, endpoint, clientID, assertion string) (*http.Response, map[string]any) {
	t.Helper()
	form := url.Values{
		"grant_type":            {oauth2.GrantClientCredentials},
		"client_id":             {clientID},
		"client_assertion":      {assertion},
		"client_assertion_type": {oauth2.ClientAssertionTypeJWTBearer},
	}
	resp, err := http.PostForm(endpoint, form)
	if err != nil {
		t.Fatalf("token request: %v | 令牌请求：%v", err, err)
	}
	defer resp.Body.Close()
	return resp, decodeOIDCBody(t, resp)
}

// decodeOIDCBody decodes a live HTTP response body. | decodeOIDCBody 解码真实 HTTP 响应正文。
func decodeOIDCBody(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v | 读取正文：%v", err, err)
	}
	out := make(map[string]any)
	if len(data) > 0 {
		if err := json.Unmarshal(data, &out); err != nil {
			t.Fatalf("decode body: %v | 解码正文：%v", err, err)
		}
	}
	return out
}

// TestOIDCRegistrationAcceptsClientSecretJWT verifies dynamic registration issues and persists a
// usable client_secret_jwt secret. | TestOIDCRegistrationAcceptsClientSecretJWT 校验动态注册签发并
// 保存可用的 client_secret_jwt 密钥。
func TestOIDCRegistrationAcceptsClientSecretJWT(t *testing.T) {
	fixture, store := newClientSecretJWTOIDCFixture(t, true, true)
	endpoint := fixture.server.URL + RegistrationPath
	body, err := json.Marshal(map[string]any{
		"grant_types":                     []string{oauth2.GrantClientCredentials},
		"token_endpoint_auth_method":      oauth2.ClientSecretJWT,
		"token_endpoint_auth_signing_alg": "HS256",
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, out := registrationCall(t, http.MethodPost, endpoint, string(body), "")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register = %d body=%v | 注册 = %d 正文 = %v", resp.StatusCode, out, resp.StatusCode, out)
	}
	clientID, _ := out["client_id"].(string)
	clientSecret, _ := out["client_secret"].(string)
	if clientID == "" || clientSecret == "" {
		t.Fatalf("registration response = %v | 注册响应 = %v", out, out)
	}
	if got := store.secret(clientID); got != clientSecret {
		t.Fatalf("registrar secret = %q, want response secret | 注册器密钥 = %q，期望响应密钥", got, got)
	}
	if len(clientSecret) != 86 {
		t.Fatalf("client_secret length = %d, want 86 base64url characters | client_secret 长度 = %d，期望 86 个 base64url 字符", len(clientSecret), len(clientSecret))
	}

	discovery := fixture.provider.DiscoveryDocument()
	if !oidcContains(discovery.TokenEndpointAuthMethodsSupported, oauth2.ClientSecretJWT) {
		t.Fatalf("discovery token methods = %v | 发现令牌方法 = %v", discovery.TokenEndpointAuthMethodsSupported, discovery.TokenEndpointAuthMethodsSupported)
	}
	if !oidcContains(discovery.TokenEndpointAuthSigningAlgValuesSupported, "HS256") {
		t.Fatalf("discovery signing algs = %v | 发现签名算法 = %v", discovery.TokenEndpointAuthSigningAlgValuesSupported, discovery.TokenEndpointAuthSigningAlgValuesSupported)
	}

	assertion := signOIDCClientAssertion(t, clientSecret, "HS256", clientID, discovery.TokenEndpoint, nil)
	tokenResp, tokenBody := postClientSecretJWTToken(t, discovery.TokenEndpoint, clientID, assertion)
	if tokenResp.StatusCode != http.StatusOK {
		t.Fatalf("token status = %d body=%v | 令牌状态 = %d 正文 = %v", tokenResp.StatusCode, tokenBody, tokenResp.StatusCode, tokenBody)
	}
	if tokenBody["access_token"] == "" || tokenBody["access_token"] == nil {
		t.Fatalf("access_token missing: %v | 缺少 access_token：%v", tokenBody, tokenBody)
	}
	// The jti is single use. | jti 只能使用一次。
	replayResp, replayBody := postClientSecretJWTToken(t, discovery.TokenEndpoint, clientID, assertion)
	if replayResp.StatusCode != http.StatusUnauthorized || replayBody["error"] != oauth2.ErrorInvalidClient {
		t.Fatalf("replay = %d body=%v | 重放 = %d 正文 = %v", replayResp.StatusCode, replayBody, replayResp.StatusCode, replayBody)
	}
}

// TestOIDCClientConfigurationSwitchesToClientSecretJWT verifies RFC 7592 PUT issues and persists a
// secret when switching a shared-secret client to client_secret_jwt. |
// TestOIDCClientConfigurationSwitchesToClientSecretJWT 校验把共享密钥客户端切换为
// client_secret_jwt 时，RFC 7592 PUT 会签发并保存密钥。
func TestOIDCClientConfigurationSwitchesToClientSecretJWT(t *testing.T) {
	fixture, store := newClientSecretJWTOIDCFixture(t, true, true)
	endpoint := fixture.server.URL + RegistrationPath
	body, err := json.Marshal(map[string]any{
		"grant_types":                []string{oauth2.GrantClientCredentials},
		"token_endpoint_auth_method": oauth2.ClientSecretPost,
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, out := registrationCall(t, http.MethodPost, endpoint, string(body), "")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register = %d body=%v | 注册 = %d 正文 = %v", resp.StatusCode, out, resp.StatusCode, out)
	}
	clientID, _ := out["client_id"].(string)
	registrationToken, _ := out["registration_access_token"].(string)
	managementURI, _ := out["registration_client_uri"].(string)
	if clientID == "" || registrationToken == "" || managementURI == "" {
		t.Fatalf("registration response = %v | 注册响应 = %v", out, out)
	}
	update, err := json.Marshal(map[string]any{
		"client_id":                       clientID,
		"grant_types":                     []string{oauth2.GrantClientCredentials},
		"token_endpoint_auth_method":      oauth2.ClientSecretJWT,
		"token_endpoint_auth_signing_alg": "HS256",
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, updated := registrationCall(t, http.MethodPut, managementURI, string(update), registrationToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update = %d body=%v | 更新 = %d 正文 = %v", resp.StatusCode, updated, resp.StatusCode, updated)
	}
	newSecret, _ := updated["client_secret"].(string)
	if newSecret == "" {
		t.Fatalf("update response has no client_secret: %v | 更新响应缺少 client_secret：%v", updated, updated)
	}
	if got := store.secret(clientID); got != newSecret {
		t.Fatalf("registrar secret = %q, want update secret | 注册器密钥 = %q，期望更新密钥", got, got)
	}
	discovery := fixture.provider.DiscoveryDocument()
	assertion := signOIDCClientAssertion(t, newSecret, "HS256", clientID, discovery.TokenEndpoint, nil)
	tokenResp, tokenBody := postClientSecretJWTToken(t, discovery.TokenEndpoint, clientID, assertion)
	if tokenResp.StatusCode != http.StatusOK {
		t.Fatalf("token status = %d body=%v | 令牌状态 = %d 正文 = %v", tokenResp.StatusCode, tokenBody, tokenResp.StatusCode, tokenBody)
	}
}

// TestOIDCRegistrationClientSecretJWTWithoutRegistrar verifies registration is refused when the
// issued secret could not reach the resolver, while a preconfigured client still authenticates. |
// TestOIDCRegistrationClientSecretJWTWithoutRegistrar 校验无法把签发密钥送达解析器时拒绝注册，
// 同时预配置客户端仍可认证。
func TestOIDCRegistrationClientSecretJWTWithoutRegistrar(t *testing.T) {
	fixture, store := newClientSecretJWTOIDCFixture(t, true, false)
	endpoint := fixture.server.URL + RegistrationPath
	body, err := json.Marshal(map[string]any{
		"grant_types":                []string{oauth2.GrantClientCredentials},
		"token_endpoint_auth_method": oauth2.ClientSecretJWT,
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, out := registrationCall(t, http.MethodPost, endpoint, string(body), "")
	if resp.StatusCode != http.StatusBadRequest || out["error"] != "invalid_client_metadata" {
		t.Fatalf("register = %d body=%v | 注册 = %d 正文 = %v", resp.StatusCode, out, resp.StatusCode, out)
	}
	description, _ := out["error_description"].(string)
	if !strings.Contains(description, "client_secret_jwt") || !strings.Contains(description, "preconfigured") {
		t.Fatalf("error_description = %q | error_description = %q", description, description)
	}

	preconfigured := &oauth2.Client{
		ID:                      "preconfigured-hs",
		GrantTypes:              []string{oauth2.GrantClientCredentials},
		TokenEndpointAuthMethod: oauth2.ClientSecretJWT,
	}
	if err := fixture.oauth.Config().Clients.CreateClient(context.Background(), preconfigured); err != nil {
		t.Fatalf("create preconfigured client: %v | 创建预配置客户端：%v", err, err)
	}
	store.setSecret(preconfigured.ID, testClientSecretJWTSecret)
	discovery := fixture.provider.DiscoveryDocument()
	if !oidcContains(discovery.TokenEndpointAuthMethodsSupported, oauth2.ClientSecretJWT) {
		t.Fatalf("discovery token methods = %v | 发现令牌方法 = %v", discovery.TokenEndpointAuthMethodsSupported, discovery.TokenEndpointAuthMethodsSupported)
	}
	assertion := signOIDCClientAssertion(t, testClientSecretJWTSecret, "HS512", preconfigured.ID, discovery.TokenEndpoint, nil)
	tokenResp, tokenBody := postClientSecretJWTToken(t, discovery.TokenEndpoint, preconfigured.ID, assertion)
	if tokenResp.StatusCode != http.StatusOK {
		t.Fatalf("token status = %d body=%v | 令牌状态 = %d 正文 = %v", tokenResp.StatusCode, tokenBody, tokenResp.StatusCode, tokenBody)
	}
}

// TestOIDCDiscoveryClientSecretJWTAdvertising verifies the method is advertised only when enabled
// on every client-authentication endpoint. | TestOIDCDiscoveryClientSecretJWTAdvertising 校验仅在
// 启用时才在每个客户端认证端点上公布该方法。
func TestOIDCDiscoveryClientSecretJWTAdvertising(t *testing.T) {
	disabled := newOIDCFixture(t, true)
	document := disabled.provider.DiscoveryDocument()
	if oidcContains(document.TokenEndpointAuthMethodsSupported, oauth2.ClientSecretJWT) {
		t.Fatalf("disabled discovery advertises client_secret_jwt: %v", document.TokenEndpointAuthMethodsSupported)
	}
	if oidcContains(document.TokenEndpointAuthSigningAlgValuesSupported, "HS256") {
		t.Fatalf("disabled discovery advertises HS256: %v", document.TokenEndpointAuthSigningAlgValuesSupported)
	}

	enabled, _ := newClientSecretJWTOIDCFixture(t, true, false)
	document = enabled.provider.DiscoveryDocument()
	for name, methods := range map[string][]string{
		"token":         document.TokenEndpointAuthMethodsSupported,
		"revocation":    document.RevocationEndpointAuthMethodsSupported,
		"introspection": document.IntrospectionEndpointAuthMethodsSupported,
	} {
		if !oidcContains(methods, oauth2.ClientSecretJWT) {
			t.Fatalf("%s methods = %v | %s 方法 = %v", name, methods, name, methods)
		}
	}
	for _, alg := range []string{"HS256", "HS384", "HS512"} {
		if !oidcContains(document.TokenEndpointAuthSigningAlgValuesSupported, alg) {
			t.Fatalf("%s missing from %v | %s 缺失于 %v", alg, document.TokenEndpointAuthSigningAlgValuesSupported, alg, document.TokenEndpointAuthSigningAlgValuesSupported)
		}
	}
}

// oidcContains reports whether values contains want. | oidcContains 报告 values 是否包含 want。
func oidcContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
