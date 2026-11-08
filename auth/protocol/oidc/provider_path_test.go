package oidc

import (
	"net/http"
	"testing"

	"github.com/shibingli/ydx/auth/protocol/oauth2"
	"github.com/shibingli/ydx/auth/token/jose"
)

// pathIssuerProvider builds a provider whose issuer carries a path component. |
// pathIssuerProvider 构建 issuer 带路径部分的提供方。
func pathIssuerProvider(t *testing.T) (*Provider, *oauth2.Server) {
	t.Helper()
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
	oauthServer, err := oauth2.NewServer(oauth2.ServerConfig{
		Issuer:  "https://op.example/idp",
		Clients: oauth2.NewMemoryClientStore(),
		Store:   oauth2.NewMemoryStore(),
		Scopes:  oauth2.DefaultScopes(),
	})
	if err != nil {
		t.Fatalf("oauth server: %v | OAuth 服务器：%v", err, err)
	}
	provider, err := NewProvider(ProviderConfig{
		OAuth:              oauthServer,
		Keys:               keys,
		SigningKey:         signingKey,
		SigningAlg:         "RS256",
		EnableRegistration: true,
		EnableLogout:       true,
		SessionManagement:  true,
	})
	if err != nil {
		t.Fatalf("provider: %v | 提供方：%v", err, err)
	}
	return provider, oauthServer
}

// TestProviderEndpointsWithIssuerPath verifies that provider and discovery URLs do not repeat the
// issuer path component. | TestProviderEndpointsWithIssuerPath 校验提供方与发现文档 URL 不会重复
// issuer 的路径部分。
func TestProviderEndpointsWithIssuerPath(t *testing.T) {
	provider, oauthServer := pathIssuerProvider(t)
	if got := provider.Endpoint("keys"); got != "https://op.example/idp/keys" {
		t.Fatalf("provider endpoint = %q | 提供方端点 = %q", got, got)
	}
	oauthDocument := oauthServer.MetadataDocument()
	if oauthDocument.JWKSURI != "https://op.example/idp/jwks" {
		t.Fatalf("JWKS URI = %q | JWKS URI = %q", oauthDocument.JWKSURI, oauthDocument.JWKSURI)
	}
	if oauthDocument.RegistrationEndpoint != "https://op.example/idp/register" {
		t.Fatalf("registration endpoint = %q | 注册端点 = %q", oauthDocument.RegistrationEndpoint, oauthDocument.RegistrationEndpoint)
	}
	document := provider.DiscoveryDocument()
	checks := map[string]string{
		"token":              document.TokenEndpoint,
		"authorization":      document.AuthorizationEndpoint,
		"userinfo":           document.UserInfoEndpoint,
		"end session":        document.EndSessionEndpoint,
		"check session":      document.CheckSessionIframe,
		"registration":       document.RegistrationEndpoint,
		"jwks":               document.JWKSURI,
		"end session URL":    provider.EndSessionURL("", "", "", ""),
		"registration token": provider.Endpoint(provider.config.RegistrationPath),
	}
	wants := map[string]string{
		"token":              "https://op.example/idp/token",
		"authorization":      "https://op.example/idp/authorize",
		"userinfo":           "https://op.example/idp/userinfo",
		"end session":        "https://op.example/idp/logout",
		"check session":      "https://op.example/idp/check_session",
		"registration":       "https://op.example/idp/register",
		"jwks":               "https://op.example/idp/jwks",
		"end session URL":    "https://op.example/idp/logout",
		"registration token": "https://op.example/idp/register",
	}
	for name, got := range checks {
		if got != wants[name] {
			t.Fatalf("%s URL = %q, want %q | %s URL = %q，期望 %q", name, got, wants[name], name, got, wants[name])
		}
	}
}

// TestRegistrationPutReplacesInlineJWKS verifies that an RFC 7592 PUT is a full metadata
// replacement: an inline jwks from the original registration must not survive a PUT that selects
// jwks_uri. | TestRegistrationPutReplacesInlineJWKS 校验 RFC 7592 PUT 是完整元数据替换：原注册中的
// 内联 jwks 不得在改用 jwks_uri 的 PUT 后残留。
func TestRegistrationPutReplacesInlineJWKS(t *testing.T) {
	fixture := newOIDCFixture(t, true)
	endpoint := fixture.server.URL + RegistrationPath
	const metadata = `{
		"redirect_uris":["https://rp.example/callback"],
		"grant_types":["authorization_code"],
		"response_types":["code"],
		"scope":"openid",
		"token_endpoint_auth_method":"client_secret_basic",
		"jwks":{"keys":[{"kty":"RSA","kid":"k1","n":"AQAB","e":"AQAB"}]}
	}`
	resp, registered := registrationCall(t, http.MethodPost, endpoint, metadata, "")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register = %d body=%v | 注册 = %d，正文 = %v", resp.StatusCode, registered, resp.StatusCode, registered)
	}
	if _, ok := registered["jwks"]; !ok {
		t.Fatalf("registered metadata lost jwks: %v | 注册元数据丢失 jwks：%v", registered, registered)
	}
	clientID, _ := registered["client_id"].(string)
	registrationToken, _ := registered["registration_access_token"].(string)
	clientURI, _ := registered["registration_client_uri"].(string)
	if clientID == "" || registrationToken == "" || clientURI == "" {
		t.Fatalf("registration response = %v | 注册响应 = %v", registered, registered)
	}
	update := `{
		"client_id":"` + clientID + `",
		"redirect_uris":["https://rp.example/callback"],
		"grant_types":["authorization_code"],
		"response_types":["code"],
		"scope":"openid",
		"token_endpoint_auth_method":"client_secret_basic",
		"jwks_uri":"https://rp.example/jwks.json"
	}`
	resp, updated := registrationCall(t, http.MethodPut, clientURI, update, registrationToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update = %d body=%v | 更新 = %d，正文 = %v", resp.StatusCode, updated, resp.StatusCode, updated)
	}
	if _, ok := updated["jwks"]; ok {
		t.Fatalf("PUT retained the replaced inline jwks: %v | PUT 保留了应被替换的内联 jwks：%v", updated, updated)
	}
	if updated["jwks_uri"] != "https://rp.example/jwks.json" {
		t.Fatalf("jwks_uri = %v | jwks_uri = %v", updated["jwks_uri"], updated["jwks_uri"])
	}
	resp, current := registrationCall(t, http.MethodGet, clientURI, "", registrationToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("read = %d body=%v | 读取 = %d，正文 = %v", resp.StatusCode, current, resp.StatusCode, current)
	}
	if _, ok := current["jwks"]; ok {
		t.Fatalf("stored client retained the replaced inline jwks: %v | 存储的客户端保留了应被替换的内联 jwks：%v", current, current)
	}
	if current["jwks_uri"] != "https://rp.example/jwks.json" {
		t.Fatalf("stored jwks_uri = %v | 存储的 jwks_uri = %v", current["jwks_uri"], current["jwks_uri"])
	}
}
