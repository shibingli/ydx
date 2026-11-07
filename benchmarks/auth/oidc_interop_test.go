package auth

import (
	"context"
	"crypto/sha256"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	gojose "github.com/go-jose/go-jose/v4"
	"github.com/shibingli/ydx/auth"
	ydoauth2 "github.com/shibingli/ydx/auth/protocol/oauth2"
	ydoidc "github.com/shibingli/ydx/auth/protocol/oidc"
	"github.com/shibingli/ydx/auth/token/jose"
	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/json"
	"github.com/shibingli/ydx/router"
	xoauth2 "golang.org/x/oauth2"
)

// oidcIssuer starts a ydx OpenID Provider with one auto-approving client. |
// oidcIssuer 启动带一个自动同意客户端的 ydx OpenID Provider。
func oidcIssuer(t *testing.T) (issuer, clientID, clientSecret string) {
	t.Helper()
	var handler http.Handler = http.NotFoundHandler()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)

	key, err := jose.GenerateKey("RS256", 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	key.Kid = "sig-1"
	key.Alg = "RS256"
	key.Use = "sig"
	keys := &jose.KeySet{}
	if err := keys.Add(key); err != nil {
		t.Fatalf("KeySet.Add: %v", err)
	}
	client := &ydoauth2.Client{
		ID:                      "web",
		RedirectURIs:            []string{"https://rp.example/callback"},
		GrantTypes:              []string{ydoauth2.GrantAuthorizationCode, ydoauth2.GrantRefreshToken},
		ResponseTypes:           []string{ydoauth2.ResponseCode},
		Scopes:                  []string{ydoidc.ScopeOpenID, ydoidc.ScopeProfile, ydoidc.ScopeEmail, ydoidc.ScopeOfflineAccess},
		TokenEndpointAuthMethod: ydoauth2.ClientSecretBasic,
	}
	client.SetSecret("rp-secret")
	oauthServer, err := ydoauth2.NewServer(ydoauth2.ServerConfig{
		Issuer:  server.URL,
		Clients: ydoauth2.NewMemoryClientStore(client),
		Store:   ydoauth2.NewMemoryStore(),
		Scopes:  ydoauth2.DefaultScopes(),
		Authenticator: ydoauth2.AuthenticatorFunc(func(context.Context, http.ResponseWriter, *http.Request, *ydoauth2.AuthorizationRequest) (*auth.Principal, error) {
			return &auth.Principal{
				Subject:       "user-1",
				Email:         "alice@example.com",
				EmailVerified: true,
				Username:      "alice",
				DisplayName:   "Alice",
				AuthTime:      time.Now().UTC(),
				AMR:           []string{"pwd"},
			}, nil
		}),
		AccessTokenTTL: time.Minute,
	})
	if err != nil {
		t.Fatalf("ydoauth2.NewServer: %v", err)
	}
	provider, err := ydoidc.NewProvider(ydoidc.ProviderConfig{
		OAuth:      oauthServer,
		Keys:       keys.Public(),
		SigningKey: key,
		SigningAlg: "RS256",
	})
	if err != nil {
		t.Fatalf("oidc.NewProvider: %v", err)
	}
	r := router.New()
	oauthServer.Register(r)
	provider.Register(r)
	handler = r
	return server.URL, "web", "rp-secret"
}

// TestOIDCInteropWithCoreOS runs discovery, authorization code + PKCE, token exchange and ID token
// verification using github.com/coreos/go-oidc/v3 as the relying party. |
// TestOIDCInteropWithCoreOS 使用 github.com/coreos/go-oidc/v3 作为依赖方，走完发现、授权码 + PKCE、
// 令牌交换与 ID token 校验。
func TestOIDCInteropWithCoreOS(t *testing.T) {
	issuer, clientID, clientSecret := oidcIssuer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	provider, err := coreoidc.NewProvider(ctx, issuer)
	if err != nil {
		t.Fatalf("coreos discovery: %v", err)
	}
	if provider.Endpoint().AuthURL == "" || provider.Endpoint().TokenURL == "" {
		t.Fatalf("discovery returned empty endpoints: %+v | 发现文档端点为��", provider.Endpoint())
	}
	conf := &xoauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  "https://rp.example/callback",
		Scopes:       []string{"openid", "profile", "email"},
	}
	verifier := "ydx-benchmark-pkce-verifier-0123456789abcdef"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	authURL := conf.AuthCodeURL("state-1",
		xoauth2.SetAuthURLParam("code_challenge", challenge),
		xoauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
	httpClient := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	response, err := httpClient.Get(authURL)
	if err != nil {
		t.Fatalf("authorize request: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	location := response.Header.Get("Location")
	if location == "" {
		t.Fatalf("authorize status = %d, want redirect | 授权端点未重定向", response.StatusCode)
	}
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	query := parsed.Query()
	if query.Get("state") != "state-1" {
		t.Fatalf("state = %q, want state-1 | state 不一致", query.Get("state"))
	}
	code := query.Get("code")
	if code == "" {
		t.Fatalf("redirect has no code: %s | 重定向缺少授权码", location)
	}
	token, err := conf.Exchange(ctx, code, xoauth2.SetAuthURLParam("code_verifier", verifier))
	if err != nil {
		t.Fatalf("token exchange: %v", err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		t.Fatalf("token response has no id_token | 令牌响应缺少 id_token")
	}
	if parts := strings.Split(rawIDToken, "."); len(parts) == 3 {
		header, _ := base64.RawURLEncoding.DecodeString(parts[0])
		claims, _ := base64.RawURLEncoding.DecodeString(parts[1])
		t.Logf("id_token header: %s", header)
		t.Logf("id_token claims: %s", claims)
	}
	jwksResponse, err := http.Get(issuer + "/jwks")
	if err != nil {
		t.Fatalf("jwks fetch: %v", err)
	}
	jwksBody, _ := io.ReadAll(jwksResponse.Body)
	_ = jwksResponse.Body.Close()
	var set gojose.JSONWebKeySet
	if err := json.Unmarshal(jwksBody, &set); err != nil {
		t.Fatalf("go-jose JWKS parse: %v", err)
	}
	keys := set.Key("sig-1")
	if len(keys) == 0 {
		t.Fatalf("JWKS has no signing key: %s | JWKS 缺少签名密钥", jwksBody)
	}
	parsedToken, err := gojose.ParseSigned(rawIDToken, []gojose.SignatureAlgorithm{gojose.RS256})
	if err != nil {
		t.Fatalf("go-jose parse ID token: %v", err)
	}
	if _, err := parsedToken.Verify(keys[0].Key); err != nil {
		t.Fatalf("go-jose ID token verification: %v", err)
	}
	idToken, err := provider.Verifier(&coreoidc.Config{ClientID: clientID}).Verify(ctx, rawIDToken)
	if err != nil {
		t.Fatalf("coreos ID token verification: %v", err)
	}
	var claims struct {
		Subject       string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := idToken.Claims(&claims); err != nil {
		t.Fatalf("claims: %v", err)
	}
	if claims.Subject != "user-1" || claims.Email != "alice@example.com" || !claims.EmailVerified {
		t.Fatalf("unexpected claims: %+v | 声明不符合预期", claims)
	}
	userInfo, err := provider.UserInfo(ctx, xoauth2.StaticTokenSource(token))
	if err != nil {
		t.Fatalf("coreos UserInfo: %v", err)
	}
	var info struct {
		Subject string `json:"sub"`
		Email   string `json:"email"`
	}
	if err := userInfo.Claims(&info); err != nil {
		t.Fatalf("UserInfo claims: %v", err)
	}
	if info.Subject != "user-1" || info.Email != "alice@example.com" {
		t.Fatalf("unexpected UserInfo claims: %+v | UserInfo 声明不符合预期", info)
	}
}
