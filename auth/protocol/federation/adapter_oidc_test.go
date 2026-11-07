package federation

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/shibingli/ydx/auth/protocol/oauth2"
	"github.com/shibingli/ydx/auth/protocol/oidc"
	"github.com/shibingli/ydx/base64"
)

// assertErrorIs requires err to match every sentinel with errors.Is. | assertErrorIs 要求 err
// 通过 errors.Is 匹配每个哨兵错误。
func assertErrorIs(t *testing.T, err error, sentinels ...error) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error matching %v, got nil | 期望匹配 %v 的错误，实际为 nil", sentinels, sentinels)
	}
	for _, sentinel := range sentinels {
		if !errors.Is(err, sentinel) {
			t.Fatalf("error %q does not match %v | 错误 %q 不匹配 %v", err, sentinel, err, sentinel)
		}
	}
}

// assertErrorMentions requires err to contain every fragment. | assertErrorMentions 要求 err
// 包含每个片段。
func assertErrorMentions(t *testing.T, err error, fragments ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error mentioning %v, got nil | 期望包含 %v 的错误，实际为 nil", fragments, fragments)
	}
	for _, fragment := range fragments {
		if !strings.Contains(err.Error(), fragment) {
			t.Fatalf("error %q does not mention %q | 错误 %q 未包含 %q", err, fragment, err, fragment)
		}
	}
}

// assertNoSecrets fails when the error text contains configured secrets or a compact JWT.
// assertNoSecrets 在错误文本包含配置的密钥或紧凑 JWT 时失败。
func assertNoSecrets(t *testing.T, err error, extras ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error carrying no secrets, got nil | 期望不含密钥的错误，实际为 nil")
	}
	secrets := []string{
		oidcFixtureClientSecret,
		oidcFixtureAccessToken,
		"discovery_secret",
		"jwks_secret",
		"super-secret-description",
	}
	secrets = append(secrets, extras...)
	message := err.Error()
	for _, secret := range secrets {
		if strings.Contains(message, secret) {
			t.Fatalf("error %q leaks %q | 错误 %q 泄露 %q", message, secret, message, secret)
		}
	}
	if strings.Contains(message, "eyJ") {
		t.Fatalf("error %q leaks a compact JWT | 错误 %q 泄露紧凑 JWT", message, message)
	}
}

// TestOIDCExchangeAndUserInfo verifies the complete local OpenID Connect flow. | TestOIDCExchangeAndUserInfo
// 校验完整的本地 OpenID Connect 流程。
func TestOIDCExchangeAndUserInfo(t *testing.T) {
	fixture := newOIDCFixture(t)
	p := fixture.provider("oidc", WithScopes("openid", "email", "profile"))
	p.UserInfoHeaders = map[string]string{"X-Fixture": "userinfo"}
	adapter := newAdapter(p, nil)

	const nonce = "fixture-nonce"
	authURL, err := adapter.AuthCodeURL("state-1", nonce, "")
	if err != nil {
		t.Fatalf("AuthCodeURL: %v", err)
	}
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse auth URL: %v", err)
	}
	query := parsed.Query()
	for key, want := range map[string]string{
		"response_type": "code",
		"client_id":     oidcFixtureClientID,
		"scope":         "openid email profile",
		"state":         "state-1",
		"nonce":         nonce,
	} {
		if got := query.Get(key); got != want {
			t.Fatalf("auth URL %s=%q want %q | 授权 URL %s=%q 期望 %q", key, got, want, key, got, want)
		}
	}
	if strings.Contains(authURL, oidcFixtureClientSecret) {
		t.Fatal("authorization URL leaks the client secret | 授权 URL 泄露客户端密钥")
	}

	token, err := adapter.Exchange(context.Background(), "authorization-code", "")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if token.AccessToken != oidcFixtureAccessToken {
		t.Fatalf("access token = %q | 访问令牌 = %[1]q", token.AccessToken)
	}
	if token.TokenType != "Bearer" || token.RefreshToken != "oidc-refresh-token" {
		t.Fatalf("unexpected token metadata: %+v | 令牌元数据异常：%+v", token, token)
	}
	if token.ExpiresIn != 3600 || token.Expiry.IsZero() {
		t.Fatalf("expiry not mapped: expires_in=%d expiry=%v | 过期时间未映射：expires_in=%d expiry=%v", token.ExpiresIn, token.Expiry, token.ExpiresIn, token.Expiry)
	}
	if token.IDToken == "" || token.Claims == nil {
		t.Fatalf("ID token not verified: %+v | ID 令牌未校验：%+v", token, token)
	}
	for key, want := range map[string]string{
		"sub":                "oidc-subject",
		"iss":                fixture.issuer,
		"email":              "oidc@example.com",
		"email_verified":     "true",
		"name":               "OIDC Subject",
		"preferred_username": "oidc-user",
	} {
		if got := token.Claims[key]; got != want {
			t.Fatalf("claims[%s] = %q want %q | claims[%s] = %q 期望 %q", key, got, want, key, got, want)
		}
	}
	if _, ok := token.Claims["exp"]; !ok {
		t.Fatal("claims do not retain exp | 声明未保留 exp")
	}

	form, headers := fixture.lastTokenRequest()
	if got := form.Get("grant_type"); got != "authorization_code" {
		t.Fatalf("grant_type = %q | grant_type = %[1]q", got)
	}
	if got := form.Get("code"); got != "authorization-code" {
		t.Fatalf("code = %q | code = %[1]q", got)
	}
	if got := form.Get("client_secret"); got != oidcFixtureClientSecret {
		t.Fatalf("post auth style did not send client_secret | post 认证方式未发送 client_secret")
	}
	if headers.Get("Authorization") != "" {
		t.Fatalf("post auth style sent Authorization: %q | post 认证方式发送了 Authorization：%[1]q", headers.Get("Authorization"))
	}
	if got := headers.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
		t.Fatalf("content type = %q | 内容类型 = %[1]q", got)
	}

	discoveryCalls, jwksCalls, tokenCalls, userInfoCalls := fixture.counts()
	if discoveryCalls != 0 || jwksCalls != 1 || tokenCalls != 1 || userInfoCalls != 0 {
		t.Fatalf("unexpected request counts: discovery=%d jwks=%d token=%d userinfo=%d | 请求计数异常：discovery=%d jwks=%d token=%d userinfo=%d",
			discoveryCalls, jwksCalls, tokenCalls, userInfoCalls, discoveryCalls, jwksCalls, tokenCalls, userInfoCalls)
	}

	identity, err := adapter.UserInfo(context.Background(), token)
	if err != nil {
		t.Fatalf("UserInfo: %v", err)
	}
	if identity.Provider != "oidc" || identity.Subject != "oidc-subject" {
		t.Fatalf("identity provider/subject = %q/%q | 身份 provider/subject = %q/%q", identity.Provider, identity.Subject, identity.Provider, identity.Subject)
	}
	if identity.Email != "userinfo@example.com" || !identity.EmailVerified {
		t.Fatalf("UserInfo email not applied: %+v | UserInfo 邮箱未生效：%+v", identity, identity)
	}
	if identity.Name != "UserInfo Name" {
		t.Fatalf("UserInfo name = %q | UserInfo 名称 = %[1]q", identity.Name)
	}
	if identity.Username != "oidc-user" {
		t.Fatalf("username fallback = %q want oidc-user | 用户名回退 = %q 期望 oidc-user", identity.Username, identity.Username)
	}
	if identity.AvatarURL != "https://example.com/userinfo.png" {
		t.Fatalf("avatar = %q | 头像 = %[1]q", identity.AvatarURL)
	}
	if identity.Raw["preferred_username"] != "oidc-user" {
		t.Fatalf("claims were not merged into raw: %v | 声明未合并进 raw：%v", identity.Raw, identity.Raw)
	}

	headers = fixture.lastUserInfoRequest()
	if got := headers.Get("Authorization"); got != "Bearer "+oidcFixtureAccessToken {
		t.Fatalf("UserInfo Authorization = %q | UserInfo Authorization = %[1]q", got)
	}
	if got := headers.Get("X-Fixture"); got != "userinfo" {
		t.Fatalf("custom UserInfo header = %q | 自定义 UserInfo 头 = %[1]q", got)
	}
}

// TestOIDCMultiAudienceAZP verifies aud/azp rules for multi-audience ID tokens. | TestOIDCMultiAudienceAZP
// 校验多受众 ID 令牌的 aud/azp 规则。
func TestOIDCMultiAudienceAZP(t *testing.T) {
	t.Run("matching azp", func(t *testing.T) {
		fixture := newOIDCFixture(t)
		fixture.set(func(c *oidcFixtureConfig) {
			c.claims["aud"] = []string{oidcFixtureClientID, "second-client"}
			c.claims["azp"] = oidcFixtureClientID
		})
		adapter := newAdapter(fixture.provider("oidc"), nil)
		if _, err := adapter.Exchange(context.Background(), "code", ""); err != nil {
			t.Fatalf("Exchange: %v", err)
		}
	})

	t.Run("missing azp", func(t *testing.T) {
		fixture := newOIDCFixture(t)
		fixture.set(func(c *oidcFixtureConfig) {
			c.claims["aud"] = []string{oidcFixtureClientID, "second-client"}
		})
		adapter := newAdapter(fixture.provider("oidc"), nil)
		_, err := adapter.Exchange(context.Background(), "code", "")
		assertErrorIs(t, err, ErrTokenExchange, oidc.ErrInvalidAudience)
		assertNoSecrets(t, err)
	})

	t.Run("wrong azp", func(t *testing.T) {
		fixture := newOIDCFixture(t)
		fixture.set(func(c *oidcFixtureConfig) {
			c.claims["aud"] = []string{oidcFixtureClientID, "second-client"}
			c.claims["azp"] = "second-client"
		})
		adapter := newAdapter(fixture.provider("oidc"), nil)
		_, err := adapter.Exchange(context.Background(), "code", "")
		assertErrorIs(t, err, ErrTokenExchange, oidc.ErrInvalidAudience)
		assertNoSecrets(t, err)
	})
}

// TestOIDCDiscoveryProviderCaches verifies discovery and JWKS caching across exchanges.
// TestOIDCDiscoveryProviderCaches 校验多次兑换之间的发现文档与 JWKS 缓存。
func TestOIDCDiscoveryProviderCaches(t *testing.T) {
	fixture := newOIDCFixture(t)
	adapter := newAdapter(fixture.discoveryProvider("oidc-discovery"), nil)

	authURL, err := adapter.AuthCodeURL("state", "nonce", "")
	if err != nil {
		t.Fatalf("AuthCodeURL: %v", err)
	}
	if !strings.HasPrefix(authURL, fixture.server.URL+"/authorize?") {
		t.Fatalf("discovered authorization endpoint not used: %q | 未使用发现到的授权端点：%[1]q", authURL)
	}
	if discoveryCalls, _, _, _ := fixture.counts(); discoveryCalls != 1 {
		t.Fatalf("discovery calls after AuthCodeURL = %d want 1 | AuthCodeURL 后发现调用 = %d 期望 1", discoveryCalls, discoveryCalls)
	}

	for attempt := 1; attempt <= 2; attempt++ {
		token, err := adapter.Exchange(context.Background(), "code", "")
		if err != nil {
			t.Fatalf("Exchange %d: %v | 第 %d 次兑换：%v", attempt, err, attempt, err)
		}
		if token.Claims["sub"] != "oidc-subject" {
			t.Fatalf("Exchange %d claims sub = %q | 第 %d 次兑换 claims sub = %q", attempt, token.Claims["sub"], attempt, token.Claims["sub"])
		}
	}
	discoveryCalls, jwksCalls, tokenCalls, _ := fixture.counts()
	if discoveryCalls != 1 {
		t.Fatalf("discovery calls = %d want 1 (cached) | 发现调用 = %d 期望 1（已缓存）", discoveryCalls, discoveryCalls)
	}
	if jwksCalls != 1 {
		t.Fatalf("JWKS calls = %d want 1 (cached) | JWKS 调用 = %d 期望 1（已缓存）", jwksCalls, jwksCalls)
	}
	if tokenCalls != 2 {
		t.Fatalf("token calls = %d want 2 | 令牌调用 = %d 期望 2", tokenCalls, tokenCalls)
	}

	token, err := adapter.Exchange(context.Background(), "code", "")
	if err != nil {
		t.Fatalf("third Exchange: %v", err)
	}
	identity, err := adapter.UserInfo(context.Background(), token)
	if err != nil {
		t.Fatalf("UserInfo: %v", err)
	}
	if identity.Subject != "oidc-subject" {
		t.Fatalf("discovered UserInfo subject = %q | 发现到的 UserInfo 主体 = %[1]q", identity.Subject)
	}
	if _, _, _, userInfoCalls := fixture.counts(); userInfoCalls != 1 {
		t.Fatalf("UserInfo calls = %d want 1 | UserInfo 调用 = %d 期望 1", userInfoCalls, userInfoCalls)
	}
}

// TestOIDCAuthCodeURLBranches verifies PKCE, AuthParams and hook handling. | TestOIDCAuthCodeURLBranches
// 校验 PKCE、AuthParams 与钩子处理。
func TestOIDCAuthCodeURLBranches(t *testing.T) {
	fixture := newOIDCFixture(t)

	t.Run("pkce", func(t *testing.T) {
		p := fixture.provider("oidc", WithScopes("openid"), WithPKCE(true))
		adapter := newAdapter(p, nil)
		const verifier = "fixture-pkce-verifier-0123456789"
		authURL, err := adapter.AuthCodeURL("state", "nonce", verifier)
		if err != nil {
			t.Fatalf("AuthCodeURL: %v", err)
		}
		parsed, err := url.Parse(authURL)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if got, want := parsed.Query().Get("code_challenge"), oauth2.CodeChallengeS256(verifier); got != want {
			t.Fatalf("code_challenge = %q want %q | code_challenge = %q 期望 %q", got, want, got, want)
		}
		if got := parsed.Query().Get("code_challenge_method"); got != "S256" {
			t.Fatalf("code_challenge_method = %q | code_challenge_method = %[1]q", got)
		}
	})

	t.Run("pkce empty verifier", func(t *testing.T) {
		p := fixture.provider("oidc", WithPKCE(true))
		adapter := newAdapter(p, nil)
		_, err := adapter.AuthCodeURL("state", "nonce", "")
		assertErrorIs(t, err, ErrInvalidRequest)
	})

	t.Run("auth params", func(t *testing.T) {
		p := fixture.provider("oidc", WithScopes("openid", "email"), WithAuthParams(map[string]string{
			"prompt":      "consent",
			"access_type": "offline",
		}))
		p.ScopeSeparator = ","
		adapter := newAdapter(p, nil)
		authURL, err := adapter.AuthCodeURL("state", "nonce", "")
		if err != nil {
			t.Fatalf("AuthCodeURL: %v", err)
		}
		parsed, _ := url.Parse(authURL)
		query := parsed.Query()
		if query.Get("prompt") != "consent" || query.Get("access_type") != "offline" {
			t.Fatalf("AuthParams missing: %q | AuthParams 缺失：%q", parsed.RawQuery, parsed.RawQuery)
		}
		if got := query.Get("scope"); got != "openid,email" {
			t.Fatalf("scope separator ignored: %q | 作用域分隔符未生效：%[1]q", got)
		}
	})

	t.Run("hook skips discovery", func(t *testing.T) {
		p := fixture.discoveryProvider("oidc")
		p.AuthURLHook = func(provider *Provider, state, nonce, verifier string) (string, error) {
			return "https://hook.example/authorize?state=" + state + "&nonce=" + nonce, nil
		}
		adapter := newAdapter(p, nil)
		authURL, err := adapter.AuthCodeURL("hooked", "hook-nonce", "")
		if err != nil {
			t.Fatalf("AuthCodeURL: %v", err)
		}
		if !strings.HasPrefix(authURL, "https://hook.example/authorize?") {
			t.Fatalf("hook URL not used: %q | 未使用钩子 URL：%[1]q", authURL)
		}
		if discoveryCalls, _, _, _ := fixture.counts(); discoveryCalls != 0 {
			t.Fatalf("hook path performed discovery %d times | 钩子路径执行了 %d 次发现", discoveryCalls, discoveryCalls)
		}
	})

	t.Run("invalid endpoint", func(t *testing.T) {
		p := fixture.provider("oidc")
		p.AuthURL = "://invalid"
		adapter := newAdapter(p, nil)
		_, err := adapter.AuthCodeURL("state", "nonce", "")
		assertErrorIs(t, err, ErrProviderConfig)
	})
}

// TestOIDCTokenRequestBranches verifies auth styles, TokenParams and code_verifier. | TestOIDCTokenRequestBranches
// 校验认证方式、TokenParams 与 code_verifier。
func TestOIDCTokenRequestBranches(t *testing.T) {
	t.Run("post style", func(t *testing.T) {
		fixture := newOIDCFixture(t)
		adapter := newAdapter(fixture.provider("oidc"), nil)
		if _, err := adapter.Exchange(context.Background(), "code", ""); err != nil {
			t.Fatalf("Exchange: %v", err)
		}
		form, headers := fixture.lastTokenRequest()
		if form.Get("client_secret") != oidcFixtureClientSecret || headers.Get("Authorization") != "" {
			t.Fatalf("post style form=%q auth=%q | post 方式 form=%q auth=%q", form.Encode(), headers.Get("Authorization"), form.Encode(), headers.Get("Authorization"))
		}
	})

	t.Run("basic style", func(t *testing.T) {
		fixture := newOIDCFixture(t)
		p := fixture.provider("oidc")
		p.AuthStyle = AuthStyleBasic
		adapter := newAdapter(p, nil)
		if _, err := adapter.Exchange(context.Background(), "code", ""); err != nil {
			t.Fatalf("Exchange: %v", err)
		}
		form, headers := fixture.lastTokenRequest()
		if _, exists := form["client_secret"]; exists {
			t.Fatalf("basic style sent client_secret in form | basic 方式在表单中发送了 client_secret")
		}
		if form.Get("client_id") != oidcFixtureClientID {
			t.Fatalf("basic style client_id = %q | basic 方式 client_id = %[1]q", form.Get("client_id"))
		}
		encoded := strings.TrimPrefix(headers.Get("Authorization"), "Basic ")
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatalf("decode basic credentials: %v", err)
		}
		want := url.QueryEscape(oidcFixtureClientID) + ":" + url.QueryEscape(oidcFixtureClientSecret)
		if string(decoded) != want {
			t.Fatalf("basic credentials = %q want %q | basic 凭据 = %q 期望 %q", decoded, want, decoded, want)
		}
	})

	t.Run("auto style with secret", func(t *testing.T) {
		fixture := newOIDCFixture(t)
		p := fixture.provider("oidc")
		p.AuthStyle = AuthStyleAuto
		adapter := newAdapter(p, nil)
		if _, err := adapter.Exchange(context.Background(), "code", ""); err != nil {
			t.Fatalf("Exchange: %v", err)
		}
		_, headers := fixture.lastTokenRequest()
		if !strings.HasPrefix(headers.Get("Authorization"), "Basic ") {
			t.Fatalf("auto style did not use Basic: %q | auto 方式未使用 Basic：%[1]q", headers.Get("Authorization"))
		}
	})

	t.Run("auto style without secret", func(t *testing.T) {
		fixture := newOIDCFixture(t)
		p := fixture.provider("oidc")
		p.AuthStyle = AuthStyleAuto
		p.ClientSecret = ""
		adapter := newAdapter(p, nil)
		if _, err := adapter.Exchange(context.Background(), "code", ""); err != nil {
			t.Fatalf("Exchange: %v", err)
		}
		form, headers := fixture.lastTokenRequest()
		if headers.Get("Authorization") != "" {
			t.Fatalf("auto style without secret used Authorization | 无密钥的 auto 方式使用了 Authorization")
		}
		if _, exists := form["client_secret"]; exists {
			t.Fatal("auto style without secret sent client_secret | 无密钥的 auto 方式发送了 client_secret")
		}
	})

	t.Run("token params and verifier", func(t *testing.T) {
		fixture := newOIDCFixture(t)
		p := fixture.provider("oidc")
		p.TokenParams = map[string]string{
			"grant_type":   "override",
			"redirect_uri": "",
			"audience":     "fixture-api",
		}
		adapter := newAdapter(p, nil)
		if _, err := adapter.Exchange(context.Background(), "code", "verifier-value"); err != nil {
			t.Fatalf("Exchange: %v", err)
		}
		form, _ := fixture.lastTokenRequest()
		if got := form.Get("grant_type"); got != "override" {
			t.Fatalf("TokenParams grant_type = %q | TokenParams grant_type = %[1]q", got)
		}
		if _, exists := form["redirect_uri"]; exists {
			t.Fatal("empty TokenParams value did not delete redirect_uri | 空 TokenParams 值未删除 redirect_uri")
		}
		if got := form.Get("audience"); got != "fixture-api" {
			t.Fatalf("TokenParams audience = %q | TokenParams audience = %[1]q", got)
		}
		if got := form.Get("code_verifier"); got != "verifier-value" {
			t.Fatalf("code_verifier = %q | code_verifier = %[1]q", got)
		}
	})
}

// TestOIDCHooksAndDisabledOIDC verifies hook short-circuits and plain OAuth behavior. | TestOIDCHooksAndDisabledOIDC
// 校验钩子短路与普通 OAuth 行为。
func TestOIDCHooksAndDisabledOIDC(t *testing.T) {
	t.Run("exchange hook", func(t *testing.T) {
		fixture := newOIDCFixture(t)
		p := fixture.provider("oidc")
		p.ExchangeHook = func(context.Context, *Provider, *http.Client, string, string) (*Token, error) {
			return &Token{AccessToken: "hook-token", TokenType: "Bearer"}, nil
		}
		adapter := newAdapter(p, nil)
		token, err := adapter.Exchange(context.Background(), "code", "")
		if err != nil {
			t.Fatalf("Exchange: %v", err)
		}
		if token.AccessToken != "hook-token" {
			t.Fatalf("hook token = %q | 钩子令牌 = %[1]q", token.AccessToken)
		}
		if _, _, tokenCalls, _ := fixture.counts(); tokenCalls != 0 {
			t.Fatalf("exchange hook contacted the fixture %d times | 兑换钩子访问了 fixture %d 次", tokenCalls, tokenCalls)
		}
	})

	t.Run("missing code", func(t *testing.T) {
		fixture := newOIDCFixture(t)
		adapter := newAdapter(fixture.provider("oidc"), nil)
		_, err := adapter.Exchange(context.Background(), "", "")
		assertErrorIs(t, err, ErrMissingCode)
	})

	t.Run("nil provider", func(t *testing.T) {
		if adapter := newAdapter(nil, nil); adapter != nil {
			t.Fatalf("newAdapter(nil) = %v | newAdapter(nil) = %v", adapter, adapter)
		}
	})

	t.Run("oidc disabled ignores malformed id token", func(t *testing.T) {
		fixture := newOIDCFixture(t)
		fixture.set(func(c *oidcFixtureConfig) { c.idTokenRaw = "not-a-jwt" })
		p := fixture.provider("oauth", WithNonce(false))
		p.UseOIDC = false
		adapter := newAdapter(p, nil)
		token, err := adapter.Exchange(context.Background(), "code", "")
		if err != nil {
			t.Fatalf("Exchange: %v", err)
		}
		if token.IDToken != "not-a-jwt" {
			t.Fatalf("raw ID token = %q | 原始 ID 令牌 = %[1]q", token.IDToken)
		}
		if token.Claims != nil {
			t.Fatalf("claims must stay empty without OIDC: %v | 未启用 OIDC 时声明必须为空：%v", token.Claims, token.Claims)
		}
	})
}

// TestOIDCTransportFailure verifies disabled-provider transport failures stay sanitized. | TestOIDCTransportFailure
// 校验不可达提供方的传输失败保持脱敏。
func TestOIDCTransportFailure(t *testing.T) {
	fixture := newOIDCFixture(t)
	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closedURL := closed.URL
	closed.Close()

	p := fixture.provider("closed")
	p.TokenURL = closedURL + "/token"
	adapter := newAdapter(p, nil)
	_, err := adapter.Exchange(context.Background(), "code", "")
	assertErrorIs(t, err, ErrTokenExchange, ErrTransport)
	assertNoSecrets(t, err, closedURL)
	if strings.Contains(err.Error(), closedURL) {
		t.Fatalf("transport error exposes the endpoint URL: %q | 传输错误暴露端点 URL：%q", err, err)
	}
}
