package federation

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// presetSecret is an obvious fixed test client secret. | presetSecret 是明显的固定测试客户端密钥。
const presetSecret = "preset-client-secret"

// presetConfig returns fixed test credentials for preset hooks. | presetConfig 返回预设钩子的固定测试凭据。
func presetConfig() ProviderConfig {
	return ProviderConfig{
		ClientID:     "preset-client",
		ClientSecret: presetSecret,
		RedirectURL:  "https://app.example/auth/callback",
	}
}

// presetErrorServer serves one fixed response. | presetErrorServer 返回一个固定响应。
func presetErrorServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	return newFixtureServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	})
}

// assertNoPresetSecret fails when err contains the preset client secret. | assertNoPresetSecret
// 在 err 包含预设客户端密钥时失败。
func assertNoPresetSecret(t *testing.T, err error) {
	t.Helper()
	if err != nil && strings.Contains(err.Error(), presetSecret) {
		t.Fatalf("error %q leaks the preset client secret | 错误 %q 泄露预设客户端密钥", err, err)
	}
}

// TestApplyPresetOverrides covers every configuration override in applyPreset. | TestApplyPresetOverrides
// 覆盖 applyPreset 的每个配置覆盖分支。
func TestApplyPresetOverrides(t *testing.T) {
	client := &http.Client{Timeout: 2 * time.Second}
	p := Google(ProviderConfig{
		Name:            " custom-google ",
		DisplayName:     "Custom Google",
		Kind:            KindOAuth2,
		ClientID:        "custom-client",
		ClientSecret:    presetSecret,
		RedirectURL:     "https://app.example/custom-callback",
		Scopes:          []string{"scope-a", "scope-b"},
		AuthURL:         "https://auth.example/authorize",
		TokenURL:        "https://auth.example/token",
		UserInfoURL:     "https://auth.example/userinfo",
		JWKSURL:         "https://auth.example/jwks",
		Issuer:          "https://issuer.example",
		UseOIDC:         true,
		PKCE:            true,
		Nonce:           true,
		AuthStyle:       AuthStyleBasic,
		PrivateKey:      "test-private-key",
		HTTPClient:      client,
		Extra:           map[string]string{"custom": "value"},
		AuthParams:      map[string]string{"prompt": "consent"},
		TokenParams:     map[string]string{"audience": "api"},
		UserInfoHeaders: map[string]string{"X-Preset": "1"},
	}, WithExtra("option", "enabled"), nil)

	wantStrings := map[string][2]string{
		"Name":        {p.Name, "custom-google"},
		"DisplayName": {p.DisplayName, "Custom Google"},
		"Kind":        {p.Kind, KindOAuth2},
		"ClientID":    {p.ClientID, "custom-client"},
		"Secret":      {p.ClientSecret, presetSecret},
		"RedirectURL": {p.RedirectURL, "https://app.example/custom-callback"},
		"AuthURL":     {p.AuthURL, "https://auth.example/authorize"},
		"TokenURL":    {p.TokenURL, "https://auth.example/token"},
		"UserInfoURL": {p.UserInfoURL, "https://auth.example/userinfo"},
		"JWKSURL":     {p.JWKSURL, "https://auth.example/jwks"},
		"Issuer":      {p.Issuer, "https://issuer.example"},
		"AuthStyle":   {p.AuthStyle, AuthStyleBasic},
		"PrivateKey":  {p.PrivateKey, "test-private-key"},
	}
	for field, pair := range wantStrings {
		if pair[0] != pair[1] {
			t.Fatalf("%s = %q want %q | %s = %q 期望 %q", field, pair[0], pair[1], field, pair[0], pair[1])
		}
	}
	if len(p.Scopes) != 2 || p.Scopes[0] != "scope-a" || p.Scopes[1] != "scope-b" {
		t.Fatalf("scopes = %v | 作用域 = %v", p.Scopes, p.Scopes)
	}
	if !p.UseOIDC || !p.PKCE || !p.Nonce {
		t.Fatalf("flags = oidc:%v pkce:%v nonce:%v | 标志 = oidc:%v pkce:%v nonce:%v", p.UseOIDC, p.PKCE, p.Nonce, p.UseOIDC, p.PKCE, p.Nonce)
	}
	if p.HTTPClient != client {
		t.Fatal("HTTPClient override was not applied | HTTPClient 覆盖未生效")
	}
	if p.AuthParams["prompt"] != "consent" || p.TokenParams["audience"] != "api" || p.UserInfoHeaders["X-Preset"] != "1" {
		t.Fatalf("map overrides = %v %v %v | 映射覆盖 = %v %v %v",
			p.AuthParams, p.TokenParams, p.UserInfoHeaders, p.AuthParams, p.TokenParams, p.UserInfoHeaders)
	}
	if p.Extra["custom"] != "value" || p.Extra["option"] != "enabled" {
		t.Fatalf("extra = %v | 扩展 = %v", p.Extra, p.Extra)
	}

	microsoft := Microsoft(ProviderConfig{
		ClientID:        "ms-client",
		Extra:           map[string]string{ExtraMicrosoftTenant: "tenant-42", "custom": "x"},
		AuthParams:      map[string]string{"prompt": "login"},
		TokenParams:     map[string]string{"audience": "graph"},
		UserInfoHeaders: map[string]string{"X-Ms": "1"},
	}, WithScopes("openid"))
	if !strings.Contains(microsoft.Issuer, "/tenant-42/v2.0") {
		t.Fatalf("tenant issuer = %q | 租户 issuer = %[1]q", microsoft.Issuer)
	}
	if microsoft.AuthParams["prompt"] != "login" {
		t.Fatalf("microsoft auth params = %v | Microsoft AuthParams = %v", microsoft.AuthParams, microsoft.AuthParams)
	}
	if microsoft.TokenParams["audience"] != "graph" || microsoft.UserInfoHeaders["X-Ms"] != "1" {
		t.Fatalf("microsoft maps = %v %v | Microsoft 映射 = %v %v", microsoft.TokenParams, microsoft.UserInfoHeaders, microsoft.TokenParams, microsoft.UserInfoHeaders)
	}
	if microsoft.Extra[ExtraMicrosoftTenant] != "tenant-42" || microsoft.Extra["custom"] != "x" {
		t.Fatalf("microsoft extra = %v | Microsoft 扩展 = %v", microsoft.Extra, microsoft.Extra)
	}
	if len(microsoft.Scopes) != 1 || microsoft.Scopes[0] != "openid" {
		t.Fatalf("microsoft scopes = %v | Microsoft 作用域 = %v", microsoft.Scopes, microsoft.Scopes)
	}
}

// TestPresetHelperBranches covers the shared preset mapping helpers. | TestPresetHelperBranches
// 覆盖共享预设映射辅助函数。
func TestPresetHelperBranches(t *testing.T) {
	p := &Provider{Name: "feishu"}

	feishuCases := []struct {
		name    string
		raw     map[string]any
		wantErr bool
		mention string
	}{
		{name: "success", raw: map[string]any{"code": 0, "data": map[string]any{"open_id": "ou-1"}}},
		{name: "business code", raw: map[string]any{"code": 40001}, wantErr: true, mention: "code 40001"},
		{name: "error field", raw: map[string]any{"error": "bad code"}, wantErr: true, mention: "feishu returned error"},
		{name: "missing data", raw: map[string]any{"code": 0}, wantErr: true, mention: "no data"},
	}
	for _, tc := range feishuCases {
		t.Run("feishu data "+tc.name, func(t *testing.T) {
			data, err := feishuData(p, tc.raw, ErrTokenExchange)
			if tc.wantErr {
				assertErrorIs(t, err, ErrTokenExchange)
				if tc.mention != "" {
					assertErrorMentions(t, err, tc.mention)
				}
				return
			}
			if err != nil {
				t.Fatalf("feishuData: %v", err)
			}
			if data["open_id"] != "ou-1" {
				t.Fatalf("feishu data = %v | 飞书 data = %v", data, data)
			}
		})
	}

	alipayCases := []struct {
		name    string
		raw     map[string]any
		key     string
		wantErr bool
		mention string
	}{
		{name: "success", raw: map[string]any{"alipay_user_info_share_response": map[string]any{"code": "10000", "user_id": "u1"}}, key: "alipay_user_info_share_response"},
		{name: "sub code", raw: map[string]any{"error_response": map[string]any{"sub_code": "ACQ.INVALID"}}, key: "alipay_user_info_share_response", wantErr: true, mention: "ACQ.INVALID"},
		{name: "code", raw: map[string]any{"error_response": map[string]any{"code": "40004"}}, key: "alipay_user_info_share_response", wantErr: true, mention: "40004"},
		{name: "anonymous error", raw: map[string]any{"error_response": map[string]any{}}, key: "alipay_user_info_share_response", wantErr: true, mention: "alipay returned error"},
		{name: "missing object", raw: map[string]any{"code": "10000"}, key: "alipay_user_info_share_response", wantErr: true, mention: "no alipay_user_info_share_response object"},
		{name: "business failure", raw: map[string]any{"alipay_user_info_share_response": map[string]any{"code": "40004"}}, key: "alipay_user_info_share_response", wantErr: true, mention: "40004"},
	}
	for _, tc := range alipayCases {
		t.Run("alipay response "+tc.name, func(t *testing.T) {
			response, err := alipayResponse(p, tc.raw, tc.key, ErrUserInfo)
			if tc.wantErr {
				assertErrorIs(t, err, ErrUserInfo)
				assertErrorMentions(t, err, tc.mention)
				return
			}
			if err != nil {
				t.Fatalf("alipayResponse: %v", err)
			}
			if response["user_id"] != "u1" {
				t.Fatalf("alipay response = %v | 支付宝响应 = %v", response, response)
			}
		})
	}
	if code := providerErrorCode(nil); code != "" {
		t.Fatalf("nil provider error code = %q | 空响应错误码 = %[1]q", code)
	}

	if privateKeyFor(nil) != "" {
		t.Fatal("nil provider private key must be empty | 空提供方私钥必须为空")
	}
	if got := privateKeyFor(&Provider{PrivateKey: "direct-key"}); got != "direct-key" {
		t.Fatalf("direct private key = %q | 直接私钥 = %[1]q", got)
	}
	if got := privateKeyFor(&Provider{Extra: map[string]string{ExtraAlipayPrivateKey: "extra-key"}}); got != "extra-key" {
		t.Fatalf("extra private key = %q | 扩展私钥 = %[1]q", got)
	}

	wecomCases := []struct {
		name string
		p    *Provider
		want string
	}{
		{name: "extra override", p: &Provider{Extra: map[string]string{ExtraWeComAuthUserInfoURL: "https://custom.example/auth"}}, want: "https://custom.example/auth"},
		{name: "derived", p: &Provider{TokenURL: "https://qyapi.example/custom/token"}, want: "https://qyapi.example/cgi-bin/auth/getuserinfo"},
		{name: "default token url", p: &Provider{TokenURL: defaultWeComTokenURL}, want: defaultWeComAuthUserInfoURL},
		{name: "invalid token url", p: &Provider{TokenURL: "://invalid"}, want: "://invalid"},
	}
	for _, tc := range wecomCases {
		if got := wecomCodeUserInfoURL(tc.p); got != tc.want {
			t.Fatalf("wecomCodeUserInfoURL %s = %q want %q | wecomCodeUserInfoURL %s = %q 期望 %q", tc.name, got, tc.want, tc.name, got, tc.want)
		}
	}

	qqCases := []struct {
		name string
		p    *Provider
		want string
	}{
		{name: "extra override", p: &Provider{Extra: map[string]string{ExtraQQOpenIDURL: "https://custom.example/me"}}, want: "https://custom.example/me"},
		{name: "derived", p: &Provider{TokenURL: "https://graph.example/oauth2.0/token"}, want: "https://graph.example/oauth2.0/me"},
		{name: "default token url", p: &Provider{TokenURL: defaultQQTokenURL}, want: defaultQQOpenIDURL},
		{name: "invalid token url", p: &Provider{TokenURL: "://invalid"}, want: "://invalid"},
	}
	for _, tc := range qqCases {
		if got := qqOpenIDURL(tc.p); got != tc.want {
			t.Fatalf("qqOpenIDURL %s = %q want %q | qqOpenIDURL %s = %q 期望 %q", tc.name, got, tc.want, tc.name, got, tc.want)
		}
	}

	domainCases := map[string]string{
		"":                           "",
		" example.us.auth0.com/ ":    "https://example.us.auth0.com",
		"http://example.auth0.com/":  "http://example.auth0.com",
		"https://example.auth0.com/": "https://example.auth0.com",
	}
	for input, want := range domainCases {
		if got := normalizeDomain(input); got != want {
			t.Fatalf("normalizeDomain(%q) = %q want %q | normalizeDomain(%q) = %q 期望 %q", input, got, want, input, got, want)
		}
	}
	if auth0 := Auth0("example.us.auth0.com", presetConfig()); auth0.Issuer != "https://example.us.auth0.com/" {
		t.Fatalf("auth0 issuer = %q | Auth0 issuer = %[1]q", auth0.Issuer)
	}
}

// TestFacebookUserInfoHook verifies nested picture mapping and rejection paths. | TestFacebookUserInfoHook
// 校验嵌套头像映射与拒绝路径。
func TestFacebookUserInfoHook(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		server := newFixtureServer(t, func(w http.ResponseWriter, r *http.Request) {
			if got := r.Header.Get("Authorization"); got != "Bearer fb-access" {
				t.Errorf("facebook Authorization = %q | Facebook Authorization = %[1]q", got)
			}
			_, _ = io.WriteString(w, `{"id":"fb-1","name":"FB User","email":"fb@example.com","email_verified":true,"username":"fbuser","picture":{"data":{"url":"https://example.com/fb.png"}}}`)
		})
		p := Facebook(ProviderConfig{ClientID: "fb-client", ClientSecret: "fb-secret", UserInfoURL: server.URL + "/me"})
		identity, err := facebookUserInfo(context.Background(), p, server.Client(), &Token{AccessToken: "fb-access"})
		if err != nil {
			t.Fatalf("facebookUserInfo: %v", err)
		}
		if identity.Provider != "facebook" || identity.Subject != "fb-1" || identity.Email != "fb@example.com" {
			t.Fatalf("facebook identity = %+v | Facebook 身份 = %+v", identity, identity)
		}
		if identity.AvatarURL != "https://example.com/fb.png" {
			t.Fatalf("facebook avatar = %q | Facebook 头像 = %[1]q", identity.AvatarURL)
		}
		if identity.EmailVerified || identity.Username != "" {
			t.Fatalf("facebook must not trust email or username: %+v | Facebook 不得信任邮箱或用户名：%+v", identity, identity)
		}
	})

	cases := []struct {
		name    string
		status  int
		body    string
		want    []error
		mention string
	}{
		{name: "http error", status: http.StatusBadGateway, body: `{"error":"fb_secret"}`, want: []error{ErrUserInfo}, mention: "HTTP 502"},
		{name: "invalid json", status: http.StatusOK, body: "{", want: []error{ErrUserInfo}, mention: "invalid"},
		{name: "provider error", status: http.StatusOK, body: `{"error":"fb_error"}`, want: []error{ErrUserInfo}, mention: "fb_error"},
		{name: "missing id", status: http.StatusOK, body: `{"name":"Nobody"}`, want: []error{ErrUserInfo}, mention: "no id"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := presetErrorServer(t, tc.status, tc.body)
			p := Facebook(ProviderConfig{ClientID: "fb-client", UserInfoURL: server.URL + "/me"})
			_, err := facebookUserInfo(context.Background(), p, server.Client(), &Token{AccessToken: "fb-access"})
			assertErrorIs(t, err, tc.want...)
			assertErrorMentions(t, err, tc.mention)
			assertNoSecrets(t, err)
			assertNoPresetSecret(t, err)
		})
	}

	t.Run("transport failure", func(t *testing.T) {
		closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		closedURL := closed.URL
		closed.Close()
		p := Facebook(ProviderConfig{ClientID: "fb-client", UserInfoURL: closedURL + "/me"})
		_, err := facebookUserInfo(context.Background(), p, nil, &Token{AccessToken: "fb-access"})
		assertErrorIs(t, err, ErrUserInfo, ErrTransport)
		assertNoPresetSecret(t, err)
	})
}

// TestAlipaySigningFailure verifies signing failures are classified and sanitized. | TestAlipaySigningFailure
// 校验签名失败被正确分类并脱敏。
func TestAlipaySigningFailure(t *testing.T) {
	p := Alipay(presetConfig())
	p.PrivateKey = "not-a-key"
	_, err := alipayExchange(context.Background(), p, nil, "code", "")
	assertErrorIs(t, err, ErrTokenExchange, ErrSigning)
	assertNoPresetSecret(t, err)

	_, err = alipayUserInfo(context.Background(), p, nil, &Token{AccessToken: "alipay-token"})
	assertErrorIs(t, err, ErrUserInfo, ErrSigning)
	assertNoPresetSecret(t, err)

	if _, err := alipayUserInfo(context.Background(), p, nil, nil); !errors.Is(err, ErrUserInfo) {
		t.Fatalf("nil token error = %v | 空令牌错误 = %[1]v", err)
	}
}
