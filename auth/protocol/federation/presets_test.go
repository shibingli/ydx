package federation

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/shibingli/ydx/auth/protocol/oauth2"
	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/json"
)

func presetTestConfig() ProviderConfig {
	return ProviderConfig{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURL:  "https://app.example/auth/callback",
	}
}

func TestPresetAuthorizationURLs(t *testing.T) {
	tests := []struct {
		name          string
		provider      func() *Provider
		wantHost      string
		wantPath      string
		wantFragment  string
		wantQuery     map[string]string
		nonce         string
		verifier      string
		wantChallenge bool
	}{
		{
			name:     "google",
			provider: func() *Provider { return Google(presetTestConfig()) },
			wantHost: "accounts.google.com",
			wantPath: "/o/oauth2/v2/auth",
			wantQuery: map[string]string{
				"client_id":             "client-id",
				"redirect_uri":          "https://app.example/auth/callback",
				"response_type":         "code",
				"scope":                 "openid email profile",
				"state":                 "state-1",
				"nonce":                 "nonce-1",
				"code_challenge_method": "S256",
			},
			nonce:         "nonce-1",
			verifier:      "verifier-1",
			wantChallenge: true,
		},
		{
			name:     "github",
			provider: func() *Provider { return GitHub(presetTestConfig()) },
			wantHost: "github.com",
			wantPath: "/login/oauth/authorize",
			wantQuery: map[string]string{
				"client_id":     "client-id",
				"redirect_uri":  "https://app.example/auth/callback",
				"response_type": "code",
				"scope":         "read:user user:email",
				"state":         "state-1",
			},
			verifier:      "verifier-1",
			wantChallenge: true,
		},
		{
			name:     "facebook",
			provider: func() *Provider { return Facebook(presetTestConfig()) },
			wantHost: "www.facebook.com",
			wantPath: "/v19.0/dialog/oauth",
			wantQuery: map[string]string{
				"client_id":    "client-id",
				"redirect_uri": "https://app.example/auth/callback",
				"scope":        "email,public_profile",
				"state":        "state-1",
			},
			verifier:      "verifier-1",
			wantChallenge: true,
		},
		{
			name:     "wechat-open",
			provider: func() *Provider { return WeChat(presetTestConfig()) },
			wantHost: "open.weixin.qq.com",
			wantPath: "/connect/qrconnect",
			wantQuery: map[string]string{
				"appid":         "client-id",
				"redirect_uri":  "https://app.example/auth/callback",
				"response_type": "code",
				"scope":         "snsapi_login",
				"state":         "state-1",
			},
			wantFragment: "wechat_redirect",
		},
		{
			name: "wechat-official",
			provider: func() *Provider {
				config := presetTestConfig()
				config.Extra = map[string]string{ExtraWeChatAccountType: WeChatAccountOfficialAccount}
				return WeChat(config)
			},
			wantHost: "open.weixin.qq.com",
			wantPath: "/connect/oauth2/authorize",
			wantQuery: map[string]string{
				"appid":         "client-id",
				"redirect_uri":  "https://app.example/auth/callback",
				"response_type": "code",
				"scope":         "snsapi_userinfo",
				"state":         "state-1",
			},
			wantFragment: "wechat_redirect",
		},
		{
			name:     "alipay",
			provider: func() *Provider { return Alipay(presetTestConfig()) },
			wantHost: "openauth.alipay.com",
			wantPath: "/oauth2/publicAppAuthorize.htm",
			wantQuery: map[string]string{
				"app_id":       "client-id",
				"redirect_uri": "https://app.example/auth/callback",
				"scope":        "auth_user",
				"state":        "state-1",
			},
		},
		{
			name:     "dingtalk",
			provider: func() *Provider { return DingTalk(presetTestConfig()) },
			wantHost: "login.dingtalk.com",
			wantPath: "/oauth2/auth",
			wantQuery: map[string]string{
				"client_id":     "client-id",
				"redirect_uri":  "https://app.example/auth/callback",
				"response_type": "code",
				"scope":         "openid",
				"state":         "state-1",
				"prompt":        "consent",
			},
		},
		{
			name:     "feishu",
			provider: func() *Provider { return Feishu(presetTestConfig()) },
			wantHost: "open.feishu.cn",
			wantPath: "/open-apis/authen/v1/authorize",
			wantQuery: map[string]string{
				"app_id":        "client-id",
				"redirect_uri":  "https://app.example/auth/callback",
				"response_type": "code",
				"scope":         "contact:user.base:readonly",
				"state":         "state-1",
			},
		},
		{
			name: "wecom",
			provider: func() *Provider {
				return WeCom(presetTestConfig(), WithExtra("agentid", "1000002"))
			},
			wantHost: "open.weixin.qq.com",
			wantPath: "/connect/oauth2/authorize",
			wantQuery: map[string]string{
				"appid":         "client-id",
				"redirect_uri":  "https://app.example/auth/callback",
				"response_type": "code",
				"scope":         "snsapi_base",
				"state":         "state-1",
				"agentid":       "1000002",
			},
			wantFragment: "wechat_redirect",
		},
		{
			name:     "qq",
			provider: func() *Provider { return QQ(presetTestConfig()) },
			wantHost: "graph.qq.com",
			wantPath: "/oauth2.0/authorize",
			wantQuery: map[string]string{
				"client_id":     "client-id",
				"redirect_uri":  "https://app.example/auth/callback",
				"response_type": "code",
				"scope":         "get_user_info",
				"state":         "state-1",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider := test.provider()
			endpoint, err := newAdapter(provider, nil).AuthCodeURL("state-1", test.nonce, test.verifier)
			if err != nil {
				t.Fatalf("AuthCodeURL: %v", err)
			}
			parsed, err := url.Parse(endpoint)
			if err != nil {
				t.Fatalf("parse authorization URL: %v", err)
			}
			if parsed.Host != test.wantHost || parsed.Path != test.wantPath {
				t.Fatalf("authorization endpoint = %s%s, want %s%s", parsed.Host, parsed.Path, test.wantHost, test.wantPath)
			}
			if parsed.Fragment != test.wantFragment {
				t.Fatalf("fragment = %q, want %q", parsed.Fragment, test.wantFragment)
			}
			query := parsed.Query()
			for key, want := range test.wantQuery {
				if got := query.Get(key); got != want {
					t.Fatalf("query %s = %q, want %q (%s)", key, got, want, parsed.RawQuery)
				}
			}
			if test.wantChallenge {
				if got, want := query.Get("code_challenge"), oauth2.CodeChallengeS256(test.verifier); got != want {
					t.Fatalf("PKCE challenge = %q, want %q", got, want)
				}
			}
		})
	}
}

func TestInternationalPresetDefinitions(t *testing.T) {
	config := presetTestConfig()
	google := Google(config)
	if google.Name != "google" || google.Kind != KindOIDC || !google.UseOIDC || !google.PKCE || !google.Nonce {
		t.Fatalf("google preset = %#v", google)
	}
	if google.AuthURL != "https://accounts.google.com/o/oauth2/v2/auth" ||
		google.TokenURL != "https://oauth2.googleapis.com/token" ||
		google.UserInfoURL != "https://openidconnect.googleapis.com/v1/userinfo" ||
		google.JWKSURL != "https://www.googleapis.com/oauth2/v3/certs" ||
		google.Issuer != "https://accounts.google.com" {
		t.Fatalf("google endpoints = %#v", google)
	}

	config.Extra = map[string]string{ExtraMicrosoftTenant: "tenant-42"}
	microsoft := Microsoft(config)
	if !strings.Contains(microsoft.AuthURL, "/tenant-42/oauth2/v2.0/authorize") ||
		!strings.Contains(microsoft.TokenURL, "/tenant-42/oauth2/v2.0/token") ||
		!strings.Contains(microsoft.JWKSURL, "/tenant-42/discovery/v2.0/keys") ||
		microsoft.Issuer != "https://login.microsoftonline.com/tenant-42/v2.0" {
		t.Fatalf("microsoft endpoints = %#v", microsoft)
	}
	if microsoft.AuthParams["prompt"] != "select_account" {
		t.Fatalf("microsoft auth params = %v", microsoft.AuthParams)
	}
	config.Extra = nil

	github := GitHub(config)
	if github.AuthURL != "https://github.com/login/oauth/authorize" ||
		github.TokenURL != "https://github.com/login/oauth/access_token" ||
		github.AuthStyle != AuthStylePost || !github.PKCE {
		t.Fatalf("github preset = %#v", github)
	}
	if github.UserInfoHeaders["Accept"] == "" {
		t.Fatal("github Accept header is missing")
	}

	apple := Apple(config)
	if apple.UserInfoURL != "" || apple.JWKSURL == "" || apple.Issuer != "https://appleid.apple.com" {
		t.Fatalf("apple preset = %#v", apple)
	}
	if apple.AuthParams["response_mode"] != "form_post" {
		t.Fatalf("apple response_mode = %q", apple.AuthParams["response_mode"])
	}

	facebook := Facebook(config)
	if facebook.ScopeSeparator != "," || facebook.UserInfoHook == nil {
		t.Fatalf("facebook preset = %#v", facebook)
	}

	gitlab := GitLab(config)
	if gitlab.AuthURL != "https://gitlab.com/oauth/authorize" || gitlab.UserInfoURL != "https://gitlab.com/oauth/userinfo" {
		t.Fatalf("gitlab preset = %#v", gitlab)
	}

	okta := Okta("https://example.okta.com/", config)
	if okta.AuthURL != "https://example.okta.com/v1/authorize" ||
		okta.TokenURL != "https://example.okta.com/v1/token" ||
		okta.Issuer != "https://example.okta.com" {
		t.Fatalf("okta preset = %#v", okta)
	}

	auth0 := Auth0("example.us.auth0.com", config)
	if auth0.AuthURL != "https://example.us.auth0.com/authorize" ||
		auth0.JWKSURL != "https://example.us.auth0.com/.well-known/jwks.json" ||
		auth0.Issuer != "https://example.us.auth0.com/" {
		t.Fatalf("auth0 preset = %#v", auth0)
	}

	keycloak := Keycloak("https://keycloak.example.com/", "/demo/", config)
	if keycloak.AuthURL != "https://keycloak.example.com/realms/demo/protocol/openid-connect/auth" ||
		keycloak.Issuer != "https://keycloak.example.com/realms/demo" {
		t.Fatalf("keycloak preset = %#v", keycloak)
	}

	for _, provider := range []*Provider{google, microsoft, github, apple, facebook, gitlab, okta, auth0, keycloak} {
		if err := provider.Validate(); err != nil {
			t.Fatalf("Validate(%s): %v", provider.Name, err)
		}
	}
}

func newFixtureServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}

func TestWeChatPresetExchangeAndUserInfo(t *testing.T) {
	server := newFixtureServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			query := r.URL.Query()
			if query.Get("appid") != "wx-app" || query.Get("secret") != "wx-secret" || query.Get("code") != "wx-code" || query.Get("grant_type") != "authorization_code" {
				t.Errorf("wechat token query = %v", query)
			}
			_, _ = io.WriteString(w, `{"access_token":"wx-token","expires_in":7200,"refresh_token":"wx-refresh","openid":"openid-1","scope":"snsapi_login","unionid":"unionid-1"}`)
		case "/userinfo":
			query := r.URL.Query()
			if query.Get("access_token") != "wx-token" || query.Get("openid") != "openid-1" || query.Get("lang") != "zh_CN" {
				t.Errorf("wechat userinfo query = %v", query)
			}
			_, _ = io.WriteString(w, `{"openid":"openid-1","nickname":"微信昵称","sex":1,"language":"zh_CN","headimgurl":"https://example.com/wx.png","privilege":[],"unionid":"unionid-1"}`)
		default:
			http.NotFound(w, r)
		}
	})
	provider := WeChat(ProviderConfig{
		ClientID:     "wx-app",
		ClientSecret: "wx-secret",
		RedirectURL:  "https://app.example/callback",
	}, WithEndpoints(Endpoints{TokenURL: server.URL + "/token", UserInfoURL: server.URL + "/userinfo"}))

	adapter := newAdapter(provider, nil)
	token, err := adapter.Exchange(context.Background(), "wx-code", "")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if token.AccessToken != "wx-token" || token.OpenID != "openid-1" || token.UnionID != "unionid-1" || token.ExpiresIn != 7200 {
		t.Fatalf("wechat token = %#v", token)
	}
	identity, err := adapter.UserInfo(context.Background(), token)
	if err != nil {
		t.Fatalf("UserInfo: %v", err)
	}
	if identity.Provider != "wechat" || identity.Subject != "unionid-1" || identity.Name != "微信昵称" {
		t.Fatalf("wechat identity = %#v", identity)
	}
	if identity.AvatarURL != "https://example.com/wx.png" || identity.Email != "" || identity.EmailVerified || identity.Username != "" {
		t.Fatalf("wechat identity fields = %#v", identity)
	}
	if _, ok := identity.Raw["access_token"]; ok {
		t.Fatal("wechat identity raw contains access token")
	}
}

func TestDingTalkPresetExchangeAndUserInfo(t *testing.T) {
	server := newFixtureServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			if r.Method != http.MethodPost {
				t.Errorf("dingtalk token method = %s", r.Method)
			}
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Errorf("decode dingtalk token body: %v", err)
			}
			if stringValue(payload["clientId"]) != "dt-app" || stringValue(payload["clientSecret"]) != "dt-secret" ||
				stringValue(payload["code"]) != "dt-code" || stringValue(payload["grantType"]) != "authorization_code" {
				t.Errorf("dingtalk token payload = %v", payload)
			}
			_, _ = io.WriteString(w, `{"accessToken":"dt-token","refreshToken":"dt-refresh","expireIn":7200,"corpId":"corp-1"}`)
		case "/userinfo":
			if got := r.Header.Get("x-acs-dingtalk-access-token"); got != "dt-token" {
				t.Errorf("dingtalk userinfo token header = %q", got)
			}
			_, _ = io.WriteString(w, `{"unionId":"union-1","openId":"open-1","nick":"钉钉昵称","avatarUrl":"https://example.com/dt.png","mobile":"13800000000","code":"0"}`)
		default:
			http.NotFound(w, r)
		}
	})
	provider := DingTalk(ProviderConfig{
		ClientID:     "dt-app",
		ClientSecret: "dt-secret",
		RedirectURL:  "https://app.example/callback",
	}, WithEndpoints(Endpoints{TokenURL: server.URL + "/token", UserInfoURL: server.URL + "/userinfo"}))

	adapter := newAdapter(provider, nil)
	token, err := adapter.Exchange(context.Background(), "dt-code", "")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if token.AccessToken != "dt-token" || token.ExpiresIn != 7200 {
		t.Fatalf("dingtalk token = %#v", token)
	}
	identity, err := adapter.UserInfo(context.Background(), token)
	if err != nil {
		t.Fatalf("UserInfo: %v", err)
	}
	if identity.Subject != "union-1" || identity.Name != "钉钉昵称" || identity.AvatarURL != "https://example.com/dt.png" {
		t.Fatalf("dingtalk identity = %#v", identity)
	}
	if identity.EmailVerified || identity.Username != "" {
		t.Fatalf("dingtalk identity flags = %#v", identity)
	}
}

func TestFeishuPresetExchangeAndUserInfo(t *testing.T) {
	server := newFixtureServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
				t.Errorf("feishu token content type = %q", r.Header.Get("Content-Type"))
			}
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Errorf("decode feishu token body: %v", err)
			}
			if stringValue(payload["client_id"]) != "fs-app" || stringValue(payload["client_secret"]) != "fs-secret" ||
				stringValue(payload["code"]) != "fs-code" || stringValue(payload["grant_type"]) != "authorization_code" ||
				stringValue(payload["redirect_uri"]) != "https://app.example/callback" {
				t.Errorf("feishu token payload = %v", payload)
			}
			_, _ = io.WriteString(w, `{"code":0,"msg":"ok","data":{"access_token":"fs-token","token_type":"Bearer","expires_in":7200,"refresh_token":"fs-refresh"}}`)
		case "/userinfo":
			if got := r.Header.Get("Authorization"); got != "Bearer fs-token" {
				t.Errorf("feishu userinfo authorization = %q", got)
			}
			_, _ = io.WriteString(w, `{"code":0,"msg":"ok","data":{"name":"飞书用户","en_name":"Feishu User","avatar_url":"https://example.com/fs.png","avatar_big":"https://example.com/fs-big.png","open_id":"ou_1","union_id":"on_1","user_id":"uid_1","email":"fs@example.com"}}`)
		default:
			http.NotFound(w, r)
		}
	})
	provider := Feishu(ProviderConfig{
		ClientID:     "fs-app",
		ClientSecret: "fs-secret",
		RedirectURL:  "https://app.example/callback",
	}, WithEndpoints(Endpoints{TokenURL: server.URL + "/token", UserInfoURL: server.URL + "/userinfo"}))

	adapter := newAdapter(provider, nil)
	token, err := adapter.Exchange(context.Background(), "fs-code", "")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if token.AccessToken != "fs-token" || token.ExpiresIn != 7200 {
		t.Fatalf("feishu token = %#v", token)
	}
	identity, err := adapter.UserInfo(context.Background(), token)
	if err != nil {
		t.Fatalf("UserInfo: %v", err)
	}
	if identity.Subject != "on_1" || identity.Name != "飞书用户" || identity.AvatarURL != "https://example.com/fs.png" {
		t.Fatalf("feishu identity = %#v", identity)
	}
	if identity.Email != "fs@example.com" || identity.EmailVerified || identity.Username != "" {
		t.Fatalf("feishu identity flags = %#v", identity)
	}
}

func TestAlipayPresetExchangeAndUserInfo(t *testing.T) {
	key, privatePEM := generateRSAKey(t)
	server := newFixtureServer(t, func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse alipay form: %v", err)
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if form := r.PostForm; form.Get("app_id") != "ali-app" || form.Get("sign_type") != "RSA2" || form.Get("format") != "json" {
			t.Errorf("alipay base form = %v", form)
		}
		if err := verifyAlipayForm(r.PostForm, &key.PublicKey); err != nil {
			t.Errorf("alipay signature on %s: %v", r.URL.Path, err)
		}
		switch r.URL.Path {
		case "/token":
			if r.PostForm.Get("method") != "alipay.system.oauth.token" ||
				r.PostForm.Get("grant_type") != "authorization_code" ||
				r.PostForm.Get("code") != "ali-code" {
				t.Errorf("alipay token form = %v", r.PostForm)
			}
			_, _ = io.WriteString(w, `{"alipay_system_oauth_token_response":{"access_token":"ali-token","user_id":"2088000000000000","expires_in":3600,"refresh_token":"ali-refresh"}}`)
		case "/userinfo":
			if r.PostForm.Get("method") != "alipay.user.info.share" || r.PostForm.Get("auth_token") != "ali-token" {
				t.Errorf("alipay userinfo form = %v", r.PostForm)
			}
			_, _ = io.WriteString(w, `{"alipay_user_info_share_response":{"code":"10000","msg":"Success","user_id":"2088000000000000","avatar":"https://example.com/ali.png","nick_name":"支付宝用户","email":"ali@example.com"}}`)
		default:
			http.NotFound(w, r)
		}
	})
	provider := Alipay(ProviderConfig{
		ClientID:    "ali-app",
		RedirectURL: "https://app.example/callback",
		PrivateKey:  privatePEM,
	}, WithEndpoints(Endpoints{TokenURL: server.URL + "/token", UserInfoURL: server.URL + "/userinfo"}))

	adapter := newAdapter(provider, nil)
	token, err := adapter.Exchange(context.Background(), "ali-code", "")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if token.AccessToken != "ali-token" || token.Raw["user_id"] != "2088000000000000" {
		t.Fatalf("alipay token = %#v", token)
	}
	identity, err := adapter.UserInfo(context.Background(), token)
	if err != nil {
		t.Fatalf("UserInfo: %v", err)
	}
	if identity.Subject != "2088000000000000" || identity.Name != "支付宝用户" || identity.AvatarURL != "https://example.com/ali.png" {
		t.Fatalf("alipay identity = %#v", identity)
	}
	if identity.Email != "ali@example.com" || identity.EmailVerified || identity.Username != "" {
		t.Fatalf("alipay identity flags = %#v", identity)
	}
}

func TestWeComPresetExchangeAndUserInfo(t *testing.T) {
	server := newFixtureServer(t, func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		switch r.URL.Path {
		case "/token":
			if query.Get("corpid") != "ww-app" || query.Get("corpsecret") != "ww-secret" {
				t.Errorf("wecom token query = %v", query)
			}
			_, _ = io.WriteString(w, `{"errcode":0,"errmsg":"ok","access_token":"corp-token","expires_in":7200}`)
		case "/getuserinfo":
			if query.Get("access_token") != "corp-token" || query.Get("code") != "ww-code" {
				t.Errorf("wecom getuserinfo query = %v", query)
			}
			_, _ = io.WriteString(w, `{"errcode":0,"errmsg":"ok","UserId":"zhangsan","DeviceId":"device-1","user_ticket":"ticket","openid":"open-1","external_userid":"external-1"}`)
		case "/user/get":
			if query.Get("access_token") != "corp-token" || query.Get("userid") != "zhangsan" {
				t.Errorf("wecom user/get query = %v", query)
			}
			_, _ = io.WriteString(w, `{"errcode":0,"errmsg":"ok","userid":"zhangsan","name":"张三","email":"zhangsan@example.com","avatar":"https://example.com/ww.png","department":[1]}`)
		default:
			http.NotFound(w, r)
		}
	})
	provider := WeCom(ProviderConfig{
		ClientID:     "ww-app",
		ClientSecret: "ww-secret",
		RedirectURL:  "https://app.example/callback",
	},
		WithEndpoints(Endpoints{TokenURL: server.URL + "/token", UserInfoURL: server.URL + "/user/get"}),
		WithExtra(ExtraWeComAuthUserInfoURL, server.URL+"/getuserinfo"))

	adapter := newAdapter(provider, nil)
	token, err := adapter.Exchange(context.Background(), "ww-code", "")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if token.AccessToken != "corp-token" || token.OpenID != "open-1" {
		t.Fatalf("wecom token = %#v", token)
	}
	if _, ok := token.Raw["access_token"]; ok {
		t.Fatal("wecom token raw contains the corp access token")
	}
	identity, err := adapter.UserInfo(context.Background(), token)
	if err != nil {
		t.Fatalf("UserInfo: %v", err)
	}
	if identity.Subject != "zhangsan" || identity.Name != "张三" || identity.Email != "zhangsan@example.com" || identity.AvatarURL != "https://example.com/ww.png" {
		t.Fatalf("wecom identity = %#v", identity)
	}
	if identity.EmailVerified || identity.Username != "" {
		t.Fatalf("wecom identity flags = %#v", identity)
	}
	if _, ok := identity.Raw["access_token"]; ok {
		t.Fatal("wecom identity raw contains the corp access token")
	}
}

func TestQQPresetExchangeAndUserInfo(t *testing.T) {
	server := newFixtureServer(t, func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		switch r.URL.Path {
		case "/oauth2.0/token":
			if query.Get("client_id") != "qq-app" || query.Get("client_secret") != "qq-secret" ||
				query.Get("code") != "qq-code" || query.Get("grant_type") != "authorization_code" ||
				query.Get("redirect_uri") != "https://app.example/callback" || query.Get("fmt") != "json" {
				t.Errorf("qq token query = %v", query)
			}
			_, _ = io.WriteString(w, `{"access_token":"qq-token","expires_in":7776000,"refresh_token":"qq-refresh"}`)
		case "/oauth2.0/me":
			if query.Get("access_token") != "qq-token" || query.Get("fmt") != "json" {
				t.Errorf("qq me query = %v", query)
			}
			_, _ = io.WriteString(w, `callback( {"client_id":"qq-app","openid":"qq-openid"} );`)
		case "/user/get":
			if query.Get("access_token") != "qq-token" || query.Get("oauth_consumer_key") != "qq-app" ||
				query.Get("openid") != "qq-openid" || query.Get("fmt") != "json" {
				t.Errorf("qq userinfo query = %v", query)
			}
			_, _ = io.WriteString(w, `{"ret":0,"msg":"","nickname":"QQ昵称","figureurl_qq_2":"https://example.com/qq.png","gender":"男"}`)
		default:
			http.NotFound(w, r)
		}
	})
	provider := QQ(ProviderConfig{
		ClientID:     "qq-app",
		ClientSecret: "qq-secret",
		RedirectURL:  "https://app.example/callback",
	}, WithEndpoints(Endpoints{TokenURL: server.URL + "/oauth2.0/token", UserInfoURL: server.URL + "/user/get"}))

	adapter := newAdapter(provider, nil)
	token, err := adapter.Exchange(context.Background(), "qq-code", "")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if token.AccessToken != "qq-token" || token.OpenID != "qq-openid" {
		t.Fatalf("qq token = %#v", token)
	}
	identity, err := adapter.UserInfo(context.Background(), token)
	if err != nil {
		t.Fatalf("UserInfo: %v", err)
	}
	if identity.Subject != "qq-openid" || identity.Name != "QQ昵称" || identity.AvatarURL != "https://example.com/qq.png" {
		t.Fatalf("qq identity = %#v", identity)
	}
	if identity.EmailVerified || identity.Username != "" {
		t.Fatalf("qq identity flags = %#v", identity)
	}
}

func TestOtherChinesePresetUserInfoDecoders(t *testing.T) {
	server := newFixtureServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/weibo":
			_, _ = io.WriteString(w, `{"id":12345,"screen_name":"微博用户","avatar_large":"https://example.com/wb.png"}`)
		case "/baidu":
			_, _ = io.WriteString(w, `{"userid":"baidu-1","username":"baidu_user","realname":"百度用户","portrait":"https://example.com/bd.png"}`)
		case "/gitee":
			_, _ = io.WriteString(w, `{"id":100,"login":"gitee_user","name":"码云用户","avatar_url":"https://example.com/gt.png"}`)
		default:
			http.NotFound(w, r)
		}
	})
	client := server.Client()
	ctx := context.Background()

	weibo := Weibo(ProviderConfig{ClientID: "weibo-app", UserInfoURL: server.URL + "/weibo"})
	weiboIdentity, err := weibo.UserInfoHook(ctx, weibo, client, &Token{AccessToken: "weibo-token", Raw: map[string]string{"uid": "12345"}})
	if err != nil {
		t.Fatalf("weibo UserInfo: %v", err)
	}
	if weiboIdentity.Subject != "12345" || weiboIdentity.Name != "微博用户" || weiboIdentity.AvatarURL != "https://example.com/wb.png" {
		t.Fatalf("weibo identity = %#v", weiboIdentity)
	}

	baidu := Baidu(ProviderConfig{ClientID: "baidu-app", UserInfoURL: server.URL + "/baidu"})
	baiduIdentity, err := baidu.UserInfoHook(ctx, baidu, client, &Token{AccessToken: "baidu-token"})
	if err != nil {
		t.Fatalf("baidu UserInfo: %v", err)
	}
	if baiduIdentity.Subject != "baidu-1" || baiduIdentity.Username != "baidu_user" ||
		baiduIdentity.Name != "百度用户" || baiduIdentity.AvatarURL != "https://example.com/bd.png" {
		t.Fatalf("baidu identity = %#v", baiduIdentity)
	}

	gitee := Gitee(ProviderConfig{ClientID: "gitee-app", UserInfoURL: server.URL + "/gitee"})
	giteeIdentity, err := gitee.UserInfoHook(ctx, gitee, client, &Token{AccessToken: "gitee-token"})
	if err != nil {
		t.Fatalf("gitee UserInfo: %v", err)
	}
	if giteeIdentity.Subject != "100" || giteeIdentity.Username != "gitee_user" ||
		giteeIdentity.Name != "码云用户" || giteeIdentity.AvatarURL != "https://example.com/gt.png" {
		t.Fatalf("gitee identity = %#v", giteeIdentity)
	}
}

func verifyAlipayForm(form url.Values, public *rsa.PublicKey) error {
	params := make(map[string]string, len(form))
	for key, values := range form {
		if key == "sign" || len(values) == 0 || values[0] == "" {
			continue
		}
		params[key] = values[0]
	}
	signature, err := base64.StdEncoding.DecodeString(form.Get("sign"))
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(alipayCanonicalString(params)))
	if err := rsa.VerifyPKCS1v15(public, crypto.SHA256, digest[:], signature); err != nil {
		return errors.New("invalid RSA2 signature")
	}
	return nil
}
