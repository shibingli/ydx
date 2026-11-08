package oauth2

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth"
)

// flowNow is the deterministic clock for authorization-flow tests. | flowNow 是授权流程测试使用的
// 确定性时钟。
var flowNow = time.Unix(1_700_000_000, 0).UTC()

// flowScopes returns the scope registry used by flow tests. | flowScopes 返回流程测试使用的作用域
// 注册表。
func flowScopes() *StaticScopes {
	return NewStaticScopes(
		Scope{Name: ScopeOpenID},
		Scope{Name: ScopeProfile},
		Scope{Name: ScopeOfflineAccess, OfflineAccess: true},
		Scope{Name: "api:read"},
	)
}

// flowClient returns the default confidential web client. | flowClient 返回默认机密 web 客户端。
func flowClient() *Client {
	client := &Client{
		ID:                      "web",
		RedirectURIs:            []string{"https://client.example/callback"},
		GrantTypes:              []string{GrantAuthorizationCode, GrantRefreshToken, GrantClientCredentials},
		ResponseTypes:           []string{ResponseCode},
		Scopes:                  []string{ScopeOpenID, ScopeProfile, ScopeOfflineAccess, "api:read"},
		TokenEndpointAuthMethod: ClientSecretBasic,
	}
	client.SetSecret("super-secret")
	return client
}

// flowServer builds a server with the given configuration overrides. | flowServer 用给定配置覆盖构建
// 服务器。
func flowServer(t *testing.T, mutate func(*ServerConfig)) (*Server, *Client) {
	t.Helper()
	client := flowClient()
	config := ServerConfig{
		Issuer:         "https://auth.example",
		Clients:        NewMemoryClientStore(client),
		Store:          NewMemoryStore(),
		Scopes:         flowScopes(),
		AccessTokenTTL: time.Minute,
		Clock:          func() time.Time { return flowNow },
		Authenticator: AuthenticatorFunc(func(context.Context, http.ResponseWriter, *http.Request, *AuthorizationRequest) (*auth.Principal, error) {
			return &auth.Principal{Subject: "user-1", AuthTime: flowNow, AMR: []string{"pwd"}}, nil
		}),
	}
	if mutate != nil {
		mutate(&config)
	}
	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	return server, client
}

// codeAuthorizationValues returns a valid authorization-code request. | codeAuthorizationValues 返回
// 合法的授权码请求参数。
func codeAuthorizationValues(client *Client, verifier string) url.Values {
	return url.Values{
		"response_type":         {ResponseCode},
		"client_id":             {client.ID},
		"redirect_uri":          {client.RedirectURIs[0]},
		"scope":                 {ScopeOpenID + " " + ScopeOfflineAccess},
		"state":                 {"state-1"},
		"code_challenge":        {CodeChallengeS256(verifier)},
		"code_challenge_method": {PKCES256},
	}
}

// locationValues returns the redirect query or fragment parameters. | locationValues 返回重定向的查询
// 或片段参数。
func locationValues(t *testing.T, resp *http.Response) url.Values {
	t.Helper()
	location, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse location %q: %v", resp.Header.Get("Location"), err)
	}
	if location.Fragment != "" {
		values, err := url.ParseQuery(location.Fragment)
		if err != nil {
			t.Fatalf("parse fragment: %v", err)
		}
		return values
	}
	return location.Query()
}

func TestAuthorizeLoginRequired(t *testing.T) {
	loginErr := AuthenticatorFunc(func(context.Context, http.ResponseWriter, *http.Request, *AuthorizationRequest) (*auth.Principal, error) {
		return nil, ErrLoginRequired
	})
	verifier, _ := pkcePair(t)
	cases := []struct {
		name   string
		mutate func(*ServerConfig)
		prompt string
		want   string
		status int
	}{
		{
			name:   "no authenticator",
			mutate: func(config *ServerConfig) { config.Authenticator = nil },
			want:   ErrorLoginRequired,
		},
		{
			name:   "authenticator requires login",
			mutate: func(config *ServerConfig) { config.Authenticator = loginErr },
			want:   ErrorLoginRequired,
		},
		{
			name: "authenticator returns nil principal",
			mutate: func(config *ServerConfig) {
				config.Authenticator = AuthenticatorFunc(func(context.Context, http.ResponseWriter, *http.Request, *AuthorizationRequest) (*auth.Principal, error) {
					return nil, nil
				})
			},
			want: ErrorLoginRequired,
		},
		{
			name:   "prompt none forbids interactive login",
			mutate: func(config *ServerConfig) { config.Authenticator = loginErr },
			prompt: "none",
			want:   ErrorLoginRequired,
		},
		{
			name: "login handler renders",
			mutate: func(config *ServerConfig) {
				config.Authenticator = loginErr
				config.LoginHandler = func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusNoContent)
				}
			},
			status: http.StatusNoContent,
		},
		{
			name: "max age exceeded",
			mutate: func(config *ServerConfig) {
				config.Authenticator = AuthenticatorFunc(func(context.Context, http.ResponseWriter, *http.Request, *AuthorizationRequest) (*auth.Principal, error) {
					return &auth.Principal{Subject: "user-1", AuthTime: flowNow.Add(-time.Hour)}, nil
				})
			},
			want: ErrorLoginRequired,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, client := flowServer(t, tc.mutate)
			params := codeAuthorizationValues(client, verifier)
			if tc.prompt != "" {
				params.Set("prompt", tc.prompt)
			}
			if tc.name == "max age exceeded" {
				params.Set("max_age", "60")
			}
			resp := authorize(t, server, params)
			if tc.status != 0 {
				if resp.StatusCode != tc.status {
					t.Fatalf("status = %d", resp.StatusCode)
				}
				return
			}
			if resp.StatusCode != http.StatusFound {
				t.Fatalf("status = %d", resp.StatusCode)
			}
			values := locationValues(t, resp)
			if values.Get("error") != tc.want || values.Get("state") != "state-1" {
				t.Fatalf("redirect = %v", values)
			}
		})
	}
}

func TestAuthorizeLoginRedirect(t *testing.T) {
	server, client := flowServer(t, func(config *ServerConfig) {
		config.Authenticator = AuthenticatorFunc(func(context.Context, http.ResponseWriter, *http.Request, *AuthorizationRequest) (*auth.Principal, error) {
			return nil, ErrLoginRequired
		})
		config.LoginURL = "https://auth.example/login?tenant=acme"
	})
	verifier, _ := pkcePair(t)
	resp := authorize(t, server, codeAuthorizationValues(client, verifier))
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	location, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if location.Host != "auth.example" || location.Path != "/login" || location.Query().Get("tenant") != "acme" {
		t.Fatalf("login location = %s", location)
	}
	returnTo := location.Query().Get("return_to")
	if !strings.HasPrefix(returnTo, "https://auth.example/authorize?") || !strings.Contains(returnTo, "client_id=web") {
		t.Fatalf("return_to = %q", returnTo)
	}
}

func TestAuthorizeConsentPolicies(t *testing.T) {
	verifier, _ := pkcePair(t)
	requested := []string{ScopeOpenID, ScopeProfile, ScopeOfflineAccess}
	cases := []struct {
		name    string
		consent ConsentHandler
		skip    bool
		want    string
	}{
		{
			name: "consent required with prompt none",
			consent: ConsentFunc(func(context.Context, http.ResponseWriter, *http.Request, *AuthorizationRequest, *auth.Principal) ([]string, error) {
				return nil, ErrConsentRequired
			}),
			want: ErrorConsentRequired,
		},
		{
			name: "consent denied with empty scopes",
			consent: ConsentFunc(func(context.Context, http.ResponseWriter, *http.Request, *AuthorizationRequest, *auth.Principal) ([]string, error) {
				return nil, nil
			}),
			want: ErrorAccessDenied,
		},
		{
			name: "consent grants unrequested scope",
			consent: ConsentFunc(func(context.Context, http.ResponseWriter, *http.Request, *AuthorizationRequest, *auth.Principal) ([]string, error) {
				return []string{ScopeOpenID, "admin"}, nil
			}),
			want: ErrorInvalidScope,
		},
		{
			name: "consent handler error",
			consent: ConsentFunc(func(context.Context, http.ResponseWriter, *http.Request, *AuthorizationRequest, *auth.Principal) ([]string, error) {
				return nil, errTest
			}),
			want: ErrorServerError,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, client := flowServer(t, func(config *ServerConfig) {
				config.Consent = tc.consent
			})
			params := codeAuthorizationValues(client, verifier)
			params.Set("scope", strings.Join(requested, " "))
			params.Set("prompt", "none")
			resp := authorize(t, server, params)
			if resp.StatusCode != http.StatusFound {
				t.Fatalf("status = %d", resp.StatusCode)
			}
			if values := locationValues(t, resp); values.Get("error") != tc.want {
				t.Fatalf("redirect = %v", values)
			}
		})
	}

	// Consent may grant a strict subset, which the code records. | 同意可授予严格子集，授权码会记录该子集。
	server, client := flowServer(t, func(config *ServerConfig) {
		config.Consent = ConsentFunc(func(context.Context, http.ResponseWriter, *http.Request, *AuthorizationRequest, *auth.Principal) ([]string, error) {
			return []string{ScopeOpenID}, nil
		})
	})
	params := codeAuthorizationValues(client, verifier)
	params.Set("scope", strings.Join(requested, " "))
	resp := authorize(t, server, params)
	values := locationValues(t, resp)
	code := values.Get("code")
	if resp.StatusCode != http.StatusFound || code == "" {
		t.Fatalf("consent subset status=%d values=%v", resp.StatusCode, values)
	}
	stored, err := server.config.Store.ConsumeAuthorizationCode(context.Background(), auth.HashToken(code), flowNow)
	if err != nil || len(stored.Scopes) != 1 || stored.Scopes[0] != ScopeOpenID {
		t.Fatalf("stored code = %+v err=%v", stored, err)
	}

	// SkipConsent bypasses the handler entirely. | SkipConsent 完全跳过同意处理器。
	skipped := flowClient()
	skipped.SkipConsent = true
	calls := 0
	server, _ = flowServer(t, func(config *ServerConfig) {
		config.Clients = NewMemoryClientStore(skipped)
		config.Consent = ConsentFunc(func(context.Context, http.ResponseWriter, *http.Request, *AuthorizationRequest, *auth.Principal) ([]string, error) {
			calls++
			return nil, ErrAccessDenied
		})
	})
	resp = authorize(t, server, codeAuthorizationValues(skipped, verifier))
	if resp.StatusCode != http.StatusFound || locationValues(t, resp).Get("code") == "" || calls != 0 {
		t.Fatalf("skip consent status=%d calls=%d", resp.StatusCode, calls)
	}
}

func TestAuthorizeResponseModes(t *testing.T) {
	verifier, _ := pkcePair(t)

	// form_post renders an auto-submitting form. | form_post 渲染自动提交表单。
	server, client := flowServer(t, nil)
	params := codeAuthorizationValues(client, verifier)
	params.Set("response_mode", ResponseModeFormPost)
	resp := authorize(t, server, params)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("form_post status = %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	if !strings.Contains(html, `method="post"`) || !strings.Contains(html, `action="https://client.example/callback"`) ||
		!strings.Contains(html, `name="code"`) || !strings.Contains(html, `name="state"`) ||
		!strings.Contains(html, `name="iss"`) {
		t.Fatalf("form_post html = %s", html)
	}

	// Implicit token responses use the fragment. | 隐式令牌响应使用片段。
	implicitClient := flowClient()
	implicitClient.ResponseTypes = []string{ResponseCode, ResponseToken}
	enricher := &fakeAuthorizationEnricher{}
	server, _ = flowServer(t, func(config *ServerConfig) {
		config.Clients = NewMemoryClientStore(implicitClient)
		config.AllowImplicit = true
		config.AuthorizationEnricher = enricher
	})
	resp = authorize(t, server, url.Values{
		"response_type": {ResponseToken},
		"client_id":     {implicitClient.ID},
		"redirect_uri":  {implicitClient.RedirectURIs[0]},
		"scope":         {"openid"},
		"state":         {"implicit"},
	})
	values := locationValues(t, resp)
	if resp.StatusCode != http.StatusFound || values.Get("access_token") == "" || values.Get("state") != "implicit" ||
		values.Get("token_type") != TokenTypeBearer {
		t.Fatalf("implicit redirect status=%d location=%q values=%v", resp.StatusCode, resp.Header.Get("Location"), values)
	}
	if enricher.Grant == nil || enricher.Grant.ResponseType != ResponseToken {
		t.Fatalf("authorization enricher grant = %+v", enricher.Grant)
	}

	// Hybrid flows fall back to the token enricher when the authorization enricher omits id_token. |
	// 混合流程在授权增强器未提供 id_token 时回退到令牌增强器。
	hybridClient := flowClient()
	hybridClient.ResponseTypes = []string{ResponseCode, "code id_token"}
	authEnricher := &fakeAuthorizationEnricher{}
	tokenEnricher := &fakeTokenEnricher{IDToken: "id-from-token"}
	server, _ = flowServer(t, func(config *ServerConfig) {
		config.Clients = NewMemoryClientStore(hybridClient)
		config.AuthorizationEnricher = authEnricher
		config.TokenEnricher = tokenEnricher
	})
	params = codeAuthorizationValues(hybridClient, verifier)
	params.Set("response_type", "code id_token")
	resp = authorize(t, server, params)
	values = locationValues(t, resp)
	if resp.StatusCode != http.StatusFound || values.Get("code") == "" || values.Get("id_token") != "id-from-token" {
		t.Fatalf("hybrid redirect = %v", values)
	}

	// An authorization enricher can supply the ID token directly. | 授权增强器可直接提供 ID 令牌。
	authEnricher = &fakeAuthorizationEnricher{IDToken: "id-from-auth", Params: url.Values{"session_state": {"s-1"}}}
	server, _ = flowServer(t, func(config *ServerConfig) {
		config.Clients = NewMemoryClientStore(hybridClient)
		config.AuthorizationEnricher = authEnricher
	})
	resp = authorize(t, server, params)
	values = locationValues(t, resp)
	if values.Get("id_token") != "id-from-auth" || values.Get("session_state") != "s-1" {
		t.Fatalf("enricher redirect = %v", values)
	}

	// The enricher error becomes a server_error redirect. | 增强器错误转为 server_error 重定向。
	authEnricher = &fakeAuthorizationEnricher{Err: errTest}
	server, _ = flowServer(t, func(config *ServerConfig) {
		config.Clients = NewMemoryClientStore(hybridClient)
		config.AuthorizationEnricher = authEnricher
	})
	resp = authorize(t, server, params)
	if values := locationValues(t, resp); values.Get("error") != ErrorServerError {
		t.Fatalf("enricher error redirect = %v", values)
	}

	// Without a token enricher the fallback cannot produce id_token. | 没有令牌增强器时回退无法生成
	// id_token。
	server, _ = flowServer(t, func(config *ServerConfig) {
		config.Clients = NewMemoryClientStore(hybridClient)
		config.AuthorizationEnricher = &fakeAuthorizationEnricher{}
	})
	resp = authorize(t, server, params)
	if values := locationValues(t, resp); values.Get("error") != ErrorUnsupportedResponseType {
		t.Fatalf("missing token enricher redirect = %v", values)
	}

	// A token enricher that returns no id_token is a server error. | 令牌增强器未返回 id_token 属于
	// 服务器错误。
	server, _ = flowServer(t, func(config *ServerConfig) {
		config.Clients = NewMemoryClientStore(hybridClient)
		config.AuthorizationEnricher = &fakeAuthorizationEnricher{}
		config.TokenEnricher = &fakeTokenEnricher{}
	})
	resp = authorize(t, server, params)
	if values := locationValues(t, resp); values.Get("error") != ErrorServerError {
		t.Fatalf("empty id_token redirect = %v", values)
	}
}

func TestAuthorizeValidationPolicies(t *testing.T) {
	verifier, _ := pkcePair(t)

	// Implicit flow disabled. | 隐式流程已禁用。
	implicitClient := flowClient()
	implicitClient.ResponseTypes = []string{ResponseCode, ResponseToken}
	server, _ := flowServer(t, func(config *ServerConfig) {
		config.Clients = NewMemoryClientStore(implicitClient)
	})
	resp := authorize(t, server, url.Values{
		"response_type": {ResponseToken},
		"client_id":     {implicitClient.ID},
		"redirect_uri":  {implicitClient.RedirectURIs[0]},
	})
	if values := locationValues(t, resp); values.Get("error") != ErrorUnsupportedResponseType {
		t.Fatalf("implicit disabled status=%d location=%q values=%v", resp.StatusCode, resp.Header.Get("Location"), values)
	}

	// id_token without an authorization enricher. | 没有授权增强器时的 id_token。
	idClient := flowClient()
	idClient.ResponseTypes = []string{ResponseCode, ResponseIDToken}
	server, _ = flowServer(t, func(config *ServerConfig) {
		config.Clients = NewMemoryClientStore(idClient)
	})
	resp = authorize(t, server, url.Values{
		"response_type": {ResponseIDToken},
		"client_id":     {idClient.ID},
		"redirect_uri":  {idClient.RedirectURIs[0]},
	})
	if values := locationValues(t, resp); values.Get("error") != ErrorUnsupportedResponseType {
		t.Fatalf("id_token without enricher = %v", values)
	}

	// Plain PKCE is opt-in. | 明文 PKCE 需显式启用。
	server, client := flowServer(t, nil)
	params := url.Values{
		"response_type":  {ResponseCode},
		"client_id":      {client.ID},
		"redirect_uri":   {client.RedirectURIs[0]},
		"scope":          {ScopeOpenID},
		"code_challenge": {verifier},
	}
	resp = authorize(t, server, params)
	if values := locationValues(t, resp); values.Get("error") != ErrorInvalidRequest {
		t.Fatalf("plain PKCE disabled = %v", values)
	}
	server, _ = flowServer(t, func(config *ServerConfig) { config.AllowPKCEPlain = true })
	resp = authorize(t, server, params)
	if values := locationValues(t, resp); resp.StatusCode != http.StatusFound || values.Get("code") == "" {
		t.Fatalf("plain PKCE enabled = %d %v", resp.StatusCode, values)
	}

	// AllowedResources restricts resource indicators. | AllowedResources 限制资源指示器。
	server, client = flowServer(t, func(config *ServerConfig) {
		config.AllowedResources = []string{"https://api.example"}
	})
	params = codeAuthorizationValues(client, verifier)
	params.Set("resource", "https://evil.example")
	resp = authorize(t, server, params)
	if values := locationValues(t, resp); values.Get("error") != ErrorInvalidTarget {
		t.Fatalf("disallowed resource = %v", values)
	}
	params.Set("resource", "https://api.example")
	resp = authorize(t, server, params)
	if values := locationValues(t, resp); values.Get("code") == "" {
		t.Fatalf("allowed resource = %v", values)
	}
	code := locationValues(t, resp).Get("code")
	stored, err := server.config.Store.ConsumeAuthorizationCode(context.Background(), auth.HashToken(code), flowNow)
	if err != nil || len(stored.Resource) != 1 || stored.Resource[0] != "https://api.example" {
		t.Fatalf("resource grant = %+v err=%v", stored, err)
	}

	// DPoP binding at the authorization endpoint. | 授权端点的 DPoP 绑定。
	dpop := &fakeDPoPVerifier{}
	server, client = flowServer(t, func(config *ServerConfig) {
		config.DPoPRequired = true
		config.DPoPVerifier = dpop
	})
	params = codeAuthorizationValues(client, verifier)
	resp = authorize(t, server, params)
	if values := locationValues(t, resp); values.Get("error") != ErrorInvalidDPoPProof {
		t.Fatalf("missing dpop_jkt = %v", values)
	}
	params.Set("dpop_jkt", strings.Repeat("a", 31))
	resp = authorize(t, server, params)
	if values := locationValues(t, resp); values.Get("error") != ErrorInvalidDPoPProof {
		t.Fatalf("short dpop_jkt = %v", values)
	}
	params.Set("dpop_jkt", strings.Repeat("a", 43))
	resp = authorize(t, server, params)
	values := locationValues(t, resp)
	if values.Get("code") == "" {
		t.Fatalf("valid dpop_jkt = %v", values)
	}
	stored, _ = server.config.Store.ConsumeAuthorizationCode(context.Background(), auth.HashToken(values.Get("code")), flowNow)
	if stored.DPoPJKT != strings.Repeat("a", 43) {
		t.Fatalf("code dpop binding = %q", stored.DPoPJKT)
	}

	// DisableIssuerParameter suppresses the RFC 9207 iss value. | DisableIssuerParameter 抑制
	// RFC 9207 的 iss 值。
	server, client = flowServer(t, func(config *ServerConfig) { config.DisableIssuerParameter = true })
	resp = authorize(t, server, codeAuthorizationValues(client, verifier))
	if values := locationValues(t, resp); values.Get("iss") != "" || values.Get("code") == "" {
		t.Fatalf("iss disabled = %v", values)
	}

	// DisablePKCEEnforcement allows code requests without PKCE. | DisablePKCEEnforcement 允许无
	// PKCE 的授权码请求。
	server, client = flowServer(t, func(config *ServerConfig) { config.DisablePKCEEnforcement = true })
	resp = authorize(t, server, url.Values{
		"response_type": {ResponseCode},
		"client_id":     {client.ID},
		"redirect_uri":  {client.RedirectURIs[0]},
		"scope":         {ScopeOpenID},
	})
	if values := locationValues(t, resp); values.Get("code") == "" {
		t.Fatalf("PKCE disabled = %v", values)
	}

	// A client not registered for the authorization-code grant is rejected. | 未注册授权码授权的
	// 客户端会被拒绝。
	noCode := flowClient()
	noCode.GrantTypes = []string{GrantClientCredentials}
	server, _ = flowServer(t, func(config *ServerConfig) {
		config.Clients = NewMemoryClientStore(noCode)
	})
	resp = authorize(t, server, codeAuthorizationValues(noCode, verifier))
	if values := locationValues(t, resp); values.Get("error") != ErrorUnauthorizedClient {
		t.Fatalf("unauthorized grant = %v", values)
	}

	// The client-level authorization-code TTL overrides the server default. | 客户端级授权码寿命覆盖
	// 服务器默认值。
	shortTTL := flowClient()
	shortTTL.AuthorizationCodeTTL = 7 * time.Second
	server, _ = flowServer(t, func(config *ServerConfig) { config.Clients = NewMemoryClientStore(shortTTL) })
	resp = authorize(t, server, codeAuthorizationValues(shortTTL, verifier))
	values = locationValues(t, resp)
	stored, _ = server.config.Store.ConsumeAuthorizationCode(context.Background(), auth.HashToken(values.Get("code")), flowNow)
	if stored == nil || stored.ExpiresAt.Sub(stored.CreatedAt) != 7*time.Second {
		t.Fatalf("client code ttl = %+v", stored)
	}
}

func TestAuthorizeErrorsWithoutRedirect(t *testing.T) {
	server, client := flowServer(t, nil)
	verifier, _ := pkcePair(t)

	// An unregistered redirect URI must not be used for error delivery. | 未注册重定向 URI 不得用于
	// 错误投递。
	params := codeAuthorizationValues(client, verifier)
	params.Set("redirect_uri", "https://evil.example/callback")
	w := doRequest(t, server.Authorize, http.MethodGet, "/authorize?"+params.Encode(), nil, nil)
	requireErrorCode(t, w, http.StatusBadRequest, ErrorInvalidRequest)

	// Unknown clients produce invalid_client with a Basic challenge. | 未知客户端产生带 Basic 挑战的
	// invalid_client。
	params = codeAuthorizationValues(client, verifier)
	params.Set("client_id", "unknown")
	w = doRequest(t, server.Authorize, http.MethodGet, "/authorize?"+params.Encode(), nil, nil)
	requireErrorCode(t, w, http.StatusUnauthorized, ErrorInvalidClient)
	if w.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("missing WWW-Authenticate")
	}

	// Unsupported HTTP methods and content types. | 不支持的 HTTP 方法与内容类型。
	w = doRequest(t, server.Authorize, http.MethodPut, "/authorize", nil, nil)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Header().Get("Allow"), "GET") {
		t.Fatalf("PUT = %d allow=%q", w.Code, w.Header().Get("Allow"))
	}
	w = doRequest(t, server.Authorize, http.MethodPost, "/authorize", nil, func(r *http.Request) {
		r.Header.Set("Content-Type", "application/json")
		r.Body = http.NoBody
	})
	requireErrorCode(t, w, http.StatusBadRequest, ErrorInvalidRequest)

	// A form POST succeeds. | 表单 POST 成功。
	form := codeAuthorizationValues(client, verifier)
	w = doRequest(t, server.Authorize, http.MethodPost, "/authorize", form, nil)
	if w.Code != http.StatusFound {
		t.Fatalf("POST status = %d body=%s", w.Code, w.Body.String())
	}
}

func TestAuthorizeRefreshIssuanceRules(t *testing.T) {
	verifier, _ := pkcePair(t)
	// OpenID alone does not authorize a refresh token. | 仅 openid 不授予刷新令牌。
	server, client := flowServer(t, nil)
	params := codeAuthorizationValues(client, verifier)
	params.Set("scope", ScopeOpenID)
	resp := authorize(t, server, params)
	values := locationValues(t, resp)
	code := values.Get("code")
	token, status := tokenRequest(t, server, url.Values{
		"grant_type":    {GrantAuthorizationCode},
		"code":          {code},
		"redirect_uri":  {client.RedirectURIs[0]},
		"code_verifier": {verifier},
	}, client.ID, "super-secret")
	if status != http.StatusOK || token.RefreshToken != "" {
		t.Fatalf("openid refresh = %+v status=%d", token, status)
	}

	// Offline access adds a refresh token. | offline_access 增加刷新令牌。
	params.Set("scope", ScopeOpenID+" "+ScopeOfflineAccess)
	resp = authorize(t, server, params)
	code = locationValues(t, resp).Get("code")
	token, status = tokenRequest(t, server, url.Values{
		"grant_type":    {GrantAuthorizationCode},
		"code":          {code},
		"redirect_uri":  {client.RedirectURIs[0]},
		"code_verifier": {verifier},
	}, client.ID, "super-secret")
	if status != http.StatusOK || token.RefreshToken == "" {
		t.Fatalf("offline refresh = %+v status=%d", token, status)
	}

	// Clients without the refresh grant never receive refresh tokens. | 未注册刷新授权的客户端永远
	// 不会获得刷新令牌。
	noRefresh := flowClient()
	noRefresh.GrantTypes = []string{GrantAuthorizationCode}
	server, _ = flowServer(t, func(config *ServerConfig) { config.Clients = NewMemoryClientStore(noRefresh) })
	resp = authorize(t, server, codeAuthorizationValues(noRefresh, verifier))
	code = locationValues(t, resp).Get("code")
	token, status = tokenRequest(t, server, url.Values{
		"grant_type":    {GrantAuthorizationCode},
		"code":          {code},
		"redirect_uri":  {noRefresh.RedirectURIs[0]},
		"code_verifier": {verifier},
	}, noRefresh.ID, "super-secret")
	if status != http.StatusOK || token.RefreshToken != "" {
		t.Fatalf("no-refresh client token = %+v status=%d", token, status)
	}
}
