package oauth2

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth"
)

// issuerPathServer builds a server whose issuer carries a path or whose mount prefix is explicit. |
// issuerPathServer 构建 issuer 带路径或显式挂载前缀的服务器。
func issuerPathServer(t *testing.T, mutate func(*ServerConfig), clients ...*Client) *Server {
	t.Helper()
	config := ServerConfig{
		Issuer:         "https://auth.example",
		Clients:        NewMemoryClientStore(clients...),
		Store:          NewMemoryStore(),
		Scopes:         flowScopes(),
		AccessTokenTTL: time.Minute,
		Clock:          func() time.Time { return flowNow },
	}
	if mutate != nil {
		mutate(&config)
	}
	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("new server: %v | 新服务器：%v", err, err)
	}
	return server
}

// TestMetadataEndpointsWithIssuerPath verifies that endpoint URLs are built from the mounted path
// instead of repeating an issuer path component. | TestMetadataEndpointsWithIssuerPath 校验端点 URL
// 由挂载路径构建，不会重复 issuer 的路径部分。
func TestMetadataEndpointsWithIssuerPath(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*ServerConfig)
	}{
		{
			name: "issuer path",
			mutate: func(config *ServerConfig) {
				config.Issuer = "https://auth.example/oauth"
			},
		},
		{
			name: "explicit prefix",
			mutate: func(config *ServerConfig) {
				config.PathPrefix = "/oauth"
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := issuerPathServer(t, tc.mutate)
			document := server.MetadataDocument()
			want := map[string]string{
				"authorization":       "https://auth.example/oauth/authorize",
				"token":               "https://auth.example/oauth/token",
				"revocation":          "https://auth.example/oauth/revoke",
				"introspection":       "https://auth.example/oauth/introspect",
				"par":                 "https://auth.example/oauth/par",
				"deviceAuthorization": "https://auth.example/oauth/device_authorization",
			}
			got := map[string]string{
				"authorization":       document.AuthorizationEndpoint,
				"token":               document.TokenEndpoint,
				"revocation":          document.RevocationEndpoint,
				"introspection":       document.IntrospectionEndpoint,
				"par":                 document.PushedAuthorizationRequestEndpoint,
				"deviceAuthorization": document.DeviceAuthorizationEndpoint,
			}
			for key, wantURL := range want {
				if got[key] != wantURL {
					t.Fatalf("%s endpoint = %q, want %q | %s 端点 = %q，期望 %q", key, got[key], wantURL, key, got[key], wantURL)
				}
			}
		})
	}
}

// TestEndpointUsesExplicitMountPrefix verifies that Endpoint includes an explicit PathPrefix even
// when the issuer carries no path, that Path returns the mounted path, and that the two methods
// must not be nested. | TestEndpointUsesExplicitMountPrefix 校验即使 issuer 不带路径，Endpoint 也会
// 包含显式 PathPrefix，Path 返回挂载后的路径，且两个方法不得嵌套调用。
func TestEndpointUsesExplicitMountPrefix(t *testing.T) {
	server := issuerPathServer(t, func(config *ServerConfig) {
		config.PathPrefix = "/oauth"
	})
	const want = "https://auth.example/oauth/token"
	if got := server.Endpoint("/token"); got != want {
		t.Fatalf("endpoint = %q, want %q | endpoint = %q，期望 %q", got, want, got, want)
	}
	if got := server.Path("/token"); got != "/oauth/token" {
		t.Fatalf("path = %q | path = %q", got, got)
	}
	if got := server.Endpoint(server.config.TokenPath); got != want {
		t.Fatalf("configured endpoint = %q, want %q | 配置端点 = %q，期望 %q", got, want, got, want)
	}
	// Passing an already mounted path applies the prefix twice; this is why callers pass the
	// unprefixed path instead of nesting Endpoint(Path(p)). | 传入已挂载路径会重复应用前缀；因此
	// 调用方应传未加前缀的路径，而不是嵌套调用 Endpoint(Path(p))。
	if got := server.Endpoint(server.Path("/token")); got != "https://auth.example/oauth/oauth/token" {
		t.Fatalf("nested endpoint = %q | 嵌套端点 = %q", got, got)
	}
}

// TestDeviceVerificationURIWithPathPrefix verifies that the device response advertises the mounted
// verification URI. | TestDeviceVerificationURIWithPathPrefix 校验设备响应公布的是挂载后的校验 URI。
func TestDeviceVerificationURIWithPathPrefix(t *testing.T) {
	public := &Client{
		ID:                      "device",
		GrantTypes:              []string{GrantDeviceCode},
		Public:                  true,
		TokenEndpointAuthMethod: ClientAuthNone,
	}
	server := issuerPathServer(t, func(config *ServerConfig) {
		config.PathPrefix = "/oauth"
	}, public)
	recorder := deviceHTTPRequest(t, http.HandlerFunc(server.DeviceAuthorization), http.MethodPost, "/oauth/device_authorization",
		url.Values{"client_id": {public.ID}}, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("device authorization = %d body=%s | 设备授权 = %d，正文 = %s", recorder.Code, recorder.Body.String(), recorder.Code, recorder.Body.String())
	}
	body := decodeMap(t, recorder)
	verificationURI, _ := body["verification_uri"].(string)
	complete, _ := body["verification_uri_complete"].(string)
	userCode, _ := body["user_code"].(string)
	if verificationURI != "https://auth.example/oauth/device" {
		t.Fatalf("verification_uri = %q | verification_uri = %q", verificationURI, verificationURI)
	}
	if complete != verificationURI+"?user_code="+url.QueryEscape(userCode) {
		t.Fatalf("verification_uri_complete = %q | verification_uri_complete = %q", complete, complete)
	}
}

// TestDeviceLoginRedirectKeepsLoginQuery verifies that an anonymous device verification redirect
// preserves parameters already present on LoginURL and uses the mounted return target. |
// TestDeviceLoginRedirectKeepsLoginQuery 校验匿名设备校验重定向保留 LoginURL 已有参数并使用挂载后的返回目标。
func TestDeviceLoginRedirectKeepsLoginQuery(t *testing.T) {
	server := issuerPathServer(t, func(config *ServerConfig) {
		config.PathPrefix = "/oauth"
		config.LoginURL = "https://login.example/signin?tenant=acme"
	})
	recorder := deviceHTTPRequest(t, http.HandlerFunc(server.DeviceVerification), http.MethodGet, "/oauth/device?user_code=ABCD-EFGH", nil, nil)
	if recorder.Code != http.StatusFound {
		t.Fatalf("redirect status = %d | 重定向状态 = %d", recorder.Code, recorder.Code)
	}
	location, err := url.Parse(recorder.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse location: %v | 解析 Location：%v", err, err)
	}
	if location.Host != "login.example" || location.Path != "/signin" || location.Query().Get("tenant") != "acme" {
		t.Fatalf("login location = %q | 登录地址 = %q", location.String(), location.String())
	}
	returnTo := location.Query().Get("return_to")
	target, err := url.Parse(returnTo)
	if err != nil {
		t.Fatalf("parse return_to: %v | 解析 return_to：%v", err, err)
	}
	if target.Scheme != "https" || target.Host != "auth.example" || target.Path != "/oauth/device" || target.Query().Get("user_code") != "ABCD-EFGH" {
		t.Fatalf("return_to = %q | return_to = %q", returnTo, returnTo)
	}
}

// TestAuthorizeLoginRedirectPreservesMethodParameters verifies that the login return target carries
// the authorization parameters of a POST request on the mounted path. |
// TestAuthorizeLoginRedirectPreservesMethodParameters 校验登录返回目标携带挂载路径上 POST 请求的授权参数。
func TestAuthorizeLoginRedirectPreservesMethodParameters(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(*ServerConfig)
		target   string
		wantPath string
	}{
		{
			name: "issuer path",
			mutate: func(config *ServerConfig) {
				config.Issuer = "https://auth.example/oauth"
			},
			target:   "/oauth/authorize",
			wantPath: "/oauth/authorize",
		},
		{
			name: "explicit prefix",
			mutate: func(config *ServerConfig) {
				config.PathPrefix = "/oauth"
			},
			target:   "/oauth/authorize",
			wantPath: "/oauth/authorize",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := flowClient()
			server := issuerPathServer(t, func(config *ServerConfig) {
				tc.mutate(config)
				config.LoginURL = "https://login.example/signin?tenant=acme"
				config.Authenticator = AuthenticatorFunc(func(context.Context, http.ResponseWriter, *http.Request, *AuthorizationRequest) (*auth.Principal, error) {
					return nil, ErrLoginRequired
				})
			}, client)
			verifier, _ := pkcePair(t)
			form := codeAuthorizationValues(client, verifier)
			request := httptest.NewRequest(http.MethodPost, tc.target, strings.NewReader(form.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			recorder := httptest.NewRecorder()
			server.Authorize(recorder, request)
			if recorder.Code != http.StatusFound {
				t.Fatalf("authorize status = %d body=%s | 授权状态 = %d，正文 = %s", recorder.Code, recorder.Body.String(), recorder.Code, recorder.Body.String())
			}
			location, err := url.Parse(recorder.Header().Get("Location"))
			if err != nil {
				t.Fatalf("parse location: %v | 解析 Location：%v", err, err)
			}
			if location.Query().Get("tenant") != "acme" {
				t.Fatalf("login query = %q | 登录查询 = %q", location.RawQuery, location.RawQuery)
			}
			returnTo, err := url.Parse(location.Query().Get("return_to"))
			if err != nil {
				t.Fatalf("parse return_to: %v | 解析 return_to：%v", err, err)
			}
			if returnTo.Scheme != "https" || returnTo.Host != "auth.example" || returnTo.Path != tc.wantPath {
				t.Fatalf("return_to = %q | return_to = %q", returnTo.String(), returnTo.String())
			}
			returned := returnTo.Query()
			for _, key := range []string{"response_type", "client_id", "redirect_uri", "scope", "state", "code_challenge", "code_challenge_method"} {
				if returned.Get(key) != form.Get(key) {
					t.Fatalf("return_to %s = %q, want %q | return_to %s = %q，期望 %q", key, returned.Get(key), form.Get(key), key, returned.Get(key), form.Get(key))
				}
			}
		})
	}
}

// TestClientAssertionAudienceUsesMountedEndpoint verifies the RFC 7523 audience for a private_key_jwt
// assertion sent to a server mounted under an issuer path. |
// TestClientAssertionAudienceUsesMountedEndpoint 校验挂载在 issuer 路径下的服务器收到的
// private_key_jwt 断言使用正确的 RFC 7523 受众。
func TestClientAssertionAudienceUsesMountedEndpoint(t *testing.T) {
	client := &Client{
		ID:                      "jwt-client",
		GrantTypes:              []string{GrantClientCredentials},
		Scopes:                  []string{"api:read"},
		TokenEndpointAuthMethod: PrivateKeyJWT,
	}
	verifier := &fakeClientAssertionVerifier{}
	server := issuerPathServer(t, func(config *ServerConfig) {
		config.Issuer = "https://auth.example/oauth"
		config.ClientAssertionVerifier = verifier
	}, client)
	form := url.Values{
		"grant_type":            {GrantClientCredentials},
		"client_id":             {client.ID},
		"client_assertion":      {"assertion-1"},
		"client_assertion_type": {ClientAssertionTypeJWTBearer},
		"scope":                 {"api:read"},
	}
	request := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	server.Token(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("token status = %d body=%s | 令牌状态 = %d，正文 = %s", recorder.Code, recorder.Body.String(), recorder.Code, recorder.Body.String())
	}
	if verifier.LastAudience != "https://auth.example/oauth/token" {
		t.Fatalf("assertion audience = %q | 断言受众 = %q", verifier.LastAudience, verifier.LastAudience)
	}
}

// TestIntrospectionHintFallsBack verifies the RFC 7662 requirement to search other token types when
// the hinted type does not contain the token. | TestIntrospectionHintFallsBack 校验 RFC 7662 的要求：
// 提示类型中找不到令牌时搜索其他令牌类型。
func TestIntrospectionHintFallsBack(t *testing.T) {
	server, client, _ := testServer(t)
	ctx := context.Background()
	now := server.Now()
	refreshRaw := "refresh-fallback"
	if err := server.config.Store.SaveRefreshToken(ctx, &RefreshToken{
		TokenHash: auth.HashToken(refreshRaw), FamilyID: "family", ClientID: client.ID,
		Subject: "user-1", Scopes: []string{"api:read"},
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	accessRaw := "access-fallback"
	if err := server.config.Store.SaveAccessToken(ctx, &AccessToken{
		TokenHash: auth.HashToken(accessRaw), ClientID: client.ID, Subject: "user-1",
		Scopes: []string{"api:read"}, IssuedAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		token string
		hint  string
	}{
		{name: "refresh with access hint", token: refreshRaw, hint: "access_token"},
		{name: "access with refresh hint", token: accessRaw, hint: "refresh_token"},
		{name: "refresh without hint", token: refreshRaw, hint: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := introspectRequest(t, server, client.ID, "super-secret", tc.token, tc.hint)
			body := decodeMap(t, recorder)
			if body["active"] != true {
				t.Fatalf("introspection = %v | 自省结果 = %v", body, body)
			}
		})
	}
}

// TestRevocationHintFallsBack verifies the RFC 7009 requirement to search other token types when
// the hinted type does not contain the token. | TestRevocationHintFallsBack 校验 RFC 7009 的要求：
// 提示类型中找不到令牌时搜索其他令牌类型。
func TestRevocationHintFallsBack(t *testing.T) {
	server, client, _ := testServer(t)
	ctx := context.Background()
	now := server.Now()
	refreshRaw := "revoke-refresh"
	refreshHash := auth.HashToken(refreshRaw)
	if err := server.config.Store.SaveRefreshToken(ctx, &RefreshToken{
		TokenHash: refreshHash, FamilyID: "family", ClientID: client.ID,
		Subject: "user-1", Scopes: []string{"api:read"},
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	accessRaw := "revoke-access"
	accessHash := auth.HashToken(accessRaw)
	if err := server.config.Store.SaveAccessToken(ctx, &AccessToken{
		TokenHash: accessHash, ClientID: client.ID, Subject: "user-1",
		Scopes: []string{"api:read"}, IssuedAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if recorder := revokeRequest(t, server, client.ID, "super-secret", refreshRaw, "access_token"); recorder.Code != http.StatusOK {
		t.Fatalf("refresh revocation status = %d | 刷新令牌撤销状态 = %d", recorder.Code, recorder.Code)
	}
	refresh, err := server.config.Store.GetRefreshToken(ctx, refreshHash)
	if err != nil || !refresh.Revoked {
		t.Fatalf("refresh revoked = %v err=%v | 刷新令牌已撤销 = %v，错误 = %v", refresh, err, refresh, err)
	}
	if recorder := revokeRequest(t, server, client.ID, "super-secret", accessRaw, "refresh_token"); recorder.Code != http.StatusOK {
		t.Fatalf("access revocation status = %d | 访问令牌撤销状态 = %d", recorder.Code, recorder.Code)
	}
	access, err := server.config.Store.GetAccessToken(ctx, accessHash)
	if err != nil || !access.Revoked {
		t.Fatalf("access revoked = %v err=%v | 访问令牌已撤销 = %v，错误 = %v", access, err, access, err)
	}
}

// introspectRequest posts one introspection request with Basic client authentication. |
// introspectRequest 使用 Basic 客户端认证提交一次自省请求。
func introspectRequest(t *testing.T, server *Server, clientID, secret, token, hint string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"token": {token}}
	if hint != "" {
		form.Set("token_type_hint", hint)
	}
	request := httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(secret))
	recorder := httptest.NewRecorder()
	server.Introspect(recorder, request)
	return recorder
}

// revokeRequest posts one revocation request with Basic client authentication. | revokeRequest 使用
// Basic 客户端认证提交一次撤销请求。
func revokeRequest(t *testing.T, server *Server, clientID, secret, token, hint string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"token": {token}}
	if hint != "" {
		form.Set("token_type_hint", hint)
	}
	request := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(secret))
	recorder := httptest.NewRecorder()
	server.Revoke(recorder, request)
	return recorder
}

// failingTokenStore wraps MemoryStore and fails access-token lookups. | failingTokenStore 包装
// MemoryStore 并让访问令牌查询失败。
type failingTokenStore struct {
	*MemoryStore
	nilToken bool
}

// GetAccessToken implements Store. | GetAccessToken 实现 Store。
func (s failingTokenStore) GetAccessToken(context.Context, string) (*AccessToken, error) {
	if s.nilToken {
		return nil, nil
	}
	return nil, errTest
}

// TestFormEndpointsRejectOversizedBody verifies that form endpoints reject a body above the
// configured cap instead of buffering it. | TestFormEndpointsRejectOversizedBody 校验表单端点拒绝
// 超过上限的正文，而不是完整缓冲。
func TestFormEndpointsRejectOversizedBody(t *testing.T) {
	server := issuerPathServer(t, nil)
	payload := "grant_type=client_credentials&padding=" + strings.Repeat("a", maxFormBodyBytes)
	request := httptest.NewRequest(http.MethodPost, "https://auth.example/token", strings.NewReader(payload))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	server.Token(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 | 状态 = %d，期望 400", recorder.Code, recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), ErrorInvalidRequest) {
		t.Fatalf("body = %q, want invalid_request | 正文 = %q，期望 invalid_request", recorder.Body.String(), recorder.Body.String())
	}
}

// TestAuthorizationParserRejectsOversizedBody verifies the standalone authorization parser applies
// the same body cap without a ResponseWriter. | TestAuthorizationParserRejectsOversizedBody 校验独立
// 授权解析器在没有 ResponseWriter 时同样限制正文大小。
func TestAuthorizationParserRejectsOversizedBody(t *testing.T) {
	payload := "client_id=c&padding=" + strings.Repeat("a", maxFormBodyBytes)
	request := httptest.NewRequest(http.MethodPost, "https://auth.example/authorize", strings.NewReader(payload))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_, err := ParseAuthorizationRequestContext(context.Background(), request, NewMemoryClientStore(), flowScopes())
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("error = %v, want ErrInvalidRequest | 错误 = %v，期望 ErrInvalidRequest", err, err)
	}
}

// TestJWTValidationFailsClosedOnStoreError verifies that a JWT access token is rejected when the
// revocation store fails and that a nil store record cannot panic validation. |
// TestJWTValidationFailsClosedOnStoreError 校验撤销存储失败时拒绝 JWT 访问令牌，且空存储记录不会
// 让校验发生 panic。
func TestJWTValidationFailsClosedOnStoreError(t *testing.T) {
	claims := &AccessTokenClaims{
		Issuer: "https://auth.example", Subject: "user-1", ClientID: "web",
		IssuedAt: flowNow.Unix(), ExpiresAt: flowNow.Add(time.Minute).Unix(), JTI: "jti-1",
	}
	for _, tc := range []struct {
		name  string
		store Store
	}{
		{name: "store error", store: failingTokenStore{MemoryStore: NewMemoryStore()}},
		{name: "nil record", store: failingTokenStore{MemoryStore: NewMemoryStore(), nilToken: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := issuerPathServer(t, func(config *ServerConfig) {
				config.Store = tc.store
				config.TokenFormat = TokenFormatJWT
				config.AccessTokenIssuer = &fakeJWTIssuer{Token: "jwt-token"}
				config.AccessTokenVerifier = &fakeJWTVerifier{Claims: claims}
			})
			if _, err := server.ValidateAccessToken(context.Background(), "jwt-token"); err == nil {
				t.Fatal("JWT access token was accepted despite an unusable revocation store | 撤销存储不可用时仍接受了 JWT 访问令牌")
			}
		})
	}
}
