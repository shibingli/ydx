package oauth2

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/json"
	"github.com/shibingli/ydx/router"
)

// testServer returns an OAuth server with one confidential client and one public device client. | testServer
// 返回带一个机密客户端与一个公共设备客户端的 OAuth 服务器。
func testServer(t *testing.T) (*Server, *Client, *Client) {
	t.Helper()
	confidential := &Client{
		ID:                      "web",
		RedirectURIs:            []string{"https://client.example/callback"},
		GrantTypes:              []string{GrantAuthorizationCode, GrantRefreshToken, GrantClientCredentials},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid", "profile", "offline_access", "api:read"},
		TokenEndpointAuthMethod: ClientSecretBasic,
	}
	confidential.SetSecret("super-secret")
	public := &Client{
		ID:                      "device",
		GrantTypes:              []string{GrantDeviceCode},
		ResponseTypes:           []string{"code"},
		Public:                  true,
		TokenEndpointAuthMethod: ClientAuthNone,
	}
	clients := NewMemoryClientStore(confidential, public)
	scopes := NewStaticScopes(
		Scope{Name: ScopeOpenID, Description: "openid"},
		Scope{Name: ScopeProfile, Description: "profile"},
		Scope{Name: ScopeOfflineAccess, Description: "offline", OfflineAccess: true},
		Scope{Name: "api:read", Description: "api read"},
	)
	authenticator := AuthenticatorFunc(func(context.Context, http.ResponseWriter, *http.Request, *AuthorizationRequest) (*auth.Principal, error) {
		return &auth.Principal{Subject: "user-1", AuthTime: time.Now().UTC(), AMR: []string{"pwd"}}, nil
	})
	server, err := NewServer(ServerConfig{
		Issuer:         "https://auth.example",
		Clients:        clients,
		Store:          NewMemoryStore(),
		Scopes:         scopes,
		Authenticator:  authenticator,
		AccessTokenTTL: time.Minute,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	return server, confidential, public
}

// pkcePair returns a verifier and its S256 challenge. | pkcePair 返回校验器及其 S256 挑战。
func pkcePair(t *testing.T) (string, string) {
	t.Helper()
	verifier, err := GenerateCodeVerifier()
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	return verifier, CodeChallengeS256(verifier)
}

// authorize performs an authorization request and returns the redirect location. | authorize 执行授权请求并返回重定向位置。
func authorize(t *testing.T, server *Server, query url.Values) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/authorize?"+query.Encode(), nil)
	w := httptest.NewRecorder()
	server.Authorize(w, req)
	return w.Result()
}

// tokenRequest performs a token request and decodes the response. | tokenRequest 执行令牌请求并解码响应。
func tokenRequest(t *testing.T, server *Server, form url.Values, clientID, secret string) (*TokenResponse, int) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(secret))
	w := httptest.NewRecorder()
	server.Token(w, req)
	if w.Code != http.StatusOK {
		return nil, w.Code
	}
	var response TokenResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode token response: %v (%s)", err, w.Body.String())
	}
	return &response, w.Code
}

func TestAuthorizationCodePKCEAndRefreshLifecycle(t *testing.T) {
	server, client, _ := testServer(t)
	verifier, challenge := pkcePair(t)
	params := url.Values{
		"response_type":         {ResponseCode},
		"client_id":             {client.ID},
		"redirect_uri":          {client.RedirectURIs[0]},
		"scope":                 {"openid profile offline_access api:read"},
		"state":                 {"state-1"},
		"code_challenge":        {challenge},
		"code_challenge_method": {PKCES256},
	}
	resp := authorize(t, server, params)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d", resp.StatusCode)
	}
	location, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if location.Query().Get("state") != "state-1" || location.Query().Get("iss") != server.Issuer() {
		t.Fatalf("redirect = %s", location)
	}
	code := location.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in %s", location)
	}

	form := url.Values{
		"grant_type":    {GrantAuthorizationCode},
		"code":          {code},
		"redirect_uri":  {client.RedirectURIs[0]},
		"code_verifier": {verifier},
	}
	token, status := tokenRequest(t, server, form, client.ID, "super-secret")
	if status != http.StatusOK || token.AccessToken == "" || token.RefreshToken == "" {
		t.Fatalf("token = %+v status=%d", token, status)
	}
	if token.TokenType != TokenTypeBearer {
		t.Fatalf("token type = %q", token.TokenType)
	}
	// A code is single use. | 授权码单次使用。
	if _, status := tokenRequest(t, server, form, client.ID, "super-secret"); status != http.StatusBadRequest {
		t.Fatalf("code reuse status = %d", status)
	}

	// Introspection sees the active token. | 自省看到活跃令牌。
	introspect := httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(url.Values{"token": {token.AccessToken}}.Encode()))
	introspect.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	introspect.SetBasicAuth(url.QueryEscape(client.ID), url.QueryEscape("super-secret"))
	w := httptest.NewRecorder()
	server.Introspect(w, introspect)
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["active"] != true {
		t.Fatalf("introspection = %v", body)
	}

	// Refresh rotates the token. | 刷新轮换令牌。
	refreshToken, status := tokenRequest(t, server, url.Values{
		"grant_type":    {GrantRefreshToken},
		"refresh_token": {token.RefreshToken},
	}, client.ID, "super-secret")
	if status != http.StatusOK || refreshToken.AccessToken == "" || refreshToken.RefreshToken == "" {
		t.Fatalf("refresh = %+v status=%d", refreshToken, status)
	}
	if refreshToken.RefreshToken == token.RefreshToken {
		t.Fatal("refresh token was not rotated")
	}
	// Reusing the old refresh token reports invalid_grant and revokes the family. | 复用旧刷新令牌返回
	// invalid_grant 并撤销整个家族。
	reuse := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(url.Values{
		"grant_type":    {GrantRefreshToken},
		"refresh_token": {token.RefreshToken},
	}.Encode()))
	reuse.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reuse.SetBasicAuth(url.QueryEscape(client.ID), url.QueryEscape("super-secret"))
	w = httptest.NewRecorder()
	server.Token(w, reuse)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), ErrorInvalidGrant) {
		t.Fatalf("reuse status = %d body=%s", w.Code, w.Body.String())
	}

	// Revocation makes the new token inactive. | 撤销使新令牌失效。
	revoke := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(url.Values{"token": {refreshToken.AccessToken}}.Encode()))
	revoke.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	revoke.SetBasicAuth(url.QueryEscape(client.ID), url.QueryEscape("super-secret"))
	w = httptest.NewRecorder()
	server.Revoke(w, revoke)
	if w.Code != http.StatusOK {
		t.Fatalf("revoke status = %d", w.Code)
	}
	if _, err := server.ValidateAccessToken(context.Background(), refreshToken.AccessToken); err == nil {
		t.Fatal("revoked access token still validates")
	}
}

func TestPushedAuthorizationRequest(t *testing.T) {
	server, client, _ := testServer(t)
	_, challenge := pkcePair(t)
	form := url.Values{
		"response_type":         {ResponseCode},
		"client_id":             {client.ID},
		"redirect_uri":          {client.RedirectURIs[0]},
		"scope":                 {"openid"},
		"state":                 {"par-state"},
		"code_challenge":        {challenge},
		"code_challenge_method": {PKCES256},
	}
	req := httptest.NewRequest(http.MethodPost, "/par", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(client.ID), url.QueryEscape("super-secret"))
	w := httptest.NewRecorder()
	server.PAR(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("PAR status = %d body=%s", w.Code, w.Body.String())
	}
	var pushed struct {
		RequestURI string `json:"request_uri"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &pushed); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(pushed.RequestURI, PARRequestURIPrefix) {
		t.Fatalf("request_uri = %q", pushed.RequestURI)
	}
	resp := authorize(t, server, url.Values{"client_id": {client.ID}, "request_uri": {pushed.RequestURI}})
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize via PAR status = %d", resp.StatusCode)
	}
	location, _ := url.Parse(resp.Header.Get("Location"))
	if location.Query().Get("state") != "par-state" {
		t.Fatalf("PAR redirect = %s", location)
	}
	// The request URI is single use. | 请求 URI 单次使用。
	resp = authorize(t, server, url.Values{"client_id": {client.ID}, "request_uri": {pushed.RequestURI}})
	if resp.StatusCode == http.StatusFound {
		t.Fatal("request_uri was reusable")
	}
}

func TestDeviceFlow(t *testing.T) {
	server, _, public := testServer(t)
	form := url.Values{"client_id": {public.ID}, "scope": {"openid"}}
	req := httptest.NewRequest(http.MethodPost, "/device_authorization", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	server.DeviceAuthorization(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("device authorization status = %d body=%s", w.Code, w.Body.String())
	}
	var device struct {
		DeviceCode string `json:"device_code"`
		UserCode   string `json:"user_code"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &device); err != nil {
		t.Fatal(err)
	}
	principal := &auth.Principal{Subject: "user-2", AuthTime: time.Now().UTC()}
	approve := httptest.NewRequest(http.MethodPost, "/device", strings.NewReader(url.Values{
		"user_code": {device.UserCode},
		"action":    {"approve"},
	}.Encode()))
	approve.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	approve = approve.WithContext(auth.ContextWithPrincipal(approve.Context(), principal))
	w = httptest.NewRecorder()
	server.DeviceVerification(w, approve)
	if w.Code != http.StatusOK {
		t.Fatalf("device approval status = %d body=%s", w.Code, w.Body.String())
	}
	req = httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(url.Values{
		"grant_type":  {GrantDeviceCode},
		"device_code": {device.DeviceCode},
		"client_id":   {public.ID},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	server.Token(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("device token status = %d body=%s", w.Code, w.Body.String())
	}
	var token TokenResponse
	if err := json.Unmarshal(w.Body.Bytes(), &token); err != nil {
		t.Fatal(err)
	}
	if token.AccessToken == "" {
		t.Fatalf("device token = %+v", token)
	}
}

func TestClientCredentialsAndMetadata(t *testing.T) {
	server, client, _ := testServer(t)
	token, status := tokenRequest(t, server, url.Values{
		"grant_type": {GrantClientCredentials},
		"scope":      {"api:read"},
	}, client.ID, "super-secret")
	if status != http.StatusOK || token.AccessToken == "" {
		t.Fatalf("client credentials = %+v status=%d", token, status)
	}
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()
	server.Metadata(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("metadata status = %d", w.Code)
	}
	var metadata ServerMetadata
	if err := json.Unmarshal(w.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.Issuer != server.Issuer() || metadata.AuthorizationEndpoint == "" {
		t.Fatalf("metadata = %+v", metadata)
	}
}

func TestAuthorizationRequiresPKCE(t *testing.T) {
	server, client, _ := testServer(t)
	resp := authorize(t, server, url.Values{
		"response_type": {ResponseCode},
		"client_id":     {client.ID},
		"redirect_uri":  {client.RedirectURIs[0]},
		"scope":         {"openid"},
		"state":         {"s"},
	})
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	location, _ := url.Parse(resp.Header.Get("Location"))
	if location.Query().Get("error") != ErrorInvalidRequest {
		t.Fatalf("redirect = %s", location)
	}
}

func TestRouterRegistration(t *testing.T) {
	server, _, _ := testServer(t)
	r := router.New()
	server.Register(r)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("router metadata status = %d body=%s", w.Code, w.Body.String())
	}
}
