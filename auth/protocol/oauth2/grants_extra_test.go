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

// grantClient returns a web client allowed to use every optional grant. | grantClient 返回允许所有可选
// 授权的 web 客户端。
func grantClient() *Client {
	client := flowClient()
	client.GrantTypes = []string{
		GrantAuthorizationCode, GrantRefreshToken, GrantClientCredentials,
		GrantPassword, GrantTokenExchange, GrantJWTBearer,
	}
	return client
}

// grantServer builds a server enabling token exchange, JWT bearer and password grants. | grantServer 构建
// 启用令牌交换、JWT 承载与口令授权的服务器。
func grantServer(t *testing.T, mutate func(*ServerConfig)) (*Server, *Client) {
	t.Helper()
	client := grantClient()
	config := ServerConfig{
		Issuer:              "https://auth.example",
		Clients:             NewMemoryClientStore(client),
		Store:               NewMemoryStore(),
		Scopes:              flowScopes(),
		AccessTokenTTL:      time.Minute,
		Clock:               func() time.Time { return flowNow },
		EnableTokenExchange: true,
		EnableJWTBearer:     true,
		AllowPasswordGrant:  true,
		SubjectTokenValidator: &fakeSubjectTokenValidator{Principal: &auth.Principal{
			Subject: "user-1",
			Scopes:  []string{ScopeOpenID, "api:read"},
		}},
		JWTBearerValidator:    &fakeJWTBearerValidator{Principal: &auth.Principal{Subject: "user-1", Scopes: []string{"api:read"}}},
		PasswordAuthenticator: &fakePasswordAuthenticator{Principal: &auth.Principal{Subject: "user-1", Scopes: []string{"api:read"}}},
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

func TestTokenExchangeGrant(t *testing.T) {
	server, client := grantServer(t, nil)
	form := url.Values{
		"grant_type":         {GrantTokenExchange},
		"subject_token":      {"subject-1"},
		"subject_token_type": {SubjectTokenAccessToken},
		"scope":              {"api:read"},
		"audience":           {"https://api.example"},
	}
	token, status := tokenRequest(t, server, form, client.ID, "super-secret")
	if status != http.StatusOK || token.AccessToken == "" || token.IssuedTokenType != SubjectTokenAccessToken {
		t.Fatalf("exchange = %+v status=%d", token, status)
	}
	access, err := server.ValidateAccessToken(context.Background(), token.AccessToken)
	if err != nil || access.Subject != "user-1" || len(access.Audience) != 1 {
		t.Fatalf("exchanged token = %+v err=%v", access, err)
	}

	// Missing parameters, bad scopes and unsupported output types. | 缺少参数、非法作用域与不支持的输出
	// 类型。
	bad := url.Values{"grant_type": {GrantTokenExchange}}
	if _, status := tokenRequest(t, server, bad, client.ID, "super-secret"); status != http.StatusBadRequest {
		t.Fatalf("missing subject = %d", status)
	}
	bad = url.Values{
		"grant_type":         {GrantTokenExchange},
		"subject_token":      {"s"},
		"subject_token_type": {SubjectTokenAccessToken},
		"scope":              {"admin"},
	}
	if _, status := tokenRequest(t, server, bad, client.ID, "super-secret"); status != http.StatusBadRequest {
		t.Fatalf("bad scope = %d", status)
	}
	bad = url.Values{
		"grant_type":           {GrantTokenExchange},
		"subject_token":        {"s"},
		"subject_token_type":   {SubjectTokenAccessToken},
		"requested_token_type": {"magic"},
	}
	if _, status := tokenRequest(t, server, bad, client.ID, "super-secret"); status != http.StatusBadRequest {
		t.Fatalf("bad requested type = %d", status)
	}
	actor := url.Values{
		"grant_type":         {GrantTokenExchange},
		"subject_token":      {"s"},
		"subject_token_type": {SubjectTokenAccessToken},
		"actor_token":        {"a"},
	}
	if _, status := tokenRequest(t, server, actor, client.ID, "super-secret"); status != http.StatusBadRequest {
		t.Fatalf("actor without type = %d", status)
	}
	actor.Set("actor_token_type", SubjectTokenAccessToken)
	if token, status := tokenRequest(t, server, actor, client.ID, "super-secret"); status != http.StatusOK || token.AccessToken == "" {
		t.Fatalf("actor token = %+v status=%d", token, status)
	}

	// Disabled or unauthorized exchange. | 已禁用或未授权的交换。
	disabled, disabledClient := grantServer(t, func(config *ServerConfig) { config.EnableTokenExchange = false })
	if _, status := tokenRequest(t, disabled, form, disabledClient.ID, "super-secret"); status != http.StatusBadRequest {
		t.Fatalf("disabled = %d", status)
	}
	unauthorized := grantClient()
	unauthorized.GrantTypes = []string{GrantAuthorizationCode}
	server, _ = grantServer(t, func(config *ServerConfig) { config.Clients = NewMemoryClientStore(unauthorized) })
	if _, status := tokenRequest(t, server, form, unauthorized.ID, "super-secret"); status != http.StatusBadRequest {
		t.Fatalf("unauthorized = %d", status)
	}
}

func TestTokenExchangeSubjectAndOutputTypes(t *testing.T) {
	ctx := context.Background()
	server, client := grantServer(t, func(config *ServerConfig) {
		config.SubjectTokenValidator = nil
	})
	// Opaque subject tokens are validated through the access-token store. | 不透明主体令牌通过访问
	// 令牌存储校验。
	raw := "subject-access"
	if err := server.config.Store.SaveAccessToken(ctx, &AccessToken{
		TokenHash: auth.HashToken(raw), ClientID: client.ID, Subject: "user-1",
		Scopes: []string{"api:read"}, IssuedAt: flowNow, ExpiresAt: flowNow.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	form := url.Values{
		"grant_type":         {GrantTokenExchange},
		"subject_token":      {raw},
		"subject_token_type": {SubjectTokenAccessToken},
		"scope":              {"api:read"},
	}
	if token, status := tokenRequest(t, server, form, client.ID, "super-secret"); status != http.StatusOK || token.AccessToken == "" {
		t.Fatalf("opaque subject = %+v status=%d", token, status)
	}
	form.Set("subject_token_type", "magic")
	if _, status := tokenRequest(t, server, form, client.ID, "super-secret"); status != http.StatusBadRequest {
		t.Fatalf("unsupported subject type = %d", status)
	}
	jwtForm := url.Values{
		"grant_type":         {GrantTokenExchange},
		"subject_token":      {"jwt-subject"},
		"subject_token_type": {SubjectTokenJWT},
	}
	if _, status := tokenRequest(t, server, jwtForm, client.ID, "super-secret"); status != http.StatusBadRequest {
		t.Fatalf("JWT subject without verifier = %d", status)
	}

	// ID-token output requires an enricher and gets the openid scope. | ID 令牌输出需要增强器并获得
	// openid 作用域。
	enricher := &fakeTokenEnricher{IDToken: "id-token"}
	server, client = grantServer(t, func(config *ServerConfig) { config.TokenEnricher = enricher })
	idRequest := url.Values{
		"grant_type":           {GrantTokenExchange},
		"subject_token":        {"s"},
		"subject_token_type":   {SubjectTokenAccessToken},
		"requested_token_type": {SubjectTokenIDToken},
	}
	if token, status := tokenRequest(t, server, idRequest, client.ID, "super-secret"); status != http.StatusOK || token.IDToken != "id-token" || token.IssuedTokenType != SubjectTokenIDToken {
		t.Fatalf("id token output = %+v status=%d", token, status)
	}
	server, client = grantServer(t, nil)
	if _, status := tokenRequest(t, server, idRequest, client.ID, "super-secret"); status != http.StatusBadRequest {
		t.Fatalf("id token without enricher = %d", status)
	}

	// JWT output requires the JWT token format. | JWT 输出需要 JWT 令牌格式。
	key, keySet := newTestJWTKey(t)
	issuer, err := NewJWTAccessTokenIssuer(key, "ES256")
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewJWTAccessTokenVerifier(keySet, "https://auth.example", "https://api.example")
	if err != nil {
		t.Fatal(err)
	}
	verifier.SetClock(func() time.Time { return flowNow })
	server, client = grantServer(t, func(config *ServerConfig) {
		config.TokenFormat = TokenFormatJWT
		config.AccessTokenIssuer = issuer
		config.AccessTokenVerifier = verifier
	})
	jwtRequest := url.Values{
		"grant_type":           {GrantTokenExchange},
		"subject_token":        {"s"},
		"subject_token_type":   {SubjectTokenAccessToken},
		"requested_token_type": {SubjectTokenJWT},
		"scope":                {"api:read"},
		"audience":             {"https://api.example"},
	}
	jwtToken, status := tokenRequest(t, server, jwtRequest, client.ID, "super-secret")
	if status != http.StatusOK || jwtToken.AccessToken == "" || jwtToken.IssuedTokenType != SubjectTokenJWT {
		t.Fatalf("JWT output = %+v status=%d", jwtToken, status)
	}
	if _, err := server.ValidateAccessToken(ctx, jwtToken.AccessToken); err != nil {
		t.Fatalf("JWT output validation = %v", err)
	}

	// Validator failures and nil principals are invalid_grant. | 校验器失败与空主体属于 invalid_grant。
	failing, failingClient := grantServer(t, func(config *ServerConfig) {
		config.SubjectTokenValidator = &fakeSubjectTokenValidator{Err: errTest}
	})
	if _, status := tokenRequest(t, failing, form, failingClient.ID, "super-secret"); status != http.StatusBadRequest {
		t.Fatalf("validator error = %d", status)
	}
	empty, emptyClient := grantServer(t, func(config *ServerConfig) {
		config.SubjectTokenValidator = &fakeSubjectTokenValidator{}
	})
	if _, status := tokenRequest(t, empty, form, emptyClient.ID, "super-secret"); status != http.StatusBadRequest {
		t.Fatalf("nil principal = %d", status)
	}
}

func TestJWTBearerGrant(t *testing.T) {
	server, client := grantServer(t, nil)
	form := url.Values{
		"grant_type": {GrantJWTBearer},
		"assertion":  {"assertion-1"},
		"scope":      {"api:read"},
	}
	token, status := tokenRequest(t, server, form, client.ID, "super-secret")
	if status != http.StatusOK || token.AccessToken == "" {
		t.Fatalf("JWT bearer = %+v status=%d", token, status)
	}
	bad := url.Values{"grant_type": {GrantJWTBearer}}
	if _, status := tokenRequest(t, server, bad, client.ID, "super-secret"); status != http.StatusBadRequest {
		t.Fatalf("missing assertion = %d", status)
	}
	failing, failingClient := grantServer(t, func(config *ServerConfig) {
		config.JWTBearerValidator = &fakeJWTBearerValidator{Err: errTest}
	})
	if _, status := tokenRequest(t, failing, form, failingClient.ID, "super-secret"); status != http.StatusBadRequest {
		t.Fatalf("validator error = %d", status)
	}
	empty, emptyClient := grantServer(t, func(config *ServerConfig) {
		config.JWTBearerValidator = &fakeJWTBearerValidator{}
	})
	if _, status := tokenRequest(t, empty, form, emptyClient.ID, "super-secret"); status != http.StatusBadRequest {
		t.Fatalf("nil principal = %d", status)
	}
	disabled, disabledClient := grantServer(t, func(config *ServerConfig) { config.EnableJWTBearer = false })
	if _, status := tokenRequest(t, disabled, form, disabledClient.ID, "super-secret"); status != http.StatusBadRequest {
		t.Fatalf("disabled = %d", status)
	}
	unauthorized := grantClient()
	unauthorized.GrantTypes = []string{GrantAuthorizationCode}
	server, _ = grantServer(t, func(config *ServerConfig) { config.Clients = NewMemoryClientStore(unauthorized) })
	if _, status := tokenRequest(t, server, form, unauthorized.ID, "super-secret"); status != http.StatusBadRequest {
		t.Fatalf("unauthorized = %d", status)
	}
}

func TestPasswordGrant(t *testing.T) {
	server, client := grantServer(t, func(config *ServerConfig) {
		config.PasswordAuthenticator = &fakePasswordAuthenticator{
			Principal: &auth.Principal{Subject: "user-1", Scopes: []string{"api:read"}},
			Username:  "alice",
			Password:  "correct",
		}
	})
	form := url.Values{
		"grant_type": {GrantPassword},
		"username":   {"alice"},
		"password":   {"correct"},
		"scope":      {"api:read"},
	}
	token, status := tokenRequest(t, server, form, client.ID, "super-secret")
	if status != http.StatusOK || token.AccessToken == "" || token.RefreshToken == "" {
		t.Fatalf("password = %+v status=%d", token, status)
	}
	if token, status := tokenRequest(t, server, url.Values{"grant_type": {GrantPassword}, "username": {"alice"}}, client.ID, "super-secret"); status != http.StatusBadRequest || token != nil {
		t.Fatalf("missing password = %d", status)
	}
	failing, failingClient := grantServer(t, func(config *ServerConfig) {
		config.PasswordAuthenticator = &fakePasswordAuthenticator{Err: errTest}
	})
	if _, status := tokenRequest(t, failing, form, failingClient.ID, "super-secret"); status == http.StatusOK {
		t.Fatal("authenticator error was accepted")
	}
	// Rejected resource-owner credentials are invalid_grant, not invalid_client. | 被拒绝的资源所有者
	// 凭据属于 invalid_grant，而不是 invalid_client。
	for _, sentinel := range []error{auth.ErrUnauthorized, auth.ErrSessionExpired, auth.ErrSessionRevoked} {
		rejected, rejectedClient := grantServer(t, func(config *ServerConfig) {
			config.PasswordAuthenticator = &fakePasswordAuthenticator{Err: sentinel}
		})
		w := doRequest(t, rejected.Token, http.MethodPost, "/token", form, func(r *http.Request) {
			r.SetBasicAuth(url.QueryEscape(rejectedClient.ID), url.QueryEscape("super-secret"))
		})
		requireErrorCode(t, w, http.StatusBadRequest, ErrorInvalidGrant)
	}
	disabled, disabledClient := grantServer(t, func(config *ServerConfig) { config.AllowPasswordGrant = false })
	if _, status := tokenRequest(t, disabled, form, disabledClient.ID, "super-secret"); status != http.StatusBadRequest {
		t.Fatalf("disabled = %d", status)
	}
}

func TestIntrospectionFlows(t *testing.T) {
	server, client := grantServer(t, nil)
	other := &Client{ID: "other", TokenEndpointAuthMethod: ClientSecretBasic}
	other.SetSecret("other-secret")
	if err := server.config.Clients.CreateClient(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	exchange := url.Values{
		"grant_type":         {GrantTokenExchange},
		"subject_token":      {"s"},
		"subject_token_type": {SubjectTokenAccessToken},
		"scope":              {"api:read"},
	}
	access, status := tokenRequest(t, server, exchange, client.ID, "super-secret")
	if status != http.StatusOK {
		t.Fatalf("exchange status = %d", status)
	}
	introspect := func(token, clientID, secret string) (map[string]any, int) {
		form := url.Values{"token": {token}, "token_type_hint": {"access_token"}}
		w := doRequest(t, server.Introspect, http.MethodPost, "/introspect", form, func(r *http.Request) {
			r.SetBasicAuth(clientID, secret)
		})
		var out map[string]any
		if w.Code == http.StatusOK {
			out = decodeMap(t, w)
		}
		return out, w.Code
	}
	body, code := introspect(access.AccessToken, client.ID, "super-secret")
	if code != http.StatusOK || body["active"] != true || body["client_id"] != "web" || body["sub"] != "user-1" {
		t.Fatalf("access introspection = %v status=%d", body, code)
	}
	if _, code := introspect(access.AccessToken, "other", "other-secret"); code != http.StatusOK {
		t.Fatalf("cross-client status = %d", code)
	}
	// A different client must not learn the token is active. | 其他客户端不得得知令牌有效。
	cross := doRequest(t, server.Introspect, http.MethodPost, "/introspect", url.Values{"token": {access.AccessToken}}, func(r *http.Request) {
		r.SetBasicAuth("other", "other-secret")
	})
	if cross.Code != http.StatusOK || decodeMap(t, cross)["active"] != false {
		t.Fatalf("cross-client = %d %s", cross.Code, cross.Body.String())
	}
	// Revocation makes the token inactive. | 撤销使令牌无效。
	revoke := doRequest(t, server.Revoke, http.MethodPost, "/revoke", url.Values{"token": {access.AccessToken}}, func(r *http.Request) {
		r.SetBasicAuth(client.ID, "super-secret")
	})
	if revoke.Code != http.StatusOK {
		t.Fatalf("revoke = %d body=%s", revoke.Code, revoke.Body.String())
	}
	if body, code := introspect(access.AccessToken, client.ID, "super-secret"); code != http.StatusOK || body["active"] != false {
		t.Fatalf("revoked introspection = %v status=%d", body, code)
	}
	// Refresh tokens introspect with their own token_type. | 刷新令牌以自身的 token_type 自省。
	password, status := tokenRequest(t, server, url.Values{
		"grant_type": {GrantPassword},
		"username":   {"alice"},
		"password":   {"correct"},
		"scope":      {"api:read"},
	}, client.ID, "super-secret")
	if status != http.StatusOK || password.RefreshToken == "" {
		t.Fatalf("password refresh = %+v status=%d", password, status)
	}
	refreshForm := url.Values{"token": {password.RefreshToken}, "token_type_hint": {"refresh_token"}}
	refreshResponse := doRequest(t, server.Introspect, http.MethodPost, "/introspect", refreshForm, func(r *http.Request) {
		r.SetBasicAuth(client.ID, "super-secret")
	})
	body = decodeMap(t, refreshResponse)
	code = refreshResponse.Code
	if code != http.StatusOK || body["active"] != true || body["token_type"] != "refresh_token" || body["scope"] != "api:read" {
		t.Fatalf("refresh introspection = %v status=%d", body, code)
	}
	// Authentication and parameter errors. | 认证与参数错误。
	w := doRequest(t, server.Introspect, http.MethodPost, "/introspect", url.Values{"token": {"x"}}, func(r *http.Request) {
		r.SetBasicAuth(client.ID, "wrong")
	})
	requireErrorCode(t, w, http.StatusUnauthorized, ErrorInvalidClient)
	w = doRequest(t, server.Introspect, http.MethodPost, "/introspect", nil, func(r *http.Request) {
		r.SetBasicAuth(client.ID, "super-secret")
	})
	requireErrorCode(t, w, http.StatusBadRequest, ErrorInvalidRequest)
	w = doRequest(t, server.Introspect, http.MethodGet, "/introspect", nil, nil)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Header().Get("Allow"), "POST") {
		t.Fatalf("GET introspect = %d", w.Code)
	}
}

func TestAccessTokenRequestDPoPAndTargets(t *testing.T) {
	ctx := context.Background()
	verifier := &fakeDPoPVerifier{JKT: "jkt-1"}
	server, client := grantServer(t, func(config *ServerConfig) {
		config.DPoPRequired = true
		config.DPoPVerifier = verifier
	})
	raw := "bound-token"
	if err := server.config.Store.SaveAccessToken(ctx, &AccessToken{
		TokenHash: auth.HashToken(raw), ClientID: client.ID, Subject: "user-1",
		Scopes: []string{"api:read"}, IssuedAt: flowNow, ExpiresAt: flowNow.Add(time.Minute),
		DPoPJKT: "jkt-1",
	}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "https://api.example/resource?x=1", nil)
	req.Header.Set("DPoP", "proof-1")
	token, err := server.ValidateAccessTokenRequest(ctx, req, raw)
	if err != nil || token.Subject != "user-1" {
		t.Fatalf("DPoP request = %+v err=%v", token, err)
	}
	if verifier.LastTarget != "https://api.example/resource" || verifier.LastMethod != http.MethodGet || verifier.LastAccessTok != raw {
		t.Fatalf("proof inputs = %+v", verifier)
	}
	noProof := httptest.NewRequest(http.MethodGet, "https://api.example/resource", nil)
	if _, err := server.ValidateAccessTokenRequest(ctx, noProof, raw); !errors.Is(err, ErrInvalidDPoPProof) {
		t.Fatalf("missing proof = %v", err)
	}
	verifier.JKT = "other"
	if _, err := server.ValidateAccessTokenRequest(ctx, req, raw); !errors.Is(err, ErrInvalidDPoPProof) {
		t.Fatalf("thumbprint mismatch = %v", err)
	}
	verifier.JKT = "jkt-1"
	verifier.Err = errTest
	if _, err := server.ValidateAccessTokenRequest(ctx, req, raw); !errors.Is(err, ErrInvalidDPoPProof) {
		t.Fatalf("proof error = %v", err)
	}
	verifier.Err = nil

	// A token without DPoP binding fails when DPoP is required; explicit requests are checked. |
	// 无 DPoP 绑定的令牌在强制 DPoP 时失败；显式请求会被检查。
	plain := "plain-token"
	if err := server.config.Store.SaveAccessToken(ctx, &AccessToken{
		TokenHash: auth.HashToken(plain), ClientID: client.ID, Subject: "user-1",
		Scopes: []string{"api:read"}, IssuedAt: flowNow, ExpiresAt: flowNow.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := server.ValidateAccessTokenRequest(ctx, req, plain); !errors.Is(err, ErrInvalidDPoPProof) {
		t.Fatalf("unbound token = %v", err)
	}
	relaxed, relaxedClient := grantServer(t, nil)
	if err := relaxed.config.Store.SaveAccessToken(ctx, &AccessToken{
		TokenHash: auth.HashToken(plain), ClientID: relaxedClient.ID, Subject: "user-1",
		Scopes: []string{"api:read"}, IssuedAt: flowNow, ExpiresAt: flowNow.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	if token, err := relaxed.ValidateAccessTokenRequest(ctx, nil, plain); err != nil || token.Subject != "user-1" {
		t.Fatalf("relaxed unbound = %+v err=%v", token, err)
	}

	if got := requestTarget(nil); got != "" {
		t.Fatalf("nil target = %q", got)
	}
	plainReq := httptest.NewRequest(http.MethodGet, "http://api.example/a%2Fb", nil)
	plainReq.Host = "api.example"
	plainReq.Header.Set("X-Forwarded-Proto", "https, http")
	if got := requestTarget(plainReq); got != "https://api.example/a%2Fb" {
		t.Fatalf("forwarded target = %q", got)
	}
	plainReq.Header.Del("X-Forwarded-Proto")
	if got := requestTarget(plainReq); got != "http://api.example/a%2Fb" {
		t.Fatalf("http target = %q", got)
	}
	if cnfString(nil, "jkt") != "" || cnfString(map[string]any{"jkt": "x"}, "jkt") != "x" || cnfString(map[string]any{"jkt": 1}, "jkt") != "" {
		t.Fatal("cnfString")
	}

	// JWT access tokens expose cnf confirmation fields. | JWT 访问令牌暴露 cnf 确认字段。
	claims := &AccessTokenClaims{
		Issuer: "https://auth.example", Subject: "user-1", ClientID: client.ID,
		Scope: "api:read", Audience: []string{"api"}, IssuedAt: flowNow.Unix(), ExpiresAt: flowNow.Add(time.Minute).Unix(),
		JTI: "jti-1", AuthTime: flowNow.Unix(), CNF: map[string]any{"jkt": "jkt-1", "x5t#S256": "thumb"},
	}
	jwtServer, _ := grantServer(t, func(config *ServerConfig) {
		config.TokenFormat = TokenFormatJWT
		config.AccessTokenIssuer = &fakeJWTIssuer{Token: "jwt-token"}
		config.AccessTokenVerifier = &fakeJWTVerifier{Claims: claims}
	})
	jwtToken, err := jwtServer.ValidateAccessToken(ctx, "jwt-token")
	if err != nil || jwtToken.DPoPJKT != "jkt-1" || jwtToken.CertThumbprint != "thumb" || !jwtToken.AuthTime.Equal(flowNow) {
		t.Fatalf("JWT access token = %+v err=%v", jwtToken, err)
	}
	if err := jwtServer.config.Store.SaveAccessToken(ctx, &AccessToken{TokenHash: auth.HashToken("revoked-jwt"), Revoked: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := jwtServer.ValidateAccessToken(ctx, "revoked-jwt"); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("revoked JWT = %v", err)
	}
}
