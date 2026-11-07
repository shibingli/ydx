package oauth2

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/json"
)

func TestStaticScopesHelpers(t *testing.T) {
	registry := NewStaticScopes(
		Scope{Name: "openid", Description: "auth"},
		Scope{Name: "openid", Description: "duplicate ignored"},
		Scope{Name: "", Description: "empty ignored"},
		Scope{Name: "email", Claims: []string{"email"}},
		Scope{Name: "custom-offline", OfflineAccess: true},
	)
	if got := registry.List(); !reflect.DeepEqual(got, []string{"openid", "email", "custom-offline"}) {
		t.Fatalf("list = %v", got)
	}
	if got := registry.SortedScopes(); !reflect.DeepEqual(got, []string{"custom-offline", "email", "openid"}) {
		t.Fatalf("sorted = %v", got)
	}
	if !registry.Exists("email") || registry.Exists("unknown") {
		t.Fatal("exists mismatch")
	}
	if scope, ok := registry.Get("email"); !ok || !reflect.DeepEqual(scope.Claims, []string{"email"}) {
		t.Fatalf("get = %+v ok=%v", scope, ok)
	}
	if _, ok := registry.Get("unknown"); ok {
		t.Fatal("unknown scope found")
	}
	// List returns a defensive copy. | List 返回防御性副本。
	list := registry.List()
	list[0] = "mutated"
	if registry.List()[0] != "openid" {
		t.Fatal("List leaked internal state")
	}

	client := &Client{Scopes: []string{"openid", "email"}}
	if got, err := registry.Validate([]string{" openid ", "openid", "", "email"}, client); err != nil ||
		!reflect.DeepEqual(got, []string{"openid", "email"}) {
		t.Fatalf("validate = %v err=%v", got, err)
	}
	if _, err := registry.Validate([]string{"unknown"}, client); !errors.Is(err, ErrInvalidScope) {
		t.Fatalf("unknown scope error = %v", err)
	}
	if _, err := registry.Validate([]string{"custom-offline"}, client); !errors.Is(err, ErrInvalidScope) {
		t.Fatalf("client scope error = %v", err)
	}
	if _, err := registry.Validate([]string{""}, client); !errors.Is(err, ErrInvalidScope) {
		t.Fatalf("empty scope error = %v", err)
	}
	if got, err := registry.Validate(nil, client); err != nil || len(got) != 0 {
		t.Fatalf("empty validate = %v err=%v", got, err)
	}
	if got, err := registry.Validate([]string{"unknown"}, nil); !errors.Is(err, ErrInvalidScope) || got != nil {
		t.Fatalf("nil client validate = %v err=%v", got, err)
	}

	var nilRegistry *StaticScopes
	if nilRegistry.List() != nil || nilRegistry.Exists("x") {
		t.Fatal("nil registry helpers")
	}
	if _, ok := nilRegistry.Get("x"); ok {
		t.Fatal("nil registry Get")
	}
	if got, err := nilRegistry.Validate([]string{"x"}, client); err != nil || !reflect.DeepEqual(got, []string{"x"}) {
		t.Fatalf("nil registry validate = %v err=%v", got, err)
	}
	if got := nilRegistry.SortedScopes(); len(got) != 0 {
		t.Fatalf("nil registry sorted = %v", got)
	}

	defaults := DefaultScopes()
	for _, name := range []string{ScopeOpenID, ScopeProfile, ScopeEmail, ScopeAddress, ScopePhone, ScopeOfflineAccess} {
		if !defaults.Exists(name) {
			t.Errorf("default registry misses %q", name)
		}
	}
}

func TestScopeHelpers(t *testing.T) {
	if got := ParseScope("  a b a  c "); !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Fatalf("parse = %v", got)
	}
	if got := ScopeString([]string{"a", "b"}); got != "a b" {
		t.Fatalf("scope string = %q", got)
	}
	if !HasScope([]string{"a", "b"}, "b") || HasScope([]string{"a"}, "b") {
		t.Fatal("has scope mismatch")
	}
	if got := IntersectScopes([]string{"a", "b", "c"}, []string{"c", "a", "x"}); !reflect.DeepEqual(got, []string{"a", "c"}) {
		t.Fatalf("intersect = %v", got)
	}
	if got := IntersectScopes(nil, []string{"a"}); got == nil || len(got) != 0 {
		t.Fatalf("intersect empty = %#v", got)
	}
	static := NewStaticScopes(
		Scope{Name: "offline", OfflineAccess: true},
		Scope{Name: "plain"},
	)
	if !HasOfflineAccess([]string{"offline"}, static) || HasOfflineAccess([]string{"plain"}, static) {
		t.Fatal("offline access detection")
	}
	if !HasOfflineAccess([]string{ScopeOfflineAccess}, nil) {
		t.Fatal("offline_access not detected")
	}
	if HasOfflineAccess(nil, static) {
		t.Fatal("empty scopes reported offline")
	}
	// A custom registry cannot advertise offline scopes. | 自定义注册表无法声明离线作用域。
	if HasOfflineAccess([]string{"offline"}, customScopeRegistry{}) {
		t.Fatal("custom registry reported offline")
	}
}

// customScopeRegistry implements ScopeRegistry without StaticScopes. | customScopeRegistry 实现
// 非 StaticScopes 的 ScopeRegistry。
type customScopeRegistry struct{}

func (customScopeRegistry) Validate(requested []string, _ *Client) ([]string, error) {
	return requested, nil
}
func (customScopeRegistry) List() []string { return []string{"offline"} }
func (customScopeRegistry) Exists(string) bool {
	return true
}

func TestClientHelpers(t *testing.T) {
	var nilClient *Client
	if nilClient.VerifySecret("x") || nilClient.AllowsGrant("x") || nilClient.AllowsResponseType("x") ||
		nilClient.AllowsScope("x") || nilClient.AllowsRedirect("https://x") || nilClient.AllowsPostLogoutRedirect("https://x") {
		t.Fatal("nil client allowed something")
	}
	nilClient.SetSecret("ignored")

	client := &Client{}
	client.SetSecret("correct horse")
	if client.Public || !client.VerifySecret("correct horse") {
		t.Fatal("secret was not stored")
	}
	if client.VerifySecret("wrong") || client.VerifySecret("") {
		t.Fatal("wrong secret accepted")
	}

	client.GrantTypes = []string{GrantAuthorizationCode}
	client.ResponseTypes = []string{"code", "code id_token"}
	client.Scopes = []string{"openid", "api:read"}
	client.PostLogoutRedirectURIs = []string{"https://rp.example/logout"}
	if !client.AllowsGrant(GrantAuthorizationCode) || client.AllowsGrant(GrantRefreshToken) {
		t.Fatal("grant allowlist")
	}
	if !client.AllowsResponseType("code id_token") || client.AllowsResponseType("token") {
		t.Fatal("response type allowlist")
	}
	if !client.AllowsScope("openid") || !client.AllowsScope("api:read") || client.AllowsScope("admin") {
		t.Fatal("scope allowlist")
	}

	client.Scopes = nil
	if !client.AllowsScope("anything") {
		t.Fatal("empty scope allowlist should allow")
	}
	client.Scopes = []string{"*"}
	if !client.AllowsScope("anything") {
		t.Fatal("wildcard scope")
	}
	if !client.AllowsPostLogoutRedirect("https://rp.example/logout") || client.AllowsPostLogoutRedirect("https://rp.example/other") {
		t.Fatal("post logout allowlist")
	}

	redirectClient := &Client{RedirectURIs: []string{
		"https://rp.example/callback",
		"http://127.0.0.1:8080/cb?x=1",
		"com.example.app:/oauth",
	}}
	cases := []struct {
		uri  string
		want bool
	}{
		{"https://rp.example/callback", true},
		{"https://rp.example/callback/", false},
		{"http://rp.example/callback", false},
		{"https://rp.example/callback#fragment", false},
		{"://bad", false},
		{"http://127.0.0.1:9999/cb?x=1", true},
		{"http://127.0.0.1:8080/cb?x=2", false},
		{"http://localhost:8080/cb?x=1", false},
		{"http://127.0.0.1:8080/other?x=1", false},
		{"https://127.0.0.1:8080/cb?x=1", false},
		{"com.example.app:/oauth", true},
		{"com.example.app:/oauth2", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := redirectClient.AllowsRedirect(tc.uri); got != tc.want {
			t.Errorf("AllowsRedirect(%q) = %v want %v", tc.uri, got, tc.want)
		}
	}
	localhost := &Client{RedirectURIs: []string{"http://localhost:8080/cb"}}
	if !localhost.AllowsRedirect("http://localhost:54321/cb") {
		t.Fatal("localhost loopback port wildcard")
	}
	ipv6 := &Client{RedirectURIs: []string{"http://[::1]:8080/cb"}}
	if !ipv6.AllowsRedirect("http://[::1]:9000/cb") {
		t.Fatal("ipv6 loopback port wildcard")
	}
	if !isLoopbackHost("[::1]") || !isLoopbackHost("LOCALHOST") || isLoopbackHost("example.com") {
		t.Fatal("loopback host detection")
	}
}

func TestOAuthErrorTypes(t *testing.T) {
	var nilErr *Error
	if nilErr.Error() != "" || nilErr.Unwrap() != nil {
		t.Fatal("nil error methods")
	}
	err := NewError(ErrorInvalidClient, "bad secret")
	if err.Status != http.StatusUnauthorized || !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("invalid_client = %+v", err)
	}
	if err.Error() != "oauth2: invalid_client: bad secret" {
		t.Fatalf("error string = %q", err.Error())
	}
	serverErr := NewError(ErrorServerError, "")
	if serverErr.Status != http.StatusInternalServerError || serverErr.Error() != "oauth2: server_error" {
		t.Fatalf("server_error = %+v %q", serverErr, serverErr.Error())
	}
	if NewError(ErrorTemporarilyUnavailable, "").Status != http.StatusInternalServerError {
		t.Fatal("temporarily_unavailable status")
	}
	if NewError(ErrorAccessDenied, "").Status != http.StatusBadRequest {
		t.Fatal("access_denied status")
	}
	for code, sentinel := range map[string]error{
		ErrorInvalidRequest:          ErrInvalidRequest,
		ErrorInvalidClient:           ErrInvalidClient,
		ErrorInvalidGrant:            ErrInvalidGrant,
		ErrorUnauthorizedClient:      ErrUnauthorizedClient,
		ErrorUnsupportedGrantType:    ErrUnsupportedGrantType,
		ErrorUnsupportedResponseType: ErrUnsupportedResponseType,
		ErrorInvalidScope:            ErrInvalidScope,
		ErrorAccessDenied:            ErrAccessDenied,
		ErrorInvalidDPoPProof:        ErrInvalidDPoPProof,
		ErrorInvalidTarget:           ErrInvalidTarget,
		ErrorServerError:             ErrServerError,
		"unknown_code":               ErrServerError,
	} {
		if got := NewError(code, "").Sentinel; got != sentinel {
			t.Errorf("sentinel for %q = %v want %v", code, got, sentinel)
		}
	}

	if normalizeError(nil).Code != ErrorServerError {
		t.Fatal("nil normalize")
	}
	original := NewError(ErrorInvalidScope, "scope")
	if normalizeError(original) != original {
		t.Fatal("oauth error not passed through")
	}
	cases := []struct {
		err  error
		code string
	}{
		{ErrInvalidRequest, ErrorInvalidRequest},
		{ErrInvalidClient, ErrorInvalidClient},
		{auth.ErrUnauthorized, ErrorInvalidClient},
		{ErrInvalidGrant, ErrorInvalidGrant},
		{auth.ErrSessionExpired, ErrorInvalidGrant},
		{auth.ErrSessionRevoked, ErrorInvalidGrant},
		{ErrUnauthorizedClient, ErrorUnauthorizedClient},
		{ErrUnsupportedGrantType, ErrorUnsupportedGrantType},
		{ErrUnsupportedResponseType, ErrorUnsupportedResponseType},
		{ErrInvalidScope, ErrorInvalidScope},
		{ErrAccessDenied, ErrorAccessDenied},
		{ErrInvalidDPoPProof, ErrorInvalidDPoPProof},
		{ErrInvalidTarget, ErrorInvalidTarget},
		{errors.New("unexpected"), ErrorServerError},
	}
	for _, tc := range cases {
		if got := normalizeError(tc.err).Code; got != tc.code {
			t.Errorf("normalize(%v) = %q want %q", tc.err, got, tc.code)
		}
	}
	if isOAuthError(ErrInvalidRequest) || !isOAuthError(NewError(ErrorInvalidRequest, "")) {
		t.Fatal("isOAuthError mismatch")
	}
}

func TestAuthorizationRequestAndTokenResponseHelpers(t *testing.T) {
	req := &AuthorizationRequest{Scopes: []string{"openid", "profile"}, Prompt: []string{"login", "consent"}}
	if req.ScopeString() != "openid profile" {
		t.Fatalf("scope string = %q", req.ScopeString())
	}
	if !req.HasPrompt("login") || req.HasPrompt("none") {
		t.Fatal("has prompt")
	}

	var nilResponse *TokenResponse
	data, err := json.Marshal(nilResponse)
	if err != nil || string(data) != "null" {
		t.Fatalf("nil response marshal = %s err=%v", data, err)
	}
	response := &TokenResponse{
		AccessToken:     "at",
		TokenType:       TokenTypeDPoP,
		ExpiresIn:       60,
		RefreshToken:    "rt",
		Scope:           "openid",
		IDToken:         "id",
		IssuedTokenType: SubjectTokenJWT,
		Extra: map[string]any{
			"cnf":          map[string]any{"jkt": "thumb"},
			"access_token": "must not override",
			"empty":        "",
			"zero":         0,
		},
	}
	data, err = json.Marshal(response)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if decoded["access_token"] != "at" || decoded["token_type"] != TokenTypeDPoP || decoded["issued_token_type"] != SubjectTokenJWT {
		t.Fatalf("decoded = %v", decoded)
	}
	cnf, ok := decoded["cnf"].(map[string]any)
	if !ok || cnf["jkt"] != "thumb" {
		t.Fatalf("cnf = %v", decoded["cnf"])
	}
	empty := &TokenResponse{}
	data, err = json.Marshal(empty)
	if err != nil || string(data) != "{}" {
		t.Fatalf("empty response marshal = %s err=%v", data, err)
	}

	_ = json.Marshal
}

func TestServerConfigurationAndSetters(t *testing.T) {
	for name, config := range map[string]ServerConfig{
		"empty issuer":    {Clients: NewMemoryClientStore(), Store: NewMemoryStore()},
		"relative issuer": {Issuer: "auth.example", Clients: NewMemoryClientStore(), Store: NewMemoryStore()},
		"fragment issuer": {Issuer: "https://auth.example/#fragment", Clients: NewMemoryClientStore(), Store: NewMemoryStore()},
		"nil clients":     {Issuer: "https://auth.example", Store: NewMemoryStore()},
		"nil store":       {Issuer: "https://auth.example", Clients: NewMemoryClientStore()},
		"bad token format": {
			Issuer: "https://auth.example", Clients: NewMemoryClientStore(), Store: NewMemoryStore(), TokenFormat: "mac",
		},
		"jwt without issuer": {
			Issuer: "https://auth.example", Clients: NewMemoryClientStore(), Store: NewMemoryStore(), TokenFormat: TokenFormatJWT,
		},
		"dpop without verifier": {
			Issuer: "https://auth.example", Clients: NewMemoryClientStore(), Store: NewMemoryStore(), DPoPRequired: true,
		},
	} {
		if _, err := NewServer(config); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s error = %v", name, err)
		}
	}

	server, err := NewServer(ServerConfig{
		Issuer:  "https://auth.example/oauth/",
		Clients: NewMemoryClientStore(),
		Store:   NewMemoryStore(),
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	if server.Issuer() != "https://auth.example/oauth" {
		t.Fatalf("issuer = %q", server.Issuer())
	}
	if server.Path("/token") != "/oauth/token" || server.Endpoint("/token") != "https://auth.example/oauth/token" {
		t.Fatalf("path = %q endpoint = %q", server.Path("/token"), server.Endpoint("/token"))
	}
	if config := server.Config(); config.PathPrefix != "/oauth" ||
		config.AuthorizationPath != "/authorize" || config.TokenPath != "/token" ||
		config.IntrospectionPath != "/introspect" || config.RevocationPath != "/revoke" ||
		config.DeviceAuthorizationPath != "/device_authorization" || config.DeviceVerificationPath != "/device" ||
		config.PARPath != "/par" || config.MetadataPath != "/.well-known/oauth-authorization-server" {
		t.Fatalf("config defaults = %+v", config)
	}
	if server.Config().AccessTokenTTL != defaultAccessTokenTTL ||
		server.Config().RefreshTokenTTL != defaultRefreshTokenTTL ||
		server.Config().AuthorizationCodeTTL != defaultAuthorizationCodeTTL ||
		server.Config().DeviceCodeTTL != defaultDeviceCodeTTL ||
		server.Config().DeviceInterval != defaultDeviceInterval ||
		server.Config().PARTTL != defaultPARTTL {
		t.Fatalf("ttl defaults = %+v", server.Config())
	}
	if server.Now().Location() != time.UTC {
		t.Fatal("Now is not UTC")
	}

	enricher := &fakeTokenEnricher{}
	authorizationEnricher := &fakeAuthorizationEnricher{}
	authenticator := AuthenticatorFunc(func(ctx context.Context, w http.ResponseWriter, r *http.Request, req *AuthorizationRequest) (*auth.Principal, error) {
		return nil, nil
	})
	consent := ConsentFunc(func(ctx context.Context, w http.ResponseWriter, r *http.Request, req *AuthorizationRequest, principal *auth.Principal) ([]string, error) {
		return nil, nil
	})
	dpop := &fakeDPoPVerifier{}
	server.SetTokenEnricher(enricher)
	server.SetAuthorizationEnricher(authorizationEnricher)
	server.SetAuthenticator(authenticator)
	server.SetConsentHandler(consent)
	server.SetDPoPVerifier(dpop)
	server.SetJWKSURI("https://auth.example/jwks")
	server.SetRegistrationEndpoint("https://auth.example/register")
	config := server.Config()
	if config.TokenEnricher == nil || config.AuthorizationEnricher == nil || config.Authenticator == nil ||
		config.Consent == nil || config.DPoPVerifier == nil ||
		config.JWKSURI != "https://auth.example/jwks" ||
		config.RegistrationEndpoint != "https://auth.example/register" {
		t.Fatalf("setters did not apply: %+v", config)
	}
	if server.Endpoint("/token") != "https://auth.example/oauth/token" {
		t.Fatalf("endpoint changed: %q", server.Endpoint("/token"))
	}

	// A server with explicit paths and prefix keeps them. | 显式路径与前缀的服务器保持原值。
	custom, err := NewServer(ServerConfig{
		Issuer:            "https://auth.example",
		PathPrefix:        "/idp/",
		AuthorizationPath: "/auth",
		TokenPath:         "/oauth/token",
		Clients:           NewMemoryClientStore(),
		Store:             NewMemoryStore(),
		Clock:             func() time.Time { return time.Unix(123, 0) },
	})
	if err != nil {
		t.Fatalf("custom server: %v", err)
	}
	if custom.Path("/auth") != "/idp/auth" || custom.Path("/oauth/token") != "/idp/oauth/token" {
		t.Fatalf("custom paths = %q %q", custom.Path("/auth"), custom.Path("/oauth/token"))
	}
	if custom.Now().Unix() != 123 {
		t.Fatalf("clock = %v", custom.Now())
	}

	// Relative prefixes and paths gain a leading slash instead of producing host-like patterns. |
	// 相对前缀与路径会补上前导斜杠，而不会生成类似主机名的模式。
	relative, err := NewServer(ServerConfig{
		Issuer:     "https://auth.example",
		PathPrefix: "idp/",
		TokenPath:  "oauth/token",
		Clients:    NewMemoryClientStore(),
		Store:      NewMemoryStore(),
	})
	if err != nil {
		t.Fatalf("relative server: %v", err)
	}
	if config := relative.Config(); config.PathPrefix != "/idp" || config.TokenPath != "/oauth/token" {
		t.Fatalf("relative config = prefix %q token %q", config.PathPrefix, config.TokenPath)
	}
	if relative.Path("token") != "/idp/token" || relative.Path("/token") != "/idp/token" || relative.Path("") != "/idp" {
		t.Fatalf("relative paths = %q %q %q", relative.Path("token"), relative.Path("/token"), relative.Path(""))
	}
}

func TestMetadataDocumentVariants(t *testing.T) {
	base, err := NewServer(ServerConfig{
		Issuer:  "https://auth.example",
		Clients: NewMemoryClientStore(),
		Store:   NewMemoryStore(),
	})
	if err != nil {
		t.Fatal(err)
	}
	doc := base.MetadataDocument()
	if doc.Issuer != "https://auth.example" || doc.AuthorizationEndpoint != "https://auth.example/authorize" ||
		doc.TokenEndpoint != "https://auth.example/token" ||
		doc.DeviceAuthorizationEndpoint != "https://auth.example/device_authorization" ||
		doc.PushedAuthorizationRequestEndpoint != "https://auth.example/par" ||
		doc.RevocationEndpoint != "https://auth.example/revoke" ||
		doc.IntrospectionEndpoint != "https://auth.example/introspect" {
		t.Fatalf("endpoints = %+v", doc)
	}
	if !reflect.DeepEqual(doc.ResponseTypesSupported, []string{ResponseCode, ResponseNone}) {
		t.Fatalf("response types = %v", doc.ResponseTypesSupported)
	}
	if !reflect.DeepEqual(doc.GrantTypesSupported, []string{GrantAuthorizationCode, GrantRefreshToken, GrantClientCredentials, GrantDeviceCode}) {
		t.Fatalf("grant types = %v", doc.GrantTypesSupported)
	}
	if !reflect.DeepEqual(doc.TokenEndpointAuthMethodsSupported, []string{ClientAuthNone, ClientSecretBasic, ClientSecretPost, TLSClientAuth, SelfSignedTLSClientAuth}) {
		t.Fatalf("auth methods = %v", doc.TokenEndpointAuthMethodsSupported)
	}
	if !reflect.DeepEqual(doc.CodeChallengeMethodsSupported, []string{PKCES256}) {
		t.Fatalf("pkce = %v", doc.CodeChallengeMethodsSupported)
	}
	if !doc.AuthorizationResponseIssParameterSupported || doc.DPoPSigningAlgValuesSupported != nil ||
		doc.AccessTokenSigningAlgValuesSupported != nil || doc.TokenEndpointAuthSigningAlgValuesSupported != nil {
		t.Fatalf("base flags = %+v", doc)
	}
	if len(doc.ScopesSupported) == 0 {
		t.Fatal("default scopes missing")
	}

	key, _ := newTestJWTKey(t)
	jwtIssuer, jwtVerifier := newTestJWTIssuerVerifier(t, key)
	full, err := NewServer(ServerConfig{
		Issuer:                  "https://auth.example",
		Clients:                 NewMemoryClientStore(),
		Store:                   NewMemoryStore(),
		AllowImplicit:           true,
		AllowPasswordGrant:      true,
		DisableDeviceFlow:       true,
		EnableTokenExchange:     true,
		EnableJWTBearer:         true,
		AllowPKCEPlain:          true,
		DisableIssuerParameter:  true,
		AuthorizationEnricher:   &fakeAuthorizationEnricher{},
		ClientAssertionVerifier: &fakeClientAssertionVerifier{},
		DPoPVerifier:            &fakeDPoPVerifier{},
		DPoPRequired:            true,
		TokenFormat:             TokenFormatJWT,
		AccessTokenIssuer:       jwtIssuer,
		AccessTokenVerifier:     jwtVerifier,
		JWKSURI:                 "https://auth.example/jwks",
		RegistrationEndpoint:    "https://auth.example/register",
	})
	if err != nil {
		t.Fatalf("full server: %v", err)
	}
	full.config.Scopes = nil
	doc = full.MetadataDocument()
	if doc.DeviceAuthorizationEndpoint != "" || doc.ScopesSupported != nil {
		t.Fatalf("disabled endpoints = %+v", doc)
	}
	for _, wanted := range []string{ResponseToken, ResponseIDToken, "code id_token", "code token", "token id_token", "code id_token token"} {
		if !containsString(doc.ResponseTypesSupported, wanted) {
			t.Errorf("response type %q missing from %v", wanted, doc.ResponseTypesSupported)
		}
	}
	for _, wanted := range []string{GrantPassword, GrantTokenExchange, GrantJWTBearer} {
		if !containsString(doc.GrantTypesSupported, wanted) {
			t.Errorf("grant type %q missing from %v", wanted, doc.GrantTypesSupported)
		}
	}
	if !containsString(doc.TokenEndpointAuthMethodsSupported, PrivateKeyJWT) {
		t.Errorf("private_key_jwt missing from %v", doc.TokenEndpointAuthMethodsSupported)
	}
	if !reflect.DeepEqual(doc.CodeChallengeMethodsSupported, []string{PKCES256, PKCEPlain}) {
		t.Errorf("pkce methods = %v", doc.CodeChallengeMethodsSupported)
	}
	if doc.AuthorizationResponseIssParameterSupported {
		t.Error("iss parameter still advertised")
	}
	if doc.JWKSURI != "https://auth.example/jwks" || doc.RegistrationEndpoint != "https://auth.example/register" {
		t.Errorf("metadata URIs = %+v", doc)
	}
	if !reflect.DeepEqual(doc.TokenEndpointAuthSigningAlgValuesSupported, []string{"RS256", "PS256", "ES256", "EdDSA"}) ||
		!reflect.DeepEqual(doc.DPoPSigningAlgValuesSupported, []string{"RS256", "PS256", "ES256", "EdDSA"}) ||
		!doc.DPoPBoundAccessTokensRequired ||
		!reflect.DeepEqual(doc.AccessTokenSigningAlgValuesSupported, []string{"RS256", "PS256", "ES256", "EdDSA"}) {
		t.Errorf("algorithm metadata = %+v", doc)
	}

	req := httptest.NewRequest(http.MethodPost, "/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()
	base.Metadata(w, req)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Header().Get("Allow"), "GET") {
		t.Fatalf("metadata POST = %d allow=%q", w.Code, w.Header().Get("Allow"))
	}
	if body := decodeMap(t, w); body["error"] != ErrorInvalidRequest {
		t.Fatalf("metadata POST error = %v", body["error"])
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// Ensure url remains referenced if tests change. | 确保测试调整后 url 仍被引用。
var _ = url.Values{}
