package oidc

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/auth/protocol/oauth2"
	"github.com/shibingli/ydx/auth/token/jose"
	"github.com/shibingli/ydx/json"
	"github.com/shibingli/ydx/router"
)

// oidcFixture is a running OP with one registered client. | oidcFixture 是带一个已注册客户端的运行中 OP。
type oidcFixture struct {
	server   *httptest.Server
	oauth    *oauth2.Server
	provider *Provider
	client   *oauth2.Client
}

// newOIDCFixture starts an OP and returns the fixture. | newOIDCFixture 启动 OP 并返回夹具。
func newOIDCFixture(t *testing.T, registration bool) *oidcFixture {
	t.Helper()
	var handler = http.NotFoundHandler()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)

	signingKey, err := jose.GenerateKey("RS256", 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signingKey.Kid = "sig-1"
	signingKey.Alg = "RS256"
	signingKey.Use = "sig"
	keys := &jose.KeySet{}
	if err := keys.Add(signingKey); err != nil {
		t.Fatalf("add key: %v", err)
	}
	client := &oauth2.Client{
		ID:                      "web",
		RedirectURIs:            []string{"https://rp.example/callback"},
		PostLogoutRedirectURIs:  []string{"https://rp.example/logged-out"},
		GrantTypes:              []string{oauth2.GrantAuthorizationCode, oauth2.GrantRefreshToken},
		ResponseTypes:           []string{oauth2.ResponseCode},
		Scopes:                  []string{ScopeOpenID, ScopeProfile, ScopeEmail, ScopeOfflineAccess},
		TokenEndpointAuthMethod: oauth2.ClientSecretBasic,
	}
	client.SetSecret("rp-secret")
	clients := oauth2.NewMemoryClientStore(client)
	authenticator := oauth2.AuthenticatorFunc(func(context.Context, http.ResponseWriter, *http.Request, *oauth2.AuthorizationRequest) (*auth.Principal, error) {
		verified := true
		return &auth.Principal{
			Subject:       "user-1",
			Email:         "alice@example.com",
			EmailVerified: verified,
			Username:      "alice",
			DisplayName:   "Alice",
			AuthTime:      time.Now().UTC(),
			AMR:           []string{"pwd"},
		}, nil
	})
	oauthServer, err := oauth2.NewServer(oauth2.ServerConfig{
		Issuer:         ts.URL,
		Clients:        clients,
		Store:          oauth2.NewMemoryStore(),
		Scopes:         oauth2.DefaultScopes(),
		Authenticator:  authenticator,
		AccessTokenTTL: time.Minute,
	})
	if err != nil {
		t.Fatalf("oauth server: %v", err)
	}
	provider, err := NewProvider(ProviderConfig{
		OAuth:                     oauthServer,
		Keys:                      keys,
		SigningKey:                signingKey,
		SigningAlg:                "RS256",
		EnableRegistration:        registration,
		EnableLogout:              true,
		SessionManagement:         true,
		BackchannelLogoutClientID: "web",
	})
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	r := router.New()
	oauthServer.Register(r)
	provider.Register(r)
	handler = r
	return &oidcFixture{server: ts, oauth: oauthServer, provider: provider, client: client}
}

func TestProviderRelyingPartyRoundTrip(t *testing.T) {
	fixture := newOIDCFixture(t, false)
	ctx := context.Background()
	rp, err := NewRelyingParty(ctx, RelyingPartyConfig{
		Issuer:       fixture.server.URL,
		ClientID:     "web",
		ClientSecret: "rp-secret",
		RedirectURL:  "https://rp.example/callback",
		Scopes:       []string{ScopeOpenID, ScopeProfile, ScopeEmail, ScopeOfflineAccess},
		UsePKCE:      true,
	})
	if err != nil {
		t.Fatalf("relying party: %v", err)
	}
	authURL, verifier, err := rp.AuthCodeURL("state-1", "nonce-1")
	if err != nil {
		t.Fatalf("auth code url: %v", err)
	}
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := noRedirect.Get(authURL)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("authorize status = %d body=%s", resp.StatusCode, body)
	}
	location, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("location: %v", err)
	}
	code := location.Query().Get("code")
	if code == "" || location.Query().Get("state") != "state-1" {
		t.Fatalf("redirect = %s", location)
	}
	token, err := rp.Exchange(ctx, code, "nonce-1", verifier)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if token.IDToken == nil {
		t.Fatal("no ID token")
	}
	if token.IDToken.Claims.Subject != "user-1" || token.IDToken.Claims.Email != "alice@example.com" {
		t.Fatalf("ID token claims = %+v", token.IDToken.Claims)
	}
	if err := token.IDToken.ValidateAccessTokenHash(token.AccessToken); err != nil {
		t.Fatalf("at_hash: %v", err)
	}
	claims, err := rp.UserInfo(ctx, token.AccessToken)
	if err != nil {
		t.Fatalf("userinfo: %v", err)
	}
	if claims["sub"] != "user-1" || claims["email"] != "alice@example.com" {
		t.Fatalf("userinfo = %v", claims)
	}
	refreshed, err := rp.Refresh(ctx, token.RefreshToken)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if refreshed.IDToken == nil || refreshed.RefreshToken == "" {
		t.Fatalf("refreshed = %+v", refreshed)
	}
	logoutURL := rp.EndSessionURL(token.IDToken.RawToken, "https://rp.example/logged-out", "logout-state")
	resp, err = noRedirect.Get(logoutURL)
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("logout status = %d body=%s", resp.StatusCode, body)
	}
	postLogout, _ := url.Parse(resp.Header.Get("Location"))
	if postLogout.Query().Get("state") != "logout-state" {
		t.Fatalf("logout redirect = %s", postLogout)
	}
}

func TestDiscoveryAndRegistration(t *testing.T) {
	fixture := newOIDCFixture(t, true)
	resp, err := http.Get(fixture.server.URL + DiscoveryPath)
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	defer resp.Body.Close()
	var document DiscoveryDocument
	data, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("decode discovery: %v body=%q", err, data)
	}
	if document.Issuer != fixture.server.URL || document.UserInfoEndpoint == "" || document.RegistrationEndpoint == "" {
		t.Fatalf("discovery = %+v", document)
	}
	metadata := map[string]any{
		"redirect_uris":              []string{"https://native.example/callback"},
		"client_name":                "Native App",
		"grant_types":                []string{oauth2.GrantAuthorizationCode},
		"response_types":             []string{oauth2.ResponseCode},
		"scope":                      "openid profile",
		"token_endpoint_auth_method": oauth2.ClientAuthNone,
	}
	body, _ := json.Marshal(metadata)
	resp, err = http.Post(fixture.server.URL+RegistrationPath, "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("register status = %d body=%s", resp.StatusCode, data)
	}
	var registered RegistrationResponse
	data, _ = io.ReadAll(resp.Body)
	if err := json.Unmarshal(data, &registered); err != nil {
		t.Fatalf("decode registration: %v", err)
	}
	if registered.ClientID == "" || registered.RegistrationAccessToken == "" {
		t.Fatalf("registration = %+v", registered)
	}
	req, _ := http.NewRequest(http.MethodGet, registered.RegistrationClientURI, nil)
	req.Header.Set("Authorization", "Bearer "+registered.RegistrationAccessToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("read registration: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("read registration status = %d", resp.StatusCode)
	}
}

func TestIDTokenRejectsWrongNonce(t *testing.T) {
	fixture := newOIDCFixture(t, false)
	ctx := context.Background()
	rp, err := NewRelyingParty(ctx, RelyingPartyConfig{
		Issuer:       fixture.server.URL,
		ClientID:     "web",
		ClientSecret: "rp-secret",
		RedirectURL:  "https://rp.example/callback",
		Scopes:       []string{ScopeOpenID, ScopeEmail},
		UsePKCE:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	authURL, verifier, err := rp.AuthCodeURL("s", "nonce-right")
	if err != nil {
		t.Fatal(err)
	}
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := noRedirect.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	location, _ := url.Parse(resp.Header.Get("Location"))
	code := location.Query().Get("code")
	token, err := rp.Exchange(ctx, code, "nonce-right", verifier)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if _, err := rp.ValidateIDToken(ctx, token.IDToken.RawToken, "nonce-wrong", token.AccessToken); err == nil {
		t.Fatal("wrong nonce accepted")
	}
}
