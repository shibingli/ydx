package oidc

import (
	"context"
	"errors"
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
)

func TestValidateCodeHashAndClaim(t *testing.T) {
	want, err := halfHash("RS256", "code-1")
	if err != nil {
		t.Fatal(err)
	}
	token := &IDToken{
		Claims: Claims{CodeHash: want},
		Header: map[string]any{"alg": "RS256"},
		Raw:    map[string]any{"sub": "user-1"},
	}
	if err := token.ValidateCodeHash("code-1"); err != nil {
		t.Fatalf("valid c_hash = %v", err)
	}
	if err := token.ValidateCodeHash("code-2"); !errors.Is(err, ErrInvalidCHash) {
		t.Fatalf("mismatch = %v", err)
	}
	if err := (&IDToken{Header: map[string]any{"alg": "RS256"}}).ValidateCodeHash("code-1"); !errors.Is(err, ErrInvalidCHash) {
		t.Fatalf("missing c_hash = %v", err)
	}
	if err := (*IDToken)(nil).ValidateCodeHash("code-1"); !errors.Is(err, ErrInvalidCHash) {
		t.Fatalf("nil token = %v", err)
	}
	badAlg := &IDToken{Claims: Claims{CodeHash: want}, Header: map[string]any{"alg": "magic"}}
	if err := badAlg.ValidateCodeHash("code-1"); err == nil {
		t.Fatal("unknown alg accepted")
	}
	if value, ok := token.Claim("sub"); !ok || value != "user-1" {
		t.Fatalf("claim = %v %v", value, ok)
	}
	if _, ok := token.Claim("missing"); ok {
		t.Fatal("missing claim reported present")
	}
	if _, ok := (*IDToken)(nil).Claim("sub"); ok {
		t.Fatal("nil claim reported present")
	}
}

func TestSessionStateAndCheckSession(t *testing.T) {
	fixture := newOIDCFixture(t, false)
	provider := fixture.provider
	state := provider.SessionState("web", "sid-1")
	hash, salt, ok := strings.Cut(state, ".")
	if !ok || salt == "" || hash != sessionStateHash("web", "sid-1", salt) {
		t.Fatalf("session state = %q", state)
	}
	if sessionStateHash("web", "sid-1", "salt") == sessionStateHash("other", "sid-1", "salt") {
		t.Fatal("session hash does not bind client")
	}

	call := func(method, query string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/check_session?"+query, nil)
		w := httptest.NewRecorder()
		provider.CheckSession(w, req)
		return w
	}
	if w := call(http.MethodPost, ""); w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET" {
		t.Fatalf("POST = %d", w.Code)
	}
	if w := call(http.MethodGet, ""); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "postMessage") {
		t.Fatalf("HTML = %d body=%s", w.Code, w.Body.String())
	}
	// Without a session manager every session state is reported changed. | 没有会话管理器时所有会话
	// 状态均报告为 changed。
	if w := call(http.MethodGet, url.Values{"client_id": {"web"}, "session_state": {state}}.Encode()); w.Code != http.StatusOK || w.Body.String() != "changed" {
		t.Fatalf("changed = %d %q", w.Code, w.Body.String())
	}
}

func TestDiscoveryAndJWKSHandlers(t *testing.T) {
	fixture := newOIDCFixture(t, false)
	provider := fixture.provider

	for _, tc := range []struct {
		name   string
		handle func(http.ResponseWriter, *http.Request)
	}{
		{"discovery", provider.Discovery},
		{"jwks", provider.JWKS},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			tc.handle(w, httptest.NewRequest(http.MethodGet, "/", nil))
			if w.Code != http.StatusOK || !strings.Contains(w.Header().Get("Content-Type"), "json") {
				t.Fatalf("GET = %d type=%q", w.Code, w.Header().Get("Content-Type"))
			}
			if w.Header().Get("Cache-Control") == "" {
				t.Fatal("missing Cache-Control")
			}
			w = httptest.NewRecorder()
			tc.handle(w, httptest.NewRequest(http.MethodPost, "/", nil))
			if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET" {
				t.Fatalf("POST = %d allow=%q", w.Code, w.Header().Get("Allow"))
			}
		})
	}
	if provider.Config().Issuer != fixture.server.URL || provider.OAuth() != fixture.oauth || provider.Keys() == nil {
		t.Fatal("provider accessors")
	}
	if _, err := provider.signingKeyFor("ES256"); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("unknown signing alg = %v", err)
	}
	if key, err := provider.signingKeyFor(""); err != nil || key != provider.signingKey {
		t.Fatalf("default signing key = %v %v", key, err)
	}
	if !keyMatchesAlg(provider.signingKey, "PS256") || keyMatchesAlg(provider.signingKey, "ES256") || keyMatchesAlg(provider.signingKey, "magic") {
		t.Fatal("keyMatchesAlg")
	}
	ec, err := jose.GenerateKey("ES256", 0)
	if err != nil {
		t.Fatal(err)
	}
	if keyMatchesAlg(ec, "ES256") != true || keyMatchesAlg(ec, "RS256") {
		t.Fatal("keyMatchesAlg EC")
	}
}

func TestProviderHTTPHandler(t *testing.T) {
	fixture := newOIDCFixture(t, false)
	ts := httptest.NewServer(fixture.provider.HTTPHandler())
	defer ts.Close()

	get := func(path string) (*http.Response, string) {
		resp, err := ts.Client().Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp, string(body)
	}
	for path, wantStatus := range map[string]int{
		DiscoveryPath:    http.StatusOK,
		JWKSPath:         http.StatusOK,
		CheckSessionPath: http.StatusOK,
		EndSessionPath:   http.StatusBadRequest,
		UserInfoPath:     http.StatusUnauthorized,
	} {
		resp, _ := get(path)
		if resp.StatusCode != wantStatus {
			t.Fatalf("%s = %d want %d", path, resp.StatusCode, wantStatus)
		}
	}
	// Logout channels and registration are not mounted when disabled. | 功能关闭时登出通道与注册
	// 端点未挂载。
	resp, err := ts.Client().PostForm(ts.URL+BackchannelLogoutPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("backchannel disabled = %d", resp.StatusCode)
	}
	resp, err = ts.Client().Get(ts.URL + FrontchannelLogoutPath)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("frontchannel disabled = %d", resp.StatusCode)
	}
	resp, err = ts.Client().Get(ts.URL + RegistrationPath)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("registration disabled = %d", resp.StatusCode)
	}
}

func TestUserInfoEndpointOpaqueTokens(t *testing.T) {
	fixture := newOIDCFixture(t, false)
	provider := fixture.provider
	store := fixture.oauth.Config().Store
	now := time.Now().UTC()
	save := func(raw string, scopes []string, clientID string) {
		err := store.SaveAccessToken(context.Background(), &oauth2.AccessToken{
			TokenHash: auth.HashToken(raw),
			ClientID:  clientID,
			UserID:    "user-1",
			Subject:   "user-1",
			Principal: &auth.Principal{Subject: "user-1", Email: "alice@example.com", EmailVerified: true, DisplayName: "Alice"},
			Scopes:    scopes,
			IssuedAt:  now,
			ExpiresAt: now.Add(time.Minute),
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	save("openid-token", []string{ScopeOpenID, ScopeEmail}, "web")
	save("profile-token", []string{ScopeProfile}, "web")
	save("unknown-client", []string{ScopeOpenID}, "ghost")

	call := func(method, bearer string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/userinfo", nil)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		provider.UserInfo(w, req)
		return w
	}
	if w := call(http.MethodPut, "openid-token"); w.Code != http.StatusMethodNotAllowed || !strings.Contains(w.Header().Get("Allow"), "GET") {
		t.Fatalf("PUT = %d", w.Code)
	}
	if w := call(http.MethodGet, ""); w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("missing bearer = %d", w.Code)
	}
	if w := call(http.MethodGet, "bad-token"); w.Code != http.StatusUnauthorized {
		t.Fatalf("invalid token = %d", w.Code)
	}
	if w := call(http.MethodGet, "profile-token"); w.Code != http.StatusForbidden ||
		!strings.Contains(w.Header().Get("WWW-Authenticate"), "insufficient_scope") {
		t.Fatalf("insufficient scope = %d %q", w.Code, w.Header().Get("WWW-Authenticate"))
	}
	if w := call(http.MethodGet, "unknown-client"); w.Code != http.StatusUnauthorized {
		t.Fatalf("unknown client = %d", w.Code)
	}
	w := call(http.MethodGet, "openid-token")
	if w.Code != http.StatusOK {
		t.Fatalf("userinfo = %d body=%s", w.Code, w.Body.String())
	}
	var claims map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &claims); err != nil {
		t.Fatal(err)
	}
	if claims["sub"] != "user-1" || claims["email"] != "alice@example.com" {
		t.Fatalf("claims = %v", claims)
	}
}
