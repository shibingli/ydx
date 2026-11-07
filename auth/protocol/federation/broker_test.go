package federation

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/auth/protocol/oauth2"
	"github.com/shibingli/ydx/router"
)

const (
	mockTokenResponse = `{"access_token":"mock-access-token","token_type":"Bearer","expires_in":3600,"scope":"openid email"}`
	mockUserResponse  = `{"sub":"subject-1","email":"alice@example.com","email_verified":true,"name":"Alice","preferred_username":"alice","picture":"https://example.com/alice.png"}`
)

type mockOAuthServer struct {
	server           *httptest.Server
	tokenResponse    string
	userInfoResponse string
	tokenStatus      int
	userInfoStatus   int

	mu            sync.Mutex
	tokenForms    []url.Values
	userInfoCalls int
}

func newMockOAuthServer(t *testing.T) *mockOAuthServer {
	t.Helper()
	mock := &mockOAuthServer{
		tokenResponse:    mockTokenResponse,
		userInfoResponse: mockUserResponse,
		tokenStatus:      http.StatusOK,
		userInfoStatus:   http.StatusOK,
	}
	mock.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad form", http.StatusBadRequest)
				return
			}
			mock.mu.Lock()
			mock.tokenForms = append(mock.tokenForms, cloneForm(r.PostForm))
			status := mock.tokenStatus
			body := mock.tokenResponse
			mock.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		case "/userinfo":
			mock.mu.Lock()
			mock.userInfoCalls++
			status := mock.userInfoStatus
			body := mock.userInfoResponse
			mock.mu.Unlock()
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
				http.Error(w, "missing bearer", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(mock.server.Close)
	return mock
}

func (m *mockOAuthServer) provider(name string) *Provider {
	return &Provider{
		Name:         name,
		DisplayName:  "Mock " + name,
		Kind:         KindOAuth2,
		ClientID:     "mock-client-" + name,
		ClientSecret: "mock-secret-" + name,
		RedirectURL:  "https://app.example/auth/" + name + "/callback",
		Scopes:       []string{"openid", "email"},
		AuthURL:      m.server.URL + "/authorize",
		TokenURL:     m.server.URL + "/token",
		UserInfoURL:  m.server.URL + "/userinfo",
		PKCE:         true,
		AuthStyle:    AuthStylePost,
	}
}

func (m *mockOAuthServer) lastTokenForm() url.Values {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.tokenForms) == 0 {
		return nil
	}
	return m.tokenForms[len(m.tokenForms)-1]
}

func (m *mockOAuthServer) tokenCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.tokenForms)
}

func (m *mockOAuthServer) userInfoCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.userInfoCalls
}

func cloneForm(values url.Values) url.Values {
	out := make(url.Values, len(values))
	for key, items := range values {
		out[key] = append([]string(nil), items...)
	}
	return out
}

func newTestAuthService(t *testing.T) (*auth.Service, auth.Stores) {
	t.Helper()
	stores := auth.NewMemoryStores()
	service, err := auth.New(auth.Config{Stores: stores})
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	return service, stores
}

func newTestBroker(t *testing.T, service *auth.Service, providers map[string]*Provider, mutate func(*BrokerConfig)) *Broker {
	t.Helper()
	config := BrokerConfig{
		Service:         service,
		Providers:       providers,
		SuccessRedirect: "/app",
	}
	if mutate != nil {
		mutate(&config)
	}
	broker, err := NewBroker(config)
	if err != nil {
		t.Fatalf("NewBroker: %v", err)
	}
	return broker
}

func serveHTTP(t *testing.T, handler http.Handler, method, target string, body url.Values) *httptest.ResponseRecorder {
	t.Helper()
	var request *http.Request
	if body != nil {
		request = httptest.NewRequest(method, target, strings.NewReader(body.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		request = httptest.NewRequest(method, target, nil)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func loginRedirect(t *testing.T, handler http.Handler, target string) *url.URL {
	t.Helper()
	recorder := serveHTTP(t, handler, http.MethodGet, target, nil)
	if recorder.Code != http.StatusFound {
		t.Fatalf("%s status = %d, want 302; body=%s", target, recorder.Code, recorder.Body.String())
	}
	location := recorder.Header().Get("Location")
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse redirect %q: %v", location, err)
	}
	return parsed
}

func TestBrokerFullRouterLoginFlow(t *testing.T) {
	mock := newMockOAuthServer(t)
	service, _ := newTestAuthService(t)
	broker := newTestBroker(t, service, map[string]*Provider{"mock": mock.provider("mock")}, nil)
	r := router.New()
	broker.Register(r, "/auth")

	authorization := loginRedirect(t, r, "/auth/mock/login")
	state := authorization.Query().Get("state")
	if state == "" {
		t.Fatal("authorization redirect has no state")
	}
	if authorization.Query().Get("client_id") != "mock-client-mock" {
		t.Fatalf("client_id = %q", authorization.Query().Get("client_id"))
	}
	if authorization.Query().Get("redirect_uri") != "https://app.example/auth/mock/callback" {
		t.Fatalf("redirect_uri = %q", authorization.Query().Get("redirect_uri"))
	}
	challenge := authorization.Query().Get("code_challenge")
	if challenge == "" || authorization.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("missing PKCE challenge: %s", authorization.RawQuery)
	}
	if authorization.Query().Get("scope") != "openid email" {
		t.Fatalf("scope = %q", authorization.Query().Get("scope"))
	}

	recorder := serveHTTP(t, r, http.MethodGet, "/auth/mock/callback?code=code-1&state="+url.QueryEscape(state), nil)
	if recorder.Code != http.StatusFound {
		t.Fatalf("callback status = %d, want 303; body=%s", recorder.Code, recorder.Body.String())
	}
	if location := recorder.Header().Get("Location"); location != "/app" {
		t.Fatalf("success redirect = %q, want /app", location)
	}

	form := mock.lastTokenForm()
	if form == nil {
		t.Fatal("token endpoint was not called")
	}
	if form.Get("grant_type") != "authorization_code" || form.Get("code") != "code-1" {
		t.Fatalf("token form = %v", form)
	}
	verifier := form.Get("code_verifier")
	if verifier == "" {
		t.Fatal("token request has no PKCE verifier")
	}
	if oauth2.CodeChallengeS256(verifier) != challenge {
		t.Fatal("token verifier does not match login challenge")
	}
	if form.Get("client_id") != "mock-client-mock" || form.Get("client_secret") != "mock-secret-mock" {
		t.Fatal("token request did not use POST client credentials")
	}
	if mock.userInfoCount() != 1 {
		t.Fatalf("userinfo calls = %d, want 1", mock.userInfoCount())
	}

	cookies := recorder.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("callback did not set a session cookie")
	}
	var sessionCookie *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == "ydx_session" {
			sessionCookie = cookie
		}
	}
	if sessionCookie == nil || sessionCookie.Value == "" || !sessionCookie.HttpOnly {
		t.Fatalf("session cookie = %#v", sessionCookie)
	}
	session, err := service.Sessions().Validate(context.Background(), sessionCookie.Value)
	if err != nil {
		t.Fatalf("validate session: %v", err)
	}
	if len(session.AMR) == 0 || session.AMR[0] != "federated" {
		t.Fatalf("session AMR = %v", session.AMR)
	}

	user, err := service.UserByIdentity(context.Background(), "mock", "subject-1")
	if err != nil {
		t.Fatalf("UserByIdentity: %v", err)
	}
	if user.ID != session.UserID {
		t.Fatalf("session user = %q, identity user = %q", session.UserID, user.ID)
	}
	if user.Email != "alice@example.com" || !user.EmailVerified {
		t.Fatalf("JIT user = %#v", user)
	}
	if user.DisplayName != "Alice" {
		t.Fatalf("display name = %q", user.DisplayName)
	}
}

func TestBrokerRejectsReusedUnknownAndCrossProviderState(t *testing.T) {
	mock := newMockOAuthServer(t)
	service, _ := newTestAuthService(t)
	broker := newTestBroker(t, service, map[string]*Provider{
		"mock":  mock.provider("mock"),
		"other": mock.provider("other"),
	}, nil)
	r := router.New()
	broker.Register(r, "/auth")

	authorization := loginRedirect(t, r, "/auth/mock/login")
	state := authorization.Query().Get("state")
	first := serveHTTP(t, r, http.MethodGet, "/auth/mock/callback?code=code-1&state="+url.QueryEscape(state), nil)
	if first.Code != http.StatusFound {
		t.Fatalf("first callback = %d; body=%s", first.Code, first.Body.String())
	}
	reused := serveHTTP(t, r, http.MethodGet, "/auth/mock/callback?code=code-2&state="+url.QueryEscape(state), nil)
	if reused.Code != http.StatusBadRequest || !strings.Contains(reused.Body.String(), "invalid_state") {
		t.Fatalf("reused state = %d %s", reused.Code, reused.Body.String())
	}
	if mock.tokenCount() != 1 {
		t.Fatalf("reused state reached token endpoint: %d calls", mock.tokenCount())
	}

	unknown := serveHTTP(t, r, http.MethodGet, "/auth/mock/callback?code=code&state=forged", nil)
	if unknown.Code != http.StatusBadRequest {
		t.Fatalf("unknown state = %d", unknown.Code)
	}

	authorization = loginRedirect(t, r, "/auth/mock/login")
	crossState := authorization.Query().Get("state")
	cross := serveHTTP(t, r, http.MethodGet, "/auth/other/callback?code=code&state="+url.QueryEscape(crossState), nil)
	if cross.Code != http.StatusBadRequest || !strings.Contains(cross.Body.String(), "invalid_state") {
		t.Fatalf("cross-provider state = %d %s", cross.Code, cross.Body.String())
	}
	if mock.tokenCount() != 1 {
		t.Fatalf("cross-provider state reached token endpoint: %d calls", mock.tokenCount())
	}
}

func TestBrokerProviderErrorAndMissingCode(t *testing.T) {
	mock := newMockOAuthServer(t)
	service, _ := newTestAuthService(t)
	broker := newTestBroker(t, service, map[string]*Provider{"mock": mock.provider("mock")}, nil)
	r := router.New()
	broker.Register(r, "/auth")

	authorization := loginRedirect(t, r, "/auth/mock/login")
	state := authorization.Query().Get("state")
	denied := serveHTTP(t, r, http.MethodGet, "/auth/mock/callback?error=access_denied&error_description=super-secret-description&state="+url.QueryEscape(state), nil)
	if denied.Code != http.StatusUnauthorized {
		t.Fatalf("provider denial = %d, want 401", denied.Code)
	}
	if body := denied.Body.String(); strings.Contains(body, "super-secret-description") || strings.Contains(body, "mock-secret") {
		t.Fatalf("failure body leaked provider details: %s", body)
	}
	if mock.tokenCount() != 0 {
		t.Fatal("provider denial reached token endpoint")
	}

	authorization = loginRedirect(t, r, "/auth/mock/login")
	state = authorization.Query().Get("state")
	missing := serveHTTP(t, r, http.MethodGet, "/auth/mock/callback?state="+url.QueryEscape(state), nil)
	if missing.Code != http.StatusBadRequest || !strings.Contains(missing.Body.String(), "missing_code") {
		t.Fatalf("missing code = %d %s", missing.Code, missing.Body.String())
	}
	replayed := serveHTTP(t, r, http.MethodGet, "/auth/mock/callback?code=late&state="+url.QueryEscape(state), nil)
	if replayed.Code != http.StatusBadRequest {
		t.Fatalf("replayed missing-code state = %d", replayed.Code)
	}
}

func TestBrokerTokenFailureDoesNotLeakProviderBody(t *testing.T) {
	mock := newMockOAuthServer(t)
	mock.tokenStatus = http.StatusInternalServerError
	mock.tokenResponse = `{"error":"invalid_grant","error_description":"super-secret-upstream-body"}`

	service, _ := newTestAuthService(t)
	broker := newTestBroker(t, service, map[string]*Provider{"mock": mock.provider("mock")}, nil)
	r := router.New()
	broker.Register(r, "/auth")

	authorization := loginRedirect(t, r, "/auth/mock/login")
	state := authorization.Query().Get("state")
	recorder := serveHTTP(t, r, http.MethodGet, "/auth/mock/callback?code=code&state="+url.QueryEscape(state), nil)
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("token failure = %d, want 502; body=%s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	for _, secret := range []string{"super-secret-upstream-body", "invalid_grant", "mock-secret", "mock-access-token"} {
		if strings.Contains(body, secret) {
			t.Fatalf("failure body leaked %q: %s", secret, body)
		}
	}
	if len(recorder.Result().Cookies()) != 0 {
		t.Fatal("failed login set a session cookie")
	}
}

func TestBrokerLinkByVerifiedEmail(t *testing.T) {
	mock := newMockOAuthServer(t)
	service, stores := newTestAuthService(t)
	now := time.Now()
	existing := &auth.User{
		ID:            "usr_existing",
		Email:         "alice@example.com",
		EmailVerified: true,
		Status:        auth.UserActive,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if err := stores.Users.CreateUser(context.Background(), existing); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	var result *LoginResult
	broker := newTestBroker(t, service, map[string]*Provider{"mock": mock.provider("mock")}, func(config *BrokerConfig) {
		config.LinkByEmail = true
		config.SuccessHandler = func(w http.ResponseWriter, _ *http.Request, got *LoginResult) {
			result = got
			w.WriteHeader(http.StatusNoContent)
		}
	})
	r := router.New()
	broker.Register(r, "/auth")

	authorization := loginRedirect(t, r, "/auth/mock/login")
	state := authorization.Query().Get("state")
	recorder := serveHTTP(t, r, http.MethodGet, "/auth/mock/callback?code=code&state="+url.QueryEscape(state), nil)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("callback = %d %s", recorder.Code, recorder.Body.String())
	}
	if result == nil || result.User == nil || result.User.ID != existing.ID {
		t.Fatalf("login result user = %#v, want %s", result, existing.ID)
	}
	linked, err := service.UserByIdentity(context.Background(), "mock", "subject-1")
	if err != nil || linked.ID != existing.ID {
		t.Fatalf("linked user = %#v, %v", linked, err)
	}
}

func TestBrokerNeverLinksUnverifiedEmail(t *testing.T) {
	mock := newMockOAuthServer(t)
	mock.userInfoResponse = `{"sub":"subject-2","email":"alice@example.com","email_verified":false,"name":"Impostor"}`
	service, stores := newTestAuthService(t)
	now := time.Now()
	existing := &auth.User{
		ID:            "usr_existing",
		Email:         "alice@example.com",
		EmailVerified: true,
		Status:        auth.UserActive,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if err := stores.Users.CreateUser(context.Background(), existing); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	broker := newTestBroker(t, service, map[string]*Provider{"mock": mock.provider("mock")}, func(config *BrokerConfig) {
		config.LinkByEmail = true
	})
	r := router.New()
	broker.Register(r, "/auth")

	authorization := loginRedirect(t, r, "/auth/mock/login")
	state := authorization.Query().Get("state")
	recorder := serveHTTP(t, r, http.MethodGet, "/auth/mock/callback?code=code&state="+url.QueryEscape(state), nil)
	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), "account_link_conflict") {
		t.Fatalf("unverified email login = %d %s", recorder.Code, recorder.Body.String())
	}
	if _, err := service.UserByIdentity(context.Background(), "mock", "subject-2"); !errors.Is(err, auth.ErrIdentityNotFound) {
		t.Fatalf("unverified identity was linked: %v", err)
	}
}

func TestBrokerCustomFailureHandlerAndNotFound(t *testing.T) {
	mock := newMockOAuthServer(t)
	service, _ := newTestAuthService(t)
	var captured error
	broker := newTestBroker(t, service, map[string]*Provider{"mock": mock.provider("mock")}, func(config *BrokerConfig) {
		config.FailureHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
			captured = err
			w.WriteHeader(http.StatusTeapot)
		}
	})
	r := router.New()
	broker.Register(r, "/auth")

	recorder := serveHTTP(t, r, http.MethodGet, "/auth/mock/callback?code=code&state=unknown", nil)
	if recorder.Code != http.StatusTeapot {
		t.Fatalf("custom failure status = %d", recorder.Code)
	}
	if !errors.Is(captured, ErrStateMismatch) {
		t.Fatalf("custom failure error = %v", captured)
	}

	notFound := serveHTTP(t, r, http.MethodGet, "/auth/missing/login", nil)
	if notFound.Code != http.StatusTeapot || !errors.Is(captured, ErrProviderNotFound) {
		t.Fatalf("unsupported provider = %d, %v", notFound.Code, captured)
	}

	defaultBroker := newTestBroker(t, service, map[string]*Provider{"mock": mock.provider("mock")}, nil)
	defaultRouter := router.New()
	defaultBroker.Register(defaultRouter, "/auth")
	if recorder := serveHTTP(t, defaultRouter, http.MethodGet, "/auth/missing/login", nil); recorder.Code != http.StatusNotFound {
		t.Fatalf("default unknown provider = %d, want 404", recorder.Code)
	}
}

func TestBrokerHTTPHandlerSupportsFormPostCallback(t *testing.T) {
	mock := newMockOAuthServer(t)
	service, _ := newTestAuthService(t)
	broker := newTestBroker(t, service, map[string]*Provider{"mock": mock.provider("mock")}, nil)
	handler := broker.HTTPHandler("/auth")

	authorization := loginRedirect(t, handler, "/auth/mock/login")
	state := authorization.Query().Get("state")
	recorder := serveHTTP(t, handler, http.MethodPost, "/auth/mock/callback", url.Values{
		"code":  {"form-post-code"},
		"state": {state},
	})
	if recorder.Code != http.StatusFound {
		t.Fatalf("POST callback = %d; body=%s", recorder.Code, recorder.Body.String())
	}
	if form := mock.lastTokenForm(); form.Get("code") != "form-post-code" {
		t.Fatalf("POST callback token form = %v", form)
	}

	if recorder := serveHTTP(t, handler, http.MethodGet, "/auth/mock/unknown", nil); recorder.Code != http.StatusNotFound {
		t.Fatalf("unknown action = %d", recorder.Code)
	}
	recorder = serveHTTP(t, handler, http.MethodPost, "/auth/mock/login", nil)
	if recorder.Code != http.StatusMethodNotAllowed || recorder.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("POST login = %d Allow=%q", recorder.Code, recorder.Header().Get("Allow"))
	}
	if recorder := serveHTTP(t, handler, http.MethodGet, "/other/mock/login", nil); recorder.Code != http.StatusNotFound {
		t.Fatalf("wrong prefix = %d", recorder.Code)
	}
}

func TestBrokerUsesHeadSafeLoginAndProviderClientOverride(t *testing.T) {
	mock := newMockOAuthServer(t)
	service, _ := newTestAuthService(t)
	provider := mock.provider("mock")
	provider.HTTPClient = &http.Client{Timeout: 2 * time.Second}
	broker := newTestBroker(t, service, map[string]*Provider{"mock": provider}, nil)
	handler := broker.HTTPHandler("")

	recorder := serveHTTP(t, handler, http.MethodHead, "/mock/login", nil)
	if recorder.Code != http.StatusFound {
		t.Fatalf("HEAD login = %d, want 302", recorder.Code)
	}
}
