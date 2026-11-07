package federation

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth"
)

// testStringer is a Stringer used by the scalar conversion tests. | testStringer 是标量转换测试
// 使用的 Stringer。
type testStringer struct{ value string }

func (s testStringer) String() string { return s.value }

// testAdapter is a complete custom provider adapter. | testAdapter 是完整的自定义提供方适配器。
type testAdapter struct {
	authURL string
	token   *Token
	ident   *Identity
}

func (a *testAdapter) AuthCodeURL(state, nonce, verifier string) (string, error) {
	return a.authURL + "?state=" + url.QueryEscape(state), nil
}

func (a *testAdapter) Exchange(context.Context, string, string) (*Token, error) {
	return a.token, nil
}

func (a *testAdapter) UserInfo(context.Context, *Token) (*Identity, error) { return a.ident, nil }

func TestTokenExpiryAndValidity(t *testing.T) {
	var nilToken *Token
	nilToken.SetExpiry(time.Now())
	if nilToken.Valid() {
		t.Error("nil Token.Valid() = true")
	}
	if (&Token{}).Valid() {
		t.Error("empty Token.Valid() = true")
	}
	now := time.Now()
	token := &Token{AccessToken: "a"}
	token.SetExpiry(now)
	if !token.Valid() || !token.Expiry.IsZero() {
		t.Errorf("without expires_in Valid=%v Expiry=%v", token.Valid(), token.Expiry)
	}
	token.ExpiresIn = 60
	token.SetExpiry(now)
	if !token.Expiry.After(now) || !token.Valid() {
		t.Errorf("future expiry Valid=%v Expiry=%v", token.Valid(), token.Expiry)
	}
	token.Expiry = now.Add(-time.Second)
	if token.Valid() {
		t.Error("expired Token.Valid() = true")
	}
}

func TestProviderOptionsAndConstructor(t *testing.T) {
	client := &http.Client{}
	adapter := &testAdapter{authURL: "https://example.com/auth"}
	p := &Provider{Name: "p", Extra: map[string]string{"old": "1"}}
	applyOptions(p, []ProviderOption{
		WithEndpoints(Endpoints{AuthURL: "https://a", TokenURL: "https://t", UserInfoURL: "https://u", JWKSURL: "https://j", Issuer: "iss", Extra: map[string]string{"k": "v"}}),
		WithHTTPClient(client),
		WithScopes("openid", "email"),
		WithPKCE(true),
		WithNonce(true),
		WithExtra("x", "y"),
		WithAuthParams(map[string]string{"prompt": "login"}),
		WithAuthURLHook(func(*Provider, string, string, string) (string, error) { return "hook", nil }),
		WithExchangeHook(func(context.Context, *Provider, *http.Client, string, string) (*Token, error) { return &Token{}, nil }),
		WithUserInfoHook(func(context.Context, *Provider, *http.Client, *Token) (*Identity, error) { return &Identity{}, nil }),
		WithAdapter(adapter),
	})
	if p.AuthURL != "https://a" || p.TokenURL != "https://t" || p.UserInfoURL != "https://u" || p.JWKSURL != "https://j" || p.Issuer != "iss" {
		t.Errorf("endpoints not applied: %+v", p)
	}
	if p.HTTPClient != client || !p.PKCE || !p.Nonce || p.AuthStyle != "" {
		t.Errorf("options not applied: %+v", p)
	}
	if strings.Join(p.Scopes, " ") != "openid email" || p.AuthParams["prompt"] != "login" || p.Extra["x"] != "y" || p.Extra["old"] != "1" || p.Extra["k"] != "v" {
		t.Errorf("maps/scopes not applied: %+v", p)
	}
	if p.Adapter != adapter || p.AuthURLHook == nil || p.ExchangeHook == nil || p.UserInfoHook == nil {
		t.Error("hooks/adapter not applied")
	}
	// Every option must tolerate a nil provider. | 每个选项都必须容忍 nil 提供方。
	applyOptions(nil, []ProviderOption{
		WithEndpoints(Endpoints{AuthURL: "x"}), WithHTTPClient(client), WithScopes("x"),
		WithPKCE(true), WithNonce(true), WithExtra("k", "v"), WithAuthParams(map[string]string{"k": "v"}),
		WithAuthURLHook(nil), WithExchangeHook(nil), WithUserInfoHook(nil), WithAdapter(nil), nil,
	})

	config := ProviderConfig{Name: " cfg ", ClientID: "id", TokenURL: "https://t", UserInfoURL: "https://u", UseOIDC: true, Scopes: []string{"openid"}, Extra: map[string]string{"k": "v"}}
	generic := NewProvider(config)
	if generic.Name != "cfg" || generic.Kind != KindOIDC || len(generic.Scopes) != 1 {
		t.Errorf("NewProvider(OIDC) = %+v", generic)
	}
	config.Extra["k"] = "changed"
	if generic.Extra["k"] != "v" {
		t.Error("NewProvider 未克隆 Extra")
	}
	if plain := NewProvider(ProviderConfig{Name: "p"}); plain.Kind != KindOAuth2 {
		t.Errorf("NewProvider default kind = %q", plain.Kind)
	}
}

func TestProviderValidateBranches(t *testing.T) {
	var nilProvider *Provider
	if !errors.Is(nilProvider.Validate(), ErrProviderConfig) {
		t.Error("nil provider Validate did not fail")
	}
	cases := []struct {
		name string
		p    *Provider
		ok   bool
	}{
		{"no name", &Provider{}, false},
		{"adapter bypass", &Provider{Name: "p", Adapter: &testAdapter{}}, true},
		{"no client id", &Provider{Name: "p"}, false},
		{"no auth url", &Provider{Name: "p", ClientID: "c", TokenURL: "t", UserInfoURL: "u"}, false},
		{"no token url", &Provider{Name: "p", ClientID: "c", AuthURL: "a", UserInfoURL: "u"}, false},
		{"no user info", &Provider{Name: "p", ClientID: "c", AuthURL: "a", TokenURL: "t"}, false},
		{"oidc discovery", &Provider{Name: "p", ClientID: "c", UseOIDC: true, Issuer: "https://issuer"}, true},
		{"bad auth style", &Provider{Name: "p", ClientID: "c", AuthURL: "a", TokenURL: "t", UserInfoURL: "u", AuthStyle: "bogus"}, false},
		{"valid post", &Provider{Name: "p", ClientID: "c", AuthURL: "a", TokenURL: "t", UserInfoURL: "u", AuthStyle: AuthStylePost}, true},
		{"hooks only", &Provider{Name: "p", ClientID: "c", AuthURLHook: func(*Provider, string, string, string) (string, error) { return "", nil }, ExchangeHook: func(context.Context, *Provider, *http.Client, string, string) (*Token, error) { return nil, nil }, UserInfoHook: func(context.Context, *Provider, *http.Client, *Token) (*Identity, error) { return nil, nil }}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.p.Validate()
			if tc.ok && err != nil {
				t.Errorf("Validate err = %v", err)
			}
			if !tc.ok && !errors.Is(err, ErrProviderConfig) {
				t.Errorf("Validate err = %v，期望 ErrProviderConfig", err)
			}
		})
	}
}

func TestBrokerConfigurationBranches(t *testing.T) {
	service, _ := newTestAuthService(t)
	if _, err := NewBroker(BrokerConfig{}); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("nil service err = %v", err)
	}
	if _, err := NewBroker(BrokerConfig{Service: service, Providers: map[string]*Provider{"bad": {}}}); !errors.Is(err, ErrProviderConfig) {
		t.Errorf("invalid provider err = %v", err)
	}
	broker, err := NewBroker(BrokerConfig{Service: service})
	if err != nil {
		t.Fatalf("NewBroker defaults failed: %v", err)
	}
	if broker.StateTTL <= 0 || broker.ClientID != "federation" || broker.SuccessRedirect != "/" || broker.StateStore == nil || broker.HTTPClient == nil {
		t.Errorf("defaults = %+v", broker)
	}

	var nilBroker *Broker
	if err := nilBroker.RegisterProvider("p", &Provider{}); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("nil broker RegisterProvider err = %v", err)
	}
	if err := broker.RegisterProvider("p", nil); !errors.Is(err, ErrProviderConfig) {
		t.Errorf("nil provider err = %v", err)
	}
	if err := broker.RegisterProvider("", &Provider{}); !errors.Is(err, ErrProviderConfig) {
		t.Errorf("empty name err = %v", err)
	}
	if err := broker.RegisterProvider("p", &Provider{}); !errors.Is(err, ErrProviderConfig) {
		t.Errorf("invalid provider err = %v", err)
	}
	adapter := &testAdapter{authURL: "https://example.com/auth"}
	provider := &Provider{Name: "p", Adapter: adapter}
	if err := broker.RegisterProvider("", provider); err != nil {
		t.Fatalf("RegisterProvider with adapter failed: %v", err)
	}
	if provider.Name != "p" || broker.Providers["p"] != provider {
		t.Error("RegisterProvider did not bind the route name")
	}
	gotProvider, gotAdapter, err := broker.adapter("p")
	if err != nil || gotProvider != provider || gotAdapter != adapter {
		t.Errorf("adapter(custom) = (%v, %v, %v)", gotProvider, gotAdapter, err)
	}
	if _, _, err := broker.adapter("missing"); !errors.Is(err, ErrProviderNotFound) {
		t.Errorf("adapter(missing) err = %v", err)
	}

	mock := newMockOAuthServer(t)
	plain := mock.provider("plain")
	if err := broker.RegisterProvider("plain", plain); err != nil {
		t.Fatalf("RegisterProvider(plain) failed: %v", err)
	}
	first, _, err := broker.adapter("plain")
	if err != nil {
		t.Fatalf("adapter(plain) failed: %v", err)
	}
	second, _, err := broker.adapter("plain")
	if err != nil || first != second {
		t.Error("built-in adapter 未缓存")
	}
	if err := broker.RegisterProvider("plain", mock.provider("plain")); err != nil {
		t.Fatalf("RegisterProvider replace failed: %v", err)
	}
	replaced, _, err := broker.adapter("plain")
	if err != nil || replaced == first {
		t.Error("重新注册后未重建适配器")
	}
}

func TestBrokerNativeHandlers(t *testing.T) {
	mock := newMockOAuthServer(t)
	service, _ := newTestAuthService(t)
	broker := newTestBroker(t, service, map[string]*Provider{"mock": mock.provider("mock")}, nil)

	login := broker.LoginHandler("mock")
	redirect := loginRedirect(t, login, "/login")
	state := redirect.Query().Get("state")
	if state == "" {
		t.Fatal("LoginHandler redirect has no state")
	}
	if rec := serveHTTP(t, login, http.MethodPost, "/login", nil); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("login POST status = %d", rec.Code)
	}
	if rec := serveHTTP(t, broker.LoginHandler(""), http.MethodGet, "/login", nil); rec.Code != http.StatusNotFound {
		t.Errorf("empty provider login status = %d", rec.Code)
	}

	callback := broker.CallbackHandler("mock")
	rec := serveHTTP(t, callback, http.MethodGet, "/callback?state="+url.QueryEscape(state)+"&code=test-code", nil)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/app" {
		t.Fatalf("callback status = %d location = %q body=%s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	if rec := serveHTTP(t, callback, http.MethodPut, "/callback", nil); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("callback PUT status = %d", rec.Code)
	}
	if rec := serveHTTP(t, callback, http.MethodGet, "/callback", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("missing state status = %d", rec.Code)
	}
	if rec := serveHTTP(t, callback, http.MethodGet, "/callback?state=forged&code=x", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("forged state status = %d", rec.Code)
	}
	if rec := serveHTTP(t, callback, http.MethodGet, "/callback?error=access_denied", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("provider error status = %d", rec.Code)
	}

	broker.Login(nil)
	broker.Callback(nil)
	if rec := serveHTTP(t, broker.LoginHandler("mock"), http.MethodHead, "/login", nil); rec.Code != http.StatusFound {
		t.Errorf("HEAD login status = %d", rec.Code)
	}

	httpHandler := broker.HTTPHandler("auth")
	if rec := serveHTTP(t, httpHandler, http.MethodGet, "/nope", nil); rec.Code != http.StatusNotFound {
		t.Errorf("unknown path status = %d", rec.Code)
	}
	if rec := serveHTTP(t, httpHandler, http.MethodGet, "/auth/mock/other", nil); rec.Code != http.StatusNotFound {
		t.Errorf("unknown action status = %d", rec.Code)
	}
	if rec := serveHTTP(t, httpHandler, http.MethodPost, "/auth/mock/login", nil); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("HTTP login POST status = %d", rec.Code)
	}
	if rec := serveHTTP(t, httpHandler, http.MethodPut, "/auth/mock/callback", nil); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("HTTP callback PUT status = %d", rec.Code)
	}
	redirect = loginRedirect(t, httpHandler, "/auth/mock/login")
	if redirect.Query().Get("state") == "" {
		t.Error("HTTPHandler login has no state")
	}
	broker.Register(nil, "/auth")
}

func TestBrokerLoginFailureModes(t *testing.T) {
	mock := newMockOAuthServer(t)
	service, _ := newTestAuthService(t)
	provider := mock.provider("mock")
	provider.RedirectURL = ""
	broker := newTestBroker(t, service, map[string]*Provider{"mock": provider}, nil)
	if rec := serveHTTP(t, broker.LoginHandler("mock"), http.MethodGet, "/login", nil); rec.Code != http.StatusInternalServerError {
		t.Errorf("missing redirect URL status = %d body=%s", rec.Code, rec.Body.String())
	}

	broker = newTestBroker(t, service, map[string]*Provider{"mock": mock.provider("mock")}, nil)
	broker.StateStore = nil
	if rec := serveHTTP(t, broker.LoginHandler("mock"), http.MethodGet, "/login", nil); rec.Code != http.StatusInternalServerError {
		t.Errorf("nil state store status = %d", rec.Code)
	}
}

func TestFailureMappings(t *testing.T) {
	cases := []struct {
		err    error
		reason string
		code   string
		status int
	}{
		{ErrProviderDenied, "provider_denied", "provider_denied", http.StatusUnauthorized},
		{ErrStateExpired, "state_expired", "invalid_state", http.StatusBadRequest},
		{ErrStateMismatch, "state_mismatch", "invalid_state", http.StatusBadRequest},
		{ErrMissingCode, "missing_code", "missing_code", http.StatusBadRequest},
		{ErrNonceMismatch, "nonce_mismatch", "nonce_mismatch", http.StatusBadRequest},
		{ErrTokenExchange, "token_exchange", "login_failed", http.StatusBadGateway},
		{ErrUserInfo, "user_info", "login_failed", http.StatusBadGateway},
		{ErrAccountLinkConflict, "account_link_conflict", "account_link_conflict", http.StatusConflict},
		{ErrProviderNotFound, "provider_not_found", "provider_not_found", http.StatusNotFound},
		{auth.ErrAccountDisabled, "account_disabled", "account_unavailable", http.StatusForbidden},
		{auth.ErrAccountLocked, "account_locked", "account_unavailable", http.StatusForbidden},
		{auth.ErrAccountPending, "account_pending", "account_unavailable", http.StatusForbidden},
		{ErrProviderConfig, "internal_error", "login_failed", http.StatusInternalServerError},
		{ErrInvalidRequest, "internal_error", "login_failed", http.StatusBadRequest},
		{ErrTransport, "internal_error", "login_failed", http.StatusBadGateway},
		{errors.New("boom"), "internal_error", "login_failed", http.StatusInternalServerError},
	}
	for _, tc := range cases {
		if got := failureReason(tc.err); got != tc.reason {
			t.Errorf("failureReason(%v) = %q，期望 %q", tc.err, got, tc.reason)
		}
		if got := failureCode(tc.err); got != tc.code {
			t.Errorf("failureCode(%v) = %q，期望 %q", tc.err, got, tc.code)
		}
		if got := failureStatus(tc.err); got != tc.status {
			t.Errorf("failureStatus(%v) = %d，期望 %d", tc.err, got, tc.status)
		}
	}
}

func TestVerifyNonceBranches(t *testing.T) {
	record := &StateRecord{Nonce: "nonce-1"}
	token := &Token{Claims: map[string]string{"nonce": "nonce-1"}}
	if err := verifyNonce(nil, nil, nil); err != nil {
		t.Errorf("nil provider err = %v", err)
	}
	if err := verifyNonce(&Provider{}, nil, nil); err != nil {
		t.Errorf("nonce disabled err = %v", err)
	}
	enabled := &Provider{Nonce: true}
	cases := []struct {
		name   string
		record *StateRecord
		token  *Token
		ok     bool
	}{
		{"nil record", nil, token, false},
		{"empty record nonce", &StateRecord{}, token, false},
		{"nil token", record, nil, false},
		{"no claims", record, &Token{}, false},
		{"missing claim", record, &Token{Claims: map[string]string{}}, false},
		{"wrong nonce", record, &Token{Claims: map[string]string{"nonce": "other"}}, false},
		{"match", record, token, true},
	}
	for _, tc := range cases {
		err := verifyNonce(enabled, tc.record, tc.token)
		if tc.ok && err != nil {
			t.Errorf("%s: err = %v", tc.name, err)
		}
		if !tc.ok && !errors.Is(err, ErrNonceMismatch) {
			t.Errorf("%s: err = %v，期望 ErrNonceMismatch", tc.name, err)
		}
	}
}

func TestIdentityMappingBranches(t *testing.T) {
	if identityFromClaims("p", nil) != nil {
		t.Error("identityFromClaims(empty) != nil")
	}
	identity := identityFromClaims("p", map[string]string{
		"sub": "subject", "email": "a@example.com", "email_verified": "true",
		"name": "Alice", "picture": "https://example.com/a.png",
	})
	if identity.Provider != "p" || identity.Subject != "subject" || identity.Email != "a@example.com" || !identity.EmailVerified || identity.Name != "Alice" || identity.AvatarURL == "" {
		t.Errorf("identityFromClaims = %+v", identity)
	}
	fallbackSubject := identityFromClaims("p", map[string]string{"uid": "u-1"})
	if fallbackSubject.Subject != "u-1" {
		t.Errorf("identityFromClaims uid subject = %q", fallbackSubject.Subject)
	}

	if mergeIdentity(nil, nil) != nil {
		t.Error("mergeIdentity(nil,nil) != nil")
	}
	fallback := &Identity{Provider: "p", Subject: "s", Email: "e", EmailVerified: true, Username: "u", Name: "n", AvatarURL: "a", Raw: map[string]string{"x": "1", "shared": "fallback"}}
	if mergeIdentity(nil, fallback) != fallback {
		t.Error("mergeIdentity(nil, fallback) did not return fallback")
	}
	primary := &Identity{Raw: map[string]string{"shared": "primary"}}
	merged := mergeIdentity(primary, fallback)
	if merged != primary || merged.Provider != "p" || merged.Subject != "s" || merged.Email != "e" || !merged.EmailVerified || merged.Username != "u" || merged.Name != "n" || merged.AvatarURL != "a" {
		t.Errorf("mergeIdentity = %+v", merged)
	}
	if merged.Raw["x"] != "1" || merged.Raw["shared"] != "primary" {
		t.Errorf("mergeIdentity Raw = %+v", merged.Raw)
	}
	if mergeIdentity(primary, nil) != primary {
		t.Error("mergeIdentity(identity, nil) did not return identity")
	}
	empty := &Identity{}
	mergedEmpty := mergeIdentity(empty, &Identity{Raw: nil})
	if mergedEmpty.Raw == nil {
		t.Error("mergeIdentity did not initialize Raw")
	}
}

func TestScalarConversionHelpers(t *testing.T) {
	values := []struct {
		in   any
		want string
	}{
		{nil, ""}, {"s", "s"}, {true, "true"}, {false, "false"}, {float64(1.5), "1.5"}, {float32(1.5), "1.5"},
		{7, "7"}, {int64(8), "8"}, {int32(9), "9"}, {uint64(10), "10"}, {uint(11), "11"},
		{testStringer{"str"}, "str"}, {[]string{"a", "b"}, "a b"}, {[]any{"a", 1, nil}, "a 1"},
		{map[string]string{"a": "b"}, `{"a":"b"}`}, {make(chan int), ""},
	}
	for _, tc := range values {
		if got := stringValue(tc.in); got != tc.want {
			t.Errorf("stringValue(%#v) = %q，期望 %q", tc.in, got, tc.want)
		}
	}
	ints := []struct {
		in   any
		want int64
	}{
		{int64(1), 1}, {2, 2}, {int32(3), 3}, {uint64(4), 4}, {uint64(1 << 63), 0},
		{float64(5.9), 5}, {testStringer{"6"}, 6}, {"7", 7}, {" 8 ", 8}, {"bad", 0}, {nil, 0},
	}
	for _, tc := range ints {
		if got := int64Value(tc.in); got != tc.want {
			t.Errorf("int64Value(%#v) = %d，期望 %d", tc.in, got, tc.want)
		}
	}
	bools := []struct {
		in   any
		want bool
	}{
		{true, true}, {false, false}, {"true", true}, {"1", true}, {"yes", true}, {"Y", true}, {"no", false},
		{testStringer{"1"}, true}, {testStringer{"2"}, false}, {float64(1), true}, {float64(2), false},
		{int64(1), true}, {int64(0), false}, {1, true}, {0, false}, {nil, false},
	}
	for _, tc := range bools {
		if got := boolValue(tc.in); got != tc.want {
			t.Errorf("boolValue(%#v) = %v，期望 %v", tc.in, got, tc.want)
		}
	}
	if stringMap(nil) != nil || stringMap(map[string]any{"a": ""}) != nil {
		t.Error("stringMap should return nil for empty maps")
	}
	if got := stringMap(map[string]any{"a": "x", "b": 2}); got["a"] != "x" || got["b"] != "2" {
		t.Errorf("stringMap = %+v", got)
	}
	raw := map[string]any{"nested": map[string]any{"k": "v"}, "scalar": "x"}
	if nestedMap(raw, "nested")["k"] != "v" || nestedMap(raw, "scalar") != nil {
		t.Error("nestedMap mismatch")
	}
	if firstStringValue(map[string]any{"a": "", "b": "b"}, "a", "b") != "b" {
		t.Error("firstStringValue did not skip empty values")
	}
	if firstIntValue(map[string]any{"a": 0, "b": 3}, "a", "b") != 3 {
		t.Error("firstIntValue did not skip zero")
	}
	if firstNonEmpty("", "x") != "x" || firstNonEmpty("", "") != "" {
		t.Error("firstNonEmpty mismatch")
	}
	if mergeRawMaps(nil, map[string]string{"a": "1", "b": ""}, map[string]string{"a": "2"})["a"] != "2" {
		t.Error("mergeRawMaps did not let later values win")
	}
	if mergeRawMaps(nil, nil) != nil {
		t.Error("mergeRawMaps(nil) != nil")
	}

	form, err := parseFormObject([]byte("a=1&b=2&c=3&c=4"))
	if err != nil || form["a"] != "1" || form["c"] != "3" {
		t.Errorf("parseFormObject = (%+v, %v)", form, err)
	}
	if _, err := parseFormObject([]byte("")); err == nil {
		t.Error("parseFormObject(empty) did not fail")
	}
	if _, err := parseFormObject([]byte("%zz")); err == nil {
		t.Error("parseFormObject(invalid) did not fail")
	}
	if providerStatusError(ErrTokenExchange, "p", "token", 500) == nil {
		t.Error("providerStatusError returned nil")
	}

	codes := []struct{ in, want string }{
		{"", "error"}, {"access_denied", "access_denied"}, {"bad code", "error"},
		{strings.Repeat("a", 80), strings.Repeat("a", 64)},
	}
	for _, tc := range codes {
		if got := sanitizeProviderCode(tc.in); got != tc.want {
			t.Errorf("sanitizeProviderCode(%q) = %q，期望 %q", tc.in, got, tc.want)
		}
	}
	if safeProviderName("  ") != "" || safeProviderName("bad name") != "error" || len(safeProviderName(strings.Repeat("b", 80))) != 64 {
		t.Error("safeProviderName mismatch")
	}
	prefixes := []struct{ in, want string }{
		{"", ""}, {"/", ""}, {"auth", "/auth"}, {"/auth/", "/auth"}, {" /auth ", "/auth"},
	}
	for _, tc := range prefixes {
		if got := normalizePrefix(tc.in); got != tc.want {
			t.Errorf("normalizePrefix(%q) = %q，期望 %q", tc.in, got, tc.want)
		}
	}
	routes := []struct {
		base, path, provider, action string
		ok                           bool
	}{
		{"", "/p/login", "p", "login", true},
		{"", "/p/callback", "p", "callback", true},
		{"", "p/login", "", "", false},
		{"", "/p", "", "", false},
		{"", "/p/other", "", "", false},
		{"/auth", "/auth/p/login", "p", "login", true},
		{"/auth", "/other/p/login", "", "", false},
		{"/auth", "/auth//login", "", "", false},
		{"/auth", "/auth/p/x/y", "", "", false},
	}
	for _, tc := range routes {
		provider, action, ok := matchHTTPRoute(tc.base, tc.path)
		if ok != tc.ok || provider != tc.provider || action != tc.action {
			t.Errorf("matchHTTPRoute(%q,%q) = (%q,%q,%v)，期望 (%q,%q,%v)", tc.base, tc.path, provider, action, ok, tc.provider, tc.action, tc.ok)
		}
	}
}

func TestAdapterAuthURLBranches(t *testing.T) {
	p := &Provider{Name: "p", ClientID: "c", RedirectURL: "r", AuthURL: "https://example.com/auth", TokenURL: "https://example.com/token", UserInfoURL: "https://example.com/ui", PKCE: true}
	adapter := newAdapter(p, nil)
	if _, err := adapter.AuthCodeURL("s", "n", ""); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("missing PKCE verifier err = %v", err)
	}
	target, err := adapter.AuthCodeURL("s", "n", "verifier")
	if err != nil || !strings.Contains(target, "code_challenge=") || !strings.Contains(target, "state=s") {
		t.Errorf("AuthCodeURL = (%q, %v)", target, err)
	}
	hookProvider := &Provider{Name: "p", ClientID: "c", AuthURLHook: func(*Provider, string, string, string) (string, error) { return "https://hook", nil }}
	hookTarget, err := newAdapter(hookProvider, nil).AuthCodeURL("s", "n", "")
	if err != nil || hookTarget != "https://hook" {
		t.Errorf("AuthCodeURL hook = (%q, %v)", hookTarget, err)
	}
	if newAdapter(nil, nil) != nil {
		t.Error("newAdapter(nil) != nil")
	}
}
