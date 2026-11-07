package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth/protocol/oauth2"
	"github.com/shibingli/ydx/auth/token/jose"
	"github.com/shibingli/ydx/json"
)

// signLogoutClaims signs an arbitrary logout claim set with the fixture key. The optional typ
// overrides the logout+jwt header. | signLogoutClaims 用夹具密钥签发任意登出声明集；可选的 typ
// 覆盖 logout+jwt 头部。
func signLogoutClaims(t *testing.T, provider *Provider, claims map[string]any, typ ...string) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	headerType := "logout+jwt"
	if len(typ) > 0 {
		headerType = typ[0]
	}
	signed, err := jose.Sign(payload, provider.signingKey, jose.SignOptions{
		Alg: "RS256",
		Kid: provider.signingKey.Kid,
		Typ: headerType,
	})
	if err != nil {
		t.Fatalf("sign logout claims: %v", err)
	}
	return signed
}

func TestLogoutTokenValidation(t *testing.T) {
	fixture := newOIDCFixture(t, false)
	provider := fixture.provider
	ctx := context.Background()

	if _, err := provider.LogoutToken(nil, "user-1", ""); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil client = %v", err)
	}
	raw, err := provider.LogoutToken(fixture.client, "user-1", "sid-1")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := provider.ValidateLogoutToken(ctx, raw, fixture.server.URL, "web")
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if claims.Issuer != fixture.server.URL || !claims.Audience.Contains("web") ||
		claims.Subject != "user-1" || claims.SID != "sid-1" || claims.JTI == "" ||
		claims.IssuedAt == 0 || claims.Nonce != "" {
		t.Fatalf("claims = %+v", claims)
	}
	if _, ok := claims.Events[BackchannelLogoutEvent].(map[string]any); !ok {
		t.Fatalf("events = %v", claims.Events)
	}
	if _, err := provider.ValidateLogoutToken(ctx, raw, "https://other.example", "web"); !errors.Is(err, ErrInvalidIssuer) {
		t.Fatalf("issuer mismatch = %v", err)
	}
	if _, err := provider.ValidateLogoutToken(ctx, raw, fixture.server.URL, "other"); !errors.Is(err, ErrInvalidAudience) {
		t.Fatalf("audience mismatch = %v", err)
	}
	if _, err := provider.ValidateLogoutToken(ctx, raw, fixture.server.URL, ""); err != nil {
		t.Fatalf("any audience = %v", err)
	}
	if _, err := provider.ValidateLogoutToken(ctx, "garbage", fixture.server.URL, "web"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("garbage = %v", err)
	}

	base := func() map[string]any {
		return map[string]any{
			"iss":    fixture.server.URL,
			"sub":    "user-1",
			"aud":    []string{"web"},
			"iat":    time.Now().Unix(),
			"jti":    "jti-1",
			"sid":    "sid-1",
			"events": map[string]any{BackchannelLogoutEvent: map[string]any{}},
		}
	}
	cases := []struct {
		name   string
		mutate func(map[string]any)
		want   error
	}{
		{"missing audience", func(c map[string]any) { delete(c, "aud") }, ErrInvalidAudience},
		{"empty audience", func(c map[string]any) { c["aud"] = []string{} }, ErrInvalidAudience},
		{"stale iat", func(c map[string]any) { c["iat"] = time.Now().Add(-10 * time.Minute).Unix() }, ErrInvalidToken},
		{"missing iat", func(c map[string]any) { delete(c, "iat") }, ErrInvalidToken},
		{"missing jti", func(c map[string]any) { delete(c, "jti") }, ErrInvalidToken},
		{"nonce present", func(c map[string]any) { c["nonce"] = "n-1" }, ErrInvalidToken},
		{"missing event", func(c map[string]any) { c["events"] = map[string]any{} }, ErrInvalidToken},
		{"event not object", func(c map[string]any) { c["events"] = map[string]any{BackchannelLogoutEvent: "yes"} }, ErrInvalidToken},
		{"no sub or sid", func(c map[string]any) { delete(c, "sub"); delete(c, "sid") }, ErrInvalidToken},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := base()
			tc.mutate(claims)
			raw := signLogoutClaims(t, provider, claims)
			if _, err := provider.ValidateLogoutToken(ctx, raw, fixture.server.URL, "web"); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v want %v", err, tc.want)
			}
		})
	}

	// A valid sid-only token is accepted. | 仅带 sid 的合法令牌可被接受。
	sidOnly := base()
	delete(sidOnly, "sub")
	if _, err := provider.ValidateLogoutToken(ctx, signLogoutClaims(t, provider, sidOnly), fixture.server.URL, "web"); err != nil {
		t.Fatalf("sid only = %v", err)
	}
}

func TestLogoutTokenTypAndProviderClock(t *testing.T) {
	fixture := newOIDCFixture(t, false)
	provider := fixture.provider
	ctx := context.Background()
	fixed := time.Unix(1_700_000_000, 0).UTC()
	provider.now = func() time.Time { return fixed }

	claims := map[string]any{
		"iss":    fixture.server.URL,
		"sub":    "user-1",
		"aud":    []string{"web"},
		"iat":    fixed.Unix(),
		"jti":    "jti-clock",
		"events": map[string]any{BackchannelLogoutEvent: map[string]any{}},
	}
	if _, err := provider.ValidateLogoutToken(ctx, signLogoutClaims(t, provider, claims), fixture.server.URL, "web"); err != nil {
		t.Fatalf("provider clock: %v", err)
	}
	for _, typ := range []string{"", "JWT", "id_token", "at+jwt"} {
		t.Run("typ "+typ, func(t *testing.T) {
			raw := signLogoutClaims(t, provider, claims, typ)
			if _, err := provider.ValidateLogoutToken(ctx, raw, fixture.server.URL, "web"); err == nil {
				t.Fatalf("typ %q was accepted", typ)
			}
		})
	}

	// The provider clock drives the iat window in both directions. | 提供方时钟双向约束 iat 窗口。
	provider.now = func() time.Time { return fixed.Add(10 * time.Minute) }
	if _, err := provider.ValidateLogoutToken(ctx, signLogoutClaims(t, provider, claims), fixture.server.URL, "web"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("stale against provider clock = %v", err)
	}
	provider.now = func() time.Time { return fixed.Add(-10 * time.Minute) }
	if _, err := provider.ValidateLogoutToken(ctx, signLogoutClaims(t, provider, claims), fixture.server.URL, "web"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("future against provider clock = %v", err)
	}
}

func TestProviderPathNormalization(t *testing.T) {
	fixture := newOIDCFixture(t, false)
	config := fixture.provider.Config()
	config.PathPrefix = "idp/"
	config.JWKSPath = "keys"
	config.DiscoveryPath = "custom-discovery"
	provider, err := NewProvider(config)
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}
	if got := provider.Config(); got.PathPrefix != "/idp" || got.JWKSPath != "/keys" || got.DiscoveryPath != "/custom-discovery" {
		t.Fatalf("provider config = prefix %q jwks %q discovery %q", got.PathPrefix, got.JWKSPath, got.DiscoveryPath)
	}
	if provider.Path("authorize") != "/idp/authorize" || provider.Path("/userinfo") != "/idp/userinfo" ||
		provider.Path("") != "/idp" {
		t.Fatalf("provider paths = %q %q %q", provider.Path("authorize"), provider.Path("/userinfo"), provider.Path(""))
	}
	if provider.Endpoint("keys") != fixture.server.URL+"/idp/keys" {
		t.Fatalf("endpoint = %q", provider.Endpoint("keys"))
	}
}

func TestNotifyBackchannelLogout(t *testing.T) {
	fixture := newOIDCFixture(t, false)
	provider := fixture.provider
	ctx := context.Background()

	if err := provider.NotifyBackchannelLogout(ctx, nil, "user-1", ""); err != nil {
		t.Fatalf("nil client = %v", err)
	}
	client := *fixture.client
	if err := provider.NotifyBackchannelLogout(ctx, &client, "user-1", ""); err != nil {
		t.Fatalf("no uri = %v", err)
	}

	status := http.StatusNoContent
	var received string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		received = r.Form.Get("logout_token")
		w.WriteHeader(status)
	}))
	defer target.Close()
	client.BackchannelLogoutURI = target.URL
	if err := provider.NotifyBackchannelLogout(ctx, &client, "user-1", "sid-1"); err != nil {
		t.Fatalf("notify = %v", err)
	}
	if received == "" {
		t.Fatal("missing logout token")
	}
	if _, err := provider.ValidateLogoutToken(ctx, received, fixture.server.URL, "web"); err != nil {
		t.Fatalf("delivered token = %v", err)
	}
	status = http.StatusInternalServerError
	if err := provider.NotifyBackchannelLogout(ctx, &client, "user-1", "sid-1"); !errors.Is(err, ErrLogoutFailed) {
		t.Fatalf("500 = %v", err)
	}
	client.BackchannelLogoutURI = "http://[::1]:bad"
	if err := provider.NotifyBackchannelLogout(ctx, &client, "user-1", "sid-1"); !errors.Is(err, ErrLogoutFailed) {
		t.Fatalf("bad uri = %v", err)
	}
}

func TestBackchannelLogoutEndpoint(t *testing.T) {
	fixture := newOIDCFixture(t, false)
	provider := fixture.provider
	raw, err := provider.LogoutToken(fixture.client, "user-1", "sid-1")
	if err != nil {
		t.Fatal(err)
	}
	call := func(method string, form url.Values) *httptest.ResponseRecorder {
		var body *strings.Reader
		if form != nil {
			body = strings.NewReader(form.Encode())
		} else {
			body = strings.NewReader("")
		}
		req := httptest.NewRequest(method, "/backchannel_logout", body)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		provider.BackchannelLogout(w, req)
		return w
	}
	if w := call(http.MethodGet, nil); w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "POST" {
		t.Fatalf("GET = %d allow=%q", w.Code, w.Header().Get("Allow"))
	}
	if w := call(http.MethodPost, nil); w.Code != http.StatusBadRequest {
		t.Fatalf("missing token = %d", w.Code)
	}
	if w := call(http.MethodPost, url.Values{"logout_token": {"bad"}}); w.Code != http.StatusBadRequest {
		t.Fatalf("bad token = %d", w.Code)
	}
	if w := call(http.MethodPost, url.Values{"logout_token": {raw}}); w.Code != http.StatusOK {
		t.Fatalf("valid token = %d body=%s", w.Code, w.Body.String())
	}
}

func TestEndSessionEndpointAndURL(t *testing.T) {
	fixture := newOIDCFixture(t, false)
	provider := fixture.provider

	if got := provider.EndSessionURL("", "", "", ""); got != provider.Endpoint(provider.config.EndSessionPath) {
		t.Fatalf("empty URL = %q", got)
	}
	built := provider.EndSessionURL("web", "https://rp.example/logged-out", "state-1", "hint")
	parsed, err := url.Parse(built)
	if err != nil || parsed.Query().Get("client_id") != "web" ||
		parsed.Query().Get("post_logout_redirect_uri") != "https://rp.example/logged-out" ||
		parsed.Query().Get("state") != "state-1" || parsed.Query().Get("id_token_hint") != "hint" {
		t.Fatalf("built URL = %q", built)
	}

	call := func(method string, form url.Values) *httptest.ResponseRecorder {
		body := ""
		if form != nil {
			body = form.Encode()
		}
		req := httptest.NewRequest(method, "/logout?"+body, nil)
		if method == http.MethodPost {
			req = httptest.NewRequest(method, "/logout", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		w := httptest.NewRecorder()
		provider.EndSession(w, req)
		return w
	}
	if w := call(http.MethodPut, nil); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT = %d", w.Code)
	}
	if w := call(http.MethodGet, nil); w.Code != http.StatusBadRequest {
		t.Fatalf("missing client = %d", w.Code)
	}
	if w := call(http.MethodGet, url.Values{"client_id": {"unknown"}}); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown client = %d", w.Code)
	}
	if w := call(http.MethodGet, url.Values{"client_id": {"web"}, "post_logout_redirect_uri": {"https://evil.example"}}); w.Code != http.StatusBadRequest {
		t.Fatalf("unregistered redirect = %d", w.Code)
	}
	if w := call(http.MethodGet, url.Values{"client_id": {"web"}, "id_token_hint": {"bad"}}); w.Code != http.StatusBadRequest {
		t.Fatalf("bad hint = %d", w.Code)
	}
	w := call(http.MethodGet, url.Values{
		"client_id":                {"web"},
		"post_logout_redirect_uri": {"https://rp.example/logged-out"},
		"state":                    {"state-1"},
	})
	if w.Code != http.StatusFound {
		t.Fatalf("logout = %d body=%s", w.Code, w.Body.String())
	}
	location, _ := url.Parse(w.Header().Get("Location"))
	if location.Query().Get("state") != "state-1" {
		t.Fatalf("logout location = %s", location)
	}
	if w := call(http.MethodGet, url.Values{"client_id": {"web"}}); w.Code != http.StatusOK {
		t.Fatalf("logged out page = %d", w.Code)
	}

	// A signed id_token_hint identifies the client and session. | 已签名 id_token_hint 标识客户端与会话。
	now := time.Now().Unix()
	hint := signLogoutClaims(t, provider, map[string]any{
		"iss": fixture.server.URL,
		"sub": "user-1",
		"aud": []string{"web"},
		"sid": "sid-1",
		"iat": now,
		"exp": now + 300,
	})
	w = call(http.MethodPost, url.Values{"id_token_hint": {hint}, "post_logout_redirect_uri": {"https://rp.example/logged-out"}})
	if w.Code != http.StatusFound {
		t.Fatalf("hint logout = %d body=%s", w.Code, w.Body.String())
	}
	multi := signLogoutClaims(t, provider, map[string]any{
		"iss": fixture.server.URL,
		"sub": "user-1",
		"aud": []string{"web", "other"},
		"iat": now,
		"exp": now + 300,
	})
	if w := call(http.MethodGet, url.Values{"id_token_hint": {multi}}); w.Code != http.StatusBadRequest {
		t.Fatalf("multi audience without client = %d", w.Code)
	}
	if w := call(http.MethodGet, url.Values{"id_token_hint": {multi}, "client_id": {"other"}}); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown hinted client = %d", w.Code)
	}
}

func TestFrontchannelLogout(t *testing.T) {
	fixture := newOIDCFixture(t, false)
	provider := fixture.provider
	call := func(query string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/frontchannel?"+query, nil)
		w := httptest.NewRecorder()
		provider.FrontchannelLogout(w, req)
		return w
	}
	if w := call(""); w.Code != http.StatusBadRequest {
		t.Fatalf("missing iss = %d", w.Code)
	}
	if w := call("iss=https%3A%2F%2Fother.example"); w.Code != http.StatusBadRequest {
		t.Fatalf("wrong iss = %d", w.Code)
	}
	w := call(url.Values{"iss": {fixture.server.URL}, "sid": {"<script>"}}.Encode())
	if w.Code != http.StatusOK {
		t.Fatalf("frontchannel = %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "sid=&lt;script&gt;") || strings.Contains(body, "sid=<script>") {
		t.Fatalf("html escaping = %s", body)
	}
}

func TestPairwiseSubjects(t *testing.T) {
	if PairwiseSubject("user-1", "sector-a", "salt") != PairwiseSubject("user-1", "sector-a", "salt") {
		t.Fatal("pairwise subject is not deterministic")
	}
	if PairwiseSubject("user-1", "sector-a", "salt") == PairwiseSubject("user-2", "sector-a", "salt") ||
		PairwiseSubject("user-1", "sector-a", "salt") == PairwiseSubject("user-1", "sector-b", "salt") ||
		PairwiseSubject("user-1", "sector-a", "salt") == PairwiseSubject("user-1", "sector-a", "pepper") {
		t.Fatal("pairwise subject does not vary by input")
	}
	for _, raw := range []string{"https://EXAMPLE.com/x", "https://example.com:8443/x"} {
		if got := sectorHost(raw); got != "example.com" {
			t.Fatalf("sectorHost(%q) = %q", raw, got)
		}
	}
	if sectorHost("") != "" || sectorHost("%zz") != "%zz" {
		t.Fatal("sectorHost fallback")
	}

	pairwise := &Provider{config: ProviderConfig{SubjectType: SubjectTypePairwise, PairwiseSalt: "salt"}}
	client := &oauth2.Client{ID: "web", RedirectURIs: []string{"https://rp.example/cb"}}
	subject := pairwise.subjectForClient(client, "user-1")
	if subject == "user-1" || subject != PairwiseSubject("user-1", "rp.example", "salt") {
		t.Fatalf("pairwise subject = %q", subject)
	}
	withSectorURI := &oauth2.Client{ID: "web", SectorIdentifierURI: "https://SECTOR.example/sector.json", RedirectURIs: []string{"https://rp.example/cb"}}
	if got := pairwise.subjectForClient(withSectorURI, "user-1"); got != PairwiseSubject("user-1", "sector.example", "salt") {
		t.Fatalf("sector uri subject = %q", got)
	}
	publicClient := &oauth2.Client{ID: "web", SubjectType: SubjectTypePublic, RedirectURIs: []string{"https://rp.example/cb"}}
	if pairwise.subjectForClient(publicClient, "user-1") != "user-1" {
		t.Fatal("client subject_type override")
	}
	public := &Provider{config: ProviderConfig{SubjectType: SubjectTypePublic}}
	if public.subjectForClient(client, "user-1") != "user-1" {
		t.Fatal("public subject")
	}
	custom := &Provider{config: ProviderConfig{SubjectType: SubjectTypePairwise, PairwiseSalt: "salt", SectorIdentifier: func(*oauth2.Client) string {
		return "company"
	}}}
	if got := custom.subjectForClient(client, "user-1"); got != PairwiseSubject("user-1", "company", "salt") {
		t.Fatalf("custom sector = %q", got)
	}
}

func TestRegistrationURLValidation(t *testing.T) {
	valid := []string{"https://rp.example/jwks.json", "https://rp.example:8443/.well-known/jwks.json"}
	for _, raw := range valid {
		if err := validateSecureURL(raw); err != nil {
			t.Fatalf("valid URL %q = %v", raw, err)
		}
	}
	invalid := []string{"", "http://rp.example/jwks.json", "/jwks.json", "https://user:pass@rp.example/jwks.json", "https://rp.example/jwks.json#frag", "mailto:admin@rp.example"}
	for _, raw := range invalid {
		if err := validateSecureURL(raw); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("invalid URL %q = %v", raw, err)
		}
	}
	if err := validateSectorIdentifier("https://rp.example/sector.json", []string{"https://rp.example/cb", "https://RP.example/cb2"}); err != nil {
		t.Fatalf("sector match = %v", err)
	}
	if err := validateSectorIdentifier("https://rp.example/sector.json", []string{"https://other.example/cb"}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("sector host mismatch = %v", err)
	}
	if err := validateSectorIdentifier("http://rp.example/sector.json", nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("sector scheme = %v", err)
	}
	if err := validateSectorIdentifier("https://rp.example/sector.json", []string{"native:/cb", "not a url"}); err != nil {
		t.Fatalf("redirects without hosts ignored = %v", err)
	}
}

func TestDiscoverAndRelyingPartyErrors(t *testing.T) {
	issuer := ""
	document := func(iss string) string {
		return `{"issuer":"` + iss + `","authorization_endpoint":"` + iss + `/authorize","token_endpoint":"` + iss + `/token","jwks_uri":"` + iss + `/jwks"}`
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(document(issuer)))
		}
	}))
	defer ts.Close()
	issuer = ts.URL

	ctx := context.Background()
	discovered, err := Discover(ctx, ts.URL+"/", ts.Client())
	if err != nil || discovered.Issuer != ts.URL || discovered.TokenEndpoint != ts.URL+"/token" {
		t.Fatalf("discover = %+v err=%v", discovered, err)
	}
	discovered, err = Discover(ctx, ts.URL, nil)
	if err != nil || discovered.Issuer != ts.URL {
		t.Fatalf("discover default client = %+v err=%v", discovered, err)
	}
	if _, err := Discover(ctx, "", nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("empty issuer = %v", err)
	}
	issuer = "https://other.example"
	if _, err := Discover(ctx, ts.URL, ts.Client()); !errors.Is(err, ErrInvalidIssuer) {
		t.Fatalf("issuer mismatch = %v", err)
	}
	issuer = ts.URL

	badStatus := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer badStatus.Close()
	if _, err := Discover(ctx, badStatus.URL, badStatus.Client()); !errors.Is(err, ErrDiscoveryFailed) {
		t.Fatalf("bad status = %v", err)
	}
	badJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer badJSON.Close()
	if _, err := Discover(ctx, badJSON.URL, badJSON.Client()); !errors.Is(err, ErrDiscoveryFailed) {
		t.Fatalf("bad JSON = %v", err)
	}

	if _, err := NewRelyingParty(ctx, RelyingPartyConfig{ClientID: "web", Issuer: ts.URL, Discovery: &DiscoveryDocument{ServerMetadata: &oauth2.ServerMetadata{Issuer: "https://other.example"}}}); !errors.Is(err, ErrInvalidIssuer) {
		t.Fatalf("RP issuer mismatch = %v", err)
	}
	if _, err := NewRelyingParty(ctx, RelyingPartyConfig{ClientID: "", Discovery: discovered}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("RP missing client = %v", err)
	}
	if _, err := NewRelyingParty(ctx, RelyingPartyConfig{ClientID: "web", Discovery: nil, Issuer: ts.URL, HTTPClient: ts.Client()}); err != nil {
		t.Fatalf("RP discovery = %v", err)
	}
	if _, err := NewRelyingParty(ctx, RelyingPartyConfig{ClientID: "web", Issuer: ts.URL, HTTPClient: ts.Client(), Discovery: &DiscoveryDocument{ServerMetadata: &oauth2.ServerMetadata{
		Issuer:                ts.URL,
		AuthorizationEndpoint: ts.URL + "/authorize",
		TokenEndpoint:         ts.URL + "/token",
		JWKSURI:               "http://[::1]:bad/jwks",
	}}}); !errors.Is(err, ErrDiscoveryFailed) {
		t.Fatalf("RP bad JWKS = %v", err)
	}
}

func TestRelyingPartyUserInfoJWT(t *testing.T) {
	fixture := newOIDCFixture(t, false)
	ctx := context.Background()
	discovery := fixture.provider.DiscoveryDocument()
	rp, err := NewRelyingParty(ctx, RelyingPartyConfig{
		ClientID:   "web",
		Discovery:  discovery,
		HTTPClient: fixture.server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	sign := func(claims map[string]any) string {
		payload, err := json.Marshal(claims)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := jose.Sign(payload, fixture.provider.signingKey, jose.SignOptions{Alg: "RS256", Kid: fixture.provider.signingKey.Kid})
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	raw := sign(map[string]any{"iss": discovery.Issuer, "sub": "user-1", "email": "alice@example.com"})
	claims, err := rp.verifyUserInfoJWT(ctx, raw)
	if err != nil || claims["sub"] != "user-1" || claims["email"] != "alice@example.com" {
		t.Fatalf("JWT userinfo = %+v err=%v", claims, err)
	}
	if _, err := rp.verifyUserInfoJWT(ctx, sign(map[string]any{"iss": "https://other.example", "sub": "user-1"})); !errors.Is(err, ErrInvalidIssuer) {
		t.Fatalf("issuer mismatch = %v", err)
	}
	if _, err := rp.verifyUserInfoJWT(ctx, "not-a-jwt"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("malformed = %v", err)
	}
	if _, err := rp.verifyUserInfoJWT(ctx, "a.b.c.d.e"); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("encrypted without key = %v", err)
	}
	noJWKS := &RelyingParty{discovery: &DiscoveryDocument{ServerMetadata: &oauth2.ServerMetadata{Issuer: discovery.Issuer}}}
	if _, err := noJWKS.verifyUserInfoJWT(ctx, raw); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("no JWKS = %v", err)
	}

	userInfo := func(status int, contentType, body string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer token-1" {
				t.Errorf("authorization = %q", r.Header.Get("Authorization"))
			}
			w.Header().Set("Content-Type", contentType)
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		}))
	}
	jsonServer := userInfo(http.StatusOK, "application/json", `{"sub":"user-1"}`)
	defer jsonServer.Close()
	rp.discovery.UserInfoEndpoint = jsonServer.URL
	claims, err = rp.UserInfo(ctx, "token-1")
	if err != nil || claims["sub"] != "user-1" {
		t.Fatalf("JSON userinfo = %+v err=%v", claims, err)
	}
	jwtServer := userInfo(http.StatusOK, "application/jwt", raw)
	defer jwtServer.Close()
	rp.discovery.UserInfoEndpoint = jwtServer.URL
	claims, err = rp.UserInfo(ctx, "token-1")
	if err != nil || claims["sub"] != "user-1" {
		t.Fatalf("JWT userinfo endpoint = %+v err=%v", claims, err)
	}
	failServer := userInfo(http.StatusUnauthorized, "application/json", `{"error":"invalid_token"}`)
	defer failServer.Close()
	rp.discovery.UserInfoEndpoint = failServer.URL
	if _, err := rp.UserInfo(ctx, "token-1"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("userinfo status = %v", err)
	}
	garbageServer := userInfo(http.StatusOK, "application/json", "not json")
	defer garbageServer.Close()
	rp.discovery.UserInfoEndpoint = garbageServer.URL
	if _, err := rp.UserInfo(ctx, "token-1"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("userinfo JSON = %v", err)
	}
	rp.discovery.UserInfoEndpoint = ""
	if _, err := rp.UserInfo(ctx, "token-1"); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("no endpoint = %v", err)
	}
}

func TestEqualAudience(t *testing.T) {
	if !EqualAudience(Audience{"web"}, "web") {
		t.Fatal("equal audience")
	}
	if EqualAudience(Audience{"web", "other"}, "web") || EqualAudience(Audience{"other"}, "web") || EqualAudience(nil, "") {
		t.Fatal("unequal audience")
	}
}
