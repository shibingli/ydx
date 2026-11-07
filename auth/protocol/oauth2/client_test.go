package oauth2

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shibingli/ydx/json"
)

// recordedRequest captures one client request. | recordedRequest 记录一次客户端请求。
type recordedRequest struct {
	path   string
	form   url.Values
	header http.Header
}

// clientTestServer records requests and returns canned endpoint responses. | clientTestServer 记录
// 请求并返回固定的端点响应。
type clientTestServer struct {
	server   *httptest.Server
	mu       sync.Mutex
	requests []recordedRequest
}

// last returns the most recent recorded request. | last 返回最近记录的一次请求。
func (s *clientTestServer) last(t *testing.T) recordedRequest {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.requests) == 0 {
		t.Fatal("no request recorded")
	}
	return s.requests[len(s.requests)-1]
}

// newClientTestServer starts a fake authorization server for the client implementation. | newClientTestServer
// 为客户端实现启动一个假的授权服务器。
func newClientTestServer(t *testing.T) *clientTestServer {
	t.Helper()
	recorder := &clientTestServer{}
	mux := http.NewServeMux()
	record := func(r *http.Request) url.Values {
		_ = r.ParseForm()
		recorder.mu.Lock()
		recorder.requests = append(recorder.requests, recordedRequest{
			path:   r.URL.Path,
			form:   r.PostForm,
			header: r.Header.Clone(),
		})
		recorder.mu.Unlock()
		return r.PostForm
	}
	write := func(w http.ResponseWriter, status int, body string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		form := record(r)
		if form.Get("code") == "bad-code" {
			write(w, http.StatusBadRequest, `{"error":"invalid_grant","error_description":"code is invalid"}`)
			return
		}
		switch form.Get("grant_type") {
		case "", GrantAuthorizationCode, GrantRefreshToken, GrantClientCredentials, GrantPassword, GrantJWTBearer, GrantTokenExchange, GrantDeviceCode:
			write(w, http.StatusOK, `{"access_token":"at-1","token_type":"Bearer","refresh_token":"rt-1","expires_in":60,"scope":"api:read","id_token":"id-1","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","raw_extension":true}`)
		default:
			write(w, http.StatusBadRequest, `{"error":"unsupported_grant_type","error_description":"nope","error_uri":"https://errors.example/unsupported"}`)
		}
	})
	mux.HandleFunc("/revoke", func(w http.ResponseWriter, r *http.Request) {
		form := record(r)
		if form.Get("token") == "bad" {
			write(w, http.StatusBadRequest, `{"error":"invalid_request","error_description":"missing"}`)
			return
		}
		if form.Get("token") == "broken" {
			write(w, http.StatusInternalServerError, `not json`)
			return
		}
		write(w, http.StatusOK, `{}`)
	})
	mux.HandleFunc("/introspect", func(w http.ResponseWriter, r *http.Request) {
		form := record(r)
		if form.Get("token") == "bad" {
			write(w, http.StatusBadRequest, `{"error":"invalid_request"}`)
			return
		}
		if form.Get("token") == "broken" {
			write(w, http.StatusOK, `not json`)
			return
		}
		write(w, http.StatusOK, `{"active":true,"scope":"api:read","client_id":"web","username":"alice","token_type":"Bearer","sub":"user-1","aud":["api"],"iss":"https://auth.example","jti":"jti-1","exp":2000000000,"iat":1900000000,"nbf":1900000000,"cnf":{"jkt":"thumb"}}`)
	})
	mux.HandleFunc("/device_authorization", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		write(w, http.StatusOK, `{"device_code":"dc-1","user_code":"ABCD","verification_uri":"https://auth.example/device","verification_uri_complete":"https://auth.example/device?user_code=ABCD","expires_in":600,"interval":5}`)
	})
	mux.HandleFunc("/par", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		write(w, http.StatusCreated, `{"request_uri":"urn:ietf:params:oauth:request_uri:par-1","expires_in":60}`)
	})
	recorder.server = httptest.NewServer(mux)
	t.Cleanup(recorder.server.Close)
	return recorder
}

// newTestOAuthClient builds a client pointed at the fake server. | newTestOAuthClient 构建指向假
// 服务器的客户端。
func newTestOAuthClient(t *testing.T, recorder *clientTestServer, mutate func(*ClientConfig)) *OAuthClient {
	t.Helper()
	config := ClientConfig{
		ClientID:     "web",
		ClientSecret: "s3cret",
		RedirectURL:  "https://rp.example/callback",
		Scopes:       []string{"openid", "api:read"},
		Endpoint: Endpoint{
			AuthURL:          recorder.server.URL + "/authorize?prompt=existing",
			TokenURL:         recorder.server.URL + "/token",
			DeviceAuthURL:    recorder.server.URL + "/device_authorization",
			IntrospectionURL: recorder.server.URL + "/introspect",
			RevocationURL:    recorder.server.URL + "/revoke",
			PARURL:           recorder.server.URL + "/par",
		},
	}
	if mutate != nil {
		mutate(&config)
	}
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	return client
}

func TestNewClientValidation(t *testing.T) {
	if _, err := NewClient(ClientConfig{}); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("empty id error = %v", err)
	}
	if _, err := NewClient(ClientConfig{ClientID: "x"}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("no endpoint error = %v", err)
	}
	if _, err := NewClient(ClientConfig{ClientID: "x", Endpoint: Endpoint{TokenURL: "https://a/token"}, AuthStyle: "weird"}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("auth style error = %v", err)
	}
	client, err := NewClient(ClientConfig{ClientID: "x", Endpoint: Endpoint{TokenURL: "https://a/token"}})
	if err != nil {
		t.Fatalf("default client: %v", err)
	}
	if client.Config().AuthStyle != AuthStyleAuto || client.http.Timeout != 30*time.Second {
		t.Fatalf("defaults = %+v", client.Config())
	}
	custom := &http.Client{Timeout: time.Second}
	client, err = NewClient(ClientConfig{ClientID: "x", Endpoint: Endpoint{TokenURL: "https://a/token"}, HTTPClient: custom})
	if err != nil || client.http != custom {
		t.Fatalf("custom http client = %v", err)
	}
}

func TestAuthCodeURLWithOptions(t *testing.T) {
	recorder := newClientTestServer(t)
	client := newTestOAuthClient(t, recorder, func(config *ClientConfig) {
		config.UsePKCE = true
		config.ExtraParams = url.Values{"extra": {"1"}}
	})
	raw, verifier, err := client.AuthCodeURLWithPKCE("state-1",
		WithNonce("nonce-1"),
		WithPrompt("login", "consent"),
		WithLoginHint("alice"),
		WithMaxAge(300),
		WithACRValues("urn:acr:1", "urn:acr:2"),
		WithUILocales("en", "zh"),
		WithResource("https://api.example", "https://api2.example"),
		WithResponseMode(ResponseModeFragment),
		WithAuthParam("claims", `{"id_token":{}}`),
	)
	if err != nil {
		t.Fatalf("auth code url: %v", err)
	}
	if verifier == "" {
		t.Fatal("no generated verifier")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	query := parsed.Query()
	checks := map[string]string{
		"response_type":         ResponseCode,
		"client_id":             "web",
		"redirect_uri":          "https://rp.example/callback",
		"scope":                 "openid api:read",
		"state":                 "state-1",
		"nonce":                 "nonce-1",
		"prompt":                "login consent",
		"login_hint":            "alice",
		"max_age":               "300",
		"acr_values":            "urn:acr:1 urn:acr:2",
		"ui_locales":            "en zh",
		"response_mode":         ResponseModeFragment,
		"claims":                `{"id_token":{}}`,
		"code_challenge_method": PKCES256,
		"code_challenge":        CodeChallengeS256(verifier),
	}
	for key, want := range checks {
		if got := query.Get(key); got != want {
			t.Errorf("%s = %q want %q", key, got, want)
		}
	}
	if got := query["resource"]; len(got) != 2 || got[0] != "https://api.example" || got[1] != "https://api2.example" {
		t.Errorf("resource = %v", got)
	}
	if got := query.Get("extra"); got != "1" {
		t.Errorf("extra = %q", got)
	}
	// Option values override the preset prompt parameter instead of duplicating it. | 选项值覆盖预设
	// 的 prompt 参数而不是产生重复值。
	if got := query["prompt"]; len(got) != 1 || got[0] != "login consent" {
		t.Errorf("prompt values = %v", got)
	}

	// The simple wrapper returns the same URL without the verifier. | 简单包装返回相同 URL 但不返回校验器。
	wrapped, err := client.AuthCodeURL("state-2", WithPKCE(false))
	if err != nil {
		t.Fatalf("auth code url wrapper: %v", err)
	}
	wrappedURL, _ := url.Parse(wrapped)
	if wrappedURL.Query().Get("state") != "state-2" || wrappedURL.Query().Get("code_challenge") != "" {
		t.Fatalf("wrapped url = %s", wrapped)
	}

	// An explicit verifier is reused and WithPKCE(false) disables PKCE. | 显式校验器被复用，WithPKCE(false) 关闭 PKCE。
	_, supplied, err := client.AuthCodeURLWithPKCE("s", WithCodeVerifier("verifier-value"))
	if err != nil || supplied != "verifier-value" {
		t.Fatalf("supplied verifier = %q err=%v", supplied, err)
	}
	raw, _, err = client.AuthCodeURLWithPKCE("s", WithPKCE(false), WithCodeVerifier("ignored"))
	if err != nil {
		t.Fatalf("pkce off: %v", err)
	}
	offURL, _ := url.Parse(raw)
	if offURL.Query().Get("code_challenge") != "" {
		t.Fatalf("PKCE challenge with PKCE off: %s", raw)
	}
}

func TestAuthCodeURLErrors(t *testing.T) {
	recorder := newClientTestServer(t)
	client := newTestOAuthClient(t, recorder, func(config *ClientConfig) {
		config.Endpoint.AuthURL = ""
	})
	if _, _, err := client.AuthCodeURLWithPKCE("s"); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("missing auth endpoint error = %v", err)
	}
	client = newTestOAuthClient(t, recorder, func(config *ClientConfig) {
		config.Endpoint.AuthURL = "://bad"
	})
	if _, _, err := client.AuthCodeURLWithPKCE("s"); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("bad auth endpoint error = %v", err)
	}
}

func TestClientTokenRequests(t *testing.T) {
	ctx := context.Background()
	recorder := newClientTestServer(t)
	client := newTestOAuthClient(t, recorder, nil)

	token, err := client.Exchange(ctx, "code-1",
		WithExchangeVerifier("verifier-1"),
		WithExchangeRedirectURL("https://rp.example/other"),
		WithExchangeScope("api:read"),
		WithExchangeParam("custom", "value"),
	)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if token.AccessToken != "at-1" || token.RefreshToken != "rt-1" || token.TokenType != TokenTypeBearer ||
		token.ExpiresIn != 60 || token.IDToken != "id-1" || token.Scope != "api:read" {
		t.Fatalf("token = %+v", token)
	}
	if !token.Valid() || token.Expiry.IsZero() {
		t.Fatalf("token validity = %+v", token)
	}
	if token.Raw["raw_extension"] != true {
		t.Fatalf("raw = %v", token.Raw)
	}
	call := recorder.last(t)
	form := call.form
	if form.Get("grant_type") != GrantAuthorizationCode || form.Get("code") != "code-1" ||
		form.Get("code_verifier") != "verifier-1" ||
		form.Get("redirect_uri") != "https://rp.example/other" ||
		form.Get("scope") != "api:read" || form.Get("custom") != "value" {
		t.Fatalf("exchange form = %v", form)
	}
	if call.header.Get("Cache-Control") != "no-store" || call.header.Get("Accept") != "application/json" {
		t.Fatalf("headers = %v", call.header)
	}

	if _, err := client.Refresh(ctx, "rt-old", "openid"); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if form := recorder.last(t).form; form.Get("grant_type") != GrantRefreshToken || form.Get("refresh_token") != "rt-old" || form.Get("scope") != "openid" {
		t.Fatalf("refresh form = %v", form)
	}
	if _, err := client.ClientCredentials(ctx, "api:read"); err != nil {
		t.Fatalf("client credentials: %v", err)
	}
	if form := recorder.last(t).form; form.Get("grant_type") != GrantClientCredentials || form.Get("scope") != "api:read" {
		t.Fatalf("client credentials form = %v", form)
	}
	if _, err := client.Password(ctx, "alice", "pw", "api:read"); err != nil {
		t.Fatalf("password: %v", err)
	}
	if form := recorder.last(t).form; form.Get("grant_type") != GrantPassword || form.Get("username") != "alice" || form.Get("password") != "pw" {
		t.Fatalf("password form = %v", form)
	}
	if _, err := client.JWTBearer(ctx, "assertion-1", "api:read"); err != nil {
		t.Fatalf("jwt bearer: %v", err)
	}
	if form := recorder.last(t).form; form.Get("grant_type") != GrantJWTBearer || form.Get("assertion") != "assertion-1" {
		t.Fatalf("jwt bearer form = %v", form)
	}
	if _, err := client.TokenExchange(ctx, "subject", SubjectTokenAccessToken,
		WithTokenExchangeActor("actor", "urn:actor"),
		WithTokenExchangeAudience("https://api.example"),
		WithTokenExchangeScope("api:read"),
		WithTokenExchangeRequestedType(SubjectTokenJWT),
	); err != nil {
		t.Fatalf("token exchange: %v", err)
	}
	if form := recorder.last(t).form; form.Get("grant_type") != GrantTokenExchange ||
		form.Get("subject_token") != "subject" ||
		form.Get("subject_token_type") != SubjectTokenAccessToken ||
		form.Get("actor_token") != "actor" ||
		form.Get("actor_token_type") != "urn:actor" ||
		form.Get("audience") != "https://api.example" ||
		form.Get("requested_token_type") != SubjectTokenJWT {
		t.Fatalf("token exchange form = %v", form)
	}
	if _, err := client.DeviceToken(ctx, "device-1"); err != nil {
		t.Fatalf("device token: %v", err)
	}
	if form := recorder.last(t).form; form.Get("grant_type") != GrantDeviceCode || form.Get("device_code") != "device-1" {
		t.Fatalf("device token form = %v", form)
	}
}

func TestClientErrorResponses(t *testing.T) {
	ctx := context.Background()
	recorder := newClientTestServer(t)
	client := newTestOAuthClient(t, recorder, nil)

	_, err := client.Exchange(ctx, "bad-code")
	if err == nil {
		t.Fatal("expected an error for an invalid code")
	}
	var oauthErr *Error
	if !errors.As(err, &oauthErr) || oauthErr.Code != ErrorInvalidGrant || oauthErr.Status != http.StatusBadRequest {
		t.Fatalf("error = %v", err)
	}
	_, err = client.tokenRequest(ctx, url.Values{"grant_type": {"weird"}})
	if !errors.As(err, &oauthErr) || oauthErr.Code != ErrorUnsupportedGrantType {
		t.Fatalf("unsupported grant error = %v", err)
	}
	if oauthErr.URI != "https://errors.example/unsupported" {
		t.Fatalf("error uri = %q", oauthErr.URI)
	}

	if err := client.Revoke(ctx, "bad", "access_token"); err == nil {
		t.Fatal("revoke error was nil")
	} else if !errors.As(err, &oauthErr) || oauthErr.Code != ErrorInvalidRequest {
		t.Fatalf("revoke error = %v", err)
	}
	if err := client.Revoke(ctx, "broken", ""); !errors.Is(err, ErrServerError) {
		t.Fatalf("broken revoke error = %v", err)
	}
	if _, err := client.Introspect(ctx, "bad", "access_token"); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("introspect error = %v", err)
	}
	if _, err := client.Introspect(ctx, "broken", ""); !errors.Is(err, ErrServerError) {
		t.Fatalf("broken introspect error = %v", err)
	}

	// Missing endpoint configuration. | 缺少端点配置。
	empty := newTestOAuthClient(t, recorder, func(config *ClientConfig) {
		config.Endpoint = Endpoint{AuthURL: "https://auth.example/authorize"}
	})
	if _, err := empty.Exchange(ctx, "code"); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("exchange endpoint error = %v", err)
	}
	if err := empty.Revoke(ctx, "token", ""); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("revoke endpoint error = %v", err)
	}
	if _, err := empty.Introspect(ctx, "token", ""); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("introspect endpoint error = %v", err)
	}
	if _, err := empty.DeviceAuthorization(ctx); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("device endpoint error = %v", err)
	}
	if _, err := empty.PAR(ctx, nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("par endpoint error = %v", err)
	}
}

func TestClientAuthStyles(t *testing.T) {
	ctx := context.Background()
	recorder := newClientTestServer(t)

	basic := newTestOAuthClient(t, recorder, func(config *ClientConfig) {
		config.AuthStyle = AuthStyleBasic
	})
	if _, err := basic.ClientCredentials(ctx); err != nil {
		t.Fatalf("basic client credentials: %v", err)
	}
	call := recorder.last(t)
	if !strings.HasPrefix(call.header.Get("Authorization"), "Basic ") {
		t.Fatalf("basic authorization header = %q", call.header.Get("Authorization"))
	}
	if call.form.Get("client_secret") != "" {
		t.Fatalf("basic leaked secret into form: %v", call.form)
	}

	post := newTestOAuthClient(t, recorder, func(config *ClientConfig) {
		config.AuthStyle = AuthStylePost
	})
	if _, err := post.ClientCredentials(ctx); err != nil {
		t.Fatalf("post client credentials: %v", err)
	}
	call = recorder.last(t)
	if call.header.Get("Authorization") != "" {
		t.Fatalf("post authorization header = %q", call.header.Get("Authorization"))
	}
	if call.form.Get("client_id") != "web" || call.form.Get("client_secret") != "s3cret" {
		t.Fatalf("post form = %v", call.form)
	}

	public := newTestOAuthClient(t, recorder, func(config *ClientConfig) {
		config.ClientSecret = ""
	})
	if _, err := public.DeviceAuthorization(ctx); err != nil {
		t.Fatalf("public device authorization: %v", err)
	}
	call = recorder.last(t)
	if call.header.Get("Authorization") != "" || call.form.Get("client_id") != "web" {
		t.Fatalf("public auth = header %q form %v", call.header.Get("Authorization"), call.form)
	}

	// Basic without a secret falls back to a form client_id. | 无密钥的 Basic 退化为表单 client_id。
	basicPublic := newTestOAuthClient(t, recorder, func(config *ClientConfig) {
		config.ClientSecret = ""
		config.AuthStyle = AuthStyleBasic
	})
	if _, err := basicPublic.ClientCredentials(ctx); err != nil {
		t.Fatalf("basic public: %v", err)
	}
	call = recorder.last(t)
	if call.header.Get("Authorization") != "" || call.form.Get("client_id") != "web" {
		t.Fatalf("basic public auth = header %q form %v", call.header.Get("Authorization"), call.form)
	}
}

func TestClientDeviceAndPAR(t *testing.T) {
	ctx := context.Background()
	recorder := newClientTestServer(t)
	client := newTestOAuthClient(t, recorder, func(config *ClientConfig) {
		config.Scopes = []string{"openid"}
	})

	device, err := client.DeviceAuthorization(ctx)
	if err != nil {
		t.Fatalf("device authorization: %v", err)
	}
	if device.DeviceCode != "dc-1" || device.UserCode != "ABCD" || device.VerificationURI == "" ||
		device.VerificationURIComplete == "" || device.ExpiresIn != 600 || device.Interval != 5 {
		t.Fatalf("device response = %+v", device)
	}
	if form := recorder.last(t).form; form.Get("scope") != "openid" || form.Get("client_id") != "web" {
		t.Fatalf("device form = %v", form)
	}
	if _, err := client.DeviceAuthorization(ctx, "api:read"); err != nil {
		t.Fatalf("device authorization with scopes: %v", err)
	}
	if form := recorder.last(t).form; form.Get("scope") != "api:read" {
		t.Fatalf("device scopes = %v", form)
	}

	pushed, err := client.PAR(ctx, url.Values{"state": {"s1"}})
	if err != nil {
		t.Fatalf("par: %v", err)
	}
	if pushed.RequestURI != PARRequestURIPrefix+"par-1" || pushed.ExpiresIn != 60 {
		t.Fatalf("par response = %+v", pushed)
	}
	form := recorder.last(t).form
	if form.Get("state") != "s1" || form.Get("client_id") != "web" ||
		form.Get("response_type") != ResponseCode ||
		form.Get("redirect_uri") != "https://rp.example/callback" ||
		form.Get("scope") != "openid" {
		t.Fatalf("par form = %v", form)
	}
	// Explicit PAR parameters win over defaults. | 显式 PAR 参数优先于默认值。
	if _, err := client.PAR(ctx, url.Values{
		"response_type": {ResponseIDToken},
		"redirect_uri":  {"https://rp.example/other"},
		"scope":         {"api:read"},
	}); err != nil {
		t.Fatalf("par with overrides: %v", err)
	}
	form = recorder.last(t).form
	if form.Get("response_type") != ResponseIDToken || form.Get("redirect_uri") != "https://rp.example/other" || form.Get("scope") != "api:read" {
		t.Fatalf("par overrides = %v", form)
	}
}

func TestClientIntrospectionResponse(t *testing.T) {
	recorder := newClientTestServer(t)
	client := newTestOAuthClient(t, recorder, nil)
	introspection, err := client.Introspect(context.Background(), "token-1", "access_token")
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	if !introspection.Active || introspection.ClientID != "web" || introspection.Username != "alice" ||
		introspection.TokenType != TokenTypeBearer || introspection.Sub != "user-1" ||
		introspection.JTI != "jti-1" || introspection.Exp != 2000000000 || introspection.Iat != 1900000000 ||
		introspection.Nbf != 1900000000 {
		t.Fatalf("introspection = %+v", introspection)
	}
	if introspection.Raw["active"] != true {
		t.Fatalf("raw introspection = %v", introspection.Raw)
	}
	if introspection.CNF["jkt"] != "thumb" {
		t.Fatalf("cnf = %v", introspection.CNF)
	}
	if form := recorder.last(t).form; form.Get("token_type_hint") != "access_token" {
		t.Fatalf("introspect form = %v", form)
	}
}

// dpoPSignerStub implements DPoPSigner for client tests. | dpoPSignerStub 为客户端测试实现 DPoPSigner。
type dpoPSignerStub struct {
	proof string
	err   error
}

func (s dpoPSignerStub) SignDPoP(string, string, string) (string, error) { return s.proof, s.err }
func (s dpoPSignerStub) Thumbprint() (string, error)                     { return "thumb", nil }

func TestClientDPoP(t *testing.T) {
	recorder := newClientTestServer(t)
	client := newTestOAuthClient(t, recorder, func(config *ClientConfig) {
		config.DPoPKey = dpoPSignerStub{proof: "proof-1"}
	})
	if _, err := client.ClientCredentials(context.Background()); err != nil {
		t.Fatalf("dpop request: %v", err)
	}
	if proof := recorder.last(t).header.Get("DPoP"); proof != "proof-1" {
		t.Fatalf("dpop header = %q", proof)
	}

	failing := newTestOAuthClient(t, recorder, func(config *ClientConfig) {
		config.DPoPKey = dpoPSignerStub{err: errors.New("sign failed")}
	})
	if _, err := failing.ClientCredentials(context.Background()); !errors.Is(err, ErrInvalidDPoPProof) {
		t.Fatalf("dpop signer error = %v", err)
	}
}

// failingTransport always fails the HTTP round trip. | failingTransport 总是使 HTTP 往返失败。
type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("network down")
}

func TestClientTransportError(t *testing.T) {
	recorder := newClientTestServer(t)
	client := newTestOAuthClient(t, recorder, func(config *ClientConfig) {
		config.HTTPClient = &http.Client{Transport: failingTransport{}}
	})
	if _, err := client.ClientCredentials(context.Background()); !errors.Is(err, ErrServerError) {
		t.Fatalf("transport error = %v", err)
	}
}

func TestParseOAuthError(t *testing.T) {
	err := parseOAuthError(http.StatusBadRequest, []byte(`{"error":"invalid_grant","error_description":"bad","error_uri":"https://e"}`))
	var oauthErr *Error
	if !errors.As(err, &oauthErr) || oauthErr.Code != ErrorInvalidGrant || oauthErr.Status != http.StatusBadRequest || oauthErr.URI != "https://e" {
		t.Fatalf("parsed error = %v", err)
	}
	if err := parseOAuthError(http.StatusBadGateway, []byte(`<html>`)); !errors.Is(err, ErrServerError) {
		t.Fatalf("non-json error = %v", err)
	}
	if err := parseOAuthError(http.StatusBadGateway, []byte(`{"error":""}`)); !errors.Is(err, ErrServerError) {
		t.Fatalf("empty error = %v", err)
	}
}

func TestTokenValidityAndItoa(t *testing.T) {
	var nilToken *Token
	if nilToken.Valid() {
		t.Fatal("nil token is valid")
	}
	token := &Token{}
	if !token.Valid() {
		t.Fatal("zero-expiry token is invalid")
	}
	token.SetExpiry(time.Now().Add(-time.Hour))
	if !token.Expiry.IsZero() {
		t.Fatal("SetExpiry set an expiry without expires_in")
	}
	token.ExpiresIn = 60
	token.SetExpiry(time.Now())
	if !token.Valid() {
		t.Fatal("fresh token is invalid")
	}
	token.SetExpiry(time.Now().Add(-2 * time.Minute))
	if token.Valid() {
		t.Fatal("expired token is valid")
	}
	cases := map[int]string{0: "0", 7: "7", -7: "-7", 123456789: "123456789", -123456789: "-123456789"}
	for input, want := range cases {
		if got := itoa(input); got != want {
			t.Errorf("itoa(%d) = %q want %q", input, got, want)
		}
	}
}

func TestClientConfigSnapshot(t *testing.T) {
	recorder := newClientTestServer(t)
	client := newTestOAuthClient(t, recorder, nil)
	config := client.Config()
	if config.ClientID != "web" || config.RedirectURL != "https://rp.example/callback" ||
		len(config.Scopes) != 2 || config.Endpoint.TokenURL == "" {
		t.Fatalf("config = %+v", config)
	}
}

// Ensure the fake server helper satisfies the unused-import linter for json when tests move. | 确保
// 测试调整后仍使用 json 包。
var _ = json.Marshal
