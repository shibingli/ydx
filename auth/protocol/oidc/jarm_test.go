package oidc

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth/protocol/oauth2"
	"github.com/shibingli/ydx/auth/token/jose"
	"github.com/shibingli/ydx/json"
)

// newJARMTestKey returns a fresh ES256 signing key and its key set. | newJARMTestKey 返回新的 ES256
// 签名密钥及其密钥集。
func newJARMTestKey(t *testing.T) (*jose.Key, *jose.KeySet) {
	t.Helper()
	key, err := jose.GenerateKey("ES256", 0)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	key.Kid = "jarm-test"
	key.Use = "sig"
	set := &jose.KeySet{}
	if err := set.Add(key); err != nil {
		t.Fatalf("add key: %v", err)
	}
	return key, set
}

// newTestRelyingParty performs discovery against fixture. | newTestRelyingParty 对 fixture 执行发现。
func newTestRelyingParty(t *testing.T, fixture *oidcFixture) *RelyingParty {
	t.Helper()
	rp, err := NewRelyingParty(context.Background(), RelyingPartyConfig{
		Issuer:       fixture.server.URL,
		ClientID:     "web",
		ClientSecret: "rp-secret",
		RedirectURL:  "https://rp.example/callback",
		Scopes:       []string{ScopeOpenID, ScopeProfile, ScopeEmail},
	})
	if err != nil {
		t.Fatalf("relying party: %v", err)
	}
	return rp
}

// oidcAuthorizeRequest performs a JARM authorization request and returns the redirect. |
// oidcAuthorizeRequest 执行 JARM 授权请求并返回重定向。
func oidcAuthorizeRequest(t *testing.T, fixture *oidcFixture, values url.Values) *http.Response {
	t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(fixture.server.URL + "/authorize?" + values.Encode())
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	return resp
}

// codeQuery returns a PKCE authorization-code request for the fixture client. | codeQuery 返回 fixture
// 客户端的 PKCE 授权码请求。
func codeQuery(t *testing.T, responseMode string) (url.Values, string) {
	t.Helper()
	verifier, err := oauth2.GenerateCodeVerifier()
	if err != nil {
		t.Fatal(err)
	}
	return url.Values{
		"response_type":         {oauth2.ResponseCode},
		"client_id":             {"web"},
		"redirect_uri":          {"https://rp.example/callback"},
		"scope":                 {ScopeOpenID + " " + ScopeProfile},
		"state":                 {"state-1"},
		"code_challenge":        {oauth2.CodeChallengeS256(verifier)},
		"code_challenge_method": {oauth2.PKCES256},
		"response_mode":         {responseMode},
	}, verifier
}

// verifyJARMWithProvider verifies a JARM JWT against the provider key set. | verifyJARMWithProvider
// 使用提供方密钥集校验 JARM JWT。
func verifyJARMWithProvider(t *testing.T, fixture *oidcFixture, raw string) map[string]any {
	t.Helper()
	verified, err := jose.VerifyContext(context.Background(), raw, fixture.provider.keys.Resolver(), jose.VerifyOptions{
		ValidAlgs: []string{"RS256"},
		Now:       time.Now,
	})
	if err != nil {
		t.Fatalf("verify JARM: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(verified.Claims, &claims); err != nil {
		t.Fatalf("decode JARM: %v", err)
	}
	return claims
}

func TestProviderJARMQueryResponseAndRelyingParty(t *testing.T) {
	fixture := newOIDCFixture(t, false)
	values, verifier := codeQuery(t, oauth2.ResponseModeQueryJWT)
	resp := oidcAuthorizeRequest(t, fixture, values)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d body=%s", resp.StatusCode, body)
	}
	location, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	outer := location.Query()
	if len(outer) != 1 || outer.Get("response") == "" || location.Fragment != "" {
		t.Fatalf("outer response = %v fragment=%q", outer, location.Fragment)
	}
	claims := verifyJARMWithProvider(t, fixture, outer.Get("response"))
	if claims["iss"] != fixture.server.URL || claims["aud"] != "web" {
		t.Fatalf("iss/aud = %v/%v", claims["iss"], claims["aud"])
	}
	if claims["state"] != "state-1" || claims["code"] == "" {
		t.Fatalf("claims = %v", claims)
	}
	if _, ok := claims["exp"]; !ok {
		t.Fatal("JARM has no exp")
	}

	rp := newTestRelyingParty(t, fixture)
	parsed, err := rp.ParseAuthorizationResponse(context.Background(), outer)
	if err != nil {
		t.Fatalf("parse authorization response: %v", err)
	}
	if !parsed.Signed || parsed.JWT == "" || parsed.Param("code") != claims["code"] ||
		parsed.Param("state") != "state-1" || parsed.Param("iss") != fixture.server.URL {
		t.Fatalf("parsed = %+v", parsed)
	}
	token, err := rp.Exchange(context.Background(), parsed.Param("code"), "", verifier)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if token.AccessToken == "" || token.IDToken == nil {
		t.Fatalf("token = %+v", token)
	}
}

func TestProviderJARMSignedError(t *testing.T) {
	fixture := newOIDCFixture(t, false)
	values, _ := codeQuery(t, oauth2.ResponseModeFormPostJWT)
	values.Del("code_challenge")
	values.Del("code_challenge_method")
	resp := oidcAuthorizeRequest(t, fixture, values)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if resp.StatusCode != http.StatusOK || strings.Count(text, "<input") != 1 {
		t.Fatalf("status = %d body=%s", resp.StatusCode, text)
	}
	const marker = `name="response" value="`
	index := strings.Index(text, marker)
	if index < 0 {
		t.Fatalf("no response input: %s", text)
	}
	rest := text[index+len(marker):]
	end := strings.IndexByte(rest, '"')
	if end < 0 {
		t.Fatalf("unterminated response input: %s", text)
	}
	raw := rest[:end]
	claims := verifyJARMWithProvider(t, fixture, raw)
	if claims["error"] != oauth2.ErrorInvalidRequest || claims["state"] != "state-1" {
		t.Fatalf("claims = %v", claims)
	}
	rp := newTestRelyingParty(t, fixture)
	parsed, err := rp.ParseAuthorizationResponse(context.Background(), url.Values{"response": {raw}})
	if err != nil {
		t.Fatalf("parse error response: %v", err)
	}
	if parsed.Param("error") != oauth2.ErrorInvalidRequest || parsed.Param("state") != "state-1" {
		t.Fatalf("parsed = %+v", parsed)
	}
}

// signProviderJARM signs claims with the fixture provider key. | signProviderJARM 用 fixture 提供方
// 密钥签署声明。
func signProviderJARM(t *testing.T, fixture *oidcFixture, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := jose.Sign(payload, fixture.provider.signingKey, jose.SignOptions{
		Alg: "RS256",
		Kid: fixture.provider.signingKey.Kid,
		Typ: "JWT",
	})
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// providerJARMClaims returns a valid JARM claim set. | providerJARMClaims 返回合法 JARM 声明集。
func providerJARMClaims(fixture *oidcFixture) map[string]any {
	now := time.Now().UTC()
	return map[string]any{
		"iss":   fixture.server.URL,
		"aud":   "web",
		"exp":   now.Add(5 * time.Minute).Unix(),
		"iat":   now.Unix(),
		"code":  "code-1",
		"state": "state-1",
	}
}

func TestParseAuthorizationResponseValidation(t *testing.T) {
	fixture := newOIDCFixture(t, false)
	rp := newTestRelyingParty(t, fixture)
	ctx := context.Background()

	// Unsigned responses are copied and never marked signed. | 无签名响应被复制且不会标记为已签名。
	unsigned := url.Values{"code": {"code-1"}, "state": {"state-1"}}
	parsed, err := rp.ParseAuthorizationResponse(ctx, unsigned)
	if err != nil || parsed.Signed || parsed.Param("code") != "code-1" {
		t.Fatalf("unsigned = %+v err=%v", parsed, err)
	}
	unsigned.Set("code", "changed")
	if parsed.Param("code") != "code-1" {
		t.Fatal("unsigned response was not copied")
	}
	if _, err := rp.ParseAuthorizationResponse(ctx, nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil response = %v", err)
	}
	var nilResponse *AuthorizationResponse
	if nilResponse.Param("code") != "" {
		t.Fatal("nil response Param returned a value")
	}

	valid := signProviderJARM(t, fixture, providerJARMClaims(fixture))
	parsed, err = rp.ParseAuthorizationResponse(ctx, url.Values{"response": {valid}})
	if err != nil || !parsed.Signed || parsed.Param("state") != "state-1" {
		t.Fatalf("signed = %+v err=%v", parsed, err)
	}
	if _, err := rp.ParseAuthorizationResponse(ctx, url.Values{"response": {valid}, "state": {"outer"}}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("outer parameter = %v", err)
	}
	if _, err := rp.ParseAuthorizationResponse(ctx, url.Values{"response": {valid, valid}}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("duplicate response = %v", err)
	}

	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "wrong issuer", mutate: func(claims map[string]any) { claims["iss"] = "https://other.example" }},
		{name: "wrong audience", mutate: func(claims map[string]any) { claims["aud"] = "other" }},
		{name: "expired", mutate: func(claims map[string]any) { claims["exp"] = time.Now().Add(-time.Minute).Unix() }},
		{name: "missing exp", mutate: func(claims map[string]any) { delete(claims, "exp") }},
		{name: "unsupported claim type", mutate: func(claims map[string]any) { claims["bad"] = map[string]any{"nested": true} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := providerJARMClaims(fixture)
			tc.mutate(claims)
			raw := signProviderJARM(t, fixture, claims)
			if _, err := rp.ParseAuthorizationResponse(ctx, url.Values{"response": {raw}}); !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("err = %v", err)
			}
		})
	}

	tampered := valid[:len(valid)-2] + "aa"
	if _, err := rp.ParseAuthorizationResponse(ctx, url.Values{"response": {tampered}}); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("tampered = %v", err)
	}
}

func TestAuthorizationResponseValueShapes(t *testing.T) {
	cases := []struct {
		name  string
		value any
		want  string
		ok    bool
	}{
		{name: "string", value: "value", want: "value", ok: true},
		{name: "float", value: float64(3600), want: "3600", ok: true},
		{name: "number", value: json.Number("42"), want: "42", ok: true},
		{name: "bool", value: true, want: "true", ok: true},
		{name: "array", value: []any{"a", float64(1), true}, want: "a 1 true", ok: true},
		{name: "array with object", value: []any{map[string]any{}}, ok: false},
		{name: "object", value: map[string]any{}, ok: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := authorizationResponseValue(tc.value)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("value = %q ok=%v want %q/%v", got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestSignAuthorizationResponseDirect(t *testing.T) {
	key, set := newJARMTestKey(t)
	fixed := time.Unix(1_700_000_000, 0).UTC()
	provider := &Provider{
		config:     ProviderConfig{Issuer: "https://op.example"},
		keys:       set,
		signingKey: key,
		signingAlg: "ES256",
		now:        func() time.Time { return fixed },
	}
	ctx := context.Background()
	if _, err := provider.SignAuthorizationResponse(ctx, "https://op.example", nil, url.Values{"code": {"c"}}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil client = %v", err)
	}
	if _, err := provider.SignAuthorizationResponse(ctx, "https://op.example", &oauth2.Client{ID: "web", AuthorizationSignedResponseAlg: "none"}, nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("alg none = %v", err)
	}
	if _, err := provider.SignAuthorizationResponse(ctx, "https://op.example", &oauth2.Client{ID: "web", AuthorizationSignedResponseAlg: "RS256"}, nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("missing RS256 key = %v", err)
	}
	raw, err := provider.SignAuthorizationResponse(ctx, "", &oauth2.Client{ID: "web"}, url.Values{
		"code":       {"code-1"},
		"expires_in": {"60"},
		"state":      {"state-1"},
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	verified, err := jose.VerifyContext(ctx, raw, set.Resolver(), jose.VerifyOptions{ValidAlgs: []string{"ES256"}})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(verified.Claims, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["iss"] != "https://op.example" || claims["aud"] != "web" || claims["code"] != "code-1" ||
		claims["state"] != "state-1" {
		t.Fatalf("claims = %v", claims)
	}
	if claims["expires_in"] != float64(60) {
		t.Fatalf("expires_in = %v", claims["expires_in"])
	}
	if claims["exp"] != float64(fixed.Add(jarmResponseTTL).Unix()) || claims["iat"] != float64(fixed.Unix()) {
		t.Fatalf("times = %v/%v", claims["exp"], claims["iat"])
	}

	invalidExpiry := url.Values{"expires_in": {"soon"}}
	raw, err = provider.SignAuthorizationResponse(ctx, "", &oauth2.Client{ID: "web"}, invalidExpiry)
	if err != nil {
		t.Fatalf("invalid expires_in: %v", err)
	}
	verified, err = jose.VerifyContext(ctx, raw, set.Resolver(), jose.VerifyOptions{ValidAlgs: []string{"ES256"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(verified.Claims, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["expires_in"] != "soon" {
		t.Fatalf("expires_in = %v", claims["expires_in"])
	}

	noAlg := &Provider{signingKey: key, keys: set, signingAlg: "none", now: func() time.Time { return fixed }}
	algs := noAlg.AuthorizationSigningAlgValuesSupported()
	if len(algs) != 1 || algs[0] != "ES256" {
		t.Fatalf("JARM algorithms = %v", algs)
	}
}
