package wsfed

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
	"github.com/shibingli/ydx/auth/protocol/saml"
	"github.com/shibingli/ydx/router"
)

// signedSTS returns an STS that signs assertions with a fake signer. | signedSTS 返回使用伪签名器签名
// 断言的 STS。
func signedSTS(t *testing.T, issuerRealm string) *SecurityTokenService {
	t.Helper()
	return newTestSTS(t, &stubAuthenticator{principal: testPrincipal()}, func(config *STSConfig) {
		config.Signer = &fakeSigner{}
	})
}

// responseRequest builds a POST reply for a collection. | responseRequest 为集合构建 POST 回复。
func responseRequest(t *testing.T, collection *RequestSecurityTokenResponseCollection, wctx string) *http.Request {
	t.Helper()
	return postWResult(t, testReply, marshalCollection(t, collection), wctx)
}

// TestRPParseSignInResponse validates a signed response end to end. | TestRPParseSignInResponse 端到端
// 校验已签名响应。
func TestRPParseSignInResponse(t *testing.T) {
	sts := signedSTS(t, testRealm)
	collection, _ := issueTestToken(t, sts, testPrincipal(), testRealm, testReply, "ctx-1", testNow, testNow.Add(5*time.Minute))
	rp := newTestRP(t, func(config *RelyingPartyConfig) {
		config.SignatureVerifier = testVerifier()
	})
	result, err := rp.ParseSignInResponse(responseRequest(t, collection, "ctx-1"))
	if err != nil {
		t.Fatalf("ParseSignInResponse: %v", err)
	}
	if result.Principal == nil || result.Principal.Subject != "user-1" || result.Principal.Username != "alice" {
		t.Fatalf("unexpected principal: %+v", result.Principal)
	}
	if result.Principal.Email != "alice@example.com" || result.Principal.DisplayName != "Alice" {
		t.Fatalf("unexpected principal attributes: %+v", result.Principal)
	}
	if len(result.Principal.Groups) != 2 || result.Principal.Groups[0] != "admins" {
		t.Fatalf("unexpected groups: %+v", result.Principal.Groups)
	}
	if result.Attributes["email"][0] != "alice@example.com" {
		t.Fatalf("unexpected attributes: %+v", result.Attributes)
	}
	if result.Wctx != "ctx-1" || result.TokenType != TokenTypeSAML20 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if !result.ExpiresAt.Equal(testNow.Add(5 * time.Minute)) {
		t.Fatalf("expires at %s", result.ExpiresAt)
	}
	if result.Assertion == nil || result.Assertion.ID == "" {
		t.Fatalf("assertion missing: %+v", result.Assertion)
	}
}

// TestRPRejectsUnsigned rejects an unsigned assertion when verification is configured. |
// TestRPRejectsUnsigned 在配置校验时拒绝未签名断言。
func TestRPRejectsUnsigned(t *testing.T) {
	sts := newTestSTS(t, &stubAuthenticator{principal: testPrincipal()}, nil)
	collection, _ := issueTestToken(t, sts, testPrincipal(), testRealm, testReply, "ctx", testNow, testNow.Add(5*time.Minute))
	rp := newTestRP(t, func(config *RelyingPartyConfig) {
		config.SignatureVerifier = testVerifier()
	})
	_, err := rp.ParseSignInResponse(responseRequest(t, collection, "ctx"))
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("err = %v, want ErrInvalidSignature", err)
	}
}

// TestRPRejectsBadSignature rejects a failing signature verification. | TestRPRejectsBadSignature
// 拒绝签名校验失败。
func TestRPRejectsBadSignature(t *testing.T) {
	sts := signedSTS(t, testRealm)
	collection, _ := issueTestToken(t, sts, testPrincipal(), testRealm, testReply, "ctx", testNow, testNow.Add(5*time.Minute))
	rp := newTestRP(t, func(config *RelyingPartyConfig) {
		config.SignatureVerifier = saml.SignatureVerifierFunc(func(_ context.Context, _ []byte, elementID string) error {
			if elementID == "" {
				t.Errorf("missing element ID")
			}
			return errors.New("verification failed")
		})
	})
	_, err := rp.ParseSignInResponse(responseRequest(t, collection, "ctx"))
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("err = %v, want ErrInvalidSignature", err)
	}
}

// TestRPRejectsWrongAudience rejects an assertion for another realm. | TestRPRejectsWrongAudience
// 拒绝其他领域的断言。
func TestRPRejectsWrongAudience(t *testing.T) {
	sts := newTestSTS(t, &stubAuthenticator{principal: testPrincipal()}, nil)
	collection, _ := issueTestToken(t, sts, testPrincipal(), "https://other.example.com/", testReply, "ctx", testNow, testNow.Add(5*time.Minute))
	rp := newTestRP(t, nil)
	_, err := rp.ParseSignInResponse(responseRequest(t, collection, "ctx"))
	if !errors.Is(err, ErrInvalidAudience) {
		t.Fatalf("err = %v, want ErrInvalidAudience", err)
	}
}

// TestRPRejectsWrongRecipient rejects a subject confirmation for another reply URL. |
// TestRPRejectsWrongRecipient 拒绝其他回复 URL 的主体确认。
func TestRPRejectsWrongRecipient(t *testing.T) {
	sts := newTestSTS(t, &stubAuthenticator{principal: testPrincipal()}, nil)
	collection, _ := issueTestToken(t, sts, testPrincipal(), testRealm, "https://rp.example.com/other", "ctx", testNow, testNow.Add(5*time.Minute))
	rp := newTestRP(t, nil)
	_, err := rp.ParseSignInResponse(responseRequest(t, collection, "ctx"))
	if !errors.Is(err, ErrInvalidRecipient) {
		t.Fatalf("err = %v, want ErrInvalidRecipient", err)
	}
}

// TestRPRejectsExpired rejects an expired assertion. | TestRPRejectsExpired 拒绝过期断言。
func TestRPRejectsExpired(t *testing.T) {
	sts := newTestSTS(t, &stubAuthenticator{principal: testPrincipal()}, nil)
	expiredAt := testNow.Add(-5 * time.Minute)
	collection, _ := issueTestToken(t, sts, testPrincipal(), testRealm, testReply, "ctx", expiredAt.Add(-5*time.Minute), expiredAt)
	rp := newTestRP(t, nil)
	_, err := rp.ParseSignInResponse(responseRequest(t, collection, "ctx"))
	if !errors.Is(err, ErrResponseExpired) {
		t.Fatalf("err = %v, want ErrResponseExpired", err)
	}
}

// TestRPRejectsNotYetValid rejects an assertion from the future. | TestRPRejectsNotYetValid 拒绝来自
// 未来的断言。
func TestRPRejectsNotYetValid(t *testing.T) {
	sts := newTestSTS(t, &stubAuthenticator{principal: testPrincipal()}, nil)
	future := testNow.Add(10 * time.Minute)
	collection, _ := issueTestToken(t, sts, testPrincipal(), testRealm, testReply, "ctx", future, future.Add(5*time.Minute))
	rp := newTestRP(t, nil)
	_, err := rp.ParseSignInResponse(responseRequest(t, collection, "ctx"))
	if !errors.Is(err, ErrResponseNotYetValid) {
		t.Fatalf("err = %v, want ErrResponseNotYetValid", err)
	}
}

// TestRPRejectsReplay rejects a reused assertion. | TestRPRejectsReplay 拒绝重复使用的断言。
func TestRPRejectsReplay(t *testing.T) {
	sts := newTestSTS(t, &stubAuthenticator{principal: testPrincipal()}, nil)
	collection, _ := issueTestToken(t, sts, testPrincipal(), testRealm, testReply, "ctx", testNow, testNow.Add(5*time.Minute))
	wresult := marshalCollection(t, collection)
	rp := newTestRP(t, nil)
	if _, err := rp.ParseSignInResponse(postWResult(t, testReply, wresult, "ctx")); err != nil {
		t.Fatalf("first response: %v", err)
	}
	_, err := rp.ParseSignInResponse(postWResult(t, testReply, wresult, "ctx"))
	if !errors.Is(err, ErrReplay) {
		t.Fatalf("err = %v, want ErrReplay", err)
	}
}

// TestRPRejectsUnsolicited rejects a response without an outstanding request. |
// TestRPRejectsUnsolicited 拒绝没有未完成请求的响应。
func TestRPRejectsUnsolicited(t *testing.T) {
	sts := newTestSTS(t, &stubAuthenticator{principal: testPrincipal()}, nil)
	collection, _ := issueTestToken(t, sts, testPrincipal(), testRealm, testReply, "ctx", testNow, testNow.Add(5*time.Minute))
	rp := newTestRP(t, func(config *RelyingPartyConfig) {
		config.AllowUnsolicited = false
	})
	_, err := rp.ParseSignInResponse(responseRequest(t, collection, "ctx"))
	if !errors.Is(err, ErrUnsolicited) {
		t.Fatalf("err = %v, want ErrUnsolicited", err)
	}
}

// TestRPRequestCorrelation accepts a response matching SignInURL state. | TestRPRequestCorrelation
// 接受匹配 SignInURL 状态的响应。
func TestRPRequestCorrelation(t *testing.T) {
	requests := NewMemoryRequestStore()
	rp := newTestRP(t, func(config *RelyingPartyConfig) {
		config.AllowUnsolicited = false
		config.RequestStore = requests
		config.Now = func() time.Time { return time.Now().UTC() }
	})
	location, err := rp.SignInURL("")
	if err != nil {
		t.Fatalf("SignInURL: %v", err)
	}
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse sign-in URL: %v", err)
	}
	wctx := parsed.Query().Get(ParamWctx)
	if wctx == "" {
		t.Fatalf("SignInURL did not generate wctx: %s", location)
	}
	if parsed.Query().Get(ParamWtrealm) != testRealm || parsed.Query().Get(ParamWreply) != testReply {
		t.Fatalf("unexpected sign-in URL: %s", location)
	}
	if requests.Len() != 1 {
		t.Fatalf("pending requests = %d", requests.Len())
	}
	sts := newTestSTS(t, &stubAuthenticator{principal: testPrincipal()}, nil)
	now := time.Now().UTC()
	collection, _ := issueTestToken(t, sts, testPrincipal(), testRealm, testReply, wctx, now, now.Add(5*time.Minute))
	result, err := rp.ParseSignInResponse(responseRequest(t, collection, wctx))
	if err != nil {
		t.Fatalf("ParseSignInResponse: %v", err)
	}
	if result.Wctx != wctx {
		t.Fatalf("wctx = %q, want %q", result.Wctx, wctx)
	}
	if requests.Len() != 0 {
		t.Fatalf("pending requests after reply = %d", requests.Len())
	}
}

// TestRPRejectsWctxMismatch rejects a mismatched wctx form value. | TestRPRejectsWctxMismatch 拒绝
// 不匹配的 wctx 表单值。
func TestRPRejectsWctxMismatch(t *testing.T) {
	sts := newTestSTS(t, &stubAuthenticator{principal: testPrincipal()}, nil)
	collection, _ := issueTestToken(t, sts, testPrincipal(), testRealm, testReply, "ctx-a", testNow, testNow.Add(5*time.Minute))
	collection.Responses[0].Wctx = "ctx-a"
	rp := newTestRP(t, nil)
	_, err := rp.ParseSignInResponse(responseRequest(t, collection, "ctx-b"))
	if !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("err = %v, want ErrInvalidResponse", err)
	}
}

// TestRPSAML11Token validates a SAML 1.1 token. | TestRPSAML11Token 校验 SAML 1.1 令牌。
func TestRPSAML11Token(t *testing.T) {
	sts := newTestSTS(t, &stubAuthenticator{principal: testPrincipal()}, func(config *STSConfig) {
		config.TokenType = TokenTypeSAML11
	})
	request := &SignInRequest{WA: ActionSignIn, Wtrealm: testRealm, Wreply: testReply, Wctx: "ctx"}
	tokenID, tokenXML, _, _, _, _, err := sts.issueToken(context.Background(), testPrincipal(), request, testReply, testNow, testNow.Add(5*time.Minute))
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	collection := sts.tokenResponse(request, testReply, tokenID, tokenXML, testNow, testNow.Add(5*time.Minute))
	rp := newTestRP(t, nil)
	result, err := rp.ParseSignInResponse(responseRequest(t, collection, "ctx"))
	if err != nil {
		t.Fatalf("ParseSignInResponse: %v", err)
	}
	if result.TokenType != TokenTypeSAML11 || result.Principal.Subject != "user-1" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

// TestRPJWTResponse validates a JWT token through a verifier. | TestRPJWTResponse 通过校验器校验 JWT
// 令牌。
func TestRPJWTResponse(t *testing.T) {
	var sawToken, sawAudience string
	rp := newTestRP(t, func(config *RelyingPartyConfig) {
		config.TokenType = TokenTypeJWT
		config.JWTVerifier = JWTVerifierFunc(func(_ context.Context, token, audience string) (*auth.Principal, map[string][]string, time.Time, error) {
			sawToken = token
			sawAudience = audience
			return &auth.Principal{Subject: "user-1"}, map[string][]string{"scope": {"profile"}}, testNow.Add(time.Minute), nil
		})
	})
	collection := &RequestSecurityTokenResponseCollection{Responses: []RequestSecurityTokenResponse{{
		TokenType:              TokenTypeJWT,
		Wctx:                   "ctx",
		RequestedSecurityToken: &RequestedSecurityToken{InnerXML: "a.b.c"},
		Lifetime:               &Lifetime{Created: saml.FormatTime(testNow), Expires: saml.FormatTime(testNow.Add(time.Minute))},
		Status:                 &ResponseStatus{Code: StatusSuccess},
	}}}
	result, err := rp.ParseSignInResponse(responseRequest(t, collection, "ctx"))
	if err != nil {
		t.Fatalf("ParseSignInResponse: %v", err)
	}
	if sawToken != "a.b.c" || sawAudience != testRealm {
		t.Fatalf("verifier args = %q, %q", sawToken, sawAudience)
	}
	if result.TokenType != TokenTypeJWT || result.Principal.Subject != "user-1" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if result.Attributes["scope"][0] != "profile" {
		t.Fatalf("unexpected attributes: %+v", result.Attributes)
	}
	if !result.ExpiresAt.Equal(testNow.Add(time.Minute)) {
		t.Fatalf("expires at %s", result.ExpiresAt)
	}
	rpReject := newTestRP(t, func(config *RelyingPartyConfig) {
		config.TokenType = TokenTypeJWT
		config.JWTVerifier = JWTVerifierFunc(func(_ context.Context, _, _ string) (*auth.Principal, map[string][]string, time.Time, error) {
			return nil, nil, time.Time{}, errors.New("invalid JWT")
		})
	})
	if _, err := rpReject.ParseSignInResponse(responseRequest(t, collection, "ctx")); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("err = %v, want ErrInvalidResponse", err)
	}
}

// TestRPJWTRequiresExpiry rejects a JWT response without any expiry and accepts a lifetime
// fallback. | TestRPJWTRequiresExpiry 拒绝没有任何过期时间的 JWT 响应，并接受生命周期回退。
func TestRPJWTRequiresExpiry(t *testing.T) {
	collection := func(lifetime *Lifetime) *RequestSecurityTokenResponseCollection {
		return &RequestSecurityTokenResponseCollection{Responses: []RequestSecurityTokenResponse{{
			TokenType:              TokenTypeJWT,
			Wctx:                   "ctx",
			RequestedSecurityToken: &RequestedSecurityToken{InnerXML: "a.b.c"},
			Lifetime:               lifetime,
			Status:                 &ResponseStatus{Code: StatusSuccess},
		}}}
	}
	rp := newTestRP(t, func(config *RelyingPartyConfig) {
		config.TokenType = TokenTypeJWT
		config.JWTVerifier = JWTVerifierFunc(func(_ context.Context, _, _ string) (*auth.Principal, map[string][]string, time.Time, error) {
			return &auth.Principal{Subject: "user-1"}, nil, time.Time{}, nil
		})
	})
	if _, err := rp.ParseSignInResponse(responseRequest(t, collection(nil), "ctx")); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("expiry-less JWT error = %v, want ErrInvalidResponse", err)
	}
	lifetime := &Lifetime{Created: saml.FormatTime(testNow), Expires: saml.FormatTime(testNow.Add(time.Minute))}
	result, err := rp.ParseSignInResponse(responseRequest(t, collection(lifetime), "ctx"))
	if err != nil || !result.ExpiresAt.Equal(testNow.Add(time.Minute)) {
		t.Fatalf("JWT lifetime fallback = %+v, err = %v", result, err)
	}

	expired := newTestRP(t, func(config *RelyingPartyConfig) {
		config.TokenType = TokenTypeJWT
		config.JWTVerifier = JWTVerifierFunc(func(_ context.Context, _, _ string) (*auth.Principal, map[string][]string, time.Time, error) {
			return &auth.Principal{Subject: "user-1"}, nil, testNow.Add(-5 * time.Minute), nil
		})
	})
	if _, err := expired.ParseSignInResponse(responseRequest(t, collection(nil), "ctx")); !errors.Is(err, ErrResponseExpired) {
		t.Fatalf("expired JWT error = %v, want ErrResponseExpired", err)
	}
}

// TestRPConfigValidation rejects invalid configurations. | TestRPConfigValidation 拒绝非法配置。
func TestRPConfigValidation(t *testing.T) {
	cases := []RelyingPartyConfig{
		{},
		{Realm: testRealm},
		{Realm: testRealm, ReplyURL: "/relative"},
		{Realm: testRealm, ReplyURL: "ftp://rp.example.com/reply"},
		{Realm: testRealm, ReplyURL: testReply, IDPURL: "relative"},
		{Realm: testRealm, ReplyURL: testReply, TokenType: "urn:unknown"},
		{Realm: testRealm, ReplyURL: testReply, TokenType: TokenTypeJWT},
		{Realm: testRealm, ReplyURL: testReply, RequireSigned: true},
	}
	for index, config := range cases {
		if _, err := NewRelyingParty(config); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("case %d err = %v, want ErrInvalidConfig", index, err)
		}
	}
}

// TestRPSignOutURL builds a sign-out URL with fallback. | TestRPSignOutURL 构建带回退的登出 URL。
func TestRPSignOutURL(t *testing.T) {
	rp := newTestRP(t, func(config *RelyingPartyConfig) {
		config.SignOutURL = ""
	})
	location, err := rp.SignOutURL("ctx")
	if err != nil {
		t.Fatalf("SignOutURL: %v", err)
	}
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse sign-out URL: %v", err)
	}
	query := parsed.Query()
	if parsed.String() != location || query.Get(ParamWA) != ActionSignOut || query.Get(ParamWtrealm) != testRealm || query.Get(ParamWctx) != "ctx" {
		t.Fatalf("unexpected sign-out URL: %s", location)
	}
	if !strings.HasPrefix(location, testIssuer+"wsfed/signin?") {
		t.Fatalf("sign-out did not fall back to IDP URL: %s", location)
	}
}

// TestRPParseSignOutResponse validates sign-out results. | TestRPParseSignOutResponse 校验登出结果。
func TestRPParseSignOutResponse(t *testing.T) {
	rp := newTestRP(t, nil)
	success := NewSignOutCollection("ctx")
	if err := rp.ParseSignOutResponse(postWResult(t, testReply, marshalCollection(t, success), "ctx")); err != nil {
		t.Fatalf("success sign-out: %v", err)
	}
	if err := rp.ParseSignOutResponse(postWResult(t, testReply, "", "")); err != nil {
		t.Fatalf("empty sign-out: %v", err)
	}
	failure := `<Fault><faultcode>` + FaultCodeAccessDenied + `</faultcode><faultstring>denied</faultstring></Fault>`
	if err := rp.ParseSignOutResponse(postWResult(t, testReply, failure, "ctx")); !errors.Is(err, ErrStatusFailure) {
		t.Fatalf("failure sign-out err = %v, want ErrStatusFailure", err)
	}
}

// TestRPRouterMount mounts the reply endpoint on a YD router. | TestRPRouterMount 在 YD 路由上挂载
// 回复端点。
func TestRPRouterMount(t *testing.T) {
	sts := newTestSTS(t, &stubAuthenticator{principal: testPrincipal()}, nil)
	collection, _ := issueTestToken(t, sts, testPrincipal(), testRealm, testReply, "ctx", testNow, testNow.Add(5*time.Minute))
	wresult := marshalCollection(t, collection)
	rp := newTestRP(t, nil)
	r := router.New()
	rp.Register(r, "/rp")
	recorder := httptest.NewRecorder()
	r.ServeHTTP(recorder, postWResult(t, "/rp/wsfed/reply", wresult, "ctx"))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"subject":"user-1"`) {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
}

// TestRPHTTPHandlerMount mounts the reply endpoint with net/http. | TestRPHTTPHandlerMount 使用
// net/http 挂载回复端点。
func TestRPHTTPHandlerMount(t *testing.T) {
	sts := newTestSTS(t, &stubAuthenticator{principal: testPrincipal()}, nil)
	collection, _ := issueTestToken(t, sts, testPrincipal(), testRealm, testReply, "ctx", testNow, testNow.Add(5*time.Minute))
	wresult := marshalCollection(t, collection)
	success := make(chan *SignInResult, 1)
	rp := newTestRP(t, func(config *RelyingPartyConfig) {
		config.SuccessHandler = func(w http.ResponseWriter, _ *http.Request, result *SignInResult) {
			success <- result
			w.WriteHeader(http.StatusNoContent)
		}
	})
	server := httptest.NewServer(rp.HTTPHandler("/rp"))
	defer server.Close()
	response, err := http.PostForm(server.URL+"/rp/wsfed/reply", url.Values{ParamWresult: {wresult}, ParamWctx: {"ctx"}})
	if err != nil {
		t.Fatalf("POST reply: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	if _, err := io.ReadAll(response.Body); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d", response.StatusCode)
	}
	select {
	case result := <-success:
		if result.Principal.Subject != "user-1" {
			t.Fatalf("unexpected result: %+v", result)
		}
	default:
		t.Fatalf("success handler was not called")
	}
}

// TestRPReplyHandlerErrors renders errors. | TestRPReplyHandlerErrors 渲染错误。
func TestRPReplyHandlerErrors(t *testing.T) {
	rp := newTestRP(t, nil)
	recorder := httptest.NewRecorder()
	rp.ReplyHandler(recorder, postWResult(t, testReply, "<invalid", ""))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", recorder.Code)
	}
	method := httptest.NewRecorder()
	rp.ReplyHandler(method, httptest.NewRequest(http.MethodDelete, testReply, nil))
	if method.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d", method.Code)
	}
	custom := make(chan error, 1)
	rpCustom := newTestRP(t, func(config *RelyingPartyConfig) {
		config.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
			custom <- err
			w.WriteHeader(http.StatusTeapot)
		}
	})
	recorder = httptest.NewRecorder()
	rpCustom.ReplyHandler(recorder, postWResult(t, testReply, "<invalid", ""))
	if recorder.Code != http.StatusTeapot {
		t.Fatalf("status = %d", recorder.Code)
	}
	select {
	case err := <-custom:
		if err == nil {
			t.Fatalf("custom handler got nil error")
		}
	default:
		t.Fatalf("custom error handler was not called")
	}
}
