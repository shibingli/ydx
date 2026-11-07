package wsfed

import (
	"context"
	"errors"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/auth/protocol/saml"
	"github.com/shibingli/ydx/router"
	"github.com/shibingli/ydx/xml"
)

// signInTarget builds a sign-in handler target. | signInTarget 构建登录处理器目标。
func signInTarget(realm, reply, wctx string) string {
	return "/wsfed/signin?wa=" + ActionSignIn + "&wtrealm=" + url.QueryEscape(realm) +
		"&wreply=" + url.QueryEscape(reply) + "&wctx=" + url.QueryEscape(wctx)
}

// TestHandleSignInPublishesForm verifies sign-in token publication. | TestHandleSignInPublishesForm
// 验证登录令牌发布。
func TestHandleSignInPublishesForm(t *testing.T) {
	authenticator := &stubAuthenticator{principal: testPrincipal()}
	sts := newTestSTS(t, authenticator, nil)
	recorder := httptest.NewRecorder()
	sts.HandleSignIn(recorder, httptest.NewRequest(http.MethodGet, signInTarget(testRealm, testReply, "ctx-1"), nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if contentType := recorder.Header().Get("Content-Type"); !strings.Contains(contentType, "text/html") {
		t.Fatalf("content type = %q", contentType)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, `name="wresult"`) || !strings.Contains(body, `name="wctx"`) {
		t.Fatalf("form fields missing: %s", body)
	}
	if !strings.Contains(body, `action="`+escapeHTML(testReply)+`"`) {
		t.Fatalf("reply action missing: %s", body)
	}
	if !strings.Contains(body, "RequestSecurityTokenResponseCollection") {
		t.Fatalf("token response missing: %s", body)
	}
	if authenticator.request == nil || authenticator.request.Wctx != "ctx-1" || authenticator.request.Wtrealm != testRealm {
		t.Fatalf("authenticator request = %+v", authenticator.request)
	}
	sessions, err := sts.Store().ListSessions(context.Background(), testPrincipal().Subject)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(sessions))
	}
}

// TestHandleSignInRejectsRealm rejects an unknown realm. | TestHandleSignInRejectsRealm 拒绝未知领域。
func TestHandleSignInRejectsRealm(t *testing.T) {
	sts := newTestSTS(t, &stubAuthenticator{principal: testPrincipal()}, nil)
	recorder := httptest.NewRecorder()
	sts.HandleSignIn(recorder, httptest.NewRequest(http.MethodGet, signInTarget("https://evil.example.com/", testReply, "c"), nil))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), FaultCodeAccessDenied) {
		t.Fatalf("fault code missing: %s", recorder.Body.String())
	}
}

// TestHandleSignInRequiresReply rejects a sign-in without wreply. | TestHandleSignInRequiresReply
// 拒绝没有 wreply 的登录。
func TestHandleSignInRequiresReply(t *testing.T) {
	sts := newTestSTS(t, &stubAuthenticator{principal: testPrincipal()}, nil)
	target := "/wsfed/signin?wa=" + ActionSignIn + "&wtrealm=" + url.QueryEscape(testRealm)
	recorder := httptest.NewRecorder()
	sts.HandleSignIn(recorder, httptest.NewRequest(http.MethodGet, target, nil))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), FaultCodeInvalidRequest) {
		t.Fatalf("fault code missing: %s", recorder.Body.String())
	}
}

// TestHandleSignInLoginRedirect redirects when authentication is required. |
// TestHandleSignInLoginRedirect 在需要认证时重定向。
func TestHandleSignInLoginRedirect(t *testing.T) {
	authenticator := &stubAuthenticator{err: ErrLoginRequired}
	sts := newTestSTS(t, authenticator, func(config *STSConfig) {
		config.LoginURL = "https://sts.example.com/login"
	})
	recorder := httptest.NewRecorder()
	sts.HandleSignIn(recorder, httptest.NewRequest(http.MethodGet, signInTarget(testRealm, testReply, "ctx"), nil))
	if recorder.Code != http.StatusFound {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	location := recorder.Header().Get("Location")
	if !strings.HasPrefix(location, "https://sts.example.com/login?return_to=") {
		t.Fatalf("location = %q", location)
	}
}

// TestHandleSignInLoginHandler uses a login handler. | TestHandleSignInLoginHandler 使用登录处理器。
func TestHandleSignInLoginHandler(t *testing.T) {
	sts := newTestSTS(t, &stubAuthenticator{principal: nil}, func(config *STSConfig) {
		config.LoginHandler = func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }
	})
	recorder := httptest.NewRecorder()
	sts.HandleSignIn(recorder, httptest.NewRequest(http.MethodGet, signInTarget(testRealm, testReply, "ctx"), nil))
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d", recorder.Code)
	}
}

// TestHandleSignInAuthenticatorError renders a server fault. | TestHandleSignInAuthenticatorError
// 渲染服务端故障。
func TestHandleSignInAuthenticatorError(t *testing.T) {
	sts := newTestSTS(t, &stubAuthenticator{err: errors.New("backend down")}, nil)
	recorder := httptest.NewRecorder()
	sts.HandleSignIn(recorder, httptest.NewRequest(http.MethodGet, signInTarget(testRealm, testReply, "ctx"), nil))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), FaultCodeServerError) {
		t.Fatalf("fault missing: %s", recorder.Body.String())
	}
}

// TestHandleSignInRealmResolver uses a dynamic realm resolver. | TestHandleSignInRealmResolver 使用
// 动态领域解析器。
func TestHandleSignInRealmResolver(t *testing.T) {
	resolvedReply := "https://rp.example.com/resolved"
	sts := newTestSTS(t, &stubAuthenticator{principal: testPrincipal()}, func(config *STSConfig) {
		config.AllowedRealms = nil
		config.RealmResolver = RealmResolverFunc(func(_ context.Context, realm, replyURL string) (string, error) {
			if realm != testRealm {
				return "", ErrInvalidRealm
			}
			return resolvedReply, nil
		})
	})
	recorder := httptest.NewRecorder()
	sts.HandleSignIn(recorder, httptest.NewRequest(http.MethodGet, signInTarget(testRealm, "", "ctx"), nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), resolvedReply) {
		t.Fatalf("resolved reply missing: %s", recorder.Body.String())
	}
	rejected := httptest.NewRecorder()
	sts.HandleSignIn(rejected, httptest.NewRequest(http.MethodGet, signInTarget("https://evil.example.com/", testReply, "ctx"), nil))
	if rejected.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rejected.Code)
	}
}

// TestHandleSignInInvalidMethod rejects unsupported methods. | TestHandleSignInInvalidMethod 拒绝
// 不支持的方法。
func TestHandleSignInInvalidMethod(t *testing.T) {
	sts := newTestSTS(t, &stubAuthenticator{principal: testPrincipal()}, nil)
	recorder := httptest.NewRecorder()
	sts.HandleSignIn(recorder, httptest.NewRequest(http.MethodDelete, "/wsfed/signin", nil))
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d", recorder.Code)
	}
}

// TestIssueTokenUnsignedAndSigned checks assertion signing. | TestIssueTokenUnsignedAndSigned 检查
// 断言签名。
func TestIssueTokenUnsignedAndSigned(t *testing.T) {
	t.Run("unsigned", func(t *testing.T) {
		sts := newTestSTS(t, &stubAuthenticator{principal: testPrincipal()}, nil)
		_, assertion := issueTestToken(t, sts, testPrincipal(), testRealm, testReply, "ctx", testNow, testNow.Add(time.Minute))
		if assertion.Signature != nil {
			t.Fatalf("unsigned assertion carries a signature")
		}
	})
	t.Run("signed", func(t *testing.T) {
		signer := &fakeSigner{}
		sts := newTestSTS(t, &stubAuthenticator{principal: testPrincipal()}, func(config *STSConfig) {
			config.Signer = signer
		})
		collection, assertion := issueTestToken(t, sts, testPrincipal(), testRealm, testReply, "ctx", testNow, testNow.Add(time.Minute))
		if assertion.Signature == nil {
			t.Fatalf("signed assertion has no signature marker")
		}
		if assertion.ID == "" {
			t.Fatalf("assertion ID is empty")
		}
		ids := signer.signedIDs()
		if len(ids) != 1 || ids[0] != assertion.ID {
			t.Fatalf("signed IDs = %v, assertion ID = %q", ids, assertion.ID)
		}
		if collection.Responses[0].RequestedSecurityToken == nil {
			t.Fatalf("token missing")
		}
	})
}

// TestIssueTokenSAML11 issues a SAML 1.1 assertion. | TestIssueTokenSAML11 签发 SAML 1.1 断言。
func TestIssueTokenSAML11(t *testing.T) {
	sts := newTestSTS(t, &stubAuthenticator{principal: testPrincipal()}, func(config *STSConfig) {
		config.TokenType = TokenTypeSAML11
	})
	request := &SignInRequest{WA: ActionSignIn, Wtrealm: testRealm, Wreply: testReply, Wctx: "ctx"}
	tokenID, tokenXML, sessionID, nameID, attributes, _, err := sts.issueToken(context.Background(), testPrincipal(), request, testReply, testNow, testNow.Add(5*time.Minute))
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	if tokenID == "" || sessionID == "" || nameID == "" {
		t.Fatalf("tokenID=%q sessionID=%q nameID=%q", tokenID, sessionID, nameID)
	}
	if len(attributes["email"]) != 1 || attributes["email"][0] != "alice@example.com" {
		t.Fatalf("attributes = %+v", attributes)
	}
	token := &RequestedSecurityToken{InnerXML: tokenXML}
	if token.TokenType() != TokenTypeSAML11 {
		t.Fatalf("token type = %q", token.TokenType())
	}
	assertion, err := token.Assertion()
	if err != nil {
		t.Fatalf("Assertion: %v", err)
	}
	if assertion.ID != tokenID || assertion.Subject.NameID.Value != nameID {
		t.Fatalf("unexpected assertion: %+v", assertion)
	}
}

// TestIssueTokenJWT issues a JWT token. | TestIssueTokenJWT 签发 JWT 令牌。
func TestIssueTokenJWT(t *testing.T) {
	jwtExpiry := testNow.Add(10 * time.Minute)
	sts := newTestSTS(t, &stubAuthenticator{principal: testPrincipal()}, func(config *STSConfig) {
		config.TokenType = TokenTypeJWT
		config.JWTIssuer = JWTIssuerFunc(func(_ context.Context, principal *auth.Principal, audience string, ttl time.Duration) (string, time.Time, error) {
			if principal.Subject != "user-1" || audience != testRealm || ttl != 5*time.Minute {
				return "", time.Time{}, errors.New("unexpected JWT arguments")
			}
			return "header.payload.signature", jwtExpiry, nil
		})
	})
	request := &SignInRequest{WA: ActionSignIn, Wtrealm: testRealm, Wreply: testReply, Wctx: "ctx"}
	tokenID, tokenXML, sessionID, nameID, attributes, actualExpiry, err := sts.issueToken(context.Background(), testPrincipal(), request, testReply, testNow, testNow.Add(time.Minute))
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	if !actualExpiry.Equal(jwtExpiry) {
		t.Fatalf("token expiry = %v, want the JWT issuer expiry %v", actualExpiry, jwtExpiry)
	}
	if tokenID != "" || sessionID != "" || nameID != "" {
		t.Fatalf("unexpected SAML identifiers: %q %q %q", tokenID, sessionID, nameID)
	}
	if tokenXML != "header.payload.signature" {
		t.Fatalf("token = %q", tokenXML)
	}
	if len(attributes) == 0 {
		t.Fatalf("attributes are empty")
	}
	collection := sts.tokenResponse(request, testReply, tokenID, tokenXML, testNow, actualExpiry)
	if collection.Responses[0].TokenType != TokenTypeJWT {
		t.Fatalf("token type = %q", collection.Responses[0].TokenType)
	}
	if collection.Responses[0].Lifetime.Expires != saml.FormatTime(jwtExpiry) {
		t.Fatalf("lifetime = %+v", collection.Responses[0].Lifetime)
	}
}

// TestHandleSignInUsesJWTIssuerExpiry verifies that the published WS-Federation response lifetime
// matches the JWT exp chosen by the issuer instead of the configured token TTL. |
// TestHandleSignInUsesJWTIssuerExpiry 验证发布的 WS-Federation 响应寿命与签发方选择的 JWT exp
// 一致，而不是配置的令牌 TTL。
func TestHandleSignInUsesJWTIssuerExpiry(t *testing.T) {
	jwtExpiry := testNow.Add(17 * time.Minute)
	sts := newTestSTS(t, &stubAuthenticator{principal: testPrincipal()}, func(config *STSConfig) {
		config.TokenType = TokenTypeJWT
		config.JWTIssuer = JWTIssuerFunc(func(context.Context, *auth.Principal, string, time.Duration) (string, time.Time, error) {
			return "header.payload.signature", jwtExpiry, nil
		})
	})
	recorder := httptest.NewRecorder()
	sts.HandleSignIn(recorder, httptest.NewRequest(http.MethodGet, signInTarget(testRealm, testReply, "ctx"), nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	wresult := hiddenFormValue(recorder.Body.String(), ParamWresult)
	if wresult == "" {
		t.Fatalf("wresult field missing: %s", recorder.Body.String())
	}
	collection, err := ParseWResultString(wresult)
	if err != nil {
		t.Fatalf("ParseWResultString: %v", err)
	}
	response := collection.TokenResponse()
	if response == nil || response.Lifetime == nil {
		t.Fatalf("token response or lifetime missing: %+v", collection)
	}
	if response.Lifetime.Expires != saml.FormatTime(jwtExpiry) {
		t.Fatalf("lifetime expires = %q, want %q", response.Lifetime.Expires, saml.FormatTime(jwtExpiry))
	}
}

// hiddenFormValue returns the unescaped value of a hidden input in the auto-submitting form. |
// hiddenFormValue 返回自动提交表单中隐藏输入的去转义值。
func hiddenFormValue(body, name string) string {
	marker := `name="` + name + `" value="`
	start := strings.Index(body, marker)
	if start < 0 {
		return ""
	}
	start += len(marker)
	end := strings.Index(body[start:], `">`)
	if end < 0 {
		return ""
	}
	return html.UnescapeString(body[start : start+end])
}

// TestHandleSignOutDeletesSessions deletes IdP sessions on sign-out. | TestHandleSignOutDeletesSessions
// 在登出时删除 IdP 会话。
func TestHandleSignOutDeletesSessions(t *testing.T) {
	authenticator := &stubAuthenticator{principal: testPrincipal()}
	sts := newTestSTS(t, authenticator, nil)
	signInRecorder := httptest.NewRecorder()
	sts.HandleSignIn(signInRecorder, httptest.NewRequest(http.MethodGet, signInTarget(testRealm, testReply, "ctx"), nil))
	if signInRecorder.Code != http.StatusOK {
		t.Fatalf("sign-in status = %d", signInRecorder.Code)
	}
	sessions, err := sts.Store().ListSessions(context.Background(), "user-1")
	if err != nil || len(sessions) != 1 {
		t.Fatalf("sessions before sign-out = %d, err = %v", len(sessions), err)
	}
	target := "/wsfed/signout?wa=" + ActionSignOutCleanup + "&wtrealm=" + url.QueryEscape(testRealm) + "&wctx=ctx"
	recorder := httptest.NewRecorder()
	sts.HandleSignOut(recorder, httptest.NewRequest(http.MethodGet, target, nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("sign-out status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	sessions, err = sts.Store().ListSessions(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 0 {
		t.Fatalf("sessions after sign-out = %d", len(sessions))
	}
	if !authenticator.signOut {
		t.Fatalf("authenticator was not called for sign-out")
	}
}

// TestHandleSignOutPostsResult posts a sign-out result to wreply. | TestHandleSignOutPostsResult
// 把登出结果 POST 到 wreply。
func TestHandleSignOutPostsResult(t *testing.T) {
	sts := newTestSTS(t, &stubAuthenticator{principal: testPrincipal()}, nil)
	target := "/wsfed/signout?wa=" + ActionSignOut + "&wtrealm=" + url.QueryEscape(testRealm) +
		"&wreply=" + url.QueryEscape(testReply) + "&wctx=ctx"
	recorder := httptest.NewRecorder()
	sts.HandleSignOut(recorder, httptest.NewRequest(http.MethodGet, target, nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	if !strings.Contains(body, `name="wresult"`) || !strings.Contains(body, `name="wctx"`) {
		t.Fatalf("sign-out fields missing: %s", body)
	}
	if !strings.Contains(body, "Cancel") && !strings.Contains(body, "RequestSecurityTokenResponseCollection") {
		t.Fatalf("sign-out result missing: %s", body)
	}
}

// TestHandleSignOutRejectsRealm rejects an unknown realm during sign-out. |
// TestHandleSignOutRejectsRealm 在登出期间拒绝未知领域。
func TestHandleSignOutRejectsRealm(t *testing.T) {
	sts := newTestSTS(t, &stubAuthenticator{principal: testPrincipal()}, nil)
	target := "/wsfed/signout?wa=" + ActionSignOut + "&wtrealm=" + url.QueryEscape("https://evil.example.com/")
	recorder := httptest.NewRecorder()
	sts.HandleSignOut(recorder, httptest.NewRequest(http.MethodGet, target, nil))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
}

// TestAdaptAuthenticator adapts a saml.Authenticator. | TestAdaptAuthenticator 适配 saml.Authenticator。
func TestAdaptAuthenticator(t *testing.T) {
	adapted := AdaptAuthenticator(saml.AuthenticatorFunc(func(_ context.Context, _ http.ResponseWriter, _ *http.Request, request *saml.AuthnRequest) (*auth.Principal, error) {
		if request == nil || request.Issuer == nil || request.Issuer.Value != testRealm || request.AssertionConsumerServiceURL != testReply {
			return nil, errors.New("unexpected authn request")
		}
		return testPrincipal(), nil
	}))
	principal, err := adapted.Authenticate(context.Background(), httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil),
		&SignInRequest{Wtrealm: testRealm, Wreply: testReply})
	if err != nil || principal == nil || principal.Subject != "user-1" {
		t.Fatalf("principal = %+v, err = %v", principal, err)
	}
	if AdaptAuthenticator(nil) != nil {
		t.Fatalf("nil authenticator did not adapt to nil")
	}
}

// TestSTSConfigValidation rejects invalid configurations. | TestSTSConfigValidation 拒绝非法配置。
func TestSTSConfigValidation(t *testing.T) {
	authenticator := &stubAuthenticator{principal: testPrincipal()}
	cases := []STSConfig{
		{},
		{Issuer: testIssuer},
		{Issuer: testIssuer, Authenticator: authenticator, TokenType: "urn:unknown"},
		{Issuer: testIssuer, Authenticator: authenticator, TokenType: TokenTypeJWT},
		{Issuer: testIssuer, Authenticator: authenticator, SignResponse: true},
	}
	for index, config := range cases {
		if _, err := NewSecurityTokenService(config); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("case %d err = %v, want ErrInvalidConfig", index, err)
		}
	}
}

// TestMetadataDocument serves and validates the metadata document. | TestMetadataDocument 提供并
// 校验元数据文档。
func TestMetadataDocument(t *testing.T) {
	sts := newTestSTS(t, &stubAuthenticator{principal: testPrincipal()}, nil)
	data, err := sts.MetadataXML()
	if err != nil {
		t.Fatalf("MetadataXML: %v", err)
	}
	text := string(data)
	for _, want := range []string{"EntityDescriptor", `entityID="` + testIssuer + `"`, "SecurityTokenServiceType",
		testIssuer + "wsfed/signin", testIssuer + "wsfed/signout", TokenTypeSAML20, TokenTypeSAML11} {
		if !strings.Contains(text, want) {
			t.Fatalf("metadata missing %q: %s", want, text)
		}
	}
	var parsed FederationMetadata
	if err := xml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("metadata is not parseable: %v\n%s", err, text)
	}
	if parsed.EntityID != testIssuer || parsed.RoleDescriptor == nil {
		t.Fatalf("unexpected metadata: %+v", parsed)
	}
	if sts.SignInURL() != testIssuer+"wsfed/signin" || sts.SignOutURL() != testIssuer+"wsfed/signout" {
		t.Fatalf("endpoint URLs = %q %q", sts.SignInURL(), sts.SignOutURL())
	}
	recorder := httptest.NewRecorder()
	sts.MetadataHandler(recorder, httptest.NewRequest(http.MethodGet, "/wsfed/metadata", nil))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Header().Get("Content-Type"), "wsfederationmetadata") {
		t.Fatalf("status = %d, content type = %q", recorder.Code, recorder.Header().Get("Content-Type"))
	}
	badMethod := httptest.NewRecorder()
	sts.MetadataHandler(badMethod, httptest.NewRequest(http.MethodPost, "/wsfed/metadata", nil))
	if badMethod.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d", badMethod.Code)
	}
}

// TestSTSRouterMount mounts the STS on a YD router. | TestSTSRouterMount 在 YD 路由上挂载 STS。
func TestSTSRouterMount(t *testing.T) {
	sts := newTestSTS(t, &stubAuthenticator{principal: testPrincipal()}, nil)
	r := router.New()
	sts.Register(r, "/idp")
	for _, path := range []string{"/idp/wsfed/metadata", signInTargetForPrefix("/idp")} {
		recorder := httptest.NewRecorder()
		r.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("path %s status = %d, body = %s", path, recorder.Code, recorder.Body.String())
		}
	}
}

// signInTargetForPrefix builds a prefixed sign-in target. | signInTargetForPrefix 构建带前缀的登录目标。
func signInTargetForPrefix(prefix string) string {
	return prefix + "/wsfed/signin?wa=" + ActionSignIn + "&wtrealm=" + url.QueryEscape(testRealm) +
		"&wreply=" + url.QueryEscape(testReply) + "&wctx=ctx"
}

// TestSTSHTTPHandlerMount mounts the STS with net/http. | TestSTSHTTPHandlerMount 使用 net/http 挂载 STS。
func TestSTSHTTPHandlerMount(t *testing.T) {
	sts := newTestSTS(t, &stubAuthenticator{principal: testPrincipal()}, nil)
	server := httptest.NewServer(sts.HTTPHandler("/idp"))
	defer server.Close()
	response, err := http.Get(server.URL + "/idp/wsfed/metadata")
	if err != nil {
		t.Fatalf("GET metadata: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read metadata: %v", err)
	}
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), "EntityDescriptor") {
		t.Fatalf("status = %d, body = %s", response.StatusCode, body)
	}
	signIn, err := http.Get(server.URL + signInTargetForPrefix("/idp"))
	if err != nil {
		t.Fatalf("GET sign-in: %v", err)
	}
	defer func() { _ = signIn.Body.Close() }()
	signInBody, err := io.ReadAll(signIn.Body)
	if err != nil {
		t.Fatalf("read sign-in: %v", err)
	}
	if signIn.StatusCode != http.StatusOK || !strings.Contains(string(signInBody), `name="wresult"`) {
		t.Fatalf("sign-in status = %d, body = %s", signIn.StatusCode, signInBody)
	}
}

// TestConcurrentSTSHandlers exercises shared stores under concurrency. | TestConcurrentSTSHandlers
// 在并发下测试共享存储。
func TestConcurrentSTSHandlers(t *testing.T) {
	signer := &fakeSigner{}
	sts := newTestSTS(t, &stubAuthenticator{principal: testPrincipal()}, func(config *STSConfig) {
		config.Signer = signer
	})
	const workers = 16
	var wait sync.WaitGroup
	statuses := make(chan int, workers*3)
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			signIn := httptest.NewRecorder()
			sts.HandleSignIn(signIn, httptest.NewRequest(http.MethodGet, signInTarget(testRealm, testReply, "ctx"), nil))
			statuses <- signIn.Code
			signOut := httptest.NewRecorder()
			sts.HandleSignOut(signOut, httptest.NewRequest(http.MethodGet, "/wsfed/signout?wa="+ActionSignOutCleanup, nil))
			statuses <- signOut.Code
			metadata := httptest.NewRecorder()
			sts.MetadataHandler(metadata, httptest.NewRequest(http.MethodGet, "/wsfed/metadata", nil))
			statuses <- metadata.Code
		}()
	}
	wait.Wait()
	close(statuses)
	for status := range statuses {
		if status != http.StatusOK {
			t.Fatalf("status = %d", status)
		}
	}
}
