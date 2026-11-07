package wsfed

import (
	"bytes"
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
	"github.com/shibingli/ydx/auth/protocol/saml"
	"github.com/shibingli/ydx/xml"
)

const (
	testRealm  = "https://rp.example.com/"
	testReply  = "https://rp.example.com/wsfed/reply"
	testIssuer = "https://sts.example.com/"
)

var testNow = time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)

// testPrincipal returns a principal with the common mapped attributes. | testPrincipal 返回带有常见
// 映射属性的主体。
func testPrincipal() *auth.Principal {
	return &auth.Principal{
		Subject:     "user-1",
		Username:    "alice",
		Email:       "alice@example.com",
		DisplayName: "Alice",
		Groups:      []string{"admins", "users"},
		ACR:         saml.AuthnContextPassword,
		AuthTime:    testNow.Add(-time.Minute),
	}
}

// stubAuthenticator is a configurable test Authenticator. | stubAuthenticator 是可配置的测试认证器。
type stubAuthenticator struct {
	mu        sync.Mutex
	principal *auth.Principal
	err       error
	request   *SignInRequest
	signOut   bool
}

// Authenticate records the request and returns the configured result. | Authenticate 记录请求并返回
// 配置结果。
func (a *stubAuthenticator) Authenticate(_ context.Context, _ http.ResponseWriter, _ *http.Request, request *SignInRequest) (*auth.Principal, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.request = request
	if request == nil {
		a.signOut = true
	}
	return a.principal, a.err
}

// fakeSigner inserts an empty XMLDSig Signature element and records signed IDs. | fakeSigner 插入空
// XMLDSig Signature 元素并记录签名 ID。
type fakeSigner struct {
	mu  sync.Mutex
	ids []string
}

// SignElement inserts the marker after the root start tag. | SignElement 在根起始标签后插入标记。
func (s *fakeSigner) SignElement(document []byte, elementID string) ([]byte, error) {
	s.mu.Lock()
	s.ids = append(s.ids, elementID)
	s.mu.Unlock()
	index := bytes.IndexByte(document, '>')
	if index < 0 {
		return document, nil
	}
	marker := []byte(`<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"></Signature>`)
	out := make([]byte, 0, len(document)+len(marker))
	out = append(out, document[:index+1]...)
	out = append(out, marker...)
	out = append(out, document[index+1:]...)
	return out, nil
}

// signedIDs returns a copy of the recorded IDs. | signedIDs 返回已记录 ID 的副本。
func (s *fakeSigner) signedIDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.ids...)
}

// testVerifier accepts documents carrying a Signature element. | testVerifier 接受带 Signature 元素的文档。
func testVerifier() saml.SignatureVerifier {
	return saml.SignatureVerifierFunc(func(_ context.Context, document []byte, elementID string) error {
		if elementID == "" {
			return errors.New("missing element id")
		}
		if !bytes.Contains(document, []byte("Signature")) {
			return errors.New("missing signature")
		}
		return nil
	})
}

// newTestSTS returns an STS with test defaults. | newTestSTS 返回带测试默认值的 STS。
func newTestSTS(t *testing.T, authenticator Authenticator, mutate func(*STSConfig)) *SecurityTokenService {
	t.Helper()
	config := STSConfig{
		Issuer:        testIssuer,
		Authenticator: authenticator,
		AllowedRealms: []string{testRealm},
		TokenTTL:      5 * time.Minute,
		Now:           func() time.Time { return testNow },
	}
	if mutate != nil {
		mutate(&config)
	}
	sts, err := NewSecurityTokenService(config)
	if err != nil {
		t.Fatalf("NewSecurityTokenService: %v", err)
	}
	return sts
}

// newTestRP returns an RP with test defaults. | newTestRP 返回带测试默认值的 RP。
func newTestRP(t *testing.T, mutate func(*RelyingPartyConfig)) *RelyingParty {
	t.Helper()
	config := RelyingPartyConfig{
		Realm:            testRealm,
		ReplyURL:         testReply,
		IDPURL:           testIssuer + "wsfed/signin",
		SignOutURL:       testIssuer + "wsfed/signout",
		AllowUnsolicited: true,
		Now:              func() time.Time { return testNow },
	}
	if mutate != nil {
		mutate(&config)
	}
	rp, err := NewRelyingParty(config)
	if err != nil {
		t.Fatalf("NewRelyingParty: %v", err)
	}
	return rp
}

// issueTestToken issues a token through the STS internals and returns the serialized collection and
// assertion. | issueTestToken 通过 STS 内部逻辑签发令牌，并返回序列化集合与断言。
func issueTestToken(t *testing.T, sts *SecurityTokenService, principal *auth.Principal, realm, reply, wctx string, now, expires time.Time) (*RequestSecurityTokenResponseCollection, *saml.Assertion) {
	t.Helper()
	request := &SignInRequest{WA: ActionSignIn, Wtrealm: realm, Wreply: reply, Wctx: wctx}
	tokenID, tokenXML, _, _, _, _, err := sts.issueToken(context.Background(), principal, request, reply, now, expires)
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	collection := sts.tokenResponse(request, reply, tokenID, tokenXML, now, expires)
	var assertion saml.Assertion
	if err := xml.Unmarshal([]byte(tokenXML), &assertion); err != nil {
		t.Fatalf("unmarshal assertion: %v", err)
	}
	return collection, &assertion
}

// marshalCollection serializes a collection. | marshalCollection 序列化集合。
func marshalCollection(t *testing.T, collection *RequestSecurityTokenResponseCollection) string {
	t.Helper()
	data, err := collection.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return string(data)
}

// postWResult builds a POST reply request. | postWResult 构建 POST 回复请求。
func postWResult(t *testing.T, target, wresult, wctx string) *http.Request {
	t.Helper()
	form := url.Values{ParamWresult: {wresult}}
	if wctx != "" {
		form.Set(ParamWctx, wctx)
	}
	request := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return request
}

// TestParseSignInRequestGET parses a complete GET sign-in request. | TestParseSignInRequestGET 解析
// 完整的 GET 登录请求。
func TestParseSignInRequestGET(t *testing.T) {
	target := "/signin?wa=wsignin1.0&wtrealm=" + url.QueryEscape(testRealm) +
		"&wreply=" + url.QueryEscape(testReply) + "&wctx=ctx-1&wct=2026-11-07T12:00:00Z" +
		"&whr=contoso&wfresh=0&wauth=urn:oasis:names:tc:SAML:2.0:ac:classes:Password&wp=policy"
	request := httptest.NewRequest(http.MethodGet, target, nil)
	parsed, err := ParseSignInRequest(request)
	if err != nil {
		t.Fatalf("ParseSignInRequest: %v", err)
	}
	if parsed.WA != ActionSignIn || parsed.Wtrealm != testRealm || parsed.Wreply != testReply || parsed.Wctx != "ctx-1" {
		t.Fatalf("unexpected request: %+v", parsed)
	}
	if parsed.Wct == "" || parsed.Whr != "contoso" || parsed.Wfresh != "0" || parsed.Wauth == "" || parsed.WP != "policy" {
		t.Fatalf("optional parameters missing: %+v", parsed)
	}
}

// TestParseSignInRequestPOST parses a form body and prefers it over query values. |
// TestParseSignInRequestPOST 解析表单正文并让其优先于查询值。
func TestParseSignInRequestPOST(t *testing.T) {
	form := url.Values{
		ParamWA:      {ActionSignIn},
		ParamWtrealm: {testRealm},
		ParamWreply:  {testReply},
		ParamWctx:    {"from-body"},
	}
	request := httptest.NewRequest(http.MethodPost, "/signin?wctx=from-query", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	parsed, err := ParseSignInRequest(request)
	if err != nil {
		t.Fatalf("ParseSignInRequest: %v", err)
	}
	if parsed.Wctx != "from-body" {
		t.Fatalf("wctx = %q, want from-body", parsed.Wctx)
	}
}

// TestParseSignInRequestRejectsInvalid checks wrong actions and missing realms. |
// TestParseSignInRequestRejectsInvalid 检查错误动作与缺失领域。
func TestParseSignInRequestRejectsInvalid(t *testing.T) {
	cases := []struct {
		name   string
		target string
	}{
		{name: "missing realm", target: "/signin?wa=wsignin1.0"},
		{name: "wrong action", target: "/signin?wa=wsignout1.0&wtrealm=" + url.QueryEscape(testRealm)},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := ParseSignInRequest(httptest.NewRequest(http.MethodGet, testCase.target, nil))
			if !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("err = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

// TestSignInRequestURL builds and parses a sign-in URL. | TestSignInRequestURL 构建并解析登录 URL。
func TestSignInRequestURL(t *testing.T) {
	request := SignInRequest{WA: ActionSignIn, Wtrealm: testRealm, Wreply: testReply, Wctx: "ctx"}
	location, err := request.URL("https://sts.example.com/signin?existing=1")
	if err != nil {
		t.Fatalf("URL: %v", err)
	}
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	if parsed.Query().Get(ParamWA) != ActionSignIn || parsed.Query().Get(ParamWctx) != "ctx" || parsed.Query().Get("existing") != "1" {
		t.Fatalf("unexpected URL: %s", location)
	}
	if _, err := (SignInRequest{Wtrealm: testRealm, WA: ActionSignOut}).URL("https://sts.example.com/signin"); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("wrong wa accepted: %v", err)
	}
	if _, err := (SignInRequest{WA: ActionSignIn}).URL("https://sts.example.com/signin"); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("missing realm accepted: %v", err)
	}
}

// TestSignOutRequestParsing covers sign-out and cleanup parsing and URLs. |
// TestSignOutRequestParsing 覆盖登出与清理解析及 URL。
func TestSignOutRequestParsing(t *testing.T) {
	target := "/signout?wa=wsignoutcleanup1.0&wtrealm=" + url.QueryEscape(testRealm) + "&wreply=" + url.QueryEscape(testReply) + "&wctx=c"
	parsed, err := ParseSignOutRequest(httptest.NewRequest(http.MethodGet, target, nil))
	if err != nil {
		t.Fatalf("ParseSignOutRequest: %v", err)
	}
	if parsed.WA != ActionSignOutCleanup || parsed.Wctx != "c" {
		t.Fatalf("unexpected request: %+v", parsed)
	}
	location, err := SignOutRequest{WA: ActionSignOut, Wtrealm: testRealm, Wreply: testReply, Wctx: "c"}.URL("https://sts.example.com/signout")
	if err != nil {
		t.Fatalf("URL: %v", err)
	}
	if !strings.Contains(location, "wa=wsignout1.0") {
		t.Fatalf("unexpected location: %s", location)
	}
	request := httptest.NewRequest(http.MethodGet, "/signout?wa=wsignin1.0", nil)
	if _, err := ParseSignOutRequest(request); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("wrong action accepted: %v", err)
	}
}

// TestRequestBodyLimit rejects oversized bodies. | TestRequestBodyLimit 拒绝过大的正文。
func TestRequestBodyLimit(t *testing.T) {
	body := strings.Repeat("a", MaxRequestBytes+16)
	request := httptest.NewRequest(http.MethodPost, "/signin", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_, err := ParseSignInRequest(request)
	if !errors.Is(err, ErrRequestTooLarge) {
		t.Fatalf("err = %v, want ErrRequestTooLarge", err)
	}
}

// TestFaultError formats a WS-Federation fault. | TestFaultError 格式化 WS-Federation 故障。
func TestFaultError(t *testing.T) {
	fault := &Fault{FaultCode: FaultCodeAccessDenied, FaultString: "denied"}
	if !strings.Contains(fault.Error(), FaultCodeAccessDenied) || !strings.Contains(fault.Error(), "denied") {
		t.Fatalf("unexpected fault text: %s", fault.Error())
	}
	var nilFault *Fault
	if !strings.Contains(nilFault.Error(), "status failure") {
		t.Fatalf("unexpected nil fault text: %s", nilFault.Error())
	}
}
