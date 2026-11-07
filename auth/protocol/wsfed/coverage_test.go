package wsfed

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestSTSAccessors exposes the configured endpoints and stores. | TestSTSAccessors 暴露已配置端点与存储。
func TestSTSAccessors(t *testing.T) {
	sts := newTestSTS(t, &stubAuthenticator{principal: testPrincipal()}, nil)
	if sts.Config().Issuer != testIssuer {
		t.Fatalf("issuer = %q", sts.Config().Issuer)
	}
	if sts.Store() == nil {
		t.Fatal("store is nil")
	}
	if sts.SignInURL() != testIssuer+"wsfed/signin" {
		t.Fatalf("sign-in URL = %q", sts.SignInURL())
	}
	if sts.SignOutURL() != testIssuer+"wsfed/signout" {
		t.Fatalf("sign-out URL = %q", sts.SignOutURL())
	}
	if sts.MetadataURL() != testIssuer+"wsfed/metadata" {
		t.Fatalf("metadata URL = %q", sts.MetadataURL())
	}
	custom := newTestSTS(t, &stubAuthenticator{}, func(config *STSConfig) {
		config.SignInPath = testIssuer + "custom/signin"
		config.SignOutPath = "signout"
		config.MetadataPath = "/meta"
	})
	if custom.SignInURL() != testIssuer+"custom/signin" || custom.Config().SignInPath != "/custom/signin" {
		t.Fatalf("custom sign-in = %q, %q", custom.SignInURL(), custom.Config().SignInPath)
	}
	if custom.SignOutURL() != testIssuer+"signout" || custom.Config().SignOutPath != "/signout" {
		t.Fatalf("custom sign-out = %q, %q", custom.SignOutURL(), custom.Config().SignOutPath)
	}
	if custom.MetadataURL() != testIssuer+"meta" {
		t.Fatalf("custom metadata = %q", custom.MetadataURL())
	}
	rp := newTestRP(t, nil)
	if rp.Config().Realm != testRealm {
		t.Fatalf("realm = %q", rp.Config().Realm)
	}
	if rp.Store() == nil || rp.Requests() == nil {
		t.Fatal("relying party stores are nil")
	}
}

// TestRequestedSecurityTokenHelpers covers nil, malformed and typed token paths. |
// TestRequestedSecurityTokenHelpers 覆盖空、畸形与带类型的令牌路径。
func TestRequestedSecurityTokenHelpers(t *testing.T) {
	var nilToken *RequestedSecurityToken
	if nilToken.Raw() != "" {
		t.Fatal("nil token Raw is not empty")
	}
	nilToken.SetRaw("ignored")
	token := &RequestedSecurityToken{}
	if token.Raw() != "" {
		t.Fatal("empty token Raw is not empty")
	}
	token.SetRaw("  a.b.c  ")
	if token.Raw() != "a.b.c" || token.TokenType() != TokenTypeJWT {
		t.Fatalf("token = %q, %q", token.Raw(), token.TokenType())
	}
	if _, ok := token.JWT(); !ok {
		t.Fatal("raw JWT not recognized")
	}
	if _, ok := (&RequestedSecurityToken{InnerXML: "<broken"}).JWT(); ok {
		t.Fatal("malformed JWT recognized")
	}
	if _, ok := (&RequestedSecurityToken{InnerXML: `<Assertion xmlns="` + NamespaceSAML20 + `">x</Assertion>`}).JWT(); ok {
		t.Fatal("non-BinarySecurityToken recognized as JWT")
	}
	if _, ok := (&RequestedSecurityToken{}).JWT(); ok {
		t.Fatal("empty JWT recognized")
	}
	malformed := &RequestedSecurityToken{InnerXML: "<Assertion"}
	if malformed.TokenType() != "" {
		t.Fatalf("malformed token type = %q", malformed.TokenType())
	}
	other := &RequestedSecurityToken{InnerXML: `<Other xmlns="` + NamespaceSAML20 + `"/>`}
	if other.TokenType() != "" {
		t.Fatalf("other token type = %q", other.TokenType())
	}
	noID := &RequestedSecurityToken{InnerXML: `<Assertion xmlns="` + NamespaceSAML20 + `"/>`}
	if _, err := noID.Assertion(); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("SAML 2.0 missing ID err = %v", err)
	}
	noID11 := &RequestedSecurityToken{InnerXML: `<Assertion xmlns="` + NamespaceSAML11 + `"/>`}
	if _, err := noID11.Assertion(); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("SAML 1.1 missing ID err = %v", err)
	}
}

// TestFaultErrorBranches formats every fault shape. | TestFaultErrorBranches 格式化所有故障形态。
func TestFaultErrorBranches(t *testing.T) {
	var nilFault *Fault
	if nilFault.Error() != ErrStatusFailure.Error() {
		t.Fatalf("nil fault = %q", nilFault.Error())
	}
	if got := (&Fault{FaultCode: "A", FaultString: "B"}).Error(); !strings.Contains(got, "A") || !strings.Contains(got, "B") {
		t.Fatalf("code+message = %q", got)
	}
	if got := (&Fault{FaultCode: "A"}).Error(); !strings.Contains(got, "A") {
		t.Fatalf("code = %q", got)
	}
	if got := (&Fault{FaultString: "B"}).Error(); !strings.Contains(got, "B") {
		t.Fatalf("message = %q", got)
	}
	if got := (&Fault{}).Error(); got != ErrStatusFailure.Error() {
		t.Fatalf("empty = %q", got)
	}
}

// TestResponseHelperBranches covers content detection and raw conversion. |
// TestResponseHelperBranches 覆盖内容判定与原始转换。
func TestResponseHelperBranches(t *testing.T) {
	if responseHasContent(nil) || responseHasContent(&RequestSecurityTokenResponse{}) {
		t.Fatal("empty response has content")
	}
	for _, response := range []*RequestSecurityTokenResponse{
		{TokenType: TokenTypeSAML20},
		{RequestType: RequestTypeIssue},
		{AppliesTo: &AppliesTo{}},
		{Lifetime: &Lifetime{}},
		{RequestedSecurityToken: &RequestedSecurityToken{}},
		{Status: &ResponseStatus{}},
	} {
		if !responseHasContent(response) {
			t.Fatalf("response %+v has no content", response)
		}
	}
	if (*rawResponse)(nil).hasContent() || (&rawResponse{}).hasContent() {
		t.Fatal("empty raw response has content")
	}
	if (&rawResponse{RequestedSecurityToken: &rawSecurityToken{InnerXML: "  "}}).hasContent() {
		t.Fatal("blank raw token has content")
	}
	for _, raw := range []*rawResponse{
		{TokenType: TokenTypeSAML20},
		{RequestType: RequestTypeIssue},
		{AppliesTo: &rawAppliesTo{}},
		{Lifetime: &rawLifetime{}},
		{RequestedSecurityToken: &rawSecurityToken{InnerXML: "x"}},
		{Status: &rawStatus{}},
	} {
		if !raw.hasContent() {
			t.Fatalf("raw %+v has no content", raw)
		}
	}
	converted := (&rawResponse{
		ID:                           "id",
		Context:                      "ctx",
		Wctx:                         "wctx",
		TokenType:                    TokenTypeSAML20,
		RequestType:                  RequestTypeIssue,
		KeySize:                      256,
		AppliesTo:                    &rawAppliesTo{Address: testRealm},
		Lifetime:                     &rawLifetime{Created: "c", Expires: "e"},
		RequestedSecurityToken:       &rawSecurityToken{InnerXML: "raw"},
		RequestedAttachedReference:   &rawTokenReference{},
		RequestedUnattachedReference: &rawTokenReference{Reference: &rawReferenceURI{URI: "#id", ValueType: "vt"}},
		Status:                       &rawStatus{StatusCode: StatusSuccess},
	}).response()
	if converted.ID != "id" || converted.Context != "ctx" || converted.Wctx != "wctx" || converted.KeySize != 256 {
		t.Fatalf("unexpected response: %+v", converted)
	}
	if converted.AppliesTo == nil || converted.AppliesTo.Address() != testRealm {
		t.Fatalf("applies-to = %+v", converted.AppliesTo)
	}
	if converted.Lifetime == nil || converted.Lifetime.Created != "c" || converted.Lifetime.Expires != "e" {
		t.Fatalf("lifetime = %+v", converted.Lifetime)
	}
	if converted.RequestedSecurityToken == nil || converted.RequestedSecurityToken.Raw() != "raw" {
		t.Fatalf("token = %+v", converted.RequestedSecurityToken)
	}
	if converted.RequestedAttachedReference == nil || converted.RequestedAttachedReference.SecurityTokenReference.Reference.URI != "" {
		t.Fatalf("attached = %+v", converted.RequestedAttachedReference)
	}
	if converted.RequestedUnattachedReference == nil || converted.RequestedUnattachedReference.SecurityTokenReference.Reference.URI != "#id" {
		t.Fatalf("unattached = %+v", converted.RequestedUnattachedReference)
	}
	if converted.Status == nil || converted.Status.Code != StatusSuccess {
		t.Fatalf("status = %+v", converted.Status)
	}
	endpoint := (&rawResponse{AppliesTo: &rawAppliesTo{EndpointReference: &rawEndpointReference{Address: testReply}}}).response()
	if endpoint.AppliesTo.Address() != testReply {
		t.Fatalf("endpoint address = %q", endpoint.AppliesTo.Address())
	}
	if (*rawTokenReference)(nil).reference() != nil {
		t.Fatal("nil raw reference converted")
	}
	if (&rawTokenReference{}).reference() == nil {
		t.Fatal("empty raw reference not converted")
	}
	var nilCollection *RequestSecurityTokenResponseCollection
	if nilCollection.TokenResponse() != nil {
		t.Fatal("nil collection has token")
	}
	if data, err := nilCollection.Marshal(); err == nil || data != nil {
		t.Fatal("nil collection marshaled")
	}
	if (&RequestSecurityTokenResponseCollection{Responses: []RequestSecurityTokenResponse{{}}}).TokenResponse() != nil {
		t.Fatal("tokenless collection has token")
	}
	if NewTokenReference(" # ", "") != nil || NewAttachedReference("", "") != nil || NewUnattachedReference("#", "") != nil {
		t.Fatal("empty reference accepted")
	}
	if NewTokenReference("#assertion-9", ValueTypeSAMLV20).Reference.URI != "#assertion-9" {
		t.Fatal("reference URI mismatch")
	}
}

// TestSAML11SubjectFallback derives the subject from attribute statements. |
// TestSAML11SubjectFallback 从属性语句推导主体。
func TestSAML11SubjectFallback(t *testing.T) {
	var nilAssertion *SAML11Assertion
	if nilAssertion.Assertion() != nil || nilAssertion.subject() != nil {
		t.Fatal("nil assertion converted")
	}
	empty := &SAML11Assertion{}
	if empty.subject() != nil {
		t.Fatal("empty assertion has subject")
	}
	if converted := empty.Assertion(); converted == nil || converted.Subject != nil {
		t.Fatalf("empty conversion = %+v", converted)
	}
	subject := &SAML11Subject{NameIdentifier: &SAML11NameIdentifier{Value: "alice"}}
	fromAttribute := &SAML11Assertion{AttributeStatement: []SAML11AttributeStatement{{Subject: subject}}}
	if fromAttribute.subject() != subject {
		t.Fatal("attribute subject not found")
	}
	converted := fromAttribute.Assertion()
	if converted.Subject == nil || converted.Subject.NameID.Value != "alice" {
		t.Fatalf("subject = %+v", converted.Subject)
	}
	withMethods := &SAML11Assertion{AuthenticationStatement: []SAML11AuthenticationStatement{{
		Subject: &SAML11Subject{SubjectConfirmation: []SAML11SubjectConfirmation{{ConfirmationMethod: []string{"bearer"}}}},
	}}}
	if converted := withMethods.Assertion(); converted.Subject == nil || len(converted.Subject.SubjectConfirmation) != 1 ||
		converted.Subject.SubjectConfirmation[0].Method != "bearer" {
		t.Fatalf("confirmations = %+v", converted.Subject)
	}
}

// TestMemoryRequestStore covers save, take, expiry and cancellation. |
// TestMemoryRequestStore 覆盖保存、获取、过期与取消。
func TestMemoryRequestStore(t *testing.T) {
	store := NewMemoryRequestStore()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := store.SaveRequest(canceled, RequestState{Wctx: "ctx"}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("canceled save err = %v", err)
	}
	if _, _, err := store.TakeRequest(canceled, "ctx"); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("canceled take err = %v", err)
	}
	if err := store.SaveRequest(context.Background(), RequestState{Wctx: " "}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("blank wctx err = %v", err)
	}
	if err := store.SaveRequest(context.Background(), RequestState{Wctx: "ctx", Realm: testRealm}); err != nil {
		t.Fatalf("save: %v", err)
	}
	state, ok, err := store.TakeRequest(context.Background(), "ctx")
	if err != nil || !ok || state.Realm != testRealm || state.CreatedAt.IsZero() || state.ExpiresAt.IsZero() {
		t.Fatalf("take = %+v, %v, %v", state, ok, err)
	}
	if _, ok, err := store.TakeRequest(context.Background(), "ctx"); err != nil || ok {
		t.Fatalf("second take = %v, %v", ok, err)
	}
	if _, ok, err := store.TakeRequest(context.Background(), ""); err != nil || ok {
		t.Fatalf("blank take = %v, %v", ok, err)
	}
	if err := store.SaveRequest(context.Background(), RequestState{Wctx: "expired", ExpiresAt: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatalf("save expired: %v", err)
	}
	if _, ok, err := store.TakeRequest(context.Background(), "expired"); err != nil || ok {
		t.Fatalf("expired take = %v, %v", ok, err)
	}
	if store.Len() != 0 {
		t.Fatalf("expired request retained: %d", store.Len())
	}
	if err := store.SaveRequest(context.Background(), RequestState{Wctx: "ctx2"}); err != nil {
		t.Fatalf("save ctx2: %v", err)
	}
	if err := store.SaveRequest(context.Background(), RequestState{Wctx: "ctx3"}); err != nil {
		t.Fatalf("save ctx3: %v", err)
	}
	if store.Len() != 2 {
		t.Fatalf("len = %d", store.Len())
	}
	var nilContext context.Context
	if contextError(nilContext) != nil {
		t.Fatal("nil context reported error")
	}
}

// TestVerifyIncomingToken covers every configured-verifier branch. |
// TestVerifyIncomingToken 覆盖配置校验器的每个分支。
func TestVerifyIncomingToken(t *testing.T) {
	verifying := newTestSTS(t, &stubAuthenticator{}, func(config *STSConfig) {
		config.SignatureVerifier = testVerifier()
	})
	request := func(wresult string) *http.Request {
		return httptest.NewRequest(http.MethodPost, testIssuer+"wsfed/signin", nil)
	}
	values := func(wresult string) url.Values {
		if wresult == "" {
			return url.Values{}
		}
		return url.Values{ParamWresult: {wresult}}
	}
	if err := verifying.verifyIncomingToken(request(""), values("")); err != nil {
		t.Fatalf("empty wresult: %v", err)
	}
	if err := verifying.verifyIncomingToken(request(""), values("<broken")); err == nil {
		t.Fatal("malformed wresult accepted")
	}
	signOut := marshalCollection(t, NewSignOutCollection("ctx"))
	if err := verifying.verifyIncomingToken(request(signOut), values(signOut)); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tokenless wresult err = %v", err)
	}
	jwtCollection := &RequestSecurityTokenResponseCollection{Responses: []RequestSecurityTokenResponse{{
		RequestedSecurityToken: &RequestedSecurityToken{InnerXML: "a.b.c"},
	}}}
	jwtMarshaled := marshalCollection(t, jwtCollection)
	if err := verifying.verifyIncomingToken(request(jwtMarshaled), values(jwtMarshaled)); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("JWT wresult err = %v", err)
	}
	unsignedSTS := newTestSTS(t, &stubAuthenticator{principal: testPrincipal()}, nil)
	unsignedCollection, _ := issueTestToken(t, unsignedSTS, testPrincipal(), testRealm, testReply, "ctx", testNow, testNow.Add(5*time.Minute))
	unsigned := marshalCollection(t, unsignedCollection)
	if err := verifying.verifyIncomingToken(request(unsigned), values(unsigned)); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("unsigned wresult err = %v", err)
	}
	signed := marshalCollection(t, mustIssue(t, signedSTS(t, testRealm)))
	if err := verifying.verifyIncomingToken(request(signed), values(signed)); err != nil {
		t.Fatalf("signed wresult: %v", err)
	}
}

// mustIssue issues a token for the test realm. | mustIssue 为测试领域签发令牌。
func mustIssue(t *testing.T, sts *SecurityTokenService) *RequestSecurityTokenResponseCollection {
	t.Helper()
	collection, _ := issueTestToken(t, sts, testPrincipal(), testRealm, testReply, "ctx", testNow, testNow.Add(5*time.Minute))
	return collection
}

// TestCheckTokenType validates declared and configured token type mismatches. |
// TestCheckTokenType 校验声明与配置的令牌类型不匹配。
func TestCheckTokenType(t *testing.T) {
	rp := newTestRP(t, nil)
	if err := rp.checkTokenType(TokenTypeSAML20, TokenTypeSAML20); err != nil {
		t.Fatalf("matching type: %v", err)
	}
	if err := rp.checkTokenType(TokenTypeSAML11, TokenTypeSAML20); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("declared mismatch err = %v", err)
	}
	configured := newTestRP(t, func(config *RelyingPartyConfig) {
		config.TokenType = TokenTypeJWT
		config.JWTVerifier = JWTVerifierFunc(nil)
	})
	if err := configured.checkTokenType("", TokenTypeSAML20); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("configured mismatch err = %v", err)
	}
	if err := configured.checkTokenType(TokenTypeJWT, TokenTypeJWT); err != nil {
		t.Fatalf("configured match: %v", err)
	}
	_ = rp
}

// TestAdapterNilFunctions exercises nil adapter fallbacks. | TestAdapterNilFunctions 覆盖空适配器回退。
func TestAdapterNilFunctions(t *testing.T) {
	if AdaptAuthenticator(nil) != nil {
		t.Fatal("nil authenticator adapted")
	}
	if _, err := (AuthenticatorFunc(nil)).Authenticate(context.Background(), nil, nil, nil); !errors.Is(err, ErrLoginRequired) {
		t.Fatalf("nil authenticator err = %v", err)
	}
	if reply, err := (RealmResolverFunc(nil)).ResolveRealm(context.Background(), "realm", "reply"); err != nil || reply != "reply" {
		t.Fatalf("nil resolver = %q, %v", reply, err)
	}
	if _, _, err := (JWTIssuerFunc(nil)).IssueJWT(context.Background(), nil, "", 0); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("nil issuer err = %v", err)
	}
	if _, _, _, err := (JWTVerifierFunc(nil)).VerifyJWT(context.Background(), "", ""); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("nil verifier err = %v", err)
	}
}

// TestJoinPathVariants joins mount prefixes and endpoint paths. | TestJoinPathVariants 连接挂载前缀与端点路径。
func TestJoinPathVariants(t *testing.T) {
	cases := [][3]string{
		{"", "/x", "/x"},
		{"/", "/x", "/x"},
		{"/", "x", "/x"},
		{"/base/", "", "/base"},
		{"/base", "x", "/base/x"},
		{"/base", "/x", "/base/x"},
	}
	for _, c := range cases {
		if got := joinPath(c[0], c[1]); got != c[2] {
			t.Fatalf("joinPath(%q, %q) = %q, want %q", c[0], c[1], got, c[2])
		}
	}
}

// TestEndpointHelpers covers absolute and relative endpoint resolution. |
// TestEndpointHelpers 覆盖绝对与相对端点解析。
func TestEndpointHelpers(t *testing.T) {
	if got := endpointURL(testIssuer, testIssuer+"absolute", "/fallback"); got != testIssuer+"absolute" {
		t.Fatalf("absolute endpoint = %q", got)
	}
	if got := endpointURL(testIssuer, "relative", "/fallback"); got != testIssuer+"relative" {
		t.Fatalf("relative endpoint = %q", got)
	}
	if got := endpointURL("", "/path", ""); got != "/path" {
		t.Fatalf("rootless endpoint = %q", got)
	}
	if got := localPath(testIssuer, "/fallback"); got != "/" {
		t.Fatalf("absolute root local path = %q", got)
	}
	if got := localPath("", ""); got != "/" {
		t.Fatalf("empty local path = %q", got)
	}
	if got := localPath("custom", ""); got != "/custom" {
		t.Fatalf("relative local path = %q", got)
	}
	if got := localPath("/path", ""); got != "/path" {
		t.Fatalf("rooted local path = %q", got)
	}
	var nilApplies *AppliesTo
	if nilApplies.Address() != "" {
		t.Fatal("nil applies-to has address")
	}
}
