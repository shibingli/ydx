package saml

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/guomi"
	"github.com/shibingli/ydx/router"
	"github.com/shibingli/ydx/xml"
)

// samlTestNow is the fixed clock used by validation tests. | samlTestNow 是校验测试使用的固定时钟。
var samlTestNow = time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)

// samlTestKeyCert returns a fresh RSA key and self-signed certificate. | samlTestKeyCert 返回新的
// RSA 密钥与自签名证书。
func samlTestKeyCert(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "idp.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return key, cert
}

// samlValidResponse returns a well-formed Response carrying one bearer assertion. |
// samlValidResponse 返回携带一个承载断言的良构 Response。
func samlValidResponse(now time.Time) string {
	notBefore := FormatTime(now.Add(-time.Minute))
	expires := FormatTime(now.Add(5 * time.Minute))
	return `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="resp-1" Version="2.0" IssueInstant="` + FormatTime(now) + `" Destination="https://sp.example/saml/acs" InResponseTo="req-1">` +
		`<saml:Issuer>https://idp.example/metadata</saml:Issuer>` +
		`<samlp:Status><samlp:StatusCode Value="` + StatusSuccess + `"/></samlp:Status>` +
		`<saml:Assertion ID="assert-1" Version="2.0" IssueInstant="` + FormatTime(now) + `">` +
		`<saml:Issuer>https://idp.example/metadata</saml:Issuer>` +
		`<saml:Subject><saml:NameID Format="` + NameIDEmailAddress + `">alice@example.com</saml:NameID>` +
		`<saml:SubjectConfirmation Method="` + SubjectConfirmationBearer + `">` +
		`<saml:SubjectConfirmationData Recipient="https://sp.example/saml/acs" InResponseTo="req-1" NotOnOrAfter="` + expires + `"/>` +
		`</saml:SubjectConfirmation></saml:Subject>` +
		`<saml:Conditions NotBefore="` + notBefore + `" NotOnOrAfter="` + expires + `">` +
		`<saml:AudienceRestriction><saml:Audience>https://sp.example/metadata</saml:Audience></saml:AudienceRestriction>` +
		`</saml:Conditions>` +
		`<saml:AuthnStatement AuthnInstant="` + FormatTime(now) + `" SessionIndex="session-1">` +
		`<saml:AuthnContext><saml:AuthnContextClassRef>` + AuthnContextPasswordProtectedTransport + `</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>` +
		`<saml:AttributeStatement>` +
		`<saml:Attribute Name="mail"><saml:AttributeValue>alice@example.com</saml:AttributeValue></saml:Attribute>` +
		`<saml:Attribute Name="groups"><saml:AttributeValue>admins</saml:AttributeValue><saml:AttributeValue>users</saml:AttributeValue></saml:Attribute>` +
		`</saml:AttributeStatement></saml:Assertion></samlp:Response>`
}

// samlStoreWithRequest returns a store holding request req-1. | samlStoreWithRequest 返回保存了
// req-1 请求的存储。
func samlStoreWithRequest(t *testing.T) *MemoryStore {
	t.Helper()
	store := NewMemoryStore()
	if err := store.SaveRequest(context.Background(), &RequestState{
		ID:          "req-1",
		SPEntityID:  "https://sp.example/metadata",
		IDPEntityID: "https://idp.example/metadata",
		ACSURL:      "https://sp.example/saml/acs",
		RelayState:  "relay-1",
		CreatedAt:   samlTestNow,
		ExpiresAt:   samlTestNow.Add(10 * time.Minute),
	}); err != nil {
		t.Fatalf("save request: %v", err)
	}
	return store
}

// samlValidationOptions returns validating options bound to the fixed clock. |
// samlValidationOptions 返回绑定固定时钟的校验选项。
func samlValidationOptions(store Store) ResponseValidationOptions {
	return ResponseValidationOptions{
		SPEntityID:          "https://sp.example/metadata",
		ACSURL:              "https://sp.example/saml/acs",
		IDPEntityID:         "https://idp.example/metadata",
		Store:               store,
		RequireInResponseTo: true,
		Now:                 func() time.Time { return samlTestNow },
	}
}

// TestValidateResponseAcceptsValidDocument checks the positive path and result mapping. |
// TestValidateResponseAcceptsValidDocument 校验正路径与结果映射。
func TestValidateResponseAcceptsValidDocument(t *testing.T) {
	store := samlStoreWithRequest(t)
	result, err := ValidateResponse(context.Background(), []byte(samlValidResponse(samlTestNow)), samlValidationOptions(store))
	if err != nil {
		t.Fatalf("ValidateResponse: %v", err)
	}
	if result.NameID != "alice@example.com" || result.SessionIndex != "session-1" {
		t.Fatalf("result = %+v", result)
	}
	if result.RelayState != "relay-1" {
		t.Fatalf("relay state = %q", result.RelayState)
	}
	if result.Principal.Email != "alice@example.com" || result.Principal.Subject != "alice@example.com" {
		t.Fatalf("principal = %+v", result.Principal)
	}
	if len(result.Principal.Groups) != 2 || result.Principal.Groups[0] != "admins" {
		t.Fatalf("groups = %v", result.Principal.Groups)
	}
	if result.Attributes["groups"][1] != "users" {
		t.Fatalf("attributes = %v", result.Attributes)
	}
}

// TestValidateResponseRejectsInvalidDocuments drives the negative validation matrix. |
// TestValidateResponseRejectsInvalidDocuments 驱动负向校验矩阵。
func TestValidateResponseRejectsInvalidDocuments(t *testing.T) {
	valid := samlValidResponse(samlTestNow)
	expired := samlValidResponse(samlTestNow.Add(-time.Hour))
	future := samlValidResponse(samlTestNow.Add(time.Hour))
	signatureMarker := `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/>`
	cases := []struct {
		name string
		xml  string
		opts func(*ResponseValidationOptions)
		want error
	}{
		{name: "audience", xml: strings.Replace(valid, "https://sp.example/metadata</saml:Audience>", "https://other.example</saml:Audience>", 1), want: ErrInvalidAudience},
		{name: "recipient", xml: strings.Replace(valid, `Recipient="https://sp.example/saml/acs"`, `Recipient="https://evil.example/acs"`, 1), want: ErrInvalidResponse},
		{name: "destination", xml: strings.Replace(valid, `Destination="https://sp.example/saml/acs"`, `Destination="https://evil.example/acs"`, 1), want: ErrInvalidRecipient},
		{name: "destination missing", xml: strings.Replace(valid, ` Destination="https://sp.example/saml/acs"`, "", 1), opts: func(o *ResponseValidationOptions) {
			o.SignatureVerifier = SignatureVerifierFunc(func(context.Context, []byte, string) error { return nil })
		}, want: ErrInvalidRecipient},
		{name: "in response to conflict", xml: strings.Replace(valid, `InResponseTo="req-1"`, `InResponseTo="req-2"`, 1), want: ErrInvalidRequest},
		{name: "conditions expired", xml: expired, want: ErrResponseExpired},
		{name: "conditions future", xml: future, want: ErrInvalidResponse},
		{name: "version", xml: strings.Replace(valid, `Version="2.0"`, `Version="1.1"`, 1), want: ErrInvalidResponse},
		{name: "status", xml: strings.Replace(valid, StatusSuccess, StatusAuthnFailed, 1), want: ErrStatusFailure},
		{name: "issuer", xml: strings.Replace(valid, "https://idp.example/metadata</saml:Issuer>", "https://evil.example</saml:Issuer>", 1), want: ErrInvalidIssuer},
		{name: "missing response id", xml: strings.Replace(valid, `ID="resp-1" `, "", 1), want: ErrInvalidResponse},
		{name: "missing assertion id", xml: strings.Replace(valid, `ID="assert-1" `, "", 1), want: ErrInvalidResponse},
		{name: "nameid format", xml: valid, opts: func(o *ResponseValidationOptions) { o.AllowedNameIDFormats = []string{NameIDPersistent} }, want: ErrInvalidResponse},
		{name: "subject confirmation required", xml: strings.Replace(valid, `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData Recipient="https://sp.example/saml/acs" InResponseTo="req-1" NotOnOrAfter="`+FormatTime(samlTestNow.Add(5*time.Minute))+`"/></saml:SubjectConfirmation>`, "", 1), opts: func(o *ResponseValidationOptions) { o.RequireSubjectConfirmation = true }, want: ErrInvalidResponse},
		{name: "signed response required", xml: valid, opts: func(o *ResponseValidationOptions) { o.RequireSignedResponse = true }, want: ErrInvalidSignature},
		{name: "response signature without verifier", xml: strings.Replace(valid, "</saml:Issuer>", "</saml:Issuer>"+signatureMarker, 1), want: ErrInvalidSignature},
		{name: "assertion signature without verifier", xml: strings.Replace(valid, "</saml:Issuer>", "</saml:Issuer>"+signatureMarker, 2), want: ErrInvalidSignature},
		{name: "no assertion", xml: `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="resp-1" Version="2.0" IssueInstant="` + FormatTime(samlTestNow) + `"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example/metadata</saml:Issuer><samlp:Status><samlp:StatusCode Value="` + StatusSuccess + `"/></samlp:Status></samlp:Response>`, want: ErrNoAssertion},
		{name: "encrypted without decryptor", xml: strings.Replace(valid, `<saml:Assertion ID="assert-1"`, `<saml:EncryptedAssertion/><saml:Assertion ID="assert-1"`, 1)[:0] + `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="resp-1" Version="2.0" IssueInstant="` + FormatTime(samlTestNow) + `" Destination="https://sp.example/saml/acs"><saml:Issuer>https://idp.example/metadata</saml:Issuer><samlp:Status><samlp:StatusCode Value="` + StatusSuccess + `"/></samlp:Status><saml:EncryptedAssertion/></samlp:Response>`, want: ErrDecryption},
		{name: "request id required without store", xml: valid, opts: func(o *ResponseValidationOptions) { o.Store = nil }, want: ErrInvalidConfig},
		{name: "max issue age", xml: strings.Replace(valid, `IssueInstant="`+FormatTime(samlTestNow)+`"`, `IssueInstant="`+FormatTime(samlTestNow.Add(-time.Hour))+`"`, 1), opts: func(o *ResponseValidationOptions) { o.MaxIssueAge = time.Minute }, want: ErrInvalidResponse},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := samlStoreWithRequest(t)
			opts := samlValidationOptions(store)
			if tc.opts != nil {
				tc.opts(&opts)
			}
			_, err := ValidateResponse(context.Background(), []byte(tc.xml), opts)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestValidateResponseStoreSemantics checks replay, correlation and request-state mismatches. |
// TestValidateResponseStoreSemantics 校验重放、关联与请求状态不匹配。
func TestValidateResponseStoreSemantics(t *testing.T) {
	replayDoc := []byte(strings.ReplaceAll(samlValidResponse(samlTestNow), ` InResponseTo="req-1"`, ""))
	valid := []byte(samlValidResponse(samlTestNow))
	store := samlStoreWithRequest(t)
	opts := samlValidationOptions(store)
	opts.RequireInResponseTo = false
	if _, err := ValidateResponse(context.Background(), replayDoc, opts); err != nil {
		t.Fatalf("first validation: %v", err)
	}
	if _, err := ValidateResponse(context.Background(), replayDoc, opts); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay error = %v, want ErrReplay", err)
	}

	unknownStore := NewMemoryStore()
	unknown := samlValidationOptions(unknownStore)
	if _, err := ValidateResponse(context.Background(), valid, unknown); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("unknown request error = %v, want ErrInvalidRequest", err)
	}

	acsStore := NewMemoryStore()
	if err := acsStore.SaveRequest(context.Background(), &RequestState{ID: "req-1", ACSURL: "https://other.example/acs", SPEntityID: "https://sp.example/metadata"}); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateResponse(context.Background(), valid, samlValidationOptions(acsStore)); !errors.Is(err, ErrInvalidRecipient) {
		t.Fatalf("ACS mismatch error = %v, want ErrInvalidRecipient", err)
	}

	spStore := NewMemoryStore()
	if err := spStore.SaveRequest(context.Background(), &RequestState{ID: "req-1", ACSURL: "https://sp.example/saml/acs", SPEntityID: "https://other.example"}); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateResponse(context.Background(), valid, samlValidationOptions(spStore)); !errors.Is(err, ErrInvalidAudience) {
		t.Fatalf("SP mismatch error = %v, want ErrInvalidAudience", err)
	}
}

// fakeDecryptor returns canned assertion bytes. | fakeDecryptor 返回预设断言字节。
type fakeDecryptor struct {
	document []byte
	err      error
}

// DecryptAssertion implements EncryptedAssertionDecryptor. | DecryptAssertion 实现
// EncryptedAssertionDecryptor。
func (f fakeDecryptor) DecryptAssertion(context.Context, *EncryptedAssertion) ([]byte, error) {
	return f.document, f.err
}

// TestValidateEncryptedAssertion exercises decryption paths. | TestValidateEncryptedAssertion 覆盖
// 解密路径。
func TestValidateEncryptedAssertion(t *testing.T) {
	now := samlTestNow
	response := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="resp-1" Version="2.0" IssueInstant="` + FormatTime(now) + `" Destination="https://sp.example/saml/acs">` +
		`<saml:Issuer>https://idp.example/metadata</saml:Issuer>` +
		`<samlp:Status><samlp:StatusCode Value="` + StatusSuccess + `"/></samlp:Status>` +
		`<saml:EncryptedAssertion/>` +
		`</samlp:Response>`
	opts := samlValidationOptions(nil)
	opts.RequireInResponseTo = false
	opts.Decryptor = fakeDecryptor{err: errors.New("boom")}
	if _, err := ValidateResponse(context.Background(), []byte(response), opts); !errors.Is(err, ErrDecryption) {
		t.Fatalf("decrypt failure error = %v, want ErrDecryption", err)
	}
	opts.Decryptor = fakeDecryptor{document: []byte(`<not-an-assertion`)}
	if _, err := ValidateResponse(context.Background(), []byte(response), opts); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("malformed decrypted error = %v, want ErrInvalidResponse", err)
	}
	assertion := `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="assert-1" Version="2.0" IssueInstant="` + FormatTime(now) + `">` +
		`<saml:Issuer>https://idp.example/metadata</saml:Issuer>` +
		`<saml:Subject><saml:NameID Format="` + NameIDEmailAddress + `">alice@example.com</saml:NameID>` +
		`<saml:SubjectConfirmation Method="` + SubjectConfirmationBearer + `"><saml:SubjectConfirmationData Recipient="https://sp.example/saml/acs" NotOnOrAfter="` + FormatTime(now.Add(5*time.Minute)) + `"/></saml:SubjectConfirmation></saml:Subject>` +
		`<saml:Conditions NotOnOrAfter="` + FormatTime(now.Add(5*time.Minute)) + `"><saml:AudienceRestriction><saml:Audience>https://sp.example/metadata</saml:Audience></saml:AudienceRestriction></saml:Conditions>` +
		`</saml:Assertion>`
	opts.Decryptor = fakeDecryptor{document: []byte(assertion)}
	result, err := ValidateResponse(context.Background(), []byte(response), opts)
	if err != nil {
		t.Fatalf("decrypted assertion: %v", err)
	}
	if result.NameID != "alice@example.com" {
		t.Fatalf("nameid = %q", result.NameID)
	}
}

// TestValidateAuthnRequest covers request validation and status mapping. |
// TestValidateAuthnRequest 覆盖请求校验与状态映射。
func TestValidateAuthnRequest(t *testing.T) {
	now := samlTestNow
	valid := &AuthnRequest{
		ID:                          "id-1",
		Version:                     Version,
		IssueInstant:                FormatTime(now),
		Destination:                 "https://idp.example/sso",
		AssertionConsumerServiceURL: "https://sp.example/saml/acs",
		Issuer:                      &Issuer{Value: "https://sp.example/metadata"},
	}
	opts := AuthnRequestValidationOptions{IDPEntityID: "https://idp.example/metadata", SSOURL: "https://idp.example/sso", Now: func() time.Time { return now }}
	if err := ValidateAuthnRequest(context.Background(), valid, opts); err != nil {
		t.Fatalf("valid request: %v", err)
	}
	if err := ValidateAuthnRequest(context.Background(), nil, opts); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil error = %v", err)
	}
	mutate := func(f func(*AuthnRequest)) *AuthnRequest {
		copy := *valid
		f(&copy)
		return &copy
	}
	cases := []struct {
		name string
		req  *AuthnRequest
		want error
	}{
		{name: "version", req: mutate(func(r *AuthnRequest) { r.Version = "1.1" }), want: ErrInvalidRequest},
		{name: "id", req: mutate(func(r *AuthnRequest) { r.ID = "" }), want: ErrInvalidRequest},
		{name: "instant", req: mutate(func(r *AuthnRequest) { r.IssueInstant = "" }), want: ErrInvalidRequest},
		{name: "issuer", req: mutate(func(r *AuthnRequest) { r.Issuer = nil }), want: ErrInvalidIssuer},
		{name: "destination", req: mutate(func(r *AuthnRequest) { r.Destination = "https://evil.example/sso" }), want: ErrInvalidRecipient},
		{name: "destination missing", req: mutate(func(r *AuthnRequest) { r.Destination = "" }), want: ErrInvalidRecipient},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateAuthnRequest(context.Background(), tc.req, opts); !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
	resolver := staticResolver{metadata: &EntityDescriptor{
		EntityID: "https://sp.example/metadata",
		SPSSODescriptor: &SPSSODescriptor{
			AssertionConsumerService: []IndexedEndpoint{{Binding: BindingHTTPPost, Location: "https://sp.example/saml/acs"}},
		},
	}}
	withResolver := opts
	withResolver.SPResolver = resolver
	if err := ValidateAuthnRequest(context.Background(), valid, withResolver); err != nil {
		t.Fatalf("resolver request: %v", err)
	}
	unregistered := mutate(func(r *AuthnRequest) { r.AssertionConsumerServiceURL = "https://evil.example/acs" })
	if err := ValidateAuthnRequest(context.Background(), unregistered, withResolver); !errors.Is(err, ErrInvalidRecipient) {
		t.Fatalf("unregistered ACS error = %v", err)
	}
	missingACS := mutate(func(r *AuthnRequest) { r.AssertionConsumerServiceURL = "" })
	emptyResolver := opts
	emptyResolver.SPResolver = staticResolver{metadata: &EntityDescriptor{EntityID: "https://sp.example/metadata", SPSSODescriptor: &SPSSODescriptor{}}}
	if err := ValidateAuthnRequest(context.Background(), missingACS, emptyResolver); !errors.Is(err, ErrInvalidRecipient) {
		t.Fatalf("missing ACS error = %v", err)
	}
	resolveErr := opts
	resolveErr.SPResolver = staticResolver{err: ErrInvalidMetadata}
	if err := ValidateAuthnRequest(context.Background(), valid, resolveErr); !errors.Is(err, ErrInvalidIssuer) {
		t.Fatalf("resolver failure error = %v", err)
	}
	if StatusError(nil) != StatusSuccess || StatusError(ErrInvalidAudience) != StatusRequester || StatusError(ErrInvalidResponse) != StatusResponder {
		t.Fatal("StatusError mapping mismatch")
	}
}

// staticResolver is a MetadataResolver backed by one descriptor or one error. | staticResolver 是
// 由一个描述符或一个错误支撑的 MetadataResolver。
type staticResolver struct {
	metadata *EntityDescriptor
	err      error
}

// Resolve implements MetadataResolver. | Resolve 实现 MetadataResolver。
func (r staticResolver) Resolve(context.Context, string) (*EntityDescriptor, error) {
	if r.err != nil {
		return nil, r.err
	}
	return r.metadata, nil
}

// TestSignedSSOEndToEnd runs a signed Redirect request and signed POST response. |
// TestSignedSSOEndToEnd 运行已签名的 Redirect 请求与已签名的 POST 响应。
func TestSignedSSOEndToEnd(t *testing.T) {
	key, cert := samlTestKeyCert(t)
	spStore := NewMemoryStore()
	sp, err := NewServiceProvider(ServiceProviderConfig{
		EntityID:               "https://sp.example/metadata",
		ACSURL:                 "https://sp.example/saml/acs",
		SLOURL:                 "https://sp.example/slo",
		IDPMetadata:            testMetadata(),
		Store:                  spStore,
		RequestSigningKey:      key,
		SignatureVerifier:      &XMLDSigVerifier{Certificates: []*x509.Certificate{cert}},
		RequireSignedAssertion: true,
		RequireSignedResponse:  true,
	})
	if err != nil {
		t.Fatalf("sp: %v", err)
	}
	authnURL, err := sp.AuthnRequestURL("relay-1")
	if err != nil {
		t.Fatalf("authn url: %v", err)
	}
	parsed, err := url.Parse(authnURL)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Query().Get("Signature") == "" || parsed.Query().Get("SigAlg") != SigAlgRSASHA256 {
		t.Fatalf("request not signed: %s", authnURL)
	}

	idp, err := NewIdentityProvider(IdentityProviderConfig{
		EntityID: "https://idp.example/metadata",
		SSOURL:   "https://idp.example/sso",
		Store:    NewMemoryStore(),
		Authenticator: AuthenticatorFunc(func(context.Context, http.ResponseWriter, *http.Request, *AuthnRequest) (*auth.Principal, error) {
			return &auth.Principal{Subject: "user-1", Email: "alice@example.com", DisplayName: "Alice", AuthTime: samlTestNow}, nil
		}),
		Signer:        &XMLDSigSigner{PrivateKey: key, Certificate: cert, Exclusive: true, InclusiveNamespaces: []string{"saml", "samlp"}},
		SignResponse:  true,
		SignAssertion: true,
		RedirectVerifier: func(_ context.Context, rawQuery string, _ url.Values, issuer, _ string) error {
			if issuer != "https://sp.example/metadata" {
				return ErrInvalidIssuer
			}
			return VerifyRedirectRawQuery(rawQuery, "SAMLRequest", []*x509.Certificate{cert}, nil, nil)
		},
	})
	if err != nil {
		t.Fatalf("idp: %v", err)
	}
	ssoReq := httptest.NewRequest(http.MethodGet, parsed.String(), nil)
	w := httptest.NewRecorder()
	idp.HandleSSO(w, ssoReq)
	if w.Code != http.StatusOK {
		t.Fatalf("sso status = %d body=%s", w.Code, w.Body.String())
	}
	responseValue := extractHiddenValue(w.Body.String(), "SAMLResponse")
	if responseValue == "" {
		t.Fatalf("missing SAMLResponse: %s", w.Body.String())
	}
	responseXML, err := DecodePost(responseValue)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(responseXML, []byte("ds:Signature")) {
		t.Fatalf("response is not signature-prefixed: %s", responseXML)
	}
	acsReq := httptest.NewRequest(http.MethodPost, "/acs", strings.NewReader(url.Values{
		"SAMLResponse": {responseValue},
		"RelayState":   {"relay-1"},
	}.Encode()))
	acsReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	result, err := sp.ParseResponse(acsReq)
	if err != nil {
		t.Fatalf("parse signed response: %v", err)
	}
	if result.Principal.Subject != "user-1" || result.RelayState != "relay-1" {
		t.Fatalf("result = %+v", result)
	}
}

// TestHandleSSOErrorPaths covers IdP request rejection, passive and login handling. |
// TestHandleSSOErrorPaths 覆盖 IdP 请求拒绝、被动与登录处理。
func TestHandleSSOErrorPaths(t *testing.T) {
	newIDP := func(authenticator Authenticator, config func(*IdentityProviderConfig)) *IdentityProvider {
		cfg := IdentityProviderConfig{
			EntityID:      "https://idp.example/metadata",
			SSOURL:        "https://idp.example/sso",
			LoginURL:      "https://idp.example/login",
			Store:         NewMemoryStore(),
			Authenticator: authenticator,
		}
		if config != nil {
			config(&cfg)
		}
		idp, err := NewIdentityProvider(cfg)
		if err != nil {
			t.Fatalf("idp: %v", err)
		}
		return idp
	}
	requestXML := func(mutate func(*AuthnRequest)) string {
		request := AuthnRequest{
			ID:                          "id-1",
			Version:                     Version,
			IssueInstant:                FormatTime(time.Now()),
			Destination:                 "https://idp.example/sso",
			AssertionConsumerServiceURL: "https://sp.example/saml/acs",
			Issuer:                      &Issuer{Value: "https://sp.example/metadata"},
			ProtocolBinding:             BindingHTTPPost,
		}
		if mutate != nil {
			mutate(&request)
		}
		data, err := xmlMarshal(&request)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return EncodePost(data)
	}
	post := func(value string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/sso", strings.NewReader(url.Values{"SAMLRequest": {value}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return r
	}
	alice := AuthenticatorFunc(func(context.Context, http.ResponseWriter, *http.Request, *AuthnRequest) (*auth.Principal, error) {
		return &auth.Principal{Subject: "alice", Email: "alice@example.com"}, nil
	})

	idp := newIDP(alice, nil)
	w := httptest.NewRecorder()
	idp.HandleSSO(w, post(requestXML(nil)))
	if w.Code != http.StatusOK || extractHiddenValue(w.Body.String(), "SAMLResponse") == "" {
		t.Fatalf("happy sso status = %d", w.Code)
	}

	idp = newIDP(alice, nil)
	w = httptest.NewRecorder()
	idp.HandleSSO(w, post(requestXML(func(r *AuthnRequest) { r.ProtocolBinding = BindingHTTPRedirect })))
	responseXML, err := DecodePost(extractHiddenValue(w.Body.String(), "SAMLResponse"))
	if err != nil || !bytes.Contains(responseXML, []byte(StatusRequestUnsupported)) {
		t.Fatalf("binding rejection response = %s err=%v", w.Body.String(), err)
	}

	idp = newIDP(alice, nil)
	w = httptest.NewRecorder()
	idp.HandleSSO(w, post(requestXML(func(r *AuthnRequest) { r.AssertionConsumerServiceURL = "javascript:alert(1)" })))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("bad ACS status = %d", w.Code)
	}

	idp = newIDP(AuthenticatorFunc(func(context.Context, http.ResponseWriter, *http.Request, *AuthnRequest) (*auth.Principal, error) {
		return nil, ErrLoginRequired
	}), nil)
	w = httptest.NewRecorder()
	idp.HandleSSO(w, post(requestXML(nil)))
	if w.Code != http.StatusFound || !strings.Contains(w.Header().Get("Location"), "return_to=") {
		t.Fatalf("login redirect status = %d location=%q", w.Code, w.Header().Get("Location"))
	}

	w = httptest.NewRecorder()
	idp.HandleSSO(w, post(requestXML(func(r *AuthnRequest) { r.IsPassive = true })))
	responseXML, err = DecodePost(extractHiddenValue(w.Body.String(), "SAMLResponse"))
	if err != nil || !bytes.Contains(responseXML, []byte(StatusNoPassive)) {
		t.Fatalf("passive response = %s err=%v", w.Body.String(), err)
	}

	idp = newIDP(alice, func(c *IdentityProviderConfig) {
		c.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
			w.WriteHeader(http.StatusTeapot)
			_, _ = w.Write([]byte(err.Error()))
		}
	})
	w = httptest.NewRecorder()
	idp.HandleSSO(w, post("not-base64"))
	if w.Code != http.StatusTeapot {
		t.Fatalf("error handler status = %d", w.Code)
	}

	idp = newIDP(alice, func(c *IdentityProviderConfig) { c.WantAuthnRequestsSigned = true })
	w = httptest.NewRecorder()
	idp.HandleSSO(w, post(requestXML(nil)))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("signed request required status = %d", w.Code)
	}

	idp = newIDP(AuthenticatorFunc(func(context.Context, http.ResponseWriter, *http.Request, *AuthnRequest) (*auth.Principal, error) {
		return &auth.Principal{Subject: "alice", ACR: AuthnContextPassword}, nil
	}), nil)
	w = httptest.NewRecorder()
	idp.HandleSSO(w, post(requestXML(func(r *AuthnRequest) {
		r.RequestedAuthnContext = &RequestedAuthnContext{Comparison: "exact", AuthnContextClassRef: []string{AuthnContextPasswordProtectedTransport}}
	})))
	responseXML, err = DecodePost(extractHiddenValue(w.Body.String(), "SAMLResponse"))
	if err != nil || !bytes.Contains(responseXML, []byte(StatusNoAuthnContext)) {
		t.Fatalf("authn context response = %s err=%v", w.Body.String(), err)
	}
}

// xmlMarshal marshals a SAML model value through the repository XML wrapper. | xmlMarshal 通过
// 仓库 XML 包装层编组 SAML 模型值。
func xmlMarshal(value any) ([]byte, error) {
	return xml.Marshal(value)
}

// TestSignedSLOEndToEnd runs SP-initiated logout with signed redirect binding. |
// TestSignedSLOEndToEnd 运行使用已签名 Redirect 绑定的 SP 发起登出。
func TestSignedSLOEndToEnd(t *testing.T) {
	key, cert := samlTestKeyCert(t)
	spMetadata := &EntityDescriptor{
		EntityID: "https://sp.example/metadata",
		SPSSODescriptor: &SPSSODescriptor{
			ProtocolSupportEnumeration: NamespaceProtocol,
			AssertionConsumerService:   []IndexedEndpoint{{Binding: BindingHTTPPost, Location: "https://sp.example/saml/acs"}},
			SingleLogoutService: []Endpoint{
				{Binding: BindingHTTPPost, Location: "https://sp.example/slo"},
				{Binding: BindingHTTPRedirect, Location: "https://sp.example/slo"},
			},
		},
	}
	sp, err := NewServiceProvider(ServiceProviderConfig{
		EntityID:          "https://sp.example/metadata",
		ACSURL:            "https://sp.example/saml/acs",
		SLOURL:            "https://sp.example/slo",
		IDPMetadata:       testMetadata(),
		Store:             NewMemoryStore(),
		RequestSigningKey: key,
		SignatureVerifier: &XMLDSigVerifier{Certificates: []*x509.Certificate{cert}},
		RedirectVerifier: func(_ context.Context, rawQuery string, _ url.Values, issuer, _ string) error {
			if issuer != "https://idp.example/metadata" {
				return ErrInvalidIssuer
			}
			return VerifyRedirectRawQuery(rawQuery, "SAMLResponse", []*x509.Certificate{cert}, nil, nil)
		},
	})
	if err != nil {
		t.Fatalf("sp: %v", err)
	}
	if err := sp.Store().SaveSession(context.Background(), &Session{ID: "session-1", NameID: "alice@example.com", SPEntityID: "https://sp.example/metadata", IDPEntityID: "https://idp.example/metadata"}); err != nil {
		t.Fatal(err)
	}
	idp, err := NewIdentityProvider(IdentityProviderConfig{
		EntityID: "https://idp.example/metadata",
		SSOURL:   "https://idp.example/sso",
		SLOURL:   "https://idp.example/slo",
		Store:    NewMemoryStore(),
		Authenticator: AuthenticatorFunc(func(context.Context, http.ResponseWriter, *http.Request, *AuthnRequest) (*auth.Principal, error) {
			return &auth.Principal{Subject: "alice"}, nil
		}),
		SPResolver:        staticResolver{metadata: spMetadata},
		Signer:            &XMLDSigSigner{PrivateKey: key, Certificate: cert},
		SigningKey:        key,
		SigningAlg:        SigAlgRSASHA256,
		SignatureVerifier: &XMLDSigVerifier{Certificates: []*x509.Certificate{cert}},
		RedirectVerifier: func(_ context.Context, rawQuery string, _ url.Values, issuer, _ string) error {
			if issuer != "https://sp.example/metadata" {
				return ErrInvalidIssuer
			}
			return VerifyRedirectRawQuery(rawQuery, "SAMLRequest", []*x509.Certificate{cert}, nil, nil)
		},
	})
	if err != nil {
		t.Fatalf("idp: %v", err)
	}
	if err := idp.Store().SaveSession(context.Background(), &Session{ID: "session-1", NameID: "alice@example.com", SPEntityID: "https://sp.example/metadata"}); err != nil {
		t.Fatal(err)
	}
	logoutURL, err := sp.LogoutRequestURL("alice@example.com", "session-1", "logout-relay")
	if err != nil {
		t.Fatalf("logout url: %v", err)
	}
	parsed, err := url.Parse(logoutURL)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Query().Get("Signature") == "" {
		t.Fatalf("logout request is not signed: %s", logoutURL)
	}
	w := httptest.NewRecorder()
	idp.HandleSLO(w, httptest.NewRequest(http.MethodGet, parsed.String(), nil))
	if w.Code != http.StatusFound {
		t.Fatalf("idp slo status = %d body=%s", w.Code, w.Body.String())
	}
	location, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if location.Query().Get("SAMLResponse") == "" || location.Query().Get("Signature") == "" {
		t.Fatalf("logout response location = %s", location)
	}
	if _, err := idp.Store().GetSession(context.Background(), "session-1"); err == nil {
		t.Fatal("idp session was not terminated")
	}
	w = httptest.NewRecorder()
	sp.HandleSLO(w, httptest.NewRequest(http.MethodGet, location.String(), nil))
	if w.Code != http.StatusOK || w.Body.String() != "logged out" {
		t.Fatalf("sp slo status = %d body=%s", w.Code, w.Body.String())
	}

	// A replayed LogoutResponse must be rejected. | 重放的 LogoutResponse 必须被拒绝。
	w = httptest.NewRecorder()
	sp.HandleSLO(w, httptest.NewRequest(http.MethodGet, location.String(), nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("replayed logout response status = %d", w.Code)
	}
}

// TestIdPInitiatedSLOAndPartialLogout checks POST logout and partial logout handling. |
// TestIdPInitiatedSLOAndPartialLogout 校验 POST 登出与部分登出处理。
func TestIdPInitiatedSLOAndPartialLogout(t *testing.T) {
	sp, err := NewServiceProvider(ServiceProviderConfig{
		EntityID:    "https://sp.example/metadata",
		ACSURL:      "https://sp.example/saml/acs",
		SLOURL:      "https://sp.example/slo",
		IDPMetadata: testMetadata(),
		Store:       NewMemoryStore(),
	})
	if err != nil {
		t.Fatalf("sp: %v", err)
	}
	now := time.Now().UTC()
	request := &LogoutRequest{
		ID:           "logout-1",
		Version:      Version,
		IssueInstant: FormatTime(now),
		Destination:  "https://sp.example/slo",
		NotOnOrAfter: FormatTime(now.Add(5 * time.Minute)),
		Issuer:       &Issuer{Value: "https://idp.example/metadata"},
		NameID:       NewNameID(NameIDUnspecified, "alice@example.com"),
		SessionIndex: []string{"missing-session"},
	}
	document, err := xml.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	post := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/slo", strings.NewReader(url.Values{"SAMLRequest": {EncodePost(document)}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return r
	}
	w := httptest.NewRecorder()
	sp.HandleSLO(w, post())
	if w.Code != http.StatusOK {
		t.Fatalf("partial logout status = %d body=%s", w.Code, w.Body.String())
	}
	responseXML, err := DecodePost(extractHiddenValue(w.Body.String(), "SAMLResponse"))
	if err != nil {
		t.Fatal(err)
	}
	response, err := DecodeLogoutResponse(responseXML)
	if err != nil {
		t.Fatal(err)
	}
	if response.Status == nil || response.Status.StatusCode == nil || response.Status.StatusCode.StatusCode == nil || response.Status.StatusCode.StatusCode.Value != StatusPartialLogout {
		t.Fatalf("status = %+v", response.Status)
	}
	w = httptest.NewRecorder()
	sp.HandleSLO(w, post())
	if w.Code != http.StatusBadRequest {
		t.Fatalf("replayed logout request status = %d", w.Code)
	}
}

// TestMetadataValidateAndHelpers covers parsing, validation, certificates and endpoints. |
// TestMetadataValidateAndHelpers 覆盖解析、校验、证书与端点。
func TestMetadataValidateAndHelpers(t *testing.T) {
	_, cert := samlTestKeyCert(t)
	encoded := base64.StdEncoding.EncodeToString(cert.Raw)
	metadata := &EntityDescriptor{
		EntityID:      "https://idp.example/metadata",
		ValidUntil:    FormatTime(samlTestNow.Add(time.Hour)),
		CacheDuration: "P1DT2H",
		IDPSSODescriptor: &IDPSSODescriptor{
			ProtocolSupportEnumeration: NamespaceProtocol,
			KeyDescriptor: []KeyDescriptor{
				{Use: "signing", KeyInfo: &KeyInfo{X509Data: []X509Data{{X509Certificate: []string{encoded}}}}},
				{Use: "encryption", KeyInfo: &KeyInfo{X509Data: []X509Data{{X509Certificate: []string{encoded}}}}},
			},
			SingleSignOnService: []Endpoint{{Binding: BindingHTTPRedirect, Location: "https://idp.example/sso"}},
			SingleLogoutService: []Endpoint{{Binding: BindingHTTPRedirect, Location: "https://idp.example/slo"}},
		},
	}
	if err := metadata.Validate(samlTestNow); err != nil {
		t.Fatalf("validate: %v", err)
	}
	signingCerts, err := metadata.SigningCertificates()
	if err != nil || len(signingCerts) != 1 {
		t.Fatalf("signing certs = %v err=%v", signingCerts, err)
	}
	encryptionCerts, err := metadata.EncryptionCertificates()
	if err != nil || len(encryptionCerts) != 1 {
		t.Fatalf("encryption certs = %v err=%v", encryptionCerts, err)
	}
	if metadata.SSOURL(BindingHTTPPost) != "https://idp.example/sso" || metadata.SLOURL(BindingHTTPPost) != "https://idp.example/slo" {
		t.Fatalf("endpoint fallback failed")
	}
	if metadata.ACSURL("") != "" || (*EntityDescriptor)(nil).SSOURL("") != "" {
		t.Fatal("nil descriptor endpoint should be empty")
	}
	data, err := metadata.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	parsed, err := ParseEntityDescriptor(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.EntityID != metadata.EntityID {
		t.Fatalf("parsed entity = %q", parsed.EntityID)
	}
	if _, err := ParseEntityDescriptor([]byte(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"/>`)); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("missing entityID error = %v", err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if _, err := ParseCertificatePEM(pemData); err != nil {
		t.Fatalf("parse pem: %v", err)
	}
	if _, err := ParseCertificatePEM([]byte("nope")); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("bad pem error = %v", err)
	}
	badCertMetadata := &EntityDescriptor{EntityID: "x", IDPSSODescriptor: &IDPSSODescriptor{KeyDescriptor: []KeyDescriptor{{KeyInfo: &KeyInfo{X509Data: []X509Data{{X509Certificate: []string{"!!!"}}}}}}}}
	if _, err := badCertMetadata.Certificates(""); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("bad certificate error = %v", err)
	}
}

// TestMetadataValidateErrors covers role, expiry and duration validation. |
// TestMetadataValidateErrors 覆盖角色、过期与时长校验。
func TestMetadataValidateErrors(t *testing.T) {
	if err := (*EntityDescriptor)(nil).Validate(samlTestNow); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("nil error = %v", err)
	}
	noRole := &EntityDescriptor{EntityID: "x"}
	if err := noRole.Validate(samlTestNow); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("no role error = %v", err)
	}
	bothRoles := &EntityDescriptor{EntityID: "x", IDPSSODescriptor: &IDPSSODescriptor{}, SPSSODescriptor: &SPSSODescriptor{}}
	if err := bothRoles.Validate(samlTestNow); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("both roles error = %v", err)
	}
	expired := &EntityDescriptor{EntityID: "x", ValidUntil: FormatTime(samlTestNow.Add(-time.Hour)), IDPSSODescriptor: &IDPSSODescriptor{}}
	if err := expired.Validate(samlTestNow); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("expired error = %v", err)
	}
	badValid := &EntityDescriptor{EntityID: "x", ValidUntil: "yesterday", IDPSSODescriptor: &IDPSSODescriptor{}}
	if err := badValid.Validate(samlTestNow); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("bad validUntil error = %v", err)
	}
	badCache := &EntityDescriptor{EntityID: "x", CacheDuration: "1H", IDPSSODescriptor: &IDPSSODescriptor{}}
	if err := badCache.Validate(samlTestNow); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("bad cache error = %v", err)
	}
	for _, duration := range []string{"P1Y2M3DT4H5M6S", "-P1D", "PT30M", "PT0.5S"} {
		descriptor := &EntityDescriptor{EntityID: "x", CacheDuration: duration, IDPSSODescriptor: &IDPSSODescriptor{}}
		if err := descriptor.Validate(samlTestNow); err != nil {
			t.Fatalf("duration %q: %v", duration, err)
		}
	}
	for _, duration := range []string{"P", "PT", "P1H", "1D", "Pd", "P1D1Y", "P1Y1Y", "PT1S1M", "PT1.5H"} {
		descriptor := &EntityDescriptor{EntityID: "x", CacheDuration: duration, IDPSSODescriptor: &IDPSSODescriptor{}}
		if err := descriptor.Validate(samlTestNow); !errors.Is(err, ErrInvalidMetadata) {
			t.Fatalf("duration %q error = %v", duration, err)
		}
	}
}

// TestBindingRoundTripsAndNegatives covers both bindings and their limits. |
// TestBindingRoundTripsAndNegatives 覆盖两种绑定及其限制。
func TestBindingRoundTripsAndNegatives(t *testing.T) {
	document := []byte(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id-1"/>`)
	post := EncodePost(document)
	if decoded, err := DecodePost(post); err != nil || !bytes.Equal(decoded, document) {
		t.Fatalf("post roundtrip = %q err=%v", decoded, err)
	}
	spaced := post[:10] + "\r\n\t" + post[10:]
	if decoded, err := DecodePost(spaced); err != nil || !bytes.Equal(decoded, document) {
		t.Fatalf("spaced post = %q err=%v", decoded, err)
	}
	if _, err := DecodePost("!!!"); err == nil {
		t.Fatal("invalid post accepted")
	}
	encoded, err := EncodeRedirect(document)
	if err != nil {
		t.Fatalf("encode redirect: %v", err)
	}
	if decoded, err := DecodeRedirect(encoded); err != nil || !bytes.Equal(decoded, document) {
		t.Fatalf("redirect roundtrip = %q err=%v", decoded, err)
	}
	var compressed bytes.Buffer
	zw := zlib.NewWriter(&compressed)
	_, _ = zw.Write(document)
	_ = zw.Close()
	if decoded, err := DecodeRedirect(base64.StdEncoding.EncodeToString(compressed.Bytes())); err != nil || !bytes.Equal(decoded, document) {
		t.Fatalf("zlib redirect = %q err=%v", decoded, err)
	}
	if _, err := DecodeRedirect("!!!"); err == nil {
		t.Fatal("invalid redirect accepted")
	}
	if _, err := readAllLimited(bytes.NewReader(make([]byte, 32)), 16); !errors.Is(err, ErrLimit) {
		t.Fatalf("read limit error = %v", err)
	}
	if RedirectSigningString("req", "relay", SigAlgRSASHA256) != RedirectSigningStringFor("SAMLRequest", "req", "relay", SigAlgRSASHA256) {
		t.Fatal("signing string mismatch")
	}
	if err := validateRedirectParameter("SAMLResponse"); err != nil {
		t.Fatalf("valid parameter: %v", err)
	}
	if err := validateRedirectParameter("Other"); !errors.Is(err, ErrInvalidBinding) {
		t.Fatalf("bad parameter error = %v", err)
	}
}

// TestRedirectSignatureAlgorithms signs and verifies every supported Redirect method. |
// TestRedirectSignatureAlgorithms 对每种支持的 Redirect 方法签名并校验。
func TestRedirectSignatureAlgorithms(t *testing.T) {
	rsaKey, rsaCert := samlTestKeyCert(t)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecCert := samlTestCertificateFor(t, ecKey, &ecKey.PublicKey)
	edPub, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edCert := samlTestCertificateFor(t, edKey, edPub)
	sm2Key, err := guomi.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("0123456789abcdef0123456789abcdef")
	cases := []struct {
		name string
		key  any
		alg  string
		opts func() ([]*x509.Certificate, []byte, *guomi.PublicKey)
	}{
		{name: "rsa-sha256", key: rsaKey, alg: SigAlgRSASHA256, opts: func() ([]*x509.Certificate, []byte, *guomi.PublicKey) { return []*x509.Certificate{rsaCert}, nil, nil }},
		{name: "rsa-sha384", key: rsaKey, alg: SigAlgRSASHA384, opts: func() ([]*x509.Certificate, []byte, *guomi.PublicKey) { return []*x509.Certificate{rsaCert}, nil, nil }},
		{name: "rsa-sha512", key: rsaKey, alg: SigAlgRSASHA512, opts: func() ([]*x509.Certificate, []byte, *guomi.PublicKey) { return []*x509.Certificate{rsaCert}, nil, nil }},
		{name: "rsa-pss", key: rsaKey, alg: SigAlgRSAPSSSHA256, opts: func() ([]*x509.Certificate, []byte, *guomi.PublicKey) { return []*x509.Certificate{rsaCert}, nil, nil }},
		{name: "ecdsa", key: ecKey, alg: SigAlgECDSASHA256, opts: func() ([]*x509.Certificate, []byte, *guomi.PublicKey) { return []*x509.Certificate{ecCert}, nil, nil }},
		{name: "ed25519", key: edKey, alg: SigAlgEd25519, opts: func() ([]*x509.Certificate, []byte, *guomi.PublicKey) { return []*x509.Certificate{edCert}, nil, nil }},
		{name: "hmac", key: secret, alg: SigAlgHMACSHA256, opts: func() ([]*x509.Certificate, []byte, *guomi.PublicKey) { return nil, secret, nil }},
		{name: "sm2", key: sm2Key, alg: SigAlgSM2SM3, opts: func() ([]*x509.Certificate, []byte, *guomi.PublicKey) { return nil, nil, sm2Key.Public() }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			params := url.Values{"SAMLRequest": {"payload"}, "RelayState": {"relay"}}
			if err := SignRedirect(params, tc.key, tc.alg, "relay"); err != nil {
				t.Fatalf("sign: %v", err)
			}
			if params.Get("SigAlg") != tc.alg || params.Get("Signature") == "" {
				t.Fatalf("params = %v", params)
			}
			certs, hmacKey, sm2Pub := tc.opts()
			if err := VerifyRedirect(params, certs, hmacKey, sm2Pub, "relay"); err != nil {
				t.Fatalf("verify: %v", err)
			}
			if err := VerifyRedirectRawQuery(params.Encode(), "SAMLRequest", certs, hmacKey, sm2Pub); err != nil {
				t.Fatalf("verify raw query: %v", err)
			}
			tampered := url.Values{"SAMLRequest": {"other"}, "RelayState": {"relay"}}
			for key, values := range params {
				if key != "SAMLRequest" {
					tampered[key] = values
				}
			}
			if err := VerifyRedirect(tampered, certs, hmacKey, sm2Pub, "relay"); err == nil {
				t.Fatal("tampered message accepted")
			}
		})
	}
	params := url.Values{"SAMLResponse": {"payload"}}
	if err := SignRedirectMessage(params, "SAMLResponse", rsaKey, SigAlgRSASHA256, ""); err != nil {
		t.Fatalf("sign response: %v", err)
	}
	if err := VerifyRedirectMessage(params, "SAMLResponse", []*x509.Certificate{rsaCert}, nil, nil, ""); err != nil {
		t.Fatalf("verify response: %v", err)
	}
	unsupported := url.Values{"SAMLRequest": {"payload"}, "SigAlg": {SigAlgRSASHA256}}
	if err := SignRedirect(unsupported, rsaKey, "urn:unsupported", ""); !errors.Is(err, ErrInvalidBinding) {
		t.Fatalf("unsupported sign error = %v", err)
	}
	if _, err := signRedirectBytes("payload", rsaKey, "urn:unsupported"); !errors.Is(err, ErrInvalidBinding) {
		t.Fatalf("unsupported bytes error = %v", err)
	}
	if err := verifyRedirectSignature("payload", []byte("bad"), SigAlgRSASHA256, nil, nil, nil); err == nil {
		t.Fatal("missing verifier accepted")
	}
}

// samlTestCertificateFor returns a certificate for pub signed by key. | samlTestCertificateFor 返回
// 由 key 为 pub 签发的证书。
func samlTestCertificateFor(t *testing.T, signer any, pub any) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "signer.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, signer)
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

// TestPostFormAndHTML covers form rendering and escaping. | TestPostFormAndHTML 覆盖表单渲染与转义。
func TestPostFormAndHTML(t *testing.T) {
	html := PostFormHTML("https://idp.example/sso?a=1&b=2", "SAMLRequest", `ab"cd`, `re<lay`)
	if !strings.Contains(html, `action="https://idp.example/sso?a=1&amp;b=2"`) {
		t.Fatalf("action not escaped: %s", html)
	}
	if !strings.Contains(html, `value="ab&#34;cd"`) || !strings.Contains(html, `value="re&lt;lay"`) {
		t.Fatalf("values not escaped: %s", html)
	}
	w := httptest.NewRecorder()
	WritePostForm(w, "https://idp.example/sso", "SAMLResponse", "value", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `name="SAMLResponse"`) {
		t.Fatalf("write form = %d %s", w.Code, w.Body.String())
	}
}

// TestNameIDAndAttributeHelpers covers NameID formats and attribute helpers. |
// TestNameIDAndAttributeHelpers 覆盖 NameID 格式与属性辅助函数。
func TestNameIDAndAttributeHelpers(t *testing.T) {
	principal := &auth.Principal{Subject: "subject-1", Username: "alice", Email: "Alice@Example.com", DisplayName: "Alice", Issuer: "https://idp.example", Groups: []string{"admins"}}
	cases := []struct {
		format string
		value  string
	}{
		{format: "", value: "subject-1"},
		{format: NameIDUnspecified, value: "subject-1"},
		{format: NameIDPersistent, value: "subject-1"},
		{format: NameIDEmailAddress, value: "Alice@Example.com"},
		{format: NameIDEntity, value: "https://idp.example"},
		{format: NameIDKerberos, value: "alice"},
		{format: NameIDWindowsDomainQualifiedName, value: "alice"},
	}
	for _, tc := range cases {
		nameID, err := NameIDForPrincipal(principal, tc.format)
		if err != nil {
			t.Fatalf("format %q: %v", tc.format, err)
		}
		if nameID.Value != tc.value {
			t.Fatalf("format %q value = %q, want %q", tc.format, nameID.Value, tc.value)
		}
	}
	transient, err := NameIDForPrincipal(principal, NameIDTransient)
	if err != nil || transient.Value == "" {
		t.Fatalf("transient = %+v err=%v", transient, err)
	}
	if _, err := NameIDForPrincipal(nil, NameIDUnspecified); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil principal error = %v", err)
	}
	if _, err := NameIDForPrincipal(&auth.Principal{}, NameIDEmailAddress); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("missing email error = %v", err)
	}
	if _, err := NameIDForPrincipal(&auth.Principal{}, NameIDEntity); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("missing issuer error = %v", err)
	}
	if _, err := NameIDForPrincipal(&auth.Principal{}, NameIDKerberos); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("missing name error = %v", err)
	}
	if _, err := NameIDForPrincipal(principal, "urn:unknown"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unknown format error = %v", err)
	}
	if NewNameID("", "v").Format != NameIDUnspecified {
		t.Fatal("empty format not normalized")
	}
	if SubjectNameID(nil) != "" || SubjectNameID(&Subject{}) != "" {
		t.Fatal("empty subject name")
	}
	if SubjectNameID(&Subject{NameID: NewNameID(NameIDUnspecified, "v")}) != "v" {
		t.Fatal("subject name mismatch")
	}
	first := PersistentNameID("alice", "https://sp.example", "salt")
	if first != PersistentNameID("alice", "https://sp.example", "salt") || first == PersistentNameID("alice", "https://other.example", "salt") {
		t.Fatal("persistent nameid is not deterministic or not scoped")
	}
	if !NameIDValueMatches(NewNameID(NameIDEmailAddress, "Alice@Example.com"), "alice@example.com") {
		t.Fatal("email case-insensitive match failed")
	}
	if !NameIDValueMatches(NewNameID(NameIDUnspecified, "v"), "v") || NameIDValueMatches(nil, "v") || NameIDValueMatches(NewNameID(NameIDUnspecified, "v"), "w") {
		t.Fatal("nameid match semantics wrong")
	}
	attribute := NewAttribute("mail", "a", "b")
	if attribute.NameFormat != AttrNameFormatBasic || len(AttributeValues(attribute)) != 2 {
		t.Fatalf("attribute = %+v", attribute)
	}
	statements := []AttributeStatement{{Attribute: []Attribute{
		attribute,
		{Name: "friendly", FriendlyName: "friendly-alt", AttributeValue: []AttributeValue{{Value: "v"}}},
		{FriendlyName: "only-friendly", AttributeValue: []AttributeValue{{Value: "x"}}},
		{AttributeValue: []AttributeValue{{Value: "dropped"}}},
	}}}
	mapped := AttributeMap(statements)
	if len(mapped["mail"]) != 2 || mapped["friendly"][0] != "v" || mapped["only-friendly"][0] != "x" || len(mapped) != 3 {
		t.Fatalf("attribute map = %v", mapped)
	}
	if FirstAttribute(mapped, "mail") != "a" || FirstAttribute(mapped, "absent") != "" {
		t.Fatal("first attribute mismatch")
	}
	defaults, err := DefaultAttributeMapper{}.MapAttributes(context.Background(), principal)
	if err != nil || len(defaults) != 5 {
		t.Fatalf("default attributes = %v err=%v", defaults, err)
	}
	if mappedNil, err := (DefaultAttributeMapper{}).MapAttributes(context.Background(), nil); err != nil || mappedNil != nil {
		t.Fatalf("nil principal defaults = %v", mappedNil)
	}
	mapper := AttributeMapperFunc(func(context.Context, *auth.Principal) ([]Attribute, error) {
		return []Attribute{NewAttribute("x", "y")}, nil
	})
	if result, err := mapper.MapAttributes(context.Background(), principal); err != nil || result[0].Name != "x" {
		t.Fatalf("mapper = %v err=%v", result, err)
	}
}

// TestMemoryStoreSemantics covers request, assertion, session and cleanup behavior. |
// TestMemoryStoreSemantics 覆盖请求、断言、会话与清理行为。
func TestMemoryStoreSemantics(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	now := samlTestNow
	request := &RequestState{ID: "r1", SPEntityID: "sp", IDPEntityID: "idp", ACSURL: "acs", RelayState: "relay", CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	if err := store.SaveRequest(ctx, request); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := store.SaveRequest(ctx, request); !errors.Is(err, ErrReplay) {
		t.Fatalf("duplicate request error = %v", err)
	}
	clone := request.Clone()
	if clone == request || clone.RelayState != request.RelayState {
		t.Fatal("request clone mismatch")
	}
	state, err := store.ConsumeRequest(ctx, "r1", now)
	if err != nil || state.RelayState != "relay" {
		t.Fatalf("consume = %+v err=%v", state, err)
	}
	if _, err := store.ConsumeRequest(ctx, "r1", now); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("reused request error = %v", err)
	}
	if _, err := store.ConsumeRequest(ctx, "missing", now); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("unknown request error = %v", err)
	}
	expiredRequest := &RequestState{ID: "r2", ExpiresAt: now.Add(-time.Minute)}
	if err := store.SaveRequest(ctx, expiredRequest); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeRequest(ctx, "r2", now); !errors.Is(err, ErrResponseExpired) {
		t.Fatalf("expired request error = %v", err)
	}
	fresh, err := store.SaveAssertion(ctx, "a1", now.Add(time.Minute), now)
	if err != nil || !fresh {
		t.Fatalf("save assertion = %v err=%v", fresh, err)
	}
	fresh, err = store.SaveAssertion(ctx, "a1", now.Add(time.Minute), now)
	if err != nil || fresh {
		t.Fatalf("duplicate assertion = %v err=%v", fresh, err)
	}
	fresh, err = store.SaveAssertion(ctx, "a1", now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil || !fresh {
		t.Fatalf("expired assertion replacement = %v err=%v", fresh, err)
	}
	session := &Session{ID: "s1", NameID: "alice", SPEntityID: "sp", Attributes: map[string][]string{"mail": {"a"}}, ExpiresAt: now.Add(time.Hour)}
	if err := store.SaveSession(ctx, session); err != nil {
		t.Fatalf("save session: %v", err)
	}
	got, err := store.GetSession(ctx, "s1")
	if err != nil || got.NameID != "alice" || got.Attributes["mail"][0] != "a" {
		t.Fatalf("get session = %+v err=%v", got, err)
	}
	if _, err := store.GetSession(ctx, "missing"); err == nil {
		t.Fatal("missing session accepted")
	}
	sessions, err := store.ListSessions(ctx, "alice")
	if err != nil || len(sessions) != 1 {
		t.Fatalf("list sessions = %v err=%v", sessions, err)
	}
	if sessions, err = store.ListSessions(ctx, "nobody"); err != nil || len(sessions) != 0 {
		t.Fatalf("list nobody = %v err=%v", sessions, err)
	}
	sessionClone := session.Clone()
	if sessionClone == session || sessionClone.Attributes["mail"][0] != "a" {
		t.Fatal("session clone mismatch")
	}
	if (*Session)(nil).Clone() != nil || (*RequestState)(nil).Clone() != nil {
		t.Fatal("nil clone should be nil")
	}
	if err := store.DeleteSession(ctx, "s1"); err != nil {
		t.Fatalf("delete session: %v", err)
	}
	if err := store.Cleanup(ctx, now.Add(2*time.Hour)); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, err := store.GetSession(ctx, "s1"); err == nil {
		t.Fatal("deleted session survived cleanup")
	}
}

// TestTimeHelpersAndDecode covers time formatting and logout decoding helpers. |
// TestTimeHelpersAndDecode 覆盖时间格式化与登出解码辅助函数。
func TestTimeHelpersAndDecode(t *testing.T) {
	now := samlTestNow
	if FormatTime(now) != "2026-11-08T12:00:00Z" {
		t.Fatalf("format = %s", FormatTime(now))
	}
	parsed, err := ParseTime("2026-11-08T12:00:00.123456789Z")
	if err != nil || !parsed.Equal(now.Add(123456789*time.Nanosecond)) {
		t.Fatalf("parse nano = %v err=%v", parsed, err)
	}
	if _, err := ParseTime("not-a-time"); err == nil {
		t.Fatal("invalid time accepted")
	}
	if !Now(nil).IsZero() == false {
		t.Fatal("Now(nil) should return the current time")
	}
	if err := SaveLogoutResponse(EncodePost([]byte("<LogoutResponse xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"x\" Version=\"2.0\"/>"))); err != nil {
		t.Fatal(err)
	}
	document, err := EncodeLogoutResponse("idp", "https://sp.example/slo", "req-1", now)
	if err != nil {
		t.Fatalf("encode logout response: %v", err)
	}
	response, err := DecodeLogoutResponse(document)
	if err != nil || response.InResponseTo != "req-1" {
		t.Fatalf("decode logout response = %+v err=%v", response, err)
	}
	if logoutResponseID(document) != response.ID || logoutResponseID([]byte("bad")) != "" {
		t.Fatal("logout response id mismatch")
	}
	request := &LogoutRequest{ID: "req-1", Version: Version, IssueInstant: FormatTime(now), Issuer: &Issuer{Value: "sp"}, NameID: NewNameID(NameIDUnspecified, "alice")}
	requestXML, err := xml.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	decodedRequest, err := DecodeLogoutRequest(requestXML)
	if err != nil || decodedRequest.ID != "req-1" {
		t.Fatalf("decode logout request = %+v err=%v", decodedRequest, err)
	}
	if _, err := DecodeLogoutRequest([]byte("<bad")); err == nil {
		t.Fatal("bad logout request accepted")
	}
	if _, err := DecodeLogoutResponse([]byte("<bad")); err == nil {
		t.Fatal("bad logout response accepted")
	}
}

// SaveLogoutResponse validates that DecodePost accepts the encoded document without error. |
// SaveLogoutResponse 校验 DecodePost 能无错误接受编码后的文档。
func SaveLogoutResponse(value string) error {
	_, err := DecodePost(value)
	return err
}

// TestLogoutValidationHelpers covers expiry, status and signature helpers directly. |
// TestLogoutValidationHelpers 直接覆盖过期、状态与签名辅助函数。
func TestLogoutValidationHelpers(t *testing.T) {
	now := samlTestNow
	if _, err := logoutExpiry("", now, 0); err != nil {
		t.Fatalf("empty expiry: %v", err)
	}
	if _, err := logoutExpiry(FormatTime(now.Add(time.Minute)), now, 0); err != nil {
		t.Fatalf("future expiry: %v", err)
	}
	if _, err := logoutExpiry(FormatTime(now.Add(-time.Minute)), now, 0); !errors.Is(err, ErrResponseExpired) {
		t.Fatalf("past expiry error = %v", err)
	}
	if _, err := logoutExpiry("bad", now, 0); err == nil {
		t.Fatal("bad expiry accepted")
	}
	status := func(code string, nested string) *Status {
		s := &Status{StatusCode: &StatusCode{Value: code}}
		if nested != "" {
			s.StatusCode.StatusCode = &StatusCode{Value: nested}
		}
		return s
	}
	if !logoutStatusAcceptable(status(StatusSuccess, "")) || !logoutStatusAcceptable(status(StatusRequester, StatusPartialLogout)) {
		t.Fatal("acceptable status rejected")
	}
	if logoutStatusAcceptable(nil) || logoutStatusAcceptable(status(StatusRequester, "")) {
		t.Fatal("unacceptable status accepted")
	}
	if err := verifyLogoutSignature(context.Background(), nil, "id", nil, nil, true, ""); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("required unsigned error = %v", err)
	}
	if err := verifyLogoutSignature(context.Background(), nil, "id", nil, nil, false, ""); err != nil {
		t.Fatalf("optional unsigned: %v", err)
	}
	marker := &SignatureMarker{}
	if err := verifyLogoutSignature(context.Background(), nil, "id", marker, nil, false, ""); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("missing verifier error = %v", err)
	}
	if err := verifyLogoutSignature(context.Background(), nil, "id", marker, SignatureVerifierFunc(func(context.Context, []byte, string) error { return nil }), false, ""); !errors.Is(err, ErrInvalidRecipient) {
		t.Fatalf("missing destination error = %v", err)
	}
	if err := verifyLogoutSignature(context.Background(), nil, "id", marker, SignatureVerifierFunc(func(context.Context, []byte, string) error { return nil }), false, "https://sp.example/slo"); err != nil {
		t.Fatalf("valid signature: %v", err)
	}
	verifierErr := errors.New("verifier failed")
	if err := verifyLogoutSignature(context.Background(), nil, "id", marker, SignatureVerifierFunc(func(context.Context, []byte, string) error { return verifierErr }), false, "https://sp.example/slo"); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("verifier failure error = %v", err)
	}
}

// TestValidateResponseWithoutStoreAndSignature exercises nil-store and verifier success paths. |
// TestValidateResponseWithoutStoreAndSignature 覆盖空存储与校验器成功路径。
func TestValidateResponseWithoutStoreAndSignature(t *testing.T) {
	opts := samlValidationOptions(nil)
	opts.RequireInResponseTo = false
	result, err := ValidateResponse(context.Background(), []byte(samlValidResponse(samlTestNow)), opts)
	if err != nil || result.NameID != "alice@example.com" {
		t.Fatalf("nil store validation = %+v err=%v", result, err)
	}
	// A replay is not detected without a store. | 无存储时不检测重放。
	if _, err := ValidateResponse(context.Background(), []byte(samlValidResponse(samlTestNow)), opts); err != nil {
		t.Fatalf("second nil-store validation: %v", err)
	}
	opts.RequireSignedResponse = true
	opts.SignatureVerifier = SignatureVerifierFunc(func(_ context.Context, document []byte, id string) error {
		if id != "resp-1" || !bytes.Contains(document, []byte("resp-1")) {
			return ErrInvalidSignature
		}
		return nil
	})
	document := samlValidResponse(samlTestNow)
	document = strings.Replace(document, "</saml:Issuer>", `</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/>`, 1)
	if _, err := ValidateResponse(context.Background(), []byte(document), opts); err != nil {
		t.Fatalf("signed response validation: %v", err)
	}
	// An assertion signature is verified before content validation. | 断言签名先于内容校验。
	opts.RequireSignedResponse = false
	opts.SignatureVerifier = SignatureVerifierFunc(func(context.Context, []byte, string) error { return ErrInvalidSignature })
	assertionSigned := strings.Replace(document, "</saml:Issuer>", `</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/>`, 2)
	if _, err := ValidateResponse(context.Background(), []byte(assertionSigned), opts); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("assertion signature failure error = %v", err)
	}
}

// samlFormPost builds a form-encoded POST request used by ACS tests. | samlFormPost 构建 ACS 测试
// 使用的表单编码 POST 请求。
func samlFormPost(t *testing.T, path, body string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

// TestServiceProviderConstructorsAndHandlers covers config defaults and HTTP handlers. |
// TestServiceProviderConstructorsAndHandlers 覆盖配置默认值与 HTTP 处理程序。
func TestServiceProviderConstructorsAndHandlers(t *testing.T) {
	if _, err := NewServiceProvider(ServiceProviderConfig{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("empty config error = %v", err)
	}
	if _, err := NewServiceProvider(ServiceProviderConfig{EntityID: "x"}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("missing ACS error = %v", err)
	}
	if _, err := NewServiceProvider(ServiceProviderConfig{EntityID: "x", ACSURL: "https://sp.example/acs"}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("missing metadata error = %v", err)
	}
	expired := testMetadata()
	expired.ValidUntil = FormatTime(time.Now().Add(-time.Hour))
	if _, err := NewServiceProvider(ServiceProviderConfig{EntityID: "x", ACSURL: "https://sp.example/acs", IDPMetadata: expired}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expired metadata error = %v", err)
	}
	sp, err := NewServiceProvider(ServiceProviderConfig{EntityID: "https://sp.example/metadata", ACSURL: "https://sp.example/saml/acs", IDPMetadata: testMetadata()})
	if err != nil {
		t.Fatalf("sp: %v", err)
	}
	if sp.Config().NameIDFormat != NameIDUnspecified || sp.Config().ProtocolBinding != BindingHTTPPost || sp.Config().AuthnRequestTTL != 10*time.Minute {
		t.Fatalf("defaults = %+v", sp.Config())
	}
	if server := sp.HTTPHandler("/saml"); server == nil {
		t.Fatal("nil HTTP handler")
	}
	metadataXML, err := sp.MetadataXML()
	if err != nil || !bytes.Contains(metadataXML, []byte("https://sp.example/metadata")) {
		t.Fatalf("sp metadata = %s err=%v", metadataXML, err)
	}
	w := httptest.NewRecorder()
	sp.MetadataHandler(w, httptest.NewRequest(http.MethodGet, "/saml/metadata", nil))
	if w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte("EntityDescriptor")) {
		t.Fatalf("metadata handler = %d %s", w.Code, w.Body.String())
	}

	success := false
	idpInitiated := EncodePost([]byte(strings.ReplaceAll(samlValidResponse(time.Now().UTC()), ` InResponseTo="req-1"`, "")))
	sp, err = NewServiceProvider(ServiceProviderConfig{
		EntityID:          "https://sp.example/metadata",
		ACSURL:            "https://sp.example/saml/acs",
		IDPMetadata:       testMetadata(),
		AllowIDPInitiated: true,
		SuccessHandler: func(w http.ResponseWriter, _ *http.Request, result *ValidationResult) {
			success = result != nil
			w.WriteHeader(http.StatusAccepted)
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(err.Error()))
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	sp.ACS(w, samlFormPost(t, "/acs", url.Values{"SAMLResponse": {idpInitiated}}.Encode()))
	if w.Code != http.StatusAccepted || !success {
		t.Fatalf("success handler status = %d success=%v body=%s", w.Code, success, w.Body.String())
	}
	sp, err = NewServiceProvider(ServiceProviderConfig{
		EntityID:          "https://sp.example/metadata",
		ACSURL:            "https://sp.example/saml/acs",
		IDPMetadata:       testMetadata(),
		AllowIDPInitiated: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	sp.ACS(w, samlFormPost(t, "/acs", url.Values{"SAMLResponse": {idpInitiated}}.Encode()))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"subject":"alice@example.com"`) {
		t.Fatalf("default ACS = %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	sp.ACS(w, samlFormPost(t, "/acs", ""))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("missing response status = %d", w.Code)
	}
	handled := false
	sp, err = NewServiceProvider(ServiceProviderConfig{
		EntityID:    "https://sp.example/metadata",
		ACSURL:      "https://sp.example/saml/acs",
		IDPMetadata: testMetadata(),
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			handled = true
			w.WriteHeader(http.StatusForbidden)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	sp.ACS(w, samlFormPost(t, "/acs", ""))
	if w.Code != http.StatusForbidden || !handled {
		t.Fatalf("error handler status = %d handled=%v", w.Code, handled)
	}
	if _, err := sp.AuthnRequestURL(""); err != nil {
		t.Fatalf("authn url without relay: %v", err)
	}
	noSSO := testMetadata()
	noSSO.IDPSSODescriptor.SingleSignOnService = nil
	sp, err = NewServiceProvider(ServiceProviderConfig{EntityID: "x", ACSURL: "https://sp.example/acs", IDPMetadata: noSSO})
	if err != nil {
		t.Fatalf("sp without sso: %v", err)
	}
	if _, err := sp.AuthnRequestURL(""); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("missing sso error = %v", err)
	}
}

// TestIdentityProviderConstructorsAndHandlers covers IdP config defaults and metadata handlers. |
// TestIdentityProviderConstructorsAndHandlers 覆盖 IdP 配置默认值与元数据处理程序。
func TestIdentityProviderConstructorsAndHandlers(t *testing.T) {
	authenticator := AuthenticatorFunc(func(context.Context, http.ResponseWriter, *http.Request, *AuthnRequest) (*auth.Principal, error) {
		return &auth.Principal{Subject: "alice"}, nil
	})
	if _, err := NewIdentityProvider(IdentityProviderConfig{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("empty config error = %v", err)
	}
	if _, err := NewIdentityProvider(IdentityProviderConfig{EntityID: "x", SSOURL: "https://idp.example/sso"}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("missing authenticator error = %v", err)
	}
	if _, err := NewIdentityProvider(IdentityProviderConfig{EntityID: "x", SSOURL: "https://idp.example/sso", Authenticator: authenticator, SignResponse: true}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("missing signer error = %v", err)
	}
	idp, err := NewIdentityProvider(IdentityProviderConfig{EntityID: "https://idp.example/metadata", SSOURL: "https://idp.example/sso", Authenticator: authenticator})
	if err != nil {
		t.Fatalf("idp: %v", err)
	}
	if idp.Config().NameIDFormat != NameIDUnspecified || idp.Config().ResponseTTL != 5*time.Minute || idp.Config().SessionTTL != 8*time.Hour || idp.Config().ClockSkew != 2*time.Minute {
		t.Fatalf("defaults = %+v", idp.Config())
	}
	metadata := idp.Metadata()
	if metadata.EntityID != "https://idp.example/metadata" || metadata.IDPSSODescriptor == nil {
		t.Fatalf("metadata = %+v", metadata)
	}
	metadataXML, err := idp.MetadataXML()
	if err != nil || !bytes.Contains(metadataXML, []byte(NamespaceProtocol)) {
		t.Fatalf("idp metadata = %s err=%v", metadataXML, err)
	}
	w := httptest.NewRecorder()
	idp.MetadataHandler(w, httptest.NewRequest(http.MethodGet, "/saml/metadata", nil))
	if w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte("EntityDescriptor")) {
		t.Fatalf("idp metadata handler = %d", w.Code)
	}
	if idp.HTTPHandler("/saml") == nil {
		t.Fatal("nil idp HTTP handler")
	}
	if _, _, _, err := idp.ParseAuthnRequest(httptest.NewRequest(http.MethodGet, "/sso", nil)); err == nil {
		t.Fatal("missing SAMLRequest accepted")
	}
}

// TestParseResponseAndRequestHelpers covers raw parsing helpers. |
// TestParseResponseAndRequestHelpers 覆盖原始解析辅助函数。
func TestParseResponseAndRequestHelpers(t *testing.T) {
	response, err := ParseResponse([]byte(samlValidResponse(samlTestNow)))
	if err != nil || response.ID != "resp-1" || len(response.Assertion) != 1 {
		t.Fatalf("parse response = %+v err=%v", response, err)
	}
	if _, err := ParseResponse([]byte("<bad")); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("bad response error = %v", err)
	}
	request, err := ParseAuthnRequest([]byte(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id-1" Version="2.0"/>`))
	if err != nil || request.ID != "id-1" {
		t.Fatalf("parse request = %+v err=%v", request, err)
	}
	if _, err := ParseAuthnRequest([]byte("<bad")); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("bad request error = %v", err)
	}
}

// TestReadSLOMessageBindings covers POST/GET logout message reading. |
// TestReadSLOMessageBindings 覆盖 POST/GET 登出消息读取。
func TestReadSLOMessageBindings(t *testing.T) {
	document := []byte(`<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="l1"/>`)
	post := httptest.NewRequest(http.MethodPost, "/slo", strings.NewReader(url.Values{"SAMLRequest": {EncodePost(document)}, "RelayState": {"r"}}.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	raw, relay, isRequest, redirect, err := readSLOMessage(post)
	if err != nil || !isRequest || redirect || relay != "r" || !bytes.Equal(raw, document) {
		t.Fatalf("post read = %q relay=%q request=%v redirect=%v err=%v", raw, relay, isRequest, redirect, err)
	}
	encoded, err := EncodeRedirect(document)
	if err != nil {
		t.Fatal(err)
	}
	get := httptest.NewRequest(http.MethodGet, "/slo?SAMLResponse="+url.QueryEscape(encoded), nil)
	_, _, isRequest, redirect, err = readSLOMessage(get)
	if err != nil || isRequest || !redirect {
		t.Fatalf("get read request=%v redirect=%v err=%v", isRequest, redirect, err)
	}
	if _, _, _, _, err := readSLOMessage(httptest.NewRequest(http.MethodPost, "/slo", strings.NewReader(""))); err == nil {
		t.Fatal("missing message accepted")
	}
	if _, _, _, _, err := readSLOMessage(nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil request error = %v", err)
	}
}

// TestRegisterAndFormParseErrors covers router mounts and malformed forms. |
// TestRegisterAndFormParseErrors 覆盖路由挂载与畸形表单。
func TestRegisterAndFormParseErrors(t *testing.T) {
	authenticator := AuthenticatorFunc(func(context.Context, http.ResponseWriter, *http.Request, *AuthnRequest) (*auth.Principal, error) {
		return &auth.Principal{Subject: "alice"}, nil
	})
	idp, err := NewIdentityProvider(IdentityProviderConfig{EntityID: "https://idp.example/metadata", SSOURL: "https://idp.example/sso", Authenticator: authenticator})
	if err != nil {
		t.Fatal(err)
	}
	sp, err := NewServiceProvider(ServiceProviderConfig{EntityID: "https://sp.example/metadata", ACSURL: "https://sp.example/saml/acs", IDPMetadata: testMetadata()})
	if err != nil {
		t.Fatal(err)
	}
	idp.Register(nil, "")
	sp.Register(nil, "")
	r := router.New()
	idp.Register(r, "")
	spRouter := router.New()
	sp.Register(spRouter, "")
	for server, path := range map[*router.Router]string{r: "/saml/metadata", spRouter: "/saml/metadata"} {
		w := httptest.NewRecorder()
		server.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte("EntityDescriptor")) {
			t.Fatalf("register %s status = %d", path, w.Code)
		}
	}
	w := httptest.NewRecorder()
	sp.ACS(w, samlFormPost(t, "/acs", "SAMLResponse=%zz"))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("malformed form status = %d", w.Code)
	}
}

// TestSPLogoutResponseValidation covers the SP response validation matrix. |
// TestSPLogoutResponseValidation 覆盖 SP 响应校验矩阵。
func TestSPLogoutResponseValidation(t *testing.T) {
	now := time.Now().UTC()
	newSP := func(t *testing.T) *ServiceProvider {
		t.Helper()
		sp, err := NewServiceProvider(ServiceProviderConfig{
			EntityID:    "https://sp.example/metadata",
			ACSURL:      "https://sp.example/saml/acs",
			SLOURL:      "https://sp.example/slo",
			IDPMetadata: testMetadata(),
			Store:       NewMemoryStore(),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := sp.Store().SaveRequest(context.Background(), &RequestState{ID: "logout-1", SPEntityID: "https://sp.example/metadata", RelayState: "relay-1", CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute)}); err != nil {
			t.Fatal(err)
		}
		return sp
	}
	deliver := func(t *testing.T, sp *ServiceProvider, document []byte, relayState string) int {
		t.Helper()
		w := httptest.NewRecorder()
		sp.HandleSLO(w, samlFormPost(t, "/slo", url.Values{"SAMLResponse": {EncodePost(document)}, "RelayState": {relayState}}.Encode()))
		return w.Code
	}
	valid, err := EncodeLogoutResponse("https://idp.example/metadata", "https://sp.example/slo", "logout-1", now)
	if err != nil {
		t.Fatal(err)
	}
	if status := deliver(t, newSP(t), valid, "relay-1"); status != http.StatusOK {
		t.Fatalf("valid logout response status = %d", status)
	}
	response := func(mutate func(*LogoutResponse)) []byte {
		decoded, err := DecodeLogoutResponse(valid)
		if err != nil {
			t.Fatal(err)
		}
		mutate(decoded)
		document, err := xml.Marshal(decoded)
		if err != nil {
			t.Fatal(err)
		}
		return document
	}
	cases := []struct {
		name      string
		document  []byte
		relay     string
		configure func(*ServiceProviderConfig)
	}{
		{name: "version", document: response(func(r *LogoutResponse) { r.Version = "1.1" })},
		{name: "missing id", document: response(func(r *LogoutResponse) { r.ID = "" })},
		{name: "missing in response to", document: response(func(r *LogoutResponse) { r.InResponseTo = "" })},
		{name: "issuer", document: response(func(r *LogoutResponse) { r.Issuer = &Issuer{Value: "https://evil.example"} })},
		{name: "destination", document: response(func(r *LogoutResponse) { r.Destination = "https://evil.example/slo" })},
		{name: "status", document: response(func(r *LogoutResponse) { r.Status = statusFor(StatusRequester) })},
		{name: "relay state", document: valid, relay: "other"},
		{name: "signed without verifier", document: response(func(r *LogoutResponse) { r.Signature = &SignatureMarker{} })},
		{name: "required signature", document: valid, configure: func(c *ServiceProviderConfig) { c.RequireSignedLogout = true }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sp := newSP(t)
			if tc.configure != nil {
				tc.configure(&sp.config)
			}
			if status := deliver(t, sp, tc.document, tc.relay); status != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", status)
			}
		})
	}
}

// TestIdPLogoutResponseHandling covers IdP receipt of a LogoutResponse. |
// TestIdPLogoutResponseHandling 覆盖 IdP 接收 LogoutResponse。
func TestIdPLogoutResponseHandling(t *testing.T) {
	now := time.Now().UTC()
	newIDP := func(t *testing.T) *IdentityProvider {
		t.Helper()
		idp, err := NewIdentityProvider(IdentityProviderConfig{
			EntityID: "https://idp.example/metadata",
			SSOURL:   "https://idp.example/sso",
			SLOURL:   "https://idp.example/slo",
			Store:    NewMemoryStore(),
			Authenticator: AuthenticatorFunc(func(context.Context, http.ResponseWriter, *http.Request, *AuthnRequest) (*auth.Principal, error) {
				return &auth.Principal{Subject: "alice"}, nil
			}),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := idp.Store().SaveRequest(context.Background(), &RequestState{ID: "idp-logout-1", RelayState: "relay-1", CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute)}); err != nil {
			t.Fatal(err)
		}
		return idp
	}
	valid, err := EncodeLogoutResponse("https://sp.example/metadata", "https://idp.example/slo", "", now)
	if err != nil {
		t.Fatal(err)
	}
	deliver := func(t *testing.T, idp *IdentityProvider, document []byte, relayState string) int {
		t.Helper()
		w := httptest.NewRecorder()
		idp.HandleSLO(w, samlFormPost(t, "/slo", url.Values{"SAMLResponse": {EncodePost(document)}, "RelayState": {relayState}}.Encode()))
		return w.Code
	}
	if status := deliver(t, newIDP(t), valid, ""); status != http.StatusOK {
		t.Fatalf("valid IdP logout response status = %d", status)
	}
	withRequest, err := EncodeLogoutResponse("https://sp.example/metadata", "https://idp.example/slo", "idp-logout-1", now)
	if err != nil {
		t.Fatal(err)
	}
	if status := deliver(t, newIDP(t), withRequest, "relay-1"); status != http.StatusOK {
		t.Fatalf("correlated IdP logout response status = %d", status)
	}
	if status := deliver(t, newIDP(t), withRequest, "other"); status != http.StatusBadRequest {
		t.Fatalf("relay mismatch status = %d", status)
	}
	response := func(mutate func(*LogoutResponse)) []byte {
		decoded, err := DecodeLogoutResponse(valid)
		if err != nil {
			t.Fatal(err)
		}
		mutate(decoded)
		document, err := xml.Marshal(decoded)
		if err != nil {
			t.Fatal(err)
		}
		return document
	}
	cases := []struct {
		name     string
		document []byte
	}{
		{name: "missing issuer", document: response(func(r *LogoutResponse) { r.Issuer = nil })},
		{name: "destination", document: response(func(r *LogoutResponse) { r.Destination = "https://evil.example/slo" })},
		{name: "status", document: response(func(r *LogoutResponse) { r.Status = statusFor(StatusRequester) })},
		{name: "signed without verifier", document: response(func(r *LogoutResponse) { r.Signature = &SignatureMarker{} })},
		{name: "unknown correlation", document: response(func(r *LogoutResponse) { r.InResponseTo = "missing" })},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if status := deliver(t, newIDP(t), tc.document, ""); status != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", status)
			}
		})
	}
}

// TestIdPLogoutRequestRejections covers IdP LogoutRequest validation failures. |
// TestIdPLogoutRequestRejections 覆盖 IdP LogoutRequest 校验失败。
func TestIdPLogoutRequestRejections(t *testing.T) {
	now := time.Now().UTC()
	resolver := staticResolver{metadata: &EntityDescriptor{
		EntityID: "https://sp.example/metadata",
		SPSSODescriptor: &SPSSODescriptor{
			SingleLogoutService: []Endpoint{{Binding: BindingHTTPPost, Location: "https://sp.example/slo"}},
		},
	}}
	newIDP := func(t *testing.T, configure func(*IdentityProviderConfig)) *IdentityProvider {
		t.Helper()
		cfg := IdentityProviderConfig{
			EntityID: "https://idp.example/metadata",
			SSOURL:   "https://idp.example/sso",
			SLOURL:   "https://idp.example/slo",
			Store:    NewMemoryStore(),
			Authenticator: AuthenticatorFunc(func(context.Context, http.ResponseWriter, *http.Request, *AuthnRequest) (*auth.Principal, error) {
				return &auth.Principal{Subject: "alice"}, nil
			}),
			SPResolver: resolver,
		}
		if configure != nil {
			configure(&cfg)
		}
		idp, err := NewIdentityProvider(cfg)
		if err != nil {
			t.Fatal(err)
		}
		return idp
	}
	request := func(mutate func(*LogoutRequest)) []byte {
		value := LogoutRequest{
			ID:           "logout-1",
			Version:      Version,
			IssueInstant: FormatTime(now),
			Destination:  "https://idp.example/slo",
			NotOnOrAfter: FormatTime(now.Add(5 * time.Minute)),
			Issuer:       &Issuer{Value: "https://sp.example/metadata"},
			NameID:       NewNameID(NameIDUnspecified, "alice@example.com"),
		}
		if mutate != nil {
			mutate(&value)
		}
		document, err := xml.Marshal(&value)
		if err != nil {
			t.Fatal(err)
		}
		return document
	}
	deliver := func(t *testing.T, idp *IdentityProvider, document []byte) int {
		t.Helper()
		w := httptest.NewRecorder()
		idp.HandleSLO(w, samlFormPost(t, "/slo", url.Values{"SAMLRequest": {EncodePost(document)}}.Encode()))
		return w.Code
	}
	if status := deliver(t, newIDP(t, nil), request(nil)); status != http.StatusOK {
		t.Fatalf("valid logout request status = %d", status)
	}
	cases := []struct {
		name      string
		document  []byte
		configure func(*IdentityProviderConfig)
	}{
		{name: "version", document: request(func(r *LogoutRequest) { r.Version = "1.1" })},
		{name: "missing id", document: request(func(r *LogoutRequest) { r.ID = "" })},
		{name: "missing issuer", document: request(func(r *LogoutRequest) { r.Issuer = nil })},
		{name: "missing nameid", document: request(func(r *LogoutRequest) { r.NameID = nil })},
		{name: "destination", document: request(func(r *LogoutRequest) { r.Destination = "https://evil.example/slo" })},
		{name: "expired", document: request(func(r *LogoutRequest) { r.NotOnOrAfter = FormatTime(now.Add(-time.Hour)) })},
		{name: "bad expiry", document: request(func(r *LogoutRequest) { r.NotOnOrAfter = "bad" })},
		{name: "signed without verifier", document: request(func(r *LogoutRequest) { r.Signature = &SignatureMarker{} })},
		{name: "required signature", document: request(nil), configure: func(c *IdentityProviderConfig) { c.WantLogoutRequestsSigned = true }},
		{name: "resolver failure", document: request(nil), configure: func(c *IdentityProviderConfig) { c.SPResolver = staticResolver{err: ErrInvalidMetadata} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if status := deliver(t, newIDP(t, tc.configure), tc.document); status != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", status)
			}
		})
	}
}
