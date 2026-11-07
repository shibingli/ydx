package wsfed

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth/protocol/saml"
	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/xml"
)

const testAssertionXML = `<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="assertion-1" IssueInstant="2026-11-07T12:00:00Z" Version="2.0">` +
	`<Issuer>https://sts.example.com/</Issuer>` +
	`<Subject><NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">alice</NameID></Subject>` +
	`<Conditions NotBefore="2026-11-07T11:59:00Z" NotOnOrAfter="2026-11-07T12:05:00Z">` +
	`<AudienceRestriction><Audience>https://rp.example.com/</Audience></AudienceRestriction></Conditions>` +
	`<AttributeStatement><Attribute Name="email"><AttributeValue>alice@example.com</AttributeValue></Attribute></AttributeStatement>` +
	`</Assertion>`

const legacyResponseXML = `<RequestSecurityTokenResponseCollection xmlns="http://schemas.xmlsoap.org/ws/2005/02/trust">` +
	`<RequestSecurityTokenResponse>` +
	`<TokenType>urn:oasis:names:tc:SAML:2.0:assertion</TokenType>` +
	`<RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</RequestType>` +
	`<AppliesTo><EndpointReference xmlns="http://schemas.xmlsoap.org/ws/2004/08/addressing"><Address>https://rp.example.com/</Address></EndpointReference></AppliesTo>` +
	`<Lifetime><Created xmlns="http://schemas.xmlsoap.org/ws/2005/02/trust">2026-11-07T12:00:00Z</Created>` +
	`<Expires xmlns="http://schemas.xmlsoap.org/ws/2005/02/trust">2026-11-07T12:05:00Z</Expires></Lifetime>` +
	`<RequestedSecurityToken>` + testAssertionXML + `</RequestedSecurityToken>` +
	`<Status><Code>http://schemas.xmlsoap.org/ws/2005/02/trust/status/success</Code></Status>` +
	`</RequestSecurityTokenResponse></RequestSecurityTokenResponseCollection>`

// TestResponseRoundTrip serializes and parses a full response collection. | TestResponseRoundTrip
// 序列化并解析完整响应集合。
func TestResponseRoundTrip(t *testing.T) {
	collection := &RequestSecurityTokenResponseCollection{
		ID: "collection-1",
		Responses: []RequestSecurityTokenResponse{{
			ID:          "response-1",
			Context:     "ctx",
			TokenType:   TokenTypeSAML20,
			RequestType: RequestTypeIssue,
			AppliesTo: &AppliesTo{
				EndpointReference: EndpointReference{Address: testRealm},
			},
			Lifetime: &Lifetime{
				Created: "2026-11-07T12:00:00Z",
				Expires: "2026-11-07T12:05:00Z",
			},
			RequestedSecurityToken:       &RequestedSecurityToken{InnerXML: testAssertionXML},
			RequestedAttachedReference:   NewAttachedReference("assertion-1", ValueTypeSAMLV20),
			RequestedUnattachedReference: NewUnattachedReference("assertion-1", ValueTypeSAMLV20),
			KeySize:                      256,
			Status:                       &ResponseStatus{Code: StatusSuccess},
		}},
	}
	data, err := collection.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	parsed, err := ParseWResult(data)
	if err != nil {
		t.Fatalf("ParseWResult: %v", err)
	}
	if parsed.ID != "collection-1" || len(parsed.Responses) != 1 {
		t.Fatalf("unexpected collection: %+v", parsed)
	}
	response := parsed.Responses[0]
	if response.ID != "response-1" || response.Context != "ctx" || response.TokenType != TokenTypeSAML20 {
		t.Fatalf("unexpected response: %+v", response)
	}
	if response.AppliesTo == nil || response.AppliesTo.Address() != testRealm {
		t.Fatalf("unexpected applies-to: %+v", response.AppliesTo)
	}
	if response.Lifetime == nil || response.Lifetime.Expires != "2026-11-07T12:05:00Z" {
		t.Fatalf("unexpected lifetime: %+v", response.Lifetime)
	}
	if response.RequestedAttachedReference == nil || response.RequestedAttachedReference.SecurityTokenReference.Reference.URI != "#assertion-1" {
		t.Fatalf("unexpected reference: %+v", response.RequestedAttachedReference)
	}
	assertion, err := response.RequestedSecurityToken.Assertion()
	if err != nil {
		t.Fatalf("Assertion: %v", err)
	}
	if assertion.ID != "assertion-1" || assertion.Subject == nil || assertion.Subject.NameID.Value != "alice" {
		t.Fatalf("unexpected assertion: %+v", assertion)
	}
}

// TestParseWResultLegacy parses WS-Trust 2005 namespace output. | TestParseWResultLegacy 解析
// WS-Trust 2005 命名空间输出。
func TestParseWResultLegacy(t *testing.T) {
	parsed, err := ParseWResultString(legacyResponseXML)
	if err != nil {
		t.Fatalf("ParseWResultString: %v", err)
	}
	if len(parsed.Responses) != 1 {
		t.Fatalf("responses = %d", len(parsed.Responses))
	}
	response := parsed.Responses[0]
	if response.TokenType != TokenTypeSAML20 || response.AppliesTo == nil || response.AppliesTo.Address() != testRealm {
		t.Fatalf("unexpected response: %+v", response)
	}
	if response.Lifetime == nil || response.Lifetime.Created == "" || response.Lifetime.Expires == "" {
		t.Fatalf("unexpected lifetime: %+v", response.Lifetime)
	}
	if response.Status == nil || response.Status.Code != "http://schemas.xmlsoap.org/ws/2005/02/trust/status/success" {
		t.Fatalf("unexpected status: %+v", response.Status)
	}
	if _, err := response.RequestedSecurityToken.Assertion(); err != nil {
		t.Fatalf("Assertion: %v", err)
	}
}

// TestParseWResultBareResponse parses a bare RSTR document. | TestParseWResultBareResponse 解析裸
// RSTR 文档。
func TestParseWResultBareResponse(t *testing.T) {
	start := strings.Index(legacyResponseXML, "<RequestSecurityTokenResponse>")
	end := strings.Index(legacyResponseXML, "</RequestSecurityTokenResponse>")
	bare := legacyResponseXML[start : end+len("</RequestSecurityTokenResponse>")]
	parsed, err := ParseWResultString(bare)
	if err != nil {
		t.Fatalf("ParseWResultString: %v", err)
	}
	if len(parsed.Responses) != 1 || parsed.Responses[0].TokenType != TokenTypeSAML20 {
		t.Fatalf("unexpected collection: %+v", parsed)
	}
}

// TestParseWResultBase64 decodes a base64-encoded wresult. | TestParseWResultBase64 解码 base64
// 编码的 wresult。
func TestParseWResultBase64(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte(legacyResponseXML))
	parsed, err := ParseWResultString(encoded)
	if err != nil {
		t.Fatalf("ParseWResultString: %v", err)
	}
	if len(parsed.Responses) != 1 {
		t.Fatalf("responses = %d", len(parsed.Responses))
	}
}

// TestParseWResultFault parses a fault document. | TestParseWResultFault 解析故障文档。
func TestParseWResultFault(t *testing.T) {
	_, err := ParseWResultString(`<Fault><faultcode>InvalidRequest</faultcode><faultstring>bad request</faultstring></Fault>`)
	if !errors.Is(err, ErrStatusFailure) {
		t.Fatalf("err = %v, want ErrStatusFailure", err)
	}
	var fault *Fault
	if !errors.As(err, &fault) {
		t.Fatalf("err does not wrap *Fault: %v", err)
	}
	if fault.FaultCode != FaultCodeInvalidRequest {
		t.Fatalf("fault code = %q", fault.FaultCode)
	}
}

// TestParseWResultInvalid rejects empty and unrelated payloads. | TestParseWResultInvalid 拒绝空与
// 无关载荷。
func TestParseWResultInvalid(t *testing.T) {
	if _, err := ParseWResult(nil); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("empty payload err = %v", err)
	}
	if _, err := ParseWResultString(`<Other>value</Other>`); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("unrelated payload err = %v", err)
	}
}

// TestSAML11AssertionConversion converts a SAML 1.1 assertion to the shared model. |
// TestSAML11AssertionConversion 把 SAML 1.1 断言转换为共享模型。
func TestSAML11AssertionConversion(t *testing.T) {
	nameID := saml.NewNameID(saml.NameIDUnspecified, "alice")
	assertion := buildSAML11Assertion(testIssuer, nameID, testPrincipal(), "session-1", testRealm, testNow,
		testNow.Add(-time.Minute), testNow.Add(5*time.Minute), []saml.Attribute{saml.NewAttribute("email", "alice@example.com")})
	data, err := xml.Marshal(assertion)
	if err != nil {
		t.Fatalf("marshal SAML 1.1 assertion: %v", err)
	}
	token := &RequestedSecurityToken{InnerXML: string(data)}
	if token.TokenType() != TokenTypeSAML11 {
		t.Fatalf("token type = %q", token.TokenType())
	}
	converted, err := token.Assertion()
	if err != nil {
		t.Fatalf("Assertion: %v", err)
	}
	if converted.ID != assertion.AssertionID || converted.Issuer == nil || converted.Issuer.Value != testIssuer {
		t.Fatalf("unexpected assertion: %+v", converted)
	}
	if converted.Subject == nil || converted.Subject.NameID == nil || converted.Subject.NameID.Value != "alice" {
		t.Fatalf("unexpected subject: %+v", converted.Subject)
	}
	if converted.Conditions == nil || len(converted.Conditions.AudienceRestriction) != 1 ||
		converted.Conditions.AudienceRestriction[0].Audience[0] != testRealm {
		t.Fatalf("unexpected conditions: %+v", converted.Conditions)
	}
	if len(converted.AuthnStatement) != 1 || converted.AuthnStatement[0].SessionIndex != "" {
		t.Fatalf("unexpected authn statements: %+v", converted.AuthnStatement)
	}
	if len(converted.AttributeStatement) != 1 || len(converted.AttributeStatement[0].Attribute) != 1 {
		t.Fatalf("unexpected attributes: %+v", converted.AttributeStatement)
	}
	if converted.AttributeStatement[0].Attribute[0].AttributeValue[0].Value != "alice@example.com" {
		t.Fatalf("unexpected attribute value: %+v", converted.AttributeStatement[0].Attribute[0])
	}
	parsedBody, err := ParseWResultString(`<RequestSecurityTokenResponseCollection xmlns="` + NamespaceWSTrust + `">` +
		`<RequestSecurityTokenResponse><RequestedSecurityToken>` + string(data) + `</RequestedSecurityToken></RequestSecurityTokenResponse>` +
		`</RequestSecurityTokenResponseCollection>`)
	if err != nil {
		t.Fatalf("ParseWResultString: %v", err)
	}
	if _, err := parsedBody.Responses[0].RequestedSecurityToken.Assertion(); err != nil {
		t.Fatalf("wrapped SAML 1.1 assertion: %v", err)
	}
}

// TestRequestedSecurityTokenJWT handles raw and wrapped JWT tokens. | TestRequestedSecurityTokenJWT
// 处理原始与包装的 JWT 令牌。
func TestRequestedSecurityTokenJWT(t *testing.T) {
	raw := &RequestedSecurityToken{InnerXML: "header.payload.signature"}
	if raw.TokenType() != TokenTypeJWT {
		t.Fatalf("raw token type = %q", raw.TokenType())
	}
	value, ok := raw.JWT()
	if !ok || value != "header.payload.signature" {
		t.Fatalf("JWT = %q, %v", value, ok)
	}
	wrapped := &RequestedSecurityToken{InnerXML: `<BinarySecurityToken xmlns="` + NamespaceWSSecurity + `">a.b.c</BinarySecurityToken>`}
	if wrapped.TokenType() != TokenTypeJWT {
		t.Fatalf("wrapped token type = %q", wrapped.TokenType())
	}
	value, ok = wrapped.JWT()
	if !ok || value != "a.b.c" {
		t.Fatalf("wrapped JWT = %q, %v", value, ok)
	}
	if _, err := raw.Assertion(); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Assertion err = %v, want ErrUnsupported", err)
	}
	if _, err := (&RequestedSecurityToken{}).Assertion(); !errors.Is(err, ErrNoToken) {
		t.Fatalf("empty Assertion err = %v, want ErrNoToken", err)
	}
}

// TestNewSignOutCollection builds a success response. | TestNewSignOutCollection 构建成功响应。
func TestNewSignOutCollection(t *testing.T) {
	collection := NewSignOutCollection("ctx")
	data, err := collection.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	parsed, err := ParseWResult(data)
	if err != nil {
		t.Fatalf("ParseWResult: %v", err)
	}
	if len(parsed.Responses) != 1 || !parsed.Responses[0].Status.Success() || parsed.Responses[0].Wctx != "ctx" {
		t.Fatalf("unexpected response: %+v", parsed.Responses)
	}
	if parsed.TokenResponse() != nil {
		t.Fatalf("sign-out response carries a token")
	}
}
