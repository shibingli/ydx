package saml

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/xml"
)

// Artifact flow test entity identifiers. | 工件流程测试实体标识。
const (
	artifactIDPEntity = "https://idp.example/metadata"
	artifactSPEntity  = "https://sp.example/metadata"
	artifactACSURL    = "https://sp.example/saml/acs"
)

// testAuthenticator returns an authenticator for the artifact test user. | testAuthenticator 返回工件
// 测试用户的认证器。
func testAuthenticator() Authenticator {
	return AuthenticatorFunc(func(context.Context, http.ResponseWriter, *http.Request, *AuthnRequest) (*auth.Principal, error) {
		return &auth.Principal{Subject: "artifact-user", Email: "artifact@example.com", AuthTime: samlTestNow}, nil
	})
}

// newArtifactTestIdP builds an IdP with a fixed clock, signer and memory store. | newArtifactTestIdP
// 构建具有固定时钟、签名器与内存存储的 IdP。
func newArtifactTestIdP(t *testing.T, mutate func(*IdentityProviderConfig)) (*IdentityProvider, *MemoryStore, *rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, cert := samlTestKeyCert(t)
	store := NewMemoryStore()
	config := IdentityProviderConfig{
		EntityID:      artifactIDPEntity,
		SSOURL:        "https://idp.example/sso",
		Store:         store,
		Authenticator: testAuthenticator(),
		Signer:        &XMLDSigSigner{PrivateKey: key, Certificate: cert, Exclusive: true},
		SignResponse:  true,
		SignAssertion: true,
		Now:           func() time.Time { return samlTestNow },
	}
	if mutate != nil {
		mutate(&config)
	}
	idp, err := NewIdentityProvider(config)
	if err != nil {
		t.Fatalf("idp: %v", err)
	}
	return idp, store, key, cert
}

// artifactMetadata returns IdP metadata publishing an artifact resolution endpoint. |
// artifactMetadata 返回发布工件解析端点的 IdP 元数据。
func artifactMetadata(arsURL string) *EntityDescriptor {
	metadata := testMetadata()
	metadata.IDPSSODescriptor.ArtifactResolutionService = []IndexedEndpoint{{
		Binding:  BindingSOAP,
		Location: arsURL,
		Index:    0,
	}}
	return metadata
}

// artifactAuthnRequestXML builds an AuthnRequest that requests the artifact binding. |
// artifactAuthnRequestXML 构建请求工件绑定的 AuthnRequest。
func artifactAuthnRequestXML(t *testing.T, id string) []byte {
	t.Helper()
	request := &AuthnRequest{
		ID:                          id,
		Version:                     Version,
		IssueInstant:                FormatTime(samlTestNow),
		Destination:                 "https://idp.example/sso",
		ProtocolBinding:             BindingHTTPArtifact,
		AssertionConsumerServiceURL: artifactACSURL,
		Issuer:                      &Issuer{Value: artifactSPEntity},
	}
	document, err := xml.Marshal(request)
	if err != nil {
		t.Fatalf("authn request: %v", err)
	}
	return document
}

// issueArtifact drives the IdP SSO endpoint and returns the artifact and redirect query. |
// issueArtifact 驱动 IdP SSO 端点并返回工件与重定向查询。
func issueArtifact(t *testing.T, idp *IdentityProvider, relayState string) (string, *url.URL) {
	t.Helper()
	document := artifactAuthnRequestXML(t, auth.NewID("artifact-authn"))
	request := httptest.NewRequest(http.MethodPost, "/sso", strings.NewReader(url.Values{
		"SAMLRequest": {EncodePost(document)},
		"RelayState":  {relayState},
	}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	idp.HandleSSO(recorder, request)
	if recorder.Code != http.StatusFound {
		t.Fatalf("SSO status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	location, err := url.Parse(recorder.Header().Get("Location"))
	if err != nil {
		t.Fatalf("location: %v", err)
	}
	return location.Query().Get(ArtifactParameter), location
}

// artifactResolveBody builds a SOAP ArtifactResolve envelope with the given request ID. |
// artifactResolveBody 构建具有给定请求标识的 SOAP ArtifactResolve 信封。
func artifactResolveBody(t *testing.T, id, destination, artifact, issuer string, issueInstant time.Time) []byte {
	t.Helper()
	request := &ArtifactResolve{
		ID:           id,
		Version:      Version,
		IssueInstant: FormatTime(issueInstant),
		Destination:  destination,
		Issuer:       &Issuer{Value: issuer},
		Artifact:     artifact,
	}
	document, err := xml.Marshal(request)
	if err != nil {
		t.Fatalf("artifact resolve: %v", err)
	}
	return buildSOAPEnvelope(document)
}

// postArtifactResolve posts a SOAP body to an artifact resolution handler. | postArtifactResolve 把
// SOAP 正文发送到工件解析处理器。
func postArtifactResolve(handler func(http.ResponseWriter, *http.Request), body []byte) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "https://idp.example/saml/artifact", strings.NewReader(string(body)))
	request.Header.Set("Content-Type", SOAPContentType)
	request.Header.Set("SOAPAction", SOAPActionArtifactResolve)
	recorder := httptest.NewRecorder()
	handler(recorder, request)
	return recorder
}

// artifactResponseNode parses a SOAP ArtifactResponse payload. | artifactResponseNode 解析 SOAP
// ArtifactResponse 载荷。
func artifactResponseNode(t *testing.T, body []byte) *xml.Node {
	t.Helper()
	envelope, err := parseSOAPEnvelope(body)
	if err != nil {
		t.Fatalf("soap envelope: %v", err)
	}
	payload, err := envelope.payload()
	if err != nil {
		t.Fatalf("soap payload: %v", err)
	}
	if payload.Name.Local != "ArtifactResponse" || payload.Name.Space != NamespaceProtocol {
		t.Fatalf("payload = %s", payload.Name.String())
	}
	return payload
}

// artifactResponseStatusValue reads an ArtifactResponse status code. | artifactResponseStatusValue
// 读取 ArtifactResponse 状态码。
func artifactResponseStatusValue(t *testing.T, payload *xml.Node) string {
	t.Helper()
	status, err := artifactResponseStatus(payload)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	return status.StatusCode.Value
}

// TestArtifactSSOBindingIssuesArtifact checks the IdP redirect that carries SAMLart. |
// TestArtifactSSOBindingIssuesArtifact 校验携带 SAMLart 的 IdP 重定向。
func TestArtifactSSOBindingIssuesArtifact(t *testing.T) {
	idp, _, _, _ := newArtifactTestIdP(t, nil)
	artifactValue, location := issueArtifact(t, idp, "relay-artifact")
	if artifactValue == "" {
		t.Fatalf("location = %s", location.String())
	}
	if location.Query().Get("RelayState") != "relay-artifact" {
		t.Fatalf("RelayState = %q", location.Query().Get("RelayState"))
	}
	if location.Path != "/saml/acs" || location.Host != "sp.example" {
		t.Fatalf("location = %s", location.String())
	}
	artifact, err := DecodeArtifact(artifactValue)
	if err != nil {
		t.Fatalf("decode artifact: %v", err)
	}
	if artifact.Type != ArtifactTypeHTTP || artifact.EndpointIndex != 0 || !artifact.SameSource(Artifact{SourceID: idp.ArtifactSourceID()}) {
		t.Fatalf("artifact = %+v", artifact)
	}
}

// TestArtifactResolutionUnsignedRoundTrip covers issuance through SOAP resolution. |
// TestArtifactResolutionUnsignedRoundTrip 覆盖从签发到 SOAP 解析的完整流程。
func TestArtifactResolutionUnsignedRoundTrip(t *testing.T) {
	idp, _, _, _ := newArtifactTestIdP(t, nil)
	artifactValue, _ := issueArtifact(t, idp, "")
	resolveID := auth.NewID("artifact-resolve")
	body := artifactResolveBody(t, resolveID, idp.Config().ArtifactResolutionURL, artifactValue, artifactSPEntity, samlTestNow)
	recorder := postArtifactResolve(idp.HandleArtifactResolution, body)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	payload := artifactResponseNode(t, recorder.Body.Bytes())
	if got := artifactResponseStatusValue(t, payload); got != StatusSuccess {
		t.Fatalf("status = %q body=%s", got, recorder.Body.String())
	}
	if inResponseTo := nodeAttr(payload, "InResponseTo"); inResponseTo != resolveID {
		t.Fatalf("InResponseTo = %q", inResponseTo)
	}
	issuer := payload.FirstChild("Issuer")
	if issuer == nil || strings.TrimSpace(issuer.Text()) != artifactIDPEntity {
		t.Fatalf("issuer = %+v", issuer)
	}
	response := payload.FirstChild("Response")
	if response == nil || response.Name.Space != NamespaceProtocol {
		t.Fatalf("embedded response is missing")
	}
	raw := response.OuterXML()
	if !strings.Contains(string(raw), "Assertion") {
		t.Fatalf("embedded response = %s", raw)
	}
	parsed, err := ParseResponse(raw)
	if err != nil || parsed.Issuer == nil || parsed.Issuer.Value != artifactIDPEntity {
		t.Fatalf("embedded response = %+v err=%v", parsed, err)
	}

	replay := postArtifactResolve(idp.HandleArtifactResolution, body)
	if replay.Code != http.StatusOK {
		t.Fatalf("replay status = %d", replay.Code)
	}
	replayPayload := artifactResponseNode(t, replay.Body.Bytes())
	if got := artifactResponseStatusValue(t, replayPayload); got != StatusRequester {
		t.Fatalf("replay status = %q", got)
	}
	status, _ := artifactResponseStatus(replayPayload)
	if status.StatusMessage == nil || !strings.Contains(status.StatusMessage.Value, "resolved") {
		t.Fatalf("replay message = %+v", status.StatusMessage)
	}
	if replayPayload.FirstChild("Response") != nil {
		t.Fatal("replay carried a Response")
	}
}

// TestArtifactResolutionSignatures covers signed requests and signature requirements. |
// TestArtifactResolutionSignatures 覆盖签名请求与签名要求。
func TestArtifactResolutionSignatures(t *testing.T) {
	verifier := func(cert *x509.Certificate) SignatureVerifier {
		return &XMLDSigVerifier{Certificates: []*x509.Certificate{cert}}
	}
	signRequest := func(t *testing.T, key *rsa.PrivateKey, cert *x509.Certificate, body []byte, id string) []byte {
		t.Helper()
		signed, err := (&XMLDSigSigner{PrivateKey: key, Certificate: cert, Exclusive: true}).SignElement(body, id)
		if err != nil {
			t.Fatalf("sign resolve: %v", err)
		}
		return signed
	}

	t.Run("required signature missing", func(t *testing.T) {
		idp, _, _, _ := newArtifactTestIdP(t, func(config *IdentityProviderConfig) {
			config.WantArtifactResolveSigned = true
		})
		artifactValue, _ := issueArtifact(t, idp, "")
		recorder := postArtifactResolve(idp.HandleArtifactResolution, artifactResolveBody(t, auth.NewID("resolve"), idp.Config().ArtifactResolutionURL, artifactValue, artifactSPEntity, samlTestNow))
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("status = %d", recorder.Code)
		}
		fault := artifactResponseFault(t, recorder.Body.Bytes())
		if fault.Code != "soap:Client" {
			t.Fatalf("fault = %+v", fault)
		}
	})

	t.Run("signed request", func(t *testing.T) {
		idp, _, key, cert := newArtifactTestIdP(t, func(config *IdentityProviderConfig) {
			config.WantArtifactResolveSigned = true
		})
		idp.config.SignatureVerifier = verifier(cert)
		artifactValue, _ := issueArtifact(t, idp, "")
		resolveID := auth.NewID("resolve")
		document := artifactResolveDocument(t, resolveID, idp.Config().ArtifactResolutionURL, artifactValue, artifactSPEntity)
		signed := signRequest(t, key, cert, document, resolveID)
		recorder := postArtifactResolve(idp.HandleArtifactResolution, buildSOAPEnvelope(signed))
		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
		}
		payload := artifactResponseNode(t, recorder.Body.Bytes())
		if got := artifactResponseStatusValue(t, payload); got != StatusSuccess {
			t.Fatalf("status = %q", got)
		}
	})

	t.Run("tampered signature", func(t *testing.T) {
		idp, _, key, cert := newArtifactTestIdP(t, nil)
		idp.config.SignatureVerifier = verifier(cert)
		artifactValue, _ := issueArtifact(t, idp, "")
		resolveID := auth.NewID("resolve")
		document := artifactResolveDocument(t, resolveID, idp.Config().ArtifactResolutionURL, artifactValue, artifactSPEntity)
		signed := signRequest(t, key, cert, document, resolveID)
		tampered := strings.Replace(string(signed), artifactValue, tamperedArtifact(t, artifactValue), 1)
		recorder := postArtifactResolve(idp.HandleArtifactResolution, buildSOAPEnvelope([]byte(tampered)))
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
		}
	})

	t.Run("no verifier configured", func(t *testing.T) {
		idp, _, key, cert := newArtifactTestIdP(t, nil)
		artifactValue, _ := issueArtifact(t, idp, "")
		resolveID := auth.NewID("resolve")
		signed := signRequest(t, key, cert, artifactResolveDocument(t, resolveID, idp.Config().ArtifactResolutionURL, artifactValue, artifactSPEntity), resolveID)
		recorder := postArtifactResolve(idp.HandleArtifactResolution, buildSOAPEnvelope(signed))
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("status = %d", recorder.Code)
		}
	})
}

// TestArtifactResolutionRejections covers invalid artifacts and malformed envelopes. |
// TestArtifactResolutionRejections 覆盖非法工件与非法信封。
func TestArtifactResolutionRejections(t *testing.T) {
	idp, _, _, _ := newArtifactTestIdP(t, nil)
	destination := idp.Config().ArtifactResolutionURL

	t.Run("malformed artifact", func(t *testing.T) {
		recorder := postArtifactResolve(idp.HandleArtifactResolution, artifactResolveBody(t, auth.NewID("resolve"), destination, "not-base64!", artifactSPEntity, samlTestNow))
		assertArtifactRequester(t, recorder, "invalid artifact")
	})

	t.Run("wrong source", func(t *testing.T) {
		var source [ArtifactSourceIDSize]byte
		if _, err := rand.Read(source[:]); err != nil {
			t.Fatal(err)
		}
		artifact, err := NewArtifact(0, source)
		if err != nil {
			t.Fatal(err)
		}
		recorder := postArtifactResolve(idp.HandleArtifactResolution, artifactResolveBody(t, auth.NewID("resolve"), destination, artifact.String(), artifactSPEntity, samlTestNow))
		assertArtifactRequester(t, recorder, "invalid artifact")
	})

	t.Run("wrong index", func(t *testing.T) {
		artifactValue, _ := issueArtifact(t, idp, "")
		artifact, err := DecodeArtifact(artifactValue)
		if err != nil {
			t.Fatal(err)
		}
		artifact.EndpointIndex = 1
		recorder := postArtifactResolve(idp.HandleArtifactResolution, artifactResolveBody(t, auth.NewID("resolve"), destination, artifact.String(), artifactSPEntity, samlTestNow))
		assertArtifactRequester(t, recorder, "invalid artifact")
	})

	t.Run("unknown artifact", func(t *testing.T) {
		artifact, err := NewArtifact(0, idp.ArtifactSourceID())
		if err != nil {
			t.Fatal(err)
		}
		recorder := postArtifactResolve(idp.HandleArtifactResolution, artifactResolveBody(t, auth.NewID("resolve"), destination, artifact.String(), artifactSPEntity, samlTestNow))
		assertArtifactRequester(t, recorder, "invalid artifact")
	})

	t.Run("expired artifact", func(t *testing.T) {
		current := samlTestNow
		idp, _, _, _ := newArtifactTestIdP(t, func(config *IdentityProviderConfig) {
			config.Now = func() time.Time { return current }
			config.ArtifactTTL = time.Minute
		})
		artifactValue, _ := issueArtifact(t, idp, "")
		current = current.Add(2 * time.Minute)
		recorder := postArtifactResolve(idp.HandleArtifactResolution, artifactResolveBody(t, auth.NewID("resolve"), idp.Config().ArtifactResolutionURL, artifactValue, artifactSPEntity, current))
		assertArtifactRequester(t, recorder, "artifact expired")
	})

	t.Run("wrong requester", func(t *testing.T) {
		idp, _, _, _ := newArtifactTestIdP(t, nil)
		artifactValue, _ := issueArtifact(t, idp, "")
		recorder := postArtifactResolve(idp.HandleArtifactResolution, artifactResolveBody(t, auth.NewID("resolve"), idp.Config().ArtifactResolutionURL, artifactValue, "https://other.example/metadata", samlTestNow))
		assertArtifactRequester(t, recorder, "invalid artifact")
	})

	invalidRequests := map[string][]byte{
		"missing ID":        artifactResolveBodyRaw(t, "", Version, FormatTime(samlTestNow), destination, artifactIDPEntity, "AA=="),
		"wrong version":     artifactResolveBodyRaw(t, "resolve", "1.1", FormatTime(samlTestNow), destination, artifactIDPEntity, "AA=="),
		"bad instant":       artifactResolveBodyRaw(t, "resolve", Version, "yesterday", destination, artifactIDPEntity, "AA=="),
		"missing issuer":    artifactResolveBodyRaw(t, "resolve", Version, FormatTime(samlTestNow), destination, "", "AA=="),
		"missing artifact":  artifactResolveBodyRaw(t, "resolve", Version, FormatTime(samlTestNow), destination, artifactIDPEntity, ""),
		"wrong destination": artifactResolveBodyRaw(t, "resolve", Version, FormatTime(samlTestNow), "https://evil.example/ars", artifactIDPEntity, "AA=="),
	}
	for name, body := range invalidRequests {
		recorder := postArtifactResolve(idp.HandleArtifactResolution, body)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("%s status = %d body=%s", name, recorder.Code, recorder.Body.String())
		}
	}

	otherPayload := buildSOAPEnvelope([]byte(`<samlp:LogoutRequest xmlns:samlp="` + NamespaceProtocol + `"/>`))
	if recorder := postArtifactResolve(idp.HandleArtifactResolution, otherPayload); recorder.Code != http.StatusBadRequest {
		t.Fatalf("unexpected payload status = %d", recorder.Code)
	}
	clientFault := buildSOAPEnvelope([]byte(`<soapenv:Fault xmlns:soapenv="` + NamespaceSOAP + `"><faultcode>soapenv:Client</faultcode><faultstring>bad</faultstring></soapenv:Fault>`))
	if recorder := postArtifactResolve(idp.HandleArtifactResolution, clientFault); recorder.Code != http.StatusBadRequest {
		t.Fatalf("client fault status = %d", recorder.Code)
	}

	getRequest := httptest.NewRequest(http.MethodGet, "https://idp.example/saml/artifact", nil)
	getRecorder := httptest.NewRecorder()
	idp.HandleArtifactResolution(getRecorder, getRequest)
	if getRecorder.Code != http.StatusMethodNotAllowed || getRecorder.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("GET status = %d", getRecorder.Code)
	}
	badAction := postArtifactResolve(idp.HandleArtifactResolution, artifactResolveBody(t, auth.NewID("resolve"), destination, "AA==", artifactSPEntity, samlTestNow))
	if badAction.Code != http.StatusOK {
		t.Fatalf("baseline status = %d", badAction.Code)
	}
	actionRequest := httptest.NewRequest(http.MethodPost, "/saml/artifact", strings.NewReader(string(artifactResolveBody(t, auth.NewID("resolve"), destination, "AA==", artifactSPEntity, samlTestNow))))
	actionRequest.Header.Set("SOAPAction", SOAPActionArtifactResponse)
	actionRecorder := httptest.NewRecorder()
	idp.HandleArtifactResolution(actionRecorder, actionRequest)
	if actionRecorder.Code != http.StatusBadRequest {
		t.Fatalf("wrong SOAPAction status = %d", actionRecorder.Code)
	}
	oversized := httptest.NewRequest(http.MethodPost, "/saml/artifact", strings.NewReader("<x/>"))
	oversized.Header.Set("SOAPAction", SOAPActionArtifactResolve)
	oversized.ContentLength = MaxSOAPMessageBytes + 1
	oversizedRecorder := httptest.NewRecorder()
	idp.HandleArtifactResolution(oversizedRecorder, oversized)
	if oversizedRecorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized status = %d", oversizedRecorder.Code)
	}
}

// TestArtifactSignResponseCompatibility checks artifact delivery with an unsigned response. |
// TestArtifactSignResponseCompatibility 校验未签名响应的工件投递。
func TestArtifactSignResponseCompatibility(t *testing.T) {
	idp, _, _, _ := newArtifactTestIdP(t, func(config *IdentityProviderConfig) {
		config.Signer = nil
		config.SignResponse = false
		config.SignAssertion = false
	})
	artifactValue, _ := issueArtifact(t, idp, "")
	resolveID := auth.NewID("resolve")
	recorder := postArtifactResolve(idp.HandleArtifactResolution, artifactResolveBody(t, resolveID, idp.Config().ArtifactResolutionURL, artifactValue, artifactSPEntity, samlTestNow))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	payload := artifactResponseNode(t, recorder.Body.Bytes())
	if payload.FirstChild("Signature") != nil {
		t.Fatal("unsigned IdP signed ArtifactResponse")
	}
	if got := artifactResponseStatusValue(t, payload); got != StatusSuccess {
		t.Fatalf("status = %q", got)
	}
}

// TestArtifactHandlerMounts checks router and net/http mounting of the resolution endpoint. |
// TestArtifactHandlerMounts 校验解析端点在 router 与 net/http 上的挂载。
func TestArtifactHandlerMounts(t *testing.T) {
	idp, _, _, _ := newArtifactTestIdP(t, nil)
	if idp.Config().ARSPath != "/saml/artifact" {
		t.Fatalf("ARSPath = %q", idp.Config().ARSPath)
	}
	handler := idp.HTTPHandler("")
	if handler == nil {
		t.Fatal("nil HTTP handler")
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/saml/artifact", nil))
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("mounted GET status = %d", recorder.Code)
	}
}

// artifactResolveBodyRaw builds an ArtifactResolve envelope with raw attribute values. |
// artifactResolveBodyRaw 使用原始属性值构建 ArtifactResolve 信封。
func artifactResolveBodyRaw(t *testing.T, id, version, instant, destination, issuer, artifact string) []byte {
	t.Helper()
	var b []byte
	b = append(b, `<samlp:ArtifactResolve xmlns:samlp="`+NamespaceProtocol+`" xmlns:saml="`+NamespaceAssertion+`"`...)
	if id != "" {
		b = append(b, ` ID="`+htmlEscape(id)+`"`...)
	}
	if version != "" {
		b = append(b, ` Version="`+htmlEscape(version)+`"`...)
	}
	if instant != "" {
		b = append(b, ` IssueInstant="`+htmlEscape(instant)+`"`...)
	}
	if destination != "" {
		b = append(b, ` Destination="`+htmlEscape(destination)+`"`...)
	}
	b = append(b, `>`...)
	if issuer != "" {
		b = append(b, `<saml:Issuer>`+htmlEscape(issuer)+`</saml:Issuer>`...)
	}
	if artifact != "" {
		b = append(b, `<samlp:Artifact>`+htmlEscape(artifact)+`</samlp:Artifact>`...)
	}
	b = append(b, `</samlp:ArtifactResolve>`...)
	return buildSOAPEnvelope(b)
}

// artifactResolveDocument builds a standalone ArtifactResolve document. | artifactResolveDocument
// 构建独立 ArtifactResolve 文档。
func artifactResolveDocument(t *testing.T, id, destination, artifact, issuer string) []byte {
	t.Helper()
	request := &ArtifactResolve{
		ID:           id,
		Version:      Version,
		IssueInstant: FormatTime(samlTestNow),
		Destination:  destination,
		Issuer:       &Issuer{Value: issuer},
		Artifact:     artifact,
	}
	document, err := xml.Marshal(request)
	if err != nil {
		t.Fatalf("artifact resolve: %v", err)
	}
	return document
}

// tamperedArtifact returns a valid artifact value that differs from value. | tamperedArtifact 返回与
// value 不同的合法工件值。
func tamperedArtifact(t *testing.T, value string) string {
	t.Helper()
	artifact, err := DecodeArtifact(value)
	if err != nil {
		t.Fatalf("decode artifact: %v", err)
	}
	artifact.MessageHandle[0] ^= 0xff
	return artifact.String()
}

// artifactResponseFault parses a SOAP fault from a response body. | artifactResponseFault 从响应正文
// 解析 SOAP 异常。
func artifactResponseFault(t *testing.T, body []byte) *SOAPFault {
	t.Helper()
	envelope, err := parseSOAPEnvelope(body)
	if err != nil {
		t.Fatalf("fault envelope: %v", err)
	}
	_, err = envelope.payload()
	var fault *SOAPFault
	if !errors.As(err, &fault) {
		t.Fatalf("expected fault, got %v", err)
	}
	return fault
}

// assertArtifactRequester asserts an ArtifactResponse with a requester status and message. |
// assertArtifactRequester 断言携带请求方状态与消息的 ArtifactResponse。
func assertArtifactRequester(t *testing.T, recorder *httptest.ResponseRecorder, message string) {
	t.Helper()
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	payload := artifactResponseNode(t, recorder.Body.Bytes())
	if got := artifactResponseStatusValue(t, payload); got != StatusRequester {
		t.Fatalf("status = %q body=%s", got, recorder.Body.String())
	}
	status, _ := artifactResponseStatus(payload)
	if status.StatusMessage == nil || !strings.Contains(status.StatusMessage.Value, message) {
		t.Fatalf("message = %+v want %q", status.StatusMessage, message)
	}
}
