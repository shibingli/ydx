package saml

import (
	"context"
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

// failingSigner always fails signing. | failingSigner 总是签名失败。
type failingSigner struct{ err error }

// SignElement implements XMLSigner. | SignElement 实现 XMLSigner。
func (s failingSigner) SignElement([]byte, string) ([]byte, error) { return nil, s.err }

// overrideArtifactStore wraps a MemoryStore and intercepts artifact operations. |
// overrideArtifactStore 包装 MemoryStore 并拦截工件操作。
type overrideArtifactStore struct {
	*MemoryStore
	takeErr      error
	saveErr      error
	mutateRecord func(*ArtifactRecord)
}

// SaveArtifact saves an artifact or returns the injected error. | SaveArtifact 保存工件或返回注入的错误。
func (s *overrideArtifactStore) SaveArtifact(ctx context.Context, record *ArtifactRecord, now time.Time) error {
	if s.saveErr != nil {
		return s.saveErr
	}
	return s.MemoryStore.SaveArtifact(ctx, record, now)
}

// TakeArtifact takes an artifact, optionally mutating the returned record. | TakeArtifact 取出工件，
// 并可修改返回的记录。
func (s *overrideArtifactStore) TakeArtifact(ctx context.Context, artifact Artifact, now time.Time) (*ArtifactRecord, error) {
	if s.takeErr != nil {
		return nil, s.takeErr
	}
	record, err := s.MemoryStore.TakeArtifact(ctx, artifact, now)
	if err != nil {
		return nil, err
	}
	if s.mutateRecord != nil {
		s.mutateRecord(record)
	}
	return record, nil
}

// artifactEdgeSP returns an SP for artifact response parsing tests. | artifactEdgeSP 返回用于工件响应
// 解析测试的 SP。
func artifactEdgeSP(t *testing.T, mutate func(*ServiceProviderConfig)) *ServiceProvider {
	t.Helper()
	config := ServiceProviderConfig{
		EntityID:    artifactSPEntity,
		ACSURL:      artifactACSURL,
		IDPMetadata: artifactMetadata("https://idp.example/saml/artifact"),
		Store:       NewMemoryStore(),
		Now:         func() time.Time { return samlTestNow },
	}
	if mutate != nil {
		mutate(&config)
	}
	sp, err := NewServiceProvider(config)
	if err != nil {
		t.Fatalf("sp: %v", err)
	}
	return sp
}

// artifactResponseEnvelope builds a SOAP ArtifactResponse with raw status and optional embedded
// Response. | artifactResponseEnvelope 构建携带原始状态与可选嵌入 Response 的 SOAP ArtifactResponse。
func artifactResponseEnvelope(t *testing.T, attributes, issuer, statusXML string, embedded bool) []byte {
	t.Helper()
	var b []byte
	b = append(b, `<samlp:ArtifactResponse xmlns:samlp="`+NamespaceProtocol+`" xmlns:saml="`+NamespaceAssertion+
		`" xmlns:ds="`+NamespaceXMLDSig+`"`...)
	if attributes != "" {
		b = append(b, " "+attributes...)
	}
	b = append(b, `><saml:Issuer>`+htmlEscape(issuer)+`</saml:Issuer>`+statusXML...)
	if embedded {
		b = append(b, `<samlp:Response ID="embedded-response"><samlp:Status><samlp:StatusCode Value="`+StatusSuccess+`"/></samlp:Status></samlp:Response>`...)
	}
	b = append(b, `</samlp:ArtifactResponse>`...)
	return buildSOAPEnvelope(b)
}

// TestArtifactSPInternals covers endpoint validation, signer construction and client selection. |
// TestArtifactSPInternals 覆盖端点校验、签名器构建与客户端选择。
func TestArtifactSPInternals(t *testing.T) {
	for name, test := range map[string]struct {
		url string
		ok  bool
	}{
		"https":       {url: "https://idp.example/ars", ok: true},
		"http":        {url: "http://idp.example/ars", ok: true},
		"bad url":     {url: "://bad"},
		"ftp":         {url: "ftp://idp.example/ars"},
		"no host":     {url: "https:///ars"},
		"credentials": {url: "https://user:pass@idp.example/ars"},
		"fragment":    {url: "https://idp.example/ars#frag"},
	} {
		err := validateSOAPEndpoint(test.url)
		if (err == nil) != test.ok {
			t.Fatalf("%s error = %v", name, err)
		}
		if err != nil && !errors.Is(err, ErrInvalidMetadata) {
			t.Fatalf("%s sentinel = %v", name, err)
		}
	}

	sp := artifactEdgeSP(t, func(config *ServiceProviderConfig) {
		config.ArtifactResolutionTimeout = 3 * time.Second
	})
	client := sp.artifactHTTPClient()
	if client == nil || client.Timeout != 3*time.Second || client.CheckRedirect == nil {
		t.Fatalf("default client = %+v", client)
	}
	custom := &http.Client{Timeout: time.Minute}
	sp.config.ArtifactHTTPClient = custom
	if sp.artifactHTTPClient() != custom {
		t.Fatal("configured client was not returned")
	}

	key, cert := samlTestKeyCert(t)
	signingSP := artifactEdgeSP(t, func(config *ServiceProviderConfig) {
		config.ArtifactRequestSigner = &XMLDSigSigner{PrivateKey: key, Certificate: cert, Exclusive: true}
	})
	artifact, err := NewArtifact(0, [ArtifactSourceIDSize]byte{})
	if err != nil {
		t.Fatalf("artifact: %v", err)
	}
	body, requestID, err := signingSP.buildArtifactResolve("https://idp.example/ars", artifact)
	if err != nil || requestID == "" || !strings.Contains(string(body), "Signature") {
		t.Fatalf("signed resolve = %s err=%v", body, err)
	}
	signingSP.config.ArtifactRequestSigner = failingSigner{err: errors.New("sign failed")}
	if _, _, err := signingSP.buildArtifactResolve("https://idp.example/ars", artifact); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("failing signer error = %v", err)
	}
}

// TestArtifactResponseStatusNode covers Status parsing branches. | TestArtifactResponseStatusNode
// 覆盖 Status 解析分支。
func TestArtifactResponseStatusNode(t *testing.T) {
	parsePayload := func(t *testing.T, body []byte) *xml.Node {
		t.Helper()
		envelope, err := parseSOAPEnvelope(body)
		if err != nil {
			t.Fatalf("envelope: %v", err)
		}
		payload, err := envelope.payload()
		if err != nil {
			t.Fatalf("payload: %v", err)
		}
		return payload
	}

	for name, status := range map[string]string{
		"missing status": ``,
		"missing code":   `<samlp:Status/>`,
		"empty code":     `<samlp:Status><samlp:StatusCode/></samlp:Status>`,
	} {
		payload := parsePayload(t, artifactResponseEnvelope(t, `ID="x"`, artifactIDPEntity, status, false))
		if _, err := artifactResponseStatus(payload); !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("%s error = %v", name, err)
		}
	}

	status := `<samlp:Status><samlp:StatusCode Value="` + StatusSuccess + `"><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:ac:classes:Password"/></samlp:StatusCode><samlp:StatusMessage> ok </samlp:StatusMessage></samlp:Status>`
	payload := parsePayload(t, artifactResponseEnvelope(t, `ID="x"`, artifactIDPEntity, status, false))
	parsed, err := artifactResponseStatus(payload)
	if err != nil || parsed.StatusCode.StatusCode == nil || parsed.StatusMessage == nil || parsed.StatusMessage.Value != "ok" {
		t.Fatalf("nested status = %+v err=%v", parsed, err)
	}
}

// TestArtifactResponseParseErrors covers ArtifactResponse validation branches. |
// TestArtifactResponseParseErrors 覆盖 ArtifactResponse 校验分支。
func TestArtifactResponseParseErrors(t *testing.T) {
	sp := artifactEdgeSP(t, nil)
	requestID := "artifact-request-1"
	instant := `ID="ar-1" Version="` + Version + `" IssueInstant="` + FormatTime(samlTestNow) + `" InResponseTo="` + requestID + `"`
	successStatus := `<samlp:Status><samlp:StatusCode Value="` + StatusSuccess + `"/></samlp:Status>`

	if raw, err := sp.parseArtifactResponse(context.Background(), artifactResponseEnvelope(t, instant, artifactIDPEntity, successStatus, true), http.StatusOK, requestID); err != nil {
		t.Fatalf("valid response: %v", err)
	} else if !strings.Contains(string(raw), "embedded-response") {
		t.Fatalf("embedded response = %s", raw)
	}

	cases := map[string]struct {
		body   []byte
		status int
		want   error
	}{
		"payload not ArtifactResponse": {
			body:   buildSOAPEnvelope([]byte(`<samlp:LogoutResponse xmlns:samlp="` + NamespaceProtocol + `"/>`)),
			status: http.StatusOK,
			want:   ErrInvalidResponse,
		},
		"empty SOAP body": {
			body:   []byte(`<soapenv:Envelope xmlns:soapenv="` + NamespaceSOAP + `"><soapenv:Body/></soapenv:Envelope>`),
			status: http.StatusOK,
			want:   ErrInvalidResponse,
		},
		"missing ID": {
			body:   artifactResponseEnvelope(t, `Version="`+Version+`" IssueInstant="`+FormatTime(samlTestNow)+`" InResponseTo="`+requestID+`"`, artifactIDPEntity, successStatus, true),
			status: http.StatusOK,
			want:   ErrInvalidResponse,
		},
		"wrong version": {
			body:   artifactResponseEnvelope(t, `ID="ar-1" Version="1.1" IssueInstant="`+FormatTime(samlTestNow)+`" InResponseTo="`+requestID+`"`, artifactIDPEntity, successStatus, true),
			status: http.StatusOK,
			want:   ErrInvalidResponse,
		},
		"bad instant": {
			body:   artifactResponseEnvelope(t, `ID="ar-1" Version="`+Version+`" IssueInstant="yesterday" InResponseTo="`+requestID+`"`, artifactIDPEntity, successStatus, true),
			status: http.StatusOK,
			want:   ErrInvalidResponse,
		},
		"non-200": {
			body:   artifactResponseEnvelope(t, instant, artifactIDPEntity, successStatus, true),
			status: http.StatusServiceUnavailable,
			want:   ErrInvalidResponse,
		},
		"no Response": {
			body:   artifactResponseEnvelope(t, instant, artifactIDPEntity, successStatus, false),
			status: http.StatusOK,
			want:   ErrInvalidResponse,
		},
	}
	for name, test := range cases {
		_, err := sp.parseArtifactResponse(context.Background(), test.body, test.status, requestID)
		if !errors.Is(err, test.want) {
			t.Fatalf("%s error = %v", name, err)
		}
	}

	// A payload-level signature without a configured verifier is rejected as unsigned policy. |
	// 未配置校验器时，载荷级签名按签名策略被拒绝。
	signedEnvelope := func(t *testing.T) []byte {
		t.Helper()
		var b []byte
		b = append(b, (`<samlp:ArtifactResponse xmlns:samlp="` + NamespaceProtocol + `" xmlns:saml="` + NamespaceAssertion +
			`" ID="ar-1" Version="` + Version + `" IssueInstant="` + FormatTime(samlTestNow) + `" InResponseTo="` + requestID + `">`)...)
		b = append(b, `<saml:Issuer>`+artifactIDPEntity+`</saml:Issuer><ds:Signature xmlns:ds="`+NamespaceXMLDSig+`"/>`...)
		b = append(b, successStatus...)
		b = append(b, `</samlp:ArtifactResponse>`...)
		return buildSOAPEnvelope(b)
	}
	if _, err := sp.parseArtifactResponse(context.Background(), signedEnvelope(t), http.StatusOK, requestID); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("signed without verifier error = %v", err)
	}
	sp.config.SignatureVerifier = &XMLDSigVerifier{Certificates: []*x509.Certificate{samlTestCert(t)}}
	if _, err := sp.parseArtifactResponse(context.Background(), signedEnvelope(t), http.StatusOK, requestID); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("invalid signature error = %v", err)
	}
}

// samlTestCert returns a test certificate. | samlTestCert 返回测试证书。
func samlTestCert(t *testing.T) *x509.Certificate {
	t.Helper()
	_, cert := samlTestKeyCert(t)
	return cert
}

// TestArtifactSOAPEdges covers SOAP helper branches that the main flow does not reach. |
// TestArtifactSOAPEdges 覆盖主流程未触达的 SOAP 辅助分支。
func TestArtifactSOAPEdges(t *testing.T) {
	var nilFault *SOAPFault
	if nilFault.Error() == "" {
		t.Fatal("nil fault error is empty")
	}
	if (&SOAPFault{Code: "soap:Client"}).Error() == "" {
		t.Fatal("fault error without reason is empty")
	}
	emptyFault := SOAPFault{}
	if got := emptyFault.Error(); !strings.Contains(got, "SOAP fault") {
		t.Fatalf("fault error = %q", got)
	}
	if _, err := (*soapEnvelope)(nil).payload(); err == nil {
		t.Fatal("nil envelope payload accepted")
	}
	if _, err := (&soapEnvelope{}).payload(); err == nil {
		t.Fatal("envelope without body accepted")
	}
	empty := &soapEnvelope{body: &xml.Node{Children: []*xml.Node{{Kind: xml.TextNode, Data: []byte(" ")}}}}
	if _, err := empty.payload(); err == nil {
		t.Fatal("text-only body accepted")
	}
	faultEnvelope := &soapEnvelope{body: &xml.Node{Children: []*xml.Node{{Kind: xml.ElementNode, Name: xml.Name{Local: "Fault", Space: NamespaceSOAP}, Children: []*xml.Node{{Kind: xml.ElementNode, Name: xml.Name{Local: "faultstring"}, Children: []*xml.Node{{Kind: xml.TextNode, Data: []byte("no code")}}}}}}}}
	if _, err := faultEnvelope.payload(); !errors.Is(err, ErrSOAPFault) {
		t.Fatalf("fault without code error = %v", err)
	} else if !strings.Contains(err.Error(), "soap:Server") {
		t.Fatalf("default fault code = %v", err)
	}

	var dst []byte
	if got := appendStatusCodeXML(dst, nil); len(got) != 0 {
		t.Fatalf("nil status code = %s", got)
	}
	dst = appendStatusCodeXML(nil, &StatusCode{Value: StatusSuccess})
	if string(dst) != `<samlp:StatusCode Value="`+StatusSuccess+`"/>` {
		t.Fatalf("status code = %s", dst)
	}
	dst = appendStatusCodeXML(nil, &StatusCode{Value: StatusRequester, StatusCode: &StatusCode{Value: StatusSuccess}})
	if !strings.Contains(string(dst), `</samlp:StatusCode>`) {
		t.Fatalf("nested status code = %s", dst)
	}
}

// TestArtifactMetadataFallback covers artifact endpoint lookup without the SOAP binding. |
// TestArtifactMetadataFallback 覆盖缺少 SOAP 绑定时的工件端点查找。
func TestArtifactMetadataFallback(t *testing.T) {
	metadata := artifactMetadata("")
	metadata.IDPSSODescriptor.ArtifactResolutionService = []IndexedEndpoint{{
		Binding:  BindingHTTPPost,
		Location: "https://idp.example/artifact",
		Index:    0,
	}}
	if location := metadata.ArtifactResolutionURL(0); location != "https://idp.example/artifact" {
		t.Fatalf("fallback location = %q", location)
	}
	if location := metadata.ArtifactResolutionURL(2); location != "" {
		t.Fatalf("missing index location = %q", location)
	}
	var empty *EntityDescriptor
	if location := empty.ArtifactResolutionURL(0); location != "" {
		t.Fatalf("nil metadata location = %q", location)
	}
}

// TestArtifactResolveEndpointValidation checks that resolveArtifact rejects unusable endpoints. |
// TestArtifactResolveEndpointValidation 校验 resolveArtifact 拒绝不可用端点。
func TestArtifactResolveEndpointValidation(t *testing.T) {
	sp := artifactEdgeSP(t, func(config *ServiceProviderConfig) {
		config.IDPMetadata = artifactMetadata("ftp://idp.example/ars")
	})
	artifact, err := NewArtifact(0, [ArtifactSourceIDSize]byte{})
	if err != nil {
		t.Fatalf("artifact: %v", err)
	}
	if _, err := sp.resolveArtifact(context.Background(), artifact.String()); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("error = %v", err)
	}
}

// TestArtifactResolutionStoreErrors covers store, record and signing failures at the IdP. |
// TestArtifactResolutionStoreErrors 覆盖 IdP 的存储、记录与签名失败。
func TestArtifactResolutionStoreErrors(t *testing.T) {
	t.Run("store without artifacts", func(t *testing.T) {
		idp, err := NewIdentityProvider(IdentityProviderConfig{
			EntityID:      artifactIDPEntity,
			SSOURL:        "https://idp.example/sso",
			Store:         storeWithoutArtifacts{},
			Authenticator: testAuthenticator(),
			Now:           func() time.Time { return samlTestNow },
		})
		if err != nil {
			t.Fatalf("idp: %v", err)
		}
		artifact, err := NewArtifact(0, idp.ArtifactSourceID())
		if err != nil {
			t.Fatalf("artifact: %v", err)
		}
		recorder := postArtifactResolve(idp.HandleArtifactResolution, artifactResolveBody(t, auth.NewID("resolve"), idp.Config().ArtifactResolutionURL, artifact.String(), artifactSPEntity, samlTestNow))
		fault := artifactResponseFault(t, recorder.Body.Bytes())
		if recorder.Code != http.StatusInternalServerError || fault.Code != "soap:Server" {
			t.Fatalf("status = %d fault = %+v", recorder.Code, fault)
		}
	})

	t.Run("take failure", func(t *testing.T) {
		store := &overrideArtifactStore{MemoryStore: NewMemoryStore()}
		idp, _, _, _ := newArtifactTestIdP(t, func(config *IdentityProviderConfig) { config.Store = store })
		artifactValue, _ := issueArtifact(t, idp, "")
		store.takeErr = errors.New("store down")
		recorder := postArtifactResolve(idp.HandleArtifactResolution, artifactResolveBody(t, auth.NewID("resolve"), idp.Config().ArtifactResolutionURL, artifactValue, artifactSPEntity, samlTestNow))
		fault := artifactResponseFault(t, recorder.Body.Bytes())
		if recorder.Code != http.StatusInternalServerError || fault.Code != "soap:Server" {
			t.Fatalf("status = %d fault = %+v", recorder.Code, fault)
		}
	})

	records := map[string]func(*ArtifactRecord){
		"endpoint mismatch": func(record *ArtifactRecord) { record.Artifact.EndpointIndex = 9 },
		"type mismatch":     func(record *ArtifactRecord) { record.Artifact.Type = 0x0002 },
		"handle mismatch":   func(record *ArtifactRecord) { record.Artifact.MessageHandle[0] ^= 0xff },
		"idp mismatch":      func(record *ArtifactRecord) { record.IDPEntityID = "https://other.example/metadata" },
	}
	for name, mutate := range records {
		t.Run(name, func(t *testing.T) {
			store := &overrideArtifactStore{MemoryStore: NewMemoryStore(), mutateRecord: mutate}
			idp, _, _, _ := newArtifactTestIdP(t, func(config *IdentityProviderConfig) { config.Store = store })
			artifactValue, _ := issueArtifact(t, idp, "")
			recorder := postArtifactResolve(idp.HandleArtifactResolution, artifactResolveBody(t, auth.NewID("resolve"), idp.Config().ArtifactResolutionURL, artifactValue, artifactSPEntity, samlTestNow))
			assertArtifactRequester(t, recorder, "invalid artifact")
		})
	}

	t.Run("response signing failure", func(t *testing.T) {
		idp, _, _, _ := newArtifactTestIdP(t, func(config *IdentityProviderConfig) {
			config.SignArtifactResponse = true
		})
		artifactValue, _ := issueArtifact(t, idp, "")
		idp.config.Signer = failingSigner{err: errors.New("sign failed")}
		recorder := postArtifactResolve(idp.HandleArtifactResolution, artifactResolveBody(t, auth.NewID("resolve"), idp.Config().ArtifactResolutionURL, artifactValue, artifactSPEntity, samlTestNow))
		fault := artifactResponseFault(t, recorder.Body.Bytes())
		if recorder.Code != http.StatusInternalServerError || fault.Code != "soap:Server" {
			t.Fatalf("status = %d fault = %+v", recorder.Code, fault)
		}
	})

	t.Run("status signing failure", func(t *testing.T) {
		idp, _, _, _ := newArtifactTestIdP(t, func(config *IdentityProviderConfig) {
			config.SignArtifactResponse = true
		})
		idp.config.Signer = failingSigner{err: errors.New("sign failed")}
		recorder := postArtifactResolve(idp.HandleArtifactResolution, artifactResolveBody(t, auth.NewID("resolve"), idp.Config().ArtifactResolutionURL, "AA==", artifactSPEntity, samlTestNow))
		fault := artifactResponseFault(t, recorder.Body.Bytes())
		if recorder.Code != http.StatusInternalServerError || fault.Code != "soap:Server" {
			t.Fatalf("status = %d fault = %+v", recorder.Code, fault)
		}
	})
}

// TestArtifactIdPDeliveryEdges covers metadata derivation and artifact delivery failures. |
// TestArtifactIdPDeliveryEdges 覆盖元数据推导与工件投递失败。
func TestArtifactIdPDeliveryEdges(t *testing.T) {
	idp, _, _, _ := newArtifactTestIdP(t, nil)
	if idp.ArtifactResolutionURL() != "https://idp.example/saml/artifact" {
		t.Fatalf("resolution URL = %q", idp.ArtifactResolutionURL())
	}

	relative, _, _, _ := newArtifactTestIdP(t, func(config *IdentityProviderConfig) {
		config.SSOURL = "idp.example/sso"
		config.ArtifactResolutionURL = ""
	})
	if relative.ArtifactResolutionURL() != "" {
		t.Fatalf("relative SSO URL derived %q", relative.ArtifactResolutionURL())
	}
	requestXML := artifactAuthnRequestXML(t, auth.NewID("artifact-authn"))
	requestXML = []byte(strings.Replace(string(requestXML), ` Destination="https://idp.example/sso"`, "", 1))
	form := url.Values{"SAMLRequest": {EncodePost(requestXML)}}
	request := httptest.NewRequest(http.MethodPost, "/sso", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	relative.HandleSSO(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}

	store := &overrideArtifactStore{MemoryStore: NewMemoryStore()}
	failing, _, _, _ := newArtifactTestIdP(t, func(config *IdentityProviderConfig) { config.Store = store })
	store.saveErr = errors.New("save failed")
	requestXML = artifactAuthnRequestXML(t, auth.NewID("artifact-authn"))
	form = url.Values{"SAMLRequest": {EncodePost(requestXML)}}
	request = httptest.NewRequest(http.MethodPost, "/sso", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder = httptest.NewRecorder()
	failing.HandleSSO(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("save failure status = %d body=%s", recorder.Code, recorder.Body.String())
	}

	if _, err := artifactRedirectURL("://bad", "AA==", ""); !errors.Is(err, ErrInvalidRecipient) {
		t.Fatalf("bad ACS error = %v", err)
	}
	if nodeAttr(nil, "ID") != "" {
		t.Fatal("nil node attribute")
	}
}
