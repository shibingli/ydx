package saml

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// artifactResolutionPayload builds an ArtifactResponse payload that echoes inResponseTo and embeds a
// protocol Response. | artifactResolutionPayload 构建回显 inResponseTo 并嵌入协议 Response 的
// ArtifactResponse 载荷。
func artifactResolutionPayload(inResponseTo string) []byte {
	var b []byte
	b = append(b, `<samlp:ArtifactResponse xmlns:samlp="`+NamespaceProtocol+`" xmlns:saml="`+NamespaceAssertion+
		`" ID="artifact-response-soap12" Version="`+Version+`" IssueInstant="`+FormatTime(samlTestNow)+
		`" InResponseTo="`+htmlEscape(inResponseTo)+`">`...)
	b = append(b, `<saml:Issuer>`+artifactIDPEntity+`</saml:Issuer>`...)
	b = append(b, `<samlp:Status><samlp:StatusCode Value="`+StatusSuccess+`"/></samlp:Status>`...)
	b = append(b, `<samlp:Response ID="embedded-response"><samlp:Status><samlp:StatusCode Value="`+
		StatusSuccess+`"/></samlp:Status></samlp:Response>`...)
	b = append(b, `</samlp:ArtifactResponse>`...)
	return b
}

// artifactResolutionResponseBody builds a success ArtifactResponse payload in the request envelope
// version. | artifactResolutionResponseBody 以请求的信封版本构建成功 ArtifactResponse 载荷。
func artifactResolutionResponseBody(requestBody []byte) ([]byte, SOAPVersion, bool) {
	envelope, err := parseSOAPEnvelope(requestBody)
	if err != nil {
		return nil, "", false
	}
	payload, err := envelope.payload()
	if err != nil || payload.Name.Local != "ArtifactResolve" || payload.Name.Space != NamespaceProtocol {
		return nil, "", false
	}
	requestID := nodeAttr(payload, "ID")
	if requestID == "" {
		return nil, "", false
	}
	return artifactResolutionPayload(requestID), envelope.version, true
}

// TestArtifactSOAP12IdPResolution checks SOAP 1.2 request handling and versioned faults at the IdP.
// | TestArtifactSOAP12IdPResolution 校验 IdP 的 SOAP 1.2 请求处理与版本化异常。
func TestArtifactSOAP12IdPResolution(t *testing.T) {
	idp, _, _, _ := newArtifactTestIdP(t, nil)
	postSOAP12 := func(t *testing.T, artifactValue, requestID, action string) *httptest.ResponseRecorder {
		t.Helper()
		document := artifactResolveDocument(t, requestID, "", artifactValue, artifactSPEntity)
		body := buildSOAPEnvelopeVersion(SOAPVersion12, document)
		request := httptest.NewRequest(http.MethodPost, "https://idp.example/saml/artifact", bytes.NewReader(body))
		contentType := SOAPContentType12
		if action != "" {
			contentType += `; action="` + action + `"`
		}
		request.Header.Set("Content-Type", contentType)
		recorder := httptest.NewRecorder()
		idp.HandleArtifactResolution(recorder, request)
		return recorder
	}

	t.Run("SOAP 1.2 request succeeds with a SOAP 1.2 response", func(t *testing.T) {
		artifactValue, _ := issueArtifact(t, idp, "")
		recorder := postSOAP12(t, artifactValue, "resolve-soap12", SOAPActionArtifactResolve)
		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
		}
		if got := recorder.Header().Get("Content-Type"); got != SOAPContentType12 {
			t.Fatalf("Content-Type = %q", got)
		}
		envelope, err := parseSOAPEnvelope(recorder.Body.Bytes())
		if err != nil || envelope.version != SOAPVersion12 {
			t.Fatalf("response envelope = %v, err = %v", envelope, err)
		}
		payload := artifactResponseNode(t, recorder.Body.Bytes())
		if got := artifactResponseStatusValue(t, payload); got != StatusSuccess {
			t.Fatalf("status = %q body=%s", got, recorder.Body.String())
		}
	})

	t.Run("SOAP 1.2 envelope is accepted without a content type", func(t *testing.T) {
		artifactValue, _ := issueArtifact(t, idp, "")
		document := artifactResolveDocument(t, "resolve-soap12-no-content-type", "", artifactValue, artifactSPEntity)
		body := buildSOAPEnvelopeVersion(SOAPVersion12, document)
		request := httptest.NewRequest(http.MethodPost, "https://idp.example/saml/artifact", bytes.NewReader(body))
		recorder := httptest.NewRecorder()
		idp.HandleArtifactResolution(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
		}
		if got := recorder.Header().Get("Content-Type"); got != SOAPContentType12 {
			t.Fatalf("Content-Type = %q", got)
		}
		payload := artifactResponseNode(t, recorder.Body.Bytes())
		if got := artifactResponseStatusValue(t, payload); got != StatusSuccess {
			t.Fatalf("status = %q body=%s", got, recorder.Body.String())
		}
	})

	t.Run("SOAP 1.2 action mismatch returns a Sender fault", func(t *testing.T) {
		artifactValue, _ := issueArtifact(t, idp, "")
		recorder := postSOAP12(t, artifactValue, "resolve-soap12-bad-action", SOAPActionArtifactResponse)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
		}
		if got := recorder.Header().Get("Content-Type"); got != SOAPContentType12 {
			t.Fatalf("Content-Type = %q", got)
		}
		fault := artifactResponseFault(t, recorder.Body.Bytes())
		if fault.Code != "env:Sender" {
			t.Fatalf("fault code = %q", fault.Code)
		}
	})
}

// TestArtifactSPUsesSOAP12 checks that the SP selects SOAP 1.2 by configuration. |
// TestArtifactSPUsesSOAP12 校验 SP 按配置选择 SOAP 1.2。
func TestArtifactSPUsesSOAP12(t *testing.T) {
	var idp *IdentityProvider
	var mu sync.Mutex
	var observedVersion SOAPVersion
	var observedContentType, observedActionHeader, observedActionParam string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read", http.StatusInternalServerError)
			return
		}
		mu.Lock()
		observedContentType = r.Header.Get("Content-Type")
		observedActionHeader = r.Header.Get("SOAPAction")
		observedActionParam = soapActionFromContentType(observedContentType)
		if envelope, err := parseSOAPEnvelope(body); err == nil {
			observedVersion = envelope.version
		}
		mu.Unlock()
		clone := r.Clone(r.Context())
		clone.Body = io.NopCloser(bytes.NewReader(body))
		idp.HandleArtifactResolution(w, clone)
	}))
	defer server.Close()
	idp, _, _, _ = newArtifactTestIdP(t, func(config *IdentityProviderConfig) {
		config.ArtifactResolutionURL = server.URL
	})
	artifactValue, _ := issueArtifact(t, idp, "")
	sp := artifactEdgeSP(t, func(config *ServiceProviderConfig) {
		config.IDPMetadata = artifactMetadata(server.URL)
		config.ArtifactSOAPVersion = SOAPVersion12
	})
	raw, err := sp.resolveArtifact(context.Background(), artifactValue)
	if err != nil {
		t.Fatalf("resolveArtifact: %v", err)
	}
	if !strings.Contains(string(raw), `xmlns="`+NamespaceProtocol+`"`) || !strings.Contains(string(raw), "Assertion") {
		t.Fatalf("resolved response = %s", raw)
	}
	mu.Lock()
	defer mu.Unlock()
	if observedVersion != SOAPVersion12 {
		t.Fatalf("request envelope version = %q", observedVersion)
	}
	if !strings.HasPrefix(observedContentType, SOAPContentType12) {
		t.Fatalf("request Content-Type = %q", observedContentType)
	}
	if observedActionParam != SOAPActionArtifactResolve {
		t.Fatalf("request action parameter = %q", observedActionParam)
	}
	if observedActionHeader != "" {
		t.Fatalf("SOAP 1.2 request carried SOAPAction header %q", observedActionHeader)
	}
}

// TestArtifactResponseSOAPVersionMismatch checks declared response versions and actions. |
// TestArtifactResponseSOAPVersionMismatch 校验收到的响应声明的版本与动作。
func TestArtifactResponseSOAPVersionMismatch(t *testing.T) {
	sp := artifactEdgeSP(t, nil)
	requestID := "artifact-request-version"
	payload := artifactResolutionPayload(requestID)
	envelope11 := buildSOAPEnvelopeVersion(SOAPVersion11, payload)
	envelope12 := buildSOAPEnvelopeVersion(SOAPVersion12, payload)
	ctx := context.Background()

	t.Run("SOAP 1.1 envelope without a declared version", func(t *testing.T) {
		raw, err := sp.parseArtifactResponseContentType(ctx, envelope11, http.StatusOK, requestID, "")
		if err != nil || !strings.Contains(string(raw), "embedded-response") {
			t.Fatalf("raw = %s, err = %v", raw, err)
		}
	})
	t.Run("SOAP 1.2 envelope without a declared version", func(t *testing.T) {
		raw, err := sp.parseArtifactResponseContentType(ctx, envelope12, http.StatusOK, requestID, "")
		if err != nil || !strings.Contains(string(raw), "embedded-response") {
			t.Fatalf("raw = %s, err = %v", raw, err)
		}
	})
	t.Run("declared SOAP 1.2 rejects a SOAP 1.1 envelope", func(t *testing.T) {
		if _, err := sp.parseArtifactResponseContentType(ctx, envelope11, http.StatusOK, requestID, SOAPContentType12); !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("error = %v, want ErrInvalidResponse", err)
		}
	})
	t.Run("declared SOAP 1.1 rejects a SOAP 1.2 envelope", func(t *testing.T) {
		if _, err := sp.parseArtifactResponseContentType(ctx, envelope12, http.StatusOK, requestID, SOAPContentType); !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("error = %v, want ErrInvalidResponse", err)
		}
	})
	t.Run("declared ArtifactResponse action is accepted", func(t *testing.T) {
		contentType := SOAPContentType12 + `; action="` + SOAPActionArtifactResponse + `"`
		if _, err := sp.parseArtifactResponseContentType(ctx, envelope12, http.StatusOK, requestID, contentType); err != nil {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("declared ArtifactResolve action is rejected", func(t *testing.T) {
		contentType := SOAPContentType12 + `; action="` + SOAPActionArtifactResolve + `"`
		if _, err := sp.parseArtifactResponseContentType(ctx, envelope12, http.StatusOK, requestID, contentType); !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("error = %v, want ErrInvalidResponse", err)
		}
	})
}
