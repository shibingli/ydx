package saml

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestSPArtifactEndToEnd covers browser artifact delivery and SOAP resolution at the SP. |
// TestSPArtifactEndToEnd 覆盖浏览器工件投递与 SP 的 SOAP 解析。
func TestSPArtifactEndToEnd(t *testing.T) {
	var idp *IdentityProvider
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idp.HandleArtifactResolution(w, r)
	}))
	defer server.Close()
	idp, _, _, cert := newArtifactTestIdP(t, func(config *IdentityProviderConfig) {
		config.ArtifactResolutionURL = server.URL
		config.SignArtifactResponse = true
	})
	sp, err := NewServiceProvider(ServiceProviderConfig{
		EntityID:                      artifactSPEntity,
		ACSURL:                        artifactACSURL,
		IDPMetadata:                   artifactMetadata(server.URL),
		Store:                         NewMemoryStore(),
		SignatureVerifier:             &XMLDSigVerifier{Certificates: []*x509.Certificate{cert}},
		RequireSignedAssertion:        true,
		RequireSignedResponse:         true,
		RequireSignedArtifactResponse: true,
		ProtocolBinding:               BindingHTTPArtifact,
		Now:                           func() time.Time { return samlTestNow },
	})
	if err != nil {
		t.Fatalf("sp: %v", err)
	}
	authnURL, err := sp.AuthnRequestURL("relay-artifact")
	if err != nil {
		t.Fatalf("authn url: %v", err)
	}
	parsed, err := url.Parse(authnURL)
	if err != nil {
		t.Fatalf("authn url parse: %v", err)
	}
	requestXML, err := DecodeRedirect(parsed.Query().Get("SAMLRequest"))
	if err != nil {
		t.Fatalf("decode authn: %v", err)
	}
	ssoRequest := httptest.NewRequest(http.MethodPost, "/sso", strings.NewReader(url.Values{
		"SAMLRequest": {EncodePost(requestXML)},
		"RelayState":  {"relay-artifact"},
	}.Encode()))
	ssoRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ssoRecorder := httptest.NewRecorder()
	idp.HandleSSO(ssoRecorder, ssoRequest)
	if ssoRecorder.Code != http.StatusFound {
		t.Fatalf("SSO status = %d body=%s", ssoRecorder.Code, ssoRecorder.Body.String())
	}
	location, err := url.Parse(ssoRecorder.Header().Get("Location"))
	if err != nil {
		t.Fatalf("redirect: %v", err)
	}
	artifactValue := location.Query().Get(ArtifactParameter)
	if artifactValue == "" {
		t.Fatalf("redirect has no artifact: %s", location.String())
	}
	acsURL := "/acs?" + url.Values{ArtifactParameter: {artifactValue}, "RelayState": {location.Query().Get("RelayState")}}.Encode()
	acsRequest := httptest.NewRequest(http.MethodGet, acsURL, nil)
	result, err := sp.ParseResponse(acsRequest)
	if err != nil {
		t.Fatalf("SP artifact resolution: %v", err)
	}
	if result.Principal == nil || result.Principal.Subject != "artifact-user" {
		t.Fatalf("principal = %+v", result.Principal)
	}
	if result.RelayState != "relay-artifact" {
		t.Fatalf("RelayState = %q", result.RelayState)
	}

	replayRequest := httptest.NewRequest(http.MethodGet, acsURL, nil)
	if _, err := sp.ParseResponse(replayRequest); !errors.Is(err, ErrStatusFailure) {
		t.Fatalf("replay error = %v", err)
	}
}

// TestSPArtifactFailures covers resolution transport, SOAP and validation failures at the SP. |
// TestSPArtifactFailures 覆盖 SP 的解析传输、SOAP 与校验失败。
func TestSPArtifactFailures(t *testing.T) {
	idp, _, _, cert := newArtifactTestIdP(t, nil)
	artifactValue, _ := issueArtifact(t, idp, "")
	artifact, err := DecodeArtifact(artifactValue)
	if err != nil {
		t.Fatalf("artifact: %v", err)
	}

	newSP := func(t *testing.T, arsURL string, mutate func(*ServiceProviderConfig)) *ServiceProvider {
		t.Helper()
		config := ServiceProviderConfig{
			EntityID:          artifactSPEntity,
			ACSURL:            artifactACSURL,
			IDPMetadata:       artifactMetadata(arsURL),
			Store:             NewMemoryStore(),
			SignatureVerifier: &XMLDSigVerifier{Certificates: []*x509.Certificate{cert}},
			ProtocolBinding:   BindingHTTPArtifact,
			Now:               func() time.Time { return samlTestNow },
			AllowIDPInitiated: true,
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
	resolve := func(t *testing.T, sp *ServiceProvider, value string) error {
		t.Helper()
		request := httptest.NewRequest(http.MethodGet, "/acs?"+url.Values{ArtifactParameter: {value}}.Encode(), nil)
		_, err := sp.ParseResponse(request)
		return err
	}

	t.Run("missing resolution endpoint", func(t *testing.T) {
		sp := newSP(t, "", nil)
		if err := resolve(t, sp, artifactValue); !errors.Is(err, ErrInvalidMetadata) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("pinned source mismatch", func(t *testing.T) {
		sp := newSP(t, "https://idp.example/saml/artifact", func(config *ServiceProviderConfig) {
			config.ArtifactSourceID = make([]byte, ArtifactSourceIDSize)
		})
		if err := resolve(t, sp, artifactValue); !errors.Is(err, ErrArtifactInvalid) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("unknown endpoint index", func(t *testing.T) {
		sp := newSP(t, "https://idp.example/saml/artifact", func(config *ServiceProviderConfig) {
			config.ArtifactSourceID = artifact.SourceID[:]
		})
		indexed := *artifact
		indexed.EndpointIndex = 4
		if err := resolve(t, sp, indexed.String()); !errors.Is(err, ErrInvalidMetadata) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("malformed artifact", func(t *testing.T) {
		sp := newSP(t, "https://idp.example/saml/artifact", nil)
		if err := resolve(t, sp, "not-base64!"); !errors.Is(err, ErrArtifactInvalid) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("SOAP fault", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			writeSOAPFault(w, http.StatusInternalServerError, "soap:Server", "resolution failed")
		}))
		defer server.Close()
		sp := newSP(t, server.URL, func(config *ServiceProviderConfig) { config.ArtifactSourceID = artifact.SourceID[:] })
		if err := resolve(t, sp, artifact.String()); !errors.Is(err, ErrSOAPFault) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("non-success artifact status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeSOAPPayload(w, fakeArtifactResponseBody(r, artifactIDPEntity, StatusRequester, "", true))
		}))
		defer server.Close()
		sp := newSP(t, server.URL, func(config *ServiceProviderConfig) { config.ArtifactSourceID = artifact.SourceID[:] })
		err := resolve(t, sp, artifact.String())
		if !errors.Is(err, ErrStatusFailure) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("wrong issuer", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeSOAPPayload(w, fakeArtifactResponseBody(r, "https://evil.example/metadata", StatusSuccess, "", true))
		}))
		defer server.Close()
		sp := newSP(t, server.URL, func(config *ServiceProviderConfig) { config.ArtifactSourceID = artifact.SourceID[:] })
		if err := resolve(t, sp, artifact.String()); !errors.Is(err, ErrInvalidIssuer) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("wrong InResponseTo", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			writeSOAPPayload(w, fakeArtifactResponseBody(nil, artifactIDPEntity, StatusSuccess, "wrong-id", true))
		}))
		defer server.Close()
		sp := newSP(t, server.URL, func(config *ServiceProviderConfig) { config.ArtifactSourceID = artifact.SourceID[:] })
		if err := resolve(t, sp, artifact.String()); !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("required signature missing", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeSOAPPayload(w, fakeArtifactResponseBody(r, artifactIDPEntity, StatusSuccess, "", true))
		}))
		defer server.Close()
		sp := newSP(t, server.URL, func(config *ServiceProviderConfig) {
			config.ArtifactSourceID = artifact.SourceID[:]
			config.RequireSignedArtifactResponse = true
		})
		if err := resolve(t, sp, artifact.String()); !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("malformed SOAP", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", SOAPContentType)
			_, _ = w.Write([]byte("not xml"))
		}))
		defer server.Close()
		sp := newSP(t, server.URL, func(config *ServiceProviderConfig) { config.ArtifactSourceID = artifact.SourceID[:] })
		if err := resolve(t, sp, artifact.String()); !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("HTTP error status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		}))
		defer server.Close()
		sp := newSP(t, server.URL, func(config *ServiceProviderConfig) { config.ArtifactSourceID = artifact.SourceID[:] })
		if err := resolve(t, sp, artifact.String()); !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("oversized response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", SOAPContentType)
			_, _ = w.Write(make([]byte, MaxSOAPMessageBytes+1))
		}))
		defer server.Close()
		sp := newSP(t, server.URL, func(config *ServiceProviderConfig) { config.ArtifactSourceID = artifact.SourceID[:] })
		if err := resolve(t, sp, artifact.String()); !errors.Is(err, ErrLimit) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("transport failure", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		address := server.URL
		server.Close()
		sp := newSP(t, address, func(config *ServiceProviderConfig) { config.ArtifactSourceID = artifact.SourceID[:] })
		if err := resolve(t, sp, artifact.String()); !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		}))
		defer server.Close()
		sp := newSP(t, server.URL, func(config *ServiceProviderConfig) { config.ArtifactSourceID = artifact.SourceID[:] })
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		request := httptest.NewRequest(http.MethodGet, "/acs?"+url.Values{ArtifactParameter: {artifact.String()}}.Encode(), nil).WithContext(ctx)
		if _, err := sp.ParseResponse(request); err == nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v", err)
		}
	})
}

// fakeArtifactResponseBody builds an unsigned ArtifactResponse for a request. When request is nil
// the provided inResponseTo is used verbatim. | fakeArtifactResponseBody 为请求构建未签名
// ArtifactResponse。request 为 nil 时直接使用提供的 inResponseTo。
func fakeArtifactResponseBody(r *http.Request, issuer, statusCode, inResponseTo string, echoRequestID bool) []byte {
	if echoRequestID && r != nil {
		if body, err := io.ReadAll(r.Body); err == nil {
			if envelope, err := parseSOAPEnvelope(body); err == nil {
				if payload, err := envelope.payload(); err == nil {
					inResponseTo = nodeAttr(payload, "ID")
				}
			}
		}
	}
	var b []byte
	b = append(b, `<samlp:ArtifactResponse xmlns:samlp="`+NamespaceProtocol+`" xmlns:saml="`+NamespaceAssertion+
		`" ID="fake-artifact-response" Version="2.0" IssueInstant="`+FormatTime(samlTestNow)+`"`...)
	if inResponseTo != "" {
		b = append(b, ` InResponseTo="`+htmlEscape(inResponseTo)+`"`...)
	}
	b = append(b, `><saml:Issuer>`+htmlEscape(issuer)+`</saml:Issuer><samlp:Status><samlp:StatusCode Value="`+htmlEscape(statusCode)+`"/></samlp:Status></samlp:ArtifactResponse>`...)
	return b
}
