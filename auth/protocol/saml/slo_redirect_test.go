package saml

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/xml"
)

// cloneQuery returns a deep copy of url.Values. | cloneQuery 返回 url.Values 的深拷贝。
func cloneQuery(values url.Values) url.Values {
	out := make(url.Values, len(values))
	for key, items := range values {
		out[key] = append([]string(nil), items...)
	}
	return out
}

// redirectResponseVerifier verifies SAMLResponse redirect signatures with cert. |
// redirectResponseVerifier 使用 cert 校验 SAMLResponse 重定向签名。
func redirectResponseVerifier(cert *x509.Certificate) RedirectVerifier {
	return func(_ context.Context, rawQuery string, _ url.Values, _, _ string) error {
		return VerifyRedirectRawQuery(rawQuery, "SAMLResponse", []*x509.Certificate{cert}, nil, nil)
	}
}

// TestSLORedirectSignaturePolicy covers valid, tampered, wrong-algorithm, missing and unsigned
// redirect SLO messages. | TestSLORedirectSignaturePolicy 覆盖有效、篡改、错误算法、缺失签名与
// 未签名的重定向 SLO 消息。
func TestSLORedirectSignaturePolicy(t *testing.T) {
	key, cert := samlTestKeyCert(t)
	verifier := redirectResponseVerifier(cert)
	ctx := context.Background()
	signed := url.Values{"SAMLResponse": {"payload"}, "RelayState": {"relay"}}
	if err := SignRedirectMessage(signed, "SAMLResponse", key, SigAlgRSASHA256, "relay"); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := verifySLORedirect(ctx, signed.Encode(), "SAMLResponse", "idp", "relay", verifier, false); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}

	tamperedXML := cloneQuery(signed)
	tamperedXML.Set("SAMLResponse", "other")
	if err := verifySLORedirect(ctx, tamperedXML.Encode(), "SAMLResponse", "idp", "relay", verifier, false); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tampered XML error = %v, want ErrInvalidSignature", err)
	}

	tamperedRelay := cloneQuery(signed)
	tamperedRelay.Set("RelayState", "evil")
	if err := verifySLORedirect(ctx, tamperedRelay.Encode(), "SAMLResponse", "idp", "relay", verifier, false); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tampered RelayState error = %v, want ErrInvalidSignature", err)
	}

	wrongAlgorithm := url.Values{"SAMLResponse": {"payload"}, "SigAlg": {"urn:unsupported"}, "Signature": {"AAAA"}}
	if err := verifySLORedirect(ctx, wrongAlgorithm.Encode(), "SAMLResponse", "idp", "", verifier, false); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("wrong algorithm error = %v, want ErrInvalidSignature", err)
	}

	unsigned := url.Values{"SAMLResponse": {"payload"}}
	if err := verifySLORedirect(ctx, unsigned.Encode(), "SAMLResponse", "idp", "", verifier, true); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("missing required signature error = %v, want ErrInvalidSignature", err)
	}
	if err := verifySLORedirect(ctx, unsigned.Encode(), "SAMLResponse", "idp", "", func(context.Context, string, url.Values, string, string) error {
		return errors.New("verifier must not run for unsigned messages")
	}, false); err != nil {
		t.Fatalf("unsigned compatibility mode rejected: %v", err)
	}

	if err := verifySLORedirect(ctx, signed.Encode(), "SAMLResponse", "idp", "relay", nil, false); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("signed message without verifier error = %v, want ErrInvalidSignature", err)
	}
	sigAlgOnly := url.Values{"SAMLResponse": {"payload"}, "SigAlg": {SigAlgRSASHA256}}
	if err := verifySLORedirect(ctx, sigAlgOnly.Encode(), "SAMLResponse", "idp", "", verifier, false); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("SigAlg without Signature error = %v, want ErrInvalidSignature", err)
	}
}

// logoutResponseForTest builds a valid LogoutResponse. | logoutResponseForTest 构建有效的
// LogoutResponse。
func logoutResponseForTest(t *testing.T) []byte {
	t.Helper()
	document, err := xml.Marshal(&LogoutResponse{
		ID:           "logout-response-1",
		InResponseTo: "logout-request-1",
		Version:      Version,
		IssueInstant: FormatTime(time.Now().UTC()),
		Destination:  "https://sp.example/slo",
		Issuer:       &Issuer{Value: "https://idp.example/metadata"},
		Status:       &Status{StatusCode: &StatusCode{Value: StatusSuccess}},
	})
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	return document
}

// newRedirectSLOProvider returns an SP and IdP pair for redirect handler tests. |
// newRedirectSLOProvider 返回用于重定向处理器测试的 SP 与 IdP。
func newRedirectSLOProvider(t *testing.T, verifier RedirectVerifier, requireSigned bool) (*ServiceProvider, *IdentityProvider) {
	t.Helper()
	sp, err := NewServiceProvider(ServiceProviderConfig{
		EntityID:            "https://sp.example/metadata",
		ACSURL:              "https://sp.example/saml/acs",
		SLOURL:              "https://sp.example/slo",
		IDPMetadata:         testMetadata(),
		Store:               NewMemoryStore(),
		RequireSignedLogout: requireSigned,
		RedirectVerifier:    verifier,
	})
	if err != nil {
		t.Fatalf("sp: %v", err)
	}
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
		t.Fatalf("idp: %v", err)
	}
	return sp, idp
}

// TestSLORedirectHandlers covers handler-level reject/accept decisions. |
// TestSLORedirectHandlers 覆盖处理器层面的拒绝与接受决策。
func TestSLORedirectHandlers(t *testing.T) {
	key, cert := samlTestKeyCert(t)
	responseXML := logoutResponseForTest(t)
	params := url.Values{"SAMLResponse": {encodeRedirectForTest(t, responseXML)}}
	if err := SignRedirectMessage(params, "SAMLResponse", key, SigAlgRSASHA256, "relay"); err != nil {
		t.Fatalf("sign response: %v", err)
	}

	sp, _ := newRedirectSLOProvider(t, nil, false)
	w := httptest.NewRecorder()
	sp.HandleSLO(w, httptest.NewRequest(http.MethodGet, "/slo?"+params.Encode(), nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("signed redirect without verifier status = %d", w.Code)
	}

	verifier := redirectResponseVerifier(cert)
	sp, _ = newRedirectSLOProvider(t, verifier, false)
	tampered := cloneQuery(params)
	tampered.Set("RelayState", "evil")
	w = httptest.NewRecorder()
	sp.HandleSLO(w, httptest.NewRequest(http.MethodGet, "/slo?"+tampered.Encode(), nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("tampered RelayState status = %d", w.Code)
	}

	sp, _ = newRedirectSLOProvider(t, verifier, true)
	unsigned := url.Values{"SAMLResponse": {encodeRedirectForTest(t, responseXML)}}
	w = httptest.NewRecorder()
	sp.HandleSLO(w, httptest.NewRequest(http.MethodGet, "/slo?"+unsigned.Encode(), nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("missing required signature status = %d", w.Code)
	}

	sp, _ = newRedirectSLOProvider(t, nil, false)
	if err := sp.Store().SaveRequest(context.Background(), &RequestState{
		ID:          "logout-request-1",
		SPEntityID:  "https://sp.example/metadata",
		IDPEntityID: "https://idp.example/metadata",
		ExpiresAt:   time.Now().Add(10 * time.Minute),
	}); err != nil {
		t.Fatalf("save request: %v", err)
	}
	w = httptest.NewRecorder()
	sp.HandleSLO(w, httptest.NewRequest(http.MethodGet, "/slo?"+url.Values{"SAMLResponse": {encodeRedirectForTest(t, responseXML)}}.Encode(), nil))
	if w.Code != http.StatusOK || w.Body.String() != "logged out" {
		t.Fatalf("unsigned compatibility status = %d body=%s", w.Code, w.Body.String())
	}

	sp, _ = newRedirectSLOProvider(t, nil, false)
	requestXML, err := xml.Marshal(&LogoutRequest{
		ID:           "logout-request-2",
		Version:      Version,
		IssueInstant: FormatTime(time.Now().UTC()),
		Destination:  "https://sp.example/slo",
		NotOnOrAfter: FormatTime(time.Now().Add(5 * time.Minute)),
		Issuer:       &Issuer{Value: "https://idp.example/metadata"},
		NameID:       NewNameID(NameIDUnspecified, "alice@example.com"),
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	w = httptest.NewRecorder()
	sp.HandleSLO(w, httptest.NewRequest(http.MethodGet, "/slo?"+url.Values{"SAMLRequest": {encodeRedirectForTest(t, requestXML)}}.Encode(), nil))
	if w.Code != http.StatusFound {
		t.Fatalf("unsigned request compatibility status = %d body=%s", w.Code, w.Body.String())
	}

	_, idp := newRedirectSLOProvider(t, nil, false)
	signedRequest := url.Values{"SAMLRequest": {encodeRedirectForTest(t, requestXML)}}
	if err := SignRedirectMessage(signedRequest, "SAMLRequest", key, SigAlgRSASHA256, ""); err != nil {
		t.Fatalf("sign request: %v", err)
	}
	w = httptest.NewRecorder()
	idp.HandleSLO(w, httptest.NewRequest(http.MethodGet, "/slo?"+signedRequest.Encode(), nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("idp signed redirect without verifier status = %d", w.Code)
	}
}

// redirectRequestVerifier verifies SAMLRequest redirect signatures with cert. |
// redirectRequestVerifier 使用 cert 校验 SAMLRequest 重定向签名。
func redirectRequestVerifier(cert *x509.Certificate) RedirectVerifier {
	return func(_ context.Context, rawQuery string, _ url.Values, _, _ string) error {
		return VerifyRedirectRawQuery(rawQuery, "SAMLRequest", []*x509.Certificate{cert}, nil, nil)
	}
}

// TestSLORedirectSignedOnlyAcceptsSignedMessages verifies that a valid query signature satisfies
// RequireSignedLogout and WantLogoutRequestsSigned without requiring a second XML signature. |
// TestSLORedirectSignedOnlyAcceptsSignedMessages 校验有效的查询签名即可满足 RequireSignedLogout
// 与 WantLogoutRequestsSigned，无须再要求 XML 签名。
func TestSLORedirectSignedOnlyAcceptsSignedMessages(t *testing.T) {
	key, cert := samlTestKeyCert(t)

	t.Run("sp logout response", func(t *testing.T) {
		params := url.Values{"SAMLResponse": {encodeRedirectForTest(t, logoutResponseForTest(t))}}
		if err := SignRedirectMessage(params, "SAMLResponse", key, SigAlgRSASHA256, ""); err != nil {
			t.Fatalf("sign response: %v", err)
		}
		sp, _ := newRedirectSLOProvider(t, redirectResponseVerifier(cert), true)
		if err := sp.Store().SaveRequest(context.Background(), &RequestState{
			ID:          "logout-request-1",
			SPEntityID:  "https://sp.example/metadata",
			IDPEntityID: "https://idp.example/metadata",
			ExpiresAt:   time.Now().Add(10 * time.Minute),
		}); err != nil {
			t.Fatalf("save request: %v", err)
		}
		w := httptest.NewRecorder()
		sp.HandleSLO(w, httptest.NewRequest(http.MethodGet, "/slo?"+params.Encode(), nil))
		if w.Code != http.StatusOK || w.Body.String() != "logged out" {
			t.Fatalf("status = %d body = %s", w.Code, w.Body.String())
		}
	})

	t.Run("sp logout request", func(t *testing.T) {
		requestXML, err := xml.Marshal(&LogoutRequest{
			ID:           "logout-request-2",
			Version:      Version,
			IssueInstant: FormatTime(time.Now().UTC()),
			Destination:  "https://sp.example/slo",
			NotOnOrAfter: FormatTime(time.Now().Add(5 * time.Minute)),
			Issuer:       &Issuer{Value: "https://idp.example/metadata"},
			NameID:       NewNameID(NameIDUnspecified, "alice@example.com"),
		})
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		params := url.Values{"SAMLRequest": {encodeRedirectForTest(t, requestXML)}}
		if err := SignRedirectMessage(params, "SAMLRequest", key, SigAlgRSASHA256, ""); err != nil {
			t.Fatalf("sign request: %v", err)
		}
		sp, _ := newRedirectSLOProvider(t, redirectRequestVerifier(cert), true)
		w := httptest.NewRecorder()
		sp.HandleSLO(w, httptest.NewRequest(http.MethodGet, "/slo?"+params.Encode(), nil))
		if w.Code != http.StatusFound {
			t.Fatalf("status = %d body = %s", w.Code, w.Body.String())
		}
	})

	t.Run("idp logout request", func(t *testing.T) {
		spMetadata := &EntityDescriptor{
			EntityID: "https://sp.example/metadata",
			SPSSODescriptor: &SPSSODescriptor{
				SingleLogoutService: []Endpoint{{Binding: BindingHTTPRedirect, Location: "https://sp.example/slo"}},
			},
		}
		idp, err := NewIdentityProvider(IdentityProviderConfig{
			EntityID:                 "https://idp.example/metadata",
			SSOURL:                   "https://idp.example/sso",
			SLOURL:                   "https://idp.example/slo",
			Store:                    NewMemoryStore(),
			SPResolver:               staticResolver{metadata: spMetadata},
			WantLogoutRequestsSigned: true,
			RedirectVerifier:         redirectRequestVerifier(cert),
			Authenticator: AuthenticatorFunc(func(context.Context, http.ResponseWriter, *http.Request, *AuthnRequest) (*auth.Principal, error) {
				return &auth.Principal{Subject: "alice"}, nil
			}),
		})
		if err != nil {
			t.Fatalf("idp: %v", err)
		}
		requestXML, err := xml.Marshal(&LogoutRequest{
			ID:           "logout-request-3",
			Version:      Version,
			IssueInstant: FormatTime(time.Now().UTC()),
			Destination:  "https://idp.example/slo",
			NotOnOrAfter: FormatTime(time.Now().Add(5 * time.Minute)),
			Issuer:       &Issuer{Value: "https://sp.example/metadata"},
			NameID:       NewNameID(NameIDUnspecified, "alice@example.com"),
		})
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		params := url.Values{"SAMLRequest": {encodeRedirectForTest(t, requestXML)}}
		if err := SignRedirectMessage(params, "SAMLRequest", key, SigAlgRSASHA256, ""); err != nil {
			t.Fatalf("sign request: %v", err)
		}
		w := httptest.NewRecorder()
		idp.HandleSLO(w, httptest.NewRequest(http.MethodGet, "/slo?"+params.Encode(), nil))
		if w.Code != http.StatusFound {
			t.Fatalf("status = %d body = %s", w.Code, w.Body.String())
		}
	})

	t.Run("idp logout response", func(t *testing.T) {
		spMetadata := &EntityDescriptor{EntityID: "https://sp.example/metadata", SPSSODescriptor: &SPSSODescriptor{}}
		idp, err := NewIdentityProvider(IdentityProviderConfig{
			EntityID:                 "https://idp.example/metadata",
			SSOURL:                   "https://idp.example/sso",
			SLOURL:                   "https://idp.example/slo",
			Store:                    NewMemoryStore(),
			SPResolver:               staticResolver{metadata: spMetadata},
			WantLogoutRequestsSigned: true,
			RedirectVerifier:         redirectResponseVerifier(cert),
			Authenticator: AuthenticatorFunc(func(context.Context, http.ResponseWriter, *http.Request, *AuthnRequest) (*auth.Principal, error) {
				return &auth.Principal{Subject: "alice"}, nil
			}),
		})
		if err != nil {
			t.Fatalf("idp: %v", err)
		}
		responseXML, err := xml.Marshal(&LogoutResponse{
			ID:           "logout-response-2",
			Version:      Version,
			IssueInstant: FormatTime(time.Now().UTC()),
			Issuer:       &Issuer{Value: "https://sp.example/metadata"},
			Status:       &Status{StatusCode: &StatusCode{Value: StatusSuccess}},
		})
		if err != nil {
			t.Fatalf("marshal response: %v", err)
		}
		params := url.Values{"SAMLResponse": {encodeRedirectForTest(t, responseXML)}}
		if err := SignRedirectMessage(params, "SAMLResponse", key, SigAlgRSASHA256, ""); err != nil {
			t.Fatalf("sign response: %v", err)
		}
		w := httptest.NewRecorder()
		idp.HandleSLO(w, httptest.NewRequest(http.MethodGet, "/slo?"+params.Encode(), nil))
		if w.Code != http.StatusOK || w.Body.String() != "logged out" {
			t.Fatalf("status = %d body = %s", w.Code, w.Body.String())
		}
	})
}

// encodeRedirectForTest encodes an XML document for the redirect binding. |
// encodeRedirectForTest 为重定向绑定编码 XML 文档。
func encodeRedirectForTest(t *testing.T, document []byte) string {
	t.Helper()
	encoded, err := EncodeRedirect(document)
	if err != nil {
		t.Fatalf("EncodeRedirect: %v", err)
	}
	return encoded
}
