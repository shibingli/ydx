package saml

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth"
)

// testMetadata returns IdP metadata pointing at example URLs. | testMetadata 返回指向示例 URL 的 IdP 元数据。
func testMetadata() *EntityDescriptor {
	return &EntityDescriptor{
		EntityID: "https://idp.example/metadata",
		IDPSSODescriptor: &IDPSSODescriptor{
			ProtocolSupportEnumeration: NamespaceProtocol,
			SingleSignOnService: []Endpoint{
				{Binding: BindingHTTPRedirect, Location: "https://idp.example/sso"},
				{Binding: BindingHTTPPost, Location: "https://idp.example/sso"},
			},
			SingleLogoutService: []Endpoint{
				{Binding: BindingHTTPRedirect, Location: "https://idp.example/slo"},
			},
		},
	}
}

func TestSPAuthnRequestAndIdPResponse(t *testing.T) {
	spStore := NewMemoryStore()
	sp, err := NewServiceProvider(ServiceProviderConfig{
		EntityID:          "https://sp.example/metadata",
		ACSURL:            "https://sp.example/saml/acs",
		IDPMetadata:       testMetadata(),
		Store:             spStore,
		AllowIDPInitiated: false,
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
	if parsed.Query().Get("RelayState") != "relay-1" || parsed.Query().Get("SAMLRequest") == "" {
		t.Fatalf("authn url = %s", authnURL)
	}
	requestXML, err := DecodeRedirect(parsed.Query().Get("SAMLRequest"))
	if err != nil {
		t.Fatalf("decode request: %v", err)
	}
	request, err := ParseAuthnRequest(requestXML)
	if err != nil {
		t.Fatalf("parse request: %v", err)
	}
	if request.Issuer.Value != sp.Config().EntityID || request.AssertionConsumerServiceURL != sp.Config().ACSURL {
		t.Fatalf("request = %+v", request)
	}

	idpStore := NewMemoryStore()
	idp, err := NewIdentityProvider(IdentityProviderConfig{
		EntityID: "https://idp.example/metadata",
		SSOURL:   "https://idp.example/sso",
		Store:    idpStore,
		Authenticator: AuthenticatorFunc(func(context.Context, http.ResponseWriter, *http.Request, *AuthnRequest) (*auth.Principal, error) {
			return &auth.Principal{
				Subject:     "user-1",
				Email:       "alice@example.com",
				DisplayName: "Alice",
				AuthTime:    time.Now().UTC(),
				AMR:         []string{"pwd"},
			}, nil
		}),
		SignResponse:  false,
		SignAssertion: false,
	})
	if err != nil {
		t.Fatalf("idp: %v", err)
	}
	post := url.Values{"SAMLRequest": {EncodePost(requestXML)}, "RelayState": {"relay-1"}}
	req := httptest.NewRequest(http.MethodPost, "/sso", strings.NewReader(post.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	idp.HandleSSO(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("idp status = %d body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	responseValue := extractHiddenValue(body, "SAMLResponse")
	if responseValue == "" {
		t.Fatalf("no SAMLResponse in %s", body)
	}
	responseXML, err := DecodePost(responseValue)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	acsReq := httptest.NewRequest(http.MethodPost, "/acs", strings.NewReader(url.Values{
		"SAMLResponse": {EncodePost(responseXML)},
		"RelayState":   {"relay-1"},
	}.Encode()))
	acsReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	result, err := sp.ParseResponse(acsReq)
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if result.Principal.Subject != "user-1" || result.Principal.Email != "alice@example.com" {
		t.Fatalf("principal = %+v", result.Principal)
	}
	if result.RelayState != "relay-1" {
		t.Fatalf("relay state = %q", result.RelayState)
	}
	// Replay of the same assertion is rejected. | 同一断言重放会被拒绝。
	replay := httptest.NewRequest(http.MethodPost, "/acs", strings.NewReader(url.Values{
		"SAMLResponse": {EncodePost(responseXML)},
	}.Encode()))
	replay.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if _, err := sp.ParseResponse(replay); err == nil {
		t.Fatal("replayed response accepted")
	}
}

// extractHiddenValue extracts the value of a hidden input by name. | extractHiddenValue 按名称提取隐藏输入值。
func extractHiddenValue(body, name string) string {
	needle := `name="` + name + `" value="`
	start := strings.Index(body, needle)
	if start < 0 {
		return ""
	}
	start += len(needle)
	end := strings.Index(body[start:], `"`)
	if end < 0 {
		return ""
	}
	return body[start : start+end]
}

func TestRedirectSignatureHMAC(t *testing.T) {
	request := "compressed-request"
	params := url.Values{"SAMLRequest": {request}}
	secret := []byte("0123456789abcdef0123456789abcdef")
	if err := SignRedirect(params, secret, SigAlgHMACSHA256, "relay"); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := VerifyRedirect(params, nil, secret, nil, "relay"); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := VerifyRedirect(params, nil, secret, nil, "other"); err == nil {
		t.Fatal("tampered relay accepted")
	}
}

func TestRedirectSignatureRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	request := "compressed-request"
	params := url.Values{"SAMLRequest": {request}}
	if err := SignRedirect(params, key, SigAlgRSASHA256, "relay"); err != nil {
		t.Fatalf("sign: %v", err)
	}
	pub := &key.PublicKey
	// VerifyRedirect requires certificates; use a helper call through verifyRedirectWithKey. | VerifyRedirect
	// 需要证书；通过 verifyRedirectWithKey 辅助调用。
	signing := RedirectSigningString(request, "relay", SigAlgRSASHA256)
	signature, err := base64Decode(params.Get("Signature"))
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyRedirectWithKey(signing, signature, pub, SigAlgRSASHA256); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestMetadataRoundTrip(t *testing.T) {
	metadata := testMetadata()
	data, err := metadata.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	parsed, err := ParseEntityDescriptor(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.EntityID != metadata.EntityID || parsed.SSOURL(BindingHTTPRedirect) != "https://idp.example/sso" {
		t.Fatalf("parsed = %+v", parsed)
	}
}
