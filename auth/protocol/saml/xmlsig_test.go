package saml

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth"
)

// testCertificate returns a self-signed RSA certificate for XMLDSig tests. | testCertificate
// 返回用于 XMLDSig 测试的自签名 RSA 证书。
func testCertificate(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "idp.example"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

func TestSAMLXMLDSigRoundTrip(t *testing.T) {
	key, cert := testCertificate(t)
	spStore := NewMemoryStore()
	sp, err := NewServiceProvider(ServiceProviderConfig{
		EntityID:               "https://sp.example/metadata",
		ACSURL:                 "https://sp.example/saml/acs",
		IDPMetadata:            testMetadata(),
		Store:                  spStore,
		SignatureVerifier:      &XMLDSigVerifier{Certificates: []*x509.Certificate{cert}},
		RequireSignedAssertion: true,
		RequireSignedResponse:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	authnURL, err := sp.AuthnRequestURL("relay-signed")
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(authnURL)
	requestXML, err := DecodeRedirect(parsed.Query().Get("SAMLRequest"))
	if err != nil {
		t.Fatal(err)
	}
	idp, err := NewIdentityProvider(IdentityProviderConfig{
		EntityID: "https://idp.example/metadata",
		SSOURL:   "https://idp.example/sso",
		Store:    NewMemoryStore(),
		Authenticator: AuthenticatorFunc(func(context.Context, http.ResponseWriter, *http.Request, *AuthnRequest) (*auth.Principal, error) {
			return &auth.Principal{Subject: "signed-user", Email: "signed@example.com", AuthTime: time.Now().UTC()}, nil
		}),
		Signer:        &XMLDSigSigner{PrivateKey: key, Certificate: cert, Exclusive: true},
		SignResponse:  true,
		SignAssertion: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/sso", strings.NewReader(url.Values{
		"SAMLRequest": {EncodePost(requestXML)},
		"RelayState":  {"relay-signed"},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	idp.HandleSSO(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("idp status = %d body=%s", w.Code, w.Body.String())
	}
	value := extractHiddenValue(w.Body.String(), "SAMLResponse")
	responseXML, err := DecodePost(value)
	if err != nil {
		t.Fatal(err)
	}
	acsReq := httptest.NewRequest(http.MethodPost, "/acs", strings.NewReader(url.Values{
		"SAMLResponse": {EncodePost(responseXML)},
	}.Encode()))
	acsReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	result, err := sp.ParseResponse(acsReq)
	if err != nil {
		t.Fatalf("signed response rejected: %v", err)
	}
	if result.Principal.Subject != "signed-user" {
		t.Fatalf("principal = %+v", result.Principal)
	}
	// A tampered response must fail signature verification. | 被篡改的响应必须验签失败。
	tampered := strings.Replace(string(responseXML), "signed-user", "tampered-user", 1)
	badReq := httptest.NewRequest(http.MethodPost, "/acs", strings.NewReader(url.Values{
		"SAMLResponse": {EncodePost([]byte(tampered))},
	}.Encode()))
	badReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if _, err := sp.ParseResponse(badReq); err == nil {
		t.Fatal("tampered signed response accepted")
	}
}
