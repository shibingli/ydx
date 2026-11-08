package saml

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth"
)

// TestValidateResponseRequiresEveryAudienceRestriction verifies SAML Core 2.5.1.4 intersection
// semantics: every AudienceRestriction element must contain the relying party. |
// TestValidateResponseRequiresEveryAudienceRestriction 校验 SAML Core 2.5.1.4 的交集语义：每个
// AudienceRestriction 元素都必须包含该依赖方。
func TestValidateResponseRequiresEveryAudienceRestriction(t *testing.T) {
	valid := samlValidResponse(samlTestNow)
	foreign := `<saml:AudienceRestriction><saml:Audience>https://other.example/metadata</saml:Audience></saml:AudienceRestriction>`
	document := strings.Replace(valid, `<saml:AudienceRestriction>`, foreign+`<saml:AudienceRestriction>`, 1)
	if !strings.Contains(document, foreign) {
		t.Fatalf("test document was not assembled")
	}
	if _, err := ValidateResponse(context.Background(), []byte(document), samlValidationOptions(samlStoreWithRequest(t))); !errors.Is(err, ErrInvalidAudience) {
		t.Fatalf("error = %v, want ErrInvalidAudience", err)
	}
}

// TestValidateAuthnRequestRejectsACSMissingFromMetadata rejects a request-supplied ACS URL when the
// resolved SP metadata does not register one. | TestValidateAuthnRequestRejectsACSMissingFromMetadata
// 在解析出的 SP 元数据未注册 ACS 时拒绝请求自带的 ACS URL。
func TestValidateAuthnRequestRejectsACSMissingFromMetadata(t *testing.T) {
	request := &AuthnRequest{
		ID:                          "request-1",
		Version:                     Version,
		IssueInstant:                FormatTime(samlTestNow),
		Destination:                 "https://idp.example/sso",
		Issuer:                      &Issuer{Value: "https://sp.example/metadata"},
		AssertionConsumerServiceURL: "https://evil.example/acs",
	}
	opts := AuthnRequestValidationOptions{
		IDPEntityID: "https://idp.example/metadata",
		SSOURL:      "https://idp.example/sso",
		SPResolver: staticResolver{metadata: &EntityDescriptor{
			EntityID:        "https://sp.example/metadata",
			SPSSODescriptor: &SPSSODescriptor{},
		}},
		Now: func() time.Time { return samlTestNow },
	}
	if err := ValidateAuthnRequest(context.Background(), request, opts); !errors.Is(err, ErrInvalidRecipient) {
		t.Fatalf("error = %v, want ErrInvalidRecipient", err)
	}
}

// TestResolveACSPrefersRegisteredEndpoint verifies that a configured resolver decides the ACS URL
// even when a request carries one. | TestResolveACSPrefersRegisteredEndpoint 校验配置解析器时即使
// 请求自带 ACS URL 也以已注册端点为准。
func TestResolveACSPrefersRegisteredEndpoint(t *testing.T) {
	idp, err := NewIdentityProvider(IdentityProviderConfig{
		EntityID: "https://idp.example/metadata",
		SSOURL:   "https://idp.example/sso",
		Store:    NewMemoryStore(),
		SPResolver: staticResolver{metadata: &EntityDescriptor{
			EntityID: "https://sp.example/metadata",
			SPSSODescriptor: &SPSSODescriptor{
				AssertionConsumerService: []IndexedEndpoint{{Binding: BindingHTTPPost, Location: "https://sp.example/saml/acs"}},
			},
		}},
		Authenticator: AuthenticatorFunc(func(context.Context, http.ResponseWriter, *http.Request, *AuthnRequest) (*auth.Principal, error) {
			return &auth.Principal{Subject: "alice"}, nil
		}),
	})
	if err != nil {
		t.Fatalf("idp: %v", err)
	}
	request := &AuthnRequest{
		Issuer:                      &Issuer{Value: "https://sp.example/metadata"},
		AssertionConsumerServiceURL: "https://evil.example/acs",
	}
	acs, err := idp.resolveACS(context.Background(), request)
	if err != nil {
		t.Fatalf("resolveACS: %v", err)
	}
	if acs != "https://sp.example/saml/acs" {
		t.Fatalf("ACS = %q, want the registered endpoint", acs)
	}
}
