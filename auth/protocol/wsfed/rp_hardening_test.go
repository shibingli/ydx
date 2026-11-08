package wsfed

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/auth/protocol/saml"
	"github.com/shibingli/ydx/xml"
)

// tokenCollectionFor issues an unsigned token and rewrites its serialized XML with mutate. |
// tokenCollectionFor 签发未签名令牌，并用 mutate 重写其序列化 XML。
func tokenCollectionFor(t *testing.T, tokenType string, mutate func(string) string) *RequestSecurityTokenResponseCollection {
	t.Helper()
	sts := newTestSTS(t, &stubAuthenticator{principal: testPrincipal()}, func(config *STSConfig) {
		config.TokenType = tokenType
	})
	request := &SignInRequest{WA: ActionSignIn, Wtrealm: testRealm, Wreply: testReply, Wctx: "ctx"}
	tokenID, tokenXML, _, _, _, _, err := sts.issueToken(context.Background(), testPrincipal(), request, testReply, testNow, testNow.Add(5*time.Minute))
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	if mutate != nil {
		tokenXML = mutate(tokenXML)
	}
	return sts.tokenResponse(request, testReply, tokenID, tokenXML, testNow, testNow.Add(5*time.Minute))
}

// assertionWithIssuer rewrites a SAML 2.0 assertion issuer; nil removes it. |
// assertionWithIssuer 重写 SAML 2.0 断言的签发方；nil 表示移除。
func assertionWithIssuer(t *testing.T, tokenXML string, issuer *saml.Issuer) string {
	t.Helper()
	var assertion saml.Assertion
	if err := xml.Unmarshal([]byte(tokenXML), &assertion); err != nil {
		t.Fatalf("unmarshal assertion: %v", err)
	}
	assertion.Issuer = issuer
	data, err := xml.Marshal(&assertion)
	if err != nil {
		t.Fatalf("marshal assertion: %v", err)
	}
	return string(data)
}

// saml11WithIssuer rewrites a SAML 1.1 assertion issuer. | saml11WithIssuer 重写 SAML 1.1 断言的
// 签发方。
func saml11WithIssuer(t *testing.T, tokenXML, issuer string) string {
	t.Helper()
	var assertion SAML11Assertion
	if err := xml.Unmarshal([]byte(tokenXML), &assertion); err != nil {
		t.Fatalf("unmarshal SAML 1.1 assertion: %v", err)
	}
	assertion.Issuer = issuer
	data, err := xml.Marshal(&assertion)
	if err != nil {
		t.Fatalf("marshal SAML 1.1 assertion: %v", err)
	}
	return string(data)
}

// jwtCollection returns a JWT token response. | jwtCollection 返回 JWT 令牌响应。
func jwtCollection() *RequestSecurityTokenResponseCollection {
	return &RequestSecurityTokenResponseCollection{Responses: []RequestSecurityTokenResponse{{
		TokenType:              TokenTypeJWT,
		Wctx:                   "ctx",
		RequestedSecurityToken: &RequestedSecurityToken{InnerXML: "a.b.c"},
		Lifetime:               &Lifetime{Created: saml.FormatTime(testNow), Expires: saml.FormatTime(testNow.Add(time.Minute))},
		Status:                 &ResponseStatus{Code: StatusSuccess},
	}}}
}

// jwtRP returns an RP whose verifier reports tokenIssuer. | jwtRP 返回校验器报告 tokenIssuer 的 RP。
func jwtRP(t *testing.T, tokenIssuer, pinnedIssuer string) *RelyingParty {
	t.Helper()
	return newTestRP(t, func(config *RelyingPartyConfig) {
		config.TokenType = TokenTypeJWT
		config.Issuer = pinnedIssuer
		config.JWTVerifier = JWTVerifierFunc(func(_ context.Context, _, _ string) (*auth.Principal, map[string][]string, time.Time, error) {
			return &auth.Principal{Subject: "user-1", Issuer: tokenIssuer}, nil, testNow.Add(time.Minute), nil
		})
	})
}

// TestRPSignedAssertionWithoutVerifierIsRejected rejects signatures that cannot be verified. |
// TestRPSignedAssertionWithoutVerifierIsRejected 拒绝无法校验的签名。
func TestRPSignedAssertionWithoutVerifierIsRejected(t *testing.T) {
	sts := signedSTS(t, testRealm)
	collection, _ := issueTestToken(t, sts, testPrincipal(), testRealm, testReply, "ctx-1", testNow, testNow.Add(5*time.Minute))
	rp := newTestRP(t, nil)
	if _, err := rp.ParseSignInResponse(responseRequest(t, collection, "ctx-1")); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("error = %v, want ErrInvalidSignature", err)
	}
}

// TestRPRequireSignedSemantics checks RequireSigned together with a verifier. |
// TestRPRequireSignedSemantics 校验 RequireSigned 与校验器的组合语义。
func TestRPRequireSignedSemantics(t *testing.T) {
	t.Run("signed assertion is accepted", func(t *testing.T) {
		sts := signedSTS(t, testRealm)
		collection, _ := issueTestToken(t, sts, testPrincipal(), testRealm, testReply, "ctx", testNow, testNow.Add(5*time.Minute))
		rp := newTestRP(t, func(config *RelyingPartyConfig) {
			config.RequireSigned = true
			config.SignatureVerifier = testVerifier()
		})
		if _, err := rp.ParseSignInResponse(responseRequest(t, collection, "ctx")); err != nil {
			t.Fatalf("signed assertion: %v", err)
		}
	})
	t.Run("unsigned assertion is rejected", func(t *testing.T) {
		sts := newTestSTS(t, &stubAuthenticator{principal: testPrincipal()}, nil)
		collection, _ := issueTestToken(t, sts, testPrincipal(), testRealm, testReply, "ctx", testNow, testNow.Add(5*time.Minute))
		rp := newTestRP(t, func(config *RelyingPartyConfig) {
			config.RequireSigned = true
			config.SignatureVerifier = testVerifier()
		})
		if _, err := rp.ParseSignInResponse(responseRequest(t, collection, "ctx")); !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("error = %v, want ErrInvalidSignature", err)
		}
	})
	t.Run("RequireSigned without a verifier fails construction", func(t *testing.T) {
		if _, err := NewRelyingParty(RelyingPartyConfig{
			Realm:         testRealm,
			ReplyURL:      testReply,
			RequireSigned: true,
		}); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("error = %v, want ErrInvalidConfig", err)
		}
	})
}

// TestRPIssuerPinning checks issuer matching for SAML 2.0, SAML 1.1 and JWT tokens. |
// TestRPIssuerPinning 校验 SAML 2.0、SAML 1.1 与 JWT 令牌的签发方匹配。
func TestRPIssuerPinning(t *testing.T) {
	pinned := func(t *testing.T) *RelyingParty {
		t.Helper()
		return newTestRP(t, func(config *RelyingPartyConfig) {
			config.Issuer = " " + testIssuer + " "
		})
	}
	parse := func(t *testing.T, rp *RelyingParty, collection *RequestSecurityTokenResponseCollection) error {
		t.Helper()
		_, err := rp.ParseSignInResponse(responseRequest(t, collection, "ctx"))
		return err
	}

	t.Run("SAML 2.0 matching issuer is accepted", func(t *testing.T) {
		collection := tokenCollectionFor(t, TokenTypeSAML20, func(tokenXML string) string {
			return assertionWithIssuer(t, tokenXML, &saml.Issuer{Value: testIssuer})
		})
		if err := parse(t, pinned(t), collection); err != nil {
			t.Fatalf("ParseSignInResponse: %v", err)
		}
	})
	t.Run("SAML 2.0 mismatched issuer is rejected", func(t *testing.T) {
		collection := tokenCollectionFor(t, TokenTypeSAML20, func(tokenXML string) string {
			return assertionWithIssuer(t, tokenXML, &saml.Issuer{Value: "https://evil.example/"})
		})
		if err := parse(t, pinned(t), collection); !errors.Is(err, ErrInvalidIssuer) {
			t.Fatalf("error = %v, want ErrInvalidIssuer", err)
		}
	})
	t.Run("SAML 2.0 missing issuer is rejected", func(t *testing.T) {
		collection := tokenCollectionFor(t, TokenTypeSAML20, func(tokenXML string) string {
			return assertionWithIssuer(t, tokenXML, nil)
		})
		if err := parse(t, pinned(t), collection); !errors.Is(err, ErrInvalidIssuer) {
			t.Fatalf("error = %v, want ErrInvalidIssuer", err)
		}
	})
	t.Run("SAML 1.1 matching issuer is accepted", func(t *testing.T) {
		collection := tokenCollectionFor(t, TokenTypeSAML11, func(tokenXML string) string {
			return saml11WithIssuer(t, tokenXML, testIssuer)
		})
		if err := parse(t, pinned(t), collection); err != nil {
			t.Fatalf("ParseSignInResponse: %v", err)
		}
	})
	t.Run("SAML 1.1 mismatched issuer is rejected", func(t *testing.T) {
		collection := tokenCollectionFor(t, TokenTypeSAML11, func(tokenXML string) string {
			return saml11WithIssuer(t, tokenXML, "https://evil.example/")
		})
		if err := parse(t, pinned(t), collection); !errors.Is(err, ErrInvalidIssuer) {
			t.Fatalf("error = %v, want ErrInvalidIssuer", err)
		}
	})
	t.Run("SAML 1.1 missing issuer is rejected", func(t *testing.T) {
		collection := tokenCollectionFor(t, TokenTypeSAML11, func(tokenXML string) string {
			return saml11WithIssuer(t, tokenXML, "")
		})
		if err := parse(t, pinned(t), collection); !errors.Is(err, ErrInvalidIssuer) {
			t.Fatalf("error = %v, want ErrInvalidIssuer", err)
		}
	})
	t.Run("JWT matching issuer is accepted", func(t *testing.T) {
		if err := parse(t, jwtRP(t, testIssuer, testIssuer), jwtCollection()); err != nil {
			t.Fatalf("ParseSignInResponse: %v", err)
		}
	})
	t.Run("JWT mismatched issuer is rejected", func(t *testing.T) {
		if err := parse(t, jwtRP(t, "https://evil.example/", testIssuer), jwtCollection()); !errors.Is(err, ErrInvalidIssuer) {
			t.Fatalf("error = %v, want ErrInvalidIssuer", err)
		}
	})
	t.Run("JWT missing issuer is rejected", func(t *testing.T) {
		if err := parse(t, jwtRP(t, "", testIssuer), jwtCollection()); !errors.Is(err, ErrInvalidIssuer) {
			t.Fatalf("error = %v, want ErrInvalidIssuer", err)
		}
	})
	t.Run("unpinned issuer accepts any issuer", func(t *testing.T) {
		collection := tokenCollectionFor(t, TokenTypeSAML20, func(tokenXML string) string {
			return assertionWithIssuer(t, tokenXML, &saml.Issuer{Value: "https://other.example/"})
		})
		if err := parse(t, newTestRP(t, nil), collection); err != nil {
			t.Fatalf("ParseSignInResponse: %v", err)
		}
	})
}

// TestRPRejectsStatusWithoutCode rejects present WS-Trust status elements without a success code. |
// TestRPRejectsStatusWithoutCode 拒绝存在但没有成功码的 WS-Trust 状态元素。
func TestRPRejectsStatusWithoutCode(t *testing.T) {
	rp := newTestRP(t, nil)
	collection := &RequestSecurityTokenResponseCollection{Responses: []RequestSecurityTokenResponse{{
		Status: &ResponseStatus{},
	}}}
	if _, err := rp.ParseSignInResponse(responseRequest(t, collection, "ctx")); !errors.Is(err, ErrStatusFailure) {
		t.Fatalf("sign-in error = %v, want ErrStatusFailure", err)
	}
	const namespace = `xmlns:trust="http://docs.oasis-open.org/ws-sx/ws-trust/200512"`
	failure := `<trust:RequestSecurityTokenResponseCollection ` + namespace + `><trust:RequestSecurityTokenResponse><trust:Status></trust:Status></trust:RequestSecurityTokenResponse></trust:RequestSecurityTokenResponseCollection>`
	if err := rp.ParseSignOutResponse(postWResult(t, testReply, failure, "ctx")); !errors.Is(err, ErrStatusFailure) {
		t.Fatalf("sign-out error = %v, want ErrStatusFailure", err)
	}
	success := `<trust:RequestSecurityTokenResponseCollection ` + namespace + `><trust:RequestSecurityTokenResponse><trust:Status><trust:Code>` +
		StatusSuccess + `</trust:Code></trust:Status></trust:RequestSecurityTokenResponse></trust:RequestSecurityTokenResponseCollection>`
	if err := rp.ParseSignOutResponse(postWResult(t, testReply, success, "ctx")); err != nil {
		t.Fatalf("successful sign-out: %v", err)
	}
}
