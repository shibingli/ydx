package oidc

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/shibingli/ydx/auth/token/jose"
	"github.com/shibingli/ydx/json"
)

// privateJWKSMembers are the JWK members that must never be published. | privateJWKSMembers 是绝不
// 允许发布的 JWK 成员。
var privateJWKSMembers = []string{"d", "p", "q", "dp", "dq", "qi"}

func TestProviderJWKSPublishesOnlyPublicMaterial(t *testing.T) {
	fixture := newOIDCFixture(t, false)

	// The configured set holds the private signing key. | 配置的密钥集保存私钥签名密钥。
	private := fixture.provider.Keys().Keys[0]
	if private.D == "" {
		t.Fatal("fixture signing key has no private material")
	}

	resp, err := http.Get(fixture.server.URL + JWKSPath)
	if err != nil {
		t.Fatalf("get jwks: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read jwks: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("jwks status = %d body=%s", resp.StatusCode, body)
	}
	if contentType := resp.Header.Get("Content-Type"); contentType != "application/jwk-set+json" {
		t.Fatalf("content type = %q", contentType)
	}

	var document struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	if len(document.Keys) != 1 {
		t.Fatalf("keys = %d", len(document.Keys))
	}
	key := document.Keys[0]
	for _, member := range privateJWKSMembers {
		if _, ok := key[member]; ok {
			t.Errorf("private member %q published: %s", member, body)
		}
		if strings.Contains(string(body), `"`+member+`":`) {
			t.Errorf("raw jwks contains private member %q: %s", member, body)
		}
	}
	if key["kty"] != "RSA" || key["n"] == "" || key["e"] == "" {
		t.Fatalf("published key is not a usable RSA public key: %v", key)
	}
	if key["kid"] != private.Kid {
		t.Fatalf("kid = %v", key["kid"])
	}

	// A set parsed from the published document verifies a token signed by the private key. | 从发布
	// 文档解析出的集合可以校验私钥签发的令牌。
	set, err := jose.ParseKeySet(body)
	if err != nil {
		t.Fatalf("parse published jwks: %v", err)
	}
	token, err := jose.Sign([]byte(`{"iss":"test"}`), private, jose.SignOptions{Alg: "RS256", Kid: private.Kid})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := jose.VerifyContext(context.Background(), token, set.Resolver(), jose.VerifyOptions{
		ValidAlgs: []string{"RS256"},
	}); err != nil {
		t.Fatalf("verify with published jwks: %v", err)
	}
}

func TestProviderJWKSOmitsSymmetricKeys(t *testing.T) {
	fixture := newOIDCFixture(t, false)
	hmac, err := jose.FromHMAC("hmac-1", []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("hmac key: %v", err)
	}
	hmac.Alg = "HS256"
	hmac.Use = "sig"
	if err := fixture.provider.Keys().Add(hmac); err != nil {
		t.Fatalf("add hmac key: %v", err)
	}

	resp, err := http.Get(fixture.server.URL + JWKSPath)
	if err != nil {
		t.Fatalf("get jwks: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read jwks: %v", err)
	}
	if strings.Contains(string(body), `"k":`) || strings.Contains(string(body), `"oct"`) {
		t.Fatalf("symmetric key published: %s", body)
	}
	if strings.Contains(string(body), "hmac-1") {
		t.Fatalf("symmetric kid published: %s", body)
	}
}

func TestProviderJWKSMethodNotAllowed(t *testing.T) {
	fixture := newOIDCFixture(t, false)
	resp, err := http.Post(fixture.server.URL+JWKSPath, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("post jwks: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if allow := resp.Header.Get("Allow"); !strings.Contains(allow, "GET") {
		t.Fatalf("allow = %q", allow)
	}
}
