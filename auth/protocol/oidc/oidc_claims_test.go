package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/auth/protocol/oauth2"
	"github.com/shibingli/ydx/auth/token/jose"
	"github.com/shibingli/ydx/json"
)

func TestClaimsProvidersAndScopeFiltering(t *testing.T) {
	ctx := context.Background()
	verified := true
	principal := &auth.Principal{
		Subject:       "user-1",
		DisplayName:   "Alice",
		Username:      "alice",
		Email:         "alice@example.com",
		EmailVerified: verified,
		AMR:           []string{"pwd"},
		Attributes: map[string]string{
			"given_name":            "Alice",
			"family_name":           "Smith",
			"picture":               "https://rp.example/alice.png",
			"locale":                "en",
			"zoneinfo":              "UTC",
			"phone_number":          "+15550001",
			"phone_number_verified": "true",
		},
	}
	allScopes := []string{ScopeOpenID, ScopeProfile, ScopeEmail, ScopePhone, ScopeAddress}
	claims, err := (DefaultClaimsProvider{}).IDTokenClaims(ctx, principal, allScopes)
	if err != nil {
		t.Fatalf("ID token claims: %v", err)
	}
	if claims.Subject != "user-1" || claims.Name != "Alice" || claims.GivenName != "Alice" ||
		claims.FamilyName != "Smith" || claims.PreferredUsername != "alice" || claims.Email != "alice@example.com" ||
		claims.EmailVerified == nil || !*claims.EmailVerified || claims.PhoneNumber != "+15550001" ||
		claims.PhoneNumberVerified == nil || !*claims.PhoneNumberVerified || claims.Locale != "en" ||
		claims.Zoneinfo != "UTC" || claims.Picture == "" || len(claims.AMR) != 1 {
		t.Fatalf("claims = %+v", claims)
	}
	minimal, err := (DefaultClaimsProvider{}).IDTokenClaims(ctx, principal, []string{ScopeOpenID})
	if err != nil {
		t.Fatalf("minimal claims: %v", err)
	}
	if minimal.Name != "" || minimal.Email != "" || minimal.EmailVerified != nil ||
		minimal.PhoneNumber != "" || minimal.PhoneNumberVerified != nil || minimal.GivenName != "" {
		t.Fatalf("unfiltered claims = %+v", minimal)
	}
	if empty, err := (DefaultClaimsProvider{}).IDTokenClaims(ctx, nil, nil); err != nil || empty.Subject != "" {
		t.Fatalf("nil principal = %+v err=%v", empty, err)
	}

	userInfo, err := (DefaultClaimsProvider{}).UserInfoClaims(ctx, principal, allScopes)
	if err != nil {
		t.Fatalf("UserInfo claims: %v", err)
	}
	if userInfo["sub"] != "user-1" || userInfo["email"] != "alice@example.com" ||
		userInfo["given_name"] != "Alice" || userInfo["phone_number"] != "+15550001" {
		t.Fatalf("userinfo = %v", userInfo)
	}
	userInfo, err = (DefaultClaimsProvider{}).UserInfoClaims(ctx, nil, nil)
	if err != nil || len(userInfo) != 0 {
		t.Fatalf("nil userinfo = %v err=%v", userInfo, err)
	}

	// ClaimsProviderFunc falls back to the default provider and otherwise delegates. | ClaimsProviderFunc
	// 缺省时回退到默认提供者，否则委托调用。
	var fallback ClaimsProvider = ClaimsProviderFunc{}
	if claims, err := fallback.IDTokenClaims(ctx, principal, []string{ScopeOpenID, ScopeEmail}); err != nil || claims.Email == "" {
		t.Fatalf("fallback ID token = %+v err=%v", claims, err)
	}
	if got, err := fallback.UserInfoClaims(ctx, principal, []string{ScopeOpenID}); err != nil || got["sub"] != "user-1" {
		t.Fatalf("fallback userinfo = %v err=%v", got, err)
	}
	custom := ClaimsProviderFunc{
		IDToken: func(context.Context, *auth.Principal, []string) (*Claims, error) {
			return &Claims{Subject: "custom"}, nil
		},
		UserInfo: func(context.Context, *auth.Principal, []string) (map[string]any, error) {
			return map[string]any{"custom": true}, nil
		},
	}
	if claims, err := custom.IDTokenClaims(ctx, principal, nil); err != nil || claims.Subject != "custom" {
		t.Fatalf("custom ID token = %+v err=%v", claims, err)
	}
	if got, err := custom.UserInfoClaims(ctx, principal, nil); err != nil || got["custom"] != true {
		t.Fatalf("custom userinfo = %v err=%v", got, err)
	}
	filterClaims(nil, nil)
}

func TestClaimsPayloadExtraMerge(t *testing.T) {
	payload, err := claimsPayload(&Claims{
		Subject: "user-1",
		Extra:   map[string]any{"custom": "value", "sub": "attacker"},
	})
	if err != nil {
		t.Fatalf("claims payload: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded["sub"] != "user-1" || decoded["custom"] != "value" {
		t.Fatalf("payload = %v", decoded)
	}
	plain, err := claimsPayload(&Claims{Subject: "user-2"})
	if err != nil {
		t.Fatalf("plain payload: %v", err)
	}
	decoded = make(map[string]any)
	if err := json.Unmarshal(plain, &decoded); err != nil || decoded["sub"] != "user-2" || decoded["custom"] != nil {
		t.Fatalf("plain payload = %v err=%v", decoded, err)
	}
}

// newEncryptionKey returns an RSA-OAEP client key. | newEncryptionKey 返回 RSA-OAEP 客户端密钥。
func newEncryptionKey(t *testing.T) *jose.Key {
	t.Helper()
	key, err := jose.GenerateKey("RSA-OAEP-256", 2048)
	if err != nil {
		t.Fatalf("generate encryption key: %v", err)
	}
	key.Kid = "enc-1"
	key.Alg = "RSA-OAEP-256"
	key.Use = "enc"
	return key
}

// publicJWKS returns the public JWKS document for keys. | publicJWKS 返回 keys 的公开 JWKS 文档。
func publicJWKS(t *testing.T, keys ...*jose.Key) []byte {
	t.Helper()
	set := &jose.KeySet{}
	for _, key := range keys {
		if err := set.Add(key.Public()); err != nil {
			t.Fatalf("add key: %v", err)
		}
	}
	body, err := set.Marshal()
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}
	return body
}

func TestClientEncryptionKey(t *testing.T) {
	fixture := newOIDCFixture(t, false)
	provider := fixture.provider
	ctx := context.Background()
	encKey := newEncryptionKey(t)
	client := &oauth2.Client{ID: "web", JWKS: publicJWKS(t, encKey)}
	key, err := provider.clientEncryptionKey(ctx, client)
	if err != nil || key.Kid != "enc-1" {
		t.Fatalf("inline JWKS = %+v err=%v", key, err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jwks":
			_, _ = w.Write(publicJWKS(t, encKey))
		case "/garbage":
			_, _ = w.Write([]byte("not json"))
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()
	remote := &oauth2.Client{ID: "web", JWKSURI: server.URL + "/jwks"}
	if key, err := provider.clientEncryptionKey(ctx, remote); err != nil || key.Kid != "enc-1" {
		t.Fatalf("remote JWKS = %+v err=%v", key, err)
	}
	if _, err := provider.clientEncryptionKey(ctx, &oauth2.Client{ID: "web", JWKSURI: server.URL + "/garbage"}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("garbage JWKS = %v", err)
	}
	if _, err := provider.clientEncryptionKey(ctx, &oauth2.Client{ID: "web"}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("missing JWKS = %v", err)
	}
	if _, err := provider.clientEncryptionKey(ctx, &oauth2.Client{ID: "web", JWKS: []byte("not json")}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("invalid inline JWKS = %v", err)
	}
	sigKey, err := jose.GenerateKey("RS256", 2048)
	if err != nil {
		t.Fatal(err)
	}
	sigKey.Use = "sig"
	sigOnly := &oauth2.Client{ID: "web", JWKS: publicJWKS(t, sigKey)}
	if _, err := provider.clientEncryptionKey(ctx, sigOnly); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("signature-only JWKS = %v", err)
	}
}

func TestBuildIDTokenEncryption(t *testing.T) {
	fixture := newOIDCFixture(t, false)
	provider := fixture.provider
	encKey := newEncryptionKey(t)
	client := &oauth2.Client{
		ID:                          "web",
		IDTokenEncryptedResponseAlg: "RSA-OAEP-256",
		IDTokenEncryptedResponseEnc: "A256GCM",
		JWKS:                        publicJWKS(t, encKey),
	}
	grant := &oauth2.Grant{
		Client:    client,
		Principal: &auth.Principal{Subject: "user-1", Email: "alice@example.com"},
		Subject:   "user-1",
		Scopes:    []string{ScopeOpenID, ScopeEmail},
		Nonce:     "nonce-1",
		AuthTime:  time.Unix(1_700_000_000, 0).UTC(),
		IssuedAt:  time.Unix(1_700_000_000, 0).UTC(),
	}
	raw, err := provider.buildIDToken(context.Background(), grant, "access-token-1", "code-1")
	if err != nil {
		t.Fatalf("build encrypted ID token: %v", err)
	}
	if strings.Count(raw, ".") != 4 {
		t.Fatalf("encrypted token = %q", raw)
	}
	signed, err := jose.Decrypt(raw, encKey, jose.DecryptOptions{})
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	verified, err := jose.VerifyContext(context.Background(), string(signed), provider.Keys().Resolver(), jose.VerifyOptions{ValidAlgs: []string{"RS256"}})
	if err != nil {
		t.Fatalf("verify decrypted token: %v", err)
	}
	var claims Claims
	if err := json.Unmarshal(verified.Claims, &claims); err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	atHash, err := halfHash("RS256", "access-token-1")
	if err != nil {
		t.Fatal(err)
	}
	cHash, err := halfHash("RS256", "code-1")
	if err != nil {
		t.Fatal(err)
	}
	if claims.Issuer != fixture.server.URL || claims.Subject != "user-1" || !claims.Audience.Contains("web") ||
		claims.Nonce != "nonce-1" || claims.AccessTokenHash != atHash || claims.CodeHash != cHash ||
		claims.Email != "alice@example.com" || claims.JTI == "" {
		t.Fatalf("decrypted claims = %+v", claims)
	}

	missing := &oauth2.Client{ID: "web", IDTokenEncryptedResponseAlg: "RSA-OAEP-256"}
	grant.Client = missing
	if _, err := provider.buildIDToken(context.Background(), grant, "access", "code"); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("missing encryption key = %v", err)
	}
	unsupported := &oauth2.Client{ID: "web", IDTokenSignedResponseAlg: "HS256"}
	grant.Client = unsupported
	if _, err := provider.buildIDToken(context.Background(), grant, "access", "code"); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("unsupported signing alg = %v", err)
	}
}
