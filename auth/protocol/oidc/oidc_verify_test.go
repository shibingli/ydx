package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth/protocol/oauth2"
	"github.com/shibingli/ydx/auth/token/jose"
	"github.com/shibingli/ydx/json"
)

// signVerifyToken signs an ID token claim set with key. | signVerifyToken 用 key 签发 ID 令牌声明集。
func signVerifyToken(t *testing.T, key *jose.Key, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	signed, err := jose.Sign(payload, key, jose.SignOptions{Alg: key.Alg, Kid: key.Kid, Typ: "JWT"})
	if err != nil {
		t.Fatalf("sign ID token: %v", err)
	}
	return signed
}

// verifyClaims returns a valid claim baseline at now. | verifyClaims 返回 now 时刻的合法声明基线。
func verifyClaims(issuer string, now time.Time) map[string]any {
	return map[string]any{
		"iss": issuer,
		"sub": "user-1",
		"aud": []string{"web"},
		"exp": now.Add(5 * time.Minute).Unix(),
		"iat": now.Unix(),
	}
}

func TestVerifyIDTokenClaimsAndHashes(t *testing.T) {
	fixture := newOIDCFixture(t, false)
	now := time.Unix(1_700_000_000, 0).UTC()
	claims := verifyClaims(fixture.server.URL, now)
	accessToken := "access-token-1"
	code := "code-1"
	atHash, err := halfHash("RS256", accessToken)
	if err != nil {
		t.Fatal(err)
	}
	cHash, err := halfHash("RS256", code)
	if err != nil {
		t.Fatal(err)
	}
	claims["nonce"] = "nonce-1"
	claims["auth_time"] = now.Add(-time.Minute).Unix()
	claims["at_hash"] = atHash
	claims["c_hash"] = cHash
	claims["custom_claim"] = "custom-value"
	raw := signVerifyToken(t, fixture.provider.signingKey, claims)
	opts := IDTokenVerifyOptions{
		Issuer:      fixture.server.URL,
		Audience:    "web",
		Nonce:       "nonce-1",
		AccessToken: accessToken,
		Code:        code,
		MaxAge:      time.Hour,
		Now:         func() time.Time { return now },
	}
	token, err := VerifyIDToken(context.Background(), raw, fixture.provider.Keys().Resolver(), opts)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if token.Claims.Subject != "user-1" || token.Claims.Email != "" || token.Claims.AuthTime == 0 ||
		token.Raw["custom_claim"] != "custom-value" || token.Header["alg"] != "RS256" || token.RawToken != raw {
		t.Fatalf("verified token = %+v raw=%v", token, token.Raw)
	}
	if err := token.ValidateAccessTokenHash(accessToken); err != nil {
		t.Fatalf("at_hash: %v", err)
	}
	if err := token.ValidateCodeHash(code); err != nil {
		t.Fatalf("c_hash: %v", err)
	}
	if err := token.ValidateAccessTokenHash("other"); !errors.Is(err, ErrInvalidAtHash) {
		t.Fatalf("wrong at_hash = %v", err)
	}
	if err := token.ValidateCodeHash("other"); !errors.Is(err, ErrInvalidCHash) {
		t.Fatalf("wrong c_hash = %v", err)
	}
	if err := (&IDToken{}).ValidateAccessTokenHash("x"); !errors.Is(err, ErrInvalidAtHash) {
		t.Fatalf("missing at_hash = %v", err)
	}
	var nilToken *IDToken
	if err := nilToken.ValidateCodeHash("x"); !errors.Is(err, ErrInvalidCHash) {
		t.Fatalf("nil c_hash = %v", err)
	}
}

func TestVerifyIDTokenFailures(t *testing.T) {
	fixture := newOIDCFixture(t, false)
	resolver := fixture.provider.Keys().Resolver()
	now := time.Unix(1_700_000_000, 0).UTC()
	baseOpts := func() IDTokenVerifyOptions {
		return IDTokenVerifyOptions{
			Issuer:   fixture.server.URL,
			Audience: "web",
			Nonce:    "nonce-1",
			Now:      func() time.Time { return now },
		}
	}
	goodHash, err := halfHash("RS256", "access-token-1")
	if err != nil {
		t.Fatal(err)
	}
	goodCodeHash, err := halfHash("RS256", "code-1")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := VerifyIDToken(context.Background(), "x", nil, baseOpts()); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil resolver = %v", err)
	}
	noIssuer := baseOpts()
	noIssuer.Issuer = ""
	if _, err := VerifyIDToken(context.Background(), "x", resolver, noIssuer); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("empty issuer = %v", err)
	}
	noAudience := baseOpts()
	noAudience.Audience = ""
	if _, err := VerifyIDToken(context.Background(), "x", resolver, noAudience); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("empty audience = %v", err)
	}
	if _, err := VerifyIDToken(context.Background(), "not-a-token", resolver, baseOpts()); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("garbage token = %v", err)
	}
	nonObject, err := jose.Sign([]byte(`[1,2,3]`), fixture.provider.signingKey, jose.SignOptions{Alg: "RS256", Kid: fixture.provider.signingKey.Kid})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyIDToken(context.Background(), nonObject, resolver, baseOpts()); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("non-object payload = %v", err)
	}

	cases := []struct {
		name   string
		mutate func(map[string]any)
		opts   func(*IDTokenVerifyOptions)
		want   error
	}{
		{"issuer mismatch", func(c map[string]any) { c["iss"] = "https://other.example" }, nil, ErrInvalidIssuer},
		{"missing subject", func(c map[string]any) { delete(c, "sub") }, nil, ErrInvalidToken},
		{"wrong audience", func(c map[string]any) { c["aud"] = []string{"other"} }, nil, ErrInvalidAudience},
		{"multi audience without azp", func(c map[string]any) { c["aud"] = []string{"web", "other"} }, nil, ErrInvalidAudience},
		{"multi audience wrong azp", func(c map[string]any) {
			c["aud"] = []string{"web", "other"}
			c["azp"] = "other"
		}, nil, ErrInvalidAudience},
		{"single audience wrong azp", func(c map[string]any) { c["azp"] = "other" }, nil, ErrInvalidAudience},
		{"missing exp", func(c map[string]any) { delete(c, "exp") }, nil, ErrInvalidToken},
		{"missing iat", func(c map[string]any) { delete(c, "iat") }, nil, ErrInvalidToken},
		{"expired", func(c map[string]any) { c["exp"] = now.Add(-time.Minute).Unix() }, nil, ErrTokenExpired},
		{"not yet valid", func(c map[string]any) { c["nbf"] = now.Add(time.Hour).Unix() }, nil, ErrTokenNotYetValid},
		{"iat in the future", func(c map[string]any) { c["iat"] = now.Add(time.Hour).Unix() }, nil, ErrInvalidToken},
		{"wrong nonce", func(c map[string]any) { c["nonce"] = "other" }, nil, ErrInvalidNonce},
		{"max_age without auth_time", func(c map[string]any) {}, func(o *IDTokenVerifyOptions) {
			o.MaxAge = time.Hour
		}, ErrInvalidToken},
		{"max_age exceeded", func(c map[string]any) { c["auth_time"] = now.Add(-2 * time.Hour).Unix() }, func(o *IDTokenVerifyOptions) {
			o.MaxAge = time.Hour
		}, ErrInvalidToken},
		{"at_hash missing", func(c map[string]any) {}, func(o *IDTokenVerifyOptions) {
			o.AccessToken = "access-token-1"
		}, ErrInvalidAtHash},
		{"at_hash mismatch", func(c map[string]any) { c["at_hash"] = goodHash }, func(o *IDTokenVerifyOptions) {
			o.AccessToken = "other-token"
		}, ErrInvalidAtHash},
		{"c_hash missing", func(c map[string]any) {}, func(o *IDTokenVerifyOptions) {
			o.Code = "code-1"
		}, ErrInvalidCHash},
		{"c_hash mismatch", func(c map[string]any) { c["c_hash"] = goodCodeHash }, func(o *IDTokenVerifyOptions) {
			o.Code = "other-code"
		}, ErrInvalidCHash},
		{"alg outside allow list", func(c map[string]any) {}, func(o *IDTokenVerifyOptions) {
			o.ValidAlgs = []string{"ES256"}
		}, ErrInvalidToken},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := verifyClaims(fixture.server.URL, now)
			if !containsNonceCase(tc.name) {
				claims["nonce"] = "nonce-1"
			}
			tc.mutate(claims)
			opts := baseOpts()
			if tc.opts != nil {
				tc.opts(&opts)
			}
			raw := signVerifyToken(t, fixture.provider.signingKey, claims)
			if _, err := VerifyIDToken(context.Background(), raw, resolver, opts); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v want %v", err, tc.want)
			}
		})
	}

	// A token signed by an unrelated key must not verify. | 由无关密钥签发的令牌不得通过校验。
	other, err := jose.GenerateKey("RS256", 2048)
	if err != nil {
		t.Fatal(err)
	}
	other.Kid = fixture.provider.signingKey.Kid
	other.Alg = "RS256"
	raw := signVerifyToken(t, other, verifyClaims(fixture.server.URL, now))
	if _, err := VerifyIDToken(context.Background(), raw, resolver, baseOpts()); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("foreign key = %v", err)
	}
}

// containsNonceCase reports whether name intentionally removes or replaces the nonce. | containsNonceCase
// 报告用例是否刻意移除或替换 nonce。
func containsNonceCase(name string) bool {
	return name == "wrong nonce"
}

func TestVerifyIDTokenHMACPolicy(t *testing.T) {
	hmac, err := jose.FromHMAC("hmac-1", []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("hmac key: %v", err)
	}
	hmac.Alg = "HS256"
	keys := &jose.KeySet{}
	if err := keys.Add(hmac); err != nil {
		t.Fatalf("add hmac: %v", err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	raw := signVerifyToken(t, hmac, verifyClaims("https://op.example", now))
	opts := IDTokenVerifyOptions{
		Issuer:   "https://op.example",
		Audience: "web",
		Now:      func() time.Time { return now },
	}
	if _, err := VerifyIDToken(context.Background(), raw, keys.Resolver(), opts); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("HMAC accepted by default = %v", err)
	}
	opts.AllowHMAC = true
	if _, err := VerifyIDToken(context.Background(), raw, keys.Resolver(), opts); err != nil {
		t.Fatalf("HMAC with AllowHMAC = %v", err)
	}
}

func TestRelyingPartyJWKSRotation(t *testing.T) {
	newKey := func(kid string) *jose.Key {
		key, err := jose.GenerateKey("RS256", 2048)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		key.Kid = kid
		key.Alg = "RS256"
		key.Use = "sig"
		return key
	}
	key1 := newKey("rotate-1")
	key2 := newKey("rotate-2")
	key3 := newKey("rotate-3")
	setBody := func(keys ...*jose.Key) []byte {
		set := &jose.KeySet{}
		for _, key := range keys {
			if err := set.Add(key.Public()); err != nil {
				t.Fatalf("add public key: %v", err)
			}
		}
		body, err := set.Marshal()
		if err != nil {
			t.Fatalf("marshal JWKS: %v", err)
		}
		return body
	}

	var mu sync.Mutex
	current := setBody(key1)
	fetches := 0
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		body := current
		fetches++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write(body)
	}))
	defer jwks.Close()

	issuer := "https://op.example"
	discovery := &DiscoveryDocument{ServerMetadata: &oauth2.ServerMetadata{
		Issuer:                issuer,
		AuthorizationEndpoint: issuer + "/authorize",
		TokenEndpoint:         issuer + "/token",
		JWKSURI:               jwks.URL,
	}}
	ctx := context.Background()
	rp, err := NewRelyingParty(ctx, RelyingPartyConfig{
		Issuer:     issuer,
		ClientID:   "web",
		Discovery:  discovery,
		HTTPClient: jwks.Client(),
	})
	if err != nil {
		t.Fatalf("relying party: %v", err)
	}
	now := time.Now()
	if _, err := rp.ValidateIDToken(ctx, signVerifyToken(t, key1, verifyClaims(issuer, now)), "", ""); err != nil {
		t.Fatalf("initial JWKS: %v", err)
	}

	mu.Lock()
	current = setBody(key2)
	mu.Unlock()
	if _, err := rp.ValidateIDToken(ctx, signVerifyToken(t, key2, verifyClaims(issuer, now)), "", ""); err != nil {
		t.Fatalf("rotated JWKS: %v", err)
	}
	if fetches < 2 {
		t.Fatalf("fetches = %d", fetches)
	}

	mu.Lock()
	current = setBody()
	mu.Unlock()
	if _, err := rp.ValidateIDToken(ctx, signVerifyToken(t, key3, verifyClaims(issuer, now)), "", ""); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("missing rotated key = %v", err)
	}
}
