package federation

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth/protocol/oidc"
	"github.com/shibingli/ydx/auth/token/jose"
)

// oidcFailureCase describes one rejected token exchange. | oidcFailureCase 描述一次被拒绝的令牌兑换。
type oidcFailureCase struct {
	name        string
	discover    bool
	mutate      func(*oidcFixture)
	configure   func(*Provider)
	want        []error
	notWant     []error
	wantMessage []string
	after       func(*testing.T, *oidcFixture)
}

// runOIDCFailureCase executes one rejection case against a fresh fixture. | runOIDCFailureCase
// 针对全新 fixture 执行一个拒绝用例。
func runOIDCFailureCase(t *testing.T, tc oidcFailureCase) {
	t.Helper()
	fixture := newOIDCFixture(t)
	if tc.mutate != nil {
		tc.mutate(fixture)
	}
	var adapter ProviderAdapter
	if tc.discover {
		adapter = newAdapter(fixture.discoveryProvider("oidc-sec"), nil)
	} else {
		p := fixture.provider("oidc-sec")
		if tc.configure != nil {
			tc.configure(p)
		}
		adapter = newAdapter(p, nil)
	}
	_, err := adapter.Exchange(context.Background(), "authorization-code", "")
	assertErrorIs(t, err, append([]error{ErrTokenExchange}, tc.want...)...)
	for _, sentinel := range tc.notWant {
		if err != nil && errors.Is(err, sentinel) {
			t.Fatalf("error %q unexpectedly matches %v | 错误 %q 意外匹配 %v", err, sentinel, err, sentinel)
		}
	}
	if len(tc.wantMessage) > 0 {
		assertErrorMentions(t, err, tc.wantMessage...)
	}
	assertNoSecrets(t, err)
	if tc.after != nil {
		tc.after(t, fixture)
	}
}

// TestOIDCExchangeRejectsInvalidIDTokens verifies the security-critical ID token checks.
// TestOIDCExchangeRejectsInvalidIDTokens 校验安全关键的 ID 令牌检查。
func TestOIDCExchangeRejectsInvalidIDTokens(t *testing.T) {
	now := time.Now()
	_, _, rogue, _ := sharedOIDCKeys(t)
	wrongFamilyHeader := map[string]any{"alg": "ES256", "kid": "rsa-1", "typ": "JWT"}
	wrongFamilyClaims := map[string]any{
		"iss": "",
		"sub": "oidc-subject",
		"aud": oidcFixtureClientID,
		"exp": now.Add(5 * time.Minute).Unix(),
		"iat": now.Add(-10 * time.Second).Unix(),
	}
	cases := []oidcFailureCase{
		{
			name: "wrong issuer",
			mutate: func(f *oidcFixture) {
				f.set(func(c *oidcFixtureConfig) { c.claims["iss"] = "https://wrong-issuer.example" })
			},
			want: []error{oidc.ErrInvalidIssuer},
		},
		{
			name: "wrong audience",
			mutate: func(f *oidcFixture) {
				f.set(func(c *oidcFixtureConfig) { c.claims["aud"] = "other-client" })
			},
			want: []error{oidc.ErrInvalidAudience},
		},
		{
			name: "expired token",
			mutate: func(f *oidcFixture) {
				f.set(func(c *oidcFixtureConfig) {
					c.claims["exp"] = now.Add(-time.Hour).Unix()
					c.claims["iat"] = now.Add(-2 * time.Hour).Unix()
				})
			},
			want: []error{oidc.ErrTokenExpired},
		},
		{
			name: "missing exp",
			mutate: func(f *oidcFixture) {
				f.set(func(c *oidcFixtureConfig) { c.claims["exp"] = nil })
			},
			want: []error{oidc.ErrInvalidToken},
		},
		{
			name: "missing iat",
			mutate: func(f *oidcFixture) {
				f.set(func(c *oidcFixtureConfig) { c.claims["iat"] = nil })
			},
			want: []error{oidc.ErrInvalidToken},
		},
		{
			name: "missing subject",
			mutate: func(f *oidcFixture) {
				f.set(func(c *oidcFixtureConfig) { c.claims["sub"] = nil })
			},
			want: []error{oidc.ErrInvalidToken},
		},
		{
			name: "bad signature",
			mutate: func(f *oidcFixture) {
				f.set(func(c *oidcFixtureConfig) { c.signKey = rogue })
			},
			want: []error{jose.ErrSignatureInvalid},
		},
		{
			name: "wrong key family",
			mutate: func(f *oidcFixture) {
				f.set(func(c *oidcFixtureConfig) {
					c.idTokenRaw = craftCompactJWS(t, wrongFamilyHeader, wrongFamilyClaims)
				})
			},
			want:    []error{jose.ErrKeyTypeMismatch},
			notWant: []error{jose.ErrSignatureInvalid},
		},
		{
			name:     "algorithm not advertised",
			discover: true,
			mutate: func(f *oidcFixture) {
				f.set(func(c *oidcFixtureConfig) { c.discoveryAlgs = []string{"ES256"} })
			},
			want: []error{jose.ErrAlgNotAllowed},
			after: func(t *testing.T, f *oidcFixture) {
				if _, jwksCalls, _, _ := f.counts(); jwksCalls != 0 {
					t.Fatalf("JWKS fetched %d times before the alg check | 算法检查前获取 JWKS %d 次", jwksCalls, jwksCalls)
				}
			},
		},
		{
			name: "malformed token",
			mutate: func(f *oidcFixture) {
				f.set(func(c *oidcFixtureConfig) { c.idTokenRaw = "not-a-jwt" })
			},
			want: []error{jose.ErrMalformed},
		},
		{
			name: "missing id token",
			mutate: func(f *oidcFixture) {
				f.set(func(c *oidcFixtureConfig) { c.includeIDToken = false })
			},
			wantMessage: []string{"no ID token"},
		},
		{
			name: "at_hash mismatch",
			mutate: func(f *oidcFixture) {
				f.set(func(c *oidcFixtureConfig) { c.claims["at_hash"] = "AAAAAAAAAAAAAAAAAAAAAA" })
			},
			want: []error{oidc.ErrInvalidAtHash},
		},
		{
			name: "at_hash missing",
			mutate: func(f *oidcFixture) {
				f.set(func(c *oidcFixtureConfig) { c.claims["at_hash"] = nil })
			},
			want: []error{oidc.ErrInvalidAtHash},
		},
		{
			name: "jwks status failure",
			mutate: func(f *oidcFixture) {
				f.set(func(c *oidcFixtureConfig) {
					c.jwksStatus = http.StatusInternalServerError
					c.jwksBody = []byte(`{"error":"jwks_secret"}`)
				})
			},
			want: []error{jose.ErrFetchFailed},
		},
		{
			name: "malformed jwks",
			mutate: func(f *oidcFixture) {
				f.set(func(c *oidcFixtureConfig) { c.jwksBody = []byte(`{"keys":`) })
			},
			want: []error{jose.ErrFetchFailed},
		},
		{
			name: "unknown kid",
			mutate: func(f *oidcFixture) {
				f.set(func(c *oidcFixtureConfig) { c.signKid = "rsa-unknown" })
			},
			want: []error{jose.ErrKeyNotFound},
			after: func(t *testing.T, f *oidcFixture) {
				if _, jwksCalls, _, _ := f.counts(); jwksCalls != 2 {
					t.Fatalf("JWKS calls = %d want 2 (initial + forced refresh) | JWKS 调用 = %d 期望 2（首次 + 强制刷新）", jwksCalls, jwksCalls)
				}
			},
		},
		{
			name: "token endpoint json error",
			mutate: func(f *oidcFixture) {
				f.set(func(c *oidcFixtureConfig) {
					c.tokenStatus = http.StatusBadRequest
					c.tokenBody = []byte(`{"error":"invalid_grant","error_description":"super-secret-description"}`)
				})
			},
			wantMessage: []string{"invalid_grant", "HTTP 400"},
		},
		{
			name: "token endpoint form error",
			mutate: func(f *oidcFixture) {
				f.set(func(c *oidcFixtureConfig) {
					c.tokenStatus = http.StatusBadRequest
					c.tokenBody = []byte("error=invalid_grant&error_description=super-secret-description")
				})
			},
			wantMessage: []string{"invalid_grant", "HTTP 400"},
		},
		{
			name: "token endpoint without code",
			mutate: func(f *oidcFixture) {
				f.set(func(c *oidcFixtureConfig) {
					c.tokenStatus = http.StatusServiceUnavailable
					c.tokenBody = []byte("   ")
				})
			},
			wantMessage: []string{"token endpoint returned HTTP 503"},
		},
		{
			name: "empty token response",
			mutate: func(f *oidcFixture) {
				f.set(func(c *oidcFixtureConfig) { c.tokenBody = []byte(" ") })
			},
			wantMessage: []string{"empty token response"},
		},
		{
			name: "invalid token response",
			mutate: func(f *oidcFixture) {
				f.set(func(c *oidcFixtureConfig) { c.tokenBody = []byte("{") })
			},
			wantMessage: []string{"invalid token response"},
		},
		{
			name: "missing access token",
			mutate: func(f *oidcFixture) {
				f.set(func(c *oidcFixtureConfig) { c.tokenBody = []byte(`{"token_type":"Bearer"}`) })
			},
			wantMessage: []string{"no access token"},
		},
		{
			name: "nested provider error",
			mutate: func(f *oidcFixture) {
				f.set(func(c *oidcFixtureConfig) {
					c.tokenBody = []byte(`{"data":{"error":"nested_error"}}`)
				})
			},
			wantMessage: []string{"nested_error"},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) { runOIDCFailureCase(t, tc) })
	}
}

// TestOIDCDiscoveryFailures verifies discovery rejection and sanitization. | TestOIDCDiscoveryFailures
// 校验发现文档拒绝与脱敏。
func TestOIDCDiscoveryFailures(t *testing.T) {
	t.Run("http status", func(t *testing.T) {
		fixture := newOIDCFixture(t)
		fixture.set(func(c *oidcFixtureConfig) {
			c.discoveryStatus = http.StatusBadGateway
			c.discoveryBody = []byte(`{"error":"discovery_secret"}`)
		})
		adapter := newAdapter(fixture.discoveryProvider("oidc"), nil)
		_, err := adapter.Exchange(context.Background(), "code", "")
		assertErrorIs(t, err, ErrProviderConfig, oidc.ErrDiscoveryFailed)
		assertNoSecrets(t, err)
	})

	t.Run("malformed document", func(t *testing.T) {
		fixture := newOIDCFixture(t)
		fixture.set(func(c *oidcFixtureConfig) { c.discoveryBody = []byte(`{"issuer":`) })
		adapter := newAdapter(fixture.discoveryProvider("oidc"), nil)
		_, err := adapter.Exchange(context.Background(), "code", "")
		assertErrorIs(t, err, ErrProviderConfig, oidc.ErrDiscoveryFailed)
		assertNoSecrets(t, err)
	})

	t.Run("issuer mismatch", func(t *testing.T) {
		fixture := newOIDCFixture(t)
		fixture.set(func(c *oidcFixtureConfig) { c.discoveryIssuer = "https://other-issuer.example" })
		adapter := newAdapter(fixture.discoveryProvider("oidc"), nil)
		_, err := adapter.Exchange(context.Background(), "code", "")
		assertErrorIs(t, err, ErrProviderConfig, oidc.ErrInvalidIssuer)
		assertNoSecrets(t, err)
	})

	t.Run("missing endpoints", func(t *testing.T) {
		fixture := newOIDCFixture(t)
		fixture.set(func(c *oidcFixtureConfig) { c.omitDiscoveryEndpoints = true })
		adapter := newAdapter(fixture.discoveryProvider("oidc"), nil)
		_, err := adapter.Exchange(context.Background(), "code", "")
		assertErrorIs(t, err, ErrProviderConfig)
		assertErrorMentions(t, err, "authorization or token endpoint")
		assertNoSecrets(t, err)
	})

	t.Run("missing jwks uri", func(t *testing.T) {
		fixture := newOIDCFixture(t)
		fixture.set(func(c *oidcFixtureConfig) { c.omitJWKS = true })
		adapter := newAdapter(fixture.discoveryProvider("oidc"), nil)
		_, err := adapter.Exchange(context.Background(), "code", "")
		assertErrorIs(t, err, ErrTokenExchange, oidc.ErrInvalidConfig)
		assertErrorMentions(t, err, "no JWKS URI")
		assertNoSecrets(t, err)
	})

	t.Run("missing issuer for discovery", func(t *testing.T) {
		fixture := newOIDCFixture(t)
		p := NewProvider(ProviderConfig{
			Name:       "oidc",
			ClientID:   oidcFixtureClientID,
			UseOIDC:    true,
			HTTPClient: fixture.server.Client(),
		})
		adapter := newAdapter(p, nil)
		_, err := adapter.Exchange(context.Background(), "code", "")
		assertErrorIs(t, err, ErrProviderConfig)
		assertErrorMentions(t, err, "needs an issuer")
		assertNoSecrets(t, err)
		if discoveryCalls, _, _, _ := fixture.counts(); discoveryCalls != 0 {
			t.Fatalf("discovery attempted without an issuer %d times | 无 issuer 时尝试发现 %d 次", discoveryCalls, discoveryCalls)
		}
	})

	t.Run("unreachable issuer", func(t *testing.T) {
		fixture := newOIDCFixture(t)
		closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		closedURL := closed.URL
		closed.Close()
		p := fixture.discoveryProvider("oidc")
		p.Issuer = closedURL
		adapter := newAdapter(p, nil)
		_, err := adapter.Exchange(context.Background(), "code", "")
		assertErrorIs(t, err, ErrProviderConfig, oidc.ErrDiscoveryFailed)
		// The issuer URL is provider metadata, not a secret, so it may appear. | issuer URL
		// 是提供方元数据而非密钥，因此可以出现。
		assertNoSecrets(t, err)
	})

	t.Run("cannot verify without jwks or issuer", func(t *testing.T) {
		fixture := newOIDCFixture(t)
		p := fixture.provider("oidc")
		p.Issuer = ""
		adapter := newAdapter(p, nil)
		_, err := adapter.Exchange(context.Background(), "code", "")
		assertErrorIs(t, err, ErrTokenExchange)
		assertErrorMentions(t, err, "cannot verify ID tokens without a JWKS")
		assertNoSecrets(t, err)
		if _, jwksCalls, _, _ := fixture.counts(); jwksCalls != 0 {
			t.Fatalf("JWKS fetched %d times without an issuer | 无 issuer 时获取 JWKS %d 次", jwksCalls, jwksCalls)
		}
	})
}

// TestOIDCKeyRotation verifies the forced JWKS refresh on an unknown kid. | TestOIDCKeyRotation
// 校验未知 kid 触发的 JWKS 强制刷新。
func TestOIDCKeyRotation(t *testing.T) {
	fixture := newOIDCFixture(t)
	primary, rotated, _, _ := sharedOIDCKeys(t)
	adapter := newAdapter(fixture.provider("oidc"), nil)

	if _, err := adapter.Exchange(context.Background(), "code", ""); err != nil {
		t.Fatalf("initial Exchange: %v", err)
	}
	if _, jwksCalls, _, _ := fixture.counts(); jwksCalls != 1 {
		t.Fatalf("JWKS calls after initial exchange = %d want 1 | 初次兑换后 JWKS 调用 = %d 期望 1", jwksCalls, jwksCalls)
	}

	fixture.set(func(c *oidcFixtureConfig) {
		c.keys = []*jose.Key{publicJWK(primary, "rsa-1"), publicJWK(rotated, "rsa-2")}
		c.signKey = rotated
		c.signKid = "rsa-2"
	})

	token, err := adapter.Exchange(context.Background(), "code", "")
	if err != nil {
		t.Fatalf("rotated Exchange: %v", err)
	}
	if token.AccessToken != oidcFixtureAccessToken || token.Claims["sub"] != "oidc-subject" {
		t.Fatalf("rotated token not verified: %+v | 轮换后的令牌未校验：%+v", token, token)
	}
	if _, jwksCalls, _, _ := fixture.counts(); jwksCalls != 2 {
		t.Fatalf("JWKS calls after rotation = %d want 2 | 轮换后 JWKS 调用 = %d 期望 2", jwksCalls, jwksCalls)
	}
}
