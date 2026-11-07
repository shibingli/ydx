package federation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// exchangeFixtureToken performs one verified exchange for UserInfo tests. | exchangeFixtureToken
// 为 UserInfo 测试执行一次已校验的兑换。
func exchangeFixtureToken(t *testing.T, fixture *oidcFixture, adapter ProviderAdapter) *Token {
	t.Helper()
	token, err := adapter.Exchange(context.Background(), "authorization-code", "")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	return token
}

// TestOIDCUserInfoFromClaims verifies the verified-claims fallback when no endpoint exists.
// TestOIDCUserInfoFromClaims 校验没有端点时回退到已校验声明。
func TestOIDCUserInfoFromClaims(t *testing.T) {
	fixture := newOIDCFixture(t)
	p := fixture.provider("oidc")
	p.UserInfoURL = ""
	adapter := newAdapter(p, nil)
	token := exchangeFixtureToken(t, fixture, adapter)

	identity, err := adapter.UserInfo(context.Background(), token)
	if err != nil {
		t.Fatalf("UserInfo: %v", err)
	}
	if identity.Subject != "oidc-subject" || identity.Email != "oidc@example.com" || !identity.EmailVerified {
		t.Fatalf("claims identity not mapped: %+v | 声明身份未映射：%+v", identity, identity)
	}
	if identity.Username != "oidc-user" || identity.Name != "OIDC Subject" {
		t.Fatalf("claims username/name = %q/%q | 声明用户名/名称 = %q/%q", identity.Username, identity.Name, identity.Username, identity.Name)
	}
	if _, _, _, userInfoCalls := fixture.counts(); userInfoCalls != 0 {
		t.Fatalf("claims fallback contacted UserInfo %d times | 声明回退访问 UserInfo %d 次", userInfoCalls, userInfoCalls)
	}

	token.Claims = map[string]string{"email": "no-subject@example.com"}
	_, err = adapter.UserInfo(context.Background(), token)
	assertErrorIs(t, err, ErrUserInfo)
	assertErrorMentions(t, err, "no user info endpoint or claims")
	assertNoSecrets(t, err)
}

// TestOIDCUserInfoFailures verifies UserInfo rejection paths and secret hygiene. | TestOIDCUserInfoFailures
// 校验 UserInfo 拒绝路径与密钥卫生。
func TestOIDCUserInfoFailures(t *testing.T) {
	t.Run("nil token", func(t *testing.T) {
		fixture := newOIDCFixture(t)
		adapter := newAdapter(fixture.provider("oidc"), nil)
		_, err := adapter.UserInfo(context.Background(), nil)
		assertErrorIs(t, err, ErrUserInfo)
	})

	t.Run("http status", func(t *testing.T) {
		fixture := newOIDCFixture(t)
		adapter := newAdapter(fixture.provider("oidc"), nil)
		token := exchangeFixtureToken(t, fixture, adapter)
		fixture.set(func(c *oidcFixtureConfig) {
			c.userInfoStatus = http.StatusInternalServerError
			c.userInfoBody = `{"error":"userinfo_secret"}`
		})
		_, err := adapter.UserInfo(context.Background(), token)
		assertErrorIs(t, err, ErrUserInfo)
		assertErrorMentions(t, err, "HTTP 500")
		assertNoSecrets(t, err, "userinfo_secret")
	})

	t.Run("provider error", func(t *testing.T) {
		fixture := newOIDCFixture(t)
		adapter := newAdapter(fixture.provider("oidc"), nil)
		token := exchangeFixtureToken(t, fixture, adapter)
		fixture.set(func(c *oidcFixtureConfig) {
			c.userInfoBody = `{"error":"invalid_token","error_description":"super-secret-description"}`
		})
		_, err := adapter.UserInfo(context.Background(), token)
		assertErrorIs(t, err, ErrUserInfo)
		assertErrorMentions(t, err, "invalid_token")
		assertNoSecrets(t, err)
	})

	t.Run("numeric provider error", func(t *testing.T) {
		fixture := newOIDCFixture(t)
		adapter := newAdapter(fixture.provider("oidc"), nil)
		token := exchangeFixtureToken(t, fixture, adapter)
		fixture.set(func(c *oidcFixtureConfig) {
			c.userInfoBody = `{"errcode":40001,"errmsg":"userinfo_secret"}`
		})
		_, err := adapter.UserInfo(context.Background(), token)
		assertErrorIs(t, err, ErrUserInfo)
		assertErrorMentions(t, err, "40001")
		assertNoSecrets(t, err, "userinfo_secret")
	})

	t.Run("invalid json", func(t *testing.T) {
		fixture := newOIDCFixture(t)
		adapter := newAdapter(fixture.provider("oidc"), nil)
		token := exchangeFixtureToken(t, fixture, adapter)
		fixture.set(func(c *oidcFixtureConfig) { c.userInfoBody = "{" })
		_, err := adapter.UserInfo(context.Background(), token)
		assertErrorIs(t, err, ErrUserInfo)
		assertErrorMentions(t, err, "invalid")
		assertNoSecrets(t, err)
	})

	t.Run("missing subject", func(t *testing.T) {
		fixture := newOIDCFixture(t)
		adapter := newAdapter(fixture.provider("oidc"), nil)
		token := exchangeFixtureToken(t, fixture, adapter)
		token.Claims = nil
		fixture.set(func(c *oidcFixtureConfig) { c.userInfoBody = `{"name":"No Subject"}` })
		_, err := adapter.UserInfo(context.Background(), token)
		assertErrorIs(t, err, ErrUserInfo)
		assertErrorMentions(t, err, "no subject")
		assertNoSecrets(t, err)
	})

	t.Run("resolve failure", func(t *testing.T) {
		fixture := newOIDCFixture(t)
		p := NewProvider(ProviderConfig{
			Name:        "oidc",
			ClientID:    oidcFixtureClientID,
			UserInfoURL: fixture.server.URL + "/userinfo",
			HTTPClient:  fixture.server.Client(),
		})
		adapter := newAdapter(p, nil)
		_, err := adapter.UserInfo(context.Background(), &Token{AccessToken: "access"})
		assertErrorIs(t, err, ErrUserInfo, ErrProviderConfig)
		assertNoSecrets(t, err)
	})

	t.Run("transport failure", func(t *testing.T) {
		fixture := newOIDCFixture(t)
		closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		closedURL := closed.URL
		closed.Close()
		p := NewProvider(ProviderConfig{
			Name:        "oidc",
			ClientID:    oidcFixtureClientID,
			AuthURL:     fixture.server.URL + "/authorize",
			TokenURL:    fixture.server.URL + "/token",
			UserInfoURL: closedURL + "/userinfo",
			HTTPClient:  fixture.server.Client(),
		})
		adapter := newAdapter(p, nil)
		_, err := adapter.UserInfo(context.Background(), &Token{AccessToken: "transport-access-token"})
		assertErrorIs(t, err, ErrUserInfo, ErrTransport)
		assertNoSecrets(t, err)
		if err != nil && strings.Contains(err.Error(), closedURL) {
			t.Fatalf("UserInfo transport error exposes the endpoint: %q | UserInfo 传输错误暴露端点：%q", err, err)
		}
	})

	t.Run("hook short circuit", func(t *testing.T) {
		fixture := newOIDCFixture(t)
		p := fixture.provider("oidc")
		p.UserInfoHook = func(_ context.Context, provider *Provider, _ *http.Client, token *Token) (*Identity, error) {
			return &Identity{Provider: provider.Name, Subject: "hook-subject", Email: "hook@example.com", Raw: map[string]string{"access": token.AccessToken}}, nil
		}
		adapter := newAdapter(p, nil)
		identity, err := adapter.UserInfo(context.Background(), &Token{AccessToken: "hook-access"})
		if err != nil {
			t.Fatalf("UserInfo: %v", err)
		}
		if identity.Subject != "hook-subject" || identity.Raw["access"] != "hook-access" {
			t.Fatalf("hook identity = %+v | 钩子身份 = %+v", identity, identity)
		}
		if _, _, _, userInfoCalls := fixture.counts(); userInfoCalls != 0 {
			t.Fatalf("UserInfo hook contacted the fixture %d times | UserInfo 钩子访问 fixture %d 次", userInfoCalls, userInfoCalls)
		}
	})
}

// TestOIDCUserInfoSubjectBinding verifies OpenID Connect Core 5.3.2 subject equality.
// TestOIDCUserInfoSubjectBinding 校验 OpenID Connect Core 5.3.2 的主体一致性。
func TestOIDCUserInfoSubjectBinding(t *testing.T) {
	prepare := func(t *testing.T, body string) (ProviderAdapter, *Token) {
		t.Helper()
		fixture := newOIDCFixture(t)
		adapter := newAdapter(fixture.provider("oidc"), nil)
		token := exchangeFixtureToken(t, fixture, adapter)
		fixture.set(func(c *oidcFixtureConfig) { c.userInfoBody = body })
		return adapter, token
	}

	t.Run("matching subject", func(t *testing.T) {
		adapter, token := prepare(t, `{"sub":"oidc-subject","email":"bound@example.com"}`)
		identity, err := adapter.UserInfo(context.Background(), token)
		if err != nil {
			t.Fatalf("UserInfo: %v", err)
		}
		if identity.Subject != token.Claims["sub"] || identity.Email != "bound@example.com" {
			t.Fatalf("bound identity = %+v | 绑定身份 = %+v", identity, identity)
		}
	})

	t.Run("mismatched subject", func(t *testing.T) {
		adapter, token := prepare(t, `{"sub":"attacker-subject","email":"attacker@example.com"}`)
		_, err := adapter.UserInfo(context.Background(), token)
		assertErrorIs(t, err, ErrUserInfo)
		assertErrorMentions(t, err, "does not match")
		assertNoSecrets(t, err, token.IDToken, "attacker-subject", "oidc-subject")
	})

	t.Run("missing userinfo subject", func(t *testing.T) {
		adapter, token := prepare(t, `{"email":"fallback@example.com","name":"Fallback"}`)
		identity, err := adapter.UserInfo(context.Background(), token)
		if err != nil {
			t.Fatalf("UserInfo: %v", err)
		}
		if identity.Subject != "oidc-subject" || identity.Email != "fallback@example.com" {
			t.Fatalf("fallback identity = %+v | 回退身份 = %+v", identity, identity)
		}
	})
}
