package federation

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth/protocol/oauth2"
	"github.com/shibingli/ydx/auth/protocol/oidc"
)

// TestSameIDTokenMetadata verifies comparison of discovery verification metadata. |
// TestSameIDTokenMetadata 校验发现校验元数据的比较。
func TestSameIDTokenMetadata(t *testing.T) {
	left := &oidc.DiscoveryDocument{
		ServerMetadata:                   &oauth2.ServerMetadata{Issuer: "https://issuer", JWKSURI: "https://issuer/jwks"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
	}
	right := &oidc.DiscoveryDocument{
		ServerMetadata:                   &oauth2.ServerMetadata{Issuer: "https://issuer", JWKSURI: "https://issuer/jwks"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
	}
	if !sameIDTokenMetadata(left, right) {
		t.Fatal("identical metadata should compare equal | 相同元数据应相等")
	}
	right.IDTokenSigningAlgValuesSupported = []string{"ES256"}
	if sameIDTokenMetadata(left, right) {
		t.Fatal("changed algorithms should compare unequal | 算法变化应不相等")
	}
	if sameIDTokenMetadata(nil, left) {
		t.Fatal("nil left document should compare unequal | 左文档为空应不相等")
	}
	if !sameIDTokenMetadata(nil, nil) {
		t.Fatal("two nil documents should compare equal | 两个空文档应相等")
	}
	if !sameIDTokenMetadata(&oidc.DiscoveryDocument{}, &oidc.DiscoveryDocument{}) {
		t.Fatal("two missing server metadata should compare equal | 两个缺少服务元数据的文档应相等")
	}
	if sameIDTokenMetadata(&oidc.DiscoveryDocument{}, left) {
		t.Fatal("missing server metadata should compare unequal | 缺少服务元数据应不相等")
	}
}

// TestDiscoveryPolicyMerge verifies provider overrides and nil handling. |
// TestDiscoveryPolicyMerge 校验提供方覆盖与空值处理。
func TestDiscoveryPolicyMerge(t *testing.T) {
	if policy := discoveryPolicyFor(nil, nil); policy.enabled() || policy.nextTTL() != 0 {
		t.Fatalf("nil merge = %+v | 空合并 = %+v", policy, policy)
	}
	provider := &Provider{DiscoveryTTLMax: 2 * time.Minute, DiscoveryJitter: 0.25}
	policy := discoveryPolicyFor(nil, provider)
	if policy.maxTTL != 2*time.Minute || policy.jitter != 0.25 {
		t.Fatalf("provider override = %+v | 提供方覆盖 = %+v", policy, policy)
	}
}

// TestNewAdapterVariants verifies nil, custom adapter and default clock handling. |
// TestNewAdapterVariants 校验空值、自定义适配器与默认时钟处理。
func TestNewAdapterVariants(t *testing.T) {
	if adapter := newAdapterWithPolicy(nil, nil, discoveryPolicy{}, nil); adapter != nil {
		t.Fatalf("nil provider adapter = %v | 空提供方适配器 = %v", adapter, adapter)
	}
	custom := &testAdapter{}
	if adapter := newAdapterWithPolicy(&Provider{Name: "p", Adapter: custom}, nil, discoveryPolicy{}, nil); adapter != custom {
		t.Fatalf("custom adapter = %v, want %v | 自定义适配器 = %v，期望 %v", adapter, custom, adapter, custom)
	}
	provider := &Provider{Name: "p", ClientID: "c", AuthURL: "https://auth", TokenURL: "https://token"}
	builtin, ok := newAdapterWithPolicy(provider, nil, discoveryPolicy{}, nil).(*oauthAdapter)
	if !ok {
		t.Fatalf("built-in adapter type mismatch | 内置适配器类型不匹配")
	}
	if builtin.now == nil {
		t.Fatal("default clock is nil | 默认时钟为空")
	}
}

// TestDiscoveryFailureStaleBound verifies the negative staleness branch and disabled
// fallback. | TestDiscoveryFailureStaleBound 校验负过期差分支与禁用回退。
func TestDiscoveryFailureStaleBound(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	adapter := &oauthAdapter{
		discovery:          &oidc.DiscoveryDocument{},
		discoveryExpiresAt: now.Add(time.Minute),
		policy:             discoveryPolicy{ttl: time.Minute},
	}
	cause := errors.New("refresh failed")
	if err := adapter.discoveryFailureLocked(cause, now); err != nil {
		t.Fatalf("fallback before expiry = %v | 到期前回退 = %v", err, err)
	}
	adapter.policy.maxStale = -time.Second
	if err := adapter.discoveryFailureLocked(cause, now); !errors.Is(err, ErrProviderConfig) {
		t.Fatalf("disabled fallback err = %v | 禁用回退错误 = %v", err, err)
	}
	adapter.policy.maxStale = 0
	adapter.discoveryExpiresAt = now.Add(-time.Hour)
	if err := adapter.discoveryFailureLocked(cause, now); !errors.Is(err, ErrProviderConfig) {
		t.Fatalf("too stale err = %v | 过度过期错误 = %v", err, err)
	}
	adapter.discovery = nil
	if err := adapter.discoveryFailureLocked(cause, now); !errors.Is(err, ErrProviderConfig) {
		t.Fatalf("no cache err = %v | 无缓存错误 = %v", err, err)
	}
}

// TestVerifyIDTokenFailureBranches verifies discovery and relying-party errors are
// classified as token exchange failures. | TestVerifyIDTokenFailureBranches 校验发现与
// 依赖方错误被归类为令牌兑换失败。
func TestVerifyIDTokenFailureBranches(t *testing.T) {
	withoutJWKS := &Provider{Name: "no-jwks", UseOIDC: true, AuthURL: "https://auth", TokenURL: "https://token"}
	adapter := &oauthAdapter{
		provider: withoutJWKS,
		client:   http.DefaultClient,
		now:      time.Now,
		authURL:  withoutJWKS.AuthURL,
		tokenURL: withoutJWKS.TokenURL,
	}
	err := adapter.verifyIDToken(context.Background(), &Token{IDToken: "token"})
	assertErrorIs(t, err, ErrTokenExchange)

	withoutClientID := &Provider{
		Name:     "no-client",
		UseOIDC:  true,
		AuthURL:  "https://auth",
		TokenURL: "https://token",
		JWKSURL:  "https://issuer/jwks",
		Issuer:   "https://issuer",
	}
	adapter = &oauthAdapter{
		provider: withoutClientID,
		client:   http.DefaultClient,
		now:      time.Now,
		authURL:  withoutClientID.AuthURL,
		tokenURL: withoutClientID.TokenURL,
		jwksURL:  withoutClientID.JWKSURL,
		issuer:   withoutClientID.Issuer,
	}
	err = adapter.verifyIDToken(context.Background(), &Token{IDToken: "token"})
	assertErrorIs(t, err, ErrTokenExchange)
}

// TestDiscoveryRefreshInvalidatesRelyingParty verifies that a signing algorithm change
// rebuilds the relying party and refreshes JWKS before the next token check. |
// TestDiscoveryRefreshInvalidatesRelyingParty 校验签名算法变化会重建依赖方，并在下次
// 令牌校验前刷新 JWKS。
func TestDiscoveryRefreshInvalidatesRelyingParty(t *testing.T) {
	fixture := newOIDCFixture(t)
	clock := newTestDiscoveryClock()
	provider := fixture.discoveryProvider("rp-change")
	provider.DiscoveryTTL = time.Minute
	adapter := newAdapterWithPolicy(provider, nil, discoveryPolicyFor(nil, provider), clock.Now).(*oauthAdapter)

	if _, err := adapter.AuthCodeURL("state", "nonce", ""); err != nil {
		t.Fatalf("initial AuthCodeURL: %v | 首次 AuthCodeURL：%v", err, err)
	}
	if _, err := adapter.Exchange(context.Background(), "code-1", ""); err != nil {
		t.Fatalf("first Exchange: %v | 首次 Exchange：%v", err, err)
	}
	_, jwksBefore, _, _ := fixture.counts()
	fixture.set(func(c *oidcFixtureConfig) {
		c.discoveryAlgs = []string{"RS256"}
	})
	clock.Advance(2 * time.Minute)
	if _, err := adapter.Exchange(context.Background(), "code-2", ""); err != nil {
		t.Fatalf("second Exchange: %v | 第二次 Exchange：%v", err, err)
	}
	discovery, jwksAfter, _, _ := fixture.counts()
	if discovery != 2 {
		t.Fatalf("discovery calls = %d, want 2 | 发现调用 = %d，期望 2", discovery, discovery)
	}
	if jwksAfter != jwksBefore+1 {
		t.Fatalf("JWKS calls = %d, want %d | JWKS 调用 = %d，期望 %d", jwksAfter, jwksBefore+1, jwksAfter, jwksBefore+1)
	}
}

// TestBrokerNilHelpers verifies nil-safe broker helpers and identity conversion. |
// TestBrokerNilHelpers 校验空值安全的代理辅助函数与身份转换。
func TestBrokerNilHelpers(t *testing.T) {
	var broker *Broker
	if broker.now().IsZero() {
		t.Fatal("nil broker clock returned zero | 空代理时钟返回零值")
	}
	if broker.stateTTL() != DefaultStateTTL {
		t.Fatalf("nil broker state TTL = %s | 空代理 state TTL = %s", broker.stateTTL(), broker.stateTTL())
	}
	if identity := toAuthIdentity(nil); identity != nil {
		t.Fatalf("nil identity = %+v | 空身份 = %+v", identity, identity)
	}
	if _, err := callbackValues(nil, nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil callback err = %v | 空回调错误 = %v", err, err)
	}
}
