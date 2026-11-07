package federation

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth/protocol/oidc"
)

// testDiscoveryClock is a manually advanced clock for discovery refresh tests. |
// testDiscoveryClock 是用于发现刷新测试的手动推进时钟。
type testDiscoveryClock struct {
	mu  sync.Mutex
	now time.Time
}

// newTestDiscoveryClock returns a clock fixed at a deterministic instant. | newTestDiscoveryClock
// 返回固定在确定时刻的时钟。
func newTestDiscoveryClock() *testDiscoveryClock {
	return &testDiscoveryClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

// Now returns the current test time. | Now 返回当前测试时间。
func (c *testDiscoveryClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the test clock forward. | Advance 向前推进测试时钟。
func (c *testDiscoveryClock) Advance(delta time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(delta)
	c.mu.Unlock()
}

// TestDiscoveryRefreshExpiryAndEndpointChange verifies TTL expiry, endpoint rotation and
// preservation of the JWKS cache across endpoint-only discovery changes. |
// TestDiscoveryRefreshExpiryAndEndpointChange 校验 TTL 过期、端点轮换以及仅端点变化时
// JWKS 缓存的保留。
func TestDiscoveryRefreshExpiryAndEndpointChange(t *testing.T) {
	fixture := newOIDCFixture(t)
	clock := newTestDiscoveryClock()
	provider := fixture.discoveryProvider("refresh")
	provider.DiscoveryTTL = 10 * time.Minute
	adapter := newAdapterWithPolicy(provider, nil, discoveryPolicyFor(nil, provider), clock.Now).(*oauthAdapter)

	first, err := adapter.AuthCodeURL("state-1", "nonce-1", "")
	if err != nil {
		t.Fatalf("initial AuthCodeURL: %v | 首次 AuthCodeURL：%v", err, err)
	}
	if discovery, _, _, _ := fixture.counts(); discovery != 1 {
		t.Fatalf("discovery calls = %d, want 1 | 发现调用 = %d，期望 1", discovery, discovery)
	}

	clock.Advance(9 * time.Minute)
	second, err := adapter.AuthCodeURL("state-1", "nonce-1", "")
	if err != nil {
		t.Fatalf("cached AuthCodeURL: %v | 缓存 AuthCodeURL：%v", err, err)
	}
	if second != first {
		t.Fatalf("cached URL changed: %q != %q | 缓存 URL 变化：%q != %q", second, first, second, first)
	}
	if discovery, _, _, _ := fixture.counts(); discovery != 1 {
		t.Fatalf("discovery calls before expiry = %d, want 1 | 过期前发现调用 = %d，期望 1", discovery, discovery)
	}

	fixture.set(func(c *oidcFixtureConfig) {
		c.discoveryAuthURL = fixture.server.URL + "/authorize-v2"
		c.discoveryTokenURL = fixture.server.URL + "/token-v2"
	})
	clock.Advance(2 * time.Minute)
	third, err := adapter.AuthCodeURL("state-1", "nonce-1", "")
	if err != nil {
		t.Fatalf("refreshed AuthCodeURL: %v | 刷新后 AuthCodeURL：%v", err, err)
	}
	if !strings.Contains(third, "/authorize-v2") {
		t.Fatalf("refreshed URL = %q, want rotated authorization endpoint | 刷新 URL = %q，期望轮换后的授权端点", third, third)
	}
	if discovery, _, _, _ := fixture.counts(); discovery != 2 {
		t.Fatalf("discovery calls after expiry = %d, want 2 | 过期后发现调用 = %d，期望 2", discovery, discovery)
	}

	token, err := adapter.Exchange(context.Background(), "code-1", "")
	if err != nil {
		t.Fatalf("Exchange after endpoint rotation: %v | 端点轮换后 Exchange：%v", err, err)
	}
	if token.AccessToken != oidcFixtureAccessToken {
		t.Fatalf("access token = %q | 访问令牌 = %q", token.AccessToken, token.AccessToken)
	}
	form, _ := fixture.lastTokenRequest()
	if form.Get("code") != "code-1" {
		t.Fatalf("token request code = %q, want code-1 | 令牌请求 code = %q，期望 code-1", form.Get("code"), form.Get("code"))
	}
	if discovery, jwks, _, _ := fixture.counts(); discovery != 2 || jwks != 1 {
		t.Fatalf("after exchange discovery=%d jwks=%d, want 2/1 | 兑换后 discovery=%d jwks=%d，期望 2/1", discovery, jwks, discovery, jwks)
	}

	clock.Advance(11 * time.Minute)
	if _, err := adapter.Exchange(context.Background(), "code-2", ""); err != nil {
		t.Fatalf("Exchange after second expiry: %v | 第二次过期后 Exchange：%v", err, err)
	}
	if discovery, jwks, tokenCalls, _ := fixture.counts(); discovery != 3 || jwks != 1 || tokenCalls != 2 {
		t.Fatalf("second refresh discovery=%d jwks=%d token=%d, want 3/1/2 | 第二次刷新 discovery=%d jwks=%d token=%d，期望 3/1/2", discovery, jwks, tokenCalls, discovery, jwks, tokenCalls)
	}
}

// TestDiscoveryRefreshSingleFlight verifies concurrent callers share one refresh. |
// TestDiscoveryRefreshSingleFlight 校验并发调用方共享一次刷新。
func TestDiscoveryRefreshSingleFlight(t *testing.T) {
	fixture := newOIDCFixture(t)
	fixture.set(func(c *oidcFixtureConfig) { c.discoveryDelay = 150 * time.Millisecond })
	clock := newTestDiscoveryClock()
	provider := fixture.discoveryProvider("single-flight")
	provider.DiscoveryTTL = time.Hour
	adapter := newAdapterWithPolicy(provider, nil, discoveryPolicyFor(nil, provider), clock.Now).(*oauthAdapter)

	if _, err := adapter.AuthCodeURL("state", "nonce", ""); err != nil {
		t.Fatalf("initial AuthCodeURL: %v | 首次 AuthCodeURL：%v", err, err)
	}
	clock.Advance(2 * time.Hour)

	const callers = 8
	start := make(chan struct{})
	results := make(chan error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := adapter.AuthCodeURL("state", "nonce", "")
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("concurrent AuthCodeURL: %v | 并发 AuthCodeURL：%v", err, err)
		}
	}
	if discovery, _, _, _ := fixture.counts(); discovery != 2 {
		t.Fatalf("discovery calls = %d, want 2 (initial + one refresh) | 发现调用 = %d，期望 2（首次 + 一次刷新）", discovery, discovery)
	}
}

// TestDiscoveryRefreshFailureSingleFlight verifies that waiters receive the leader's
// refresh failure and no extra network attempt is made. | TestDiscoveryRefreshFailureSingleFlight
// 校验等待方收到主导方的刷新失败，且不会产生额外网络请求。
func TestDiscoveryRefreshFailureSingleFlight(t *testing.T) {
	fixture := newOIDCFixture(t)
	clock := newTestDiscoveryClock()
	provider := fixture.discoveryProvider("failure-flight")
	provider.DiscoveryTTL = time.Hour
	provider.DiscoveryMaxStale = -time.Minute
	adapter := newAdapterWithPolicy(provider, nil, discoveryPolicyFor(nil, provider), clock.Now).(*oauthAdapter)

	if _, err := adapter.AuthCodeURL("state", "nonce", ""); err != nil {
		t.Fatalf("initial AuthCodeURL: %v | 首次 AuthCodeURL：%v", err, err)
	}
	fixture.set(func(c *oidcFixtureConfig) {
		c.discoveryStatus = 502
		c.discoveryDelay = 150 * time.Millisecond
	})
	clock.Advance(2 * time.Hour)

	const callers = 6
	start := make(chan struct{})
	results := make(chan error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := adapter.AuthCodeURL("state", "nonce", "")
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	for err := range results {
		assertErrorIs(t, err, ErrProviderConfig)
	}
	if discovery, _, _, _ := fixture.counts(); discovery != 2 {
		t.Fatalf("discovery calls = %d, want 2 (initial + one failed refresh) | 发现调用 = %d，期望 2（首次 + 一次失败刷新）", discovery, discovery)
	}
}

// TestDiscoveryStaleFallback verifies bounded stale-while-revalidate behavior. |
// TestDiscoveryStaleFallback 校验有界过期回退行为。
func TestDiscoveryStaleFallback(t *testing.T) {
	cases := []struct {
		name       string
		maxStale   time.Duration
		firstWait  time.Duration
		secondWait time.Duration
		okAfterTTL bool
	}{
		{"default one ttl", 0, 11 * time.Minute, 10 * time.Minute, true},
		{"explicit bound", 2 * time.Minute, 11 * time.Minute, 2 * time.Minute, true},
		{"disabled", -time.Second, 11 * time.Minute, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newOIDCFixture(t)
			clock := newTestDiscoveryClock()
			provider := fixture.discoveryProvider("stale")
			provider.DiscoveryTTL = 10 * time.Minute
			provider.DiscoveryMaxStale = tc.maxStale
			adapter := newAdapterWithPolicy(provider, nil, discoveryPolicyFor(nil, provider), clock.Now).(*oauthAdapter)

			cached, err := adapter.AuthCodeURL("state", "nonce", "")
			if err != nil {
				t.Fatalf("initial AuthCodeURL: %v | 首次 AuthCodeURL：%v", err, err)
			}
			fixture.set(func(c *oidcFixtureConfig) { c.discoveryStatus = 502 })

			clock.Advance(tc.firstWait)
			got, err := adapter.AuthCodeURL("state", "nonce", "")
			if tc.okAfterTTL {
				if err != nil {
					t.Fatalf("stale fallback AuthCodeURL: %v | 过期回退 AuthCodeURL：%v", err, err)
				}
				if got != cached {
					t.Fatalf("stale URL changed: %q != %q | 过期 URL 变化：%q != %q", got, cached, got, cached)
				}
				clock.Advance(tc.secondWait)
				_, err = adapter.AuthCodeURL("state", "nonce", "")
			}
			if !tc.okAfterTTL || err != nil {
				assertErrorIs(t, err, ErrProviderConfig)
			}
		})
	}
}

// TestDiscoveryIssuerChangeRejected verifies that a rotated issuer is rejected and the
// previous endpoints remain untouched. | TestDiscoveryIssuerChangeRejected 校验轮换后的
// 签发方被拒绝，且旧端点保持不变。
func TestDiscoveryIssuerChangeRejected(t *testing.T) {
	fixture := newOIDCFixture(t)
	clock := newTestDiscoveryClock()
	provider := fixture.discoveryProvider("issuer-change")
	provider.DiscoveryTTL = 10 * time.Minute
	provider.DiscoveryMaxStale = -time.Second
	adapter := newAdapterWithPolicy(provider, nil, discoveryPolicyFor(nil, provider), clock.Now).(*oauthAdapter)

	if _, err := adapter.AuthCodeURL("state", "nonce", ""); err != nil {
		t.Fatalf("initial AuthCodeURL: %v | 首次 AuthCodeURL：%v", err, err)
	}
	authURL, tokenURL, _ := adapter.endpointSnapshot()
	fixture.set(func(c *oidcFixtureConfig) { c.discoveryIssuer = "https://other-issuer.example" })
	clock.Advance(11 * time.Minute)

	_, err := adapter.AuthCodeURL("state", "nonce", "")
	assertErrorIs(t, err, ErrProviderConfig, oidc.ErrInvalidIssuer)

	currentAuthURL, currentTokenURL, _ := adapter.endpointSnapshot()
	if currentAuthURL != authURL || currentTokenURL != tokenURL {
		t.Fatalf("endpoints changed after rejected discovery | 被拒绝的发现后端点发生变化")
	}

	fixture.set(func(c *oidcFixtureConfig) { c.discoveryIssuer = "" })
	clock.Advance(11 * time.Minute)
	if _, err := adapter.AuthCodeURL("state", "nonce", ""); err != nil {
		t.Fatalf("AuthCodeURL after recovery: %v | 恢复后 AuthCodeURL：%v", err, err)
	}
	if discovery, _, _, _ := fixture.counts(); discovery != 3 {
		t.Fatalf("discovery calls = %d, want 3 | 发现调用 = %d，期望 3", discovery, discovery)
	}
}

// TestDiscoveryPolicyClampingAndJitter verifies TTL clamping and bounded jitter. |
// TestDiscoveryPolicyClampingAndJitter 校验 TTL 限制与有界抖动。
func TestDiscoveryPolicyClampingAndJitter(t *testing.T) {
	if policy := (discoveryPolicy{}); policy.enabled() || policy.nextTTL() != 0 {
		t.Fatalf("zero policy should be disabled | 零值策略应被禁用")
	}
	raised := discoveryPolicy{ttl: time.Minute, minTTL: 5 * time.Minute}
	if got := raised.effectiveTTL(); got != 5*time.Minute {
		t.Fatalf("raised TTL = %s, want 5m | 提升后 TTL = %s，期望 5m", got, got)
	}
	lowered := discoveryPolicy{ttl: 30 * time.Minute, maxTTL: 20 * time.Minute}
	if got := lowered.effectiveTTL(); got != 20*time.Minute {
		t.Fatalf("lowered TTL = %s, want 20m | 降低后 TTL = %s，期望 20m", got, got)
	}
	exact := discoveryPolicy{ttl: 10 * time.Minute}
	if got := exact.nextTTL(); got != 10*time.Minute {
		t.Fatalf("un-jittered TTL = %s, want 10m | 无抖动 TTL = %s，期望 10m", got, got)
	}
	jittered := discoveryPolicy{ttl: 10 * time.Minute, minTTL: 9 * time.Minute, maxTTL: 11 * time.Minute, jitter: 0.75}
	for i := 0; i < 1000; i++ {
		got := jittered.nextTTL()
		if got < 9*time.Minute || got > 11*time.Minute {
			t.Fatalf("jittered TTL %s outside [9m, 11m] | 抖动 TTL %s 超出 [9m, 11m]", got, got)
		}
	}
	if en, zh := (discoveryPolicy{ttl: time.Minute, minTTL: 2 * time.Minute, maxTTL: time.Minute}).problem(); en == "" || zh == "" {
		t.Fatalf("min > max should be rejected | min > max 应被拒绝")
	}
}

// TestDiscoverySettingsValidation verifies provider, broker and merged validation. |
// TestDiscoverySettingsValidation 校验提供方、代理与合并后的配置校验。
func TestDiscoverySettingsValidation(t *testing.T) {
	service, _ := newTestAuthService(t)
	invalidBroker := []BrokerConfig{
		{DiscoveryTTL: -time.Second},
		{DiscoveryTTLMin: -time.Second},
		{DiscoveryTTLMax: -time.Second},
		{DiscoveryJitter: -0.1},
		{DiscoveryJitter: 1.5},
		{DiscoveryTTLMin: 2 * time.Minute, DiscoveryTTLMax: time.Minute},
	}
	for _, config := range invalidBroker {
		config.Service = service
		if _, err := NewBroker(config); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("NewBroker(%+v) err = %v, want ErrInvalidConfig | NewBroker(%+v) 错误 = %v，期望 ErrInvalidConfig", config, err, config, err)
		}
	}
	validBroker, err := NewBroker(BrokerConfig{
		Service:         service,
		DiscoveryTTL:    10 * time.Minute,
		DiscoveryTTLMin: time.Minute,
		DiscoveryTTLMax: time.Hour,
		DiscoveryJitter: 0.2,
	})
	if err != nil {
		t.Fatalf("valid discovery broker: %v | 合法发现代理：%v", err, err)
	}

	invalidProviders := []*Provider{
		{Name: "p", ClientID: "c", AuthURL: "a", TokenURL: "t", UserInfoURL: "u", DiscoveryTTL: -time.Second},
		{Name: "p", ClientID: "c", AuthURL: "a", TokenURL: "t", UserInfoURL: "u", DiscoveryJitter: 2},
		{Name: "p", ClientID: "c", AuthURL: "a", TokenURL: "t", UserInfoURL: "u", DiscoveryTTLMin: 2 * time.Minute, DiscoveryTTLMax: time.Minute},
		{Name: "p", ClientID: "c", UseOIDC: true, DiscoveryTTL: time.Minute},
	}
	for _, provider := range invalidProviders {
		if err := provider.Validate(); !errors.Is(err, ErrProviderConfig) {
			t.Fatalf("Validate(%+v) err = %v, want ErrProviderConfig | Validate(%+v) 错误 = %v，期望 ErrProviderConfig", provider, err, provider, err)
		}
	}

	merged := &Provider{Name: "p", ClientID: "c", AuthURL: "a", TokenURL: "t", UserInfoURL: "u", DiscoveryTTLMin: 2 * time.Minute}
	narrowBroker, err := NewBroker(BrokerConfig{Service: service, DiscoveryTTLMax: time.Minute})
	if err != nil {
		t.Fatalf("narrow broker: %v | 窄代理：%v", err, err)
	}
	if err := narrowBroker.RegisterProvider("merged", merged); !errors.Is(err, ErrProviderConfig) {
		t.Fatalf("merged min/max err = %v, want ErrProviderConfig | 合并 min/max 错误 = %v，期望 ErrProviderConfig", err, err)
	}
	inherited := &Provider{Name: "p", ClientID: "c", AuthURL: "a", TokenURL: "t", UserInfoURL: "u", UseOIDC: true}
	if err := validBroker.RegisterProvider("inherited", inherited); !errors.Is(err, ErrProviderConfig) {
		t.Fatalf("issuer-less inherited TTL err = %v, want ErrProviderConfig | 无 issuer 继承 TTL 错误 = %v，期望 ErrProviderConfig", err, err)
	}
}

// TestBrokerDiscoveryPolicyApplied verifies broker defaults and per-provider overrides
// reach the built-in adapter and that the broker clock drives refreshes. |
// TestBrokerDiscoveryPolicyApplied 校验代理默认值与提供方覆盖值进入内置适配器，且代理
// 时钟驱动刷新。
func TestBrokerDiscoveryPolicyApplied(t *testing.T) {
	fixture := newOIDCFixture(t)
	clock := newTestDiscoveryClock()
	service, _ := newTestAuthService(t)
	broker, err := NewBroker(BrokerConfig{
		Service:      service,
		HTTPClient:   fixture.server.Client(),
		Now:          clock.Now,
		DiscoveryTTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewBroker: %v | NewBroker：%v", err, err)
	}
	provider := fixture.discoveryProvider("broker-refresh")
	if err := broker.RegisterProvider("broker-refresh", provider); err != nil {
		t.Fatalf("RegisterProvider: %v | RegisterProvider：%v", err, err)
	}
	_, adapter, err := broker.adapter("broker-refresh")
	if err != nil {
		t.Fatalf("broker adapter: %v | 代理适配器：%v", err, err)
	}
	builtin, ok := adapter.(*oauthAdapter)
	if !ok {
		t.Fatalf("adapter type = %T | 适配器类型 = %T", adapter, adapter)
	}
	if builtin.policy.ttl != time.Hour {
		t.Fatalf("inherited TTL = %s, want 1h | 继承 TTL = %s，期望 1h", builtin.policy.ttl, builtin.policy.ttl)
	}

	override := fixture.discoveryProvider("broker-override")
	override.DiscoveryTTL = time.Minute
	override.DiscoveryMaxStale = -time.Second
	if err := broker.RegisterProvider("broker-override", override); err != nil {
		t.Fatalf("RegisterProvider override: %v | RegisterProvider 覆盖：%v", err, err)
	}
	_, overrideAdapter, err := broker.adapter("broker-override")
	if err != nil {
		t.Fatalf("override adapter: %v | 覆盖适配器：%v", err, err)
	}
	overrideBuiltin := overrideAdapter.(*oauthAdapter)
	if overrideBuiltin.policy.ttl != time.Minute || overrideBuiltin.policy.maxStale != -time.Second {
		t.Fatalf("override policy = %+v | 覆盖策略 = %+v", overrideBuiltin.policy, overrideBuiltin.policy)
	}

	if _, err := builtin.AuthCodeURL("state", "nonce", ""); err != nil {
		t.Fatalf("AuthCodeURL: %v | AuthCodeURL：%v", err, err)
	}
	clock.Advance(61 * time.Minute)
	if _, err := builtin.AuthCodeURL("state", "nonce", ""); err != nil {
		t.Fatalf("refreshed AuthCodeURL: %v | 刷新后 AuthCodeURL：%v", err, err)
	}
	if discovery, _, _, _ := fixture.counts(); discovery != 2 {
		t.Fatalf("discovery calls = %d, want 2 | 发现调用 = %d，期望 2", discovery, discovery)
	}
}

// TestDiscoveryRefreshWithoutCachedDocument verifies a missing endpoint still reports a
// configuration error instead of silently falling back. | TestDiscoveryRefreshWithoutCachedDocument
// 校验缺少端点时仍报告配置错误，而不是静默回退。
func TestDiscoveryRefreshWithoutCachedDocument(t *testing.T) {
	provider := &Provider{Name: "no-issuer", ClientID: "c", UseOIDC: true}
	adapter := newAdapter(provider, nil).(*oauthAdapter)
	_, err := adapter.AuthCodeURL("state", "nonce", "")
	assertErrorIs(t, err, ErrProviderConfig)
}
