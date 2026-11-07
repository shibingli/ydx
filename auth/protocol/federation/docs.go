// Package federation brokers social and enterprise logins into ydx auth.
//
// A Broker owns one provider per route, implements the OAuth 2.0
// authorization-code flow with optional PKCE and OIDC nonce validation, maps the
// provider response onto a stable Identity, and passes that identity to
// auth.Service.EnsureUserFromIdentity before creating a normal ydx session.
// It never links accounts by unverified email: LinkByEmail only takes effect
// when the provider asserts a verified address. | Package federation 把社交与企业
// 登录接入 ydx auth。Broker 按路由管理提供方，实现带可选 PKCE 与 OIDC nonce 校验的
// OAuth 2.0 授权码流程，把提供方响应映射为稳定的 Identity，并在创建普通 ydx 会话前交给
// auth.Service.EnsureUserFromIdentity。它绝不会按未验证邮箱关联账号：LinkByEmail 仅在提供方
// 断言邮箱已验证时生效。
//
// When OIDC is enabled, Exchange requires an ID token and verifies its issuer,
// audience, expiry, nonce and at_hash; UserInfo then rejects a non-empty `sub`
// that differs from the verified ID token subject (OpenID Connect Core 5.3.2),
// so a compromised or mixed-up UserInfo endpoint cannot switch identities. | 启用
// OIDC 时，Exchange 要求响应包含 ID 令牌并校验签发方、受众、过期时间、nonce 与
// at_hash；UserInfo 随后拒绝与已校验 ID 令牌主体不一致的非空 `sub`（OpenID Connect
// Core 5.3.2），避免被攻破或混淆的 UserInfo 端点切换身份。
//
// Built-in presets cover Google, Microsoft Entra ID, GitHub, Apple, Facebook,
// GitLab, Okta, Auth0 and Keycloak, plus WeChat, Alipay, DingTalk, Feishu, WeCom,
// QQ, Weibo, Baidu and Gitee. Presets supply endpoints, scopes and quirks; the
// same Provider fields remain available for custom OAuth 2.0 or OIDC services. | 内置
// 预设覆盖 Google、Microsoft Entra ID、GitHub、Apple、Facebook、GitLab、Okta、Auth0 与
// Keycloak，以及微信、支付宝、钉钉、飞书、企业微信、QQ、微博、百度与 Gitee。预设提供端点、
// 作用域与特殊处理；相同的 Provider 字段也可用于自定义 OAuth 2.0 或 OIDC 服务。
//
// OIDC discovery documents are cached for the adapter lifetime by default. Set
// Provider.DiscoveryTTL or BrokerConfig.DiscoveryTTL to refresh them periodically;
// DiscoveryTTLMin, DiscoveryTTLMax and DiscoveryJitter bound and jitter the effective
// lifetime. Concurrent expiry is collapsed into one network refresh (single-flight).
// When a refresh fails transiently, an expired document may still be served for up to
// DiscoveryMaxStale (zero means one effective TTL, a negative value disables the stale
// fallback). ID token verification keys are cached separately: an endpoint-only
// discovery change keeps the relying party and its JWKS cache, while an issuer, JWKS
// URI or signing-algorithm change rebuilds them. | OIDC 发现文档默认在适配器生命周期内
// 缓存。设置 Provider.DiscoveryTTL 或 BrokerConfig.DiscoveryTTL 可周期性刷新；
// DiscoveryTTLMin、DiscoveryTTLMax 与 DiscoveryJitter 限制并抖动生效有效期。并发到期会被
// 合并为一次网络刷新（单飞）。刷新瞬时失败时，过期文档最多仍可提供 DiscoveryMaxStale
// 指定的时长（零值表示一个生效 TTL，负值禁用过期回退）。ID 令牌校验密钥单独缓存：仅端点
// 变化时保留依赖方及其 JWKS 缓存，签发方、JWKS URI 或签名算法变化时重建。
//
// # YD router
//
//	svc, _ := auth.New(auth.Config{Stores: stores})
//	broker, _ := federation.NewBroker(federation.BrokerConfig{
//	    Service: svc,
//	    SuccessRedirect: "/app",
//	    Providers: map[string]*federation.Provider{
//	        "google": federation.Google(federation.ProviderConfig{
//	            ClientID:     clientID,
//	            ClientSecret: clientSecret,
//	            RedirectURL:  "https://example.com/auth/google/callback",
//	        }),
//	    },
//	})
//	r := router.New()
//	broker.Register(r, "/auth") // GET /auth/:provider/login, GET|POST /auth/:provider/callback
//
// # Native net/http
//
//	broker, _ := federation.NewBroker(federation.BrokerConfig{Service: svc})
//	_ = broker.RegisterProvider("github", federation.GitHub(federation.ProviderConfig{
//	    ClientID:     clientID,
//	    ClientSecret: clientSecret,
//	    RedirectURL:  "https://example.com/auth/github/callback",
//	}))
//	mux := http.NewServeMux()
//	mux.Handle("/auth/", broker.HTTPHandler("/auth"))
//	// Or mount a single provider directly:
//	mux.Handle("/login/github", broker.LoginHandler("github"))
//	mux.Handle("/callback/github", broker.CallbackHandler("github"))
//
// Callbacks consume state through StateStore before exchanging the code, so a
// replayed or cross-provider state is rejected. The default MemoryStateStore is
// suitable for a single process; multi-instance deployments should provide a
// shared StateStore. | 回调在兑换授权码前通过 StateStore 单次消费 state，因此重放或跨提供方
// 的 state 会被拒绝。默认 MemoryStateStore 适用于单进程；多实例部署应提供共享 StateStore。
package federation
