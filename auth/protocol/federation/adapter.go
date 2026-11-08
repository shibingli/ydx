package federation

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/shibingli/ydx/auth/protocol/oauth2"
	"github.com/shibingli/ydx/auth/protocol/oidc"
	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
)

// builtinOIDCAlgorithms lists the signature algorithms accepted for ID tokens when
// discovery does not advertise a restricted set. | builtinOIDCAlgorithms 列出发现文档未限定
// 签名算法时接受的 ID 令牌算法。
var builtinOIDCAlgorithms = []string{
	"RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
	"ES256", "ES384", "ES512", "EdDSA",
}

// oauthAdapter is the built-in OAuth 2.0/OIDC adapter with provider hooks. | oauthAdapter
// 是带提供方钩子的内置 OAuth 2.0/OIDC 适配器。
type oauthAdapter struct {
	provider *Provider
	client   *http.Client
	now      func() time.Time
	policy   discoveryPolicy

	mu                 sync.Mutex
	authURL            string
	tokenURL           string
	userURL            string
	jwksURL            string
	issuer             string
	discovery          *oidc.DiscoveryDocument
	discoveryExpiresAt time.Time
	rp                 *oidc.RelyingParty
	refresh            *discoveryRefresh
}

// discoveryRefresh is one in-flight discovery refresh shared by single-flight waiters.
// err is written once before done is closed. | discoveryRefresh 是一次进行中的发现刷新，
// 由单飞等待方共享。err 在 done 关闭前只写入一次。
type discoveryRefresh struct {
	done chan struct{}
	err  error
}

// newAdapter returns the provider adapter with periodic discovery refresh disabled.
// newAdapter 返回禁用周期性发现刷新的提供方适配器。
func newAdapter(p *Provider, fallback *http.Client) ProviderAdapter {
	return newAdapterWithPolicy(p, fallback, discoveryPolicy{}, time.Now)
}

// newAdapterWithPolicy returns the built-in adapter with an explicit discovery cache
// policy and clock. A nil clock defaults to time.Now. | newAdapterWithPolicy 返回带显式
// 发现缓存策略与时钟的内置适配器；时钟为空时使用 time.Now。
func newAdapterWithPolicy(p *Provider, fallback *http.Client, policy discoveryPolicy, now func() time.Time) ProviderAdapter {
	if p == nil {
		return nil
	}
	if p.Adapter != nil {
		return p.Adapter
	}
	if now == nil {
		now = time.Now
	}
	return &oauthAdapter{
		provider: p,
		client:   clientFor(p, fallback),
		now:      now,
		policy:   policy,
		authURL:  p.AuthURL,
		tokenURL: p.TokenURL,
		userURL:  p.UserInfoURL,
		jwksURL:  p.JWKSURL,
		issuer:   p.Issuer,
	}
}

// AuthCodeURL builds the authorization redirect URL. | AuthCodeURL 构建授权重定向 URL。
func (a *oauthAdapter) AuthCodeURL(state, nonce, verifier string) (string, error) {
	p := a.provider
	if p.AuthURLHook != nil {
		return p.AuthURLHook(p, state, nonce, verifier)
	}
	if err := a.resolve(context.Background()); err != nil {
		return "", err
	}
	params := map[string]string{
		"response_type": "code",
		"client_id":     p.ClientID,
		"redirect_uri":  p.RedirectURL,
		"scope":         scopeValue(p),
		"state":         state,
		"nonce":         nonce,
	}
	if p.PKCE {
		if verifier == "" {
			return "", errs.Detail(ErrInvalidRequest, "PKCE verifier is empty | PKCE verifier 为空")
		}
		params["code_challenge"] = oauth2.CodeChallengeS256(verifier)
		params["code_challenge_method"] = "S256"
	}
	for key, value := range p.AuthParams {
		params[key] = value
	}
	authURL, _, _ := a.endpointSnapshot()
	return setQueryParams(authURL, params)
}

// Exchange redeems an authorization code. | Exchange 兑换授权码。
func (a *oauthAdapter) Exchange(ctx context.Context, code, verifier string) (*Token, error) {
	p := a.provider
	if code == "" {
		return nil, ErrMissingCode
	}
	if p.ExchangeHook != nil {
		return p.ExchangeHook(ctx, p, a.client, code, verifier)
	}
	if err := a.resolve(ctx); err != nil {
		return nil, err
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", p.RedirectURL)
	form.Set("client_id", p.ClientID)
	headers := make(map[string]string)
	style := p.AuthStyle
	if style == "" {
		style = AuthStylePost
	}
	if style == AuthStyleAuto {
		if p.ClientSecret != "" {
			style = AuthStyleBasic
		} else {
			style = AuthStylePost
		}
	}
	switch style {
	case AuthStyleBasic:
		credentials := url.QueryEscape(p.ClientID) + ":" + url.QueryEscape(p.ClientSecret)
		headers["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(credentials))
	case AuthStylePost:
		if p.ClientSecret != "" {
			form.Set("client_secret", p.ClientSecret)
		}
	}
	if verifier != "" {
		form.Set("code_verifier", verifier)
	}
	for key, value := range p.TokenParams {
		if value == "" {
			form.Del(key)
		} else {
			form.Set(key, value)
		}
	}
	_, tokenURL, _ := a.endpointSnapshot()
	status, body, err := postForm(ctx, a.client, tokenURL, form, headers)
	if err != nil {
		return nil, errs.Wrap(err, ErrTokenExchange)
	}
	if status < http.StatusOK || status >= http.StatusMultipleChoices {
		return nil, tokenHTTPError(status, body)
	}
	token, err := tokenFromBody(body, time.Now())
	if err != nil {
		return nil, errs.Wrap(err, ErrTokenExchange)
	}
	if p.UseOIDC {
		// OpenID Connect Core 3.1.3.3 requires an ID token in every authorization-code
		// token response. Skipping verification when it is absent would drop issuer,
		// audience and at_hash binding without any error. | OpenID Connect Core 3.1.3.3
		// 要求每个授权码令牌响应都包含 ID 令牌；缺失时跳过校验会静默丢弃签发方、受众与
		// at_hash 绑定。
		if token.IDToken == "" {
			return nil, errs.Detail(ErrTokenExchange, "provider %s returned no ID token | 提供方 %s 未返回 ID 令牌", p.Name, p.Name)
		}
		if err := a.verifyIDToken(ctx, token); err != nil {
			return nil, err
		}
	}
	return token, nil
}

// UserInfo returns the normalized upstream identity. For OIDC providers, a UserInfo
// response whose sub claim differs from the verified ID token subject is rejected
// (OpenID Connect Core 5.3.2). | UserInfo 返回规范化上游身份。对 OIDC 提供方而言，
// UserInfo 响应中的 sub 声明与已校验 ID 令牌主体不一致时会被拒绝（OpenID Connect Core
// 5.3.2）。
func (a *oauthAdapter) UserInfo(ctx context.Context, token *Token) (*Identity, error) {
	p := a.provider
	if token == nil {
		return nil, errs.Detail(ErrUserInfo, "token is nil | 令牌为空")
	}
	if p.UserInfoHook != nil {
		return p.UserInfoHook(ctx, p, a.client, token)
	}
	var claimsIdentity *Identity
	if p.UseOIDC && len(token.Claims) > 0 {
		claimsIdentity = identityFromClaims(p.Name, token.Claims)
	}
	if err := a.resolve(ctx); err != nil {
		return nil, errs.Wrap(err, ErrUserInfo)
	}
	_, _, userURL := a.endpointSnapshot()
	if userURL == "" {
		if claimsIdentity != nil && claimsIdentity.Subject != "" {
			return claimsIdentity, nil
		}
		return nil, errs.Detail(ErrUserInfo, "provider %s has no user info endpoint or claims | 提供方 %s 没有用户信息端点或声明", p.Name, p.Name)
	}
	headers := map[string]string{
		"Authorization": "Bearer " + token.AccessToken,
	}
	for key, value := range p.UserInfoHeaders {
		headers[key] = value
	}
	status, body, err := getProvider(ctx, a.client, userURL, headers)
	if err != nil {
		return nil, errs.Wrap(err, ErrUserInfo)
	}
	if status < http.StatusOK || status >= http.StatusMultipleChoices {
		return nil, errs.Detail(ErrUserInfo, "provider %s UserInfo returned HTTP %d | 提供方 %s UserInfo 返回 HTTP %d", p.Name, status, p.Name, status)
	}
	raw, err := parseJSONObject(body)
	if err != nil {
		return nil, errs.Detail(ErrUserInfo, "provider %s UserInfo is invalid | 提供方 %s UserInfo 非法", p.Name, p.Name)
	}
	if code := providerErrorCode(raw); code != "" {
		return nil, errs.Detail(ErrUserInfo, "provider %s UserInfo returned %s | 提供方 %s UserInfo 返回 %s", p.Name, code, p.Name, code)
	}
	identity := identityFromMap(p.Name, raw)
	if p.UseOIDC {
		if err := checkUserInfoSubject(p, token, raw); err != nil {
			return nil, err
		}
	}
	identity = mergeIdentity(identity, claimsIdentity)
	if identity.Subject == "" {
		return nil, errs.Detail(ErrUserInfo, "provider %s UserInfo has no subject | 提供方 %s UserInfo 缺少主体", p.Name, p.Name)
	}
	return identity, nil
}

// resolve performs OIDC discovery when required, refreshing an expired document when a
// discovery TTL is configured. | resolve 在需要时执行 OIDC 发现，并在配置发现 TTL 后
// 刷新过期文档。
func (a *oauthAdapter) resolve(ctx context.Context) error {
	return a.ensureDiscovery(ctx, false)
}

// ensureDiscovery refreshes discovery metadata when missing or due and then validates
// that the effective endpoints are usable. | ensureDiscovery 在元数据缺失或到期时刷新
// 发现，并校验生效端点可用。
func (a *oauthAdapter) ensureDiscovery(ctx context.Context, needJWKS bool) error {
	a.mu.Lock()
	a.applyProviderDefaultsLocked()
	pending := a.discoveryPendingLocked(needJWKS)
	a.mu.Unlock()
	if pending {
		if err := a.refreshDiscovery(ctx, needJWKS); err != nil {
			return err
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.authURL == "" || a.tokenURL == "" {
		return errs.Detail(ErrProviderConfig, "provider %s has no authorization or token endpoint | 提供方 %s 缺少授权或令牌端点", a.provider.Name, a.provider.Name)
	}
	return nil
}

// applyProviderDefaultsLocked fills unset fields from the immutable provider config.
// applyProviderDefaultsLocked 从不可变提供方配置填充未设置字段。
func (a *oauthAdapter) applyProviderDefaultsLocked() {
	p := a.provider
	if p == nil {
		return
	}
	if a.authURL == "" {
		a.authURL = p.AuthURL
	}
	if a.tokenURL == "" {
		a.tokenURL = p.TokenURL
	}
	if a.userURL == "" {
		a.userURL = p.UserInfoURL
	}
	if a.jwksURL == "" {
		a.jwksURL = p.JWKSURL
	}
	if a.issuer == "" {
		a.issuer = p.Issuer
	}
}

// discoveryPendingLocked reports whether discovery must be fetched or refreshed. The
// caller must hold a.mu. | discoveryPendingLocked 报告是否必须获取或刷新发现；调用方必须
// 持有 a.mu。
func (a *oauthAdapter) discoveryPendingLocked(needJWKS bool) bool {
	p := a.provider
	if p == nil || !p.UseOIDC {
		return false
	}
	if a.discovery == nil {
		return a.authURL == "" || a.tokenURL == "" || (needJWKS && a.jwksURL == "")
	}
	return a.policy.enabled() && !a.now().Before(a.discoveryExpiresAt)
}

// refreshDiscovery fetches the discovery document with single-flight semantics. Only
// one caller performs the network request; concurrent callers wait for its result or
// for their own context to end. | refreshDiscovery 以单飞语义获取发现文档。只有一个
// 调用方执行网络请求，并发调用方等待该结果或自身上下文结束。
func (a *oauthAdapter) refreshDiscovery(ctx context.Context, needJWKS bool) error {
	a.mu.Lock()
	a.applyProviderDefaultsLocked()
	if !a.discoveryPendingLocked(needJWKS) {
		a.mu.Unlock()
		return nil
	}
	if refresh := a.refresh; refresh != nil {
		a.mu.Unlock()
		select {
		case <-refresh.done:
			// The result belongs to this refresh cycle, so a later leader cannot
			// overwrite what this waiter observes. | 结果属于本次刷新周期，后续主导方
			// 无法覆盖本等待方观察到的值。
			return refresh.err
		case <-ctx.Done():
			return errs.Wrap(ctx.Err(), ErrProviderConfig)
		}
	}
	refresh := &discoveryRefresh{done: make(chan struct{})}
	a.refresh = refresh
	issuer := a.issuer
	client := a.client
	a.mu.Unlock()

	err := a.fetchDiscovery(ctx, issuer, client)

	a.mu.Lock()
	refresh.err = err
	a.refresh = nil
	close(refresh.done)
	a.mu.Unlock()
	return err
}

// fetchDiscovery fetches and applies one discovery document, falling back to a cached
// document while it is within the configured stale bound. | fetchDiscovery 获取并应用
// 一个发现文档；缓存文档仍在配置的过期范围内时回退到该缓存。
func (a *oauthAdapter) fetchDiscovery(ctx context.Context, issuer string, client *http.Client) error {
	if strings.TrimSpace(issuer) == "" {
		return errs.Detail(ErrProviderConfig, "provider %s needs an issuer for discovery | 提供方 %s 需要 issuer 才能发现", a.provider.Name, a.provider.Name)
	}
	document, err := oidc.Discover(ctx, issuer, client)
	now := a.now()
	a.mu.Lock()
	defer a.mu.Unlock()
	if err != nil {
		return a.discoveryFailureLocked(err, now)
	}
	a.applyDiscoveryLocked(document, now)
	return nil
}

// applyDiscoveryLocked records a fetched document, refreshes endpoint snapshots and
// invalidates relying-party state only when ID token verification metadata changed.
// applyDiscoveryLocked 记录已获取文档、刷新端点快照，并仅在 ID 令牌校验元数据变化时
// 失效依赖方状态。
func (a *oauthAdapter) applyDiscoveryLocked(document *oidc.DiscoveryDocument, now time.Time) {
	if document == nil {
		return
	}
	previous := a.discovery
	if previous == nil {
		a.authURL = document.AuthorizationEndpoint
		a.tokenURL = document.TokenEndpoint
		a.userURL = document.UserInfoEndpoint
		a.jwksURL = document.JWKSURI
		a.issuer = document.Issuer
	} else {
		if document.AuthorizationEndpoint != "" {
			a.authURL = document.AuthorizationEndpoint
		}
		if document.TokenEndpoint != "" {
			a.tokenURL = document.TokenEndpoint
		}
		if document.UserInfoEndpoint != "" {
			a.userURL = document.UserInfoEndpoint
		}
		if document.JWKSURI != "" {
			a.jwksURL = document.JWKSURI
		}
		if document.Issuer != "" {
			a.issuer = document.Issuer
		}
	}
	a.discovery = document
	a.discoveryExpiresAt = now.Add(a.policy.nextTTL())
	if previous != nil && !sameIDTokenMetadata(previous, document) {
		a.rp = nil
	}
}

// discoveryFailureLocked applies the stale fallback bound to a refresh failure. The
// caller must hold a.mu. | discoveryFailureLocked 对刷新失败应用过期回退边界；调用方必须
// 持有 a.mu。
func (a *oauthAdapter) discoveryFailureLocked(cause error, now time.Time) error {
	if a.discovery == nil {
		return errs.Wrap(cause, ErrProviderConfig)
	}
	limit := a.policy.maxStale
	if limit < 0 {
		return errs.Wrap(cause, ErrProviderConfig)
	}
	if limit == 0 {
		limit = a.policy.effectiveTTL()
	}
	staleFor := now.Sub(a.discoveryExpiresAt)
	if staleFor < 0 {
		staleFor = 0
	}
	if limit > 0 && staleFor <= limit {
		return nil
	}
	return errs.WrapDetail(cause, ErrProviderConfig, "discovery refresh failed and the cached document is too stale | 发现刷新失败且缓存文档过期过久")
}

// sameIDTokenMetadata reports whether two documents describe the same issuer and ID
// token verification keys. Endpoint-only changes keep the cached relying party, and
// with it the JWKS cache. | sameIDTokenMetadata 报告两个文档是否描述相同的签发方与 ID
// 令牌校验密钥。仅端点变化时保留缓存的依赖方及其 JWKS 缓存。
func sameIDTokenMetadata(left, right *oidc.DiscoveryDocument) bool {
	if left == nil || right == nil {
		return left == right
	}
	leftMeta := left.ServerMetadata
	rightMeta := right.ServerMetadata
	if leftMeta == nil || rightMeta == nil {
		return leftMeta == rightMeta
	}
	return leftMeta.Issuer == rightMeta.Issuer &&
		leftMeta.JWKSURI == rightMeta.JWKSURI &&
		slices.Equal(left.IDTokenSigningAlgValuesSupported, right.IDTokenSigningAlgValuesSupported)
}

// endpointSnapshot returns the current endpoint set under a.mu. | endpointSnapshot 在
// a.mu 下返回当前端点集合。
func (a *oauthAdapter) endpointSnapshot() (authURL, tokenURL, userURL string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.authURL, a.tokenURL, a.userURL
}

// verifyIDToken verifies the ID token and records scalar claims. | verifyIDToken 校验 ID 令牌并记录标量声明。
func (a *oauthAdapter) verifyIDToken(ctx context.Context, token *Token) error {
	if err := a.ensureDiscovery(ctx, true); err != nil {
		return errs.Wrap(err, ErrTokenExchange)
	}
	a.mu.Lock()
	discovery := a.discovery
	issuer := a.issuer
	jwksURL := a.jwksURL
	userURL := a.userURL
	if discovery == nil && issuer != "" && jwksURL != "" {
		discovery = &oidc.DiscoveryDocument{
			ServerMetadata: &oauth2.ServerMetadata{
				Issuer:                issuer,
				AuthorizationEndpoint: a.authURL,
				TokenEndpoint:         a.tokenURL,
				JWKSURI:               jwksURL,
			},
			UserInfoEndpoint:                 userURL,
			IDTokenSigningAlgValuesSupported: append([]string(nil), builtinOIDCAlgorithms...),
		}
	}
	rp := a.rp
	if rp == nil && discovery != nil {
		p := a.provider
		created, err := oidc.NewRelyingParty(ctx, oidc.RelyingPartyConfig{
			Issuer:       issuer,
			ClientID:     p.ClientID,
			ClientSecret: p.ClientSecret,
			RedirectURL:  p.RedirectURL,
			Scopes:       append([]string(nil), p.Scopes...),
			HTTPClient:   a.client,
			Discovery:    discovery,
			UsePKCE:      p.PKCE,
		})
		if err != nil {
			a.mu.Unlock()
			return errs.Wrap(err, ErrTokenExchange)
		}
		a.rp = created
		rp = created
	}
	a.mu.Unlock()
	if rp == nil {
		return errs.Detail(ErrTokenExchange, "provider %s cannot verify ID tokens without a JWKS | 提供方 %s 没有 JWKS，无法校验 ID 令牌", a.provider.Name, a.provider.Name)
	}
	verified, err := rp.ValidateIDToken(ctx, token.IDToken, "", token.AccessToken)
	if err != nil {
		return errs.Wrap(err, ErrTokenExchange)
	}
	token.Claims = stringMap(verified.Raw)
	return nil
}

// identityFromClaims maps verified ID token claims into an Identity. | identityFromClaims
// 把已校验 ID 令牌声明映射为 Identity。
func identityFromClaims(providerName string, claims map[string]string) *Identity {
	if len(claims) == 0 {
		return nil
	}
	raw := make(map[string]any, len(claims))
	for key, value := range claims {
		raw[key] = value
	}
	identity := identityFromMap(providerName, raw)
	if identity.Subject == "" {
		identity.Subject = claims["sub"]
	}
	return identity
}

// checkUserInfoSubject enforces OpenID Connect Core 5.3.2: once an ID token has been
// verified, a non-empty UserInfo sub must equal the verified ID token subject. The
// error never includes either subject or any token material. | checkUserInfoSubject
// 实现 OpenID Connect Core 5.3.2：ID 令牌校验通过后，非空 UserInfo sub 必须等于已校验
// ID 令牌主体；错误不会包含任一主体或令牌内容。
func checkUserInfoSubject(p *Provider, token *Token, raw map[string]any) error {
	expected := token.Claims["sub"]
	actual := stringValue(raw["sub"])
	if expected == "" || actual == "" || actual == expected {
		return nil
	}
	return errs.Detail(ErrUserInfo, "provider %s UserInfo subject does not match the verified ID token | 提供方 %s UserInfo 主体与已校验 ID 令牌不一致", p.Name, p.Name)
}

// tokenHTTPError describes a non-2xx token response without exposing its body. | tokenHTTPError
// 描述非 2xx 令牌响应，且不暴露响应体。
func tokenHTTPError(status int, body []byte) error {
	code := ""
	if raw, err := parseJSONObject(body); err == nil {
		code = providerErrorCode(raw)
	} else if raw, err := parseFormObject(body); err == nil {
		code = providerErrorCode(raw)
	}
	if code != "" {
		return errs.Detail(ErrTokenExchange, "token endpoint returned HTTP %d (%s) | 令牌端点返回 HTTP %d（%s）", status, code, status, code)
	}
	return errs.Detail(ErrTokenExchange, "token endpoint returned HTTP %d | 令牌端点返回 HTTP %d", status, status)
}
