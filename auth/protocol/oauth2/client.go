package oauth2

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
)

// Client auth styles for the client implementation. | 客户端实现的认证风格。
const (
	// AuthStyleAuto uses Basic for confidential clients and form-body for public clients. | AuthStyleAuto 对机密客户端使用 Basic，对公共客户端使用表单体。
	AuthStyleAuto = "auto"
	// AuthStyleBasic always uses HTTP Basic client authentication. | AuthStyleBasic 总是使用 HTTP Basic 客户端认证。
	AuthStyleBasic = "basic"
	// AuthStylePost always uses form-body client authentication. | AuthStylePost 总是使用表单体客户端认证。
	AuthStylePost = "post"
)

// Endpoint groups the OAuth endpoints a client talks to. | Endpoint 汇总客户端访问的 OAuth 端点。
type Endpoint struct {
	// AuthURL is the authorization endpoint. | AuthURL 是授权端点。
	AuthURL string
	// TokenURL is the token endpoint. | TokenURL 是令牌端点。
	TokenURL string
	// DeviceAuthURL is the RFC 8628 device authorization endpoint. | DeviceAuthURL 是 RFC 8628 设备授权端点。
	DeviceAuthURL string
	// IntrospectionURL is the RFC 7662 introspection endpoint. | IntrospectionURL 是 RFC 7662 自省端点。
	IntrospectionURL string
	// RevocationURL is the RFC 7009 revocation endpoint. | RevocationURL 是 RFC 7009 撤销端点。
	RevocationURL string
	// PARURL is the RFC 9126 pushed authorization request endpoint. | PARURL 是 RFC 9126 推送授权请求端点。
	PARURL string
	// JWKSURL is the server key set. | JWKSURL 是服务器密钥集。
	JWKSURL string
}

// ClientConfig configures a Client. | ClientConfig 配置 Client。
type ClientConfig struct {
	// ClientID is the registered client identifier. | ClientID 是已注册客户端标识。
	ClientID string
	// ClientSecret is the registered secret; empty for public clients. | ClientSecret 是已注册密钥；公共客户端为空。
	ClientSecret string
	// RedirectURL is the client redirect URI. | RedirectURL 是客户端重定向 URI。
	RedirectURL string
	// Scopes is the default scope set. | Scopes 是默认作用域集。
	Scopes []string
	// Endpoint groups the server endpoints. | Endpoint 汇总服务器端点。
	Endpoint Endpoint
	// HTTPClient performs requests; nil means http.DefaultClient with a timeout. | HTTPClient 执行请求；空值表示带超时的 http.DefaultClient。
	HTTPClient *http.Client
	// AuthStyle selects client authentication. | AuthStyle 选择客户端认证方式。
	AuthStyle string
	// UsePKCE enables PKCE for authorization-code flows. | UsePKCE 为授权码流程启用 PKCE。
	UsePKCE bool
	// DPoPKey is a signer for RFC 9449 proofs; nil disables DPoP. | DPoPKey 是 RFC 9449 证明签名器；空值禁用 DPoP。
	DPoPKey DPoPSigner
	// ExtraParams are appended to authorization requests. | ExtraParams 追加到授权请求。
	ExtraParams url.Values
}

// Client is an OAuth 2.1 client. | Client 是 OAuth 2.1 客户端。
type OAuthClient struct {
	config ClientConfig
	http   *http.Client
}

// NewClient returns a Client. | NewClient 返回 Client。
func NewClient(config ClientConfig) (*OAuthClient, error) {
	if config.ClientID == "" {
		return nil, errs.Detail(ErrInvalidClient, "client id is empty | 客户端标识为空")
	}
	if config.Endpoint.AuthURL == "" && config.Endpoint.TokenURL == "" {
		return nil, errs.Detail(ErrInvalidConfig, "no endpoint configured | 未配置端点")
	}
	if config.AuthStyle == "" {
		config.AuthStyle = AuthStyleAuto
	}
	switch config.AuthStyle {
	case AuthStyleAuto, AuthStyleBasic, AuthStylePost:
	default:
		return nil, errs.Detail(ErrInvalidConfig, "unknown auth style %[1]q | 未知认证风格 %[1]q", config.AuthStyle)
	}
	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &OAuthClient{config: config, http: httpClient}, nil
}

// Config returns a copy of the client configuration. | Config 返回客户端配置副本。
func (c *OAuthClient) Config() ClientConfig { return c.config }

// AuthCodeOption customizes an authorization URL. | AuthCodeOption 定制授权 URL。
type AuthCodeOption func(*authCodeOptions)

// authCodeOptions collects authorization URL options. | authCodeOptions 汇总授权 URL 选项。
type authCodeOptions struct {
	// verifier is the PKCE verifier generated or supplied by the caller. | verifier 是调用方生成或提供的 PKCE 校验器。
	verifier string
	// nonce is the OpenID Connect nonce. | nonce 是 OpenID Connect nonce。
	nonce string
	// params holds additional query parameters. | params 保存附加查询参数。
	params url.Values
	// pkce forces PKCE on or off; nil uses the client default. | pkce 强制开启或关闭 PKCE；nil 使用客户端默认。
	pkce *bool
}

// WithCodeVerifier sets a caller-supplied PKCE verifier. | WithCodeVerifier 设置调用方提供的 PKCE 校验器。
func WithCodeVerifier(verifier string) AuthCodeOption {
	return func(o *authCodeOptions) { o.verifier = verifier }
}

// WithNonce sets the OpenID Connect nonce. | WithNonce 设置 OpenID Connect nonce。
func WithNonce(nonce string) AuthCodeOption {
	return func(o *authCodeOptions) { o.nonce = nonce }
}

// WithPrompt sets the OpenID Connect prompt parameter. | WithPrompt 设置 OpenID Connect prompt 参数。
func WithPrompt(prompt ...string) AuthCodeOption {
	return func(o *authCodeOptions) { o.params.Set("prompt", strings.Join(prompt, " ")) }
}

// WithLoginHint sets the OpenID Connect login_hint parameter. | WithLoginHint 设置 OpenID Connect login_hint 参数。
func WithLoginHint(hint string) AuthCodeOption {
	return func(o *authCodeOptions) { o.params.Set("login_hint", hint) }
}

// WithMaxAge sets the OpenID Connect max_age parameter. | WithMaxAge 设置 OpenID Connect max_age 参数。
func WithMaxAge(seconds int) AuthCodeOption {
	return func(o *authCodeOptions) { o.params.Set("max_age", itoa(seconds)) }
}

// WithACRValues sets the OpenID Connect acr_values parameter. | WithACRValues 设置 OpenID Connect acr_values 参数。
func WithACRValues(values ...string) AuthCodeOption {
	return func(o *authCodeOptions) { o.params.Set("acr_values", strings.Join(values, " ")) }
}

// WithUILocales sets the OpenID Connect ui_locales parameter. | WithUILocales 设置 OpenID Connect ui_locales 参数。
func WithUILocales(locales ...string) AuthCodeOption {
	return func(o *authCodeOptions) { o.params.Set("ui_locales", strings.Join(locales, " ")) }
}

// WithResource appends RFC 8707 resource indicators. | WithResource 追加 RFC 8707 资源指示器。
func WithResource(resources ...string) AuthCodeOption {
	return func(o *authCodeOptions) {
		for _, resource := range resources {
			o.params.Add("resource", resource)
		}
	}
}

// WithResponseMode sets the response mode. | WithResponseMode 设置响应模式。
func WithResponseMode(mode string) AuthCodeOption {
	return func(o *authCodeOptions) { o.params.Set("response_mode", mode) }
}

// WithAuthParam sets an arbitrary authorization parameter. | WithAuthParam 设置任意授权参数。
func WithAuthParam(key, value string) AuthCodeOption {
	return func(o *authCodeOptions) { o.params.Set(key, value) }
}

// WithPKCE forces PKCE on or off for this request. | WithPKCE 为本次请求强制开启或关闭 PKCE。
func WithPKCE(enabled bool) AuthCodeOption {
	return func(o *authCodeOptions) { o.pkce = &enabled }
}

// AuthCodeURL builds an authorization URL. | AuthCodeURL 构建授权 URL。
//
// When PKCE is enabled a verifier is generated internally and cannot be recovered by the caller;
// use AuthCodeURLWithPKCE when the verifier must be supplied to Exchange. | 启用 PKCE 时内部会生成
// 校验器，调用方无法取回；需要把校验器传给 Exchange 时请使用 AuthCodeURLWithPKCE。
func (c *OAuthClient) AuthCodeURL(state string, opts ...AuthCodeOption) (string, error) {
	raw, _, err := c.AuthCodeURLWithPKCE(state, opts...)
	return raw, err
}

// AuthCodeURLWithPKCE builds an authorization URL and returns the PKCE verifier used, if any. | AuthCodeURLWithPKCE
// 构建授权 URL，并返回使用的 PKCE 校验器（如有）。
func (c *OAuthClient) AuthCodeURLWithPKCE(state string, opts ...AuthCodeOption) (string, string, error) {
	if c.config.Endpoint.AuthURL == "" {
		return "", "", errs.Detail(ErrInvalidConfig, "authorization endpoint is empty | 授权端点为为空")
	}
	options := authCodeOptions{params: make(url.Values)}
	for key, values := range c.config.ExtraParams {
		for _, value := range values {
			options.params.Add(key, value)
		}
	}
	for _, opt := range opts {
		opt(&options)
	}
	endpoint, err := url.Parse(c.config.Endpoint.AuthURL)
	if err != nil {
		return "", "", errs.Wrap(err, ErrInvalidConfig)
	}
	query := endpoint.Query()
	query.Set("response_type", ResponseCode)
	query.Set("client_id", c.config.ClientID)
	if c.config.RedirectURL != "" {
		query.Set("redirect_uri", c.config.RedirectURL)
	}
	if len(c.config.Scopes) > 0 {
		query.Set("scope", ScopeString(c.config.Scopes))
	}
	if state != "" {
		query.Set("state", state)
	}
	if options.nonce != "" {
		query.Set("nonce", options.nonce)
	}
	usePKCE := c.config.UsePKCE
	if options.pkce != nil {
		usePKCE = *options.pkce
	}
	verifier := options.verifier
	if usePKCE {
		if verifier == "" {
			generated, err := GenerateCodeVerifier()
			if err != nil {
				return "", "", err
			}
			verifier = generated
		}
		query.Set("code_challenge", CodeChallengeS256(verifier))
		query.Set("code_challenge_method", PKCES256)
	}
	for key, values := range options.params {
		if len(values) == 0 {
			continue
		}
		// Option values replace same-named parameters preset on the endpoint URL. Appending would
		// emit duplicates such as prompt=existing&prompt=login, which RFC 6749 forbids and which
		// some authorization servers reject outright. | 选项值替换端点上预设的同名参数；追加会产生
		// prompt=existing&prompt=login 这类 RFC 6749 禁止且部分授权服务器直接拒绝的重复参数。
		query.Del(key)
		for _, value := range values {
			if value == "" {
				continue
			}
			query.Add(key, value)
		}
	}
	endpoint.RawQuery = query.Encode()
	return endpoint.String(), verifier, nil
}

// ExchangeOption customizes a token exchange. | ExchangeOption 定制令牌交换。
type ExchangeOption func(*exchangeOptions)

// exchangeOptions collects token request options. | exchangeOptions 汇总令牌请求选项。
type exchangeOptions struct {
	verifier    string
	redirectURL string
	scopes      []string
	params      url.Values
}

// WithExchangeVerifier sets the PKCE verifier for the code exchange. | WithExchangeVerifier 设置授权码交换的 PKCE 校验器。
func WithExchangeVerifier(verifier string) ExchangeOption {
	return func(o *exchangeOptions) { o.verifier = verifier }
}

// WithExchangeRedirectURL overrides the redirect URI for the exchange. | WithExchangeRedirectURL 覆盖交换使用的重定向 URI。
func WithExchangeRedirectURL(redirectURL string) ExchangeOption {
	return func(o *exchangeOptions) { o.redirectURL = redirectURL }
}

// WithExchangeScope narrows the requested scopes. | WithExchangeScope 收窄请求的作用域。
func WithExchangeScope(scopes ...string) ExchangeOption {
	return func(o *exchangeOptions) { o.scopes = scopes }
}

// WithExchangeParam sets an arbitrary token request parameter. | WithExchangeParam 设置任意令牌请求参数。
func WithExchangeParam(key, value string) ExchangeOption {
	return func(o *exchangeOptions) { o.params.Set(key, value) }
}

// Exchange redeems an authorization code. | Exchange 兑换授权码。
func (c *OAuthClient) Exchange(ctx context.Context, code string, opts ...ExchangeOption) (*Token, error) {
	if c.config.Endpoint.TokenURL == "" {
		return nil, errs.Detail(ErrInvalidConfig, "token endpoint is empty | 令牌端点为为空")
	}
	options := exchangeOptions{params: make(url.Values)}
	for _, opt := range opts {
		opt(&options)
	}
	form := url.Values{
		"grant_type": {GrantAuthorizationCode},
		"code":       {code},
	}
	if len(options.scopes) > 0 {
		form.Set("scope", ScopeString(options.scopes))
	}
	redirectURL := c.config.RedirectURL
	if options.redirectURL != "" {
		redirectURL = options.redirectURL
	}
	if redirectURL != "" {
		form.Set("redirect_uri", redirectURL)
	}
	if options.verifier != "" {
		form.Set("code_verifier", options.verifier)
	}
	for key, values := range options.params {
		for _, value := range values {
			form.Add(key, value)
		}
	}
	return c.tokenRequest(ctx, form)
}

// Refresh redeems a refresh token. | Refresh 兑换刷新令牌。
func (c *OAuthClient) Refresh(ctx context.Context, refreshToken string, scopes ...string) (*Token, error) {
	form := url.Values{
		"grant_type":    {GrantRefreshToken},
		"refresh_token": {refreshToken},
	}
	if len(scopes) > 0 {
		form.Set("scope", ScopeString(scopes))
	}
	return c.tokenRequest(ctx, form)
}

// ClientCredentials obtains a client-credentials token. | ClientCredentials 获取客户端凭据令牌。
func (c *OAuthClient) ClientCredentials(ctx context.Context, scopes ...string) (*Token, error) {
	form := url.Values{"grant_type": {GrantClientCredentials}}
	if len(scopes) > 0 {
		form.Set("scope", ScopeString(scopes))
	}
	return c.tokenRequest(ctx, form)
}

// Password performs the deprecated resource-owner-password grant. | Password 执行已弃用的资源所有者口令授权。
func (c *OAuthClient) Password(ctx context.Context, username, password string, scopes ...string) (*Token, error) {
	form := url.Values{
		"grant_type": {GrantPassword},
		"username":   {username},
		"password":   {password},
	}
	if len(scopes) > 0 {
		form.Set("scope", ScopeString(scopes))
	}
	return c.tokenRequest(ctx, form)
}

// JWTBearer performs the RFC 7523 JWT-bearer grant. | JWTBearer 执行 RFC 7523 JWT 承载授权。
func (c *OAuthClient) JWTBearer(ctx context.Context, assertion string, scopes ...string) (*Token, error) {
	form := url.Values{
		"grant_type": {GrantJWTBearer},
		"assertion":  {assertion},
	}
	if len(scopes) > 0 {
		form.Set("scope", ScopeString(scopes))
	}
	return c.tokenRequest(ctx, form)
}

// TokenExchangeOption customizes RFC 8693 token exchange. | TokenExchangeOption 定制 RFC 8693 令牌交换。
type TokenExchangeOption func(url.Values)

// WithTokenExchangeActor sets the actor token. | WithTokenExchangeActor 设置行为者令牌。
func WithTokenExchangeActor(token, tokenType string) TokenExchangeOption {
	return func(form url.Values) {
		form.Set("actor_token", token)
		form.Set("actor_token_type", tokenType)
	}
}

// WithTokenExchangeAudience sets the target audience. | WithTokenExchangeAudience 设置目标受众。
func WithTokenExchangeAudience(audience string) TokenExchangeOption {
	return func(form url.Values) { form.Set("audience", audience) }
}

// WithTokenExchangeScope sets the requested scopes. | WithTokenExchangeScope 设置请求作用域。
func WithTokenExchangeScope(scopes ...string) TokenExchangeOption {
	return func(form url.Values) { form.Set("scope", ScopeString(scopes)) }
}

// WithTokenExchangeRequestedType sets the requested token type. | WithTokenExchangeRequestedType 设置请求令牌类型。
func WithTokenExchangeRequestedType(tokenType string) TokenExchangeOption {
	return func(form url.Values) { form.Set("requested_token_type", tokenType) }
}

// TokenExchange performs RFC 8693 token exchange. | TokenExchange 执行 RFC 8693 令牌交换。
func (c *OAuthClient) TokenExchange(ctx context.Context, subjectToken, subjectTokenType string, opts ...TokenExchangeOption) (*Token, error) {
	form := url.Values{
		"grant_type":         {GrantTokenExchange},
		"subject_token":      {subjectToken},
		"subject_token_type": {subjectTokenType},
	}
	for _, opt := range opts {
		opt(form)
	}
	return c.tokenRequest(ctx, form)
}

// Revoke revokes a token per RFC 7009. | Revoke 按 RFC 7009 撤销令牌。
func (c *OAuthClient) Revoke(ctx context.Context, token, tokenTypeHint string) error {
	if c.config.Endpoint.RevocationURL == "" {
		return errs.Detail(ErrInvalidConfig, "revocation endpoint is empty | 撤销端点为为空")
	}
	form := url.Values{"token": {token}}
	if tokenTypeHint != "" {
		form.Set("token_type_hint", tokenTypeHint)
	}
	status, body, err := c.postForm(ctx, c.config.Endpoint.RevocationURL, form, true)
	if err != nil {
		return err
	}
	if status >= 400 {
		return parseOAuthError(status, body)
	}
	return nil
}

// Introspection is the RFC 7662 response. | Introspection 是 RFC 7662 响应。
type Introspection struct {
	// Active reports whether the token is currently valid. | Active 报告令牌当前是否有效。
	Active bool `json:"active"`
	// Scope is the space-delimited scope. | Scope 是空格分隔作用域。
	Scope string `json:"scope,omitempty"`
	// ClientID is the client the token was issued to. | ClientID 是令牌的签发对象。
	ClientID string `json:"client_id,omitempty"`
	// Username is the resource-owner login if available. | Username 是可用时的资源所有者登录名。
	Username string `json:"username,omitempty"`
	// TokenType is the token type. | TokenType 是令牌类型。
	TokenType string `json:"token_type,omitempty"`
	// Sub is the subject claim. | Sub 是主体声明。
	Sub string `json:"sub,omitempty"`
	// Aud is the audience claim. | Aud 是受众声明。
	Aud any `json:"aud,omitempty"`
	// Iss is the issuer claim. | Iss 是签发方声明。
	Iss string `json:"iss,omitempty"`
	// JTI is the token identifier claim. | JTI 是令牌标识声明。
	JTI string `json:"jti,omitempty"`
	// Exp is the expiry NumericDate. | Exp 是过期 NumericDate。
	Exp int64 `json:"exp,omitempty"`
	// Iat is the issue NumericDate. | Iat 是签发 NumericDate。
	Iat int64 `json:"iat,omitempty"`
	// Nbf is the not-before NumericDate. | Nbf 是生效前 NumericDate。
	Nbf int64 `json:"nbf,omitempty"`
	// CNF is the confirmation claim. | CNF 是确认声明。
	CNF map[string]any `json:"cnf,omitempty"`
	// Raw holds the whole response. | Raw 保存完整响应。
	Raw map[string]any `json:"-"`
}

// Introspect calls the RFC 7662 endpoint. | Introspect 调用 RFC 7662 端点。
func (c *OAuthClient) Introspect(ctx context.Context, token, tokenTypeHint string) (*Introspection, error) {
	if c.config.Endpoint.IntrospectionURL == "" {
		return nil, errs.Detail(ErrInvalidConfig, "introspection endpoint is empty | 自省端点为为空")
	}
	form := url.Values{"token": {token}}
	if tokenTypeHint != "" {
		form.Set("token_type_hint", tokenTypeHint)
	}
	status, body, err := c.postForm(ctx, c.config.Endpoint.IntrospectionURL, form, true)
	if err != nil {
		return nil, err
	}
	if status >= 400 {
		return nil, parseOAuthError(status, body)
	}
	var out Introspection
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, errs.Wrap(err, ErrServerError)
	}
	_ = json.Unmarshal(body, &out.Raw)
	return &out, nil
}

// DeviceAuthResponse is the RFC 8628 device authorization response. | DeviceAuthResponse 是 RFC 8628 设备授权响应。
type DeviceAuthResponse struct {
	// DeviceCode is the long device code. | DeviceCode 是长设备码。
	DeviceCode string `json:"device_code"`
	// UserCode is the short human code. | UserCode 是短人工码。
	UserCode string `json:"user_code"`
	// VerificationURI is the user-facing verification page. | VerificationURI 是用户验证页。
	VerificationURI string `json:"verification_uri"`
	// VerificationURIComplete includes the user code. | VerificationURIComplete 包含用户码。
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	// ExpiresIn is the device-code lifetime in seconds. | ExpiresIn 是设备码寿命（秒）。
	ExpiresIn int64 `json:"expires_in"`
	// Interval is the minimum polling interval in seconds. | Interval 是最小轮询间隔（秒）。
	Interval int64 `json:"interval,omitempty"`
}

// DeviceAuthorization starts an RFC 8628 flow. | DeviceAuthorization 启动 RFC 8628 流程。
func (c *OAuthClient) DeviceAuthorization(ctx context.Context, scopes ...string) (*DeviceAuthResponse, error) {
	if c.config.Endpoint.DeviceAuthURL == "" {
		return nil, errs.Detail(ErrInvalidConfig, "device authorization endpoint is empty | 设备授权端点为为空")
	}
	form := url.Values{"client_id": {c.config.ClientID}}
	if len(scopes) > 0 {
		form.Set("scope", ScopeString(scopes))
	} else if len(c.config.Scopes) > 0 {
		form.Set("scope", ScopeString(c.config.Scopes))
	}
	status, body, err := c.postForm(ctx, c.config.Endpoint.DeviceAuthURL, form, true)
	if err != nil {
		return nil, err
	}
	if status >= 400 {
		return nil, parseOAuthError(status, body)
	}
	var out DeviceAuthResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, errs.Wrap(err, ErrServerError)
	}
	return &out, nil
}

// DeviceToken polls the token endpoint for a device grant. | DeviceToken 轮询设备许可的令牌端点。
func (c *OAuthClient) DeviceToken(ctx context.Context, deviceCode string) (*Token, error) {
	form := url.Values{
		"grant_type":  {GrantDeviceCode},
		"device_code": {deviceCode},
	}
	return c.tokenRequest(ctx, form)
}

// PARResponse is the RFC 9126 response. | PARResponse 是 RFC 9126 响应。
type PARResponse struct {
	// RequestURI is the urn:ietf:params:oauth:request_uri value. | RequestURI 是 urn:ietf:params:oauth:request_uri 取值。
	RequestURI string `json:"request_uri"`
	// ExpiresIn is the request-URI lifetime in seconds. | ExpiresIn 是请求 URI 寿命（秒）。
	ExpiresIn int64 `json:"expires_in"`
}

// PAR pushes an authorization request. | PAR 推送授权请求。
func (c *OAuthClient) PAR(ctx context.Context, params url.Values) (*PARResponse, error) {
	if c.config.Endpoint.PARURL == "" {
		return nil, errs.Detail(ErrInvalidConfig, "PAR endpoint is empty | PAR 端点为为空")
	}
	form := cloneValues(params)
	form.Set("client_id", c.config.ClientID)
	if form.Get("response_type") == "" {
		form.Set("response_type", ResponseCode)
	}
	if form.Get("redirect_uri") == "" && c.config.RedirectURL != "" {
		form.Set("redirect_uri", c.config.RedirectURL)
	}
	if form.Get("scope") == "" && len(c.config.Scopes) > 0 {
		form.Set("scope", ScopeString(c.config.Scopes))
	}
	status, body, err := c.postForm(ctx, c.config.Endpoint.PARURL, form, true)
	if err != nil {
		return nil, err
	}
	if status >= 400 {
		return nil, parseOAuthError(status, body)
	}
	var out PARResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, errs.Wrap(err, ErrServerError)
	}
	return &out, nil
}

// Token is a token-endpoint response. | Token 是令牌端点响应。
type Token struct {
	// AccessToken is the issued access token. | AccessToken 是签发的访问令牌。
	AccessToken string `json:"access_token"`
	// TokenType is Bearer or DPoP. | TokenType 取值为 Bearer 或 DPoP。
	TokenType string `json:"token_type"`
	// RefreshToken is the optional refresh token. | RefreshToken 是可选刷新令牌。
	RefreshToken string `json:"refresh_token,omitempty"`
	// ExpiresIn is the lifetime in seconds. | ExpiresIn 是寿命（秒）。
	ExpiresIn int64 `json:"expires_in,omitempty"`
	// Scope is the granted scope. | Scope 是已授予作用域。
	Scope string `json:"scope,omitempty"`
	// IDToken is the OpenID Connect ID token. | IDToken 是 OpenID Connect ID 令牌。
	IDToken string `json:"id_token,omitempty"`
	// IssuedTokenType is the RFC 8693 issued type. | IssuedTokenType 是 RFC 8693 签发类型。
	IssuedTokenType string `json:"issued_token_type,omitempty"`
	// Raw holds the whole response. | Raw 保存完整响应。
	Raw map[string]any `json:"-"`
	// Expiry is the computed absolute expiry. | Expiry 是计算出的绝对过期时间。
	Expiry time.Time `json:"-"`
}

// Valid reports whether the token has not expired. | Valid 报告令牌是否未过期。
func (t *Token) Valid() bool {
	if t == nil {
		return false
	}
	return t.Expiry.IsZero() || time.Now().Before(t.Expiry)
}

// SetExpiry computes Expiry from ExpiresIn at now. | SetExpiry 在 now 时刻由 ExpiresIn 计算 Expiry。
func (t *Token) SetExpiry(now time.Time) {
	if t != nil && t.ExpiresIn > 0 {
		t.Expiry = now.Add(time.Duration(t.ExpiresIn) * time.Second)
	}
}

// tokenRequest posts a token form and parses the response. | tokenRequest 提交令牌表单并解析响应。
func (c *OAuthClient) tokenRequest(ctx context.Context, form url.Values) (*Token, error) {
	if c.config.Endpoint.TokenURL == "" {
		return nil, errs.Detail(ErrInvalidConfig, "token endpoint is empty | 令牌端点为为空")
	}
	status, body, err := c.postForm(ctx, c.config.Endpoint.TokenURL, form, true)
	if err != nil {
		return nil, err
	}
	if status >= 400 {
		return nil, parseOAuthError(status, body)
	}
	var token Token
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, errs.Wrap(err, ErrServerError)
	}
	_ = json.Unmarshal(body, &token.Raw)
	token.SetExpiry(time.Now())
	return &token, nil
}

// postForm sends a form-encoded request with client authentication. | postForm 发送带客户端认证的表单请求。
func (c *OAuthClient) postForm(ctx context.Context, endpoint string, form url.Values, authenticate bool) (int, []byte, error) {
	body := form.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		return 0, nil, errs.Wrap(err, ErrInvalidRequest)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cache-Control", "no-store")
	if authenticate {
		if err := c.applyClientAuth(req, form); err != nil {
			return 0, nil, err
		}
	}
	if c.config.DPoPKey != nil {
		if err := c.applyDPoP(req); err != nil {
			return 0, nil, err
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, errs.Wrap(err, ErrServerError)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, nil, errs.Wrap(err, ErrServerError)
	}
	return resp.StatusCode, data, nil
}

// applyClientAuth attaches client authentication to req. | applyClientAuth 把客户端认证附加到 req。
func (c *OAuthClient) applyClientAuth(req *http.Request, form url.Values) error {
	style := c.config.AuthStyle
	if style == AuthStyleAuto {
		if c.config.ClientSecret == "" || req.URL == nil {
			style = AuthStylePost
		} else {
			style = AuthStyleBasic
		}
	}
	switch style {
	case AuthStyleBasic:
		if c.config.ClientSecret == "" {
			form.Set("client_id", c.config.ClientID)
			req.Body = io.NopCloser(strings.NewReader(form.Encode()))
			req.ContentLength = int64(len(form.Encode()))
			return nil
		}
		credentials := url.QueryEscape(c.config.ClientID) + ":" + url.QueryEscape(c.config.ClientSecret)
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(credentials)))
		return nil
	case AuthStylePost:
		form.Set("client_id", c.config.ClientID)
		if c.config.ClientSecret != "" {
			form.Set("client_secret", c.config.ClientSecret)
		}
		encoded := form.Encode()
		req.Body = io.NopCloser(strings.NewReader(encoded))
		req.ContentLength = int64(len(encoded))
		return nil
	default:
		return errs.Detail(ErrInvalidConfig, "unknown auth style %[1]q | 未知认证风格 %[1]q", style)
	}
}

// parseOAuthError converts a non-success response into *Error. | parseOAuthError 把非成功响应转换为 *Error。
func parseOAuthError(status int, body []byte) error {
	var payload struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
		URI         string `json:"error_uri"`
	}
	if err := json.Unmarshal(body, &payload); err != nil || payload.Error == "" {
		return errs.Detail(ErrServerError, "HTTP %[1]d | HTTP %[1]d", status)
	}
	out := NewError(payload.Error, payload.Description)
	out.URI = payload.URI
	out.Status = status
	return out
}

// itoa converts a non-negative int to its decimal form without importing strconv at call sites. | itoa
// 把非负整数转换为十进制形式，避免调用点导入 strconv。
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
