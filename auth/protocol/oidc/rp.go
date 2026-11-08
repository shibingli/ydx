package oidc

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/shibingli/ydx/auth/protocol/oauth2"
	"github.com/shibingli/ydx/auth/token/jose"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
)

// RelyingPartyConfig configures an OpenID Connect relying party. | RelyingPartyConfig 配置 OpenID Connect 依赖方。
type RelyingPartyConfig struct {
	// Issuer is the OP issuer used for discovery. | Issuer 是用于发现文档的 OP 签发方。
	Issuer string
	// ClientID is the registered client identifier. | ClientID 是已注册客户端标识。
	ClientID string
	// ClientSecret is the registered client secret. | ClientSecret 是已注册客户端密钥。
	ClientSecret string
	// RedirectURL is the registered redirect URI. | RedirectURL 是已注册重定向 URI。
	RedirectURL string
	// Scopes are the default scopes. | Scopes 是默认作用域。
	Scopes []string
	// HTTPClient performs discovery, token, UserInfo and JWKS requests. | HTTPClient 执行发现、令牌、UserInfo 与 JWKS 请求。
	HTTPClient *http.Client
	// Discovery, when set, skips the network discovery request. | Discovery 设置时跳过网络发现请求。
	Discovery *DiscoveryDocument
	// DecryptionKey decrypts encrypted UserInfo responses. | DecryptionKey 解密加密的 UserInfo 响应。
	DecryptionKey *jose.Key
	// Now overrides the clock. | Now 替换时钟。
	Now func() time.Time
	// Leeway is the clock tolerance applied to ID tokens. | Leeway 是应用于 ID 令牌的时钟容差。
	Leeway time.Duration
	// UsePKCE enables PKCE for the authorization-code flow. | UsePKCE 为授权码流程启用 PKCE。
	UsePKCE bool
}

// RelyingParty is an OpenID Connect client. | RelyingParty 是 OpenID Connect 客户端。
type RelyingParty struct {
	config    RelyingPartyConfig
	discovery *DiscoveryDocument
	oauth     *oauth2.OAuthClient
	fetcher   *jose.Fetcher
	now       func() time.Time
}

// Discover fetches an OpenID Provider discovery document. | Discover 获取 OpenID 提供方发现文档。
func Discover(ctx context.Context, issuer string, httpClient *http.Client) (*DiscoveryDocument, error) {
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	if issuer == "" {
		return nil, errs.Detail(ErrInvalidConfig, "issuer is empty | issuer 为空")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	endpoint := issuer + DiscoveryPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, errs.Wrap(err, ErrDiscoveryFailed)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, errs.Wrap(err, ErrDiscoveryFailed)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errs.Detail(ErrDiscoveryFailed, "discovery returned HTTP %[1]d | 发现文档返回 HTTP %[1]d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, errs.Wrap(err, ErrDiscoveryFailed)
	}
	document := &DiscoveryDocument{ServerMetadata: &oauth2.ServerMetadata{}}
	if err := json.Unmarshal(body, document); err != nil {
		return nil, errs.Wrap(err, ErrDiscoveryFailed)
	}
	if document.Issuer != issuer {
		return nil, errs.Detail(ErrInvalidIssuer, "discovery issuer %[1]q does not match %[2]q | 发现文档 issuer %[1]q 不匹配 %[2]q", document.Issuer, issuer)
	}
	return document, nil
}

// NewRelyingParty returns a relying party, performing discovery when needed. | NewRelyingParty 返回依赖方，必要时执行发现。
func NewRelyingParty(ctx context.Context, config RelyingPartyConfig) (*RelyingParty, error) {
	if config.ClientID == "" {
		return nil, errs.Detail(ErrInvalidConfig, "client id is empty | 客户端标识为空")
	}
	issuer := strings.TrimRight(strings.TrimSpace(config.Issuer), "/")
	discovery := config.Discovery
	if discovery == nil {
		document, err := Discover(ctx, issuer, config.HTTPClient)
		if err != nil {
			return nil, err
		}
		discovery = document
	}
	if discovery == nil {
		return nil, errs.Detail(ErrInvalidConfig, "discovery document is nil | 发现文档为空")
	}
	if issuer != "" && discovery.Issuer != issuer {
		return nil, errs.Detail(ErrInvalidIssuer, "discovery issuer mismatch | 发现文档签发方不匹配")
	}
	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	// Store the effective client so every RP request path shares one bounded-timeout client
	// instead of falling back to http.DefaultClient. | 保存实际客户端，使 RP 的所有请求路径共用
	// 同一个带超时的客户端，而不是回退到 http.DefaultClient。
	config.HTTPClient = httpClient
	config.Issuer = issuer
	oauthClient, err := oauth2.NewClient(oauth2.ClientConfig{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  config.RedirectURL,
		Scopes:       config.Scopes,
		HTTPClient:   httpClient,
		UsePKCE:      config.UsePKCE,
		Endpoint: oauth2.Endpoint{
			AuthURL:          discovery.AuthorizationEndpoint,
			TokenURL:         discovery.TokenEndpoint,
			DeviceAuthURL:    discovery.DeviceAuthorizationEndpoint,
			IntrospectionURL: discovery.IntrospectionEndpoint,
			RevocationURL:    discovery.RevocationEndpoint,
			PARURL:           discovery.PushedAuthorizationRequestEndpoint,
			JWKSURL:          discovery.JWKSURI,
		},
	})
	if err != nil {
		return nil, err
	}
	rp := &RelyingParty{config: config, discovery: discovery, oauth: oauthClient, now: config.Now}
	if rp.now == nil {
		rp.now = time.Now
	}
	if discovery.JWKSURI != "" {
		fetcher, err := jose.NewFetcher(discovery.JWKSURI, jose.FetcherOptions{Client: httpClient, Now: config.Now})
		if err != nil {
			return nil, errs.Wrap(err, ErrDiscoveryFailed)
		}
		rp.fetcher = fetcher
	}
	return rp, nil
}

// Discovery returns the provider metadata. | Discovery 返回提供方元数据。
func (rp *RelyingParty) Discovery() *DiscoveryDocument { return rp.discovery }

// Client returns the underlying OAuth client. | Client 返回底层 OAuth 客户端。
func (rp *RelyingParty) Client() *oauth2.OAuthClient { return rp.oauth }

// AuthCodeURL builds an authorization URL. | AuthCodeURL 构建授权 URL。
func (rp *RelyingParty) AuthCodeURL(state, nonce string, opts ...oauth2.AuthCodeOption) (string, string, error) {
	options := append([]oauth2.AuthCodeOption{oauth2.WithNonce(nonce)}, opts...)
	return rp.oauth.AuthCodeURLWithPKCE(state, options...)
}

// Token is an OAuth token response with a verified ID token. | Token 是带已校验 ID 令牌的 OAuth 令牌响应。
type Token struct {
	// Token is the OAuth token. | Token 是 OAuth 令牌。
	oauth2.Token
	// IDToken is the verified ID token when one was returned. | IDToken 是返回时已校验的 ID 令牌。
	IDToken *IDToken
}

// Exchange redeems an authorization code and verifies the ID token. | Exchange 兑换授权码并校验 ID 令牌。
func (rp *RelyingParty) Exchange(ctx context.Context, code, nonce, verifier string) (*Token, error) {
	token, err := rp.oauth.Exchange(ctx, code, oauth2.WithExchangeVerifier(verifier))
	if err != nil {
		return nil, err
	}
	out := &Token{Token: *token}
	if token.IDToken != "" {
		idToken, err := rp.ValidateIDToken(ctx, token.IDToken, nonce, token.AccessToken)
		if err != nil {
			return nil, err
		}
		out.IDToken = idToken
	}
	return out, nil
}

// ValidateIDToken verifies an ID token against the issuer, client and nonce. | ValidateIDToken 依据签发方、客户端与 nonce 校验 ID 令牌。
func (rp *RelyingParty) ValidateIDToken(ctx context.Context, raw, nonce, accessToken string) (*IDToken, error) {
	opts := IDTokenVerifyOptions{
		Issuer:      rp.discovery.Issuer,
		Audience:    rp.config.ClientID,
		Nonce:       nonce,
		AccessToken: accessToken,
		Leeway:      rp.config.Leeway,
		Now:         rp.config.Now,
		ValidAlgs:   append([]string(nil), rp.discovery.IDTokenSigningAlgValuesSupported...),
	}
	return VerifyIDToken(ctx, raw, rp.resolver(), opts)
}

// resolver returns the JWKS resolver, refreshing once on an unknown key. | resolver 返回 JWKS 解析器，遇到未知密钥时刷新一次。
func (rp *RelyingParty) resolver() jose.KeyResolver {
	if rp.fetcher == nil {
		return jose.KeyResolverFunc(func(context.Context, jose.Header) (*jose.Key, error) {
			return nil, errs.Detail(ErrInvalidConfig, "provider has no JWKS URI | 提供方没有 JWKS URI")
		})
	}
	return jose.KeyResolverFunc(func(ctx context.Context, header jose.Header) (*jose.Key, error) {
		key, err := rp.fetcher.Key(ctx, header.String("kid"))
		if err == nil {
			return key, nil
		}
		if _, refreshErr := rp.fetcher.ForceRefresh(ctx); refreshErr != nil {
			return nil, errs.Wrap(refreshErr, ErrInvalidToken)
		}
		return rp.fetcher.Key(ctx, header.String("kid"))
	})
}

// UserInfo calls the UserInfo endpoint and verifies signed responses. | UserInfo 调用 UserInfo 端点并校验签名响应。
func (rp *RelyingParty) UserInfo(ctx context.Context, accessToken string) (map[string]any, error) {
	if rp.discovery.UserInfoEndpoint == "" {
		return nil, errs.Detail(ErrInvalidConfig, "provider has no UserInfo endpoint | 提供方没有 UserInfo 端点")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rp.discovery.UserInfoEndpoint, nil)
	if err != nil {
		return nil, errs.Wrap(err, ErrInvalidRequest)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json, application/jwt")
	client := rp.config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errs.Wrap(err, ErrInvalidToken)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, errs.Wrap(err, ErrInvalidToken)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errs.Detail(ErrInvalidToken, "UserInfo returned HTTP %[1]d | UserInfo 返回 HTTP %[1]d", resp.StatusCode)
	}
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(contentType, "application/jwt") {
		return rp.verifyUserInfoJWT(ctx, string(body))
	}
	var claims map[string]any
	if err := json.Unmarshal(body, &claims); err != nil {
		return nil, errs.Wrap(err, ErrInvalidToken)
	}
	return claims, nil
}

// verifyUserInfoJWT verifies and decrypts a JWT UserInfo response. | verifyUserInfoJWT 校验并解密 JWT UserInfo 响应。
func (rp *RelyingParty) verifyUserInfoJWT(ctx context.Context, raw string) (map[string]any, error) {
	if strings.Count(raw, ".") == 4 {
		if rp.config.DecryptionKey == nil {
			return nil, errs.Detail(ErrInvalidConfig, "encrypted UserInfo needs a decryption key | 加密 UserInfo 需要解密密钥")
		}
		plaintext, err := jose.Decrypt(raw, rp.config.DecryptionKey, jose.DecryptOptions{})
		if err != nil {
			return nil, errs.Wrap(err, ErrInvalidToken)
		}
		raw = string(plaintext)
	}
	verified, err := jose.VerifyContext(ctx, raw, rp.resolver(), jose.VerifyOptions{})
	if err != nil {
		return nil, errs.Wrap(err, ErrInvalidToken)
	}
	var claims map[string]any
	if err := json.Unmarshal(verified.Payload, &claims); err != nil {
		return nil, errs.Wrap(err, ErrInvalidToken)
	}
	if issuer, _ := claims["iss"].(string); issuer != "" && issuer != rp.discovery.Issuer {
		return nil, ErrInvalidIssuer
	}
	return claims, nil
}

// Refresh redeems a refresh token and verifies a new ID token when present. | Refresh 兑换刷新令牌，并在存在时校验新 ID 令牌。
func (rp *RelyingParty) Refresh(ctx context.Context, refreshToken string, scopes ...string) (*Token, error) {
	token, err := rp.oauth.Refresh(ctx, refreshToken, scopes...)
	if err != nil {
		return nil, err
	}
	out := &Token{Token: *token}
	if token.IDToken != "" {
		idToken, err := rp.ValidateIDToken(ctx, token.IDToken, "", token.AccessToken)
		if err != nil {
			return nil, err
		}
		out.IDToken = idToken
	}
	return out, nil
}

// Revoke revokes an access or refresh token. | Revoke 撤销访问或刷新令牌。
func (rp *RelyingParty) Revoke(ctx context.Context, token, hint string) error {
	return rp.oauth.Revoke(ctx, token, hint)
}

// DeviceAuthorization starts a device flow. | DeviceAuthorization 启动设备流程。
func (rp *RelyingParty) DeviceAuthorization(ctx context.Context, scopes ...string) (*oauth2.DeviceAuthResponse, error) {
	return rp.oauth.DeviceAuthorization(ctx, scopes...)
}

// DeviceToken polls a device flow. | DeviceToken 轮询设备流程。
func (rp *RelyingParty) DeviceToken(ctx context.Context, deviceCode string) (*oauth2.Token, error) {
	return rp.oauth.DeviceToken(ctx, deviceCode)
}

// PAR pushes an authorization request. | PAR 推送授权请求。
func (rp *RelyingParty) PAR(ctx context.Context, params url.Values) (*oauth2.PARResponse, error) {
	return rp.oauth.PAR(ctx, params)
}

// EndSessionURL builds the provider's RP-initiated logout URL. | EndSessionURL 构建提供方的 RP 发起登出 URL。
func (rp *RelyingParty) EndSessionURL(idTokenHint, postLogoutRedirectURI, state string) string {
	endpoint := rp.discovery.EndSessionEndpoint
	if endpoint == "" {
		return ""
	}
	query := url.Values{}
	if idTokenHint != "" {
		query.Set("id_token_hint", idTokenHint)
	}
	if rp.config.ClientID != "" {
		query.Set("client_id", rp.config.ClientID)
	}
	if postLogoutRedirectURI != "" {
		query.Set("post_logout_redirect_uri", postLogoutRedirectURI)
	}
	if state != "" {
		query.Set("state", state)
	}
	if len(query) == 0 {
		return endpoint
	}
	return endpoint + "?" + query.Encode()
}
