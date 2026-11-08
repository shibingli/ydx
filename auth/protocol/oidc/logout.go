package oidc

import (
	"context"
	"crypto/subtle"
	htmlstd "html"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/auth/protocol/oauth2"
	"github.com/shibingli/ydx/auth/token/jose"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
)

// BackchannelLogoutEvent is the OIDC back-channel logout event key. | BackchannelLogoutEvent 是 OIDC 后端登出事件键。
const BackchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// LogoutTokenClaims is an OIDC back-channel logout token. | LogoutTokenClaims 是 OIDC 后端登出令牌。
type LogoutTokenClaims struct {
	// Issuer is the iss claim. | Issuer 是 iss 声明。
	Issuer string `json:"iss"`
	// Subject is the sub claim. | Subject 是 sub 声明。
	Subject string `json:"sub,omitempty"`
	// Audience is the aud claim. | Audience 是 aud 声明。
	Audience Audience `json:"aud"`
	// AZP is the azp claim identifying the RP the token is directed to; it is required when the
	// token has multiple audiences. | AZP 是标识令牌目标 RP 的 azp 声明；令牌有多个受众时必填。
	AZP string `json:"azp,omitempty"`
	// IssuedAt is the iat claim. | IssuedAt 是 iat 声明。
	IssuedAt int64 `json:"iat"`
	// JTI is the jti claim. | JTI 是 jti 声明。
	JTI string `json:"jti"`
	// Events holds the back-channel logout event object. | Events 保存后端登出事件对象。
	Events map[string]any `json:"events"`
	// SID is the sid claim. | SID 是 sid 声明。
	SID string `json:"sid,omitempty"`
	// Nonce must be absent in a logout token. | Nonce 在登出令牌中必须缺失。
	Nonce string `json:"nonce,omitempty"`
}

// LogoutToken builds a signed back-channel logout token. | LogoutToken 构建已签名的后端登出令牌。
func (p *Provider) LogoutToken(client *oauth2.Client, subject, sid string) (string, error) {
	if client == nil {
		return "", errs.Detail(ErrInvalidConfig, "client is nil | 客户端为空")
	}
	claims := &LogoutTokenClaims{
		Issuer:   p.config.Issuer,
		Subject:  p.subjectForClient(client, subject),
		Audience: Audience{client.ID},
		IssuedAt: p.Now().Unix(),
		JTI:      auth.NewID("logout"),
		Events:   map[string]any{BackchannelLogoutEvent: map[string]any{}},
		SID:      sid,
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", errs.Wrap(err, ErrLogoutFailed)
	}
	signed, err := jose.Sign(payload, p.signingKey, jose.SignOptions{
		Alg: p.signingAlg,
		Kid: p.signingKey.Kid,
		Typ: "logout+jwt",
	})
	if err != nil {
		return "", errs.Wrap(err, ErrLogoutFailed)
	}
	return signed, nil
}

// ValidateLogoutToken verifies a back-channel logout token. The typ header must be logout+jwt,
// verification keys come from the configured back-channel key source (ProviderConfig
// BackchannelLogoutKeySet, BackchannelLogoutJWKSURI or BackchannelLogoutKeyResolver, defaulting
// to this provider's own keys for issuer), iat is evaluated against the provider clock, and nonce
// must be absent. When audience is non-empty, the aud claim must contain it and a present azp
// claim must equal it, while multiple audiences additionally require azp; an empty audience only
// requires a non-empty aud for callers that do not know their receiver identity yet. When
// ProviderConfig.LogoutReplay is set, an already accepted jti is rejected; the store keeps the
// identifier until the end of the iat acceptance window. Replay protection is opt-in because
// replaying a logout token only repeats an idempotent session revocation. | ValidateLogoutToken
// 校验后端登出令牌。
// typ 头部必须是 logout+jwt，校验密钥来自配置的后端登出密钥来源（ProviderConfig
// BackchannelLogoutKeySet、BackchannelLogoutJWKSURI 或 BackchannelLogoutKeyResolver，issuer
// 为本提供方时默认使用自身密钥），iat 用提供方时钟评估，nonce 必须缺失。audience 非空时，aud
// 声明必须包含它，出现的 azp 声明必须等于它，且多受众还要求提供 azp；空 audience 只要求 aud
// 非空，供尚不知道接收方标识的调用方使用。设置 ProviderConfig.LogoutReplay 后，已接受过的 jti
// 会被拒绝；存储会保留该标识至 iat 接受窗口结束。重放保护为选择性启用，因为重放登出令牌只会
// 重复幂等的会话撤销。
func (p *Provider) ValidateLogoutToken(ctx context.Context, raw, issuer, audience string) (*LogoutTokenClaims, error) {
	verified, err := jose.VerifyContext(ctx, raw, p.logoutTokenResolver(issuer), jose.VerifyOptions{
		Typ: "logout+jwt",
		Now: p.Now,
	})
	if err != nil {
		return nil, errs.Wrap(err, ErrInvalidToken)
	}
	if !verified.IsJSON() {
		return nil, errs.Detail(ErrInvalidToken, "logout token payload is not JSON | 登出令牌载荷不是 JSON")
	}
	var claims LogoutTokenClaims
	if err := json.Unmarshal(verified.Claims, &claims); err != nil {
		return nil, errs.Wrap(err, ErrInvalidToken)
	}
	if claims.Issuer != issuer {
		return nil, errs.Detail(ErrInvalidIssuer, "logout token issuer mismatch | 登出令牌签发方不匹配")
	}
	if len(claims.Audience) == 0 {
		return nil, errs.Detail(ErrInvalidAudience, "logout token audience is missing | 登出令牌缺少受众")
	}
	if audience != "" {
		if !claims.Audience.Contains(audience) {
			return nil, errs.Detail(ErrInvalidAudience, "logout token audience mismatch | 登出令牌受众不匹配")
		}
		// OIDC Back-Channel Logout 1.0 requires azp when aud has multiple values, and a present
		// azp must identify the receiving RP. | OIDC 后端登出 1.0 要求 aud 含多个值时提供 azp，
		// 且出现的 azp 必须标识接收 RP。
		if len(claims.Audience) > 1 && claims.AZP == "" {
			return nil, errs.Detail(ErrInvalidAudience, "logout token azp is required with multiple audiences | 多受众的登出令牌必须提供 azp")
		}
		if claims.AZP != "" && claims.AZP != audience {
			return nil, errs.Detail(ErrInvalidAudience, "logout token azp mismatch | 登出令牌 azp 不匹配")
		}
	}
	if claims.IssuedAt == 0 || p.Now().Sub(time.Unix(claims.IssuedAt, 0)).Abs() > 5*time.Minute {
		return nil, errs.Detail(ErrInvalidToken, "logout token iat is stale | 登出令牌 iat 过旧")
	}
	if claims.JTI == "" {
		return nil, errs.Detail(ErrInvalidToken, "logout token jti is missing | 登出令牌缺少 jti")
	}
	if claims.Nonce != "" {
		return nil, errs.Detail(ErrInvalidToken, "logout token must not contain nonce | 登出令牌不得包含 nonce")
	}
	event, ok := claims.Events[BackchannelLogoutEvent]
	if !ok {
		return nil, errs.Detail(ErrInvalidToken, "logout token event is missing | 登出令牌缺少事件")
	}
	if _, isObject := event.(map[string]any); !isObject {
		return nil, errs.Detail(ErrInvalidToken, "logout token event must be a JSON object | 登出令牌事件必须是 JSON 对象")
	}
	if claims.Subject == "" && claims.SID == "" {
		return nil, errs.Detail(ErrInvalidToken, "logout token needs sub or sid | 登出令牌需要 sub 或 sid")
	}
	if p.config.LogoutReplay != nil {
		// Record only after every other check succeeded so invalid tokens cannot poison the
		// store; keep the jti for the rest of the iat acceptance window. | 所有其他检查通过后才
		// 记录，避免非法令牌污染存储；jti 保留至 iat 接受窗口结束。
		expiresAt := time.Unix(claims.IssuedAt, 0).UTC().Add(5 * time.Minute)
		fresh, err := p.config.LogoutReplay.Accept(ctx, claims.JTI, expiresAt)
		if err != nil {
			return nil, errs.Wrap(err, ErrInvalidToken)
		}
		if !fresh {
			return nil, errs.Detail(ErrInvalidToken, "logout token replay detected | 检测到登出令牌重放")
		}
	}
	return &claims, nil
}

// logoutTokenResolver picks verification keys for a logout token expected from issuer. Tokens
// expected from the configured receiver issuer use its key source; tokens claiming this provider
// as issuer use the provider key set so an external receiver configuration does not break local
// validation. | logoutTokenResolver 为期望来自 issuer 的登出令牌选择校验密钥。期望来自配置的接收
// 方签发方的令牌使用其密钥来源；声明本提供方为签发方的令牌使用提供方密钥集，避免外部接收方配置
// 破坏本地校验。
func (p *Provider) logoutTokenResolver(issuer string) jose.KeyResolver {
	if p.backchannelResolver != nil && issuer == p.backchannelIssuer {
		return p.backchannelResolver
	}
	if issuer == p.config.Issuer {
		return p.keys.Resolver()
	}
	if p.backchannelResolver != nil {
		return p.backchannelResolver
	}
	return p.keys.Resolver()
}

// NotifyBackchannelLogout delivers a logout token to a client. | NotifyBackchannelLogout 把登出令牌投递给客户端。
func (p *Provider) NotifyBackchannelLogout(ctx context.Context, client *oauth2.Client, subject, sid string) error {
	if client == nil || client.BackchannelLogoutURI == "" {
		return nil
	}
	token, err := p.LogoutToken(client, subject, sid)
	if err != nil {
		return err
	}
	form := url.Values{"logout_token": {token}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, client.BackchannelLogoutURI, strings.NewReader(form.Encode()))
	if err != nil {
		return errs.Wrap(err, ErrLogoutFailed)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return errs.Wrap(err, ErrLogoutFailed)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errs.Detail(ErrLogoutFailed, "back-channel logout returned HTTP %[1]d | 后端登出返回 HTTP %[1]d", resp.StatusCode)
	}
	return nil
}

// EndSession is the RP-initiated logout endpoint. | EndSession 是 RP 发起登出端点。
func (p *Provider) EndSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		writeError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed | 方法不允许")
		return
	}
	if err := r.ParseForm(); err != nil {
		badRequest(w, "invalid form | 表单非法")
		return
	}
	idTokenHint := r.Form.Get("id_token_hint")
	clientID := r.Form.Get("client_id")
	subject := ""
	sid := ""
	var client *oauth2.Client
	if idTokenHint != "" {
		verified, verifyErr := jose.VerifyContext(r.Context(), idTokenHint, p.keys.Resolver(), jose.VerifyOptions{})
		if verifyErr != nil || !verified.IsJSON() {
			badRequest(w, "id_token_hint is invalid | id_token_hint 无效")
			return
		}
		var claims Claims
		if err := json.Unmarshal(verified.Claims, &claims); err != nil {
			badRequest(w, "id_token_hint is invalid | id_token_hint 无效")
			return
		}
		if claims.Issuer != p.config.Issuer {
			badRequest(w, "id_token_hint issuer mismatch | id_token_hint 签发方不匹配")
			return
		}
		if clientID == "" {
			if len(claims.Audience) != 1 {
				badRequest(w, "client_id is required with a multi-audience id_token_hint | 多受众 id_token_hint 必须提供 client_id")
				return
			}
			clientID = claims.Audience[0]
		} else if !claims.Audience.Contains(clientID) {
			badRequest(w, "id_token_hint audience mismatch | id_token_hint 受众不匹配")
			return
		}
		subject = claims.Subject
		sid = claims.SID
	}
	if clientID == "" {
		badRequest(w, "client_id or id_token_hint is required | 需要 client_id 或 id_token_hint")
		return
	}
	client, err := p.oauth.Config().Clients.GetClient(r.Context(), clientID)
	if err != nil {
		badRequest(w, "unknown client | 未知客户端")
		return
	}
	redirectURI := r.Form.Get("post_logout_redirect_uri")
	if redirectURI != "" && !client.AllowsPostLogoutRedirect(redirectURI) {
		badRequest(w, "post_logout_redirect_uri is not registered | post_logout_redirect_uri 未注册")
		return
	}
	if p.config.Sessions != nil {
		if sid != "" {
			_ = p.config.Sessions.Revoke(r.Context(), sid, "rp_initiated_logout")
		} else if subject != "" {
			_, _ = p.config.Sessions.RevokeUser(r.Context(), subject, "rp_initiated_logout")
		}
	}
	if p.config.BackchannelLogout && (subject != "" || sid != "") {
		_ = p.NotifyBackchannelLogout(r.Context(), client, subject, sid)
	}
	if redirectURI != "" {
		location, err := url.Parse(redirectURI)
		if err != nil {
			badRequest(w, "invalid post_logout_redirect_uri | 登出重定向 URI 无效")
			return
		}
		if state := r.Form.Get("state"); state != "" {
			query := location.Query()
			query.Set("state", state)
			location.RawQuery = query.Encode()
		}
		http.Redirect(w, r, location.String(), http.StatusFound)
		return
	}
	writeLoggedOut(w)
}

// BackchannelLogout receives a back-channel logout token. The receiver acts as an RP and validates
// that the token iss equals ProviderConfig.BackchannelLogoutIssuer (defaulting to this provider's
// issuer) and that aud contains ProviderConfig.BackchannelLogoutClientID; tokens issued by another
// issuer or for another RP are rejected. Verification keys come from the configured back-channel
// key source. Without a configured client ID the endpoint fails closed instead of revoking
// sessions for any well-formed token. | BackchannelLogout 接收后端登出令牌。接收端以 RP 身份校验
// 令牌 iss 等于 ProviderConfig.BackchannelLogoutIssuer（默认使用本提供方签发方），且 aud 包含
// ProviderConfig.BackchannelLogoutClientID；由其他签发方签发或面向其他 RP 的令牌会被拒绝。
// 校验密钥来自配置的后端登出密钥来源。未配置 client ID 时端点按失败关闭处理，而不是为任何格式
// 正确的令牌撤销会话。
func (p *Provider) BackchannelLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed | 方法不允许")
		return
	}
	clientID := strings.TrimSpace(p.config.BackchannelLogoutClientID)
	if clientID == "" {
		writeError(w, http.StatusInternalServerError, "server_error", "back-channel logout receiver has no client_id | 后端登出接收端未配置 client_id")
		return
	}
	if err := r.ParseForm(); err != nil {
		badRequest(w, "invalid form | 表单非法")
		return
	}
	raw := r.Form.Get("logout_token")
	if raw == "" {
		badRequest(w, "logout_token is required | 必须提供 logout_token")
		return
	}
	issuer := p.backchannelIssuer
	if issuer == "" {
		issuer = p.config.Issuer
	}
	claims, err := p.ValidateLogoutToken(r.Context(), raw, issuer, clientID)
	if err != nil {
		badRequest(w, "logout_token is invalid | logout_token 无效")
		return
	}
	if p.config.Sessions != nil {
		if claims.SID != "" {
			_ = p.config.Sessions.Revoke(r.Context(), claims.SID, "backchannel_logout")
		} else if claims.Subject != "" {
			_, _ = p.config.Sessions.RevokeUser(r.Context(), claims.Subject, "backchannel_logout")
		}
	}
	w.WriteHeader(http.StatusOK)
}

// FrontchannelLogout renders the front-channel logout page for an RP. It requires GET, an iss
// that identifies this provider, and at least one of sid or sub. When the request carries a
// client_id or aud parameter, the handler requires it to identify
// ProviderConfig.FrontchannelLogoutClientID and rejects requests for another client; without a
// configured client ID the endpoint fails closed. OIDC Front-Channel Logout 1.0 defines neither a
// client_id nor an aud parameter, so a request without one is accepted because the registered
// frontchannel_logout_uri already binds it to this client. This handler does not revoke sessions:
// mapping sid or sub to a local session remains the caller's responsibility, and callers must
// verify that the identifier belongs to a session of the configured client. |
// FrontchannelLogout 为 RP 渲染前端登出页面。它要求 GET、iss 标识本提供方，且 sid 或 sub 至少
// 出现一个。请求携带 client_id 或 aud 参数时，处理器要求其标识
// ProviderConfig.FrontchannelLogoutClientID，并拒绝面向其他客户端的请求；未配置 client ID 时
// 端点按失败关闭处理。OIDC 前端登出 1.0 未定义 client_id 与 aud 参数，因此不带这些参数的请求会被
// 接受，因为已注册的 frontchannel_logout_uri 已将其绑定到此客户端。本处理器不撤销会话：sid 或
// sub 到本地会话的映射仍由调用方负责，调用方必须确认该标识属于配置客户端的会话。
func (p *Provider) FrontchannelLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed | 方法不允许")
		return
	}
	clientID := strings.TrimSpace(p.config.FrontchannelLogoutClientID)
	if clientID == "" {
		writeError(w, http.StatusInternalServerError, "server_error", "front-channel logout receiver has no client_id | 前端登出接收端未配置 client_id")
		return
	}
	query := r.URL.Query()
	issuer := query.Get("iss")
	sid := query.Get("sid")
	sub := query.Get("sub")
	if issuer == "" {
		badRequest(w, "iss is required | 必须提供 iss")
		return
	}
	if issuer != p.config.Issuer {
		badRequest(w, "iss is not this provider | iss 不是本提供方")
		return
	}
	if requested := strings.TrimSpace(query.Get("client_id")); requested != "" && requested != clientID {
		badRequest(w, "client_id is not this receiver | client_id 不是本接收端")
		return
	}
	if audience := query.Get("aud"); audience != "" && !frontchannelAudienceMatches(audience, clientID) {
		badRequest(w, "aud does not contain this receiver | aud 不包含本接收端")
		return
	}
	if sid == "" && sub == "" {
		badRequest(w, "sid or sub is required | 必须提供 sid 或 sub")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("<!doctype html><html><head><meta charset=\"utf-8\"><title>Logout</title></head><body>" +
		"<p>Logged out | 已登出</p><script>window.location.replace(" +
		quoteJS(issuer) + ");</script><p>iss=" + htmlstd.EscapeString(issuer) +
		" sid=" + htmlstd.EscapeString(sid) +
		" sub=" + htmlstd.EscapeString(sub) + "</p></body></html>"))
}

// frontchannelAudienceMatches reports whether a space- or comma-separated aud parameter contains
// clientID. | frontchannelAudienceMatches 报告以空格或逗号分隔的 aud 参数是否包含 clientID。
func frontchannelAudienceMatches(raw, clientID string) bool {
	for _, value := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ' ' || r == ',' || r == '\t'
	}) {
		if value == clientID {
			return true
		}
	}
	return false
}

// quoteJS quotes a string for a JavaScript literal without importing encoding/json. | quoteJS 把字符串
// 引用为 JavaScript 字面量而不导入 encoding/json。
func quoteJS(value string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range value {
		switch r {
		case '\\', '"':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '<', '>', '&':
			// Escaping these characters keeps </script> from terminating the surrounding
			// element. | 转义这些字符可防止 </script> 提前结束所在元素。
			b.WriteByte('\\')
			b.WriteRune(r)
		case 0x2028, 0x2029:
			// Line and paragraph separators terminate JavaScript string literals. | 行分隔符与
			// 段分隔符会终止 JavaScript 字符串字面量。
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// writeLoggedOut writes a minimal logged-out page. | writeLoggedOut 写入最小登出页面。
func writeLoggedOut(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("<!doctype html><html><head><meta charset=\"utf-8\"><title>Logged out</title></head><body><p>Logged out | 已登出</p></body></html>"))
}

// EndSessionURL builds an RP-initiated logout URL. | EndSessionURL 构建 RP 发起登出 URL。
func (p *Provider) EndSessionURL(clientID, postLogoutRedirectURI, state, idTokenHint string) string {
	endpoint := p.Endpoint(p.config.EndSessionPath)
	query := url.Values{}
	if clientID != "" {
		query.Set("client_id", clientID)
	}
	if postLogoutRedirectURI != "" {
		query.Set("post_logout_redirect_uri", postLogoutRedirectURI)
	}
	if state != "" {
		query.Set("state", state)
	}
	if idTokenHint != "" {
		query.Set("id_token_hint", idTokenHint)
	}
	if len(query) == 0 {
		return endpoint
	}
	return endpoint + "?" + query.Encode()
}

// EqualAudience reports whether audience equals value. | EqualAudience 报告 audience 是否等于 value。
func EqualAudience(audience Audience, value string) bool {
	if len(audience) != 1 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(audience[0]), []byte(value)) == 1
}
