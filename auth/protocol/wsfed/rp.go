package wsfed

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/auth/protocol/saml"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
	"github.com/shibingli/ydx/router"
)

// Defaults used by relying parties and token services. | 依赖方与令牌服务使用的默认值。
const (
	defaultClockSkew  = 2 * time.Minute
	defaultRequestTTL = 10 * time.Minute
	defaultReplyPath  = "/wsfed/reply"
)

// RequestState records an outstanding sign-in request. | RequestState 记录未完成的登录请求。
type RequestState struct {
	// Wctx is the correlation context. | Wctx 是关联上下文。
	Wctx string
	// Realm is the relying party realm that started the request. | Realm 是发起请求的依赖方领域。
	Realm string
	// ReplyURL is the reply URL that started the request. | ReplyURL 是发起请求的回复 URL。
	ReplyURL string
	// CreatedAt is the request creation time. | CreatedAt 是请求创建时间。
	CreatedAt time.Time
	// ExpiresAt is the request expiry time. | ExpiresAt 是请求过期时间。
	ExpiresAt time.Time
}

// RequestStore correlates sign-in responses with outstanding requests. | RequestStore 把登录响应与
// 未完成请求关联起来。
type RequestStore interface {
	// SaveRequest stores an outstanding request keyed by Wctx. | SaveRequest 按 Wctx 保存未完成请求。
	SaveRequest(ctx context.Context, state RequestState) error
	// TakeRequest atomically consumes a request and reports whether it was present and fresh. |
	// TakeRequest 原子消费请求，并报告是否存在且未过期。
	TakeRequest(ctx context.Context, wctx string) (RequestState, bool, error)
}

// MemoryRequestStore is a concurrency-safe in-memory RequestStore. | MemoryRequestStore 是并发安全的
// 内存 RequestStore。
type MemoryRequestStore struct {
	mu       sync.Mutex
	requests map[string]RequestState
}

// NewMemoryRequestStore returns an empty in-memory request store. | NewMemoryRequestStore 返回空内存请求存储。
func NewMemoryRequestStore() *MemoryRequestStore {
	return &MemoryRequestStore{requests: make(map[string]RequestState)}
}

// SaveRequest stores an outstanding request. | SaveRequest 保存未完成请求。
func (s *MemoryRequestStore) SaveRequest(ctx context.Context, state RequestState) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	state.Wctx = strings.TrimSpace(state.Wctx)
	if state.Wctx == "" {
		return errs.Detail(ErrInvalidRequest, "wctx is required | 需要 wctx")
	}
	now := time.Now()
	if state.CreatedAt.IsZero() {
		state.CreatedAt = now
	}
	if state.ExpiresAt.IsZero() {
		state.ExpiresAt = now.Add(defaultRequestTTL)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.requests == nil {
		s.requests = make(map[string]RequestState)
	}
	s.cleanupLocked(now)
	s.requests[state.Wctx] = state
	return nil
}

// TakeRequest consumes a request. | TakeRequest 消费请求。
func (s *MemoryRequestStore) TakeRequest(ctx context.Context, wctx string) (RequestState, bool, error) {
	if err := contextError(ctx); err != nil {
		return RequestState{}, false, err
	}
	wctx = strings.TrimSpace(wctx)
	if wctx == "" {
		return RequestState{}, false, nil
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.requests[wctx]
	if !ok {
		return RequestState{}, false, nil
	}
	delete(s.requests, wctx)
	s.cleanupLocked(now)
	if !state.ExpiresAt.IsZero() && !now.Before(state.ExpiresAt) {
		return RequestState{}, false, nil
	}
	return state, true, nil
}

// Len returns the number of stored requests. | Len 返回已保存请求数量。
func (s *MemoryRequestStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests)
}

// cleanupLocked removes expired requests. The caller must hold s.mu. | cleanupLocked 删除过期请求。
// 调用方必须持有 s.mu。
func (s *MemoryRequestStore) cleanupLocked(now time.Time) {
	for wctx, state := range s.requests {
		if !state.ExpiresAt.IsZero() && !now.Before(state.ExpiresAt) {
			delete(s.requests, wctx)
		}
	}
}

// contextError reports a canceled or expired context. | contextError 报告已取消或已过期的上下文。
func contextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return errs.Wrap(ctx.Err(), ErrInvalidRequest)
	default:
		return nil
	}
}

// JWTVerifier verifies a JWT bearer token and returns its principal, attributes and expiry. |
// JWTVerifier 校验 JWT 承载令牌并返回主体、属性与过期时间。
type JWTVerifier interface {
	// VerifyJWT verifies token for audience. | VerifyJWT 为 audience 校验 token。
	VerifyJWT(ctx context.Context, token, audience string) (*auth.Principal, map[string][]string, time.Time, error)
}

// JWTVerifierFunc adapts a function to JWTVerifier. | JWTVerifierFunc 把函数适配为 JWTVerifier。
type JWTVerifierFunc func(ctx context.Context, token, audience string) (*auth.Principal, map[string][]string, time.Time, error)

// VerifyJWT calls f. | VerifyJWT 调用 f。
func (f JWTVerifierFunc) VerifyJWT(ctx context.Context, token, audience string) (*auth.Principal, map[string][]string, time.Time, error) {
	if f == nil {
		return nil, nil, time.Time{}, errs.Detail(ErrUnsupported, "JWT verifier is not configured | 未配置 JWT 校验器")
	}
	return f(ctx, token, audience)
}

// RelyingPartyConfig configures a WS-Federation relying party. | RelyingPartyConfig 配置
// WS-Federation 依赖方。
type RelyingPartyConfig struct {
	// Realm is the relying party realm sent as wtrealm and required as the assertion audience. |
	// Realm 是作为 wtrealm 发送并作为断言受众要求的依赖方领域。
	Realm string
	// ReplyURL receives the WS-Trust response and constrains the subject confirmation recipient. |
	// ReplyURL 接收 WS-Trust 响应并约束主体确认接收方。
	ReplyURL string
	// IDPURL is the security token service sign-in endpoint. | IDPURL 是安全令牌服务登录端点。
	IDPURL string
	// Issuer pins the expected security-token-service issuer. When set, a SAML assertion must carry
	// exactly this issuer and a JWT principal must report it through Principal.Issuer. | Issuer 固定
	// 期望的安全令牌服务签发方。设置后 SAML 断言必须携带该签发方，JWT 主体必须通过 Principal.Issuer
	// 报告该签发方。
	Issuer string
	// SignOutURL is the security token service sign-out endpoint; it falls back to IDPURL. |
	// SignOutURL 是安全令牌服务登出端点；为空时回退到 IDPURL。
	SignOutURL string
	// TokenType is the expected token type; empty accepts SAML 2.0, SAML 1.1 and verified JWT. |
	// TokenType 是期望的令牌类型；为空时接受 SAML 2.0、SAML 1.1 与已校验 JWT。
	TokenType string
	// Store rejects replayed assertions and keeps sessions when used by an STS. | Store 拒绝重放
	// 断言，并在作为 STS 使用时保存会话。
	Store saml.Store
	// SignatureVerifier verifies assertion signatures. When set, unsigned tokens are rejected. |
	// SignatureVerifier 校验断言签名。设置后拒绝未签名令牌。
	SignatureVerifier saml.SignatureVerifier
	// RequireSigned requires a verifiable signature and therefore a SignatureVerifier. | RequireSigned
	// 要求可校验签名，因此需要 SignatureVerifier。
	RequireSigned bool
	// ClockSkew is the tolerated clock difference. | ClockSkew 是容忍的时钟差。
	ClockSkew time.Duration
	// AllowUnsolicited accepts responses without a matching outstanding request. | AllowUnsolicited
	// 接受没有匹配未完成请求的响应。
	AllowUnsolicited bool
	// NameIDFormat restricts the accepted subject NameID format when non-empty. | NameIDFormat 非空时
	// 限制接受的主体 NameID 格式。
	NameIDFormat string
	// RequestStore correlates sign-in responses; nil uses a MemoryRequestStore. | RequestStore 关联
	// 登录响应；为空时使用 MemoryRequestStore。
	RequestStore RequestStore
	// RequestTTL is the correlation lifetime. | RequestTTL 是关联寿命。
	RequestTTL time.Duration
	// JWTVerifier verifies JWT tokens; required when TokenType is JWT. | JWTVerifier 校验 JWT 令牌；
	// TokenType 为 JWT 时必需。
	JWTVerifier JWTVerifier
	// Now overrides the clock. | Now 替换时钟。
	Now func() time.Time
	// SuccessHandler receives a validated result; nil writes a small JSON body. | SuccessHandler
	// 接收已校验结果；空值写入小型 JSON 正文。
	SuccessHandler func(w http.ResponseWriter, r *http.Request, result *SignInResult)
	// ErrorHandler renders failures; nil writes a generic 400. | ErrorHandler 渲染失败；空值写入通用 400。
	ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)
	// ReplyPath is the local mount path for ReplyURL. | ReplyPath 是 ReplyURL 的本地挂载路径。
	ReplyPath string
}

// RelyingParty is a WS-Federation passive relying party. | RelyingParty 是 WS-Federation 被动依赖方。
type RelyingParty struct {
	config   RelyingPartyConfig
	store    saml.Store
	requests RequestStore
	now      func() time.Time
}

// SignInResult is a validated sign-in response. | SignInResult 是已校验的登录响应。
type SignInResult struct {
	// Principal is the authenticated principal. | Principal 是已认证主体。
	Principal *auth.Principal
	// Assertion is the validated SAML assertion, nil for JWT tokens. | Assertion 是已校验的 SAML 断言，
	// JWT 令牌时为 nil。
	Assertion *saml.Assertion
	// Attributes are the assertion or token attributes. | Attributes 是断言或令牌属性。
	Attributes map[string][]string
	// Wctx is the opaque context echoed by the token service. | Wctx 是令牌服务回显的不透明上下文。
	Wctx string
	// ExpiresAt is the token expiry. | ExpiresAt 是令牌过期时间。
	ExpiresAt time.Time
	// TokenType is the validated token type. | TokenType 是已校验令牌类型。
	TokenType string
}

// NewRelyingParty returns a relying party. | NewRelyingParty 返回依赖方。
func NewRelyingParty(config RelyingPartyConfig) (*RelyingParty, error) {
	config.Realm = strings.TrimSpace(config.Realm)
	config.ReplyURL = strings.TrimSpace(config.ReplyURL)
	config.IDPURL = strings.TrimSpace(config.IDPURL)
	config.SignOutURL = strings.TrimSpace(config.SignOutURL)
	config.Issuer = strings.TrimSpace(config.Issuer)
	if config.Realm == "" {
		return nil, errs.Detail(ErrInvalidConfig, "realm is required | 需要 realm")
	}
	if config.ReplyURL == "" {
		return nil, errs.Detail(ErrInvalidConfig, "reply URL is required | 需要回复 URL")
	}
	if err := validateEndpointURL("reply URL", config.ReplyURL); err != nil {
		return nil, err
	}
	if config.IDPURL != "" {
		if err := validateEndpointURL("IDP URL", config.IDPURL); err != nil {
			return nil, err
		}
	}
	if config.SignOutURL != "" {
		if err := validateEndpointURL("sign-out URL", config.SignOutURL); err != nil {
			return nil, err
		}
	}
	switch config.TokenType {
	case "", TokenTypeSAML20, TokenTypeSAML11:
	case TokenTypeJWT:
		if config.JWTVerifier == nil {
			return nil, errs.Detail(ErrInvalidConfig, "JWT token type requires a JWT verifier | JWT 令牌类型需要 JWT 校验器")
		}
	default:
		return nil, errs.Detail(ErrInvalidConfig, "unsupported token type %[1]q | 不支持的令牌类型 %[1]q", config.TokenType)
	}
	if config.RequireSigned && config.SignatureVerifier == nil {
		return nil, errs.Detail(ErrInvalidConfig, "RequireSigned needs a signature verifier | RequireSigned 需要签名校验器")
	}
	if config.ClockSkew <= 0 {
		config.ClockSkew = defaultClockSkew
	}
	if config.RequestTTL <= 0 {
		config.RequestTTL = defaultRequestTTL
	}
	if config.ReplyPath == "" {
		config.ReplyPath = defaultReplyPath
	}
	if !strings.HasPrefix(config.ReplyPath, "/") {
		config.ReplyPath = "/" + config.ReplyPath
	}
	store := config.Store
	if store == nil {
		store = saml.NewMemoryStore()
	}
	requests := config.RequestStore
	if requests == nil {
		requests = NewMemoryRequestStore()
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	return &RelyingParty{config: config, store: store, requests: requests, now: now}, nil
}

// Config returns the configuration. | Config 返回配置。
func (rp *RelyingParty) Config() RelyingPartyConfig { return rp.config }

// Store returns the assertion replay store. | Store 返回断言重放存储。
func (rp *RelyingParty) Store() saml.Store { return rp.store }

// Requests returns the pending-request store. | Requests 返回未完成请求存储。
func (rp *RelyingParty) Requests() RequestStore { return rp.requests }

// SignInURL builds a sign-in request URL and records its correlation state. | SignInURL 构建登录请求
// URL 并记录关联状态。
func (rp *RelyingParty) SignInURL(wctx string) (string, error) {
	if rp.config.IDPURL == "" {
		return "", errs.Detail(ErrInvalidConfig, "IDP URL is required for sign-in | 登录需要 IDP URL")
	}
	wctx = strings.TrimSpace(wctx)
	if wctx == "" && !rp.config.AllowUnsolicited {
		wctx = auth.NewID("wctx")
	}
	request := SignInRequest{
		WA:      ActionSignIn,
		Wtrealm: rp.config.Realm,
		Wreply:  rp.config.ReplyURL,
		Wctx:    wctx,
	}
	location, err := request.URL(rp.config.IDPURL)
	if err != nil {
		return "", err
	}
	if !rp.config.AllowUnsolicited && wctx != "" {
		now := rp.now().UTC()
		state := RequestState{
			Wctx:      wctx,
			Realm:     rp.config.Realm,
			ReplyURL:  rp.config.ReplyURL,
			CreatedAt: now,
			ExpiresAt: now.Add(rp.config.RequestTTL),
		}
		if err := rp.requests.SaveRequest(context.Background(), state); err != nil {
			return "", err
		}
	}
	return location, nil
}

// SignOutURL builds a sign-out request URL. | SignOutURL 构建登出请求 URL。
func (rp *RelyingParty) SignOutURL(wctx string) (string, error) {
	base := rp.config.SignOutURL
	if base == "" {
		base = rp.config.IDPURL
	}
	if base == "" {
		return "", errs.Detail(ErrInvalidConfig, "sign-out URL is required | 需要登出 URL")
	}
	request := SignOutRequest{
		WA:      ActionSignOut,
		Wtrealm: rp.config.Realm,
		Wreply:  rp.config.ReplyURL,
		Wctx:    strings.TrimSpace(wctx),
	}
	return request.URL(base)
}

// ParseSignInResponse parses and validates a sign-in response from wresult. | ParseSignInResponse
// 解析并校验 wresult 中的登录响应。
func (rp *RelyingParty) ParseSignInResponse(r *http.Request) (*SignInResult, error) {
	values, err := requestValues(r)
	if err != nil {
		return nil, err
	}
	wresult := strings.TrimSpace(values.Get(ParamWresult))
	if wresult == "" {
		return nil, errs.Detail(ErrNoToken, "wresult is missing | 缺少 wresult")
	}
	if len(wresult) > MaxRequestBytes {
		return nil, errs.Detail(ErrRequestTooLarge, "wresult exceeds %[1]d bytes | wresult 超过 %[1]d 字节", MaxRequestBytes)
	}
	collection, err := ParseWResultString(wresult)
	if err != nil {
		return nil, err
	}
	if err := checkResponseStatuses(collection.Responses); err != nil {
		return nil, err
	}
	response := collection.TokenResponse()
	if response == nil {
		return nil, errs.Detail(ErrNoToken, "wresult carries no security token | wresult 未携带安全令牌")
	}
	wctx := strings.TrimSpace(values.Get(ParamWctx))
	switch {
	case wctx == "":
		wctx = strings.TrimSpace(response.Wctx)
	case strings.TrimSpace(response.Wctx) != "" && !secureEqual(wctx, strings.TrimSpace(response.Wctx)):
		return nil, errs.Detail(ErrInvalidResponse, "wctx does not match the token response | wctx 与令牌响应不匹配")
	}
	if !rp.config.AllowUnsolicited {
		state, ok, err := rp.requests.TakeRequest(r.Context(), wctx)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errs.Detail(ErrUnsolicited, "no outstanding request for wctx | 没有匹配 wctx 的未完成请求")
		}
		if state.Realm != "" && !secureEqual(state.Realm, rp.config.Realm) {
			return nil, errs.Detail(ErrUnsolicited, "outstanding request realm mismatch | 未完成请求领域不匹配")
		}
		if state.ReplyURL != "" && !secureEqual(state.ReplyURL, rp.config.ReplyURL) {
			return nil, errs.Detail(ErrUnsolicited, "outstanding request reply URL mismatch | 未完成请求回复 URL 不匹配")
		}
	}
	token := response.RequestedSecurityToken
	actualType := token.TokenType()
	if actualType == "" {
		return nil, errs.Detail(ErrUnsupported, "unknown security token type | 未知安全令牌类型")
	}
	if err := rp.checkTokenType(response.TokenType, actualType); err != nil {
		return nil, err
	}
	if actualType == TokenTypeJWT {
		return rp.parseJWTResponse(r, token, response, wctx)
	}
	assertion, err := token.Assertion()
	if err != nil {
		return nil, err
	}
	if err := rp.validateAssertion(r, token.Raw(), assertion, response, wctx); err != nil {
		return nil, err
	}
	attributes := assertionAttributes(assertion)
	expiresAt, err := rp.assertionExpiry(assertion, response)
	if err != nil {
		return nil, err
	}
	principal := principalFromAssertion(assertion, attributes, rp.config.Realm, expiresAt)
	return &SignInResult{
		Principal:  principal,
		Assertion:  assertion,
		Attributes: attributes,
		Wctx:       wctx,
		ExpiresAt:  expiresAt,
		TokenType:  actualType,
	}, nil
}

// checkTokenType validates the response-declared and configured token types. | checkTokenType 校验
// 响应声明与配置的令牌类型。
func (rp *RelyingParty) checkTokenType(declared, actual string) error {
	if declared != "" && declared != actual {
		return errs.Detail(ErrInvalidResponse, "declared token type %[1]q does not match token %[2]q | 声明令牌类型 %[1]q 与令牌 %[2]q 不匹配", declared, actual)
	}
	if rp.config.TokenType != "" && rp.config.TokenType != actual {
		return errs.Detail(ErrInvalidResponse, "expected token type %[1]q, got %[2]q | 期望令牌类型 %[1]q，实际 %[2]q", rp.config.TokenType, actual)
	}
	return nil
}

// parseJWTResponse validates a JWT token response. | parseJWTResponse 校验 JWT 令牌响应。
func (rp *RelyingParty) parseJWTResponse(r *http.Request, token *RequestedSecurityToken, response *RequestSecurityTokenResponse, wctx string) (*SignInResult, error) {
	raw, ok := token.JWT()
	if !ok || raw == "" {
		return nil, errs.Detail(ErrNoToken, "JWT token is empty | JWT 令牌为空")
	}
	if rp.config.JWTVerifier == nil {
		return nil, errs.Detail(ErrUnsupported, "JWT verification is not configured | 未配置 JWT 校验")
	}
	principal, attributes, expiresAt, err := rp.config.JWTVerifier.VerifyJWT(r.Context(), raw, rp.config.Realm)
	if err != nil {
		return nil, errs.Wrap(err, ErrInvalidResponse)
	}
	if principal == nil {
		return nil, errs.Detail(ErrInvalidResponse, "JWT verifier returned no principal | JWT 校验器未返回主体")
	}
	if rp.config.Issuer != "" {
		issuer := strings.TrimSpace(principal.Issuer)
		if !secureEqual(issuer, rp.config.Issuer) {
			return nil, errs.Detail(ErrInvalidIssuer, "JWT issuer %[1]q does not match %[2]q | JWT 签发方 %[1]q 与 %[2]q 不匹配", issuer, rp.config.Issuer)
		}
	}
	if expiresAt.IsZero() && response.Lifetime != nil && response.Lifetime.Expires != "" {
		expiresAt, err = parseResponseTime(response.Lifetime.Expires, "lifetime expiry")
		if err != nil {
			return nil, err
		}
	}
	// A JWT without any expiry would create a session that never ends, so an explicit expiry from
	// the verifier or the WS-Trust lifetime is mandatory. The clock check is defense in depth for
	// verifiers that return an already expired timestamp. | 没有任何过期时间的 JWT 会产生永不过期的
	// 会话，因此校验器或 WS-Trust 生命周期必须给出明确过期时间。时钟检查用于防御返回已过期时间戳的
	// 校验器。
	if expiresAt.IsZero() {
		return nil, errs.Detail(ErrInvalidResponse, "JWT token has no expiry | JWT 令牌没有过期时间")
	}
	if !rp.now().UTC().Add(-rp.config.ClockSkew).Before(expiresAt) {
		return nil, errs.Detail(ErrResponseExpired, "JWT token expired at %[1]s | JWT 令牌于 %[1]s 过期", saml.FormatTime(expiresAt))
	}
	if principal.Audience == nil {
		principal.Audience = []string{rp.config.Realm}
	}
	return &SignInResult{
		Principal:  principal,
		Attributes: attributes,
		Wctx:       wctx,
		ExpiresAt:  expiresAt,
		TokenType:  TokenTypeJWT,
	}, nil
}

// validateAssertion validates signature, audience, recipient, lifetime, issue instant and replay. |
// validateAssertion 校验签名、受众、接收方、生命周期、签发时间与重放。
func (rp *RelyingParty) validateAssertion(r *http.Request, raw string, assertion *saml.Assertion, response *RequestSecurityTokenResponse, wctx string) error {
	if assertion == nil {
		return ErrNoToken
	}
	if assertion.Subject == nil || assertion.Subject.NameID == nil || strings.TrimSpace(assertion.Subject.NameID.Value) == "" {
		return errs.Detail(ErrInvalidResponse, "assertion subject is missing | 缺少断言主体")
	}
	if rp.config.NameIDFormat != "" && assertion.Subject.NameID.Format != "" &&
		!secureEqual(assertion.Subject.NameID.Format, rp.config.NameIDFormat) {
		return errs.Detail(ErrInvalidResponse, "NameID format %[1]q does not match %[2]q | NameID 格式 %[1]q 与 %[2]q 不匹配",
			assertion.Subject.NameID.Format, rp.config.NameIDFormat)
	}
	if rp.config.SignatureVerifier != nil {
		if assertion.Signature == nil {
			return errs.Detail(ErrInvalidSignature, "assertion is not signed | 断言未签名")
		}
		if err := rp.config.SignatureVerifier.VerifySignature(r.Context(), []byte(raw), assertion.ID); err != nil {
			return errs.WrapDetail(err, ErrInvalidSignature, "assertion %[1]q | 断言 %[1]q", assertion.ID)
		}
	} else if assertion.Signature != nil || rp.config.RequireSigned {
		// A signature that cannot be verified is never ignored, and RequireSigned is enforced even
		// when the constructor did not see a verifier. | 无法校验的签名绝不会被忽略；即使构造时未看到
		// 校验器，RequireSigned 仍会强制生效。
		return errs.Detail(ErrInvalidSignature, "assertion signature cannot be verified | 无法校验断言签名")
	}
	if rp.config.Issuer != "" {
		issuer := strings.TrimSpace(assertionIssuer(assertion))
		if !secureEqual(issuer, rp.config.Issuer) {
			return errs.Detail(ErrInvalidIssuer, "assertion issuer %[1]q does not match %[2]q | 断言签发方 %[1]q 与 %[2]q 不匹配", issuer, rp.config.Issuer)
		}
	}
	now := rp.now().UTC()
	skew := rp.config.ClockSkew
	if !audienceMatches(assertion.Conditions, rp.config.Realm) {
		return errs.Detail(ErrInvalidAudience, "assertion audience does not include %[1]q | 断言受众不包含 %[1]q", rp.config.Realm)
	}
	if assertion.Conditions != nil {
		if err := checkTimeWindow(assertion.Conditions.NotBefore, assertion.Conditions.NotOnOrAfter, now, skew); err != nil {
			return err
		}
	}
	if err := checkRecipient(assertion.Subject, rp.config.ReplyURL, now, skew); err != nil {
		return err
	}
	if err := checkIssueInstant(assertion.IssueInstant, now, skew); err != nil {
		return err
	}
	expiresAt, err := rp.assertionExpiry(assertion, response)
	if err != nil {
		return err
	}
	if !now.Add(-skew).Before(expiresAt) {
		return errs.Detail(ErrResponseExpired, "assertion expired at %[1]s | 断言于 %[1]s 过期", saml.FormatTime(expiresAt))
	}
	fresh, err := rp.store.SaveAssertion(r.Context(), assertion.ID, expiresAt.Add(skew), now)
	if err != nil {
		return errs.Wrap(err, ErrInvalidResponse)
	}
	if !fresh {
		return errs.Detail(ErrReplay, "assertion %[1]q was already used | 断言 %[1]q 已被使用", assertion.ID)
	}
	return nil
}

// assertionExpiry returns the earliest assertion or lifetime expiry. | assertionExpiry 返回断言或
// 生命周期中最早的过期时间。
func (rp *RelyingParty) assertionExpiry(assertion *saml.Assertion, response *RequestSecurityTokenResponse) (time.Time, error) {
	var expiry time.Time
	if assertion != nil && assertion.Conditions != nil && assertion.Conditions.NotOnOrAfter != "" {
		parsed, err := parseResponseTime(assertion.Conditions.NotOnOrAfter, "Conditions.NotOnOrAfter")
		if err != nil {
			return time.Time{}, err
		}
		expiry = parsed
	}
	if response != nil && response.Lifetime != nil && response.Lifetime.Expires != "" {
		parsed, err := parseResponseTime(response.Lifetime.Expires, "Lifetime.Expires")
		if err != nil {
			return time.Time{}, err
		}
		if expiry.IsZero() || parsed.Before(expiry) {
			expiry = parsed
		}
	}
	if expiry.IsZero() {
		return time.Time{}, errs.Detail(ErrInvalidResponse, "assertion has no expiry | 断言没有过期时间")
	}
	return expiry, nil
}

// ParseSignOutResponse validates a sign-out response from wresult. | ParseSignOutResponse 校验
// wresult 中的登出响应。
func (rp *RelyingParty) ParseSignOutResponse(r *http.Request) error {
	values, err := requestValues(r)
	if err != nil {
		return err
	}
	wresult := strings.TrimSpace(values.Get(ParamWresult))
	if wresult == "" {
		return nil
	}
	if len(wresult) > MaxRequestBytes {
		return errs.Detail(ErrRequestTooLarge, "wresult exceeds %[1]d bytes | wresult 超过 %[1]d 字节", MaxRequestBytes)
	}
	collection, err := ParseWResultString(wresult)
	if err != nil {
		return err
	}
	return checkResponseStatuses(collection.Responses)
}

// ReplyHandler handles the wreply endpoint. | ReplyHandler 处理 wreply 端点。
func (rp *RelyingParty) ReplyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	result, err := rp.ParseSignInResponse(r)
	if err != nil {
		if rp.config.ErrorHandler != nil {
			rp.config.ErrorHandler(w, r, err)
			return
		}
		http.Error(w, "wsfed sign-in rejected", http.StatusBadRequest)
		return
	}
	if rp.config.SuccessHandler != nil {
		rp.config.SuccessHandler(w, r, result)
		return
	}
	body, marshalErr := json.Marshal(map[string]string{
		"subject": result.Principal.Subject,
		"wctx":    result.Wctx,
	})
	if marshalErr != nil {
		http.Error(w, "wsfed sign-in succeeded", http.StatusOK)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// Register mounts the reply endpoint on a YD router. | Register 在 YD 路由上挂载回复端点。
func (rp *RelyingParty) Register(r *router.Router, prefix string) {
	if r == nil {
		return
	}
	path := joinPath(prefix, rp.config.ReplyPath)
	r.HandleRaw(http.MethodGet, path, rp.ReplyHandler)
	r.HandleRaw(http.MethodPost, path, rp.ReplyHandler)
}

// HTTPHandler returns a net/http handler for the reply endpoint. | HTTPHandler 返回回复端点的
// net/http 处理器。
func (rp *RelyingParty) HTTPHandler(prefix string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(joinPath(prefix, rp.config.ReplyPath), rp.ReplyHandler)
	return mux
}

// validateEndpointURL validates an absolute HTTP endpoint URL. | validateEndpointURL 校验绝对 HTTP 端点 URL。
func validateEndpointURL(name, value string) error {
	parsed, err := url.Parse(value)
	if err != nil {
		return errs.WrapDetail(err, ErrInvalidConfig, "%[1]s %[2]q | %[1]s %[2]q", name, value)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return errs.Detail(ErrInvalidConfig, "%s must be absolute | %s 必须是绝对 URL", name, name)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return errs.Detail(ErrInvalidConfig, "%s must use http or https | %s 必须使用 http 或 https", name, name)
	}
	return nil
}

// secureEqual compares two public protocol values in constant time. | secureEqual 以常量时间比较
// 两个公开协议值。
func secureEqual(a, b string) bool {
	return auth.SecureEqual(a, b)
}

// audienceMatches reports whether every audience restriction includes realm, as required by SAML
// intersection semantics. | audienceMatches 报告是否每个受众限制都包含 realm，符合 SAML 交集语义。
func audienceMatches(conditions *saml.Conditions, realm string) bool {
	if conditions == nil || len(conditions.AudienceRestriction) == 0 {
		return false
	}
	for _, restriction := range conditions.AudienceRestriction {
		matched := false
		for _, audience := range restriction.Audience {
			if secureEqual(strings.TrimSpace(audience), realm) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// checkTimeWindow validates a NotBefore/NotOnOrAfter pair with clock skew. | checkTimeWindow 结合
// 时钟偏移校验 NotBefore/NotOnOrAfter 组合。
func checkTimeWindow(notBefore, notOnOrAfter string, now time.Time, skew time.Duration) error {
	if notBefore != "" {
		parsed, err := parseResponseTime(notBefore, "NotBefore")
		if err != nil {
			return err
		}
		if now.Add(skew).Before(parsed) {
			return errs.Detail(ErrResponseNotYetValid, "assertion is not valid before %[1]s | 断言在 %[1]s 前无效", saml.FormatTime(parsed))
		}
	}
	if notOnOrAfter != "" {
		parsed, err := parseResponseTime(notOnOrAfter, "NotOnOrAfter")
		if err != nil {
			return err
		}
		if !now.Add(-skew).Before(parsed) {
			return errs.Detail(ErrResponseExpired, "assertion expired at %[1]s | 断言于 %[1]s 过期", saml.FormatTime(parsed))
		}
	}
	return nil
}

// saml11BearerMethod is the SAML 1.1 bearer confirmation method. | saml11BearerMethod 是 SAML 1.1
// 承载确认方法。
const saml11BearerMethod = "urn:oasis:names:tc:SAML:1.0:cm:bearer"

// checkRecipient validates the bearer confirmation recipient and window. Confirmations using any
// other method require proof of possession that the passive profile cannot verify, so a recipient
// carried by such a confirmation is never accepted. | checkRecipient 校验承载确认接收方与时间窗口。
// 其它方法的确认需要被动配置无法验证的持有证明，因此这类确认携带的接收方一律不接受。
func checkRecipient(subject *saml.Subject, replyURL string, now time.Time, skew time.Duration) error {
	if subject == nil || len(subject.SubjectConfirmation) == 0 {
		return nil
	}
	sawRecipient := false
	for index := range subject.SubjectConfirmation {
		confirmation := &subject.SubjectConfirmation[index]
		data := confirmation.SubjectConfirmationData
		if data == nil || data.Recipient == "" {
			continue
		}
		sawRecipient = true
		if confirmation.Method != saml.SubjectConfirmationBearer && confirmation.Method != saml11BearerMethod {
			continue
		}
		if !secureEqual(strings.TrimSpace(data.Recipient), replyURL) {
			continue
		}
		if err := checkTimeWindow(data.NotBefore, data.NotOnOrAfter, now, skew); err != nil {
			return err
		}
		return nil
	}
	if sawRecipient {
		return errs.Detail(ErrInvalidRecipient, "subject confirmation recipient does not match %[1]q | 主体确认接收方与 %[1]q 不匹配", replyURL)
	}
	return nil
}

// checkIssueInstant rejects assertions issued in the future. | checkIssueInstant 拒绝未来签发的断言。
func checkIssueInstant(value string, now time.Time, skew time.Duration) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	parsed, err := parseResponseTime(value, "IssueInstant")
	if err != nil {
		return err
	}
	if parsed.After(now.Add(skew)) {
		return errs.Detail(ErrResponseNotYetValid, "assertion issue time %[1]s is in the future | 断言签发时间 %[1]s 在未来", saml.FormatTime(parsed))
	}
	return nil
}

// parseResponseTime parses a SAML time and maps failures to ErrInvalidResponse. | parseResponseTime
// 解析 SAML 时间并把失败映射为 ErrInvalidResponse。
func parseResponseTime(value, field string) (time.Time, error) {
	parsed, err := saml.ParseTime(value)
	if err != nil {
		return time.Time{}, errs.WrapDetail(err, ErrInvalidResponse, "%[1]s %[2]q | %[1]s %[2]q", field, value)
	}
	return parsed, nil
}

// checkResponseStatuses rejects any non-success WS-Trust status. | checkResponseStatuses 拒绝任何
// 非成功 WS-Trust 状态。
func checkResponseStatuses(responses []RequestSecurityTokenResponse) error {
	for index := range responses {
		status := responses[index].Status
		if status == nil || status.Success() {
			continue
		}
		return errs.Detail(ErrStatusFailure, "wresult status %[1]q | wresult 状态 %[1]q", status.Code)
	}
	return nil
}

// assertionAttributes flattens SAML attribute statements. | assertionAttributes 展平 SAML 属性语句。
func assertionAttributes(assertion *saml.Assertion) map[string][]string {
	attributes := make(map[string][]string)
	if assertion == nil {
		return attributes
	}
	for _, statement := range assertion.AttributeStatement {
		for _, attribute := range statement.Attribute {
			name := strings.TrimSpace(attribute.Name)
			if name == "" {
				continue
			}
			for _, value := range attribute.AttributeValue {
				attributes[name] = append(attributes[name], value.Value)
			}
			if _, ok := attributes[name]; !ok {
				attributes[name] = []string{}
			}
		}
	}
	return attributes
}

// principalFromAssertion builds a principal from a validated assertion. | principalFromAssertion
// 从已校验断言构建主体。
func principalFromAssertion(assertion *saml.Assertion, attributes map[string][]string, realm string, expiresAt time.Time) *auth.Principal {
	principal := &auth.Principal{
		Subject:     saml.SubjectNameID(assertion.Subject),
		Issuer:      assertionIssuer(assertion),
		Audience:    []string{realm},
		Username:    firstAttribute(attributes, "username", "uid", "sAMAccountName", "urn:oid:0.9.2342.19200300.100.1.1"),
		Email:       firstAttribute(attributes, "email", "mail", "urn:oid:0.9.2342.19200300.100.1.3"),
		DisplayName: firstAttribute(attributes, "displayName", "cn", "name", "urn:oid:2.16.840.1.113730.3.1.241"),
		Groups:      append([]string(nil), attributes["groups"]...),
		AMR:         []string{"wsfed"},
		Attributes:  flattenAttributes(attributes),
		ExpiresAt:   expiresAt,
	}
	if len(principal.Groups) == 0 {
		principal.Groups = append(principal.Groups, attributes["memberOf"]...)
	}
	if len(principal.Groups) == 0 {
		principal.Groups = append(principal.Groups, attributes["urn:oid:1.3.6.1.4.1.5923.1.5.1.1"]...)
	}
	if assertion.Subject != nil && assertion.Subject.NameID != nil {
		principal.ACR = assertion.Subject.NameID.Format
	}
	if parsed, err := saml.ParseTime(assertion.IssueInstant); err == nil {
		principal.IssuedAt = parsed
	}
	if len(assertion.AuthnStatement) > 0 {
		statement := assertion.AuthnStatement[0]
		principal.SessionID = statement.SessionIndex
		if statement.AuthnInstant != "" {
			if parsed, err := saml.ParseTime(statement.AuthnInstant); err == nil {
				principal.AuthTime = parsed
			}
		}
		if statement.AuthnContext != nil && statement.AuthnContext.AuthnContextClassRef != "" {
			principal.ACR = statement.AuthnContext.AuthnContextClassRef
		}
	}
	return principal
}

// assertionIssuer returns the assertion issuer value. | assertionIssuer 返回断言签发方取值。
func assertionIssuer(assertion *saml.Assertion) string {
	if assertion != nil && assertion.Issuer != nil {
		return assertion.Issuer.Value
	}
	return ""
}

// firstAttribute returns the first value among names. | firstAttribute 返回 names 中的第一个取值。
func firstAttribute(attributes map[string][]string, names ...string) string {
	for _, name := range names {
		if values := attributes[name]; len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

// flattenAttributes keeps the first value of every attribute as a principal attribute. |
// flattenAttributes 把每个属性的第一个取值保留为主体属性。
func flattenAttributes(attributes map[string][]string) map[string]string {
	if len(attributes) == 0 {
		return nil
	}
	out := make(map[string]string, len(attributes))
	for key, values := range attributes {
		if len(values) > 0 {
			out[key] = values[0]
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
