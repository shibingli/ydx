package wsfed

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/auth/protocol/saml"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/router"
	"github.com/shibingli/ydx/xml"
)

// Default STS paths and lifetimes. | 默认 STS 路径与生命周期。
const (
	defaultSignInPath   = "/wsfed/signin"
	defaultSignOutPath  = "/wsfed/signout"
	defaultMetadataPath = "/wsfed/metadata"
)

// Authenticator resolves the browser user for a sign-in request. request is nil during sign-out. |
// Authenticator 为登录请求解析浏览器用户。登出期间 request 为 nil。
type Authenticator interface {
	// Authenticate returns the current principal or ErrLoginRequired. | Authenticate 返回当前主体或
	// ErrLoginRequired。
	Authenticate(ctx context.Context, w http.ResponseWriter, r *http.Request, request *SignInRequest) (*auth.Principal, error)
}

// AuthenticatorFunc adapts a function to Authenticator. | AuthenticatorFunc 把函数适配为 Authenticator。
type AuthenticatorFunc func(ctx context.Context, w http.ResponseWriter, r *http.Request, request *SignInRequest) (*auth.Principal, error)

// Authenticate calls f. | Authenticate 调用 f。
func (f AuthenticatorFunc) Authenticate(ctx context.Context, w http.ResponseWriter, r *http.Request, request *SignInRequest) (*auth.Principal, error) {
	if f == nil {
		return nil, ErrLoginRequired
	}
	return f(ctx, w, r, request)
}

// AdaptAuthenticator adapts a saml.Authenticator by mapping the sign-in request to a minimal SAML
// AuthnRequest. | AdaptAuthenticator 把 saml.Authenticator 适配为本地接口，将登录请求映射为最小
// SAML AuthnRequest。
func AdaptAuthenticator(authenticator saml.Authenticator) Authenticator {
	if authenticator == nil {
		return nil
	}
	return AuthenticatorFunc(func(ctx context.Context, w http.ResponseWriter, r *http.Request, request *SignInRequest) (*auth.Principal, error) {
		authnRequest := &saml.AuthnRequest{}
		if request != nil {
			authnRequest.Issuer = &saml.Issuer{Value: request.Wtrealm}
			authnRequest.AssertionConsumerServiceURL = request.Wreply
		}
		return authenticator.Authenticate(ctx, w, r, authnRequest)
	})
}

// RealmResolver validates a relying party realm and may return a canonical reply URL. | RealmResolver
// 校验依赖方领域，并可返回规范回复 URL。
type RealmResolver interface {
	// ResolveRealm validates realm and replyURL and returns the reply URL to use. | ResolveRealm 校验
	// realm 与 replyURL 并返回使用的回复 URL。
	ResolveRealm(ctx context.Context, realm, replyURL string) (string, error)
}

// RealmResolverFunc adapts a function to RealmResolver. | RealmResolverFunc 把函数适配为 RealmResolver。
type RealmResolverFunc func(ctx context.Context, realm, replyURL string) (string, error)

// ResolveRealm calls f. | ResolveRealm 调用 f。
func (f RealmResolverFunc) ResolveRealm(ctx context.Context, realm, replyURL string) (string, error) {
	if f == nil {
		return replyURL, nil
	}
	return f(ctx, realm, replyURL)
}

// JWTIssuer issues JWT tokens for a principal. | JWTIssuer 为主体签发 JWT 令牌。
type JWTIssuer interface {
	// IssueJWT returns a signed JWT and its expiry. | IssueJWT 返回已签名 JWT 及其过期时间。
	IssueJWT(ctx context.Context, principal *auth.Principal, audience string, ttl time.Duration) (string, time.Time, error)
}

// JWTIssuerFunc adapts a function to JWTIssuer. | JWTIssuerFunc 把函数适配为 JWTIssuer。
type JWTIssuerFunc func(ctx context.Context, principal *auth.Principal, audience string, ttl time.Duration) (string, time.Time, error)

// IssueJWT calls f. | IssueJWT 调用 f。
func (f JWTIssuerFunc) IssueJWT(ctx context.Context, principal *auth.Principal, audience string, ttl time.Duration) (string, time.Time, error) {
	if f == nil {
		return "", time.Time{}, errs.Detail(ErrUnsupported, "JWT issuer is not configured | 未配置 JWT 签发器")
	}
	return f(ctx, principal, audience, ttl)
}

// STSConfig configures a WS-Federation security token service. | STSConfig 配置 WS-Federation 安全令牌服务。
type STSConfig struct {
	// Issuer is the token service entity ID and issuer. | Issuer 是令牌服务实体标识与签发方。
	Issuer string
	// SignInPath, SignOutPath and MetadataPath are endpoint paths or absolute URLs. | SignInPath、
	// SignOutPath 与 MetadataPath 是端点路径或绝对 URL。
	SignInPath   string
	SignOutPath  string
	MetadataPath string
	// Authenticator resolves the current browser user. | Authenticator 解析当前浏览器用户。
	Authenticator Authenticator
	// AttributeMapper maps the principal to assertion attributes. | AttributeMapper 把主体映射为断言属性。
	AttributeMapper saml.AttributeMapper
	// Signer signs assertions and optionally responses. | Signer 签名断言并可选签名响应。
	Signer saml.XMLSigner
	// Store persists sessions and optionally incoming signed tokens. | Store 持久化会话，并可保存传入的
	// 已签名令牌。
	Store saml.Store
	// SignatureVerifier verifies signed wresult values supplied to the STS. | SignatureVerifier 校验
	// 提供给 STS 的已签名 wresult 取值。
	SignatureVerifier saml.SignatureVerifier
	// AllowedRealms is the relying party realm allow-list; empty allows every realm. | AllowedRealms 是
	// 依赖方领域允许列表；为空时允许所有领域。
	AllowedRealms []string
	// RealmResolver provides dynamic realm validation and reply URL resolution. | RealmResolver 提供
	// 动态领域校验与回复 URL 解析。
	RealmResolver RealmResolver
	// TokenType is the issued token type; zero means SAML 2.0. | TokenType 是已签发令牌类型；零值表示
	// SAML 2.0。
	TokenType string
	// TokenTTL is the assertion lifetime. | TokenTTL 是断言寿命。
	TokenTTL time.Duration
	// SessionTTL is the IdP session lifetime. | SessionTTL 是 IdP 会话寿命。
	SessionTTL time.Duration
	// ClockSkew is the tolerated clock difference. | ClockSkew 是容忍的时钟差。
	ClockSkew time.Duration
	// NameIDFormat is the issued NameID format. | NameIDFormat 是已签发 NameID 格式。
	NameIDFormat string
	// SignResponse signs the WS-Trust response collection in addition to the assertion. | SignResponse
	// 除断言外还签名 WS-Trust 响应集合。
	SignResponse bool
	// JWTIssuer issues JWT tokens when TokenType is JWT. | TokenType 为 JWT 时 JWTIssuer 签发 JWT 令牌。
	JWTIssuer JWTIssuer
	// Now overrides the clock. | Now 替换时钟。
	Now func() time.Time
	// LoginURL receives unauthenticated browsers. | LoginURL 接收未认证浏览器。
	LoginURL string
	// LoginHandler renders a login page instead of redirecting. | LoginHandler 渲染登录页而不是重定向。
	LoginHandler http.HandlerFunc
	// ErrorHandler renders failures; nil writes a WS-Federation fault. | ErrorHandler 渲染失败；空值写入
	// WS-Federation 故障。
	ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)
}

// SecurityTokenService is a WS-Federation passive security token service. | SecurityTokenService 是
// WS-Federation 被动安全令牌服务。
type SecurityTokenService struct {
	config      STSConfig
	store       saml.Store
	now         func() time.Time
	signInURL   string
	signOutURL  string
	metadataURL string
}

// NewSecurityTokenService returns a security token service. | NewSecurityTokenService 返回安全令牌服务。
func NewSecurityTokenService(config STSConfig) (*SecurityTokenService, error) {
	config.Issuer = strings.TrimSpace(config.Issuer)
	config.LoginURL = strings.TrimSpace(config.LoginURL)
	if config.Issuer == "" {
		return nil, errs.Detail(ErrInvalidConfig, "issuer is required | 需要 issuer")
	}
	if config.Authenticator == nil {
		return nil, errs.Detail(ErrInvalidConfig, "authenticator is required | 需要认证器")
	}
	switch config.TokenType {
	case "":
		config.TokenType = TokenTypeSAML20
	case TokenTypeSAML20, TokenTypeSAML11:
	case TokenTypeJWT:
		if config.JWTIssuer == nil {
			return nil, errs.Detail(ErrInvalidConfig, "JWT token type requires a JWT issuer | JWT 令牌类型需要 JWT 签发器")
		}
	default:
		return nil, errs.Detail(ErrInvalidConfig, "unsupported token type %[1]q | 不支持的令牌类型 %[1]q", config.TokenType)
	}
	if config.SignResponse && config.Signer == nil {
		return nil, errs.Detail(ErrInvalidConfig, "SignResponse needs a signer | SignResponse 需要签名器")
	}
	if config.AttributeMapper == nil {
		config.AttributeMapper = saml.DefaultAttributeMapper{}
	}
	if config.TokenTTL <= 0 {
		config.TokenTTL = 5 * time.Minute
	}
	if config.SessionTTL <= 0 {
		config.SessionTTL = 8 * time.Hour
	}
	if config.ClockSkew <= 0 {
		config.ClockSkew = defaultClockSkew
	}
	if config.NameIDFormat == "" {
		config.NameIDFormat = saml.NameIDUnspecified
	}
	store := config.Store
	if store == nil {
		store = saml.NewMemoryStore()
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	signInURL := endpointURL(config.Issuer, config.SignInPath, defaultSignInPath)
	signOutURL := endpointURL(config.Issuer, config.SignOutPath, defaultSignOutPath)
	metadataURL := endpointURL(config.Issuer, config.MetadataPath, defaultMetadataPath)
	config.SignInPath = localPath(config.SignInPath, defaultSignInPath)
	config.SignOutPath = localPath(config.SignOutPath, defaultSignOutPath)
	config.MetadataPath = localPath(config.MetadataPath, defaultMetadataPath)
	return &SecurityTokenService{
		config:      config,
		store:       store,
		now:         now,
		signInURL:   signInURL,
		signOutURL:  signOutURL,
		metadataURL: metadataURL,
	}, nil
}

// Config returns the configuration. | Config 返回配置。
func (sts *SecurityTokenService) Config() STSConfig { return sts.config }

// Store returns the session store. | Store 返回会话存储。
func (sts *SecurityTokenService) Store() saml.Store { return sts.store }

// SignInURL returns the public sign-in endpoint URL. | SignInURL 返回公开登录端点 URL。
func (sts *SecurityTokenService) SignInURL() string { return sts.signInURL }

// SignOutURL returns the public sign-out endpoint URL. | SignOutURL 返回公开登出端点 URL。
func (sts *SecurityTokenService) SignOutURL() string { return sts.signOutURL }

// MetadataURL returns the public metadata endpoint URL. | MetadataURL 返回公开元数据端点 URL。
func (sts *SecurityTokenService) MetadataURL() string { return sts.metadataURL }

// HandleSignIn handles wa=wsignin1.0. | HandleSignIn 处理 wa=wsignin1.0。
func (sts *SecurityTokenService) HandleSignIn(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	values, err := requestValues(r)
	if err != nil {
		sts.fail(w, r, err)
		return
	}
	request, err := signInRequestFromValues(values)
	if err != nil {
		sts.fail(w, r, err)
		return
	}
	if err := sts.verifyIncomingToken(r, values); err != nil {
		sts.fail(w, r, err)
		return
	}
	replyURL, err := sts.resolveRealm(r, request.Wtrealm, request.Wreply)
	if err != nil {
		sts.fail(w, r, err)
		return
	}
	if replyURL == "" {
		sts.fail(w, r, errs.Detail(ErrInvalidRequest, "wreply is missing | 缺少 wreply"))
		return
	}
	principal, err := sts.config.Authenticator.Authenticate(r.Context(), w, r, request)
	if err != nil {
		if errors.Is(err, ErrLoginRequired) || errors.Is(err, saml.ErrLoginRequired) {
			sts.login(w, r)
			return
		}
		sts.fail(w, r, err)
		return
	}
	if principal == nil {
		sts.login(w, r)
		return
	}
	now := sts.now().UTC()
	expiresAt := now.Add(sts.config.TokenTTL)
	assertionID, tokenXML, sessionID, sessionNameID, attributes, tokenExpiry, err := sts.issueToken(r.Context(), principal, request, replyURL, now, expiresAt)
	if err != nil {
		sts.fail(w, r, err)
		return
	}
	if err := sts.saveSession(r.Context(), request.Wtrealm, sessionID, sessionNameID, attributes, now); err != nil {
		sts.fail(w, r, err)
		return
	}
	response := sts.tokenResponse(request, replyURL, assertionID, tokenXML, now, tokenExpiry)
	data, err := sts.marshalCollection(response)
	if err != nil {
		sts.fail(w, r, err)
		return
	}
	fields := [][2]string{{ParamWresult, string(data)}}
	if request.Wctx != "" {
		fields = append(fields, [2]string{ParamWctx, request.Wctx})
	}
	postForm(w, replyURL, fields)
}

// issueToken builds the issued token, returning its reference ID, XML, session index, attributes and
// the actual token expiry. The expiry can differ from expiresAt when a JWT issuer picks its own. |
// issueToken 构建已签发令牌，返回其引用 ID、XML、会话索引、属性与实际令牌过期时间。JWT 签发器自行
// 选择过期时间时，该值可能与 expiresAt 不同。
func (sts *SecurityTokenService) issueToken(ctx context.Context, principal *auth.Principal, request *SignInRequest, replyURL string, now, expiresAt time.Time) (string, string, string, string, map[string][]string, time.Time, error) {
	attributes, err := sts.config.AttributeMapper.MapAttributes(ctx, principal)
	if err != nil {
		return "", "", "", "", nil, time.Time{}, errs.Wrap(err, ErrInvalidResponse)
	}
	attributeMap := saml.AttributeMap([]saml.AttributeStatement{{Attribute: attributes}})
	if sts.config.TokenType == TokenTypeJWT {
		raw, jwtExpiry, err := sts.config.JWTIssuer.IssueJWT(ctx, principal, request.Wtrealm, sts.config.TokenTTL)
		if err != nil {
			return "", "", "", "", nil, time.Time{}, errs.Wrap(err, ErrUnsupported)
		}
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return "", "", "", "", nil, time.Time{}, errs.Detail(ErrNoToken, "JWT issuer returned an empty token | JWT 签发器返回空令牌")
		}
		if !jwtExpiry.IsZero() {
			expiresAt = jwtExpiry
		}
		return "", raw, "", "", attributeMap, expiresAt, nil
	}
	nameID, err := saml.NameIDForPrincipal(principal, sts.config.NameIDFormat)
	if err != nil {
		return "", "", "", "", nil, time.Time{}, errs.Wrap(err, ErrInvalidRequest)
	}
	sessionID := auth.NewID("sess")
	notBefore := now.Add(-sts.config.ClockSkew)
	switch sts.config.TokenType {
	case TokenTypeSAML11:
		assertion := buildSAML11Assertion(sts.config.Issuer, nameID, principal, sessionID, request.Wtrealm, now, notBefore, expiresAt, attributes)
		data, err := xml.Marshal(assertion)
		if err != nil {
			return "", "", "", "", nil, time.Time{}, errs.Wrap(err, ErrInvalidResponse)
		}
		if sts.config.Signer != nil {
			data, err = sts.config.Signer.SignElement(data, assertion.AssertionID)
			if err != nil {
				return "", "", "", "", nil, time.Time{}, errs.Wrap(err, ErrInvalidSignature)
			}
		}
		return assertion.AssertionID, string(data), sessionID, nameID.Value, attributeMap, expiresAt, nil
	default:
		assertion := buildSAML20Assertion(sts.config.Issuer, nameID, principal, sessionID, request.Wtrealm, replyURL, now, notBefore, expiresAt, sts.config.SessionTTL, attributes)
		data, err := xml.Marshal(assertion)
		if err != nil {
			return "", "", "", "", nil, time.Time{}, errs.Wrap(err, ErrInvalidResponse)
		}
		if sts.config.Signer != nil {
			data, err = sts.config.Signer.SignElement(data, assertion.ID)
			if err != nil {
				return "", "", "", "", nil, time.Time{}, errs.Wrap(err, ErrInvalidSignature)
			}
		}
		return assertion.ID, string(data), sessionID, nameID.Value, attributeMap, expiresAt, nil
	}
}

// buildSAML20Assertion builds a SAML 2.0 bearer assertion. | buildSAML20Assertion 构建 SAML 2.0
// 承载断言。
func buildSAML20Assertion(issuer string, nameID *saml.NameID, principal *auth.Principal, sessionID, realm, replyURL string, now, notBefore, expiresAt time.Time, sessionTTL time.Duration, attributes []saml.Attribute) *saml.Assertion {
	authnInstant := principal.AuthTime
	if authnInstant.IsZero() {
		authnInstant = now
	}
	contextClass := principal.ACR
	if contextClass == "" {
		contextClass = saml.AuthnContextUnspecified
	}
	assertion := &saml.Assertion{
		ID:           auth.NewID("assertion"),
		IssueInstant: saml.FormatTime(now),
		Version:      saml.Version,
		Issuer:       &saml.Issuer{Value: issuer},
		Subject: &saml.Subject{
			NameID: nameID,
			SubjectConfirmation: []saml.SubjectConfirmation{{
				Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
				SubjectConfirmationData: &saml.SubjectConfirmationData{
					NotOnOrAfter: saml.FormatTime(expiresAt),
					Recipient:    replyURL,
				},
			}},
		},
		Conditions: &saml.Conditions{
			NotBefore:           saml.FormatTime(notBefore),
			NotOnOrAfter:        saml.FormatTime(expiresAt),
			AudienceRestriction: []saml.AudienceRestriction{{Audience: []string{realm}}},
		},
		AuthnStatement: []saml.AuthnStatement{{
			AuthnInstant:        saml.FormatTime(authnInstant),
			SessionIndex:        sessionID,
			SessionNotOnOrAfter: saml.FormatTime(now.Add(sessionTTL)),
			AuthnContext:        &saml.AuthnContext{AuthnContextClassRef: contextClass},
		}},
	}
	if len(attributes) > 0 {
		assertion.AttributeStatement = []saml.AttributeStatement{{Attribute: attributes}}
	}
	return assertion
}

// buildSAML11Assertion builds a SAML 1.1 bearer assertion. | buildSAML11Assertion 构建 SAML 1.1
// 承载断言。
func buildSAML11Assertion(issuer string, nameID *saml.NameID, principal *auth.Principal, sessionID, realm string, now, notBefore, expiresAt time.Time, attributes []saml.Attribute) *SAML11Assertion {
	authnInstant := principal.AuthTime
	if authnInstant.IsZero() {
		authnInstant = now
	}
	contextClass := principal.ACR
	if contextClass == "" {
		contextClass = saml.AuthnContextUnspecified
	}
	subject := &SAML11Subject{
		NameIdentifier: &SAML11NameIdentifier{
			Format: nameID.Format,
			Value:  nameID.Value,
		},
		SubjectConfirmation: []SAML11SubjectConfirmation{{
			ConfirmationMethod: []string{"urn:oasis:names:tc:SAML:1.0:cm:bearer"},
		}},
	}
	assertion := &SAML11Assertion{
		AssertionID:  auth.NewID("assertion"),
		Issuer:       issuer,
		IssueInstant: saml.FormatTime(now),
		MajorVersion: "1",
		MinorVersion: "1",
		Conditions: &SAML11Conditions{
			NotBefore:                    saml.FormatTime(notBefore),
			NotOnOrAfter:                 saml.FormatTime(expiresAt),
			AudienceRestrictionCondition: []SAML11AudienceRestriction{{Audience: []string{realm}}},
		},
		AuthenticationStatement: []SAML11AuthenticationStatement{{
			AuthenticationInstant: saml.FormatTime(authnInstant),
			AuthenticationMethod:  contextClass,
			Subject:               subject,
		}},
	}
	if len(attributes) > 0 {
		statement := SAML11AttributeStatement{Subject: subject}
		for _, attribute := range attributes {
			statement.Attribute = append(statement.Attribute, SAML11Attribute{
				AttributeName:      attribute.Name,
				AttributeNamespace: attribute.NameFormat,
				AttributeValue:     saml.AttributeValues(attribute),
			})
		}
		assertion.AttributeStatement = []SAML11AttributeStatement{statement}
	}
	return assertion
}

// tokenResponse wraps tokenXML in a WS-Trust response collection. | tokenResponse 把 tokenXML 包装进
// WS-Trust 响应集合。
func (sts *SecurityTokenService) tokenResponse(request *SignInRequest, replyURL, tokenID, tokenXML string, now, expiresAt time.Time) *RequestSecurityTokenResponseCollection {
	referenceValueType := ""
	switch sts.config.TokenType {
	case TokenTypeSAML20:
		referenceValueType = ValueTypeSAMLV20
	case TokenTypeSAML11:
		referenceValueType = ValueTypeSAMLV11
	}
	response := RequestSecurityTokenResponse{
		ID:          auth.NewID("rstr"),
		Context:     request.Wctx,
		TokenType:   sts.config.TokenType,
		RequestType: RequestTypeIssue,
		AppliesTo: &AppliesTo{
			EndpointReference: EndpointReference{Address: request.Wtrealm},
		},
		Lifetime: &Lifetime{
			Created: saml.FormatTime(now),
			Expires: saml.FormatTime(expiresAt),
		},
		RequestedSecurityToken: &RequestedSecurityToken{InnerXML: tokenXML},
	}
	if tokenID != "" && referenceValueType != "" {
		response.RequestedAttachedReference = NewAttachedReference(tokenID, referenceValueType)
		response.RequestedUnattachedReference = NewUnattachedReference(tokenID, referenceValueType)
	}
	return &RequestSecurityTokenResponseCollection{
		ID:        auth.NewID("rstrc"),
		Responses: []RequestSecurityTokenResponse{response},
	}
}

// marshalCollection serializes and optionally signs a response collection. | marshalCollection 序列化
// 并可选签名响应集合。
func (sts *SecurityTokenService) marshalCollection(collection *RequestSecurityTokenResponseCollection) ([]byte, error) {
	data, err := collection.Marshal()
	if err != nil {
		return nil, err
	}
	if sts.config.SignResponse && sts.config.Signer != nil && collection.ID != "" {
		signed, err := sts.config.Signer.SignElement(data, collection.ID)
		if err != nil {
			return nil, errs.Wrap(err, ErrInvalidSignature)
		}
		data = signed
	}
	return data, nil
}

// saveSession stores an IdP session for sign-out. | saveSession 保存用于登出的 IdP 会话。
func (sts *SecurityTokenService) saveSession(ctx context.Context, realm, sessionID, nameID string, attributes map[string][]string, now time.Time) error {
	if sessionID == "" || nameID == "" {
		return nil
	}
	session := &saml.Session{
		ID:          sessionID,
		NameID:      nameID,
		SPEntityID:  realm,
		IDPEntityID: sts.config.Issuer,
		CreatedAt:   now,
		ExpiresAt:   now.Add(sts.config.SessionTTL),
		Attributes:  attributes,
	}
	if err := sts.store.SaveSession(ctx, session); err != nil {
		return errs.Wrap(err, ErrInvalidResponse)
	}
	return nil
}

// HandleSignOut handles wa=wsignout1.0 and wa=wsignoutcleanup1.0. | HandleSignOut 处理
// wa=wsignout1.0 与 wa=wsignoutcleanup1.0。
func (sts *SecurityTokenService) HandleSignOut(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	values, err := requestValues(r)
	if err != nil {
		sts.fail(w, r, err)
		return
	}
	request, err := signOutRequestFromValues(values)
	if err != nil {
		sts.fail(w, r, err)
		return
	}
	if err := sts.verifyIncomingToken(r, values); err != nil {
		sts.fail(w, r, err)
		return
	}
	if request.Wtrealm != "" {
		if _, err := sts.resolveRealm(r, request.Wtrealm, request.Wreply); err != nil {
			sts.fail(w, r, err)
			return
		}
	}
	if principal, authErr := sts.config.Authenticator.Authenticate(r.Context(), w, r, nil); authErr == nil && principal != nil {
		sts.deleteSessions(r.Context(), principal)
	}
	if request.WA == ActionSignOutCleanup || request.Wreply == "" {
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		return
	}
	collection := NewSignOutCollection(request.Wctx)
	collection.ID = auth.NewID("rstrc")
	data, err := sts.marshalCollection(collection)
	if err != nil {
		sts.fail(w, r, err)
		return
	}
	fields := [][2]string{{ParamWresult, string(data)}}
	if request.Wctx != "" {
		fields = append(fields, [2]string{ParamWctx, request.Wctx})
	}
	postForm(w, request.Wreply, fields)
}

// deleteSessions removes every known session of principal. | deleteSessions 删除 principal 的所有已知会话。
func (sts *SecurityTokenService) deleteSessions(ctx context.Context, principal *auth.Principal) {
	if principal == nil {
		return
	}
	if principal.SessionID != "" {
		_ = sts.store.DeleteSession(ctx, principal.SessionID)
	}
	names := []string{principal.Subject, principal.Email, principal.Username}
	seen := make(map[string]struct{})
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		sessions, err := sts.store.ListSessions(ctx, name)
		if err != nil {
			continue
		}
		for _, session := range sessions {
			if session == nil || session.ID == "" {
				continue
			}
			_ = sts.store.DeleteSession(ctx, session.ID)
		}
	}
}

// verifyIncomingToken verifies a signed wresult supplied to the STS when a verifier is configured. |
// verifyIncomingToken 在配置校验器时校验提供给 STS 的已签名 wresult。
func (sts *SecurityTokenService) verifyIncomingToken(r *http.Request, values url.Values) error {
	if sts.config.SignatureVerifier == nil {
		return nil
	}
	wresult := strings.TrimSpace(values.Get(ParamWresult))
	if wresult == "" {
		return nil
	}
	collection, err := ParseWResultString(wresult)
	if err != nil {
		return err
	}
	response := collection.TokenResponse()
	if response == nil {
		return errs.Detail(ErrInvalidSignature, "signed request carries no token | 签名请求未携带令牌")
	}
	assertion, err := response.RequestedSecurityToken.Assertion()
	if err != nil {
		return err
	}
	if err := sts.config.SignatureVerifier.VerifySignature(r.Context(), []byte(response.RequestedSecurityToken.Raw()), assertion.ID); err != nil {
		return errs.Wrap(err, ErrInvalidSignature)
	}
	return nil
}

// resolveRealm validates the realm and resolves the reply URL. | resolveRealm 校验领域并解析回复 URL。
func (sts *SecurityTokenService) resolveRealm(r *http.Request, realm, replyURL string) (string, error) {
	realm = strings.TrimSpace(realm)
	if realm == "" {
		return "", errs.Detail(ErrInvalidRequest, "wtrealm is missing | 缺少 wtrealm")
	}
	if len(sts.config.AllowedRealms) > 0 {
		allowed := false
		for _, candidate := range sts.config.AllowedRealms {
			if secureEqual(strings.TrimSpace(candidate), realm) {
				allowed = true
				break
			}
		}
		if !allowed {
			return "", errs.Detail(ErrInvalidRealm, "realm %[1]q is not allowed | 领域 %[1]q 不被允许", realm)
		}
	}
	resolved := strings.TrimSpace(replyURL)
	if sts.config.RealmResolver != nil {
		value, err := sts.config.RealmResolver.ResolveRealm(r.Context(), realm, resolved)
		if err != nil {
			return "", errs.WrapDetail(err, ErrInvalidRealm, "realm %[1]q | 领域 %[1]q", realm)
		}
		if strings.TrimSpace(value) != "" {
			resolved = strings.TrimSpace(value)
		}
	}
	if resolved != "" {
		if err := validateEndpointURL("reply URL", resolved); err != nil {
			return "", errs.WrapDetail(err, ErrInvalidRequest, "reply URL %[1]q | 回复 URL %[1]q", resolved)
		}
	}
	return resolved, nil
}

// login redirects or renders a login page. | login 重定向或渲染登录页。
func (sts *SecurityTokenService) login(w http.ResponseWriter, r *http.Request) {
	if sts.config.LoginHandler != nil {
		sts.config.LoginHandler(w, r)
		return
	}
	if sts.config.LoginURL != "" {
		location := sts.config.LoginURL + "?return_to=" + url.QueryEscape(r.URL.String())
		http.Redirect(w, r, location, http.StatusFound)
		return
	}
	sts.fail(w, r, ErrLoginRequired)
}

// fail renders a WS-Federation fault without leaking internal details. | fail 渲染不泄露内部细节的
// WS-Federation 故障。
func (sts *SecurityTokenService) fail(w http.ResponseWriter, r *http.Request, err error) {
	if sts.config.ErrorHandler != nil {
		sts.config.ErrorHandler(w, r, err)
		return
	}
	code := FaultCodeServerError
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, ErrInvalidRealm), errors.Is(err, saml.ErrInvalidAudience):
		code, status = FaultCodeAccessDenied, http.StatusForbidden
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrNoToken),
		errors.Is(err, ErrUnsupported), errors.Is(err, saml.ErrInvalidRequest):
		code, status = FaultCodeInvalidRequest, http.StatusBadRequest
	case errors.Is(err, ErrLoginRequired), errors.Is(err, saml.ErrLoginRequired),
		errors.Is(err, ErrInvalidSignature):
		code, status = FaultCodeAuthenticationFailed, http.StatusUnauthorized
	}
	fault := Fault{FaultCode: code, FaultString: faultString(code)}
	data, marshalErr := xml.Marshal(&fault)
	if marshalErr != nil {
		http.Error(w, "wsfed request rejected", status)
		return
	}
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

// faultString returns a generic description for code. | faultString 返回 code 的通用描述。
func faultString(code string) string {
	switch code {
	case FaultCodeInvalidRequest:
		return "The request is invalid. | 请求非法。"
	case FaultCodeAuthenticationFailed:
		return "Authentication is required. | 需要认证。"
	case FaultCodeAccessDenied:
		return "The relying party is not allowed. | 依赖方不被允许。"
	default:
		return "The token service failed. | 令牌服务失败。"
	}
}

// Register mounts sign-in, sign-out and metadata on a YD router. | Register 在 YD 路由上挂载登录、
// 登出与元数据端点。
func (sts *SecurityTokenService) Register(r *router.Router, prefix string) {
	if r == nil {
		return
	}
	signIn := joinPath(prefix, sts.config.SignInPath)
	signOut := joinPath(prefix, sts.config.SignOutPath)
	metadata := joinPath(prefix, sts.config.MetadataPath)
	r.HandleRaw(http.MethodGet, signIn, sts.HandleSignIn)
	r.HandleRaw(http.MethodPost, signIn, sts.HandleSignIn)
	r.HandleRaw(http.MethodGet, signOut, sts.HandleSignOut)
	r.HandleRaw(http.MethodPost, signOut, sts.HandleSignOut)
	r.HandleRaw(http.MethodGet, metadata, sts.MetadataHandler)
}

// HTTPHandler returns a net/http handler for the STS endpoints. | HTTPHandler 返回 STS 端点的
// net/http 处理器。
func (sts *SecurityTokenService) HTTPHandler(prefix string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(joinPath(prefix, sts.config.SignInPath), sts.HandleSignIn)
	mux.HandleFunc(joinPath(prefix, sts.config.SignOutPath), sts.HandleSignOut)
	mux.HandleFunc(joinPath(prefix, sts.config.MetadataPath), sts.MetadataHandler)
	return mux
}

// endpointURL resolves an endpoint path against issuer. | endpointURL 相对 issuer 解析端点路径。
func endpointURL(issuer, configured, fallback string) string {
	value := strings.TrimSpace(configured)
	if value == "" {
		value = fallback
	}
	if parsed, err := url.Parse(value); err == nil && parsed.Scheme != "" && parsed.Host != "" {
		return value
	}
	base := strings.TrimRight(strings.TrimSpace(issuer), "/")
	if base == "" {
		return value
	}
	return base + "/" + strings.TrimLeft(value, "/")
}

// localPath returns the local mount path for an endpoint. | localPath 返回端点的本地挂载路径。
func localPath(configured, fallback string) string {
	value := strings.TrimSpace(configured)
	if value == "" {
		value = fallback
	}
	if parsed, err := url.Parse(value); err == nil && parsed.Scheme != "" && parsed.Host != "" {
		if parsed.Path != "" {
			return parsed.Path
		}
		return "/"
	}
	if !strings.HasPrefix(value, "/") {
		return "/" + value
	}
	return value
}
