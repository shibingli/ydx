package saml

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/router"
	"github.com/shibingli/ydx/xml"
)

// Authenticator resolves the resource owner at the IdP SSO endpoint. | Authenticator 在 IdP SSO 端点解析资源所有者。
type Authenticator interface {
	// Authenticate returns the current principal or ErrLoginRequired. | Authenticate 返回当前主体或 ErrLoginRequired。
	Authenticate(ctx context.Context, w http.ResponseWriter, r *http.Request, request *AuthnRequest) (*auth.Principal, error)
}

// AuthenticatorFunc adapts a function to Authenticator. | AuthenticatorFunc 把函数适配为 Authenticator。
type AuthenticatorFunc func(ctx context.Context, w http.ResponseWriter, r *http.Request, request *AuthnRequest) (*auth.Principal, error)

// Authenticate calls f. | Authenticate 调用 f。
func (f AuthenticatorFunc) Authenticate(ctx context.Context, w http.ResponseWriter, r *http.Request, request *AuthnRequest) (*auth.Principal, error) {
	return f(ctx, w, r, request)
}

// RedirectVerifier verifies an HTTP-Redirect binding signature. rawQuery is the exact URL query
// octet sequence that was signed, preserving provider-specific escaping and parameter order; params
// is its parsed form. Implementations should verify rawQuery, not re-encode params. | RedirectVerifier
// 校验 HTTP-Redirect 绑定签名。rawQuery 是参与签名的精确 URL 查询八位组序列，保留提供方特有转义与
// 参数顺序；params 是解析后的形式。实现应校验 rawQuery，而不是重新编码 params。
type RedirectVerifier func(ctx context.Context, rawQuery string, params url.Values, issuer, relayState string) error

// IdentityProviderConfig configures a SAML IdP. | IdentityProviderConfig 配置 SAML IdP。
type IdentityProviderConfig struct {
	// EntityID is the IdP entity ID. | EntityID 是 IdP 实体标识。
	EntityID string
	// SSOURL and SLOURL are the public IdP endpoint URLs. | SSOURL 与 SLOURL 是公开 IdP 端点 URL。
	SSOURL string
	SLOURL string
	// ArtifactResolutionURL is the public SOAP artifact resolution endpoint. When empty it is derived
	// from SSOURL and ARSPath. | ArtifactResolutionURL 是公开的 SOAP 工件解析端点。为空时由 SSOURL 与
	// ARSPath 推导。
	ArtifactResolutionURL string
	// ArtifactTTL is the artifact lifetime; zero means DefaultArtifactTTL. | ArtifactTTL 是工件寿命；
	// 零值表示 DefaultArtifactTTL。
	ArtifactTTL time.Duration
	// ArtifactSourceID pins the 20-byte artifact source identifier. Zero generates a random value;
	// multi-instance deployments must configure the same value on every instance. | ArtifactSourceID
	// 固定 20 字节工件源标识。零值表示随机生成；多实例部署必须在每个实例配置相同取值。
	ArtifactSourceID []byte
	// WantArtifactResolveSigned rejects unsigned SOAP ArtifactResolve messages. | WantArtifactResolveSigned
	// 拒绝未签名的 SOAP ArtifactResolve 消息。
	WantArtifactResolveSigned bool
	// SignArtifactResponse signs the SOAP ArtifactResponse; it requires Signer. | SignArtifactResponse
	// 签名 SOAP ArtifactResponse；需要 Signer。
	SignArtifactResponse bool
	// LoginURL receives unauthenticated browsers. | LoginURL 接收未认证浏览器。
	LoginURL string
	// LoginHandler renders a login page instead of redirecting. | LoginHandler 渲染登录页而无需跳转。
	LoginHandler http.HandlerFunc
	// Store tracks requests, assertions and sessions. | Store 跟踪请求、断言与会话。
	Store Store
	// SignatureVerifier verifies XML signatures on AuthnRequests and LogoutRequests. | SignatureVerifier
	// 校验 AuthnRequest 与 LogoutRequest 上的 XML 签名。
	SignatureVerifier SignatureVerifier
	// RedirectVerifier verifies HTTP-Redirect signatures over the exact raw query octets. It is
	// required for signed redirect SLO messages; when nil, such messages are rejected. Unsigned
	// redirect messages remain accepted unless WantLogoutRequestsSigned is set. | RedirectVerifier
	// 基于精确原始查询八位组校验 HTTP-Redirect 签名。签名重定向 SLO 消息必须配置它；为空时拒绝这类
	// 消息。未签名重定向消息仍可接受，除非设置 WantLogoutRequestsSigned。
	RedirectVerifier RedirectVerifier
	// Signer signs Responses and Assertions. | Signer 签名 Response 与 Assertion。
	Signer XMLSigner
	// SigningKey and SigningAlg sign HTTP-Redirect binding messages. | SigningKey 与 SigningAlg
	// 签名 HTTP-Redirect 绑定消息。
	SigningKey any
	SigningAlg string
	// SPResolver resolves service-provider metadata. | SPResolver 解析服务提供方元数据。
	SPResolver MetadataResolver
	// Authenticator resolves the current user. | Authenticator 解析当前用户。
	Authenticator Authenticator
	// AttributeMapper maps the principal to attributes. | AttributeMapper 把主体映射为属性。
	AttributeMapper AttributeMapper
	// SigningCertificates are the IdP signing certificates for metadata. | SigningCertificates 是用于元数据的 IdP 签名证书。
	SigningCertificates []*x509.Certificate
	// EncryptionCertificates are the IdP encryption certificates for metadata. | EncryptionCertificates 是用于元数据的 IdP 加密证书。
	EncryptionCertificates []*x509.Certificate
	// SignResponse and SignAssertion require the signer and request signatures. | SignResponse 与 SignAssertion 要求签名器与请求签名。
	SignResponse  bool
	SignAssertion bool
	// WantAuthnRequestsSigned rejects unsigned AuthnRequests. | WantAuthnRequestsSigned 拒绝未签名 AuthnRequest。
	WantAuthnRequestsSigned bool
	// WantLogoutRequestsSigned rejects unsigned LogoutRequests. | WantLogoutRequestsSigned 拒绝未签名
	// LogoutRequest。
	WantLogoutRequestsSigned bool
	// NameIDFormat is the default NameID format. | NameIDFormat 是默认 NameID 格式。
	NameIDFormat string
	// AllowedNameIDFormats restricts requested NameID formats. | AllowedNameIDFormats 限定请求的 NameID 格式。
	AllowedNameIDFormats []string
	// ResponseTTL is the assertion lifetime; zero means five minutes. | ResponseTTL 是断言寿命；零值表示 5 分钟。
	ResponseTTL time.Duration
	// SessionTTL is the IdP session lifetime; zero means eight hours. | SessionTTL 是 IdP 会话寿命；零值表示 8 小时。
	SessionTTL time.Duration
	// ClockSkew is the tolerated clock difference. | ClockSkew 是容忍的时钟差。
	ClockSkew time.Duration
	// MaxIssueAge rejects requests issued longer ago than this; zero disables the check. |
	// MaxIssueAge 拒绝签发时间早于此时长的请求；零值禁用。
	MaxIssueAge time.Duration
	// Now overrides the clock. | Now 替换时钟。
	Now func() time.Time
	// ErrorHandler renders IdP failures; nil writes a SAML error response or 400. | ErrorHandler 渲染 IdP 失败；空值写入 SAML 错误响应或 400。
	ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)
	// SSOPath, SLOPath, ARSPath and MetadataPath are local mount paths. | SSOPath、SLOPath、ARSPath
	// 与 MetadataPath 是本地挂载路径。
	SSOPath      string
	SLOPath      string
	ARSPath      string
	MetadataPath string
}

// IdentityProvider is a SAML 2.0 identity provider. | IdentityProvider 是 SAML 2.0 身份提供方。
type IdentityProvider struct {
	config           IdentityProviderConfig
	store            Store
	now              func() time.Time
	artifactSourceID [ArtifactSourceIDSize]byte
}

// NewIdentityProvider returns an identity provider. | NewIdentityProvider 返回身份提供方。
func NewIdentityProvider(config IdentityProviderConfig) (*IdentityProvider, error) {
	if config.EntityID == "" || config.SSOURL == "" {
		return nil, errs.Detail(ErrInvalidConfig, "entityID and SSOURL are required | entityID 与 SSOURL 必填")
	}
	if config.Authenticator == nil {
		return nil, errs.Detail(ErrInvalidConfig, "authenticator is required | 需要认证器")
	}
	if config.SignResponse || config.SignAssertion || config.SignArtifactResponse {
		if config.Signer == nil {
			return nil, errs.Detail(ErrInvalidConfig, "signing requested without a signer | 要求签名但未提供签名器")
		}
	}
	if config.SigningKey != nil && config.SigningAlg == "" {
		config.SigningAlg = SigAlgRSASHA256
	}
	if config.NameIDFormat == "" {
		config.NameIDFormat = NameIDUnspecified
	}
	if config.ResponseTTL <= 0 {
		config.ResponseTTL = 5 * time.Minute
	}
	if config.SessionTTL <= 0 {
		config.SessionTTL = 8 * time.Hour
	}
	if config.ClockSkew <= 0 {
		config.ClockSkew = 2 * time.Minute
	}
	if config.SSOPath == "" {
		config.SSOPath = "/saml/sso"
	}
	if config.SLOPath == "" {
		config.SLOPath = "/saml/slo"
	}
	if config.ARSPath == "" {
		config.ARSPath = "/saml/artifact"
	}
	if config.MetadataPath == "" {
		config.MetadataPath = "/saml/metadata"
	}
	if config.ArtifactTTL <= 0 {
		config.ArtifactTTL = DefaultArtifactTTL
	}
	if config.ArtifactResolutionURL == "" {
		config.ArtifactResolutionURL = deriveArtifactResolutionURL(config.SSOURL, config.ARSPath)
	}
	var artifactSourceID [ArtifactSourceIDSize]byte
	if len(config.ArtifactSourceID) > 0 {
		if len(config.ArtifactSourceID) != ArtifactSourceIDSize {
			return nil, errs.Detail(ErrInvalidConfig, "artifact source ID must be %d bytes | 工件源标识必须为 %d 字节", ArtifactSourceIDSize, ArtifactSourceIDSize)
		}
		copy(artifactSourceID[:], config.ArtifactSourceID)
	} else {
		generated, err := NewArtifactSourceID()
		if err != nil {
			return nil, err
		}
		artifactSourceID = generated
	}
	store := config.Store
	if store == nil {
		store = NewMemoryStore()
	}
	provider := &IdentityProvider{config: config, store: store, now: config.Now, artifactSourceID: artifactSourceID}
	if provider.now == nil {
		provider.now = time.Now
	}
	return provider, nil
}

// deriveArtifactResolutionURL derives the public artifact resolution URL from the SSO URL and the
// local artifact resolution path. | deriveArtifactResolutionURL 由 SSO URL 与本地工件解析路径推导
// 公开工件解析 URL。
func deriveArtifactResolutionURL(ssoURL, arsPath string) string {
	parsed, err := url.Parse(ssoURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	parsed.Path = arsPath
	parsed.RawPath = ""
	parsed.RawQuery = ""
	parsed.Fragment = ""
	parsed.User = nil
	return parsed.String()
}

// Config returns the configuration. | Config 返回配置。
func (idp *IdentityProvider) Config() IdentityProviderConfig { return idp.config }

// Store returns the correlation store. | Store 返回关联存储。
func (idp *IdentityProvider) Store() Store { return idp.store }

// ArtifactSourceID returns the 20-byte source identifier carried by artifacts this IdP issues. |
// ArtifactSourceID 返回本 IdP 签发工件携带的 20 字节源标识。
func (idp *IdentityProvider) ArtifactSourceID() [ArtifactSourceIDSize]byte {
	return idp.artifactSourceID
}

// ArtifactResolutionURL returns the public SOAP artifact resolution endpoint. | ArtifactResolutionURL
// 返回公开的 SOAP 工件解析端点。
func (idp *IdentityProvider) ArtifactResolutionURL() string { return idp.config.ArtifactResolutionURL }

// HandleSSO processes an AuthnRequest and emits a Response to the SP ACS endpoint. | HandleSSO
// 处理 AuthnRequest 并向 SP ACS 端点发出 Response。
func (idp *IdentityProvider) HandleSSO(w http.ResponseWriter, r *http.Request) {
	boundFormBody(w, r)
	request, _, relayState, err := idp.ParseAuthnRequest(r)
	if err != nil {
		idp.fail(w, r, nil, err)
		return
	}
	if request.ProtocolBinding != "" && request.ProtocolBinding != BindingHTTPPost && request.ProtocolBinding != BindingHTTPArtifact {
		idp.failStatus(w, r, request, relayState, StatusRequestUnsupported)
		return
	}
	acsURL, err := idp.resolveACS(r.Context(), request)
	if err != nil {
		idp.fail(w, r, request, err)
		return
	}
	principal, err := idp.config.Authenticator.Authenticate(r.Context(), w, r, request)
	if err != nil {
		if errors.Is(err, ErrLoginRequired) {
			if request.IsPassive {
				idp.failStatus(w, r, request, relayState, StatusNoPassive)
				return
			}
			idp.login(w, r)
			return
		}
		idp.fail(w, r, request, err)
		return
	}
	if principal == nil {
		if request.IsPassive {
			idp.failStatus(w, r, request, relayState, StatusNoPassive)
			return
		}
		idp.login(w, r)
		return
	}
	if !satisfiesAuthnContext(request.RequestedAuthnContext, principal) {
		idp.failStatus(w, r, request, relayState, StatusNoAuthnContext)
		return
	}
	now := Now(idp.now)
	sessionIndex := auth.NewID("sess")
	nameIDFormat := idp.config.NameIDFormat
	if request.NameIDPolicy != nil && request.NameIDPolicy.Format != "" {
		if len(idp.config.AllowedNameIDFormats) > 0 && !containsString(idp.config.AllowedNameIDFormats, request.NameIDPolicy.Format) {
			idp.fail(w, r, request, errs.Detail(ErrInvalidRequest, "NameID format is not allowed | 不允许 NameID 格式"))
			return
		}
		nameIDFormat = request.NameIDPolicy.Format
	}
	nameID, err := NameIDForPrincipal(principal, nameIDFormat)
	if err != nil {
		idp.fail(w, r, request, err)
		return
	}
	if nameID == nil || nameID.Value == "" {
		idp.fail(w, r, request, errs.Detail(ErrInvalidRequest, "NameID value is empty | NameID 取值为空"))
		return
	}
	attributes, err := idp.attributes(r.Context(), principal)
	if err != nil {
		idp.fail(w, r, request, err)
		return
	}
	expiresAt := now.Add(idp.config.ResponseTTL)
	assertion := Assertion{
		ID:           auth.NewID("assertion"),
		IssueInstant: FormatTime(now),
		Version:      Version,
		Issuer:       &Issuer{Value: idp.config.EntityID},
		Subject: &Subject{
			NameID: nameID,
			SubjectConfirmation: []SubjectConfirmation{{
				Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
				SubjectConfirmationData: &SubjectConfirmationData{
					Recipient:    acsURL,
					InResponseTo: request.ID,
					NotOnOrAfter: FormatTime(expiresAt),
				},
			}},
		},
		Conditions: &Conditions{
			NotBefore:    FormatTime(now.Add(-idp.config.ClockSkew)),
			NotOnOrAfter: FormatTime(expiresAt),
			AudienceRestriction: []AudienceRestriction{{
				Audience: []string{request.Issuer.Value},
			}},
		},
		AuthnStatement: []AuthnStatement{{
			AuthnInstant: FormatTime(now),
			SessionIndex: sessionIndex,
			AuthnContext: &AuthnContext{AuthnContextClassRef: authnContext(principal)},
		}},
		AttributeStatement: []AttributeStatement{{Attribute: attributes}},
	}
	response := Response{
		ID:           auth.NewID("response"),
		InResponseTo: request.ID,
		Version:      Version,
		IssueInstant: FormatTime(now),
		Destination:  acsURL,
		Issuer:       &Issuer{Value: idp.config.EntityID},
		Status:       &Status{StatusCode: &StatusCode{Value: StatusSuccess}},
		Assertion:    []Assertion{assertion},
	}
	document, err := xml.Marshal(&response)
	if err != nil {
		idp.fail(w, r, request, errs.Wrap(err, ErrInvalidResponse))
		return
	}
	document, err = idp.sign(document, &response, &assertion)
	if err != nil {
		idp.fail(w, r, request, err)
		return
	}
	if err := idp.store.SaveSession(r.Context(), &Session{
		ID:          sessionIndex,
		NameID:      nameID.Value,
		SPEntityID:  request.Issuer.Value,
		IDPEntityID: idp.config.EntityID,
		CreatedAt:   now,
		ExpiresAt:   now.Add(idp.config.SessionTTL),
		Attributes:  attributesToMap(attributes),
	}); err != nil {
		idp.fail(w, r, request, err)
		return
	}
	if err := idp.deliverResponse(w, r, request, relayState, acsURL, document); err != nil {
		idp.fail(w, r, request, err)
	}
}

// deliverResponse sends the Response through the binding requested by the AuthnRequest. | deliverResponse
// 按 AuthnRequest 请求的绑定发送 Response。
func (idp *IdentityProvider) deliverResponse(w http.ResponseWriter, r *http.Request, request *AuthnRequest, relayState, acsURL string, document []byte) error {
	if request.ProtocolBinding != BindingHTTPArtifact {
		WritePostForm(w, acsURL, "SAMLResponse", EncodePost(document), relayState)
		return nil
	}
	if idp.config.ArtifactResolutionURL == "" {
		return errs.Detail(ErrInvalidConfig, "artifact resolution URL is missing | 缺少工件解析 URL")
	}
	store, err := artifactStoreOf(idp.store)
	if err != nil {
		return err
	}
	now := Now(idp.now)
	artifact, err := NewArtifact(0, idp.artifactSourceID)
	if err != nil {
		return err
	}
	record := &ArtifactRecord{
		Artifact:    *artifact,
		Message:     append([]byte(nil), document...),
		SPEntityID:  request.Issuer.Value,
		IDPEntityID: idp.config.EntityID,
		IssuedAt:    now,
		ExpiresAt:   now.Add(idp.config.ArtifactTTL),
	}
	if err := store.SaveArtifact(r.Context(), record, now); err != nil {
		return err
	}
	location, err := artifactRedirectURL(acsURL, artifact.String(), relayState)
	if err != nil {
		return err
	}
	http.Redirect(w, r, location, http.StatusFound)
	return nil
}

// artifactRedirectURL builds the ACS redirect that carries an artifact and RelayState. |
// artifactRedirectURL 构建携带工件与 RelayState 的 ACS 重定向 URL。
func artifactRedirectURL(acsURL, artifact, relayState string) (string, error) {
	location, err := url.Parse(acsURL)
	if err != nil {
		return "", errs.WrapDetail(err, ErrInvalidRecipient, "ACS URL is invalid | ACS URL 非法")
	}
	query := location.Query()
	query.Set(ArtifactParameter, artifact)
	if relayState != "" {
		query.Set("RelayState", relayState)
	}
	location.RawQuery = query.Encode()
	return location.String(), nil
}

// resolveACS returns the registered assertion consumer URL for a request. | resolveACS 返回请求
// 已注册的断言消费 URL。
func (idp *IdentityProvider) resolveACS(ctx context.Context, request *AuthnRequest) (string, error) {
	if request == nil {
		return "", errs.Detail(ErrInvalidRequest, "request is nil | 请求为空")
	}
	acsURL := request.AssertionConsumerServiceURL
	if acsURL == "" && idp.config.SPResolver != nil {
		metadata, err := idp.config.SPResolver.Resolve(ctx, request.Issuer.Value)
		if err != nil {
			return "", errs.Wrap(err, ErrInvalidIssuer)
		}
		acsURL = metadata.ACSURL(request.ProtocolBinding)
	}
	if acsURL == "" {
		return "", errs.Detail(ErrInvalidRequest, "ACS URL is missing | 缺少 ACS URL")
	}
	if err := validateACSURL(acsURL); err != nil {
		return "", err
	}
	return acsURL, nil
}

// validateACSURL rejects malformed and credential-bearing ACS URLs. | validateACSURL 拒绝非法与
// 携带凭据的 ACS URL。
func validateACSURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil {
		return errs.WrapDetail(err, ErrInvalidRecipient, "ACS URL is invalid | ACS URL 非法")
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return errs.Detail(ErrInvalidRecipient, "ACS URL scheme %[1]q | ACS URL 协议 %[1]q", parsed.Scheme)
	}
	if parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return errs.Detail(ErrInvalidRecipient, "ACS URL is not acceptable | ACS URL 不可接受")
	}
	return nil
}

// satisfiesAuthnContext reports whether the principal satisfies the requested context. | satisfiesAuthnContext
// 报告主体是否满足请求的认证上下文。
func satisfiesAuthnContext(requested *RequestedAuthnContext, principal *auth.Principal) bool {
	if requested == nil || len(requested.AuthnContextClassRef) == 0 {
		return true
	}
	if len(requested.AuthnContextDeclRef) > 0 {
		return false
	}
	actual := authnContext(principal)
	if principal != nil && principal.ACR != "" {
		actual = principal.ACR
	}
	return containsString(requested.AuthnContextClassRef, actual)
}

// failStatus sends a Response that carries a failure status and no assertion. | failStatus 发送只带
// 失败状态、不带断言的 Response。
func (idp *IdentityProvider) failStatus(w http.ResponseWriter, r *http.Request, request *AuthnRequest, relayState, code string) {
	acsURL, err := idp.resolveACS(r.Context(), request)
	if err != nil {
		http.Error(w, "saml request rejected", http.StatusBadRequest)
		return
	}
	now := Now(idp.now)
	response := Response{
		ID:           auth.NewID("response"),
		InResponseTo: request.ID,
		Version:      Version,
		IssueInstant: FormatTime(now),
		Destination:  acsURL,
		Issuer:       &Issuer{Value: idp.config.EntityID},
		Status:       statusFor(code),
	}
	document, err := xml.Marshal(&response)
	if err != nil {
		http.Error(w, "saml response error", http.StatusInternalServerError)
		return
	}
	if idp.config.Signer != nil && idp.config.SignResponse {
		document, err = idp.config.Signer.SignElement(document, response.ID)
		if err != nil {
			http.Error(w, "saml signature error", http.StatusInternalServerError)
			return
		}
	}
	if err := idp.deliverResponse(w, r, request, relayState, acsURL, document); err != nil {
		http.Error(w, "saml response error", http.StatusInternalServerError)
	}
}

// statusFor builds a Status with the correct top-level and second-level codes. | statusFor 构建
// 具有正确顶层与第二层状态码的 Status。
func statusFor(code string) *Status {
	if code == StatusSuccess {
		return &Status{StatusCode: &StatusCode{Value: StatusSuccess}}
	}
	top := StatusResponder
	switch code {
	case StatusRequestUnsupported, StatusInvalidNameIDPolicy:
		top = StatusRequester
	}
	return &Status{StatusCode: &StatusCode{Value: top, StatusCode: &StatusCode{Value: code}}}
}

// sign applies assertion and response signatures. | sign 应用断言与响应签名。
func (idp *IdentityProvider) sign(document []byte, response *Response, assertion *Assertion) ([]byte, error) {
	if idp.config.Signer == nil {
		return document, nil
	}
	var err error
	if idp.config.SignAssertion {
		document, err = idp.config.Signer.SignElement(document, assertion.ID)
		if err != nil {
			return nil, errs.Wrap(err, ErrInvalidSignature)
		}
	}
	if idp.config.SignResponse {
		document, err = idp.config.Signer.SignElement(document, response.ID)
		if err != nil {
			return nil, errs.Wrap(err, ErrInvalidSignature)
		}
	}
	return document, nil
}

// attributes maps the principal through the configured mapper. | attributes 通过配置的映射器映射主体。
func (idp *IdentityProvider) attributes(ctx context.Context, principal *auth.Principal) ([]Attribute, error) {
	mapper := idp.config.AttributeMapper
	if mapper == nil {
		mapper = DefaultAttributeMapper{}
	}
	return mapper.MapAttributes(ctx, principal)
}

// attributesToMap converts attributes to a multi-value map. | attributesToMap 把属性转换为多值映射。
func attributesToMap(attributes []Attribute) map[string][]string {
	out := make(map[string][]string, len(attributes))
	for _, attribute := range attributes {
		out[attribute.Name] = append(out[attribute.Name], AttributeValues(attribute)...)
	}
	return out
}

// authnContext returns the authentication context class for a principal. | authnContext 返回主体的认证上下文类。
func authnContext(principal *auth.Principal) string {
	if principal != nil && principal.ACR != "" {
		return principal.ACR
	}
	return AuthnContextPasswordProtectedTransport
}

// ParseAuthnRequest extracts and validates an AuthnRequest. | ParseAuthnRequest 提取并校验 AuthnRequest。
func (idp *IdentityProvider) ParseAuthnRequest(r *http.Request) (*AuthnRequest, []byte, string, error) {
	raw, relayState, redirect, err := readSAMLRequest(r)
	if err != nil {
		return nil, nil, "", err
	}
	request, err := ParseAuthnRequest(raw)
	if err != nil {
		return nil, nil, "", err
	}
	if request.Signature != nil {
		if idp.config.SignatureVerifier == nil {
			return nil, nil, "", errs.Detail(ErrInvalidSignature, "no signature verifier configured | 未配置签名校验器")
		}
		if err := idp.config.SignatureVerifier.VerifySignature(r.Context(), raw, request.ID); err != nil {
			return nil, nil, "", errs.Wrap(err, ErrInvalidSignature)
		}
	}
	if redirect {
		signed := r.URL.Query().Get("Signature") != "" || r.URL.Query().Get("SigAlg") != ""
		if signed || idp.config.WantAuthnRequestsSigned {
			if idp.config.RedirectVerifier == nil {
				return nil, nil, "", errs.Detail(ErrInvalidSignature, "redirect verifier is not configured | 未配置重定向签名校验器")
			}
			if err := idp.config.RedirectVerifier(r.Context(), r.URL.RawQuery, r.URL.Query(), request.Issuer.Value, relayState); err != nil {
				return nil, nil, "", errs.Wrap(err, ErrInvalidSignature)
			}
		}
	} else if idp.config.WantAuthnRequestsSigned && request.Signature == nil {
		return nil, nil, "", errs.Detail(ErrInvalidSignature, "AuthnRequest is not signed | AuthnRequest 未签名")
	}
	if err := ValidateAuthnRequest(r.Context(), request, AuthnRequestValidationOptions{
		IDPEntityID: idp.config.EntityID,
		SSOURL:      idp.config.SSOURL,
		SPResolver:  idp.config.SPResolver,
		ClockSkew:   idp.config.ClockSkew,
		MaxIssueAge: idp.config.MaxIssueAge,
		Now:         idp.now,
	}); err != nil {
		return nil, nil, "", err
	}
	return request, raw, relayState, nil
}

// readSAMLRequest reads a SAMLRequest and reports whether it used the Redirect binding. | readSAMLRequest
// 读取 SAMLRequest 并报告是否使用 Redirect 绑定。
func readSAMLRequest(r *http.Request) ([]byte, string, bool, error) {
	if r == nil {
		return nil, "", false, errs.Detail(ErrInvalidRequest, "request is nil | 请求为空")
	}
	if err := checkFormBody(r); err != nil {
		return nil, "", false, err
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			return nil, "", false, formParseError(err)
		}
		value := r.PostForm.Get("SAMLRequest")
		if value == "" {
			return nil, "", false, errs.Detail(ErrInvalidRequest, "SAMLRequest is missing | 缺少 SAMLRequest")
		}
		decoded, err := DecodePost(value)
		if err != nil {
			return nil, "", false, err
		}
		return decoded, r.PostForm.Get("RelayState"), false, nil
	}
	value := r.URL.Query().Get("SAMLRequest")
	if value == "" {
		return nil, "", false, errs.Detail(ErrInvalidRequest, "SAMLRequest is missing | 缺少 SAMLRequest")
	}
	decoded, err := DecodeRedirect(value)
	if err != nil {
		return nil, "", true, err
	}
	return decoded, r.URL.Query().Get("RelayState"), true, nil
}

// login redirects to the login page or renders it. | login 跳转到登录页或渲染它。
func (idp *IdentityProvider) login(w http.ResponseWriter, r *http.Request) {
	if idp.config.LoginHandler != nil {
		idp.config.LoginHandler(w, r)
		return
	}
	if idp.config.LoginURL != "" {
		location := idp.config.LoginURL + "?return_to=" + url.QueryEscape(r.URL.String())
		http.Redirect(w, r, location, http.StatusFound)
		return
	}
	http.Error(w, "login required", http.StatusUnauthorized)
}

// fail renders an IdP failure. | fail 渲染 IdP 失败。
func (idp *IdentityProvider) fail(w http.ResponseWriter, r *http.Request, request *AuthnRequest, err error) {
	if idp.config.ErrorHandler != nil {
		idp.config.ErrorHandler(w, r, err)
		return
	}
	http.Error(w, "saml request rejected", http.StatusBadRequest)
}

// Metadata returns the IdP metadata. | Metadata 返回 IdP 元数据。
func (idp *IdentityProvider) Metadata() *EntityDescriptor {
	descriptor := &EntityDescriptor{
		EntityID: idp.config.EntityID,
		IDPSSODescriptor: &IDPSSODescriptor{
			WantAuthnRequestsSigned:    idp.config.WantAuthnRequestsSigned,
			ProtocolSupportEnumeration: NamespaceProtocol,
			SingleSignOnService: []Endpoint{
				{Binding: BindingHTTPRedirect, Location: idp.config.SSOURL},
				{Binding: BindingHTTPPost, Location: idp.config.SSOURL},
			},
		},
	}
	if idp.config.SLOURL != "" {
		descriptor.IDPSSODescriptor.SingleLogoutService = []Endpoint{
			{Binding: BindingHTTPRedirect, Location: idp.config.SLOURL},
			{Binding: BindingHTTPPost, Location: idp.config.SLOURL},
		}
	}
	if idp.config.NameIDFormat != "" {
		descriptor.IDPSSODescriptor.NameIDFormat = []string{idp.config.NameIDFormat}
	}
	if idp.config.ArtifactResolutionURL != "" {
		descriptor.IDPSSODescriptor.ArtifactResolutionService = []IndexedEndpoint{{
			Binding:   BindingSOAP,
			Location:  idp.config.ArtifactResolutionURL,
			Index:     0,
			IsDefault: true,
		}}
	}
	descriptor.IDPSSODescriptor.KeyDescriptor = keyDescriptors(idp.config.SigningCertificates, idp.config.EncryptionCertificates)
	return descriptor
}

// MetadataXML returns marshaled IdP metadata. | MetadataXML 返回序列化的 IdP 元数据。
func (idp *IdentityProvider) MetadataXML() ([]byte, error) { return idp.Metadata().Marshal() }

// MetadataHandler serves IdP metadata. | MetadataHandler 提供 IdP 元数据。
func (idp *IdentityProvider) MetadataHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	data, err := idp.MetadataXML()
	if err != nil {
		http.Error(w, "metadata error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// Register mounts SSO, SLO and metadata on a ydx/router Router. | Register 把 SSO、SLO 与元数据挂载到 ydx/router Router。
func (idp *IdentityProvider) Register(r *router.Router, prefix string) {
	if r == nil {
		return
	}
	r.HandleRaw(http.MethodGet, prefix+idp.config.SSOPath, idp.HandleSSO)
	r.HandleRaw(http.MethodPost, prefix+idp.config.SSOPath, idp.HandleSSO)
	r.HandleRaw(http.MethodGet, prefix+idp.config.SLOPath, idp.HandleSLO)
	r.HandleRaw(http.MethodPost, prefix+idp.config.SLOPath, idp.HandleSLO)
	r.HandleRaw(http.MethodPost, prefix+idp.config.ARSPath, idp.HandleArtifactResolution)
	r.HandleRaw(http.MethodGet, prefix+idp.config.MetadataPath, idp.MetadataHandler)
}

// HTTPHandler returns a net/http handler for the IdP endpoints. | HTTPHandler 返回 IdP 端点的 net/http 处理器。
func (idp *IdentityProvider) HTTPHandler(prefix string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(prefix+idp.config.SSOPath, idp.HandleSSO)
	mux.HandleFunc(prefix+idp.config.SLOPath, idp.HandleSLO)
	mux.HandleFunc(prefix+idp.config.ARSPath, idp.HandleArtifactResolution)
	mux.HandleFunc(prefix+idp.config.MetadataPath, idp.MetadataHandler)
	return mux
}

// EncodeLogoutResponse builds a LogoutResponse. | EncodeLogoutResponse 构建 LogoutResponse。
func EncodeLogoutResponse(issuer, destination, inResponseTo string, now time.Time) ([]byte, error) {
	response := LogoutResponse{
		ID:           auth.NewID("logout"),
		InResponseTo: inResponseTo,
		Version:      Version,
		IssueInstant: FormatTime(now),
		Destination:  destination,
		Issuer:       &Issuer{Value: issuer},
		Status:       &Status{StatusCode: &StatusCode{Value: StatusSuccess}},
	}
	return xml.Marshal(&response)
}

// DecodeLogoutRequest parses a LogoutRequest. | DecodeLogoutRequest 解析 LogoutRequest。
func DecodeLogoutRequest(data []byte) (*LogoutRequest, error) {
	var request LogoutRequest
	if err := xml.Unmarshal(data, &request); err != nil {
		return nil, errs.Wrap(err, ErrInvalidRequest)
	}
	return &request, nil
}

// DecodeLogoutResponse parses a LogoutResponse. | DecodeLogoutResponse 解析 LogoutResponse。
func DecodeLogoutResponse(data []byte) (*LogoutResponse, error) {
	var response LogoutResponse
	if err := xml.Unmarshal(data, &response); err != nil {
		return nil, errs.Wrap(err, ErrInvalidResponse)
	}
	return &response, nil
}

// base64Decode decodes a standard base64 value. | base64Decode 解码标准 base64 值。
func base64Decode(value string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(strings.TrimSpace(value))
}
