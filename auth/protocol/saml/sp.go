package saml

import (
	"context"
	"crypto/x509"
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

// XMLSigner inserts an XMLDSig signature over the element with elementID. | XMLSigner 为 elementID
// 元素插入 XMLDSig 签名。
type XMLSigner interface {
	// SignElement returns document with a signature over the element. | SignElement 返回带元素签名的文档。
	SignElement(document []byte, elementID string) ([]byte, error)
}

// ServiceProviderConfig configures a SAML SP. | ServiceProviderConfig 配置 SAML SP。
type ServiceProviderConfig struct {
	// EntityID is the SP entity ID. | EntityID 是 SP 实体标识。
	EntityID string
	// ACSURL is the assertion consumer URL. | ACSURL 是断言消费 URL。
	ACSURL string
	// SLOURL is the single-logout URL. | SLOURL 是单点登出 URL。
	SLOURL string
	// IDPMetadata is the IdP metadata. | IDPMetadata 是 IdP 元数据。
	IDPMetadata *EntityDescriptor
	// Store correlates requests and rejects replay. | Store 关联请求并拒绝重放。
	Store Store
	// AssertionReplayStore enforces Conditions/OneTimeUse assertions. When nil, Store is used when it
	// implements AssertionReplayStore; otherwise OneTimeUse assertions are rejected unless
	// AllowOneTimeUseWithoutReplayStore is set. | AssertionReplayStore 强制 Conditions/OneTimeUse
	// 断言。为空时若 Store 实现 AssertionReplayStore 则使用它；否则拒绝 OneTimeUse 断言，除非设置
	// AllowOneTimeUseWithoutReplayStore。
	AssertionReplayStore AssertionReplayStore
	// AllowOneTimeUseWithoutReplayStore accepts OneTimeUse assertions without replay detection when
	// neither AssertionReplayStore nor Store enforces single use. The default false fails closed. |
	// AllowOneTimeUseWithoutReplayStore 在 AssertionReplayStore 与 Store 均无法强制一次性使用时
	// 接受 OneTimeUse 断言且不检测重放。默认 false 失败关闭。
	AllowOneTimeUseWithoutReplayStore bool
	// SignatureVerifier verifies response and assertion signatures. | SignatureVerifier 校验响应与断言签名。
	SignatureVerifier SignatureVerifier
	// Decryptor decrypts EncryptedAssertion elements. | Decryptor 解密 EncryptedAssertion 元素。
	Decryptor EncryptedAssertionDecryptor
	// RequestSigningKey signs AuthnRequests in the Redirect binding. | RequestSigningKey 在 Redirect 绑定中签名 AuthnRequest。
	RequestSigningKey any
	// RequestSigningAlg is the Redirect signature algorithm. | RequestSigningAlg 是 Redirect 签名算法。
	RequestSigningAlg string
	// RequestSigningCertificates are the SP certificates for metadata. | RequestSigningCertificates 是用于元数据的 SP 证书。
	RequestSigningCertificates []*x509.Certificate
	// EncryptionCertificates are the SP encryption certificates for metadata. | EncryptionCertificates 是用于元数据的 SP 加密证书。
	EncryptionCertificates []*x509.Certificate
	// RequireSignedAssertion requires a signature on the assertion or response. | RequireSignedAssertion 要求断言或响应签名。
	RequireSignedAssertion bool
	// RequireSignedResponse requires a signature on the response. | RequireSignedResponse 要求响应签名。
	RequireSignedResponse bool
	// AllowIDPInitiated accepts responses without InResponseTo. | AllowIDPInitiated 接受无 InResponseTo 的响应。
	AllowIDPInitiated bool
	// RequireSubjectConfirmation requires a bearer subject confirmation. | RequireSubjectConfirmation 要求承载主体确认。
	RequireSubjectConfirmation bool
	// RequireSignedLogout requires signed LogoutRequest and LogoutResponse messages. |
	// RequireSignedLogout 要求签名的 LogoutRequest 与 LogoutResponse 消息。
	RequireSignedLogout bool
	// RedirectVerifier verifies HTTP-Redirect signatures over the exact raw query octets. Signed
	// redirect logout messages are rejected when it is nil; unsigned redirect messages remain
	// accepted unless RequireSignedLogout is set. | RedirectVerifier 基于精确原始查询八位组校验
	// HTTP-Redirect 签名。为空时拒绝签名重定向登出消息；未签名重定向消息仍可接受，除非设置
	// RequireSignedLogout。
	RedirectVerifier RedirectVerifier
	// NameIDFormat is the requested NameID format. | NameIDFormat 是请求的 NameID 格式。
	NameIDFormat string
	// ProtocolBinding is the requested response binding. | ProtocolBinding 是请求的响应绑定。
	ProtocolBinding string
	// ClockSkew is the tolerated clock difference. | ClockSkew 是容忍的时钟差。
	ClockSkew time.Duration
	// MaxIssueAge rejects responses and assertions issued longer ago than this; zero disables the
	// check. | MaxIssueAge 拒绝签发时间早于此时长的响应与断言；零值禁用。
	MaxIssueAge time.Duration
	// AuthnRequestTTL is the request correlation lifetime. | AuthnRequestTTL 是请求关联寿命。
	AuthnRequestTTL time.Duration
	// ArtifactResolutionTimeout bounds one SOAP artifact resolution round trip; zero means ten
	// seconds. | ArtifactResolutionTimeout 约束单次 SOAP 工件解析往返；零值表示 10 秒。
	ArtifactResolutionTimeout time.Duration
	// ArtifactHTTPClient overrides the HTTP client used for artifact resolution. The zero client
	// does not follow redirects and honors ArtifactResolutionTimeout. | ArtifactHTTPClient 替换用于
	// 工件解析的 HTTP 客户端。零值客户端不跟随重定向并遵循 ArtifactResolutionTimeout。
	ArtifactHTTPClient *http.Client
	// ArtifactSOAPVersion selects the SOAP envelope version of outgoing ArtifactResolve messages;
	// the zero value is SOAPVersion11. | ArtifactSOAPVersion 选择外发 ArtifactResolve 消息的 SOAP
	// 信封版本；零值是 SOAPVersion11。
	ArtifactSOAPVersion SOAPVersion
	// ArtifactResolutionMaxEndpoints bounds the failover candidates tried for one artifact; zero
	// means DefaultArtifactResolutionMaxEndpoints and values above MaxArtifactResolutionEndpoints
	// are rejected. | ArtifactResolutionMaxEndpoints 限制单个工件的故障转移候选端点；零值表示
	// DefaultArtifactResolutionMaxEndpoints，大于 MaxArtifactResolutionEndpoints 的值会被拒绝。
	ArtifactResolutionMaxEndpoints int
	// ArtifactResolutionTotalTimeout bounds all failover attempts together; zero means three times
	// ArtifactResolutionTimeout. | ArtifactResolutionTotalTimeout 约束全部故障转移尝试的总时长；
	// 零值表示 ArtifactResolutionTimeout 的三倍。
	ArtifactResolutionTotalTimeout time.Duration
	// ArtifactSourceID pins the accepted 20-byte artifact source identifier; nil accepts the source
	// resolved by the configured IdP. | ArtifactSourceID 固定接受的 20 字节工件源标识；为空时接受
	// 已配置 IdP 解析的源。
	ArtifactSourceID []byte
	// ArtifactRequestSigner signs outgoing SOAP ArtifactResolve messages. | ArtifactRequestSigner 签名
	// 外发 SOAP ArtifactResolve 消息。
	ArtifactRequestSigner XMLSigner
	// RequireSignedArtifactResponse requires a verified signature on the SOAP ArtifactResponse. |
	// RequireSignedArtifactResponse 要求 SOAP ArtifactResponse 上存在已校验签名。
	RequireSignedArtifactResponse bool
	// Now overrides the clock. | Now 替换时钟。
	Now func() time.Time
	// SuccessHandler receives a validated assertion; nil writes a small JSON body. | SuccessHandler
	// 接收已校验断言；空值写入小型 JSON 正文。
	SuccessHandler func(w http.ResponseWriter, r *http.Request, result *ValidationResult)
	// ErrorHandler renders validation failures; nil writes a 400. | ErrorHandler 渲染校验失败；空值写入 400。
	ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)
	// ACSPath is the local assertion consumer mount path. | ACSPath 是本地断言消费挂载路径。
	ACSPath string
	// SLOPath is the local single-logout mount path. | SLOPath 是本地单点登出挂载路径。
	SLOPath string
	// MetadataPath is the local metadata mount path. | MetadataPath 是本地元数据挂载路径。
	MetadataPath string
}

// ServiceProvider is a SAML 2.0 service provider. | ServiceProvider 是 SAML 2.0 服务提供方。
type ServiceProvider struct {
	config ServiceProviderConfig
	store  Store
	now    func() time.Time
}

// NewServiceProvider returns a service provider. | NewServiceProvider 返回服务提供方。
func NewServiceProvider(config ServiceProviderConfig) (*ServiceProvider, error) {
	if config.EntityID == "" || config.ACSURL == "" {
		return nil, errs.Detail(ErrInvalidConfig, "entityID and ACSURL are required | entityID 与 ACSURL 必填")
	}
	if config.IDPMetadata == nil || config.IDPMetadata.EntityID == "" {
		return nil, errs.Detail(ErrInvalidConfig, "IdP metadata is required | 需要 IdP 元数据")
	}
	if err := config.IDPMetadata.Validate(Now(config.Now)); err != nil {
		return nil, errs.Wrap(err, ErrInvalidConfig)
	}
	if config.RequestSigningAlg == "" {
		config.RequestSigningAlg = SigAlgRSASHA256
	}
	if config.ProtocolBinding == "" {
		config.ProtocolBinding = BindingHTTPPost
	}
	if config.NameIDFormat == "" {
		config.NameIDFormat = NameIDUnspecified
	}
	if config.ClockSkew <= 0 {
		config.ClockSkew = 2 * time.Minute
	}
	if config.AuthnRequestTTL <= 0 {
		config.AuthnRequestTTL = 10 * time.Minute
	}
	if config.ArtifactResolutionTimeout <= 0 {
		config.ArtifactResolutionTimeout = 10 * time.Second
	}
	if config.ArtifactSOAPVersion == "" {
		config.ArtifactSOAPVersion = SOAPVersion11
	}
	if config.ArtifactSOAPVersion != SOAPVersion11 && config.ArtifactSOAPVersion != SOAPVersion12 {
		return nil, errs.Detail(ErrInvalidConfig, "unsupported artifact SOAP version %[1]q | 不支持的工件 SOAP 版本 %[1]q", config.ArtifactSOAPVersion)
	}
	if config.ArtifactResolutionMaxEndpoints < 0 {
		return nil, errs.Detail(ErrInvalidConfig, "artifact resolution max endpoints is negative | 工件解析最大端点为负")
	}
	if config.ArtifactResolutionMaxEndpoints == 0 {
		config.ArtifactResolutionMaxEndpoints = DefaultArtifactResolutionMaxEndpoints
	}
	if config.ArtifactResolutionMaxEndpoints > MaxArtifactResolutionEndpoints {
		return nil, errs.Detail(ErrInvalidConfig, "artifact resolution max endpoints %d exceeds %d | 工件解析最大端点 %d 超过 %d", config.ArtifactResolutionMaxEndpoints, MaxArtifactResolutionEndpoints, config.ArtifactResolutionMaxEndpoints, MaxArtifactResolutionEndpoints)
	}
	if config.ArtifactResolutionTotalTimeout <= 0 {
		config.ArtifactResolutionTotalTimeout = 3 * config.ArtifactResolutionTimeout
	}
	if len(config.ArtifactSourceID) > 0 && len(config.ArtifactSourceID) != ArtifactSourceIDSize {
		return nil, errs.Detail(ErrInvalidConfig, "artifact source ID must be %d bytes | 工件源标识必须为 %d 字节", ArtifactSourceIDSize, ArtifactSourceIDSize)
	}
	if config.ACSPath == "" {
		config.ACSPath = "/saml/acs"
	}
	if config.SLOPath == "" {
		config.SLOPath = "/saml/slo"
	}
	if config.MetadataPath == "" {
		config.MetadataPath = "/saml/metadata"
	}
	store := config.Store
	if store == nil {
		store = NewMemoryStore()
	}
	provider := &ServiceProvider{config: config, store: store, now: config.Now}
	if provider.now == nil {
		provider.now = time.Now
	}
	return provider, nil
}

// Config returns the configuration. | Config 返回配置。
func (sp *ServiceProvider) Config() ServiceProviderConfig { return sp.config }

// Store returns the correlation store. | Store 返回关联存储。
func (sp *ServiceProvider) Store() Store { return sp.store }

// AuthnRequestURL builds a signed or unsigned AuthnRequest redirect URL. | AuthnRequestURL 构建已签名或未签名的 AuthnRequest 重定向 URL。
func (sp *ServiceProvider) AuthnRequestURL(relayState string) (string, error) {
	now := Now(sp.now)
	idp := sp.config.IDPMetadata
	ssoURL := idp.SSOURL(BindingHTTPRedirect)
	if ssoURL == "" {
		ssoURL = idp.SSOURL("")
	}
	if ssoURL == "" {
		return "", errs.Detail(ErrInvalidMetadata, "IdP has no SSO endpoint | IdP 没有 SSO 端点")
	}
	request := &AuthnRequest{
		ID:                          auth.NewID("id"),
		Version:                     Version,
		IssueInstant:                FormatTime(now),
		Destination:                 ssoURL,
		ProtocolBinding:             sp.config.ProtocolBinding,
		AssertionConsumerServiceURL: sp.config.ACSURL,
		ProviderName:                sp.config.EntityID,
		Issuer:                      &Issuer{Value: sp.config.EntityID},
		NameIDPolicy:                &NameIDPolicy{Format: sp.config.NameIDFormat, AllowCreate: true},
	}
	document, err := xml.Marshal(request)
	if err != nil {
		return "", errs.Wrap(err, ErrInvalidRequest)
	}
	encoded, err := EncodeRedirect(document)
	if err != nil {
		return "", err
	}
	params := url.Values{"SAMLRequest": {encoded}}
	if relayState != "" {
		params.Set("RelayState", relayState)
	}
	if sp.config.RequestSigningKey != nil {
		if err := SignRedirect(params, sp.config.RequestSigningKey, sp.config.RequestSigningAlg, relayState); err != nil {
			return "", err
		}
	}
	state := &RequestState{
		ID:           request.ID,
		SPEntityID:   sp.config.EntityID,
		IDPEntityID:  idp.EntityID,
		ACSURL:       sp.config.ACSURL,
		RelayState:   relayState,
		NameIDFormat: sp.config.NameIDFormat,
		CreatedAt:    now,
		ExpiresAt:    now.Add(sp.config.AuthnRequestTTL),
	}
	if err := sp.store.SaveRequest(context.Background(), state); err != nil {
		return "", err
	}
	location, err := url.Parse(ssoURL)
	if err != nil {
		return "", errs.Wrap(err, ErrInvalidMetadata)
	}
	query := location.Query()
	for key, values := range params {
		for _, value := range values {
			query.Set(key, value)
		}
	}
	location.RawQuery = query.Encode()
	return location.String(), nil
}

// ParseResponse decodes and validates a SAML Response from r. It accepts SAMLart through the
// HTTP-Artifact binding as well as SAMLResponse through the POST and Redirect bindings. | ParseResponse
// 从 r 解码并校验 SAML Response。除 POST 与 Redirect 绑定的 SAMLResponse 外，也接受 HTTP-Artifact
// 绑定的 SAMLart。
func (sp *ServiceProvider) ParseResponse(r *http.Request) (*ValidationResult, error) {
	artifact, artifactRelayState, err := readArtifact(r)
	if err != nil {
		return nil, err
	}
	if artifact != "" {
		raw, err := sp.resolveArtifact(r.Context(), artifact)
		if err != nil {
			return nil, err
		}
		result, err := sp.validateResponse(r.Context(), raw)
		if err != nil {
			return nil, err
		}
		if result.RelayState == "" {
			result.RelayState = artifactRelayState
		}
		return result, nil
	}
	raw, relayState, err := readSAMLResponse(r)
	if err != nil {
		return nil, err
	}
	result, err := sp.validateResponse(r.Context(), raw)
	if err != nil {
		return nil, err
	}
	if result.RelayState == "" {
		result.RelayState = relayState
	}
	return result, nil
}

// validateResponse applies the configured response validation options. | validateResponse 应用配置的
// 响应校验选项。
func (sp *ServiceProvider) validateResponse(ctx context.Context, raw []byte) (*ValidationResult, error) {
	var allowedFormats []string
	if sp.config.NameIDFormat != "" && sp.config.NameIDFormat != NameIDUnspecified {
		allowedFormats = []string{sp.config.NameIDFormat}
	}
	return ValidateResponse(ctx, raw, ResponseValidationOptions{
		SPEntityID:                        sp.config.EntityID,
		ACSURL:                            sp.config.ACSURL,
		IDPEntityID:                       sp.config.IDPMetadata.EntityID,
		Store:                             sp.store,
		AssertionReplayStore:              sp.config.AssertionReplayStore,
		AllowOneTimeUseWithoutReplayStore: sp.config.AllowOneTimeUseWithoutReplayStore,
		SignatureVerifier:                 sp.config.SignatureVerifier,
		Decryptor:                         sp.config.Decryptor,
		RequireSignedResponse:             sp.config.RequireSignedResponse,
		RequireSignedAssertion:            sp.config.RequireSignedAssertion,
		RequireInResponseTo:               !sp.config.AllowIDPInitiated,
		RequireSubjectConfirmation:        sp.config.RequireSubjectConfirmation,
		ClockSkew:                         sp.config.ClockSkew,
		MaxIssueAge:                       sp.config.MaxIssueAge,
		AllowedNameIDFormats:              allowedFormats,
		Now:                               sp.now,
	})
}

// readArtifact extracts a SAMLart and RelayState without requiring either. | readArtifact 提取
// SAMLart 与 RelayState，两者均为可选。
func readArtifact(r *http.Request) (string, string, error) {
	if r == nil {
		return "", "", errs.Detail(ErrInvalidRequest, "request is nil | 请求为空")
	}
	if r.Method == http.MethodPost {
		if err := checkFormBody(r); err != nil {
			return "", "", err
		}
		if err := r.ParseForm(); err != nil {
			return "", "", formParseError(err)
		}
		return r.PostForm.Get(ArtifactParameter), r.PostForm.Get("RelayState"), nil
	}
	return r.URL.Query().Get(ArtifactParameter), r.URL.Query().Get("RelayState"), nil
}

// readSAMLResponse extracts the SAMLResponse and RelayState. | readSAMLResponse 提取 SAMLResponse 与 RelayState。
func readSAMLResponse(r *http.Request) ([]byte, string, error) {
	if r == nil {
		return nil, "", errs.Detail(ErrInvalidRequest, "request is nil | 请求为空")
	}
	value := ""
	relayState := ""
	redirect := false
	if err := checkFormBody(r); err != nil {
		return nil, "", err
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			return nil, "", formParseError(err)
		}
		value = r.PostForm.Get("SAMLResponse")
		relayState = r.PostForm.Get("RelayState")
	} else {
		value = r.URL.Query().Get("SAMLResponse")
		relayState = r.URL.Query().Get("RelayState")
		redirect = true
	}
	if value == "" {
		return nil, "", errs.Detail(ErrInvalidRequest, "SAMLResponse is missing | 缺少 SAMLResponse")
	}
	var decoded []byte
	var err error
	if redirect {
		decoded, err = DecodeRedirect(value)
	} else {
		decoded, err = DecodePost(value)
	}
	if err != nil {
		return nil, "", err
	}
	return decoded, relayState, nil
}

// ACS handles the assertion consumer service. | ACS 处理断言消费服务。
func (sp *ServiceProvider) ACS(w http.ResponseWriter, r *http.Request) {
	boundFormBody(w, r)
	result, err := sp.ParseResponse(r)
	if err != nil {
		if sp.config.ErrorHandler != nil {
			sp.config.ErrorHandler(w, r, err)
			return
		}
		http.Error(w, "saml assertion rejected", http.StatusBadRequest)
		return
	}
	if sp.config.SuccessHandler != nil {
		sp.config.SuccessHandler(w, r, result)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"subject":"` + jsonEscape(result.Principal.Subject) + `","session_index":"` + jsonEscape(result.SessionIndex) + `"}`))
}

// Metadata returns the SP metadata. | Metadata 返回 SP 元数据。
func (sp *ServiceProvider) Metadata() *EntityDescriptor {
	descriptor := &EntityDescriptor{
		EntityID: sp.config.EntityID,
		SPSSODescriptor: &SPSSODescriptor{
			AuthnRequestsSigned:        sp.config.RequestSigningKey != nil,
			WantAssertionsSigned:       sp.config.RequireSignedAssertion,
			ProtocolSupportEnumeration: NamespaceProtocol,
			AssertionConsumerService: []IndexedEndpoint{
				{
					Binding:   BindingHTTPPost,
					Location:  sp.config.ACSURL,
					Index:     0,
					IsDefault: true,
				},
				{
					Binding:  BindingHTTPArtifact,
					Location: sp.config.ACSURL,
					Index:    1,
				},
			},
		},
	}
	if sp.config.SLOURL != "" {
		descriptor.SPSSODescriptor.SingleLogoutService = []Endpoint{{
			Binding:  BindingHTTPPost,
			Location: sp.config.SLOURL,
		}}
	}
	if sp.config.NameIDFormat != "" {
		descriptor.SPSSODescriptor.NameIDFormat = []string{sp.config.NameIDFormat}
	}
	descriptor.SPSSODescriptor.KeyDescriptor = keyDescriptors(sp.config.RequestSigningCertificates, sp.config.EncryptionCertificates)
	return descriptor
}

// MetadataXML returns the marshaled SP metadata. | MetadataXML 返回序列化的 SP 元数据。
func (sp *ServiceProvider) MetadataXML() ([]byte, error) {
	return sp.Metadata().Marshal()
}

// MetadataHandler serves the SP metadata. | MetadataHandler 提供 SP 元数据。
func (sp *ServiceProvider) MetadataHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	data, err := sp.MetadataXML()
	if err != nil {
		http.Error(w, "metadata error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// Register mounts ACS, SLO and metadata on a ydx/router Router. | Register 把 ACS、SLO 与元数据挂载到 ydx/router Router。
func (sp *ServiceProvider) Register(r *router.Router, prefix string) {
	if r == nil {
		return
	}
	r.HandleRaw(http.MethodPost, prefix+sp.config.ACSPath, sp.ACS)
	r.HandleRaw(http.MethodGet, prefix+sp.config.ACSPath, sp.ACS)
	r.HandleRaw(http.MethodGet, prefix+sp.config.MetadataPath, sp.MetadataHandler)
	r.HandleRaw(http.MethodGet, prefix+sp.config.SLOPath, sp.HandleSLO)
	r.HandleRaw(http.MethodPost, prefix+sp.config.SLOPath, sp.HandleSLO)
}

// HTTPHandler returns a net/http handler for the SP endpoints. | HTTPHandler 返回 SP 端点的 net/http 处理器。
func (sp *ServiceProvider) HTTPHandler(prefix string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(prefix+sp.config.ACSPath, sp.ACS)
	mux.HandleFunc(prefix+sp.config.MetadataPath, sp.MetadataHandler)
	mux.HandleFunc(prefix+sp.config.SLOPath, sp.HandleSLO)
	return mux
}

// keyDescriptors builds metadata key descriptors. | keyDescriptors 构建元数据密钥描述符。
func keyDescriptors(signing, encryption []*x509.Certificate) []KeyDescriptor {
	var out []KeyDescriptor
	if len(signing) > 0 {
		out = append(out, KeyDescriptor{Use: "signing", KeyInfo: keyInfoFor(signing)})
	}
	if len(encryption) > 0 {
		out = append(out, KeyDescriptor{Use: "encryption", KeyInfo: keyInfoFor(encryption)})
	}
	return out
}

// keyInfoFor builds an XMLDSig KeyInfo from certificates. | keyInfoFor 从证书构建 XMLDSig KeyInfo。
func keyInfoFor(certificates []*x509.Certificate) *KeyInfo {
	data := X509Data{}
	for _, cert := range certificates {
		if cert != nil {
			data.X509Certificate = append(data.X509Certificate, base64.StdEncoding.EncodeToString(cert.Raw))
		}
	}
	return &KeyInfo{X509Data: []X509Data{data}}
}

// jsonEscape escapes a string for a JSON string literal. | jsonEscape 为 JSON 字符串字面量转义字符串。
func jsonEscape(value string) string {
	var b strings.Builder
	for _, r := range value {
		switch r {
		case '\\', '"':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				b.WriteString(`\u00`)
				const hex = "0123456789abcdef"
				b.WriteByte(hex[(r>>4)&0xf])
				b.WriteByte(hex[r&0xf])
			} else {
				b.WriteRune(r)
			}
		}
	}
	return b.String()
}
