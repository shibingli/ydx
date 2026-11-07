// Package saml implements SAML 2.0 service-provider and identity-provider behavior.
// | Package saml 实现 SAML 2.0 服务提供方与身份提供方行为。
//
// The package covers the Web Browser SSO profile with HTTP-POST, HTTP-Redirect and HTTP-Artifact
// bindings, Single Logout, Metadata, encrypted assertions, XML signatures (including SM2/SM3 when
// configured), name-identifier formats, attribute profiles, replay protection, clock skew and the
// common compatibility switches needed by real-world identity providers. | 本包覆盖 Web Browser SSO
// 的 HTTP-POST、HTTP-Redirect 与 HTTP-Artifact 绑定，单点登出、元数据、加密断言、XML 签名（配置后
// 支持 SM2/SM3）、NameID 格式、属性配置、重放保护、时钟偏移，以及真实身份提供方常见的兼容开关。
//
// The handlers use the ydx/router-native signature shape and are also valid net/http handlers. | 处理器
// 使用 ydx/router 原生签名形状，同时也是合法的 net/http 处理器。
package saml

import (
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
)

// XML namespaces. | XML 命名空间。
const (
	// NamespaceAssertion is the SAML assertion namespace. | NamespaceAssertion 是 SAML 断言命名空间。
	NamespaceAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"
	// NamespaceProtocol is the SAML protocol namespace. | NamespaceProtocol 是 SAML 协议命名空间。
	NamespaceProtocol = "urn:oasis:names:tc:SAML:2.0:protocol"
	// NamespaceMetadata is the SAML metadata namespace. | NamespaceMetadata 是 SAML 元数据命名空间。
	NamespaceMetadata = "urn:oasis:names:tc:SAML:2.0:metadata"
	// NamespaceXMLDSig is the XML Signature namespace. | NamespaceXMLDSig 是 XML 签名命名空间。
	NamespaceXMLDSig = "http://www.w3.org/2000/09/xmldsig#"
	// NamespaceXMLEnc is the XML Encryption namespace. | NamespaceXMLEnc 是 XML 加密命名空间。
	NamespaceXMLEnc = "http://www.w3.org/2001/04/xmlenc#"
	// NamespaceSOAP is the SOAP 1.1 envelope namespace. | NamespaceSOAP 是 SOAP 1.1 信封命名空间。
	NamespaceSOAP = "http://schemas.xmlsoap.org/soap/envelope/"
)

// Version is the SAML protocol version. | Version 是 SAML 协议版本。
const Version = "2.0"

// Status codes. | 状态码。
const (
	// StatusSuccess is the success status. | StatusSuccess 是成功状态。
	StatusSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success"
	// StatusRequester is the requester error status. | StatusRequester 是请求方错误状态。
	StatusRequester = "urn:oasis:names:tc:SAML:2.0:status:Requester"
	// StatusResponder is the responder error status. | StatusResponder 是响应方错误状态。
	StatusResponder = "urn:oasis:names:tc:SAML:2.0:status:Responder"
	// StatusVersionMismatch is the version-mismatch status. | StatusVersionMismatch 是版本不匹配状态。
	StatusVersionMismatch = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch"
	// StatusAuthnFailed is the authentication-failed status. | StatusAuthnFailed 是认证失败状态。
	StatusAuthnFailed = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"
	// StatusNoAuthnContext is the no-authn-context status. | StatusNoAuthnContext 是无认证上下文状态。
	StatusNoAuthnContext = "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext"
	// StatusRequestDenied is the request-denied status. | StatusRequestDenied 是请求被拒绝状态。
	StatusRequestDenied = "urn:oasis:names:tc:SAML:2.0:status:RequestDenied"
	// StatusRequestUnsupported is the request-unsupported status. | StatusRequestUnsupported 是请求不支持状态。
	StatusRequestUnsupported = "urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported"
	// StatusInvalidNameIDPolicy is the invalid-nameid-policy status. | StatusInvalidNameIDPolicy 是非法 NameID 策略状态。
	StatusInvalidNameIDPolicy = "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy"
	// StatusPartialLogout is the partial-logout status. | StatusPartialLogout 是部分登出状态。
	StatusPartialLogout = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout"
	// StatusNoPassive is the passive-authentication-unavailable status. | StatusNoPassive 是无交互认证不可用状态。
	StatusNoPassive = "urn:oasis:names:tc:SAML:2.0:status:NoPassive"
)

// Bindings. | 绑定。
const (
	// BindingHTTPPost is the HTTP-POST binding. | BindingHTTPPost 是 HTTP-POST 绑定。
	BindingHTTPPost = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	// BindingHTTPRedirect is the HTTP-Redirect binding. | BindingHTTPRedirect 是 HTTP-Redirect 绑定。
	BindingHTTPRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	// BindingHTTPArtifact is the HTTP-Artifact binding. | BindingHTTPArtifact 是 HTTP-Artifact 绑定。
	BindingHTTPArtifact = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"
	// BindingSOAP is the SOAP binding. | BindingSOAP 是 SOAP 绑定。
	BindingSOAP = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP"
	// BindingPAOS is the PAOS binding. | BindingPAOS 是 PAOS 绑定。
	BindingPAOS = "urn:oasis:names:tc:SAML:2.0:bindings:PAOS"
)

// Name identifier formats. | 名称标识格式。
const (
	// NameIDUnspecified is the unspecified NameID format. | NameIDUnspecified 是未指定 NameID 格式。
	NameIDUnspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	// NameIDEmailAddress is the emailAddress NameID format. | NameIDEmailAddress 是 emailAddress NameID 格式。
	NameIDEmailAddress = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	// NameIDTransient is the transient NameID format. | NameIDTransient 是 transient NameID 格式。
	NameIDTransient = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
	// NameIDPersistent is the persistent NameID format. | NameIDPersistent 是 persistent NameID 格式。
	NameIDPersistent = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	// NameIDEntity is the entity NameID format. | NameIDEntity 是 entity NameID 格式。
	NameIDEntity = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
	// NameIDKerberos is the Kerberos NameID format. | NameIDKerberos 是 Kerberos NameID 格式。
	NameIDKerberos = "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos"
	// NameIDWindowsDomainQualifiedName is the Windows domain qualified name format. | NameIDWindowsDomainQualifiedName 是 Windows 域限定名格式。
	NameIDWindowsDomainQualifiedName = "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName"
	// NameIDX509SubjectName is the X.509 subject name format. | NameIDX509SubjectName 是 X.509 主体名格式。
	NameIDX509SubjectName = "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName"
)

// Attribute name formats. | 属性名称格式。
const (
	// AttrNameFormatUnspecified is the unspecified attribute name format. | AttrNameFormatUnspecified 是未指定属性名格式。
	AttrNameFormatUnspecified = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"
	// AttrNameFormatURI is the URI attribute name format. | AttrNameFormatURI 是 URI 属性名格式。
	AttrNameFormatURI = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
	// AttrNameFormatBasic is the basic attribute name format. | AttrNameFormatBasic 是 basic 属性名格式。
	AttrNameFormatBasic = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
)

// Authentication context classes. | 认证上下文类。
const (
	// AuthnContextPassword is the password authentication context. | AuthnContextPassword 是口令认证上下文。
	AuthnContextPassword = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"
	// AuthnContextPasswordProtectedTransport is the protected-transport password context. | AuthnContextPasswordProtectedTransport 是受保护传输口令上下文。
	AuthnContextPasswordProtectedTransport = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
	// AuthnContextX509 is the X.509 authentication context. | AuthnContextX509 是 X.509 认证上下文。
	AuthnContextX509 = "urn:oasis:names:tc:SAML:2.0:ac:classes:X509"
	// AuthnContextUnspecified is the unspecified authentication context. | AuthnContextUnspecified 是未指定认证上下文。
	AuthnContextUnspecified = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified"
)

// TimeFormat is the SAML dateTime lexical format. | TimeFormat 是 SAML dateTime 词法格式。
const TimeFormat = "2006-01-02T15:04:05Z07:00"

// The declared sentinels of this package. | 本包的哨兵错误声明。
var (
	// ErrInvalidConfig reports a missing or contradictory configuration. | ErrInvalidConfig 表示配置缺失或矛盾。
	ErrInvalidConfig = errs.New("saml: invalid configuration | saml：配置非法")
	// ErrInvalidRequest reports a malformed SAML request. | ErrInvalidRequest 表示 SAML 请求非法。
	ErrInvalidRequest = errs.New("saml: invalid request | saml：请求非法")
	// ErrInvalidResponse reports a malformed or unsuccessful SAML response. | ErrInvalidResponse 表示 SAML 响应非法或失败。
	ErrInvalidResponse = errs.New("saml: invalid response | saml：响应非法")
	// ErrInvalidSignature reports a failed XML signature verification. | ErrInvalidSignature 表示 XML 签名校验失败。
	ErrInvalidSignature = errs.New("saml: invalid signature | saml：签名无效")
	// ErrInvalidIssuer reports an issuer mismatch. | ErrInvalidIssuer 表示签发方不匹配。
	ErrInvalidIssuer = errs.New("saml: issuer mismatch | saml：签发方不匹配")
	// ErrInvalidAudience reports an audience mismatch. | ErrInvalidAudience 表示受众不匹配。
	ErrInvalidAudience = errs.New("saml: audience mismatch | saml：受众不匹配")
	// ErrInvalidRecipient reports a recipient or destination mismatch. | ErrInvalidRecipient 表示接收方或目标不匹配。
	ErrInvalidRecipient = errs.New("saml: recipient mismatch | saml：接收方不匹配")
	// ErrResponseExpired reports an assertion past NotOnOrAfter. | ErrResponseExpired 表示断言超过 NotOnOrAfter。
	ErrResponseExpired = errs.New("saml: response expired | saml：响应已过期")
	// ErrResponseNotYetValid reports an assertion before NotBefore. | ErrResponseNotYetValid 表示断言早于 NotBefore。
	ErrResponseNotYetValid = errs.New("saml: response not yet valid | saml：响应尚未生效")
	// ErrReplay reports a replayed assertion or request. | ErrReplay 表示断言或请求重放。
	ErrReplay = errs.New("saml: replay detected | saml：检测到重放")
	// ErrStatusFailure reports a non-success SAML status. | ErrStatusFailure 表示 SAML 状态非成功。
	ErrStatusFailure = errs.New("saml: status failure | saml：状态失败")
	// ErrInvalidMetadata reports malformed metadata. | ErrInvalidMetadata 表示元数据非法。
	ErrInvalidMetadata = errs.New("saml: invalid metadata | saml：元数据非法")
	// ErrInvalidBinding reports an unsupported or malformed binding. | ErrInvalidBinding 表示绑定不支持或非法。
	ErrInvalidBinding = errs.New("saml: invalid binding | saml：绑定非法")
	// ErrNoAssertion reports a response without a usable assertion. | ErrNoAssertion 表示响应没有可用断言。
	ErrNoAssertion = errs.New("saml: no assertion | saml：没有断言")
	// ErrDecryption reports a failed encrypted-assertion decryption. | ErrDecryption 表示加密断言解密失败。
	ErrDecryption = errs.New("saml: decryption failed | saml：解密失败")
	// ErrUnsupported reports a feature this build does not implement. | ErrUnsupported 表示本构建未实现该特性。
	ErrUnsupported = errs.New("saml: unsupported | saml：不支持")
	// ErrLoginRequired reports that the IdP needs an authenticated user. | ErrLoginRequired 表示 IdP 需要已认证用户。
	ErrLoginRequired = errs.New("saml: login required | saml：需要登录")
	// ErrLimit reports a message, decompression or body-size limit violation. | ErrLimit 表示消息、解压或
	// 正文大小超过限制。
	ErrLimit = errs.New("saml: limit exceeded | saml：超过限制")
	// ErrArtifactInvalid reports a malformed, unknown or unauthorized SAML artifact. | ErrArtifactInvalid
	// 表示 SAML 工件非法、未知或未授权。
	ErrArtifactInvalid = errs.New("saml: invalid artifact | saml：工件非法")
	// ErrSOAPFault reports a SOAP fault produced by a peer. | ErrSOAPFault 表示对端产生的 SOAP 异常。
	ErrSOAPFault = errs.New("saml: SOAP fault | saml：SOAP 异常")
)

// FormatTime formats t as a SAML dateTime. | FormatTime 把 t 格式化为 SAML dateTime。
func FormatTime(t time.Time) string { return t.UTC().Format(TimeFormat) }

// ParseTime parses a SAML dateTime, accepting fractional seconds. | ParseTime 解析 SAML dateTime，接受小数秒。
func ParseTime(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, errs.Detail(ErrInvalidRequest, "empty SAML time | 空 SAML 时间")
	}
	if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return parsed.UTC(), nil
	}
	parsed, err := time.Parse(TimeFormat, value)
	if err != nil {
		return time.Time{}, errs.WrapDetail(err, ErrInvalidRequest, "time %[1]q | 时间 %[1]q", value)
	}
	return parsed.UTC(), nil
}

// Now returns the UTC time from clock, or time.Now. | Now 返回 clock 的 UTC 时间，或 time.Now。
func Now(clock func() time.Time) time.Time {
	if clock == nil {
		return time.Now().UTC()
	}
	return clock().UTC()
}
