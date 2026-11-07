package saml

import "github.com/shibingli/ydx/xml"

// SignatureMarker records the presence of an XMLDSig Signature element. | SignatureMarker 记录
// XMLDSig Signature 元素的存在。
type SignatureMarker struct {
	// XMLName is the element name. | XMLName 是元素名。
	XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`
}

// Issuer identifies a SAML entity. | Issuer 标识一个 SAML 实体。
type Issuer struct {
	// XMLName is the element name. | XMLName 是元素名。
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	// Format is the optional issuer format. | Format 是可选的签发方格式。
	Format string `xml:"Format,attr,omitempty"`
	// NameQualifier and SPNameQualifier qualify the issuer name. | NameQualifier 与 SPNameQualifier 限定签发方名称。
	NameQualifier   string `xml:"NameQualifier,attr,omitempty"`
	SPNameQualifier string `xml:"SPNameQualifier,attr,omitempty"`
	// Value is the issuer URI. | Value 是签发方 URI。
	Value string `xml:",chardata"`
}

// NameID is a SAML subject identifier. | NameID 是 SAML 主体标识。
type NameID struct {
	// XMLName is the element name. | XMLName 是元素名。
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
	// Format is the name-identifier format. | Format 是名称标识格式。
	Format string `xml:"Format,attr,omitempty"`
	// NameQualifier and SPNameQualifier qualify the identifier. | NameQualifier 与 SPNameQualifier 限定标识。
	NameQualifier   string `xml:"NameQualifier,attr,omitempty"`
	SPNameQualifier string `xml:"SPNameQualifier,attr,omitempty"`
	// SPProvidedID is the service-provider-provided identifier. | SPProvidedID 是服务提供方提供的标识。
	SPProvidedID string `xml:"SPProvidedID,attr,omitempty"`
	// Value is the identifier text. | Value 是标识文本。
	Value string `xml:",chardata"`
}

// Subject identifies the subject of an assertion. | Subject 标识断言主体。
type Subject struct {
	// XMLName is the element name. | XMLName 是元素名。
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Subject"`
	// NameID is the subject identifier. | NameID 是主体标识。
	NameID *NameID `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID,omitempty"`
	// SubjectConfirmation carries the confirmation methods. | SubjectConfirmation 携带确认方法。
	SubjectConfirmation []SubjectConfirmation `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmation,omitempty"`
}

// SubjectConfirmation constrains when a subject is confirmed. | SubjectConfirmation 约束主体何时被确认。
type SubjectConfirmation struct {
	// Method is the confirmation method URI. | Method 是确认方法 URI。
	Method string `xml:"Method,attr"`
	// NameID is an optional confirmation identifier. | NameID 是可选的确认标识。
	NameID *NameID `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID,omitempty"`
	// SubjectConfirmationData carries the confirmation constraints. | SubjectConfirmationData 携带确认约束。
	SubjectConfirmationData *SubjectConfirmationData `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmationData,omitempty"`
}

// SubjectConfirmationData is the bearer confirmation data. | SubjectConfirmationData 是承载确认数据。
type SubjectConfirmationData struct {
	// NotBefore and NotOnOrAfter bound the confirmation window. | NotBefore 与 NotOnOrAfter 限定确认窗口。
	NotBefore    string `xml:"NotBefore,attr,omitempty"`
	NotOnOrAfter string `xml:"NotOnOrAfter,attr,omitempty"`
	// Recipient is the intended ACS URL. | Recipient 是目标 ACS URL。
	Recipient string `xml:"Recipient,attr,omitempty"`
	// InResponseTo is the request identifier being answered. | InResponseTo 是被应答的请求标识。
	InResponseTo string `xml:"InResponseTo,attr,omitempty"`
	// Address is the client address constraint. | Address 是客户端地址约束。
	Address string `xml:"Address,attr,omitempty"`
	// InnerXML preserves extension content. | InnerXML 保留扩展内容。
	InnerXML string `xml:",innerxml"`
}

// Conditions constrain assertion validity. | Conditions 约束断言有效性。
type Conditions struct {
	// NotBefore and NotOnOrAfter bound the validity window. | NotBefore 与 NotOnOrAfter 限定有效窗口。
	NotBefore    string `xml:"NotBefore,attr,omitempty"`
	NotOnOrAfter string `xml:"NotOnOrAfter,attr,omitempty"`
	// AudienceRestriction lists the allowed audiences. | AudienceRestriction 列出允许受众。
	AudienceRestriction []AudienceRestriction `xml:"urn:oasis:names:tc:SAML:2.0:assertion AudienceRestriction,omitempty"`
	// OneTimeUse marks a one-time assertion. | OneTimeUse 标记一次性断言。
	OneTimeUse *OneTimeUse `xml:"urn:oasis:names:tc:SAML:2.0:assertion OneTimeUse,omitempty"`
	// ProxyRestriction limits proxying. | ProxyRestriction 限制代理。
	ProxyRestriction *ProxyRestriction `xml:"urn:oasis:names:tc:SAML:2.0:assertion ProxyRestriction,omitempty"`
}

// AudienceRestriction lists one or more audiences. | AudienceRestriction 列出一个或多个受众。
type AudienceRestriction struct {
	// Audience is the allowed audience list. | Audience 是允许受众列表。
	Audience []string `xml:"urn:oasis:names:tc:SAML:2.0:assertion Audience,omitempty"`
}

// OneTimeUse marks an assertion as single-use. | OneTimeUse 把断言标记为一次性。
type OneTimeUse struct {
	// XMLName is the element name. | XMLName 是元素名。
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion OneTimeUse"`
}

// ProxyRestriction limits the number of proxy hops. | ProxyRestriction 限制代理跳数。
type ProxyRestriction struct {
	// Count is the maximum number of proxies. | Count 是最大代理数量。
	Count int `xml:"Count,attr,omitempty"`
	// Audience lists entities allowed to proxy. | Audience 列出允许代理的实体。
	Audience []string `xml:"urn:oasis:names:tc:SAML:2.0:assertion Audience,omitempty"`
}

// Advice carries additional assertion information. | Advice 携带附加断言信息。
type Advice struct {
	// InnerXML preserves extension content. | InnerXML 保留扩展内容。
	InnerXML string `xml:",innerxml"`
}

// SubjectLocality describes the authenticated client location. | SubjectLocality 描述已认证客户端位置。
type SubjectLocality struct {
	// Address is the client IP address. | Address 是客户端 IP 地址。
	Address string `xml:"Address,attr,omitempty"`
	// DNSName is the client DNS name. | DNSName 是客户端 DNS 名。
	DNSName string `xml:"DNSName,attr,omitempty"`
}

// AuthnContext describes how the subject authenticated. | AuthnContext 描述主体如何认证。
type AuthnContext struct {
	// AuthnContextClassRef is the authentication context class. | AuthnContextClassRef 是认证上下文类。
	AuthnContextClassRef string `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContextClassRef,omitempty"`
	// AuthnContextDeclRef references a context declaration. | AuthnContextDeclRef 引用上下文声明。
	AuthnContextDeclRef string `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContextDeclRef,omitempty"`
	// AuthenticatingAuthorities lists the authenticating authorities. | AuthenticatingAuthorities 列出认证机构。
	AuthenticatingAuthorities []string `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthenticatingAuthority,omitempty"`
}

// AuthnStatement records one authentication event. | AuthnStatement 记录一次认证事件。
type AuthnStatement struct {
	// AuthnInstant is the authentication time. | AuthnInstant 是认证时间。
	AuthnInstant string `xml:"AuthnInstant,attr,omitempty"`
	// SessionIndex is the session identifier. | SessionIndex 是会话标识。
	SessionIndex string `xml:"SessionIndex,attr,omitempty"`
	// SessionNotOnOrAfter is the session expiry. | SessionNotOnOrAfter 是会话过期时间。
	SessionNotOnOrAfter string `xml:"SessionNotOnOrAfter,attr,omitempty"`
	// SubjectLocality describes the client location. | SubjectLocality 描述客户端位置。
	SubjectLocality *SubjectLocality `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectLocality,omitempty"`
	// AuthnContext describes the authentication context. | AuthnContext 描述认证上下文。
	AuthnContext *AuthnContext `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContext,omitempty"`
}

// AttributeValue is one attribute value. | AttributeValue 是一个属性值。
type AttributeValue struct {
	// Type is the xsi:type of the value. | Type 是值的 xsi:type。
	Type string `xml:"http://www.w3.org/2001/XMLSchema-instance type,attr,omitempty"`
	// Value is the text value. | Value 是文本值。
	Value string `xml:",chardata"`
}

// Attribute is a SAML attribute. | Attribute 是 SAML 属性。
type Attribute struct {
	// Name is the attribute name. | Name 是属性名。
	Name string `xml:"Name,attr"`
	// NameFormat is the attribute name format. | NameFormat 是属性名格式。
	NameFormat string `xml:"NameFormat,attr,omitempty"`
	// FriendlyName is a human-readable name. | FriendlyName 是人类可读名称。
	FriendlyName string `xml:"FriendlyName,attr,omitempty"`
	// AttributeValue is the value list. | AttributeValue 是值列表。
	AttributeValue []AttributeValue `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeValue,omitempty"`
}

// AttributeStatement groups attributes. | AttributeStatement 对属性分组。
type AttributeStatement struct {
	// Attribute is the attribute list. | Attribute 是属性列表。
	Attribute []Attribute `xml:"urn:oasis:names:tc:SAML:2.0:assertion Attribute,omitempty"`
}

// Action is an authorization decision action. | Action 是授权决策动作。
type Action struct {
	// Namespace is the action namespace. | Namespace 是动作命名空间。
	Namespace string `xml:"Namespace,attr,omitempty"`
	// Value is the action name. | Value 是动作名。
	Value string `xml:",chardata"`
}

// AuthzDecisionStatement records an authorization decision. | AuthzDecisionStatement 记录授权决策。
type AuthzDecisionStatement struct {
	// Resource is the affected resource. | Resource 是受影响资源。
	Resource string `xml:"Resource,attr,omitempty"`
	// Decision is Permit, Deny or Indeterminate. | Decision 取值为 Permit、Deny 或 Indeterminate。
	Decision string `xml:"Decision,attr,omitempty"`
	// Action lists the decided actions. | Action 列出已决策动作。
	Action []Action `xml:"urn:oasis:names:tc:SAML:2.0:assertion Action,omitempty"`
}

// Assertion is a SAML assertion. | Assertion 是 SAML 断言。
type Assertion struct {
	// XMLName is the element name. | XMLName 是元素名。
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
	// ID is the assertion identifier. | ID 是断言标识。
	ID string `xml:"ID,attr,omitempty"`
	// IssueInstant is the issue time. | IssueInstant 是签发时间。
	IssueInstant string `xml:"IssueInstant,attr,omitempty"`
	// Version is the SAML version. | Version 是 SAML 版本。
	Version string `xml:"Version,attr,omitempty"`
	// Signature marks an XMLDSig signature element. | Signature 标记 XMLDSig 签名元素。
	Signature *SignatureMarker `xml:"http://www.w3.org/2000/09/xmldsig# Signature,omitempty"`
	// Issuer is the assertion issuer. | Issuer 是断言签发方。
	Issuer *Issuer `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer,omitempty"`
	// Subject is the assertion subject. | Subject 是断言主体。
	Subject *Subject `xml:"urn:oasis:names:tc:SAML:2.0:assertion Subject,omitempty"`
	// Conditions constrain validity. | Conditions 约束有效性。
	Conditions *Conditions `xml:"urn:oasis:names:tc:SAML:2.0:assertion Conditions,omitempty"`
	// Advice carries additional information. | Advice 携带附加信息。
	Advice *Advice `xml:"urn:oasis:names:tc:SAML:2.0:assertion Advice,omitempty"`
	// AuthnStatement is the authentication statement list. | AuthnStatement 是认证语句列表。
	AuthnStatement []AuthnStatement `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnStatement,omitempty"`
	// AttributeStatement is the attribute statement list. | AttributeStatement 是属性语句列表。
	AttributeStatement []AttributeStatement `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeStatement,omitempty"`
	// AuthzDecisionStatement is the authorization decision list. | AuthzDecisionStatement 是授权决策列表。
	AuthzDecisionStatement []AuthzDecisionStatement `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthzDecisionStatement,omitempty"`
}

// EncryptedAssertion is an assertion encrypted with XML Encryption. | EncryptedAssertion 是使用
// XML Encryption 加密的断言。
type EncryptedAssertion struct {
	// XMLName is the element name. | XMLName 是元素名。
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion EncryptedAssertion"`
	// InnerXML preserves the encrypted data for xmlsig. | InnerXML 保留加密数据供 xmlsig 使用。
	InnerXML string `xml:",innerxml"`
}

// StatusCode is a SAML status code, optionally nested. | StatusCode 是 SAML 状态码，可嵌套。
type StatusCode struct {
	// Value is the status URI. | Value 是状态 URI。
	Value string `xml:"Value,attr"`
	// StatusCode is the nested status code. | StatusCode 是嵌套状态码。
	StatusCode *StatusCode `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode,omitempty"`
}

// StatusMessage is a human-readable status message. | StatusMessage 是人类可读状态消息。
type StatusMessage struct {
	// Value is the message text. | Value 是消息文本。
	Value string `xml:",chardata"`
}

// StatusDetail carries extension status detail. | StatusDetail 携带扩展状态细节。
type StatusDetail struct {
	// InnerXML preserves extension content. | InnerXML 保留扩展内容。
	InnerXML string `xml:",innerxml"`
}

// Status is a SAML response status. | Status 是 SAML 响应状态。
type Status struct {
	// StatusCode is the status code. | StatusCode 是状态码。
	StatusCode *StatusCode `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode,omitempty"`
	// StatusMessage is the status message. | StatusMessage 是状态消息。
	StatusMessage *StatusMessage `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusMessage,omitempty"`
	// StatusDetail is the status detail. | StatusDetail 是状态细节。
	StatusDetail *StatusDetail `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusDetail,omitempty"`
}

// Response is a SAML protocol response. | Response 是 SAML 协议响应。
type Response struct {
	// XMLName is the element name. | XMLName 是元素名。
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
	// ID is the response identifier. | ID 是响应标识。
	ID string `xml:"ID,attr,omitempty"`
	// InResponseTo is the request identifier being answered. | InResponseTo 是被应答的请求标识。
	InResponseTo string `xml:"InResponseTo,attr,omitempty"`
	// Version is the SAML version. | Version 是 SAML 版本。
	Version string `xml:"Version,attr,omitempty"`
	// IssueInstant is the issue time. | IssueInstant 是签发时间。
	IssueInstant string `xml:"IssueInstant,attr,omitempty"`
	// Destination is the intended recipient URL. | Destination 是目标接收方 URL。
	Destination string `xml:"Destination,attr,omitempty"`
	// Consent is the consent value. | Consent 是同意取值。
	Consent string `xml:"Consent,attr,omitempty"`
	// Signature marks an XMLDSig signature element. | Signature 标记 XMLDSig 签名元素。
	Signature *SignatureMarker `xml:"http://www.w3.org/2000/09/xmldsig# Signature,omitempty"`
	// Issuer is the response issuer. | Issuer 是响应签发方。
	Issuer *Issuer `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer,omitempty"`
	// Status is the response status. | Status 是响应状态。
	Status *Status `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status,omitempty"`
	// Assertion is the assertion list. | Assertion 是断言列表。
	Assertion []Assertion `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion,omitempty"`
	// EncryptedAssertion is the encrypted assertion list. | EncryptedAssertion 是加密断言列表。
	EncryptedAssertion []EncryptedAssertion `xml:"urn:oasis:names:tc:SAML:2.0:assertion EncryptedAssertion,omitempty"`
}

// NameIDPolicy constrains the requested NameID. | NameIDPolicy 约束请求的 NameID。
type NameIDPolicy struct {
	// Format is the requested format. | Format 是请求的格式。
	Format string `xml:"Format,attr,omitempty"`
	// SPNameQualifier is the requested SP qualifier. | SPNameQualifier 是请求的 SP 限定符。
	SPNameQualifier string `xml:"SPNameQualifier,attr,omitempty"`
	// AllowCreate permits the IdP to create an identifier. | AllowCreate 允许 IdP 创建标识。
	AllowCreate bool `xml:"AllowCreate,attr,omitempty"`
}

// RequestedAuthnContext requests authentication context classes. | RequestedAuthnContext 请求认证上下文类。
type RequestedAuthnContext struct {
	// Comparison is exact, minimum, maximum or better. | Comparison 取值为 exact、minimum、maximum 或 better。
	Comparison string `xml:"Comparison,attr,omitempty"`
	// AuthnContextClassRef lists requested classes. | AuthnContextClassRef 列出请求类。
	AuthnContextClassRef []string `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContextClassRef,omitempty"`
	// AuthnContextDeclRef lists requested declarations. | AuthnContextDeclRef 列出请求声明。
	AuthnContextDeclRef []string `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContextDeclRef,omitempty"`
}

// IDPEntry identifies one identity provider. | IDPEntry 标识一个身份提供方。
type IDPEntry struct {
	// ProviderID is the IdP entity ID. | ProviderID 是 IdP 实体标识。
	ProviderID string `xml:"ProviderID,attr,omitempty"`
	// Name is a human-readable name. | Name 是人类可读名称。
	Name string `xml:"Name,attr,omitempty"`
	// Loc is the location hint. | Loc 是位置提示。
	Loc string `xml:"Loc,attr,omitempty"`
}

// IDPList lists identity providers. | IDPList 列出身份提供方。
type IDPList struct {
	// IDPEntry is the provider list. | IDPEntry 是提供方列表。
	IDPEntry []IDPEntry `xml:"urn:oasis:names:tc:SAML:2.0:protocol IDPEntry,omitempty"`
}

// Scoping carries IdP discovery hints. | Scoping 携带 IdP 发现提示。
type Scoping struct {
	// IDPList is the provider list. | IDPList 是提供方列表。
	IDPList *IDPList `xml:"urn:oasis:names:tc:SAML:2.0:protocol IDPList,omitempty"`
	// RequesterID lists the requester identifiers. | RequesterID 列出请求方标识。
	RequesterID []string `xml:"urn:oasis:names:tc:SAML:2.0:protocol RequesterID,omitempty"`
}

// AuthnRequest is a SAML authentication request. | AuthnRequest 是 SAML 认证请求。
type AuthnRequest struct {
	// XMLName is the element name. | XMLName 是元素名。
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`
	// ID is the request identifier. | ID 是请求标识。
	ID string `xml:"ID,attr,omitempty"`
	// Version is the SAML version. | Version 是 SAML 版本。
	Version string `xml:"Version,attr,omitempty"`
	// IssueInstant is the issue time. | IssueInstant 是签发时间。
	IssueInstant string `xml:"IssueInstant,attr,omitempty"`
	// Destination is the intended IdP URL. | Destination 是目标 IdP URL。
	Destination string `xml:"Destination,attr,omitempty"`
	// Consent is the consent value. | Consent 是同意取值。
	Consent string `xml:"Consent,attr,omitempty"`
	// ForceAuthn forces re-authentication. | ForceAuthn 强制重新认证。
	ForceAuthn bool `xml:"ForceAuthn,attr,omitempty"`
	// IsPassive requires no user interaction. | IsPassive 要求无用户交互。
	IsPassive bool `xml:"IsPassive,attr,omitempty"`
	// ProtocolBinding is the requested response binding. | ProtocolBinding 是请求的响应绑定。
	ProtocolBinding string `xml:"ProtocolBinding,attr,omitempty"`
	// AssertionConsumerServiceURL is the SP ACS URL. | AssertionConsumerServiceURL 是 SP ACS URL。
	AssertionConsumerServiceURL string `xml:"AssertionConsumerServiceURL,attr,omitempty"`
	// AttributeConsumingServiceIndex selects an attribute service. | AttributeConsumingServiceIndex 选择属性服务。
	AttributeConsumingServiceIndex *int `xml:"AttributeConsumingServiceIndex,attr,omitempty"`
	// ProviderName is a human-readable SP name. | ProviderName 是人类可读 SP 名称。
	ProviderName string `xml:"ProviderName,attr,omitempty"`
	// Signature marks an XMLDSig signature element. | Signature 标记 XMLDSig 签名元素。
	Signature *SignatureMarker `xml:"http://www.w3.org/2000/09/xmldsig# Signature,omitempty"`
	// Issuer is the SP issuer. | Issuer 是 SP 签发方。
	Issuer *Issuer `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer,omitempty"`
	// Subject is an optional requested subject. | Subject 是可选请求主体。
	Subject *Subject `xml:"urn:oasis:names:tc:SAML:2.0:assertion Subject,omitempty"`
	// NameIDPolicy constrains the NameID. | NameIDPolicy 约束 NameID。
	NameIDPolicy *NameIDPolicy `xml:"urn:oasis:names:tc:SAML:2.0:protocol NameIDPolicy,omitempty"`
	// Conditions constrains the assertion. | Conditions 约束断言。
	Conditions *Conditions `xml:"urn:oasis:names:tc:SAML:2.0:assertion Conditions,omitempty"`
	// RequestedAuthnContext requests authentication classes. | RequestedAuthnContext 请求认证类。
	RequestedAuthnContext *RequestedAuthnContext `xml:"urn:oasis:names:tc:SAML:2.0:protocol RequestedAuthnContext,omitempty"`
	// Scoping carries discovery hints. | Scoping 携带发现提示。
	Scoping *Scoping `xml:"urn:oasis:names:tc:SAML:2.0:protocol Scoping,omitempty"`
}

// LogoutRequest is a SAML single-logout request. | LogoutRequest 是 SAML 单点登出请求。
type LogoutRequest struct {
	// XMLName is the element name. | XMLName 是元素名。
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol LogoutRequest"`
	// ID is the request identifier. | ID 是请求标识。
	ID string `xml:"ID,attr,omitempty"`
	// Version is the SAML version. | Version 是 SAML 版本。
	Version string `xml:"Version,attr,omitempty"`
	// IssueInstant is the issue time. | IssueInstant 是签发时间。
	IssueInstant string `xml:"IssueInstant,attr,omitempty"`
	// Destination is the intended recipient. | Destination 是目标接收方。
	Destination string `xml:"Destination,attr,omitempty"`
	// Reason is the logout reason. | Reason 是登出原因。
	Reason string `xml:"Reason,attr,omitempty"`
	// NotOnOrAfter is the request expiry. | NotOnOrAfter 是请求过期时间。
	NotOnOrAfter string `xml:"NotOnOrAfter,attr,omitempty"`
	// Signature marks an XMLDSig signature element. | Signature 标记 XMLDSig 签名元素。
	Signature *SignatureMarker `xml:"http://www.w3.org/2000/09/xmldsig# Signature,omitempty"`
	// Issuer is the requester issuer. | Issuer 是请求方签发方。
	Issuer *Issuer `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer,omitempty"`
	// NameID is the subject to log out. | NameID 是待登出主体。
	NameID *NameID `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID,omitempty"`
	// SessionIndex lists sessions to terminate. | SessionIndex 列出待终止会话。
	SessionIndex []string `xml:"urn:oasis:names:tc:SAML:2.0:protocol SessionIndex,omitempty"`
}

// LogoutResponse is a SAML single-logout response. | LogoutResponse 是 SAML 单点登出响应。
type LogoutResponse struct {
	// XMLName is the element name. | XMLName 是元素名。
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol LogoutResponse"`
	// ID is the response identifier. | ID 是响应标识。
	ID string `xml:"ID,attr,omitempty"`
	// InResponseTo is the request identifier. | InResponseTo 是请求标识。
	InResponseTo string `xml:"InResponseTo,attr,omitempty"`
	// Version is the SAML version. | Version 是 SAML 版本。
	Version string `xml:"Version,attr,omitempty"`
	// IssueInstant is the issue time. | IssueInstant 是签发时间。
	IssueInstant string `xml:"IssueInstant,attr,omitempty"`
	// Destination is the intended recipient. | Destination 是目标接收方。
	Destination string `xml:"Destination,attr,omitempty"`
	// Signature marks an XMLDSig signature element. | Signature 标记 XMLDSig 签名元素。
	Signature *SignatureMarker `xml:"http://www.w3.org/2000/09/xmldsig# Signature,omitempty"`
	// Issuer is the responder issuer. | Issuer 是响应方签发方。
	Issuer *Issuer `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer,omitempty"`
	// Status is the response status. | Status 是响应状态。
	Status *Status `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status,omitempty"`
}

// ArtifactResolve is a SAML artifact-resolution request. | ArtifactResolve 是 SAML 工件解析请求。
type ArtifactResolve struct {
	// XMLName is the element name. | XMLName 是元素名。
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol ArtifactResolve"`
	// ID is the request identifier. | ID 是请求标识。
	ID string `xml:"ID,attr,omitempty"`
	// Version is the SAML version. | Version 是 SAML 版本。
	Version string `xml:"Version,attr,omitempty"`
	// IssueInstant is the issue time. | IssueInstant 是签发时间。
	IssueInstant string `xml:"IssueInstant,attr,omitempty"`
	// Destination is the intended recipient URL. | Destination 是目标接收方 URL。
	Destination string `xml:"Destination,attr,omitempty"`
	// Consent is the consent value. | Consent 是同意取值。
	Consent string `xml:"Consent,attr,omitempty"`
	// Issuer is the requester issuer. | Issuer 是请求方签发方。
	Issuer *Issuer `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer,omitempty"`
	// Signature marks an XMLDSig signature element. | Signature 标记 XMLDSig 签名元素。
	Signature *SignatureMarker `xml:"http://www.w3.org/2000/09/xmldsig# Signature,omitempty"`
	// Artifact is the artifact to resolve. | Artifact 是待解析工件。
	Artifact string `xml:"urn:oasis:names:tc:SAML:2.0:protocol Artifact,omitempty"`
}

// ArtifactResponse is a SAML artifact-resolution response. | ArtifactResponse 是 SAML 工件解析响应。
type ArtifactResponse struct {
	// XMLName is the element name. | XMLName 是元素名。
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol ArtifactResponse"`
	// ID is the response identifier. | ID 是响应标识。
	ID string `xml:"ID,attr,omitempty"`
	// InResponseTo is the request identifier. | InResponseTo 是请求标识。
	InResponseTo string `xml:"InResponseTo,attr,omitempty"`
	// Version is the SAML version. | Version 是 SAML 版本。
	Version string `xml:"Version,attr,omitempty"`
	// IssueInstant is the issue time. | IssueInstant 是签发时间。
	IssueInstant string `xml:"IssueInstant,attr,omitempty"`
	// Destination is the intended recipient URL. | Destination 是目标接收方 URL。
	Destination string `xml:"Destination,attr,omitempty"`
	// Consent is the consent value. | Consent 是同意取值。
	Consent string `xml:"Consent,attr,omitempty"`
	// Issuer is the responder issuer. | Issuer 是响应方签发方。
	Issuer *Issuer `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer,omitempty"`
	// Signature marks an XMLDSig signature element. | Signature 标记 XMLDSig 签名元素。
	Signature *SignatureMarker `xml:"http://www.w3.org/2000/09/xmldsig# Signature,omitempty"`
	// Status is the response status. | Status 是响应状态。
	Status *Status `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status,omitempty"`
	// Response is the embedded protocol response. | Response 是嵌入的协议响应。
	Response *Response `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response,omitempty"`
}

// StatusResponse is a bare SAML status response. | StatusResponse 是仅含状态的 SAML 响应。
type StatusResponse struct {
	// XMLName is the element name. | XMLName 是元素名。
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusResponse"`
	// ID is the response identifier. | ID 是响应标识。
	ID string `xml:"ID,attr,omitempty"`
	// InResponseTo is the request identifier. | InResponseTo 是请求标识。
	InResponseTo string `xml:"InResponseTo,attr,omitempty"`
	// Version is the SAML version. | Version 是 SAML 版本。
	Version string `xml:"Version,attr,omitempty"`
	// IssueInstant is the issue time. | IssueInstant 是签发时间。
	IssueInstant string `xml:"IssueInstant,attr,omitempty"`
	// Destination is the intended recipient. | Destination 是目标接收方。
	Destination string `xml:"Destination,attr,omitempty"`
	// Issuer is the responder issuer. | Issuer 是响应方签发方。
	Issuer *Issuer `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer,omitempty"`
	// Status is the response status. | Status 是响应状态。
	Status *Status `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status,omitempty"`
}
