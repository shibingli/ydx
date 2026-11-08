package saml

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"time"

	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/xml"
)

// KeyDescriptor describes a signing or encryption key. | KeyDescriptor 描述签名或加密密钥。
type KeyDescriptor struct {
	// Use is "signing", "encryption" or empty. | Use 取值为 "signing"、"encryption" 或空。
	Use string `xml:"use,attr,omitempty"`
	// KeyInfo carries the key material. | KeyInfo 携带密钥材料。
	KeyInfo *KeyInfo `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo,omitempty"`
}

// KeyInfo is an XMLDSig KeyInfo element. | KeyInfo 是 XMLDSig KeyInfo 元素。
type KeyInfo struct {
	// KeyName is an optional key name. | KeyName 是可选密钥名。
	KeyName []string `xml:"http://www.w3.org/2000/09/xmldsig# KeyName,omitempty"`
	// X509Data carries X.509 certificates and identifiers. | X509Data 携带 X.509 证书与标识。
	X509Data []X509Data `xml:"http://www.w3.org/2000/09/xmldsig# X509Data,omitempty"`
}

// X509Data is an XMLDSig X509Data element. | X509Data 是 XMLDSig X509Data 元素。
type X509Data struct {
	// X509Certificate is the base64 DER certificate list. | X509Certificate 是 base64 DER 证书列表。
	X509Certificate []string `xml:"http://www.w3.org/2000/09/xmldsig# X509Certificate,omitempty"`
	// X509SubjectName is the certificate subject name list. | X509SubjectName 是证书主体名列表。
	X509SubjectName []string `xml:"http://www.w3.org/2000/09/xmldsig# X509SubjectName,omitempty"`
	// X509IssuerSerial is the issuer and serial list. | X509IssuerSerial 是签发者与序列号列表。
	X509IssuerSerial []X509IssuerSerial `xml:"http://www.w3.org/2000/09/xmldsig# X509IssuerSerial,omitempty"`
	// X509SKI is the subject key identifier list. | X509SKI 是主体密钥标识列表。
	X509SKI []string `xml:"http://www.w3.org/2000/09/xmldsig# X509SKI,omitempty"`
}

// X509IssuerSerial pairs an issuer name with a serial number. | X509IssuerSerial 把签发者名与序列号配对。
type X509IssuerSerial struct {
	// X509IssuerName is the issuer distinguished name. | X509IssuerName 是签发者可分辨名称。
	X509IssuerName string `xml:"http://www.w3.org/2000/09/xmldsig# X509IssuerName"`
	// X509SerialNumber is the certificate serial number. | X509SerialNumber 是证书序列号。
	X509SerialNumber string `xml:"http://www.w3.org/2000/09/xmldsig# X509SerialNumber"`
}

// Endpoint is a SAML binding endpoint. | Endpoint 是 SAML 绑定端点。
type Endpoint struct {
	// Binding is the binding URI. | Binding 是绑定 URI。
	Binding string `xml:"Binding,attr"`
	// Location is the endpoint URL. | Location 是端点 URL。
	Location string `xml:"Location,attr"`
	// ResponseLocation is the response URL for asynchronous bindings. | ResponseLocation 是异步绑定的响应 URL。
	ResponseLocation string `xml:"ResponseLocation,attr,omitempty"`
}

// IndexedEndpoint is an endpoint with an index and default flag. | IndexedEndpoint 是带索引与默认标志的端点。
type IndexedEndpoint struct {
	// Binding is the binding URI. | Binding 是绑定 URI。
	Binding string `xml:"Binding,attr"`
	// Location is the endpoint URL. | Location 是端点 URL。
	Location string `xml:"Location,attr"`
	// ResponseLocation is the response URL. | ResponseLocation 是响应 URL。
	ResponseLocation string `xml:"ResponseLocation,attr,omitempty"`
	// Index is the endpoint index. | Index 是端点索引。
	Index int `xml:"index,attr"`
	// IsDefault marks the default endpoint. | IsDefault 标记默认端点。
	IsDefault bool `xml:"isDefault,attr,omitempty"`
}

// LocalizedName is a language-tagged string. | LocalizedName 是带语言标签的字符串。
type LocalizedName struct {
	// Lang is the xml:lang value. | Lang 是 xml:lang 取值。
	Lang string `xml:"http://www.w3.org/XML/1998/namespace lang,attr,omitempty"`
	// Value is the localized text. | Value 是本地化文本。
	Value string `xml:",chardata"`
}

// RequestedAttribute is an attribute requested by an SP. | RequestedAttribute 是 SP 请求的属性。
type RequestedAttribute struct {
	// Name is the attribute name. | Name 是属性名。
	Name string `xml:"Name,attr"`
	// NameFormat is the attribute name format. | NameFormat 是属性名格式。
	NameFormat string `xml:"NameFormat,attr,omitempty"`
	// FriendlyName is a human-readable name. | FriendlyName 是人类可读名称。
	FriendlyName string `xml:"FriendlyName,attr,omitempty"`
	// IsRequired marks a required attribute. | IsRequired 标记必需属性。
	IsRequired bool `xml:"isRequired,attr,omitempty"`
	// AttributeValue is an optional value constraint. | AttributeValue 是可选值约束。
	AttributeValue []string `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeValue,omitempty"`
}

// AttributeConsumingService describes an SP attribute service. | AttributeConsumingService 描述 SP 属性服务。
type AttributeConsumingService struct {
	// Index is the service index. | Index 是服务索引。
	Index int `xml:"index,attr"`
	// IsDefault marks the default service. | IsDefault 标记默认服务。
	IsDefault bool `xml:"isDefault,attr,omitempty"`
	// ServiceName is the service name list. | ServiceName 是服务名列表。
	ServiceName []LocalizedName `xml:"urn:oasis:names:tc:SAML:2.0:metadata ServiceName,omitempty"`
	// ServiceDescription is the service description list. | ServiceDescription 是服务描述列表。
	ServiceDescription []LocalizedName `xml:"urn:oasis:names:tc:SAML:2.0:metadata ServiceDescription,omitempty"`
	// RequestedAttribute is the requested attribute list. | RequestedAttribute 是请求属性列表。
	RequestedAttribute []RequestedAttribute `xml:"urn:oasis:names:tc:SAML:2.0:metadata RequestedAttribute,omitempty"`
}

// Organization describes a SAML entity organization. | Organization 描述 SAML 实体组织。
type Organization struct {
	// OrganizationName is the organization name list. | OrganizationName 是组织名列表。
	OrganizationName []LocalizedName `xml:"urn:oasis:names:tc:SAML:2.0:metadata OrganizationName,omitempty"`
	// OrganizationDisplayName is the display name list. | OrganizationDisplayName 是展示名列表。
	OrganizationDisplayName []LocalizedName `xml:"urn:oasis:names:tc:SAML:2.0:metadata OrganizationDisplayName,omitempty"`
	// OrganizationURL is the URL list. | OrganizationURL 是 URL 列表。
	OrganizationURL []LocalizedName `xml:"urn:oasis:names:tc:SAML:2.0:metadata OrganizationURL,omitempty"`
}

// ContactPerson describes a SAML entity contact. | ContactPerson 描述 SAML 实体联系人。
type ContactPerson struct {
	// ContactType is technical, support, administrative, billing or other. | ContactType 取值为 technical、support、administrative、billing 或 other。
	ContactType string `xml:"contactType,attr"`
	// Company is the company name. | Company 是公司名。
	Company string `xml:"urn:oasis:names:tc:SAML:2.0:metadata Company,omitempty"`
	// GivenName is the given name. | GivenName 是名。
	GivenName string `xml:"urn:oasis:names:tc:SAML:2.0:metadata GivenName,omitempty"`
	// SurName is the surname. | SurName 是姓。
	SurName string `xml:"urn:oasis:names:tc:SAML:2.0:metadata SurName,omitempty"`
	// EmailAddress is the email address list. | EmailAddress 是邮箱地址列表。
	EmailAddress []string `xml:"urn:oasis:names:tc:SAML:2.0:metadata EmailAddress,omitempty"`
	// TelephoneNumber is the phone number list. | TelephoneNumber 是电话号码列表。
	TelephoneNumber []string `xml:"urn:oasis:names:tc:SAML:2.0:metadata TelephoneNumber,omitempty"`
}

// IDPSSODescriptor describes an identity provider. | IDPSSODescriptor 描述身份提供方。
type IDPSSODescriptor struct {
	// WantAuthnRequestsSigned reports whether signed requests are required. | WantAuthnRequestsSigned 报告是否要求签名请求。
	WantAuthnRequestsSigned bool `xml:"WantAuthnRequestsSigned,attr,omitempty"`
	// ProtocolSupportEnumeration is the supported protocol list. | ProtocolSupportEnumeration 是支持的协议列表。
	ProtocolSupportEnumeration string `xml:"protocolSupportEnumeration,attr,omitempty"`
	// KeyDescriptor is the key list. | KeyDescriptor 是密钥列表。
	KeyDescriptor []KeyDescriptor `xml:"urn:oasis:names:tc:SAML:2.0:metadata KeyDescriptor,omitempty"`
	// SingleLogoutService is the SLO endpoint list. | SingleLogoutService 是 SLO 端点列表。
	SingleLogoutService []Endpoint `xml:"urn:oasis:names:tc:SAML:2.0:metadata SingleLogoutService,omitempty"`
	// SingleSignOnService is the SSO endpoint list. | SingleSignOnService 是 SSO 端点列表。
	SingleSignOnService []Endpoint `xml:"urn:oasis:names:tc:SAML:2.0:metadata SingleSignOnService,omitempty"`
	// ArtifactResolutionService is the artifact endpoint list. | ArtifactResolutionService 是工件端点列表。
	ArtifactResolutionService []IndexedEndpoint `xml:"urn:oasis:names:tc:SAML:2.0:metadata ArtifactResolutionService,omitempty"`
	// NameIDFormat is the supported NameID format list. | NameIDFormat 是支持的 NameID 格式列表。
	NameIDFormat []string `xml:"urn:oasis:names:tc:SAML:2.0:metadata NameIDFormat,omitempty"`
	// Attribute is the supported attribute list. | Attribute 是支持的属性列表。
	Attribute []Attribute `xml:"urn:oasis:names:tc:SAML:2.0:assertion Attribute,omitempty"`
}

// SPSSODescriptor describes a service provider. | SPSSODescriptor 描述服务提供方。
type SPSSODescriptor struct {
	// AuthnRequestsSigned reports whether requests are signed. | AuthnRequestsSigned 报告请求是否签名。
	AuthnRequestsSigned bool `xml:"AuthnRequestsSigned,attr,omitempty"`
	// WantAssertionsSigned reports whether signed assertions are required. | WantAssertionsSigned 报告是否要求签名断言。
	WantAssertionsSigned bool `xml:"WantAssertionsSigned,attr,omitempty"`
	// ProtocolSupportEnumeration is the supported protocol list. | ProtocolSupportEnumeration 是支持的协议列表。
	ProtocolSupportEnumeration string `xml:"protocolSupportEnumeration,attr,omitempty"`
	// KeyDescriptor is the key list. | KeyDescriptor 是密钥列表。
	KeyDescriptor []KeyDescriptor `xml:"urn:oasis:names:tc:SAML:2.0:metadata KeyDescriptor,omitempty"`
	// SingleLogoutService is the SLO endpoint list. | SingleLogoutService 是 SLO 端点列表。
	SingleLogoutService []Endpoint `xml:"urn:oasis:names:tc:SAML:2.0:metadata SingleLogoutService,omitempty"`
	// AssertionConsumerService is the ACS endpoint list. | AssertionConsumerService 是 ACS 端点列表。
	AssertionConsumerService []IndexedEndpoint `xml:"urn:oasis:names:tc:SAML:2.0:metadata AssertionConsumerService,omitempty"`
	// AttributeConsumingService is the attribute service list. | AttributeConsumingService 是属性服务列表。
	AttributeConsumingService []AttributeConsumingService `xml:"urn:oasis:names:tc:SAML:2.0:metadata AttributeConsumingService,omitempty"`
	// NameIDFormat is the supported NameID format list. | NameIDFormat 是支持的 NameID 格式列表。
	NameIDFormat []string `xml:"urn:oasis:names:tc:SAML:2.0:metadata NameIDFormat,omitempty"`
}

// EntityDescriptor is a SAML metadata entity. | EntityDescriptor 是 SAML 元数据实体。
type EntityDescriptor struct {
	// XMLName is the element name. | XMLName 是元素名。
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	// ID is the metadata identifier. | ID 是元数据标识。
	ID string `xml:"ID,attr,omitempty"`
	// EntityID is the entity identifier. | EntityID 是实体标识。
	EntityID string `xml:"entityID,attr"`
	// ValidUntil is the metadata expiry. | ValidUntil 是元数据过期时间。
	ValidUntil string `xml:"validUntil,attr,omitempty"`
	// CacheDuration is the cache duration. | CacheDuration 是缓存时长。
	CacheDuration string `xml:"cacheDuration,attr,omitempty"`
	// IDPSSODescriptor is the IdP descriptor. | IDPSSODescriptor 是 IdP 描述符。
	IDPSSODescriptor *IDPSSODescriptor `xml:"urn:oasis:names:tc:SAML:2.0:metadata IDPSSODescriptor,omitempty"`
	// SPSSODescriptor is the SP descriptor. | SPSSODescriptor 是 SP 描述符。
	SPSSODescriptor *SPSSODescriptor `xml:"urn:oasis:names:tc:SAML:2.0:metadata SPSSODescriptor,omitempty"`
	// Organization is the organization metadata. | Organization 是组织元数据。
	Organization *Organization `xml:"urn:oasis:names:tc:SAML:2.0:metadata Organization,omitempty"`
	// ContactPerson is the contact list. | ContactPerson 是联系人列表。
	ContactPerson []ContactPerson `xml:"urn:oasis:names:tc:SAML:2.0:metadata ContactPerson,omitempty"`
}

// ParseEntityDescriptor parses one SAML metadata document. | ParseEntityDescriptor 解析一个 SAML 元数据文档。
func ParseEntityDescriptor(data []byte) (*EntityDescriptor, error) {
	var descriptor EntityDescriptor
	if err := xml.Unmarshal(data, &descriptor); err != nil {
		return nil, errs.Wrap(err, ErrInvalidMetadata)
	}
	if descriptor.EntityID == "" {
		return nil, errs.Detail(ErrInvalidMetadata, "entityID is missing | 缺少 entityID")
	}
	return &descriptor, nil
}

// Validate checks the entity identifier and the optional validUntil and cacheDuration values. A
// descriptor without validUntil never expires. | Validate 检查实体标识与可选的 validUntil 和
// cacheDuration 取值。没有 validUntil 的描述符永不过期。
func (d *EntityDescriptor) Validate(now time.Time) error {
	if d == nil || d.EntityID == "" {
		return errs.Detail(ErrInvalidMetadata, "entityID is missing | 缺少 entityID")
	}
	now = now.UTC()
	if d.ValidUntil != "" {
		validUntil, err := ParseTime(d.ValidUntil)
		if err != nil {
			return errs.WrapDetail(err, ErrInvalidMetadata, "validUntil is invalid | validUntil 非法")
		}
		if !now.Before(validUntil) {
			return errs.Detail(ErrInvalidMetadata, "metadata expired at %s | 元数据已于 %s 过期", d.ValidUntil, d.ValidUntil)
		}
	}
	if d.CacheDuration != "" {
		if err := parseXSDuration(d.CacheDuration); err != nil {
			return errs.WrapDetail(err, ErrInvalidMetadata, "cacheDuration is invalid | cacheDuration 非法")
		}
	}
	if d.IDPSSODescriptor == nil && d.SPSSODescriptor == nil {
		return errs.Detail(ErrInvalidMetadata, "entity has no role descriptor | 实体没有角色描述符")
	}
	if d.IDPSSODescriptor != nil && d.SPSSODescriptor != nil {
		return errs.Detail(ErrInvalidMetadata, "entity has conflicting role descriptors | 实体角色描述符冲突")
	}
	return nil
}

// parseXSDuration validates an xs:duration lexical value. Date and time designators must appear in
// schema order without duplicates, and only seconds may carry a fraction. | parseXSDuration 校验
// xs:duration 词法值。日期与时间指示符必须按 schema 顺序出现且不得重复，仅秒可以带小数。
func parseXSDuration(value string) error {
	original := value
	value = strings.TrimPrefix(value, "-")
	if !strings.HasPrefix(value, "P") {
		return durationError(original)
	}
	value = value[1:]
	datePart, timePart, hasTime := strings.Cut(value, "T")
	if hasTime && timePart == "" {
		return durationError(original)
	}
	seen := false
	if err := consumeDurationPart(datePart, "YMD", false, original, &seen); err != nil {
		return err
	}
	if hasTime {
		if err := consumeDurationPart(timePart, "HMS", true, original, &seen); err != nil {
			return err
		}
	}
	if !seen {
		return durationError(original)
	}
	return nil
}

// consumeDurationPart consumes the ordered designators of one xs:duration part. When fractions is
// true only the final seconds designator may carry a decimal fraction. |
// consumeDurationPart 消费 xs:duration 单个部分中按顺序排列的指示符。fractions 为 true 时仅最后的
// 秒指示符可以带小数。
func consumeDurationPart(part, units string, fractions bool, original string, seen *bool) error {
	unitIndex := 0
	for part != "" {
		digitEnd := 0
		for digitEnd < len(part) && part[digitEnd] >= '0' && part[digitEnd] <= '9' {
			digitEnd++
		}
		if digitEnd == 0 {
			return durationError(original)
		}
		unitEnd := digitEnd
		if fractions && digitEnd < len(part) && part[digitEnd] == '.' {
			unitEnd = digitEnd + 1
			for unitEnd < len(part) && part[unitEnd] >= '0' && part[unitEnd] <= '9' {
				unitEnd++
			}
			if unitEnd == digitEnd+1 {
				return durationError(original)
			}
		}
		if unitEnd >= len(part) {
			return durationError(original)
		}
		unit := part[unitEnd]
		position := strings.IndexByte(units, unit)
		if position < 0 || position < unitIndex {
			return durationError(original)
		}
		if unitEnd != digitEnd && (unit != 'S' || unitEnd+1 != len(part)) {
			return durationError(original)
		}
		unitIndex = position + 1
		*seen = true
		part = part[unitEnd+1:]
	}
	return nil
}

// durationError returns the shared invalid-duration error. | durationError 返回统一的非法时长错误。
func durationError(original string) error {
	return errs.Detail(ErrInvalidMetadata, "duration %[1]q | 时长 %[1]q", original)
}

// Marshal encodes the descriptor as XML. | Marshal 把描述符编码为 XML。
func (d *EntityDescriptor) Marshal() ([]byte, error) {
	if d == nil || d.EntityID == "" {
		return nil, errs.Detail(ErrInvalidMetadata, "entityID is missing | 缺少 entityID")
	}
	data, err := xml.Marshal(d)
	if err != nil {
		return nil, errs.Wrap(err, ErrInvalidMetadata)
	}
	return data, nil
}

// Certificates returns the certificates for a key use ("signing", "encryption" or ""). | Certificates
// 返回指定密钥用途（"signing"、"encryption" 或 ""）的证书。
func (d *EntityDescriptor) Certificates(use string) ([]*x509.Certificate, error) {
	if d == nil {
		return nil, nil
	}
	var descriptors []KeyDescriptor
	switch {
	case d.IDPSSODescriptor != nil:
		descriptors = d.IDPSSODescriptor.KeyDescriptor
	case d.SPSSODescriptor != nil:
		descriptors = d.SPSSODescriptor.KeyDescriptor
	}
	return certificatesFromKeyDescriptors(descriptors, use)
}

// certificatesFromKeyDescriptors extracts certificates from descriptors. | certificatesFromKeyDescriptors
// 从描述符提取证书。
func certificatesFromKeyDescriptors(descriptors []KeyDescriptor, use string) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for _, descriptor := range descriptors {
		if use != "" && descriptor.Use != "" && descriptor.Use != use {
			continue
		}
		if descriptor.KeyInfo == nil {
			continue
		}
		for _, data := range descriptor.KeyInfo.X509Data {
			for _, encoded := range data.X509Certificate {
				der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
				if err != nil {
					return nil, errs.Wrap(err, ErrInvalidMetadata)
				}
				cert, err := x509.ParseCertificate(der)
				if err != nil {
					return nil, errs.Wrap(err, ErrInvalidMetadata)
				}
				out = append(out, cert)
			}
		}
	}
	return out, nil
}

// SigningCertificates returns signing certificates. | SigningCertificates 返回签名证书。
func (d *EntityDescriptor) SigningCertificates() ([]*x509.Certificate, error) {
	return d.Certificates("signing")
}

// EncryptionCertificates returns encryption certificates. | EncryptionCertificates 返回加密证书。
func (d *EntityDescriptor) EncryptionCertificates() ([]*x509.Certificate, error) {
	return d.Certificates("encryption")
}

// SSOURL returns the SingleSignOnService location for binding, preferring the exact binding. | SSOURL
// 返回 binding 的 SingleSignOnService 位置，优先精确绑定。
func (d *EntityDescriptor) SSOURL(binding string) string {
	if d == nil || d.IDPSSODescriptor == nil {
		return ""
	}
	for _, endpoint := range d.IDPSSODescriptor.SingleSignOnService {
		if binding == "" || endpoint.Binding == binding {
			return endpoint.Location
		}
	}
	if len(d.IDPSSODescriptor.SingleSignOnService) > 0 {
		return d.IDPSSODescriptor.SingleSignOnService[0].Location
	}
	return ""
}

// SLOURL returns the SingleLogoutService location for binding. | SLOURL 返回 binding 的 SingleLogoutService 位置。
func (d *EntityDescriptor) SLOURL(binding string) string {
	if d == nil {
		return ""
	}
	var endpoints []Endpoint
	if d.IDPSSODescriptor != nil {
		endpoints = d.IDPSSODescriptor.SingleLogoutService
	} else if d.SPSSODescriptor != nil {
		endpoints = d.SPSSODescriptor.SingleLogoutService
	}
	for _, endpoint := range endpoints {
		if binding == "" || endpoint.Binding == binding {
			return endpoint.Location
		}
	}
	if len(endpoints) > 0 {
		return endpoints[0].Location
	}
	return ""
}

// ACSURL returns the AssertionConsumerService location for binding. | ACSURL 返回 binding 的 AssertionConsumerService 位置。
func (d *EntityDescriptor) ACSURL(binding string) string {
	if d == nil || d.SPSSODescriptor == nil {
		return ""
	}
	for _, endpoint := range d.SPSSODescriptor.AssertionConsumerService {
		if binding == "" || endpoint.Binding == binding {
			return endpoint.Location
		}
	}
	if len(d.SPSSODescriptor.AssertionConsumerService) > 0 {
		return d.SPSSODescriptor.AssertionConsumerService[0].Location
	}
	return ""
}

// ArtifactResolutionURL returns the SOAP ArtifactResolutionService location with index. It
// returns an empty string when the IdP publishes no endpoint with that index. | ArtifactResolutionURL
// 返回索引为 index 的 SOAP ArtifactResolutionService 位置。IdP 未发布该索引端点时返回空字符串。
func (d *EntityDescriptor) ArtifactResolutionURL(index int) string {
	if d == nil || d.IDPSSODescriptor == nil {
		return ""
	}
	endpoints := d.IDPSSODescriptor.ArtifactResolutionService
	for _, endpoint := range endpoints {
		if endpoint.Index == index && endpoint.Binding == BindingSOAP {
			return endpoint.Location
		}
	}
	for _, endpoint := range endpoints {
		if endpoint.Index == index {
			return endpoint.Location
		}
	}
	return ""
}

// ParseCertificatePEM parses one PEM certificate. | ParseCertificatePEM 解析一个 PEM 证书。
func ParseCertificatePEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errs.Detail(ErrInvalidMetadata, "PEM block is missing | 缺少 PEM 块")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errs.Wrap(err, ErrInvalidMetadata)
	}
	return cert, nil
}
