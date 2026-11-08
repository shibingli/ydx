package wsfed

import (
	"bytes"
	"strings"

	"github.com/shibingli/ydx/auth/protocol/saml"
	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/xml"
)

// EndpointReference is a WS-Addressing endpoint reference. | EndpointReference 是 WS-Addressing 端点引用。
type EndpointReference struct {
	// XMLName is the element name. | XMLName 是元素名。
	XMLName xml.Name `xml:"http://www.w3.org/2005/08/addressing EndpointReference"`
	// Address is the endpoint address. | Address 是端点地址。
	Address string `xml:"http://www.w3.org/2005/08/addressing Address"`
}

// AppliesTo identifies the token audience. | AppliesTo 标识令牌受众。
type AppliesTo struct {
	// XMLName is the element name. | XMLName 是元素名。
	XMLName xml.Name `xml:"http://docs.oasis-open.org/ws-sx/ws-trust/200512 AppliesTo"`
	// EndpointReference is the audience endpoint reference. | EndpointReference 是受众端点引用。
	EndpointReference EndpointReference `xml:"http://www.w3.org/2005/08/addressing EndpointReference"`
}

// Address returns the audience address. | Address 返回受众地址。
func (a *AppliesTo) Address() string {
	if a == nil {
		return ""
	}
	return strings.TrimSpace(a.EndpointReference.Address)
}

// Lifetime bounds the issued token. | Lifetime 限定已签发令牌的有效期。
type Lifetime struct {
	// XMLName is the element name. | XMLName 是元素名。
	XMLName xml.Name `xml:"http://docs.oasis-open.org/ws-sx/ws-trust/200512 Lifetime"`
	// Created is the token creation time. | Created 是令牌创建时间。
	Created string `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd Created,omitempty"`
	// Expires is the token expiry time. | Expires 是令牌过期时间。
	Expires string `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd Expires,omitempty"`
}

// RequestedSecurityToken carries the issued security token. | RequestedSecurityToken 携带已签发安全令牌。
//
// XML tokens such as SAML assertions are kept verbatim in InnerXML so signatures remain over the
// exact document the issuer produced. JWT tokens are kept as text. | SAML 断言等 XML 令牌原样保存在
// InnerXML 中，使签名仍覆盖签发方生成的精确文档；JWT 令牌以文本保存。
type RequestedSecurityToken struct {
	// XMLName is the element name. | XMLName 是元素名。
	XMLName xml.Name `xml:"http://docs.oasis-open.org/ws-sx/ws-trust/200512 RequestedSecurityToken"`
	// InnerXML is the raw token content. | InnerXML 是原始令牌内容。
	InnerXML string `xml:",innerxml"`
}

// Raw returns the trimmed token content. | Raw 返回去除首尾空白的令牌内容。
func (t *RequestedSecurityToken) Raw() string {
	if t == nil {
		return ""
	}
	return strings.TrimSpace(t.InnerXML)
}

// SetRaw replaces the token content. | SetRaw 替换令牌内容。
func (t *RequestedSecurityToken) SetRaw(raw string) {
	if t == nil {
		return
	}
	t.InnerXML = raw
}

// TokenType returns the token type inferred from the carried token. | TokenType 返回从携带令牌推断的类型。
func (t *RequestedSecurityToken) TokenType() string {
	raw := t.Raw()
	if raw == "" {
		return ""
	}
	if !strings.HasPrefix(raw, "<") {
		return TokenTypeJWT
	}
	var root struct {
		XMLName xml.Name
	}
	if err := xml.Unmarshal([]byte(raw), &root); err != nil {
		return ""
	}
	switch root.XMLName.Space {
	case NamespaceSAML20:
		if root.XMLName.Local == "Assertion" {
			return TokenTypeSAML20
		}
	case NamespaceSAML11:
		if root.XMLName.Local == "Assertion" {
			return TokenTypeSAML11
		}
	}
	if root.XMLName.Local == "BinarySecurityToken" {
		return TokenTypeJWT
	}
	return ""
}

// Assertion returns the carried SAML assertion, converting SAML 1.1 to the shared model. |
// Assertion 返回携带的 SAML 断言，并把 SAML 1.1 转换为共享模型。
func (t *RequestedSecurityToken) Assertion() (*saml.Assertion, error) {
	raw := t.Raw()
	if raw == "" {
		return nil, ErrNoToken
	}
	switch t.TokenType() {
	case TokenTypeSAML20:
		var assertion saml.Assertion
		if err := xml.Unmarshal([]byte(raw), &assertion); err != nil {
			return nil, errs.Wrap(err, ErrInvalidResponse)
		}
		if assertion.ID == "" {
			return nil, errs.Detail(ErrInvalidResponse, "assertion ID is missing | 缺少断言 ID")
		}
		return &assertion, nil
	case TokenTypeSAML11:
		var assertion SAML11Assertion
		if err := xml.Unmarshal([]byte(raw), &assertion); err != nil {
			return nil, errs.Wrap(err, ErrInvalidResponse)
		}
		if assertion.AssertionID == "" {
			return nil, errs.Detail(ErrInvalidResponse, "assertion ID is missing | 缺少断言 ID")
		}
		return assertion.Assertion(), nil
	default:
		return nil, errs.Detail(ErrUnsupported, "security token is not a SAML assertion | 安全令牌不是 SAML 断言")
	}
}

// JWT returns the carried JWT text. | JWT 返回携带的 JWT 文本。
func (t *RequestedSecurityToken) JWT() (string, bool) {
	raw := t.Raw()
	if raw == "" {
		return "", false
	}
	if !strings.HasPrefix(raw, "<") {
		return raw, true
	}
	var binary struct {
		XMLName xml.Name
		Value   string `xml:",chardata"`
	}
	if err := xml.Unmarshal([]byte(raw), &binary); err != nil {
		return "", false
	}
	if binary.XMLName.Local != "BinarySecurityToken" {
		return "", false
	}
	value := strings.TrimSpace(binary.Value)
	return value, value != ""
}

// SecurityTokenReferenceURI is a WS-Security reference. | SecurityTokenReferenceURI 是 WS-Security 引用。
type SecurityTokenReferenceURI struct {
	// URI is the reference URI, usually "#assertion-id". | URI 是引用 URI，通常为 "#assertion-id"。
	URI string `xml:"URI,attr,omitempty"`
	// ValueType identifies the token profile. | ValueType 标识令牌配置。
	ValueType string `xml:"ValueType,attr,omitempty"`
}

// SecurityTokenReference references a token inside the response. | SecurityTokenReference 引用响应内的令牌。
type SecurityTokenReference struct {
	// XMLName is the element name. | XMLName 是元素名。
	XMLName xml.Name `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd SecurityTokenReference"`
	// Reference is the token reference. | Reference 是令牌引用。
	Reference SecurityTokenReferenceURI `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd Reference"`
}

// RequestedAttachedReference is a WS-Trust attached token reference element. |
// RequestedAttachedReference 是 WS-Trust 附加令牌引用元素。
type RequestedAttachedReference struct {
	// XMLName is the element name. | XMLName 是元素名。
	XMLName xml.Name `xml:"http://docs.oasis-open.org/ws-sx/ws-trust/200512 RequestedAttachedReference"`
	// SecurityTokenReference is the WS-Security reference. | SecurityTokenReference 是 WS-Security 引用。
	SecurityTokenReference SecurityTokenReference `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd SecurityTokenReference"`
}

// RequestedUnattachedReference is a WS-Trust unattached token reference element. |
// RequestedUnattachedReference 是 WS-Trust 未附加令牌引用元素。
type RequestedUnattachedReference struct {
	// XMLName is the element name. | XMLName 是元素名。
	XMLName xml.Name `xml:"http://docs.oasis-open.org/ws-sx/ws-trust/200512 RequestedUnattachedReference"`
	// SecurityTokenReference is the WS-Security reference. | SecurityTokenReference 是 WS-Security 引用。
	SecurityTokenReference SecurityTokenReference `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd SecurityTokenReference"`
}

// ResponseStatus is the WS-Trust status element. | ResponseStatus 是 WS-Trust 状态元素。
type ResponseStatus struct {
	// XMLName is the element name. | XMLName 是元素名。
	XMLName xml.Name `xml:"http://docs.oasis-open.org/ws-sx/ws-trust/200512 Status"`
	// Code is the status code URI. | Code 是状态码 URI。
	Code string `xml:"http://docs.oasis-open.org/ws-sx/ws-trust/200512 Code,omitempty"`
	// Reason is the optional human-readable reason. | Reason 是可选的人类可读原因。
	Reason string `xml:"http://docs.oasis-open.org/ws-sx/ws-trust/200512 Reason,omitempty"`
}

// Success reports whether the status is absent or a success code. | Success 报告状态缺失或为成功码。
func (s *ResponseStatus) Success() bool {
	return s == nil || s.Code == "" || s.Code == StatusSuccess
}

// Fault is a WS-Federation fault body. | Fault 是 WS-Federation 故障正文。
type Fault struct {
	// XMLName is the element name. | XMLName 是元素名。
	XMLName xml.Name
	// FaultCode is the fault code. | FaultCode 是故障码。
	FaultCode string `xml:"faultcode,omitempty"`
	// FaultString is the fault description. | FaultString 是故障描述。
	FaultString string `xml:"faultstring,omitempty"`
	// Detail carries optional fault detail. | Detail 携带可选故障细节。
	Detail string `xml:"detail,omitempty"`
}

// Error implements the error interface. | Error 实现 error 接口。
func (f *Fault) Error() string {
	if f == nil {
		return ErrStatusFailure.Error()
	}
	code := strings.TrimSpace(f.FaultCode)
	message := strings.TrimSpace(f.FaultString)
	switch {
	case code != "" && message != "":
		return "wsfed: fault " + code + ": " + message + " | wsfed：故障 " + code + "：" + message
	case code != "":
		return "wsfed: fault " + code + " | wsfed：故障 " + code
	case message != "":
		return "wsfed: fault: " + message + " | wsfed：故障：" + message
	default:
		return ErrStatusFailure.Error()
	}
}

// RequestSecurityTokenResponse is one WS-Trust token response. | RequestSecurityTokenResponse 是一个
// WS-Trust 令牌响应。
type RequestSecurityTokenResponse struct {
	// XMLName is the element name. | XMLName 是元素名。
	XMLName xml.Name `xml:"http://docs.oasis-open.org/ws-sx/ws-trust/200512 RequestSecurityTokenResponse"`
	// ID is an extension identifier used when the response itself is signed. | ID 是响应自身被签名时
	// 使用的扩展标识。
	ID string `xml:"ID,attr,omitempty"`
	// Context echoes the WS-Trust request context. | Context 回显 WS-Trust 请求上下文。
	Context string `xml:"Context,attr,omitempty"`
	// Wctx echoes the WS-Federation context when an attribute form is used. | Wctx 在属性形式下回显
	// WS-Federation 上下文。
	Wctx string `xml:"wctx,attr,omitempty"`
	// TokenType is the issued token type. | TokenType 是已签发令牌类型。
	TokenType string `xml:"http://docs.oasis-open.org/ws-sx/ws-trust/200512 TokenType,omitempty"`
	// RequestType is the WS-Trust request type. | RequestType 是 WS-Trust 请求类型。
	RequestType string `xml:"http://docs.oasis-open.org/ws-sx/ws-trust/200512 RequestType,omitempty"`
	// AppliesTo identifies the token audience. | AppliesTo 标识令牌受众。
	AppliesTo *AppliesTo `xml:"http://docs.oasis-open.org/ws-sx/ws-trust/200512 AppliesTo,omitempty"`
	// Lifetime bounds the issued token. | Lifetime 限定已签发令牌的有效期。
	Lifetime *Lifetime `xml:"http://docs.oasis-open.org/ws-sx/ws-trust/200512 Lifetime,omitempty"`
	// RequestedSecurityToken carries the issued token. | RequestedSecurityToken 携带已签发令牌。
	RequestedSecurityToken *RequestedSecurityToken `xml:"http://docs.oasis-open.org/ws-sx/ws-trust/200512 RequestedSecurityToken,omitempty"`
	// RequestedAttachedReference references an attached token. | RequestedAttachedReference 引用附加令牌。
	RequestedAttachedReference *RequestedAttachedReference `xml:"http://docs.oasis-open.org/ws-sx/ws-trust/200512 RequestedAttachedReference,omitempty"`
	// RequestedUnattachedReference references an unattached token. | RequestedUnattachedReference
	// 引用未附加令牌。
	RequestedUnattachedReference *RequestedUnattachedReference `xml:"http://docs.oasis-open.org/ws-sx/ws-trust/200512 RequestedUnattachedReference,omitempty"`
	// KeySize is the issued proof key size. | KeySize 是已签发证明密钥大小。
	KeySize int `xml:"http://docs.oasis-open.org/ws-sx/ws-trust/200512 KeySize,omitempty"`
	// Status is the response status. | Status 是响应状态。
	Status *ResponseStatus `xml:"http://docs.oasis-open.org/ws-sx/ws-trust/200512 Status,omitempty"`
}

// RequestSecurityTokenResponseCollection is the WS-Trust response collection carried in wresult. |
// RequestSecurityTokenResponseCollection 是 wresult 携带的 WS-Trust 响应集合。
type RequestSecurityTokenResponseCollection struct {
	// XMLName is the element name. | XMLName 是元素名。
	XMLName xml.Name `xml:"http://docs.oasis-open.org/ws-sx/ws-trust/200512 RequestSecurityTokenResponseCollection"`
	// ID is an extension identifier used when the collection is signed. | ID 是集合被签名时使用的扩展标识。
	ID string `xml:"ID,attr,omitempty"`
	// Responses is the response list. | Responses 是响应列表。
	Responses []RequestSecurityTokenResponse `xml:"http://docs.oasis-open.org/ws-sx/ws-trust/200512 RequestSecurityTokenResponse,omitempty"`
}

// Marshal serializes the collection as the wresult XML payload. | Marshal 把集合序列化为 wresult XML 载荷。
func (c *RequestSecurityTokenResponseCollection) Marshal() ([]byte, error) {
	if c == nil {
		return nil, errs.Detail(ErrInvalidResponse, "response collection is nil | 响应集合为空")
	}
	data, err := xml.Marshal(c)
	if err != nil {
		return nil, errs.Wrap(err, ErrInvalidResponse)
	}
	return data, nil
}

// TokenResponse returns the first response carrying a security token. | TokenResponse 返回第一个携带
// 安全令牌的响应。
func (c *RequestSecurityTokenResponseCollection) TokenResponse() *RequestSecurityTokenResponse {
	if c == nil {
		return nil
	}
	for index := range c.Responses {
		response := &c.Responses[index]
		if response.RequestedSecurityToken != nil && response.RequestedSecurityToken.Raw() != "" {
			return response
		}
	}
	return nil
}

// NewTokenReference returns a security token reference for id. | NewTokenReference 返回 id 的安全令牌引用。
func NewTokenReference(id, valueType string) *SecurityTokenReference {
	id = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(id), "#"))
	if id == "" {
		return nil
	}
	return &SecurityTokenReference{Reference: SecurityTokenReferenceURI{URI: "#" + id, ValueType: valueType}}
}

// NewAttachedReference returns an attached token reference for id. | NewAttachedReference 返回 id 的
// 附加令牌引用。
func NewAttachedReference(id, valueType string) *RequestedAttachedReference {
	reference := NewTokenReference(id, valueType)
	if reference == nil {
		return nil
	}
	return &RequestedAttachedReference{SecurityTokenReference: *reference}
}

// NewUnattachedReference returns an unattached token reference for id. | NewUnattachedReference 返回 id
// 的未附加令牌引用。
func NewUnattachedReference(id, valueType string) *RequestedUnattachedReference {
	reference := NewTokenReference(id, valueType)
	if reference == nil {
		return nil
	}
	return &RequestedUnattachedReference{SecurityTokenReference: *reference}
}

// NewSignOutCollection builds a successful WS-Trust Cancel response for wctx. | NewSignOutCollection
// 为 wctx 构建成功的 WS-Trust Cancel 响应。
func NewSignOutCollection(wctx string) *RequestSecurityTokenResponseCollection {
	return &RequestSecurityTokenResponseCollection{
		Responses: []RequestSecurityTokenResponse{{
			RequestType: RequestTypeCancel,
			Wctx:        wctx,
			Status:      &ResponseStatus{Code: StatusSuccess},
		}},
	}
}

// ParseWResult parses a wresult payload in WS-Trust 1.3 or legacy WS-Trust 2005 form. | ParseWResult
// 解析 WS-Trust 1.3 或遗留 WS-Trust 2005 形式的 wresult 载荷。
func ParseWResult(data []byte) (*RequestSecurityTokenResponseCollection, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, errs.Detail(ErrInvalidResponse, "wresult is empty | wresult 为空")
	}
	if data[0] != '<' {
		if decoded, ok := decodeBase64XML(data); ok {
			data = decoded
		}
	}
	var collection RequestSecurityTokenResponseCollection
	if err := xml.Unmarshal(data, &collection); err == nil && len(collection.Responses) > 0 {
		return &collection, nil
	}
	var response RequestSecurityTokenResponse
	if err := xml.Unmarshal(data, &response); err == nil && responseHasContent(&response) {
		return &RequestSecurityTokenResponseCollection{Responses: []RequestSecurityTokenResponse{response}}, nil
	}
	var legacyCollection rawResponseCollection
	if err := xml.Unmarshal(data, &legacyCollection); err == nil && len(legacyCollection.Responses) > 0 {
		return legacyCollection.collection(), nil
	}
	var legacyResponse rawResponse
	if err := xml.Unmarshal(data, &legacyResponse); err == nil && legacyResponse.hasContent() {
		return &RequestSecurityTokenResponseCollection{Responses: []RequestSecurityTokenResponse{legacyResponse.response()}}, nil
	}
	var fault Fault
	if err := xml.Unmarshal(data, &fault); err == nil && strings.TrimSpace(fault.FaultCode) != "" {
		return nil, errs.WrapDetail(&fault, ErrStatusFailure, "wresult fault | wresult 故障")
	}
	return nil, errs.Detail(ErrInvalidResponse, "wresult is not a WS-Trust response | wresult 不是 WS-Trust 响应")
}

// ParseWResultString parses a string wresult payload. | ParseWResultString 解析字符串 wresult 载荷。
func ParseWResultString(value string) (*RequestSecurityTokenResponseCollection, error) {
	return ParseWResult([]byte(value))
}

// decodeBase64XML decodes a base64-encoded XML payload. | decodeBase64XML 解码 base64 编码的 XML 载荷。
func decodeBase64XML(data []byte) ([]byte, bool) {
	text := strings.TrimSpace(string(data))
	if text == "" {
		return nil, false
	}
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(text)
		if err == nil && len(decoded) > 0 && bytes.HasPrefix(bytes.TrimSpace(decoded), []byte("<")) {
			return decoded, true
		}
	}
	return nil, false
}

// responseHasContent reports whether a response carries any WS-Trust data. | responseHasContent
// 报告响应是否携带任何 WS-Trust 数据。
func responseHasContent(response *RequestSecurityTokenResponse) bool {
	if response == nil {
		return false
	}
	return response.TokenType != "" || response.RequestType != "" || response.AppliesTo != nil ||
		response.Lifetime != nil || response.RequestedSecurityToken != nil || response.Status != nil
}

// rawResponseCollection is a namespace-agnostic response collection. | rawResponseCollection 是
// 命名空间无关的响应集合。
type rawResponseCollection struct {
	// XMLName is the element name. | XMLName 是元素名。
	XMLName xml.Name
	// ID is the collection identifier. | ID 是集合标识。
	ID string `xml:"ID,attr,omitempty"`
	// Responses is the raw response list. | Responses 是原始响应列表。
	Responses []rawResponse `xml:"RequestSecurityTokenResponse,omitempty"`
}

// collection converts a raw collection to the public model. | collection 把原始集合转换为公开模型。
func (c *rawResponseCollection) collection() *RequestSecurityTokenResponseCollection {
	out := &RequestSecurityTokenResponseCollection{ID: c.ID}
	for index := range c.Responses {
		out.Responses = append(out.Responses, c.Responses[index].response())
	}
	return out
}

// rawResponse is a namespace-agnostic WS-Trust response. | rawResponse 是命名空间无关的 WS-Trust 响应。
type rawResponse struct {
	// XMLName is the element name. | XMLName 是元素名。
	XMLName xml.Name
	// ID is the response identifier. | ID 是响应标识。
	ID string `xml:"ID,attr,omitempty"`
	// Context echoes the WS-Trust request context. | Context 回显 WS-Trust 请求上下文。
	Context string `xml:"Context,attr,omitempty"`
	// Wctx echoes the WS-Federation context. | Wctx 回显 WS-Federation 上下文。
	Wctx string `xml:"wctx,attr,omitempty"`
	// TokenType is the declared token type. | TokenType 是声明的令牌类型。
	TokenType string `xml:"TokenType,omitempty"`
	// RequestType is the WS-Trust request type. | RequestType 是 WS-Trust 请求类型。
	RequestType string `xml:"RequestType,omitempty"`
	// AppliesTo identifies the token audience. | AppliesTo 标识令牌受众。
	AppliesTo *rawAppliesTo `xml:"AppliesTo,omitempty"`
	// Lifetime bounds the token lifetime. | Lifetime 限定令牌寿命。
	Lifetime *rawLifetime `xml:"Lifetime,omitempty"`
	// RequestedSecurityToken carries the raw token. | RequestedSecurityToken 携带原始令牌。
	RequestedSecurityToken *rawSecurityToken `xml:"RequestedSecurityToken,omitempty"`
	// RequestedAttachedReference references the attached token. | RequestedAttachedReference 引用附加令牌。
	RequestedAttachedReference *rawTokenReference `xml:"RequestedAttachedReference,omitempty"`
	// RequestedUnattachedReference references the unattached token. | RequestedUnattachedReference 引用未附加令牌。
	RequestedUnattachedReference *rawTokenReference `xml:"RequestedUnattachedReference,omitempty"`
	// KeySize is the proof key size. | KeySize 是证明密钥大小。
	KeySize int `xml:"KeySize,omitempty"`
	// Status is the raw status element. | Status 是原始状态元素。
	Status *rawStatus `xml:"Status,omitempty"`
}

// hasContent reports whether the raw response carries data. | hasContent 报告原始响应是否携带数据。
func (r *rawResponse) hasContent() bool {
	if r == nil {
		return false
	}
	return r.TokenType != "" || r.RequestType != "" || r.AppliesTo != nil ||
		r.Lifetime != nil || (r.RequestedSecurityToken != nil && strings.TrimSpace(r.RequestedSecurityToken.InnerXML) != "") ||
		r.Status != nil
}

// response converts a raw response to the public model. | response 把原始响应转换为公开模型。
func (r *rawResponse) response() RequestSecurityTokenResponse {
	out := RequestSecurityTokenResponse{
		ID:          r.ID,
		Context:     r.Context,
		Wctx:        r.Wctx,
		TokenType:   r.TokenType,
		RequestType: r.RequestType,
		KeySize:     r.KeySize,
	}
	if r.AppliesTo != nil {
		address := r.AppliesTo.Address
		if address == "" && r.AppliesTo.EndpointReference != nil {
			address = r.AppliesTo.EndpointReference.Address
		}
		out.AppliesTo = &AppliesTo{EndpointReference: EndpointReference{Address: address}}
	}
	if r.Lifetime != nil {
		out.Lifetime = &Lifetime{Created: r.Lifetime.Created, Expires: r.Lifetime.Expires}
	}
	if r.RequestedSecurityToken != nil {
		out.RequestedSecurityToken = &RequestedSecurityToken{InnerXML: r.RequestedSecurityToken.InnerXML}
	}
	if r.RequestedAttachedReference != nil {
		if reference := r.RequestedAttachedReference.reference(); reference != nil {
			out.RequestedAttachedReference = &RequestedAttachedReference{SecurityTokenReference: *reference}
		}
	}
	if r.RequestedUnattachedReference != nil {
		if reference := r.RequestedUnattachedReference.reference(); reference != nil {
			out.RequestedUnattachedReference = &RequestedUnattachedReference{SecurityTokenReference: *reference}
		}
	}
	if r.Status != nil {
		status := &ResponseStatus{Code: r.Status.Code, Reason: r.Status.Reason}
		if status.Code == "" {
			status.Code = r.Status.StatusCode
		}
		out.Status = status
	}
	return out
}

// rawAppliesTo is a namespace-agnostic AppliesTo element. | rawAppliesTo 是命名空间无关的 AppliesTo 元素。
type rawAppliesTo struct {
	// EndpointReference is the audience endpoint reference. | EndpointReference 是受众端点引用。
	EndpointReference *rawEndpointReference `xml:"EndpointReference,omitempty"`
	// Address is the direct audience address. | Address 是直接受众地址。
	Address string `xml:"Address,omitempty"`
}

// rawEndpointReference is a namespace-agnostic endpoint reference. | rawEndpointReference 是
// 命名空间无关的端点引用。
type rawEndpointReference struct {
	// Address is the endpoint address. | Address 是端点地址。
	Address string `xml:"Address,omitempty"`
}

// rawLifetime is a namespace-agnostic Lifetime element. | rawLifetime 是命名空间无关的 Lifetime 元素。
type rawLifetime struct {
	// Created is the creation time. | Created 是创建时间。
	Created string `xml:"Created,omitempty"`
	// Expires is the expiry time. | Expires 是过期时间。
	Expires string `xml:"Expires,omitempty"`
}

// rawSecurityToken is a namespace-agnostic RequestedSecurityToken element. | rawSecurityToken 是
// 命名空间无关的 RequestedSecurityToken 元素。
type rawSecurityToken struct {
	// InnerXML is the raw token content. | InnerXML 是原始令牌内容。
	InnerXML string `xml:",innerxml"`
}

// rawTokenReference is a namespace-agnostic token reference. | rawTokenReference 是命名空间无关的令牌引用。
type rawTokenReference struct {
	// Reference is the raw token reference. | Reference 是原始令牌引用。
	Reference *rawReferenceURI `xml:"Reference,omitempty"`
}

// reference converts a raw token reference. | reference 转换原始令牌引用。
func (r *rawTokenReference) reference() *SecurityTokenReference {
	if r == nil {
		return nil
	}
	out := &SecurityTokenReference{}
	if r.Reference != nil {
		out.Reference = SecurityTokenReferenceURI{URI: r.Reference.URI, ValueType: r.Reference.ValueType}
	}
	return out
}

// rawReferenceURI is a namespace-agnostic Reference element. | rawReferenceURI 是命名空间无关的 Reference 元素。
type rawReferenceURI struct {
	// URI is the reference URI. | URI 是引用 URI。
	URI string `xml:"URI,attr,omitempty"`
	// ValueType identifies the token profile. | ValueType 标识令牌配置。
	ValueType string `xml:"ValueType,attr,omitempty"`
}

// rawStatus is a namespace-agnostic WS-Trust Status element. | rawStatus 是命名空间无关的 WS-Trust Status 元素。
type rawStatus struct {
	// Code is the status code. | Code 是状态码。
	Code string `xml:"Code,omitempty"`
	// Reason is the human-readable reason. | Reason 是人类可读原因。
	Reason string `xml:"Reason,omitempty"`
	// StatusCode is the nested status code variant. | StatusCode 是嵌套状态码变体。
	StatusCode string `xml:"StatusCode,omitempty"`
}

// SAML11Assertion is a SAML 1.1 assertion as issued by legacy WS-Federation token services. |
// SAML11Assertion 是遗留 WS-Federation 令牌服务签发的 SAML 1.1 断言。
type SAML11Assertion struct {
	// XMLName is the element name. | XMLName 是元素名。
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:1.0:assertion Assertion"`
	// AssertionID is the assertion identifier. | AssertionID 是断言标识。
	AssertionID string `xml:"AssertionID,attr,omitempty"`
	// Issuer is the issuer URI. | Issuer 是签发方 URI。
	Issuer string `xml:"Issuer,attr,omitempty"`
	// IssueInstant is the issue time. | IssueInstant 是签发时间。
	IssueInstant string `xml:"IssueInstant,attr,omitempty"`
	// MajorVersion is the SAML major version, normally "1". | MajorVersion 是 SAML 主版本，通常为 "1"。
	MajorVersion string `xml:"MajorVersion,attr,omitempty"`
	// MinorVersion is the SAML minor version, normally "1". | MinorVersion 是 SAML 次版本，通常为 "1"。
	MinorVersion string `xml:"MinorVersion,attr,omitempty"`
	// Signature marks an XMLDSig signature element. | Signature 标记 XMLDSig 签名元素。
	Signature *saml.SignatureMarker `xml:"http://www.w3.org/2000/09/xmldsig# Signature,omitempty"`
	// Conditions constrains validity. | Conditions 约束有效性。
	Conditions *SAML11Conditions `xml:"urn:oasis:names:tc:SAML:1.0:assertion Conditions,omitempty"`
	// AuthenticationStatement records authentication events. | AuthenticationStatement 记录认证事件。
	AuthenticationStatement []SAML11AuthenticationStatement `xml:"urn:oasis:names:tc:SAML:1.0:assertion AuthenticationStatement,omitempty"`
	// AttributeStatement groups attributes. | AttributeStatement 对属性分组。
	AttributeStatement []SAML11AttributeStatement `xml:"urn:oasis:names:tc:SAML:1.0:assertion AttributeStatement,omitempty"`
}

// SAML11Conditions constrains a SAML 1.1 assertion. | SAML11Conditions 约束 SAML 1.1 断言。
type SAML11Conditions struct {
	// NotBefore is the start of the validity window. | NotBefore 是有效窗口起点。
	NotBefore string `xml:"NotBefore,attr,omitempty"`
	// NotOnOrAfter is the end of the validity window. | NotOnOrAfter 是有效窗口终点。
	NotOnOrAfter string `xml:"NotOnOrAfter,attr,omitempty"`
	// AudienceRestrictionCondition lists the allowed audiences. | AudienceRestrictionCondition 列出允许受众。
	AudienceRestrictionCondition []SAML11AudienceRestriction `xml:"urn:oasis:names:tc:SAML:1.0:assertion AudienceRestrictionCondition,omitempty"`
}

// SAML11AudienceRestriction lists one or more audiences. | SAML11AudienceRestriction 列出一个或多个受众。
type SAML11AudienceRestriction struct {
	// Audience is the allowed audience list. | Audience 是允许受众列表。
	Audience []string `xml:"urn:oasis:names:tc:SAML:1.0:assertion Audience,omitempty"`
}

// SAML11Subject is a SAML 1.1 assertion subject. | SAML11Subject 是 SAML 1.1 断言主体。
type SAML11Subject struct {
	// NameIdentifier is the subject identifier. | NameIdentifier 是主体标识。
	NameIdentifier *SAML11NameIdentifier `xml:"urn:oasis:names:tc:SAML:1.0:assertion NameIdentifier,omitempty"`
	// SubjectConfirmation carries confirmation methods. | SubjectConfirmation 携带确认方法。
	SubjectConfirmation []SAML11SubjectConfirmation `xml:"urn:oasis:names:tc:SAML:1.0:assertion SubjectConfirmation,omitempty"`
}

// SAML11NameIdentifier is a SAML 1.1 name identifier. | SAML11NameIdentifier 是 SAML 1.1 名称标识。
type SAML11NameIdentifier struct {
	// Format is the identifier format. | Format 是标识格式。
	Format string `xml:"Format,attr,omitempty"`
	// NameQualifier qualifies the identifier. | NameQualifier 限定标识。
	NameQualifier string `xml:"NameQualifier,attr,omitempty"`
	// Value is the identifier text. | Value 是标识文本。
	Value string `xml:",chardata"`
}

// SAML11SubjectConfirmation is a SAML 1.1 subject confirmation. | SAML11SubjectConfirmation 是
// SAML 1.1 主体确认。
type SAML11SubjectConfirmation struct {
	// ConfirmationMethod lists confirmation methods. | ConfirmationMethod 列出确认方法。
	ConfirmationMethod []string `xml:"urn:oasis:names:tc:SAML:1.0:assertion ConfirmationMethod,omitempty"`
	// SubjectConfirmationData carries optional confirmation data. | SubjectConfirmationData 携带可选确认数据。
	SubjectConfirmationData string `xml:"urn:oasis:names:tc:SAML:1.0:assertion SubjectConfirmationData,omitempty"`
}

// SAML11AuthenticationStatement records one authentication event. | SAML11AuthenticationStatement
// 记录一次认证事件。
type SAML11AuthenticationStatement struct {
	// AuthenticationInstant is the authentication time. | AuthenticationInstant 是认证时间。
	AuthenticationInstant string `xml:"AuthenticationInstant,attr,omitempty"`
	// AuthenticationMethod is the authentication method URI. | AuthenticationMethod 是认证方法 URI。
	AuthenticationMethod string `xml:"AuthenticationMethod,attr,omitempty"`
	// Subject is the authenticated subject. | Subject 是已认证主体。
	Subject *SAML11Subject `xml:"urn:oasis:names:tc:SAML:1.0:assertion Subject,omitempty"`
}

// SAML11AttributeStatement groups SAML 1.1 attributes. | SAML11AttributeStatement 对 SAML 1.1 属性分组。
type SAML11AttributeStatement struct {
	// Subject is the attribute subject. | Subject 是属性主体。
	Subject *SAML11Subject `xml:"urn:oasis:names:tc:SAML:1.0:assertion Subject,omitempty"`
	// Attribute is the attribute list. | Attribute 是属性列表。
	Attribute []SAML11Attribute `xml:"urn:oasis:names:tc:SAML:1.0:assertion Attribute,omitempty"`
}

// SAML11Attribute is a SAML 1.1 attribute. | SAML11Attribute 是 SAML 1.1 属性。
type SAML11Attribute struct {
	// AttributeName is the attribute name. | AttributeName 是属性名。
	AttributeName string `xml:"AttributeName,attr,omitempty"`
	// AttributeNamespace is the attribute namespace. | AttributeNamespace 是属性命名空间。
	AttributeNamespace string `xml:"AttributeNamespace,attr,omitempty"`
	// AttributeValue is the value list. | AttributeValue 是值列表。
	AttributeValue []string `xml:"urn:oasis:names:tc:SAML:1.0:assertion AttributeValue,omitempty"`
}

// Assertion converts the SAML 1.1 assertion to the shared SAML 2.0 assertion model. | Assertion 把
// SAML 1.1 断言转换为共享的 SAML 2.0 断言模型。
func (a *SAML11Assertion) Assertion() *saml.Assertion {
	if a == nil {
		return nil
	}
	out := &saml.Assertion{
		ID:           a.AssertionID,
		IssueInstant: a.IssueInstant,
		Version:      "1.1",
		Signature:    a.Signature,
		Issuer:       &saml.Issuer{Value: a.Issuer},
	}
	if a.Conditions != nil {
		conditions := &saml.Conditions{NotBefore: a.Conditions.NotBefore, NotOnOrAfter: a.Conditions.NotOnOrAfter}
		for _, restriction := range a.Conditions.AudienceRestrictionCondition {
			conditions.AudienceRestriction = append(conditions.AudienceRestriction, saml.AudienceRestriction{
				Audience: append([]string(nil), restriction.Audience...),
			})
		}
		out.Conditions = conditions
	}
	subject := a.subject()
	if subject != nil {
		out.Subject = &saml.Subject{}
		if subject.NameIdentifier != nil {
			out.Subject.NameID = &saml.NameID{
				Format:        subject.NameIdentifier.Format,
				NameQualifier: subject.NameIdentifier.NameQualifier,
				Value:         subject.NameIdentifier.Value,
			}
		}
		for _, confirmation := range subject.SubjectConfirmation {
			converted := saml.SubjectConfirmation{}
			if len(confirmation.ConfirmationMethod) > 0 {
				converted.Method = confirmation.ConfirmationMethod[0]
			}
			out.Subject.SubjectConfirmation = append(out.Subject.SubjectConfirmation, converted)
		}
	}
	for _, statement := range a.AuthenticationStatement {
		converted := saml.AuthnStatement{
			AuthnInstant: statement.AuthenticationInstant,
			AuthnContext: &saml.AuthnContext{AuthnContextClassRef: statement.AuthenticationMethod},
		}
		out.AuthnStatement = append(out.AuthnStatement, converted)
	}
	for _, statement := range a.AttributeStatement {
		converted := saml.AttributeStatement{}
		for _, attribute := range statement.Attribute {
			outAttribute := saml.Attribute{Name: attribute.AttributeName, NameFormat: attribute.AttributeNamespace}
			for _, value := range attribute.AttributeValue {
				outAttribute.AttributeValue = append(outAttribute.AttributeValue, saml.AttributeValue{Value: value})
			}
			converted.Attribute = append(converted.Attribute, outAttribute)
		}
		out.AttributeStatement = append(out.AttributeStatement, converted)
	}
	return out
}

// subject returns the assertion subject from the authentication or attribute statements. | subject
// 从认证或属性语句返回断言主体。
func (a *SAML11Assertion) subject() *SAML11Subject {
	if a == nil {
		return nil
	}
	for index := range a.AuthenticationStatement {
		if a.AuthenticationStatement[index].Subject != nil {
			return a.AuthenticationStatement[index].Subject
		}
	}
	for index := range a.AttributeStatement {
		if a.AttributeStatement[index].Subject != nil {
			return a.AttributeStatement[index].Subject
		}
	}
	return nil
}
