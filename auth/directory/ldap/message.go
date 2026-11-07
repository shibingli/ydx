package ldap

import (
	"strings"

	"github.com/shibingli/ydx/errs"
)

// Scope selects how deeply a search traverses the directory. | Scope 选择搜索
// 在目录中的遍历深度。
type Scope int

const (
	// ScopeBaseObject searches only the base entry. | ScopeBaseObject 只搜索基准条目。
	ScopeBaseObject Scope = 0
	// ScopeSingleLevel searches the immediate children of the base entry. | ScopeSingleLevel 搜索基准条目的直接子条目。
	ScopeSingleLevel Scope = 1
	// ScopeWholeSubtree searches the base entry and every descendant. | ScopeWholeSubtree 搜索基准条目及全部后代。
	ScopeWholeSubtree Scope = 2
)

// DerefAliases controls alias dereferencing during a search. | DerefAliases
// 控制搜索期间的别名解引用。
type DerefAliases int

const (
	// NeverDerefAliases never dereferences aliases. | NeverDerefAliases 从不解引用别名。
	NeverDerefAliases DerefAliases = 0
	// DerefInSearching dereferences aliases while searching subordinates. | DerefInSearching 在搜索下级时解引用别名。
	DerefInSearching DerefAliases = 1
	// DerefFindingBaseObject dereferences the base object alias only. | DerefFindingBaseObject 只解引用基准对象别名。
	DerefFindingBaseObject DerefAliases = 2
	// DerefAlways dereferences aliases in every phase. | DerefAlways 在所有阶段解引用别名。
	DerefAlways DerefAliases = 3
)

// ModifyOperation is the operation of one modify change. | ModifyOperation 是
// 单条修改变更的操作类型。
type ModifyOperation int

const (
	// ModifyAdd adds attribute values. | ModifyAdd 添加属性值。
	ModifyAdd ModifyOperation = 0
	// ModifyDelete deletes attribute values, or the whole attribute when Values is empty. |
	// ModifyDelete 删除属性值；Values 为空时删除整个属性。
	ModifyDelete ModifyOperation = 1
	// ModifyReplace replaces all values of an attribute. | ModifyReplace 替换属性的全部值。
	ModifyReplace ModifyOperation = 2
	// ModifyIncrement increments an integer attribute (RFC 4525). | ModifyIncrement 递增整型属性（RFC 4525）。
	ModifyIncrement ModifyOperation = 3
)

// Authentication is a bind authentication choice. Only the implementations in
// this package are accepted. | Authentication 是绑定认证选择，仅接受本包内的实现。
type Authentication interface {
	bindAuthentication()
}

// SimpleAuthentication is the LDAP simple authentication choice. Empty passwords
// are rejected by Bind before any network I/O. | SimpleAuthentication 是 LDAP
// 简单认证选择。Bind 会在任何网络 I/O 之前拒绝空口令。
type SimpleAuthentication struct {
	// Password is the cleartext password; use TLS outside a trusted network. | Password 是明文口令；在非可信网络外应使用 TLS。
	Password string
}

func (SimpleAuthentication) bindAuthentication() {}

// SASLAuthentication is the SASL authentication choice. | SASLAuthentication
// 是 SASL 认证选择。
type SASLAuthentication struct {
	// Mechanism is the registered SASL mechanism name, for example PLAIN. | Mechanism 是注册的 SASL 机制名，例如 PLAIN。
	Mechanism string
	// Credentials is the mechanism-specific challenge or response bytes. | Credentials 是机制相关的挑战或响应字节。
	Credentials []byte
}

func (SASLAuthentication) bindAuthentication() {}

// BindRequest is an LDAPv3 BindRequest. | BindRequest 是 LDAPv3 BindRequest。
type BindRequest struct {
	// Version is the LDAP protocol version, normally 3. | Version 是 LDAP 协议版本，通常为 3。
	Version int
	// DN is the simple-bind name or empty for SASL. | DN 是简单绑定名称，SASL 时为空。
	DN string
	// Authentication is the authentication choice. | Authentication 是认证选择。
	Authentication Authentication
}

// BindResponse is an LDAP BindResponse. | BindResponse 是 LDAP BindResponse。
type BindResponse struct {
	// Result is the common result triple. | Result 是公共结果三元组。
	Result LDAPResult
	// ServerSASLCredentials is the optional [7] serverSaslCreds field. | ServerSASLCredentials 是可选的 [7] serverSaslCreds 字段。
	ServerSASLCredentials []byte
}

// UnbindRequest is an LDAP UnbindRequest and has no response. | UnbindRequest
// 是 LDAP UnbindRequest，没有响应。
type UnbindRequest struct{}

// Attribute is an attribute description with string values. Values may contain
// arbitrary bytes because LDAP values are octet strings. | Attribute 是带字符串值的属性
// 描述。LDAP 值是八位组串，因此 Values 可以包含任意字节。
type Attribute struct {
	// Type is the attribute description, for example cn or objectClass. | Type 是属性描述，例如 cn 或 objectClass。
	Type string
	// Values are the attribute values. | Values 是属性值。
	Values []string
}

// Entry is one SearchResultEntry. | Entry 是一个 SearchResultEntry。
type Entry struct {
	// DN is the entry distinguished name. | DN 是条目可分辨名称。
	DN string
	// Attributes preserves the order sent by the server. | Attributes 保持服务端发送的顺序。
	Attributes []Attribute
}

// Get returns every value of the named attribute using case-insensitive
// attribute-description matching. The returned slice is a copy. | Get 使用大小写不敏感的
// 属性描述匹配返回指定属性的全部值，返回切片是副本。
func (e *Entry) Get(name string) []string {
	if e == nil || name == "" {
		return nil
	}
	for i := range e.Attributes {
		if strings.EqualFold(e.Attributes[i].Type, name) {
			return append([]string(nil), e.Attributes[i].Values...)
		}
	}
	return nil
}

// First returns the first value of the named attribute, or the empty string. | First
// 返回指定属性的第一个值，缺失时返回空字符串。
func (e *Entry) First(name string) string {
	values := e.Get(name)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// Has reports whether the named attribute is present. | Has 报告指定属性是否存在。
func (e *Entry) Has(name string) bool {
	if e == nil || name == "" {
		return false
	}
	for i := range e.Attributes {
		if strings.EqualFold(e.Attributes[i].Type, name) {
			return true
		}
	}
	return false
}

// Set replaces or appends an attribute on the entry. | Set 在条目上替换或追加属性。
func (e *Entry) Set(attr Attribute) {
	if e == nil {
		return
	}
	for i := range e.Attributes {
		if strings.EqualFold(e.Attributes[i].Type, attr.Type) {
			e.Attributes[i] = attr
			return
		}
	}
	e.Attributes = append(e.Attributes, attr)
}

// SearchRequest is an LDAP SearchRequest. | SearchRequest 是 LDAP SearchRequest。
type SearchRequest struct {
	// BaseDN is the search base. | BaseDN 是搜索基准。
	BaseDN string
	// Scope is the search scope. | Scope 是搜索范围。
	Scope Scope
	// DerefAliases controls alias handling. | DerefAliases 控制别名处理。
	DerefAliases DerefAliases
	// SizeLimit is the server-side entry limit, zero for no client limit. | SizeLimit 是服务端条目上限，零表示客户端不设限。
	SizeLimit int
	// TimeLimit is the server-side time limit in seconds, zero for none. | TimeLimit 是服务端时间上限（秒），零表示不设限。
	TimeLimit int
	// TypesOnly requests attribute descriptions without values. | TypesOnly 请求只返回属性描述而不带值。
	TypesOnly bool
	// Filter selects matching entries. A nil filter is invalid. | Filter 选择匹配条目；nil 过滤器非法。
	Filter Filter
	// Attributes selects attributes; empty means the server default set. | Attributes 选择属性；为空表示服务端默认集合。
	Attributes []string
}

// SearchResultReference is a referral returned during a search. | SearchResultReference
// 是搜索期间返回的转介。
type SearchResultReference struct {
	// URIs are the referral URIs. | URIs 是转介 URI。
	URIs []string
}

// SearchResultDone is the final search response. | SearchResultDone 是搜索的最终响应。
type SearchResultDone struct {
	// Result is the common result triple. | Result 是公共结果三元组。
	Result LDAPResult
}

// ModifyChange is one change in a ModifyRequest. | ModifyChange 是 ModifyRequest
// 中的一条变更。
type ModifyChange struct {
	// Operation is the change operation. | Operation 是变更操作。
	Operation ModifyOperation
	// Attribute carries the attribute description and values. | Attribute 携带属性描述与值。
	Attribute Attribute
}

// ModifyRequest is an LDAP ModifyRequest. | ModifyRequest 是 LDAP ModifyRequest。
type ModifyRequest struct {
	// DN is the target entry. | DN 是目标条目。
	DN string
	// Changes are applied in order. | Changes 按顺序应用。
	Changes []ModifyChange
}

// ModifyResponse is an LDAP ModifyResponse. | ModifyResponse 是 LDAP ModifyResponse。
type ModifyResponse struct {
	// Result is the common result triple. | Result 是公共结果三元组。
	Result LDAPResult
}

// AddRequest is an LDAP AddRequest. | AddRequest 是 LDAP AddRequest。
type AddRequest struct {
	// DN is the new entry distinguished name. | DN 是新条目可分辨名称。
	DN string
	// Attributes are the initial attributes. | Attributes 是初始属性。
	Attributes []Attribute
}

// AddResponse is an LDAP AddResponse. | AddResponse 是 LDAP AddResponse。
type AddResponse struct {
	// Result is the common result triple. | Result 是公共结果三元组。
	Result LDAPResult
}

// DeleteRequest is an LDAP DelRequest. | DeleteRequest 是 LDAP DelRequest。
type DeleteRequest struct {
	// DN is the entry to delete. | DN 是要删除的条目。
	DN string
}

// DeleteResponse is an LDAP DelResponse. | DeleteResponse 是 LDAP DelResponse。
type DeleteResponse struct {
	// Result is the common result triple. | Result 是公共结果三元组。
	Result LDAPResult
}

// ModifyDNRequest is an LDAP ModifyDNRequest. | ModifyDNRequest 是 LDAP
// ModifyDNRequest。
type ModifyDNRequest struct {
	// DN is the entry to rename. | DN 是要重命名的条目。
	DN string
	// NewRDN is the new relative distinguished name. | NewRDN 是新的相对可分辨名称。
	NewRDN string
	// DeleteOldRDN removes the old RDN attribute values. | DeleteOldRDN 删除旧的 RDN 属性值。
	DeleteOldRDN bool
	// NewSuperior optionally moves the entry under another parent. | NewSuperior 可选地把条目移动到另一个父节点。
	NewSuperior string
}

// ModifyDNResponse is an LDAP ModifyDNResponse. | ModifyDNResponse 是 LDAP
// ModifyDNResponse。
type ModifyDNResponse struct {
	// Result is the common result triple. | Result 是公共结果三元组。
	Result LDAPResult
}

// CompareRequest is an LDAP CompareRequest. | CompareRequest 是 LDAP CompareRequest。
type CompareRequest struct {
	// DN is the entry to compare. | DN 是要比较的条目。
	DN string
	// Attribute is the attribute description. | Attribute 是属性描述。
	Attribute string
	// Value is the assertion value. | Value 是断言值。
	Value string
}

// CompareResponse is an LDAP CompareResponse. | CompareResponse 是 LDAP
// CompareResponse。
type CompareResponse struct {
	// Result is the common result triple. | Result 是公共结果三元组。
	Result LDAPResult
}

// AbandonRequest is an LDAP AbandonRequest. | AbandonRequest 是 LDAP AbandonRequest。
type AbandonRequest struct {
	// MessageID is the message being abandoned. | MessageID 是被放弃的消息。
	MessageID int
}

// ExtendedRequest is an LDAP ExtendedRequest. | ExtendedRequest 是 LDAP
// ExtendedRequest。
type ExtendedRequest struct {
	// Name is the request OID. | Name 是请求 OID。
	Name string
	// Value is the optional request value. | Value 是可选的请求值。
	Value []byte
}

// ExtendedResponse is an LDAP ExtendedResponse. | ExtendedResponse 是 LDAP
// ExtendedResponse。
type ExtendedResponse struct {
	// Result is the common result triple. | Result 是公共结果三元组。
	Result LDAPResult
	// Name is the optional response OID. | Name 是可选响应 OID。
	Name string
	// Value is the optional response value. | Value 是可选响应值。
	Value []byte
}

// IntermediateResponse is an LDAP IntermediateResponse. | IntermediateResponse
// 是 LDAP IntermediateResponse。
type IntermediateResponse struct {
	// Name is the optional response OID. | Name 是可选响应 OID。
	Name string
	// Value is the optional response value. | Value 是可选响应值。
	Value []byte
}

// ProtocolOp is an LDAP protocol operation. Only the operation types declared
// in this package implement it. | ProtocolOp 是 LDAP 协议操作，只有本包声明的操作类型实现它。
type ProtocolOp interface {
	protocolTag() uint32
	encodeOp(*berEncoder) error
}

// LDAPMessage is one LDAPMessage envelope. | LDAPMessage 是一个 LDAPMessage 信封。
type LDAPMessage struct {
	// MessageID is the request/response correlation identifier. | MessageID 是请求/响应关联标识。
	MessageID int
	// Op is the protocol operation. | Op 是协议操作。
	Op ProtocolOp
	// Controls are attached controls. | Controls 是附加控件。
	Controls []Control
}

// encodeLDAPMessage serializes one complete LDAP message. | encodeLDAPMessage
// 序列化一条完整 LDAP 消息。
func encodeLDAPMessage(message *LDAPMessage) ([]byte, error) {
	if message == nil || message.Op == nil {
		return nil, errs.Detail(ErrInvalidMessage, "nil message or protocol operation | 消息或协议操作为空")
	}
	if message.MessageID < 0 || message.MessageID > 2147483647 {
		return nil, errs.Detail(ErrInvalidMessage, "message ID %d is out of range | 消息 ID %d 超出范围", message.MessageID, message.MessageID)
	}
	e := newBEREncoder(256)
	e.open(berClassUniversal, berTagSequence)
	e.integer(int64(message.MessageID))
	if err := message.Op.encodeOp(e); err != nil {
		return nil, err
	}
	if len(message.Controls) > 0 {
		encodeControls(e, message.Controls)
	}
	e.close()
	if len(e.frames) != 0 {
		return nil, errs.Detail(ErrInvalidMessage, "unbalanced message encoder frames | 消息编码帧不平衡")
	}
	return e.bytes(), nil
}

// protocolTag constants for LDAP application tags. | LDAP 应用标签常量。
const (
	appBindRequest           uint32 = 0
	appBindResponse          uint32 = 1
	appUnbindRequest         uint32 = 2
	appSearchRequest         uint32 = 3
	appSearchResultEntry     uint32 = 4
	appSearchResultDone      uint32 = 5
	appModifyRequest         uint32 = 6
	appModifyResponse        uint32 = 7
	appAddRequest            uint32 = 8
	appAddResponse           uint32 = 9
	appDeleteRequest         uint32 = 10
	appDeleteResponse        uint32 = 11
	appModifyDNRequest       uint32 = 12
	appModifyDNResponse      uint32 = 13
	appCompareRequest        uint32 = 14
	appCompareResponse       uint32 = 15
	appAbandonRequest        uint32 = 16
	appSearchResultReference uint32 = 19
	appExtendedRequest       uint32 = 23
	appExtendedResponse      uint32 = 24
	appIntermediateResponse  uint32 = 25
)

func (r *BindRequest) protocolTag() uint32 { return appBindRequest }
func (r *BindResponse) protocolTag() uint32 {
	return appBindResponse
}
func (r *UnbindRequest) protocolTag() uint32         { return appUnbindRequest }
func (r *SearchRequest) protocolTag() uint32         { return appSearchRequest }
func (r *Entry) protocolTag() uint32                 { return appSearchResultEntry }
func (r *SearchResultDone) protocolTag() uint32      { return appSearchResultDone }
func (r *SearchResultReference) protocolTag() uint32 { return appSearchResultReference }
func (r *ModifyRequest) protocolTag() uint32         { return appModifyRequest }
func (r *ModifyResponse) protocolTag() uint32        { return appModifyResponse }
func (r *AddRequest) protocolTag() uint32            { return appAddRequest }
func (r *AddResponse) protocolTag() uint32           { return appAddResponse }
func (r *DeleteRequest) protocolTag() uint32         { return appDeleteRequest }
func (r *DeleteResponse) protocolTag() uint32        { return appDeleteResponse }
func (r *ModifyDNRequest) protocolTag() uint32       { return appModifyDNRequest }
func (r *ModifyDNResponse) protocolTag() uint32      { return appModifyDNResponse }
func (r *CompareRequest) protocolTag() uint32        { return appCompareRequest }
func (r *CompareResponse) protocolTag() uint32       { return appCompareResponse }
func (r *AbandonRequest) protocolTag() uint32        { return appAbandonRequest }
func (r *ExtendedRequest) protocolTag() uint32       { return appExtendedRequest }
func (r *ExtendedResponse) protocolTag() uint32      { return appExtendedResponse }
func (r *IntermediateResponse) protocolTag() uint32  { return appIntermediateResponse }

// encodeAVAP appends an AttributeValueAssertion. | encodeAVAP 追加
// AttributeValueAssertion。
func encodeAVAP(e *berEncoder, attribute, value string) {
	e.open(berClassUniversal, berTagSequence)
	e.text(attribute)
	e.text(value)
	e.close()
}

// encodePartialAttribute appends a PartialAttribute. | encodePartialAttribute
// 追加 PartialAttribute。
func encodePartialAttribute(e *berEncoder, attribute Attribute) {
	e.open(berClassUniversal, berTagSequence)
	e.text(attribute.Type)
	e.open(berClassUniversal, berTagSet)
	for _, value := range attribute.Values {
		e.text(value)
	}
	e.close()
	e.close()
}

// encodeResult appends the common LDAPResult fields. | encodeResult 追加公共
// LDAPResult 字段。
func encodeResult(e *berEncoder, result LDAPResult) {
	e.enumerated(int64(result.Code))
	e.text(result.MatchedDN)
	e.text(result.DiagnosticMessage)
	if len(result.Referrals) > 0 {
		e.open(berClassContext, 3)
		for _, referral := range result.Referrals {
			e.text(referral)
		}
		e.close()
	}
}

func (r *BindRequest) encodeOp(e *berEncoder) error {
	if r.Version != 3 {
		return errs.Detail(ErrInvalidMessage, "bind version %d is unsupported | 不支持的绑定版本 %d", r.Version, r.Version)
	}
	if r.Authentication == nil {
		return errs.Detail(ErrInvalidMessage, "bind authentication is nil | 绑定认证为空")
	}
	e.open(berClassApplication, appBindRequest)
	e.integer(int64(r.Version))
	e.text(r.DN)
	switch auth := r.Authentication.(type) {
	case SimpleAuthentication:
		e.primitive(berClassContext, 0, []byte(auth.Password))
	case *SimpleAuthentication:
		if auth == nil {
			return errs.Detail(ErrInvalidMessage, "simple authentication is nil | 简单认证为空")
		}
		e.primitive(berClassContext, 0, []byte(auth.Password))
	case SASLAuthentication:
		e.open(berClassContext, 3)
		e.text(auth.Mechanism)
		e.primitive(berClassUniversal, berTagOctetString, auth.Credentials)
		e.close()
	case *SASLAuthentication:
		if auth == nil {
			return errs.Detail(ErrInvalidMessage, "SASL authentication is nil | SASL 认证为空")
		}
		e.open(berClassContext, 3)
		e.text(auth.Mechanism)
		e.primitive(berClassUniversal, berTagOctetString, auth.Credentials)
		e.close()
	default:
		return errs.Detail(ErrInvalidMessage, "unknown authentication type %T | 未知认证类型 %T", auth, auth)
	}
	e.close()
	return nil
}

func (r *BindResponse) encodeOp(e *berEncoder) error {
	e.open(berClassApplication, appBindResponse)
	encodeResult(e, r.Result)
	if len(r.ServerSASLCredentials) > 0 {
		e.primitive(berClassContext, 7, r.ServerSASLCredentials)
	}
	e.close()
	return nil
}

func (r *UnbindRequest) encodeOp(e *berEncoder) error {
	e.primitive(berClassApplication, appUnbindRequest, nil)
	return nil
}

func (r *SearchRequest) encodeOp(e *berEncoder) error {
	if r.Scope < ScopeBaseObject || r.Scope > ScopeWholeSubtree {
		return errs.Detail(ErrInvalidMessage, "search scope %d is invalid | 搜索范围 %d 非法", r.Scope, r.Scope)
	}
	if r.DerefAliases < NeverDerefAliases || r.DerefAliases > DerefAlways {
		return errs.Detail(ErrInvalidMessage, "deref aliases %d is invalid | 别名解引用 %d 非法", r.DerefAliases, r.DerefAliases)
	}
	if r.SizeLimit < 0 || r.TimeLimit < 0 {
		return errs.Detail(ErrInvalidMessage, "negative search limit | 搜索限制为负")
	}
	if err := ValidateFilter(r.Filter); err != nil {
		return err
	}
	e.open(berClassApplication, appSearchRequest)
	e.text(r.BaseDN)
	e.enumerated(int64(r.Scope))
	e.enumerated(int64(r.DerefAliases))
	e.integer(int64(r.SizeLimit))
	e.integer(int64(r.TimeLimit))
	e.boolean(r.TypesOnly)
	encodeFilter(e, r.Filter)
	e.open(berClassUniversal, berTagSequence)
	for _, attribute := range r.Attributes {
		e.text(attribute)
	}
	e.close()
	e.close()
	return nil
}

func (r *Entry) encodeOp(e *berEncoder) error {
	e.open(berClassApplication, appSearchResultEntry)
	e.text(r.DN)
	e.open(berClassUniversal, berTagSequence)
	for _, attribute := range r.Attributes {
		encodePartialAttribute(e, attribute)
	}
	e.close()
	e.close()
	return nil
}

func (r *SearchResultDone) encodeOp(e *berEncoder) error {
	e.open(berClassApplication, appSearchResultDone)
	encodeResult(e, r.Result)
	e.close()
	return nil
}

func (r *SearchResultReference) encodeOp(e *berEncoder) error {
	e.open(berClassApplication, appSearchResultReference)
	for _, uri := range r.URIs {
		e.text(uri)
	}
	e.close()
	return nil
}

func (r *ModifyRequest) encodeOp(e *berEncoder) error {
	e.open(berClassApplication, appModifyRequest)
	e.text(r.DN)
	e.open(berClassUniversal, berTagSequence)
	for _, change := range r.Changes {
		if change.Operation < ModifyAdd || change.Operation > ModifyIncrement {
			return errs.Detail(ErrInvalidMessage, "modify operation %d is invalid | 修改操作 %d 非法", change.Operation, change.Operation)
		}
		e.open(berClassUniversal, berTagSequence)
		e.enumerated(int64(change.Operation))
		encodePartialAttribute(e, change.Attribute)
		e.close()
	}
	e.close()
	e.close()
	return nil
}

func (r *ModifyResponse) encodeOp(e *berEncoder) error {
	e.open(berClassApplication, appModifyResponse)
	encodeResult(e, r.Result)
	e.close()
	return nil
}

func (r *AddRequest) encodeOp(e *berEncoder) error {
	e.open(berClassApplication, appAddRequest)
	e.text(r.DN)
	e.open(berClassUniversal, berTagSequence)
	for _, attribute := range r.Attributes {
		encodePartialAttribute(e, attribute)
	}
	e.close()
	e.close()
	return nil
}

func (r *AddResponse) encodeOp(e *berEncoder) error {
	e.open(berClassApplication, appAddResponse)
	encodeResult(e, r.Result)
	e.close()
	return nil
}

func (r *DeleteRequest) encodeOp(e *berEncoder) error {
	e.primitive(berClassApplication, appDeleteRequest, []byte(r.DN))
	return nil
}

func (r *DeleteResponse) encodeOp(e *berEncoder) error {
	e.open(berClassApplication, appDeleteResponse)
	encodeResult(e, r.Result)
	e.close()
	return nil
}

func (r *ModifyDNRequest) encodeOp(e *berEncoder) error {
	e.open(berClassApplication, appModifyDNRequest)
	e.text(r.DN)
	e.text(r.NewRDN)
	e.boolean(r.DeleteOldRDN)
	if r.NewSuperior != "" {
		e.primitive(berClassContext, 0, []byte(r.NewSuperior))
	}
	e.close()
	return nil
}

func (r *ModifyDNResponse) encodeOp(e *berEncoder) error {
	e.open(berClassApplication, appModifyDNResponse)
	encodeResult(e, r.Result)
	e.close()
	return nil
}

func (r *CompareRequest) encodeOp(e *berEncoder) error {
	e.open(berClassApplication, appCompareRequest)
	e.text(r.DN)
	encodeAVAP(e, r.Attribute, r.Value)
	e.close()
	return nil
}

func (r *CompareResponse) encodeOp(e *berEncoder) error {
	e.open(berClassApplication, appCompareResponse)
	encodeResult(e, r.Result)
	e.close()
	return nil
}

func (r *AbandonRequest) encodeOp(e *berEncoder) error {
	if r.MessageID <= 0 {
		return errs.Detail(ErrInvalidMessage, "abandon message ID %d is invalid | 放弃消息 ID %d 非法", r.MessageID, r.MessageID)
	}
	e.buf = appendBERTag(e.buf, berClassApplication, false, appAbandonRequest)
	e.buf = appendBERIntegerValue(e.buf, int64(r.MessageID))
	return nil
}

func (r *ExtendedRequest) encodeOp(e *berEncoder) error {
	if r.Name == "" {
		return errs.Detail(ErrInvalidMessage, "extended request name is empty | 扩展请求名为空")
	}
	e.open(berClassApplication, appExtendedRequest)
	e.primitive(berClassContext, 0, []byte(r.Name))
	if len(r.Value) > 0 {
		e.primitive(berClassContext, 1, r.Value)
	}
	e.close()
	return nil
}

func (r *ExtendedResponse) encodeOp(e *berEncoder) error {
	e.open(berClassApplication, appExtendedResponse)
	encodeResult(e, r.Result)
	if r.Name != "" {
		e.primitive(berClassContext, 10, []byte(r.Name))
	}
	if len(r.Value) > 0 {
		e.primitive(berClassContext, 11, r.Value)
	}
	e.close()
	return nil
}

func (r *IntermediateResponse) encodeOp(e *berEncoder) error {
	e.open(berClassApplication, appIntermediateResponse)
	if r.Name != "" {
		e.primitive(berClassContext, 0, []byte(r.Name))
	}
	if len(r.Value) > 0 {
		e.primitive(berClassContext, 1, r.Value)
	}
	e.close()
	return nil
}
