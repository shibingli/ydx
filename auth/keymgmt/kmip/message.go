package kmip

import (
	"time"

	"github.com/shibingli/ydx/errs"
)

// Credential is a KMIP username/password credential. | Credential 是 KMIP 用户名/口令凭据。
type Credential struct {
	// Type is the credential type; zero means username and password. | Type 是凭据类型；零值表示用户名与口令。
	Type CredentialType
	// Username is the user name. | Username 是用户名。
	Username string
	// Password is the password. It is never logged. | Password 是口令，绝不应写入日志。
	Password string
}

// Authentication is the KMIP Authentication structure. | Authentication 是 KMIP 认证结构。
type Authentication struct {
	// Credentials holds one or more credentials. | Credentials 保存一个或多个凭据。
	Credentials []Credential
}

// Item encodes the authentication structure. | Item 编码认证结构。
func (a Authentication) Item() (Item, error) {
	if len(a.Credentials) == 0 {
		return Item{}, errs.Detail(ErrInvalidRequest, "authentication has no credential | 认证没有凭据")
	}
	children := make([]Item, 0, len(a.Credentials))
	for _, cred := range a.Credentials {
		typ := cred.Type
		if typ == 0 {
			typ = CredentialTypeUsernameAndPassword
		}
		if typ != CredentialTypeUsernameAndPassword {
			return Item{}, errs.Detail(ErrUnsupported, "unsupported credential type %d | 不支持的凭据类型 %d", typ, typ)
		}
		valueChildren := []Item{NewTextString(TagUsername, cred.Username)}
		if cred.Password != "" {
			valueChildren = append(valueChildren, NewTextString(TagPassword, cred.Password))
		}
		children = append(children, NewStructure(TagCredential,
			NewEnumeration(TagCredentialType, uint32(typ)),
			NewStructure(TagCredentialValue, valueChildren...),
		))
	}
	return NewStructure(TagAuthentication, children...), nil
}

// DecodeAuthentication decodes the Authentication structure. | DecodeAuthentication 解码认证结构。
func DecodeAuthentication(item Item) (Authentication, error) {
	if item.Type != TypeStructure || item.Tag != TagAuthentication {
		return Authentication{}, errs.Detail(ErrMalformed, "expected Authentication structure | 需要认证结构")
	}
	var out Authentication
	for _, child := range item.Children {
		if child.Tag != TagCredential {
			return Authentication{}, errs.Detail(ErrMalformed, "unexpected tag 0x%06X in Authentication | 认证中出现意外标签 0x%06X", uint32(child.Tag), uint32(child.Tag))
		}
		typeItem, err := child.RequireChild(TagCredentialType)
		if err != nil {
			return Authentication{}, err
		}
		rawType, err := typeItem.AsEnumeration()
		if err != nil {
			return Authentication{}, err
		}
		if CredentialType(rawType) != CredentialTypeUsernameAndPassword {
			return Authentication{}, errs.Detail(ErrUnsupported, "unsupported credential type 0x%08X | 不支持的凭据类型 0x%08X", rawType, rawType)
		}
		valueItem, err := child.RequireChild(TagCredentialValue)
		if err != nil {
			return Authentication{}, err
		}
		if valueItem.Type != TypeStructure {
			return Authentication{}, errs.Detail(ErrMalformed, "credential value is not a structure | 凭据值不是结构")
		}
		var cred Credential
		cred.Type = CredentialType(rawType)
		if userItem, ok := valueItem.Child(TagUsername); ok {
			cred.Username, err = userItem.AsTextString()
			if err != nil {
				return Authentication{}, err
			}
		}
		if passItem, ok := valueItem.Child(TagPassword); ok {
			cred.Password, err = passItem.AsTextString()
			if err != nil {
				return Authentication{}, err
			}
		}
		out.Credentials = append(out.Credentials, cred)
	}
	if len(out.Credentials) == 0 {
		return Authentication{}, errs.Detail(ErrMalformed, "Authentication has no Credential | 认证没有凭据")
	}
	return out, nil
}

// RequestHeader is a KMIP Request Header. | RequestHeader 是 KMIP 请求头。
type RequestHeader struct {
	// ProtocolVersion is the requested protocol version. | ProtocolVersion 是请求的协议版本。
	ProtocolVersion ProtocolVersion
	// MaximumResponseSize limits the response size; zero means no client limit. | MaximumResponseSize 限制响应长度；零表示客户端无限制。
	MaximumResponseSize int
	// ClientCorrelationValue is an optional client correlation value. | ClientCorrelationValue 是可选客户端关联值。
	ClientCorrelationValue string
	// ServerCorrelationValue echoes a server correlation value. | ServerCorrelationValue 回显服务器关联值。
	ServerCorrelationValue string
	// AsynchronousIndicator requests asynchronous execution when true. | AsynchronousIndicator 为真时请求异步执行。
	AsynchronousIndicator bool
	// Authentication optionally carries client credentials. | Authentication 可选携带客户端凭据。
	Authentication *Authentication
	// BatchErrorContinuationOption controls batch failure handling. | BatchErrorContinuationOption 控制批处理失败策略。
	BatchErrorContinuationOption BatchErrorContinuationOption
	// BatchOrderOption requests ordered batch execution when true. | BatchOrderOption 为真时请求按序执行批处理。
	BatchOrderOption bool
	// TimeStamp is the optional request creation time. | TimeStamp 是可选请求创建时间。
	TimeStamp time.Time
	// BatchCount is the number of batch items. EncodeRequest fills it when zero. | BatchCount 是批处理项数量；为零时 EncodeRequest 会填充。
	BatchCount int
}

// ResponseHeader is a KMIP Response Header. | ResponseHeader 是 KMIP 响应头。
type ResponseHeader struct {
	// ProtocolVersion is the protocol version used by the server. | ProtocolVersion 是服务器使用的协议版本。
	ProtocolVersion ProtocolVersion
	// TimeStamp is the response creation time. | TimeStamp 是响应创建时间。
	TimeStamp time.Time
	// ClientCorrelationValue echoes the request correlation value. | ClientCorrelationValue 回显请求关联值。
	ClientCorrelationValue string
	// ServerCorrelationValue is an optional server correlation value. | ServerCorrelationValue 是可选服务器关联值。
	ServerCorrelationValue string
	// BatchCount is the number of batch items. EncodeResponse fills it when zero. | BatchCount 是批处理项数量；为零时 EncodeResponse 会填充。
	BatchCount int
}

// protocolVersionItem encodes a Protocol Version structure. | protocolVersionItem 编码协议版本结构。
func protocolVersionItem(v ProtocolVersion) Item {
	return NewStructure(TagProtocolVersion,
		NewInteger(TagProtocolVersionMajor, int64(v.Major)),
		NewInteger(TagProtocolVersionMinor, int64(v.Minor)),
	)
}

// duplicateTag records tag in seen and reports whether it was already present. | duplicateTag
// 在 seen 中记录 tag，并报告其此前是否已存在。
func duplicateTag(seen map[Tag]struct{}, tag Tag) bool {
	if _, ok := seen[tag]; ok {
		return true
	}
	seen[tag] = struct{}{}
	return false
}

// duplicateTagError builds an ErrMalformed error for a repeated tag. | duplicateTagError 为重复标签
// 构造 ErrMalformed 错误。
func duplicateTagError(tag Tag, where string) error {
	return errs.Detail(ErrMalformed, "duplicate tag 0x%06X in %s | %s 中重复标签 0x%06X", uint32(tag), where, where, uint32(tag))
}

// decodeProtocolVersion decodes a Protocol Version structure. | decodeProtocolVersion 解码协议版本结构。
func decodeProtocolVersion(item Item) (ProtocolVersion, error) {
	if item.Type != TypeStructure || item.Tag != TagProtocolVersion {
		return ProtocolVersion{}, errs.Detail(ErrMalformed, "expected Protocol Version structure | 需要协议版本结构")
	}
	if len(item.ChildrenOf(TagProtocolVersionMajor)) != 1 || len(item.ChildrenOf(TagProtocolVersionMinor)) != 1 {
		return ProtocolVersion{}, errs.Detail(ErrMalformed, "Protocol Version must contain exactly one major and one minor field | 协议版本必须恰好包含一个主版本与一个次版本字段")
	}
	majorItem, err := item.RequireChild(TagProtocolVersionMajor)
	if err != nil {
		return ProtocolVersion{}, err
	}
	minorItem, err := item.RequireChild(TagProtocolVersionMinor)
	if err != nil {
		return ProtocolVersion{}, err
	}
	major, err := majorItem.AsInteger()
	if err != nil {
		return ProtocolVersion{}, err
	}
	minor, err := minorItem.AsInteger()
	if err != nil {
		return ProtocolVersion{}, err
	}
	if major <= 0 || major > 255 || minor < 0 || minor > 255 {
		return ProtocolVersion{}, errs.Detail(ErrMalformed, "invalid protocol version %d.%d | 协议版本 %d.%d 非法", major, minor, major, minor)
	}
	return ProtocolVersion{Major: int(major), Minor: int(minor)}, nil
}

// requestHeaderItem encodes a Request Header. | requestHeaderItem 编码请求头。
func requestHeaderItem(h RequestHeader) (Item, error) {
	if !h.ProtocolVersion.Valid() {
		return Item{}, errs.Detail(ErrInvalidRequest, "request header has no protocol version | 请求头没有协议版本")
	}
	children := []Item{protocolVersionItem(h.ProtocolVersion)}
	if h.MaximumResponseSize > 0 {
		children = append(children, NewInteger(TagMaximumResponseSize, int64(h.MaximumResponseSize)))
	}
	if h.ClientCorrelationValue != "" {
		children = append(children, NewTextString(TagClientCorrelationValue, h.ClientCorrelationValue))
	}
	if h.ServerCorrelationValue != "" {
		children = append(children, NewTextString(TagServerCorrelationValue, h.ServerCorrelationValue))
	}
	if h.AsynchronousIndicator {
		children = append(children, NewBoolean(TagAsynchronousIndicator, true))
	}
	if h.Authentication != nil {
		auth, err := h.Authentication.Item()
		if err != nil {
			return Item{}, err
		}
		children = append(children, auth)
	}
	if h.BatchErrorContinuationOption != 0 {
		children = append(children, NewEnumeration(TagBatchErrorContinuationOption, uint32(h.BatchErrorContinuationOption)))
	}
	if h.BatchOrderOption {
		children = append(children, NewBoolean(TagBatchOrderOption, true))
	}
	if !h.TimeStamp.IsZero() {
		children = append(children, NewDateTime(TagTimeStamp, h.TimeStamp))
	}
	if h.BatchCount < 0 {
		return Item{}, errs.Detail(ErrInvalidRequest, "negative batch count | 批处理计数为负")
	}
	children = append(children, NewInteger(TagBatchCount, int64(h.BatchCount)))
	return NewStructure(TagRequestHeader, children...), nil
}

// decodeRequestHeader decodes a Request Header. | decodeRequestHeader 解码请求头。
func decodeRequestHeader(item Item) (RequestHeader, error) {
	if item.Type != TypeStructure || item.Tag != TagRequestHeader {
		return RequestHeader{}, errs.Detail(ErrMalformed, "expected Request Header structure | 需要请求头结构")
	}
	var out RequestHeader
	seen := make(map[Tag]struct{}, len(item.Children))
	for _, child := range item.Children {
		if duplicateTag(seen, child.Tag) {
			return out, duplicateTagError(child.Tag, "Request Header")
		}
		switch child.Tag {
		case TagProtocolVersion:
			v, err := decodeProtocolVersion(child)
			if err != nil {
				return out, err
			}
			out.ProtocolVersion = v
		case TagMaximumResponseSize:
			v, err := child.AsInteger()
			if err != nil {
				return out, err
			}
			if v < 0 || v > int64(^uint(0)>>1) {
				return out, errs.Detail(ErrMalformed, "invalid maximum response size | 最大响应长度非法")
			}
			out.MaximumResponseSize = int(v)
		case TagClientCorrelationValue:
			v, err := child.AsTextString()
			if err != nil {
				return out, err
			}
			out.ClientCorrelationValue = v
		case TagServerCorrelationValue:
			v, err := child.AsTextString()
			if err != nil {
				return out, err
			}
			out.ServerCorrelationValue = v
		case TagAsynchronousIndicator:
			v, err := child.AsBoolean()
			if err != nil {
				return out, err
			}
			out.AsynchronousIndicator = v
		case TagAuthentication:
			v, err := DecodeAuthentication(child)
			if err != nil {
				return out, err
			}
			out.Authentication = &v
		case TagBatchErrorContinuationOption:
			v, err := child.AsEnumeration()
			if err != nil {
				return out, err
			}
			out.BatchErrorContinuationOption = BatchErrorContinuationOption(v)
		case TagBatchOrderOption:
			v, err := child.AsBoolean()
			if err != nil {
				return out, err
			}
			out.BatchOrderOption = v
		case TagTimeStamp:
			v, err := child.AsDateTime()
			if err != nil {
				return out, err
			}
			out.TimeStamp = v
		case TagBatchCount:
			v, err := child.AsInteger()
			if err != nil {
				return out, err
			}
			if v < 0 || v > DefaultMaxBatchItems {
				return out, errs.Detail(ErrLimitExceeded, "batch count %d exceeds limit %d | 批处理计数 %d 超过限制 %d", v, DefaultMaxBatchItems, v, DefaultMaxBatchItems)
			}
			out.BatchCount = int(v)
		default:
			// Unknown header extensions are ignored so that newer minor versions can interoperate. | 忽略未知头扩展以兼容更新的次版本。
		}
	}
	if out.ProtocolVersion.Major == 0 && out.ProtocolVersion.Minor == 0 {
		return out, errs.Detail(ErrMalformed, "Request Header has no Protocol Version | 请求头没有协议版本")
	}
	return out, nil
}

// responseHeaderItem encodes a Response Header. | responseHeaderItem 编码响应头。
func responseHeaderItem(h ResponseHeader) (Item, error) {
	if !h.ProtocolVersion.Valid() {
		return Item{}, errs.Detail(ErrInvalidRequest, "response header has no protocol version | 响应头没有协议版本")
	}
	children := []Item{protocolVersionItem(h.ProtocolVersion)}
	if !h.TimeStamp.IsZero() {
		children = append(children, NewDateTime(TagTimeStamp, h.TimeStamp))
	}
	if h.ClientCorrelationValue != "" {
		children = append(children, NewTextString(TagClientCorrelationValue, h.ClientCorrelationValue))
	}
	if h.ServerCorrelationValue != "" {
		children = append(children, NewTextString(TagServerCorrelationValue, h.ServerCorrelationValue))
	}
	if h.BatchCount < 0 {
		return Item{}, errs.Detail(ErrInvalidRequest, "negative batch count | 批处理计数为负")
	}
	children = append(children, NewInteger(TagBatchCount, int64(h.BatchCount)))
	return NewStructure(TagResponseHeader, children...), nil
}

// decodeResponseHeader decodes a Response Header. | decodeResponseHeader 解码响应头。
func decodeResponseHeader(item Item) (ResponseHeader, error) {
	if item.Type != TypeStructure || item.Tag != TagResponseHeader {
		return ResponseHeader{}, errs.Detail(ErrMalformed, "expected Response Header structure | 需要响应头结构")
	}
	var out ResponseHeader
	seen := make(map[Tag]struct{}, len(item.Children))
	for _, child := range item.Children {
		if duplicateTag(seen, child.Tag) {
			return out, duplicateTagError(child.Tag, "Response Header")
		}
		switch child.Tag {
		case TagProtocolVersion:
			v, err := decodeProtocolVersion(child)
			if err != nil {
				return out, err
			}
			out.ProtocolVersion = v
		case TagTimeStamp:
			v, err := child.AsDateTime()
			if err != nil {
				return out, err
			}
			out.TimeStamp = v
		case TagClientCorrelationValue:
			v, err := child.AsTextString()
			if err != nil {
				return out, err
			}
			out.ClientCorrelationValue = v
		case TagServerCorrelationValue:
			v, err := child.AsTextString()
			if err != nil {
				return out, err
			}
			out.ServerCorrelationValue = v
		case TagBatchCount:
			v, err := child.AsInteger()
			if err != nil {
				return out, err
			}
			if v < 0 || v > DefaultMaxBatchItems {
				return out, errs.Detail(ErrLimitExceeded, "batch count %d exceeds limit %d | 批处理计数 %d 超过限制 %d", v, DefaultMaxBatchItems, v, DefaultMaxBatchItems)
			}
			out.BatchCount = int(v)
		default:
			// Unknown header extensions are ignored. | 忽略未知头扩展。
		}
	}
	if out.ProtocolVersion.Major == 0 && out.ProtocolVersion.Minor == 0 {
		return out, errs.Detail(ErrMalformed, "Response Header has no Protocol Version | 响应头没有协议版本")
	}
	return out, nil
}

// RequestBatchItem is one KMIP request batch item. | RequestBatchItem 是一个 KMIP 请求批处理项。
type RequestBatchItem struct {
	// Operation is the requested operation. | Operation 是请求的操作。
	Operation Operation
	// UniqueBatchItemID optionally correlates this item with its response. | UniqueBatchItemID 可选地把本项与其响应关联。
	UniqueBatchItemID []byte
	// Payload is the request payload structure, tagged TagRequestPayload. | Payload 是请求负载结构，标签为 TagRequestPayload。
	Payload Item
	// MessageExtension is an optional vendor message extension. | MessageExtension 是可选厂商消息扩展。
	MessageExtension *Item
}

// ResponseBatchItem is one KMIP response batch item. | ResponseBatchItem 是一个 KMIP 响应批处理项。
type ResponseBatchItem struct {
	// Operation echoes the operation; it may be omitted in single-item responses. | Operation 回显操作；单项响应中可省略。
	Operation Operation
	// UniqueBatchItemID echoes the request batch item ID. | UniqueBatchItemID 回显请求批处理项标识。
	UniqueBatchItemID []byte
	// ResultStatus is the result status. | ResultStatus 是结果状态。
	ResultStatus ResultStatus
	// ResultReason is the failure reason when ResultStatus is not Success. | ResultReason 是结果状态非成功时的失败原因。
	ResultReason ResultReason
	// ResultMessage is a human-readable diagnostic that must not contain key material. | ResultMessage 是人类可读诊断，绝不能包含密钥材料。
	ResultMessage string
	// AsynchronousCorrelationValue correlates asynchronous operations. | AsynchronousCorrelationValue 关联异步操作。
	AsynchronousCorrelationValue []byte
	// Payload is the response payload structure, tagged TagResponsePayload. | Payload 是响应负载结构，标签为 TagResponsePayload。
	Payload Item
	// MessageExtension is an optional vendor message extension. | MessageExtension 是可选厂商消息扩展。
	MessageExtension *Item
}

// Err returns a *ResultError when the batch item failed and nil otherwise. | Err 在批处理项失败时返回 *ResultError，否则返回 nil。
func (b ResponseBatchItem) Err() error {
	if b.ResultStatus == ResultStatusSuccess {
		return nil
	}
	return &ResultError{
		Status:  b.ResultStatus,
		Reason:  b.ResultReason,
		Message: b.ResultMessage,
	}
}

// RequestMessage is a KMIP Request Message. | RequestMessage 是 KMIP 请求消息。
type RequestMessage struct {
	// Header is the request header. | Header 是请求头。
	Header RequestHeader
	// BatchItems holds the request batch. | BatchItems 保存请求批处理。
	BatchItems []RequestBatchItem
}

// ResponseMessage is a KMIP Response Message. | ResponseMessage 是 KMIP 响应消息。
type ResponseMessage struct {
	// Header is the response header. | Header 是响应头。
	Header ResponseHeader
	// BatchItems holds the response batch. | BatchItems 保存响应批处理。
	BatchItems []ResponseBatchItem
}

// requestBatchItem encodes one request batch item. | requestBatchItem 编码一个请求批处理项。
func requestBatchItem(item RequestBatchItem) (Item, error) {
	if item.Operation == 0 {
		return Item{}, errs.Detail(ErrInvalidRequest, "request batch item has no operation | 请求批处理项没有操作")
	}
	if item.Payload.Type != TypeStructure || item.Payload.Tag != TagRequestPayload {
		return Item{}, errs.Detail(ErrInvalidRequest, "request batch item payload is not a Request Payload structure | 请求批处理项负载不是 Request Payload 结构")
	}
	children := []Item{NewEnumeration(TagOperation, uint32(item.Operation))}
	if len(item.UniqueBatchItemID) > 0 {
		children = append(children, NewByteString(TagUniqueBatchItemID, item.UniqueBatchItemID))
	}
	children = append(children, item.Payload)
	if item.MessageExtension != nil {
		if item.MessageExtension.Type != TypeStructure || item.MessageExtension.Tag != TagMessageExtension {
			return Item{}, errs.Detail(ErrInvalidRequest, "message extension is not a Message Extension structure | 消息扩展不是 Message Extension 结构")
		}
		children = append(children, *item.MessageExtension)
	}
	return NewStructure(TagBatchItem, children...), nil
}

// responseBatchItem encodes one response batch item. | responseBatchItem 编码一个响应批处理项。
func responseBatchItem(item ResponseBatchItem) (Item, error) {
	children := make([]Item, 0, 8)
	if item.Operation != 0 {
		children = append(children, NewEnumeration(TagOperation, uint32(item.Operation)))
	}
	if len(item.UniqueBatchItemID) > 0 {
		children = append(children, NewByteString(TagUniqueBatchItemID, item.UniqueBatchItemID))
	}
	children = append(children, NewEnumeration(TagResultStatus, uint32(item.ResultStatus)))
	if item.ResultStatus != ResultStatusSuccess || item.ResultReason != 0 {
		children = append(children, NewEnumeration(TagResultReason, uint32(item.ResultReason)))
	}
	if item.ResultMessage != "" {
		children = append(children, NewTextString(TagResultMessage, item.ResultMessage))
	}
	if len(item.AsynchronousCorrelationValue) > 0 {
		children = append(children, NewByteString(TagAsynchronousCorrelationValue, item.AsynchronousCorrelationValue))
	}
	if item.Payload.Type != 0 {
		if item.Payload.Type != TypeStructure || item.Payload.Tag != TagResponsePayload {
			return Item{}, errs.Detail(ErrInvalidRequest, "response batch item payload is not a Response Payload structure | 响应批处理项负载不是 Response Payload 结构")
		}
		children = append(children, item.Payload)
	}
	if item.MessageExtension != nil {
		if item.MessageExtension.Type != TypeStructure || item.MessageExtension.Tag != TagMessageExtension {
			return Item{}, errs.Detail(ErrInvalidRequest, "message extension is not a Message Extension structure | 消息扩展不是 Message Extension 结构")
		}
		children = append(children, *item.MessageExtension)
	}
	return NewStructure(TagBatchItem, children...), nil
}

// RequestItem encodes the request message as a Request Message structure. | RequestItem 把请求消息编码为 Request Message 结构。
func (m RequestMessage) RequestItem() (Item, error) {
	count := len(m.BatchItems)
	if count == 0 {
		return Item{}, errs.Detail(ErrInvalidRequest, "request message has no batch item | 请求消息没有批处理项")
	}
	if count > DefaultMaxBatchItems {
		return Item{}, errs.Detail(ErrLimitExceeded, "batch count %d exceeds limit %d | 批处理计数 %d 超过限制 %d", count, DefaultMaxBatchItems, count, DefaultMaxBatchItems)
	}
	header := m.Header
	if header.BatchCount != 0 && header.BatchCount != count {
		return Item{}, errs.Detail(ErrInvalidRequest, "batch count %d does not match %d items | 批处理计数 %d 与 %d 个项不一致", header.BatchCount, count, header.BatchCount, count)
	}
	header.BatchCount = count
	hdr, err := requestHeaderItem(header)
	if err != nil {
		return Item{}, err
	}
	children := make([]Item, 0, count+1)
	children = append(children, hdr)
	for _, batch := range m.BatchItems {
		item, err := requestBatchItem(batch)
		if err != nil {
			return Item{}, err
		}
		children = append(children, item)
	}
	return NewStructure(TagRequestMessage, children...), nil
}

// ResponseItem encodes the response message as a Response Message structure. | ResponseItem 把响应消息编码为 Response Message 结构。
func (m ResponseMessage) ResponseItem() (Item, error) {
	count := len(m.BatchItems)
	if count == 0 {
		return Item{}, errs.Detail(ErrInvalidRequest, "response message has no batch item | 响应消息没有批处理项")
	}
	if count > DefaultMaxBatchItems {
		return Item{}, errs.Detail(ErrLimitExceeded, "batch count %d exceeds limit %d | 批处理计数 %d 超过限制 %d", count, DefaultMaxBatchItems, count, DefaultMaxBatchItems)
	}
	header := m.Header
	if header.BatchCount != 0 && header.BatchCount != count {
		return Item{}, errs.Detail(ErrInvalidRequest, "batch count %d does not match %d items | 批处理计数 %d 与 %d 个项不一致", header.BatchCount, count, header.BatchCount, count)
	}
	header.BatchCount = count
	hdr, err := responseHeaderItem(header)
	if err != nil {
		return Item{}, err
	}
	children := make([]Item, 0, count+1)
	children = append(children, hdr)
	for _, batch := range m.BatchItems {
		item, err := responseBatchItem(batch)
		if err != nil {
			return Item{}, err
		}
		children = append(children, item)
	}
	return NewStructure(TagResponseMessage, children...), nil
}

// EncodeRequest encodes a request message with the default limits. | EncodeRequest 使用默认限制编码请求消息。
func EncodeRequest(m RequestMessage) ([]byte, error) {
	item, err := m.RequestItem()
	if err != nil {
		return nil, err
	}
	return Encode(item)
}

// EncodeRequestWithLimits encodes a request message under the given limits. | EncodeRequestWithLimits 在给定限制下编码请求消息。
func EncodeRequestWithLimits(m RequestMessage, limits Limits) ([]byte, error) {
	item, err := m.RequestItem()
	if err != nil {
		return nil, err
	}
	return EncodeWithLimits(item, limits)
}

// EncodeResponse encodes a response message with the default limits. | EncodeResponse 使用默认限制编码响应消息。
func EncodeResponse(m ResponseMessage) ([]byte, error) {
	item, err := m.ResponseItem()
	if err != nil {
		return nil, err
	}
	return Encode(item)
}

// EncodeResponseWithLimits encodes a response message under the given limits. | EncodeResponseWithLimits 在给定限制下编码响应消息。
func EncodeResponseWithLimits(m ResponseMessage, limits Limits) ([]byte, error) {
	item, err := m.ResponseItem()
	if err != nil {
		return nil, err
	}
	return EncodeWithLimits(item, limits)
}

// decodeRequestBatchItem decodes one request batch item. | decodeRequestBatchItem 解码一个请求批处理项。
func decodeRequestBatchItem(item Item) (RequestBatchItem, error) {
	if item.Type != TypeStructure || item.Tag != TagBatchItem {
		return RequestBatchItem{}, errs.Detail(ErrMalformed, "expected Batch Item structure | 需要批处理项结构")
	}
	var out RequestBatchItem
	seen := make(map[Tag]struct{}, len(item.Children))
	for _, child := range item.Children {
		if duplicateTag(seen, child.Tag) {
			return out, duplicateTagError(child.Tag, "request Batch Item")
		}
		switch child.Tag {
		case TagOperation:
			v, err := child.AsEnumeration()
			if err != nil {
				return out, err
			}
			out.Operation = Operation(v)
		case TagUniqueBatchItemID:
			v, err := child.AsByteString()
			if err != nil {
				return out, err
			}
			out.UniqueBatchItemID = append([]byte(nil), v...)
		case TagRequestPayload:
			if child.Type != TypeStructure {
				return out, errs.Detail(ErrMalformed, "Request Payload is not a structure | Request Payload 不是结构")
			}
			out.Payload = child
		case TagMessageExtension:
			ext := child
			out.MessageExtension = &ext
		default:
			return out, errs.Detail(ErrMalformed, "unexpected tag 0x%06X in request Batch Item | 请求批处理项中出现意外标签 0x%06X", uint32(child.Tag), uint32(child.Tag))
		}
	}
	if out.Operation == 0 {
		return out, errs.Detail(ErrMalformed, "request Batch Item has no Operation | 请求批处理项没有操作")
	}
	if out.Payload.Type == 0 {
		return out, errs.Detail(ErrMalformed, "request Batch Item has no Request Payload | 请求批处理项没有请求负载")
	}
	return out, nil
}

// decodeResponseBatchItem decodes one response batch item. | decodeResponseBatchItem 解码一个响应批处理项。
func decodeResponseBatchItem(item Item) (ResponseBatchItem, error) {
	if item.Type != TypeStructure || item.Tag != TagBatchItem {
		return ResponseBatchItem{}, errs.Detail(ErrMalformed, "expected Batch Item structure | 需要批处理项结构")
	}
	var out ResponseBatchItem
	hasOperation := false
	hasResultStatus := false
	seen := make(map[Tag]struct{}, len(item.Children))
	for _, child := range item.Children {
		if duplicateTag(seen, child.Tag) {
			return out, duplicateTagError(child.Tag, "response Batch Item")
		}
		switch child.Tag {
		case TagOperation:
			v, err := child.AsEnumeration()
			if err != nil {
				return out, err
			}
			out.Operation = Operation(v)
			hasOperation = true
		case TagUniqueBatchItemID:
			v, err := child.AsByteString()
			if err != nil {
				return out, err
			}
			out.UniqueBatchItemID = append([]byte(nil), v...)
		case TagResultStatus:
			v, err := child.AsEnumeration()
			if err != nil {
				return out, err
			}
			out.ResultStatus = ResultStatus(v)
			hasResultStatus = true
		case TagResultReason:
			v, err := child.AsEnumeration()
			if err != nil {
				return out, err
			}
			out.ResultReason = ResultReason(v)
		case TagResultMessage:
			v, err := child.AsTextString()
			if err != nil {
				return out, err
			}
			out.ResultMessage = v
		case TagAsynchronousCorrelationValue:
			v, err := child.AsByteString()
			if err != nil {
				return out, err
			}
			out.AsynchronousCorrelationValue = append([]byte(nil), v...)
		case TagResponsePayload:
			if child.Type != TypeStructure {
				return out, errs.Detail(ErrMalformed, "Response Payload is not a structure | Response Payload 不是结构")
			}
			out.Payload = child
		case TagMessageExtension:
			ext := child
			out.MessageExtension = &ext
		default:
			return out, errs.Detail(ErrMalformed, "unexpected tag 0x%06X in response Batch Item | 响应批处理项中出现意外标签 0x%06X", uint32(child.Tag), uint32(child.Tag))
		}
	}
	if !hasOperation {
		return out, errs.Detail(ErrMalformed, "response Batch Item has no Operation | 响应批处理项没有操作")
	}
	if !hasResultStatus {
		return out, errs.Detail(ErrMalformed, "response Batch Item has no Result Status | 响应批处理项没有结果状态")
	}
	if out.ResultStatus > ResultStatusOperationUndone {
		return out, errs.Detail(ErrMalformed, "invalid result status 0x%08X | 结果状态 0x%08X 非法", uint32(out.ResultStatus), uint32(out.ResultStatus))
	}
	return out, nil
}

// DecodeRequest decodes a request message with the default limits. | DecodeRequest 使用默认限制解码请求消息。
//
// Decoded value slices alias data; data must not be modified while the message is in use. | 解码后的值切片与 data 共享底层数组；
// 消息使用期间不得修改 data。
func DecodeRequest(data []byte) (RequestMessage, error) {
	return DecodeRequestWithLimits(data, DefaultLimits())
}

// DecodeRequestWithLimits decodes a request message under the given limits. | DecodeRequestWithLimits 在给定限制下解码请求消息。
func DecodeRequestWithLimits(data []byte, limits Limits) (RequestMessage, error) {
	item, err := DecodeWithLimits(data, limits)
	if err != nil {
		return RequestMessage{}, err
	}
	if item.Tag != TagRequestMessage || item.Type != TypeStructure {
		return RequestMessage{}, errs.Detail(ErrMalformed, "expected Request Message structure | 需要请求消息结构")
	}
	var out RequestMessage
	var haveHeader bool
	for _, child := range item.Children {
		switch child.Tag {
		case TagRequestHeader:
			if haveHeader {
				return out, errs.Detail(ErrMalformed, "duplicate Request Header | 重复的请求头")
			}
			hdr, err := decodeRequestHeader(child)
			if err != nil {
				return out, err
			}
			out.Header = hdr
			haveHeader = true
		case TagBatchItem:
			batch, err := decodeRequestBatchItem(child)
			if err != nil {
				return out, err
			}
			out.BatchItems = append(out.BatchItems, batch)
		default:
			return out, errs.Detail(ErrMalformed, "unexpected tag 0x%06X in Request Message | 请求消息中出现意外标签 0x%06X", uint32(child.Tag), uint32(child.Tag))
		}
	}
	if !haveHeader {
		return out, errs.Detail(ErrMalformed, "Request Message has no Request Header | 请求消息没有请求头")
	}
	if len(out.BatchItems) == 0 {
		return out, errs.Detail(ErrMalformed, "Request Message has no Batch Item | 请求消息没有批处理项")
	}
	if len(out.BatchItems) > DefaultMaxBatchItems {
		return out, errs.Detail(ErrLimitExceeded, "batch count %d exceeds limit %d | 批处理计数 %d 超过限制 %d", len(out.BatchItems), DefaultMaxBatchItems, len(out.BatchItems), DefaultMaxBatchItems)
	}
	if out.Header.BatchCount != len(out.BatchItems) {
		return out, errs.Detail(ErrMalformed, "Batch Count %d does not match %d items | 批处理计数 %d 与 %d 个项不一致", out.Header.BatchCount, len(out.BatchItems), out.Header.BatchCount, len(out.BatchItems))
	}
	return out, nil
}

// DecodeResponse decodes a response message with the default limits. | DecodeResponse 使用默认限制解码响应消息。
//
// Decoded value slices alias data; data must not be modified while the message is in use. | 解码后的值切片与 data 共享底层数组；
// 消息使用期间不得修改 data。
func DecodeResponse(data []byte) (ResponseMessage, error) {
	return DecodeResponseWithLimits(data, DefaultLimits())
}

// DecodeResponseWithLimits decodes a response message under the given limits. | DecodeResponseWithLimits 在给定限制下解码响应消息。
func DecodeResponseWithLimits(data []byte, limits Limits) (ResponseMessage, error) {
	item, err := DecodeWithLimits(data, limits)
	if err != nil {
		return ResponseMessage{}, err
	}
	if item.Tag != TagResponseMessage || item.Type != TypeStructure {
		return ResponseMessage{}, errs.Detail(ErrMalformed, "expected Response Message structure | 需要响应消息结构")
	}
	var out ResponseMessage
	var haveHeader bool
	for _, child := range item.Children {
		switch child.Tag {
		case TagResponseHeader:
			if haveHeader {
				return out, errs.Detail(ErrMalformed, "duplicate Response Header | 重复的响应头")
			}
			hdr, err := decodeResponseHeader(child)
			if err != nil {
				return out, err
			}
			out.Header = hdr
			haveHeader = true
		case TagBatchItem:
			batch, err := decodeResponseBatchItem(child)
			if err != nil {
				return out, err
			}
			out.BatchItems = append(out.BatchItems, batch)
		default:
			return out, errs.Detail(ErrMalformed, "unexpected tag 0x%06X in Response Message | 响应消息中出现意外标签 0x%06X", uint32(child.Tag), uint32(child.Tag))
		}
	}
	if !haveHeader {
		return out, errs.Detail(ErrMalformed, "Response Message has no Response Header | 响应消息没有响应头")
	}
	if len(out.BatchItems) == 0 {
		return out, errs.Detail(ErrMalformed, "Response Message has no Batch Item | 响应消息没有批处理项")
	}
	if len(out.BatchItems) > DefaultMaxBatchItems {
		return out, errs.Detail(ErrLimitExceeded, "batch count %d exceeds limit %d | 批处理计数 %d 超过限制 %d", len(out.BatchItems), DefaultMaxBatchItems, len(out.BatchItems), DefaultMaxBatchItems)
	}
	if out.Header.BatchCount != len(out.BatchItems) {
		return out, errs.Detail(ErrMalformed, "Batch Count %d does not match %d items | 批处理计数 %d 与 %d 个项不一致", out.Header.BatchCount, len(out.BatchItems), out.Header.BatchCount, len(out.BatchItems))
	}
	return out, nil
}
