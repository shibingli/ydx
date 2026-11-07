package kmip

import (
	"time"

	"github.com/shibingli/ydx/errs"
)

// QueryRequest is a KMIP Query request payload. | QueryRequest 是 KMIP Query 请求负载。
type QueryRequest struct {
	// QueryFunctions selects the information requested. | QueryFunctions 选择请求的信息。
	QueryFunctions []QueryFunction
}

// Item encodes the Query request payload. | Item 编码 Query 请求负载。
func (p QueryRequest) Item() (Item, error) {
	children := make([]Item, 0, len(p.QueryFunctions))
	for _, fn := range p.QueryFunctions {
		if fn == 0 {
			return Item{}, errs.Detail(ErrInvalidRequest, "Query request has an empty query function | Query 请求包含空查询功能")
		}
		children = append(children, NewEnumeration(TagQueryFunction, uint32(fn)))
	}
	return payloadItem(TagRequestPayload, children...), nil
}

// DecodeQueryRequest decodes a Query request payload. | DecodeQueryRequest 解码 Query 请求负载。
func DecodeQueryRequest(item Item) (QueryRequest, error) {
	if item.Type != TypeStructure {
		return QueryRequest{}, errs.Detail(ErrMalformed, "Query request payload is not a structure | Query 请求负载不是结构")
	}
	var out QueryRequest
	for _, child := range item.Children {
		if child.Tag != TagQueryFunction {
			continue
		}
		v, err := child.AsEnumeration()
		if err != nil {
			return out, err
		}
		out.QueryFunctions = append(out.QueryFunctions, QueryFunction(v))
	}
	return out, nil
}

// QueryResponse is a KMIP Query response payload. | QueryResponse 是 KMIP Query 响应负载。
type QueryResponse struct {
	// Operations lists supported operations. | Operations 列出支持的操作。
	Operations []Operation
	// ObjectTypes lists supported object types. | ObjectTypes 列出支持的对象类型。
	ObjectTypes []ObjectType
	// VendorIdentification is the server vendor identifier. | VendorIdentification 是服务器厂商标识。
	VendorIdentification string
	// ServerInformation is an optional raw Server Information structure. | ServerInformation 是可选原始服务器信息结构。
	ServerInformation Item
	// ApplicationNamespaces lists supported application namespaces. | ApplicationNamespaces 列出支持的应用命名空间。
	ApplicationNamespaces []string
}

// Item encodes the Query response payload. | Item 编码 Query 响应负载。
func (p QueryResponse) Item() (Item, error) {
	children := make([]Item, 0, len(p.Operations)+len(p.ObjectTypes)+4)
	for _, op := range p.Operations {
		children = append(children, NewEnumeration(TagOperation, uint32(op)))
	}
	for _, typ := range p.ObjectTypes {
		children = append(children, NewEnumeration(TagObjectType, uint32(typ)))
	}
	children = appendText(children, TagVendorIdentification, p.VendorIdentification)
	if p.ServerInformation.Type != 0 {
		if p.ServerInformation.Type != TypeStructure || p.ServerInformation.Tag != TagServerInformation {
			return Item{}, errs.Detail(ErrInvalidRequest, "server information is not a Server Information structure | 服务器信息不是 Server Information 结构")
		}
		children = append(children, p.ServerInformation)
	}
	for _, ns := range p.ApplicationNamespaces {
		children = append(children, NewTextString(TagApplicationNamespace, ns))
	}
	return payloadItem(TagResponsePayload, children...), nil
}

// DecodeQueryResponse decodes a Query response payload. | DecodeQueryResponse 解码 Query 响应负载。
func DecodeQueryResponse(item Item) (QueryResponse, error) {
	if item.Type != TypeStructure {
		return QueryResponse{}, errs.Detail(ErrMalformed, "Query response payload is not a structure | Query 响应负载不是结构")
	}
	var out QueryResponse
	for _, child := range item.Children {
		switch child.Tag {
		case TagOperation:
			v, err := child.AsEnumeration()
			if err != nil {
				return out, err
			}
			out.Operations = append(out.Operations, Operation(v))
		case TagObjectType:
			v, err := child.AsEnumeration()
			if err != nil {
				return out, err
			}
			out.ObjectTypes = append(out.ObjectTypes, ObjectType(v))
		case TagVendorIdentification:
			v, err := child.AsTextString()
			if err != nil {
				return out, err
			}
			out.VendorIdentification = v
		case TagServerInformation:
			out.ServerInformation = child
		case TagApplicationNamespace:
			v, err := child.AsTextString()
			if err != nil {
				return out, err
			}
			out.ApplicationNamespaces = append(out.ApplicationNamespaces, v)
		}
	}
	return out, nil
}

// DiscoverVersionsRequest is a KMIP Discover Versions request payload. | DiscoverVersionsRequest 是 KMIP Discover Versions 请求负载。
type DiscoverVersionsRequest struct {
	// ProtocolVersions optionally lists the client-supported versions. | ProtocolVersions 可选列出客户端支持的版本。
	ProtocolVersions []ProtocolVersion
}

// Item encodes the Discover Versions request payload. | Item 编码 Discover Versions 请求负载。
func (p DiscoverVersionsRequest) Item() (Item, error) {
	children := make([]Item, 0, len(p.ProtocolVersions))
	for _, v := range p.ProtocolVersions {
		if !v.Valid() {
			return Item{}, errs.Detail(ErrInvalidRequest, "invalid protocol version %s | 协议版本 %s 非法", v, v)
		}
		children = append(children, protocolVersionItem(v))
	}
	return payloadItem(TagRequestPayload, children...), nil
}

// DecodeDiscoverVersionsRequest decodes a Discover Versions request payload. | DecodeDiscoverVersionsRequest 解码 Discover Versions 请求负载。
func DecodeDiscoverVersionsRequest(item Item) (DiscoverVersionsRequest, error) {
	if item.Type != TypeStructure {
		return DiscoverVersionsRequest{}, errs.Detail(ErrMalformed, "Discover Versions request payload is not a structure | Discover Versions 请求负载不是结构")
	}
	var out DiscoverVersionsRequest
	for _, child := range item.Children {
		if child.Tag != TagProtocolVersion {
			continue
		}
		v, err := decodeProtocolVersion(child)
		if err != nil {
			return out, err
		}
		out.ProtocolVersions = append(out.ProtocolVersions, v)
	}
	return out, nil
}

// DiscoverVersionsResponse is a KMIP Discover Versions response payload. | DiscoverVersionsResponse 是 KMIP Discover Versions 响应负载。
type DiscoverVersionsResponse struct {
	// ProtocolVersions lists the versions supported by both peers. | ProtocolVersions 列出双方都支持的版本。
	ProtocolVersions []ProtocolVersion
}

// Item encodes the Discover Versions response payload. | Item 编码 Discover Versions 响应负载。
func (p DiscoverVersionsResponse) Item() (Item, error) {
	children := make([]Item, 0, len(p.ProtocolVersions))
	for _, v := range p.ProtocolVersions {
		if !v.Valid() {
			return Item{}, errs.Detail(ErrInvalidRequest, "invalid protocol version %s | 协议版本 %s 非法", v, v)
		}
		children = append(children, protocolVersionItem(v))
	}
	return payloadItem(TagResponsePayload, children...), nil
}

// DecodeDiscoverVersionsResponse decodes a Discover Versions response payload. | DecodeDiscoverVersionsResponse 解码 Discover Versions 响应负载。
func DecodeDiscoverVersionsResponse(item Item) (DiscoverVersionsResponse, error) {
	if item.Type != TypeStructure {
		return DiscoverVersionsResponse{}, errs.Detail(ErrMalformed, "Discover Versions response payload is not a structure | Discover Versions 响应负载不是结构")
	}
	var out DiscoverVersionsResponse
	for _, child := range item.Children {
		if child.Tag != TagProtocolVersion {
			continue
		}
		v, err := decodeProtocolVersion(child)
		if err != nil {
			return out, err
		}
		out.ProtocolVersions = append(out.ProtocolVersions, v)
	}
	return out, nil
}

// CheckRequest is a KMIP Check request payload. | CheckRequest 是 KMIP Check 请求负载。
type CheckRequest struct {
	// UniqueIdentifier identifies the object. | UniqueIdentifier 标识对象。
	UniqueIdentifier string
	// UsageLimitsCount is the expected remaining usage count. | UsageLimitsCount 是预期剩余使用次数。
	UsageLimitsCount *int64
	// CryptographicUsageMask is the requested usage mask. | CryptographicUsageMask 是请求的用法掩码。
	CryptographicUsageMask CryptographicUsageMask
	// LeaseTime is the requested lease time. | LeaseTime 是请求的租用时间。
	LeaseTime *time.Duration
}

// Item encodes the Check request payload. | Item 编码 Check 请求负载。
func (p CheckRequest) Item() (Item, error) {
	children := appendText(nil, TagUniqueIdentifier, p.UniqueIdentifier)
	if p.UsageLimitsCount != nil {
		if *p.UsageLimitsCount < 0 {
			return Item{}, errs.Detail(ErrInvalidRequest, "negative usage limits count | 使用限制计数为负")
		}
		children = append(children, NewInteger(TagUsageLimitsCount, *p.UsageLimitsCount))
	}
	children = appendInteger(children, TagCryptographicUsageMask, int64(p.CryptographicUsageMask))
	if p.LeaseTime != nil {
		children = appendInterval(children, TagLeaseTime, *p.LeaseTime)
	}
	return payloadItem(TagRequestPayload, children...), nil
}

// DecodeCheckRequest decodes a Check request payload. | DecodeCheckRequest 解码 Check 请求负载。
func DecodeCheckRequest(item Item) (CheckRequest, error) {
	if item.Type != TypeStructure {
		return CheckRequest{}, errs.Detail(ErrMalformed, "Check request payload is not a structure | Check 请求负载不是结构")
	}
	var out CheckRequest
	var err error
	out.UniqueIdentifier, err = childText(item, TagUniqueIdentifier)
	if err != nil {
		return out, err
	}
	count, ok, err := childInteger(item, TagUsageLimitsCount)
	if err != nil {
		return out, err
	}
	if ok {
		out.UsageLimitsCount = &count
	}
	mask, _, err := childInteger(item, TagCryptographicUsageMask)
	if err != nil {
		return out, err
	}
	out.CryptographicUsageMask = CryptographicUsageMask(uint32(mask))
	out.LeaseTime, err = decodeIntervalPtr(item, TagLeaseTime)
	if err != nil {
		return out, err
	}
	return out, nil
}

// CheckResponse is a KMIP Check response payload. | CheckResponse 是 KMIP Check 响应负载。
type CheckResponse struct {
	// UniqueIdentifier is the checked object identifier. | UniqueIdentifier 是已检查对象标识符。
	UniqueIdentifier string
	// UsageLimitsCount is the remaining usage count. | UsageLimitsCount 是剩余使用次数。
	UsageLimitsCount *int64
	// CryptographicUsageMask is the object usage mask. | CryptographicUsageMask 是对象用法掩码。
	CryptographicUsageMask CryptographicUsageMask
	// LeaseTime is the granted lease time. | LeaseTime 是授予的租用时间。
	LeaseTime *time.Duration
}

// Item encodes the Check response payload. | Item 编码 Check 响应负载。
func (p CheckResponse) Item() (Item, error) {
	children := appendText(nil, TagUniqueIdentifier, p.UniqueIdentifier)
	if p.UsageLimitsCount != nil {
		children = append(children, NewInteger(TagUsageLimitsCount, *p.UsageLimitsCount))
	}
	children = appendInteger(children, TagCryptographicUsageMask, int64(p.CryptographicUsageMask))
	if p.LeaseTime != nil {
		children = appendInterval(children, TagLeaseTime, *p.LeaseTime)
	}
	return payloadItem(TagResponsePayload, children...), nil
}

// DecodeCheckResponse decodes a Check response payload. | DecodeCheckResponse 解码 Check 响应负载。
func DecodeCheckResponse(item Item) (CheckResponse, error) {
	if item.Type != TypeStructure {
		return CheckResponse{}, errs.Detail(ErrMalformed, "Check response payload is not a structure | Check 响应负载不是结构")
	}
	var out CheckResponse
	var err error
	out.UniqueIdentifier, err = childText(item, TagUniqueIdentifier)
	if err != nil {
		return out, err
	}
	count, ok, err := childInteger(item, TagUsageLimitsCount)
	if err != nil {
		return out, err
	}
	if ok {
		out.UsageLimitsCount = &count
	}
	mask, _, err := childInteger(item, TagCryptographicUsageMask)
	if err != nil {
		return out, err
	}
	out.CryptographicUsageMask = CryptographicUsageMask(uint32(mask))
	out.LeaseTime, err = decodeIntervalPtr(item, TagLeaseTime)
	if err != nil {
		return out, err
	}
	return out, nil
}
