package kmip

import "github.com/shibingli/ydx/errs"

// ExportRequest is a KMIP 1.4 Export request payload. | ExportRequest 是 KMIP 1.4 Export 请求负载。
//
// Export was removed in KMIP 2.0; servers reject this payload for 2.0 requests and clients should use Get instead. |
// KMIP 2.0 已移除 Export；服务器会拒绝 2.0 请求中的该负载，客户端应改用 Get。
type ExportRequest struct {
	// UniqueIdentifier identifies the object to export. | UniqueIdentifier 标识要导出的对象。
	UniqueIdentifier string
	// KeyFormatType optionally requests a specific key format. | KeyFormatType 可选请求特定密钥格式。
	KeyFormatType KeyFormatType
}

// Item encodes the Export request payload. | Item 编码 Export 请求负载。
func (p ExportRequest) Item() (Item, error) {
	if p.UniqueIdentifier == "" {
		return Item{}, errs.Detail(ErrInvalidRequest, "Export request has no Unique Identifier | Export 请求没有唯一标识符")
	}
	children := []Item{NewTextString(TagUniqueIdentifier, p.UniqueIdentifier)}
	children = appendEnum(children, TagKeyFormatType, uint32(p.KeyFormatType))
	return payloadItem(TagRequestPayload, children...), nil
}

// DecodeExportRequest decodes an Export request payload. | DecodeExportRequest 解码 Export 请求负载。
func DecodeExportRequest(item Item) (ExportRequest, error) {
	if item.Type != TypeStructure {
		return ExportRequest{}, errs.Detail(ErrMalformed, "Export request payload is not a structure | Export 请求负载不是结构")
	}
	var out ExportRequest
	var err error
	out.UniqueIdentifier, err = childText(item, TagUniqueIdentifier)
	if err != nil {
		return out, err
	}
	format, err := childEnumeration(item, TagKeyFormatType)
	if err != nil {
		return out, err
	}
	out.KeyFormatType = KeyFormatType(format)
	return out, nil
}

// ExportResponse is a KMIP 1.4 Export response payload. | ExportResponse 是 KMIP 1.4 Export 响应负载。
//
// KeyMaterial carries the encoded key in KeyFormatType. Encoded formats such as Raw, PKCS#8 or X.509 use the key
// bytes directly; transparent formats use the TTLV encoding of their structure. | KeyMaterial 以 KeyFormatType
// 携带编码后的密钥。Raw、PKCS#8 或 X.509 等编码格式直接使用密钥字节；透明格式使用其结构的 TTLV 编码。
type ExportResponse struct {
	// ObjectType is the exported object type. | ObjectType 是导出的对象类型。
	ObjectType ObjectType
	// UniqueIdentifier is the exported object identifier. | UniqueIdentifier 是导出对象标识符。
	UniqueIdentifier string
	// KeyFormatType is the format of KeyMaterial. | KeyFormatType 是 KeyMaterial 的格式。
	KeyFormatType KeyFormatType
	// KeyCompressionType optionally describes EC point compression. | KeyCompressionType 可选描述 EC 点压缩。
	KeyCompressionType KeyCompressionType
	// KeyMaterial is the encoded key material. | KeyMaterial 是编码后的密钥材料。
	KeyMaterial []byte
}

// Item encodes the Export response payload. | Item 编码 Export 响应负载。
func (p ExportResponse) Item() (Item, error) {
	if p.ObjectType == 0 {
		return Item{}, errs.Detail(ErrInvalidRequest, "Export response has no Object Type | Export 响应没有对象类型")
	}
	if p.UniqueIdentifier == "" {
		return Item{}, errs.Detail(ErrInvalidRequest, "Export response has no Unique Identifier | Export 响应没有唯一标识符")
	}
	if p.KeyFormatType == 0 {
		return Item{}, errs.Detail(ErrInvalidRequest, "Export response has no Key Format Type | Export 响应没有密钥格式类型")
	}
	children := []Item{
		NewEnumeration(TagObjectType, uint32(p.ObjectType)),
		NewTextString(TagUniqueIdentifier, p.UniqueIdentifier),
		NewEnumeration(TagKeyFormatType, uint32(p.KeyFormatType)),
	}
	children = appendEnum(children, TagKeyCompressionType, uint32(p.KeyCompressionType))
	children = append(children, NewByteString(TagKeyMaterial, p.KeyMaterial))
	return payloadItem(TagResponsePayload, children...), nil
}

// DecodeExportResponse decodes an Export response payload. | DecodeExportResponse 解码 Export 响应负载。
func DecodeExportResponse(item Item) (ExportResponse, error) {
	if item.Type != TypeStructure {
		return ExportResponse{}, errs.Detail(ErrMalformed, "Export response payload is not a structure | Export 响应负载不是结构")
	}
	var out ExportResponse
	var err error
	out.ObjectType, err = decodeObjectTypeChild(item, true)
	if err != nil {
		return out, err
	}
	out.UniqueIdentifier, err = childText(item, TagUniqueIdentifier)
	if err != nil {
		return out, err
	}
	if out.UniqueIdentifier == "" {
		return out, errs.Detail(ErrMalformed, "Export response has no Unique Identifier | Export 响应没有唯一标识符")
	}
	format, err := childEnumeration(item, TagKeyFormatType)
	if err != nil {
		return out, err
	}
	out.KeyFormatType = KeyFormatType(format)
	if out.KeyFormatType == 0 {
		return out, errs.Detail(ErrMalformed, "Export response has no Key Format Type | Export 响应没有密钥格式类型")
	}
	compression, err := childEnumeration(item, TagKeyCompressionType)
	if err != nil {
		return out, err
	}
	out.KeyCompressionType = KeyCompressionType(compression)
	out.KeyMaterial, err = childBytes(item, TagKeyMaterial)
	if err != nil {
		return out, err
	}
	if len(out.KeyMaterial) == 0 {
		return out, errs.Detail(ErrMalformed, "Export response has no Key Material | Export 响应没有密钥材料")
	}
	return out, nil
}
