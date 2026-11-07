package kmip

import (
	"time"

	"github.com/shibingli/ydx/errs"
)

// CreateRequest is a KMIP Create request payload. | CreateRequest 是 KMIP Create 请求负载。
type CreateRequest struct {
	// ObjectType is the type of object to create. | ObjectType 是要创建的对象类型。
	ObjectType ObjectType
	// TemplateAttribute carries the requested attributes. | TemplateAttribute 携带请求的属性。
	TemplateAttribute TemplateAttribute
}

// Item encodes the Create request payload. | Item 编码 Create 请求负载。
func (p CreateRequest) Item() (Item, error) {
	if p.ObjectType == 0 {
		return Item{}, errs.Detail(ErrInvalidRequest, "Create request has no object type | Create 请求没有对象类型")
	}
	tmpl, err := p.TemplateAttribute.Item()
	if err != nil {
		return Item{}, err
	}
	return payloadItem(TagRequestPayload,
		NewEnumeration(TagObjectType, uint32(p.ObjectType)),
		tmpl,
	), nil
}

// DecodeCreateRequest decodes a Create request payload. | DecodeCreateRequest 解码 Create 请求负载。
func DecodeCreateRequest(item Item) (CreateRequest, error) {
	if item.Type != TypeStructure {
		return CreateRequest{}, errs.Detail(ErrMalformed, "Create request payload is not a structure | Create 请求负载不是结构")
	}
	var out CreateRequest
	for _, child := range item.Children {
		switch child.Tag {
		case TagObjectType:
			v, err := child.AsEnumeration()
			if err != nil {
				return out, err
			}
			out.ObjectType = ObjectType(v)
		case TagTemplateAttribute:
			v, err := DecodeTemplateAttribute(child)
			if err != nil {
				return out, err
			}
			out.TemplateAttribute = v
		default:
			return out, errs.Detail(ErrMalformed, "unexpected tag 0x%06X in Create request | Create 请求中出现意外标签 0x%06X", uint32(child.Tag), uint32(child.Tag))
		}
	}
	if out.ObjectType == 0 {
		return out, errs.Detail(ErrMalformed, "Create request has no Object Type | Create 请求没有对象类型")
	}
	return out, nil
}

// CreateResponse is a KMIP Create response payload. | CreateResponse 是 KMIP Create 响应负载。
type CreateResponse struct {
	// ObjectType is the created object type. | ObjectType 是已创建对象类型。
	ObjectType ObjectType
	// UniqueIdentifier is the created object identifier. | UniqueIdentifier 是已创建对象标识符。
	UniqueIdentifier string
	// TemplateAttribute carries attributes implicitly set by the server. | TemplateAttribute 携带服务器隐式设置的属性。
	TemplateAttribute *TemplateAttribute
}

// Item encodes the Create response payload. | Item 编码 Create 响应负载。
func (p CreateResponse) Item() (Item, error) {
	children := []Item{
		NewEnumeration(TagObjectType, uint32(p.ObjectType)),
		NewTextString(TagUniqueIdentifier, p.UniqueIdentifier),
	}
	children, err := templateAttributeChildren(children, TagTemplateAttribute, p.TemplateAttribute)
	if err != nil {
		return Item{}, err
	}
	return payloadItem(TagResponsePayload, children...), nil
}

// DecodeCreateResponse decodes a Create response payload. | DecodeCreateResponse 解码 Create 响应负载。
func DecodeCreateResponse(item Item) (CreateResponse, error) {
	if item.Type != TypeStructure {
		return CreateResponse{}, errs.Detail(ErrMalformed, "Create response payload is not a structure | Create 响应负载不是结构")
	}
	var out CreateResponse
	var err error
	out.ObjectType, err = decodeObjectTypeChild(item, true)
	if err != nil {
		return out, err
	}
	out.UniqueIdentifier, err = childText(item, TagUniqueIdentifier)
	if err != nil {
		return out, err
	}
	out.TemplateAttribute, err = optionalTemplateAttribute(item, TagTemplateAttribute)
	if err != nil {
		return out, err
	}
	if out.UniqueIdentifier == "" {
		return out, errs.Detail(ErrMalformed, "Create response has no Unique Identifier | Create 响应没有唯一标识符")
	}
	return out, nil
}

// CreateKeyPairRequest is a KMIP Create Key Pair request payload. | CreateKeyPairRequest 是 KMIP Create Key Pair 请求负载。
type CreateKeyPairRequest struct {
	// CommonTemplateAttribute applies to both keys. | CommonTemplateAttribute 应用于两个密钥。
	CommonTemplateAttribute *TemplateAttribute
	// PrivateKeyTemplateAttribute applies to the private key. | PrivateKeyTemplateAttribute 应用于私钥。
	PrivateKeyTemplateAttribute *TemplateAttribute
	// PublicKeyTemplateAttribute applies to the public key. | PublicKeyTemplateAttribute 应用于公钥。
	PublicKeyTemplateAttribute *TemplateAttribute
}

// Item encodes the Create Key Pair request payload. | Item 编码 Create Key Pair 请求负载。
func (p CreateKeyPairRequest) Item() (Item, error) {
	children, err := templateAttributeChildren(nil, TagCommonTemplateAttribute, p.CommonTemplateAttribute)
	if err != nil {
		return Item{}, err
	}
	children, err = templateAttributeChildren(children, TagPrivateKeyTemplateAttribute, p.PrivateKeyTemplateAttribute)
	if err != nil {
		return Item{}, err
	}
	children, err = templateAttributeChildren(children, TagPublicKeyTemplateAttribute, p.PublicKeyTemplateAttribute)
	if err != nil {
		return Item{}, err
	}
	return payloadItem(TagRequestPayload, children...), nil
}

// DecodeCreateKeyPairRequest decodes a Create Key Pair request payload. | DecodeCreateKeyPairRequest 解码 Create Key Pair 请求负载。
func DecodeCreateKeyPairRequest(item Item) (CreateKeyPairRequest, error) {
	if item.Type != TypeStructure {
		return CreateKeyPairRequest{}, errs.Detail(ErrMalformed, "Create Key Pair request payload is not a structure | Create Key Pair 请求负载不是结构")
	}
	var out CreateKeyPairRequest
	var err error
	out.CommonTemplateAttribute, err = optionalTemplateAttribute(item, TagCommonTemplateAttribute)
	if err != nil {
		return out, err
	}
	out.PrivateKeyTemplateAttribute, err = optionalTemplateAttribute(item, TagPrivateKeyTemplateAttribute)
	if err != nil {
		return out, err
	}
	out.PublicKeyTemplateAttribute, err = optionalTemplateAttribute(item, TagPublicKeyTemplateAttribute)
	if err != nil {
		return out, err
	}
	return out, nil
}

// CreateKeyPairResponse is a KMIP Create Key Pair response payload. | CreateKeyPairResponse 是 KMIP Create Key Pair 响应负载。
type CreateKeyPairResponse struct {
	// PrivateKeyUniqueIdentifier is the private key identifier. | PrivateKeyUniqueIdentifier 是私钥标识符。
	PrivateKeyUniqueIdentifier string
	// PublicKeyUniqueIdentifier is the public key identifier. | PublicKeyUniqueIdentifier 是公钥标识符。
	PublicKeyUniqueIdentifier string
	// PrivateKeyTemplateAttribute carries implicit private key attributes. | PrivateKeyTemplateAttribute 携带隐式私钥属性。
	PrivateKeyTemplateAttribute *TemplateAttribute
	// PublicKeyTemplateAttribute carries implicit public key attributes. | PublicKeyTemplateAttribute 携带隐式公钥属性。
	PublicKeyTemplateAttribute *TemplateAttribute
}

// Item encodes the Create Key Pair response payload. | Item 编码 Create Key Pair 响应负载。
func (p CreateKeyPairResponse) Item() (Item, error) {
	children := []Item{
		NewTextString(TagPrivateKeyUniqueIdentifier, p.PrivateKeyUniqueIdentifier),
		NewTextString(TagPublicKeyUniqueIdentifier, p.PublicKeyUniqueIdentifier),
	}
	children, err := templateAttributeChildren(children, TagPrivateKeyTemplateAttribute, p.PrivateKeyTemplateAttribute)
	if err != nil {
		return Item{}, err
	}
	children, err = templateAttributeChildren(children, TagPublicKeyTemplateAttribute, p.PublicKeyTemplateAttribute)
	if err != nil {
		return Item{}, err
	}
	return payloadItem(TagResponsePayload, children...), nil
}

// DecodeCreateKeyPairResponse decodes a Create Key Pair response payload. | DecodeCreateKeyPairResponse 解码 Create Key Pair 响应负载。
func DecodeCreateKeyPairResponse(item Item) (CreateKeyPairResponse, error) {
	if item.Type != TypeStructure {
		return CreateKeyPairResponse{}, errs.Detail(ErrMalformed, "Create Key Pair response payload is not a structure | Create Key Pair 响应负载不是结构")
	}
	var out CreateKeyPairResponse
	var err error
	out.PrivateKeyUniqueIdentifier, err = childText(item, TagPrivateKeyUniqueIdentifier)
	if err != nil {
		return out, err
	}
	out.PublicKeyUniqueIdentifier, err = childText(item, TagPublicKeyUniqueIdentifier)
	if err != nil {
		return out, err
	}
	out.PrivateKeyTemplateAttribute, err = optionalTemplateAttribute(item, TagPrivateKeyTemplateAttribute)
	if err != nil {
		return out, err
	}
	out.PublicKeyTemplateAttribute, err = optionalTemplateAttribute(item, TagPublicKeyTemplateAttribute)
	if err != nil {
		return out, err
	}
	if out.PrivateKeyUniqueIdentifier == "" || out.PublicKeyUniqueIdentifier == "" {
		return out, errs.Detail(ErrMalformed, "Create Key Pair response has no key identifier | Create Key Pair 响应缺少密钥标识符")
	}
	return out, nil
}

// RegisterRequest is a KMIP Register request payload. | RegisterRequest 是 KMIP Register 请求负载。
type RegisterRequest struct {
	// ObjectType is the registered object type. | ObjectType 是注册的对象类型。
	ObjectType ObjectType
	// TemplateAttribute carries the requested attributes. | TemplateAttribute 携带请求的属性。
	TemplateAttribute TemplateAttribute
	// Object is the managed object to register. | Object 是要注册的受管对象。
	Object Object
}

// Item encodes the Register request payload. | Item 编码 Register 请求负载。
func (p RegisterRequest) Item() (Item, error) {
	if p.ObjectType == 0 {
		return Item{}, errs.Detail(ErrInvalidRequest, "Register request has no object type | Register 请求没有对象类型")
	}
	tmpl, err := p.TemplateAttribute.Item()
	if err != nil {
		return Item{}, err
	}
	object, err := p.Object.Item()
	if err != nil {
		return Item{}, err
	}
	return payloadItem(TagRequestPayload,
		NewEnumeration(TagObjectType, uint32(p.ObjectType)),
		tmpl,
		object,
	), nil
}

// DecodeRegisterRequest decodes a Register request payload. | DecodeRegisterRequest 解码 Register 请求负载。
func DecodeRegisterRequest(item Item) (RegisterRequest, error) {
	if item.Type != TypeStructure {
		return RegisterRequest{}, errs.Detail(ErrMalformed, "Register request payload is not a structure | Register 请求负载不是结构")
	}
	var out RegisterRequest
	for _, child := range item.Children {
		switch child.Tag {
		case TagObjectType:
			v, err := child.AsEnumeration()
			if err != nil {
				return out, err
			}
			out.ObjectType = ObjectType(v)
		case TagTemplateAttribute:
			v, err := DecodeTemplateAttribute(child)
			if err != nil {
				return out, err
			}
			out.TemplateAttribute = v
		case TagSymmetricKey, TagPublicKey, TagPrivateKey, TagSecretData, TagCertificate, TagTemplate, TagOpaqueObject:
			v, err := DecodeObject(child)
			if err != nil {
				return out, err
			}
			out.Object = v
		default:
			return out, errs.Detail(ErrMalformed, "unexpected tag 0x%06X in Register request | Register 请求中出现意外标签 0x%06X", uint32(child.Tag), uint32(child.Tag))
		}
	}
	if out.ObjectType == 0 {
		return out, errs.Detail(ErrMalformed, "Register request has no Object Type | Register 请求没有对象类型")
	}
	if out.Object.Type == 0 {
		return out, errs.Detail(ErrMalformed, "Register request has no Object | Register 请求没有对象")
	}
	if out.Object.Type != out.ObjectType {
		return out, errs.Detail(ErrInvalidRequest, "Register object type %s does not match %s | Register 对象类型 %s 与 %s 不一致", out.Object.Type, out.ObjectType, out.Object.Type, out.ObjectType)
	}
	return out, nil
}

// RegisterResponse is a KMIP Register response payload. | RegisterResponse 是 KMIP Register 响应负载。
type RegisterResponse struct {
	// UniqueIdentifier is the registered object identifier. | UniqueIdentifier 是已注册对象标识符。
	UniqueIdentifier string
	// TemplateAttribute carries attributes implicitly set by the server. | TemplateAttribute 携带服务器隐式设置的属性。
	TemplateAttribute *TemplateAttribute
}

// Item encodes the Register response payload. | Item 编码 Register 响应负载。
func (p RegisterResponse) Item() (Item, error) {
	children := []Item{NewTextString(TagUniqueIdentifier, p.UniqueIdentifier)}
	children, err := templateAttributeChildren(children, TagTemplateAttribute, p.TemplateAttribute)
	if err != nil {
		return Item{}, err
	}
	return payloadItem(TagResponsePayload, children...), nil
}

// DecodeRegisterResponse decodes a Register response payload. | DecodeRegisterResponse 解码 Register 响应负载。
func DecodeRegisterResponse(item Item) (RegisterResponse, error) {
	if item.Type != TypeStructure {
		return RegisterResponse{}, errs.Detail(ErrMalformed, "Register response payload is not a structure | Register 响应负载不是结构")
	}
	var out RegisterResponse
	var err error
	out.UniqueIdentifier, err = childText(item, TagUniqueIdentifier)
	if err != nil {
		return out, err
	}
	out.TemplateAttribute, err = optionalTemplateAttribute(item, TagTemplateAttribute)
	if err != nil {
		return out, err
	}
	if out.UniqueIdentifier == "" {
		return out, errs.Detail(ErrMalformed, "Register response has no Unique Identifier | Register 响应没有唯一标识符")
	}
	return out, nil
}

// GetRequest is a KMIP Get request payload. | GetRequest 是 KMIP Get 请求负载。
type GetRequest struct {
	// UniqueIdentifier identifies the object; empty uses the server ID placeholder. | UniqueIdentifier 标识对象；留空使用服务器 ID 占位符。
	UniqueIdentifier string
	// KeyFormatType optionally requests a specific key format. | KeyFormatType 可选请求特定密钥格式。
	KeyFormatType KeyFormatType
	// KeyWrapType optionally requests a wrapped or unwrapped key. | KeyWrapType 可选请求已封装或未封装密钥。
	KeyWrapType KeyWrapType
	// KeyCompressionType optionally requests EC point compression. | KeyCompressionType 可选请求 EC 点压缩。
	KeyCompressionType KeyCompressionType
	// KeyWrappingSpecification optionally requests key wrapping. | KeyWrappingSpecification 可选请求密钥封装。
	KeyWrappingSpecification *KeyWrappingSpecification
	// AttributeNames optionally selects attributes to return with the object. | AttributeNames 可选选择随对象返回的属性。
	AttributeNames []string
}

// Item encodes the Get request payload. | Item 编码 Get 请求负载。
func (p GetRequest) Item() (Item, error) {
	children := appendText(nil, TagUniqueIdentifier, p.UniqueIdentifier)
	children = appendEnum(children, TagKeyFormatType, uint32(p.KeyFormatType))
	children = appendEnum(children, TagKeyWrapType, uint32(p.KeyWrapType))
	children = appendEnum(children, TagKeyCompressionType, uint32(p.KeyCompressionType))
	if p.KeyWrappingSpecification != nil {
		item, err := p.KeyWrappingSpecification.Item()
		if err != nil {
			return Item{}, err
		}
		children = append(children, item)
	}
	for _, name := range p.AttributeNames {
		if name == "" {
			return Item{}, errs.Detail(ErrInvalidRequest, "empty attribute name | 属性名为空")
		}
		children = append(children, NewTextString(TagAttributeName, name))
	}
	return payloadItem(TagRequestPayload, children...), nil
}

// DecodeGetRequest decodes a Get request payload. | DecodeGetRequest 解码 Get 请求负载。
func DecodeGetRequest(item Item) (GetRequest, error) {
	if item.Type != TypeStructure {
		return GetRequest{}, errs.Detail(ErrMalformed, "Get request payload is not a structure | Get 请求负载不是结构")
	}
	var out GetRequest
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
	wrapType, err := childEnumeration(item, TagKeyWrapType)
	if err != nil {
		return out, err
	}
	out.KeyWrapType = KeyWrapType(wrapType)
	compression, err := childEnumeration(item, TagKeyCompressionType)
	if err != nil {
		return out, err
	}
	out.KeyCompressionType = KeyCompressionType(compression)
	if spec, ok := item.Child(TagKeyWrappingSpecification); ok {
		v, err := DecodeKeyWrappingSpecification(spec)
		if err != nil {
			return out, err
		}
		out.KeyWrappingSpecification = &v
	}
	for _, child := range item.Children {
		if child.Tag != TagAttributeName {
			continue
		}
		name, err := child.AsTextString()
		if err != nil {
			return out, err
		}
		out.AttributeNames = append(out.AttributeNames, name)
	}
	return out, nil
}

// GetResponse is a KMIP Get response payload. | GetResponse 是 KMIP Get 响应负载。
type GetResponse struct {
	// ObjectType is the returned object type. | ObjectType 是返回的对象类型。
	ObjectType ObjectType
	// UniqueIdentifier is the returned object identifier. | UniqueIdentifier 是返回对象标识符。
	UniqueIdentifier string
	// Object is the returned managed object. | Object 是返回的受管对象。
	Object Object
}

// Item encodes the Get response payload. | Item 编码 Get 响应负载。
func (p GetResponse) Item() (Item, error) {
	object, err := p.Object.Item()
	if err != nil {
		return Item{}, err
	}
	return payloadItem(TagResponsePayload,
		NewEnumeration(TagObjectType, uint32(p.ObjectType)),
		NewTextString(TagUniqueIdentifier, p.UniqueIdentifier),
		object,
	), nil
}

// DecodeGetResponse decodes a Get response payload. | DecodeGetResponse 解码 Get 响应负载。
func DecodeGetResponse(item Item) (GetResponse, error) {
	if item.Type != TypeStructure {
		return GetResponse{}, errs.Detail(ErrMalformed, "Get response payload is not a structure | Get 响应负载不是结构")
	}
	var out GetResponse
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
		return out, errs.Detail(ErrMalformed, "Get response has no Unique Identifier | Get 响应没有唯一标识符")
	}
	for _, child := range item.Children {
		if child.Type != TypeStructure {
			continue
		}
		switch child.Tag {
		case TagSymmetricKey, TagPublicKey, TagPrivateKey, TagSecretData, TagCertificate, TagTemplate, TagOpaqueObject:
			v, err := DecodeObject(child)
			if err != nil {
				return out, err
			}
			out.Object = v
		}
	}
	if out.Object.Type == 0 {
		return out, errs.Detail(ErrMalformed, "Get response has no Object | Get 响应没有对象")
	}
	if out.Object.Type != out.ObjectType {
		return out, errs.Detail(ErrMalformed, "Get object type %s does not match %s | Get 对象类型 %s 与 %s 不一致", out.Object.Type, out.ObjectType, out.Object.Type, out.ObjectType)
	}
	return out, nil
}

// GetAttributesRequest is a KMIP Get Attributes request payload. | GetAttributesRequest 是 KMIP Get Attributes 请求负载。
type GetAttributesRequest struct {
	// UniqueIdentifier identifies the object. | UniqueIdentifier 标识对象。
	UniqueIdentifier string
	// AttributeNames selects attributes; empty selects all. | AttributeNames 选择属性；为空表示全部。
	AttributeNames []string
}

// Item encodes the Get Attributes request payload. | Item 编码 Get Attributes 请求负载。
func (p GetAttributesRequest) Item() (Item, error) {
	children := appendText(nil, TagUniqueIdentifier, p.UniqueIdentifier)
	for _, name := range p.AttributeNames {
		if name == "" {
			return Item{}, errs.Detail(ErrInvalidRequest, "empty attribute name | 属性名为空")
		}
		children = append(children, NewTextString(TagAttributeName, name))
	}
	return payloadItem(TagRequestPayload, children...), nil
}

// DecodeGetAttributesRequest decodes a Get Attributes request payload. | DecodeGetAttributesRequest 解码 Get Attributes 请求负载。
func DecodeGetAttributesRequest(item Item) (GetAttributesRequest, error) {
	if item.Type != TypeStructure {
		return GetAttributesRequest{}, errs.Detail(ErrMalformed, "Get Attributes request payload is not a structure | Get Attributes 请求负载不是结构")
	}
	var out GetAttributesRequest
	var err error
	out.UniqueIdentifier, err = childText(item, TagUniqueIdentifier)
	if err != nil {
		return out, err
	}
	for _, child := range item.Children {
		if child.Tag != TagAttributeName {
			continue
		}
		name, err := child.AsTextString()
		if err != nil {
			return out, err
		}
		out.AttributeNames = append(out.AttributeNames, name)
	}
	return out, nil
}

// GetAttributesResponse is a KMIP Get Attributes response payload. | GetAttributesResponse 是 KMIP Get Attributes 响应负载。
type GetAttributesResponse struct {
	// UniqueIdentifier is the object identifier. | UniqueIdentifier 是对象标识符。
	UniqueIdentifier string
	// Attributes holds the returned attributes. | Attributes 保存返回的属性。
	AttributeList
}

// Item encodes the Get Attributes response payload. | Item 编码 Get Attributes 响应负载。
func (p GetAttributesResponse) Item() (Item, error) {
	children := []Item{NewTextString(TagUniqueIdentifier, p.UniqueIdentifier)}
	for _, attr := range p.AttributeList {
		item, err := attr.Item()
		if err != nil {
			return Item{}, err
		}
		children = append(children, item)
	}
	return payloadItem(TagResponsePayload, children...), nil
}

// DecodeGetAttributesResponse decodes a Get Attributes response payload. | DecodeGetAttributesResponse 解码 Get Attributes 响应负载。
func DecodeGetAttributesResponse(item Item) (GetAttributesResponse, error) {
	if item.Type != TypeStructure {
		return GetAttributesResponse{}, errs.Detail(ErrMalformed, "Get Attributes response payload is not a structure | Get Attributes 响应负载不是结构")
	}
	var out GetAttributesResponse
	var err error
	out.UniqueIdentifier, err = childText(item, TagUniqueIdentifier)
	if err != nil {
		return out, err
	}
	if out.UniqueIdentifier == "" {
		return out, errs.Detail(ErrMalformed, "Get Attributes response has no Unique Identifier | Get Attributes 响应没有唯一标识符")
	}
	for _, child := range item.Children {
		if child.Tag != TagAttribute && child.Tag != TagCustomAttribute {
			continue
		}
		attr, err := DecodeAttribute(child)
		if err != nil {
			return out, err
		}
		out.AttributeList = append(out.AttributeList, attr)
	}
	return out, nil
}

// GetAttributeListRequest is a KMIP Get Attribute List request payload. | GetAttributeListRequest 是 KMIP Get Attribute List 请求负载。
type GetAttributeListRequest struct {
	// UniqueIdentifier identifies the object. | UniqueIdentifier 标识对象。
	UniqueIdentifier string
}

// Item encodes the Get Attribute List request payload. | Item 编码 Get Attribute List 请求负载。
func (p GetAttributeListRequest) Item() (Item, error) {
	return payloadItem(TagRequestPayload, NewTextString(TagUniqueIdentifier, p.UniqueIdentifier)), nil
}

// DecodeGetAttributeListRequest decodes a Get Attribute List request payload. | DecodeGetAttributeListRequest 解码 Get Attribute List 请求负载。
func DecodeGetAttributeListRequest(item Item) (GetAttributeListRequest, error) {
	if item.Type != TypeStructure {
		return GetAttributeListRequest{}, errs.Detail(ErrMalformed, "Get Attribute List request payload is not a structure | Get Attribute List 请求负载不是结构")
	}
	id, err := childText(item, TagUniqueIdentifier)
	if err != nil {
		return GetAttributeListRequest{}, err
	}
	return GetAttributeListRequest{UniqueIdentifier: id}, nil
}

// GetAttributeListResponse is a KMIP Get Attribute List response payload. | GetAttributeListResponse 是 KMIP Get Attribute List 响应负载。
type GetAttributeListResponse struct {
	// UniqueIdentifier is the object identifier. | UniqueIdentifier 是对象标识符。
	UniqueIdentifier string
	// AttributeNames lists the attribute names present on the object. | AttributeNames 列出对象上存在的属性名。
	AttributeNames []string
}

// Item encodes the Get Attribute List response payload. | Item 编码 Get Attribute List 响应负载。
func (p GetAttributeListResponse) Item() (Item, error) {
	children := []Item{NewTextString(TagUniqueIdentifier, p.UniqueIdentifier)}
	for _, name := range p.AttributeNames {
		children = append(children, NewTextString(TagAttributeName, name))
	}
	return payloadItem(TagResponsePayload, children...), nil
}

// DecodeGetAttributeListResponse decodes a Get Attribute List response payload. | DecodeGetAttributeListResponse 解码 Get Attribute List 响应负载。
func DecodeGetAttributeListResponse(item Item) (GetAttributeListResponse, error) {
	if item.Type != TypeStructure {
		return GetAttributeListResponse{}, errs.Detail(ErrMalformed, "Get Attribute List response payload is not a structure | Get Attribute List 响应负载不是结构")
	}
	var out GetAttributeListResponse
	var err error
	out.UniqueIdentifier, err = childText(item, TagUniqueIdentifier)
	if err != nil {
		return out, err
	}
	if out.UniqueIdentifier == "" {
		return out, errs.Detail(ErrMalformed, "Get Attribute List response has no Unique Identifier | Get Attribute List 响应没有唯一标识符")
	}
	for _, child := range item.Children {
		if child.Tag != TagAttributeName {
			continue
		}
		name, err := child.AsTextString()
		if err != nil {
			return out, err
		}
		out.AttributeNames = append(out.AttributeNames, name)
	}
	return out, nil
}

// ActivateRequest is a KMIP Activate request payload. | ActivateRequest 是 KMIP Activate 请求负载。
type ActivateRequest struct {
	// UniqueIdentifier identifies the object to activate. | UniqueIdentifier 标识要激活的对象。
	UniqueIdentifier string
}

// Item encodes the Activate request payload. | Item 编码 Activate 请求负载。
func (p ActivateRequest) Item() (Item, error) {
	return payloadItem(TagRequestPayload, NewTextString(TagUniqueIdentifier, p.UniqueIdentifier)), nil
}

// DecodeActivateRequest decodes an Activate request payload. | DecodeActivateRequest 解码 Activate 请求负载。
func DecodeActivateRequest(item Item) (ActivateRequest, error) {
	if item.Type != TypeStructure {
		return ActivateRequest{}, errs.Detail(ErrMalformed, "Activate request payload is not a structure | Activate 请求负载不是结构")
	}
	id, err := childText(item, TagUniqueIdentifier)
	if err != nil {
		return ActivateRequest{}, err
	}
	return ActivateRequest{UniqueIdentifier: id}, nil
}

// ActivateResponse is a KMIP Activate response payload. | ActivateResponse 是 KMIP Activate 响应负载。
type ActivateResponse struct {
	// UniqueIdentifier is the activated object identifier. | UniqueIdentifier 是已激活对象标识符。
	UniqueIdentifier string
}

// Item encodes the Activate response payload. | Item 编码 Activate 响应负载。
func (p ActivateResponse) Item() (Item, error) {
	return payloadItem(TagResponsePayload, NewTextString(TagUniqueIdentifier, p.UniqueIdentifier)), nil
}

// DecodeActivateResponse decodes an Activate response payload. | DecodeActivateResponse 解码 Activate 响应负载。
func DecodeActivateResponse(item Item) (ActivateResponse, error) {
	if item.Type != TypeStructure {
		return ActivateResponse{}, errs.Detail(ErrMalformed, "Activate response payload is not a structure | Activate 响应负载不是结构")
	}
	id, err := childText(item, TagUniqueIdentifier)
	if err != nil {
		return ActivateResponse{}, err
	}
	if id == "" {
		return ActivateResponse{}, errs.Detail(ErrMalformed, "Activate response has no Unique Identifier | Activate 响应没有唯一标识符")
	}
	return ActivateResponse{UniqueIdentifier: id}, nil
}

// RevokeRequest is a KMIP Revoke request payload. | RevokeRequest 是 KMIP Revoke 请求负载。
type RevokeRequest struct {
	// UniqueIdentifier identifies the object to revoke. | UniqueIdentifier 标识要撤销的对象。
	UniqueIdentifier string
	// Reason is the revocation reason. | Reason 是撤销原因。
	Reason RevocationReason
	// CompromiseOccurrenceDate is required for key compromise. | CompromiseOccurrenceDate 在密钥泄露时必填。
	CompromiseOccurrenceDate time.Time
}

// Item encodes the Revoke request payload. | Item 编码 Revoke 请求负载。
func (p RevokeRequest) Item() (Item, error) {
	reason, err := p.Reason.Item()
	if err != nil {
		return Item{}, err
	}
	children := []Item{
		NewTextString(TagUniqueIdentifier, p.UniqueIdentifier),
		reason,
	}
	if !p.CompromiseOccurrenceDate.IsZero() {
		children = append(children, NewDateTime(TagCompromiseOccurrenceDate, p.CompromiseOccurrenceDate))
	}
	return payloadItem(TagRequestPayload, children...), nil
}

// DecodeRevokeRequest decodes a Revoke request payload. | DecodeRevokeRequest 解码 Revoke 请求负载。
func DecodeRevokeRequest(item Item) (RevokeRequest, error) {
	if item.Type != TypeStructure {
		return RevokeRequest{}, errs.Detail(ErrMalformed, "Revoke request payload is not a structure | Revoke 请求负载不是结构")
	}
	var out RevokeRequest
	var err error
	out.UniqueIdentifier, err = childText(item, TagUniqueIdentifier)
	if err != nil {
		return out, err
	}
	reason, ok := item.Child(TagRevocationReason)
	if !ok {
		return out, errs.Detail(ErrMalformed, "Revoke request has no Revocation Reason | Revoke 请求没有撤销原因")
	}
	out.Reason, err = DecodeRevocationReason(reason)
	if err != nil {
		return out, err
	}
	if dateItem, ok := item.Child(TagCompromiseOccurrenceDate); ok {
		out.CompromiseOccurrenceDate, err = dateItem.AsDateTime()
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

// RevokeResponse is a KMIP Revoke response payload. | RevokeResponse 是 KMIP Revoke 响应负载。
type RevokeResponse struct {
	// UniqueIdentifier is the revoked object identifier. | UniqueIdentifier 是已撤销对象标识符。
	UniqueIdentifier string
}

// Item encodes the Revoke response payload. | Item 编码 Revoke 响应负载。
func (p RevokeResponse) Item() (Item, error) {
	return payloadItem(TagResponsePayload, NewTextString(TagUniqueIdentifier, p.UniqueIdentifier)), nil
}

// DecodeRevokeResponse decodes a Revoke response payload. | DecodeRevokeResponse 解码 Revoke 响应负载。
func DecodeRevokeResponse(item Item) (RevokeResponse, error) {
	if item.Type != TypeStructure {
		return RevokeResponse{}, errs.Detail(ErrMalformed, "Revoke response payload is not a structure | Revoke 响应负载不是结构")
	}
	id, err := childText(item, TagUniqueIdentifier)
	if err != nil {
		return RevokeResponse{}, err
	}
	if id == "" {
		return RevokeResponse{}, errs.Detail(ErrMalformed, "Revoke response has no Unique Identifier | Revoke 响应没有唯一标识符")
	}
	return RevokeResponse{UniqueIdentifier: id}, nil
}

// DestroyRequest is a KMIP Destroy request payload. | DestroyRequest 是 KMIP Destroy 请求负载。
type DestroyRequest struct {
	// UniqueIdentifier identifies the object to destroy. | UniqueIdentifier 标识要销毁的对象。
	UniqueIdentifier string
}

// Item encodes the Destroy request payload. | Item 编码 Destroy 请求负载。
func (p DestroyRequest) Item() (Item, error) {
	return payloadItem(TagRequestPayload, NewTextString(TagUniqueIdentifier, p.UniqueIdentifier)), nil
}

// DecodeDestroyRequest decodes a Destroy request payload. | DecodeDestroyRequest 解码 Destroy 请求负载。
func DecodeDestroyRequest(item Item) (DestroyRequest, error) {
	if item.Type != TypeStructure {
		return DestroyRequest{}, errs.Detail(ErrMalformed, "Destroy request payload is not a structure | Destroy 请求负载不是结构")
	}
	id, err := childText(item, TagUniqueIdentifier)
	if err != nil {
		return DestroyRequest{}, err
	}
	if id == "" {
		return DestroyRequest{}, errs.Detail(ErrMalformed, "Destroy request has no Unique Identifier | Destroy 请求没有唯一标识符")
	}
	return DestroyRequest{UniqueIdentifier: id}, nil
}

// DestroyResponse is a KMIP Destroy response payload. | DestroyResponse 是 KMIP Destroy 响应负载。
type DestroyResponse struct {
	// UniqueIdentifier is the destroyed object identifier. | UniqueIdentifier 是已销毁对象标识符。
	UniqueIdentifier string
}

// Item encodes the Destroy response payload. | Item 编码 Destroy 响应负载。
func (p DestroyResponse) Item() (Item, error) {
	return payloadItem(TagResponsePayload, NewTextString(TagUniqueIdentifier, p.UniqueIdentifier)), nil
}

// DecodeDestroyResponse decodes a Destroy response payload. | DecodeDestroyResponse 解码 Destroy 响应负载。
func DecodeDestroyResponse(item Item) (DestroyResponse, error) {
	id, err := childText(item, TagUniqueIdentifier)
	if err != nil {
		return DestroyResponse{}, err
	}
	if id == "" {
		return DestroyResponse{}, errs.Detail(ErrMalformed, "Destroy response has no Unique Identifier | Destroy 响应没有唯一标识符")
	}
	return DestroyResponse{UniqueIdentifier: id}, nil
}

// LocateRequest is a KMIP Locate request payload. | LocateRequest 是 KMIP Locate 请求负载。
type LocateRequest struct {
	// MaximumItems limits the number of returned identifiers; zero means no limit. | MaximumItems 限制返回标识符数量；零表示不限制。
	MaximumItems int
	// OffsetItems skips the first identifiers. | OffsetItems 跳过前若干个标识符。
	OffsetItems int
	// StorageStatusMask filters by storage status. | StorageStatusMask 按存储状态过滤。
	StorageStatusMask uint32
	// ObjectGroupMember filters by object group membership. | ObjectGroupMember 按对象组成员关系过滤。
	ObjectGroupMember uint32
	// Attributes are the matching criteria. | Attributes 是匹配条件。
	Attributes AttributeList
}

// Item encodes the Locate request payload. | Item 编码 Locate 请求负载。
func (p LocateRequest) Item() (Item, error) {
	children := appendInteger(nil, TagMaximumItems, int64(p.MaximumItems))
	children = appendInteger(children, TagOffsetItems, int64(p.OffsetItems))
	children = appendInteger(children, TagStorageStatusMask, int64(p.StorageStatusMask))
	children = appendEnum(children, TagObjectGroupMember, p.ObjectGroupMember)
	for _, attr := range p.Attributes {
		item, err := attr.Item()
		if err != nil {
			return Item{}, err
		}
		children = append(children, item)
	}
	return payloadItem(TagRequestPayload, children...), nil
}

// DecodeLocateRequest decodes a Locate request payload. | DecodeLocateRequest 解码 Locate 请求负载。
func DecodeLocateRequest(item Item) (LocateRequest, error) {
	if item.Type != TypeStructure {
		return LocateRequest{}, errs.Detail(ErrMalformed, "Locate request payload is not a structure | Locate 请求负载不是结构")
	}
	var out LocateRequest
	var err error
	maxItems, _, err := childInteger(item, TagMaximumItems)
	if err != nil {
		return out, err
	}
	if maxItems < 0 {
		return out, errs.Detail(ErrMalformed, "negative maximum items | 最大项数为负")
	}
	out.MaximumItems = int(maxItems)
	offset, _, err := childInteger(item, TagOffsetItems)
	if err != nil {
		return out, err
	}
	if offset < 0 {
		return out, errs.Detail(ErrMalformed, "negative offset items | 偏移项数为负")
	}
	out.OffsetItems = int(offset)
	storage, _, err := childInteger(item, TagStorageStatusMask)
	if err != nil {
		return out, err
	}
	out.StorageStatusMask = uint32(storage)
	member, err := childEnumeration(item, TagObjectGroupMember)
	if err != nil {
		return out, err
	}
	out.ObjectGroupMember = member
	for _, child := range item.Children {
		if child.Tag != TagAttribute && child.Tag != TagCustomAttribute {
			continue
		}
		attr, err := DecodeAttribute(child)
		if err != nil {
			return out, err
		}
		out.Attributes = append(out.Attributes, attr)
	}
	return out, nil
}

// LocateResponse is a KMIP Locate response payload. | LocateResponse 是 KMIP Locate 响应负载。
type LocateResponse struct {
	// LocatedItems is the total number of matches when reported by the server. | LocatedItems 是服务器报告的总匹配数。
	LocatedItems int
	// HasLocatedItems reports whether LocatedItems was present. | HasLocatedItems 表示 LocatedItems 是否存在。
	HasLocatedItems bool
	// UniqueIdentifiers are the matched object identifiers. | UniqueIdentifiers 是匹配的对象标识符。
	UniqueIdentifiers []string
}

// Item encodes the Locate response payload. | Item 编码 Locate 响应负载。
func (p LocateResponse) Item() (Item, error) {
	var children []Item
	if p.HasLocatedItems {
		children = append(children, NewInteger(TagLocatedItems, int64(p.LocatedItems)))
	}
	for _, id := range p.UniqueIdentifiers {
		children = append(children, NewTextString(TagUniqueIdentifier, id))
	}
	return payloadItem(TagResponsePayload, children...), nil
}

// DecodeLocateResponse decodes a Locate response payload. | DecodeLocateResponse 解码 Locate 响应负载。
func DecodeLocateResponse(item Item) (LocateResponse, error) {
	if item.Type != TypeStructure {
		return LocateResponse{}, errs.Detail(ErrMalformed, "Locate response payload is not a structure | Locate 响应负载不是结构")
	}
	var out LocateResponse
	for _, child := range item.Children {
		switch child.Tag {
		case TagLocatedItems:
			v, err := child.AsInteger()
			if err != nil {
				return out, err
			}
			if v < 0 {
				return out, errs.Detail(ErrMalformed, "negative located items | 已定位项数为负")
			}
			out.LocatedItems = int(v)
			out.HasLocatedItems = true
		case TagUniqueIdentifier:
			id, err := child.AsTextString()
			if err != nil {
				return out, err
			}
			out.UniqueIdentifiers = append(out.UniqueIdentifiers, id)
		}
	}
	return out, nil
}

// DeriveKeyRequest is a KMIP Derive Key request payload. | DeriveKeyRequest 是 KMIP Derive Key 请求负载。
type DeriveKeyRequest struct {
	// ObjectType is the derived object type. | ObjectType 是派生对象类型。
	ObjectType ObjectType
	// UniqueIdentifiers identify the derivation keys. | UniqueIdentifiers 标识派生密钥。
	UniqueIdentifiers []string
	// DerivationMethod is the derivation method. | DerivationMethod 是派生方法。
	DerivationMethod DerivationMethod
	// DerivationParameters holds method parameters. | DerivationParameters 保存方法参数。
	DerivationParameters DerivationParameters
	// TemplateAttribute carries the derived key attributes. | TemplateAttribute 携带派生密钥属性。
	TemplateAttribute TemplateAttribute
}

// Item encodes the Derive Key request payload. | Item 编码 Derive Key 请求负载。
func (p DeriveKeyRequest) Item() (Item, error) {
	if p.ObjectType == 0 {
		return Item{}, errs.Detail(ErrInvalidRequest, "Derive Key request has no object type | Derive Key 请求没有对象类型")
	}
	children := []Item{NewEnumeration(TagObjectType, uint32(p.ObjectType))}
	for _, id := range p.UniqueIdentifiers {
		children = append(children, NewTextString(TagUniqueIdentifier, id))
	}
	children = append(children, NewEnumeration(TagDerivationMethod, uint32(p.DerivationMethod)))
	children = append(children, p.DerivationParameters.Item())
	tmpl, err := p.TemplateAttribute.Item()
	if err != nil {
		return Item{}, err
	}
	children = append(children, tmpl)
	return payloadItem(TagRequestPayload, children...), nil
}

// DecodeDeriveKeyRequest decodes a Derive Key request payload. | DecodeDeriveKeyRequest 解码 Derive Key 请求负载。
func DecodeDeriveKeyRequest(item Item) (DeriveKeyRequest, error) {
	if item.Type != TypeStructure {
		return DeriveKeyRequest{}, errs.Detail(ErrMalformed, "Derive Key request payload is not a structure | Derive Key 请求负载不是结构")
	}
	var out DeriveKeyRequest
	var err error
	out.ObjectType, err = decodeObjectTypeChild(item, true)
	if err != nil {
		return out, err
	}
	for _, child := range item.Children {
		switch child.Tag {
		case TagUniqueIdentifier:
			id, err := child.AsTextString()
			if err != nil {
				return out, err
			}
			out.UniqueIdentifiers = append(out.UniqueIdentifiers, id)
		case TagDerivationMethod:
			v, err := child.AsEnumeration()
			if err != nil {
				return out, err
			}
			out.DerivationMethod = DerivationMethod(v)
		case TagDerivationParameters:
			v, err := DecodeDerivationParameters(child)
			if err != nil {
				return out, err
			}
			out.DerivationParameters = v
		case TagTemplateAttribute:
			v, err := DecodeTemplateAttribute(child)
			if err != nil {
				return out, err
			}
			out.TemplateAttribute = v
		}
	}
	if len(out.UniqueIdentifiers) == 0 {
		return out, errs.Detail(ErrMalformed, "Derive Key request has no Unique Identifier | Derive Key 请求没有唯一标识符")
	}
	return out, nil
}

// DeriveKeyResponse is a KMIP Derive Key response payload. | DeriveKeyResponse 是 KMIP Derive Key 响应负载。
type DeriveKeyResponse struct {
	// UniqueIdentifier is the derived key identifier. | UniqueIdentifier 是派生密钥标识符。
	UniqueIdentifier string
	// TemplateAttribute carries implicit attributes. | TemplateAttribute 携带隐式属性。
	TemplateAttribute *TemplateAttribute
}

// Item encodes the Derive Key response payload. | Item 编码 Derive Key 响应负载。
func (p DeriveKeyResponse) Item() (Item, error) {
	children := []Item{NewTextString(TagUniqueIdentifier, p.UniqueIdentifier)}
	children, err := templateAttributeChildren(children, TagTemplateAttribute, p.TemplateAttribute)
	if err != nil {
		return Item{}, err
	}
	return payloadItem(TagResponsePayload, children...), nil
}

// DecodeDeriveKeyResponse decodes a Derive Key response payload. | DecodeDeriveKeyResponse 解码 Derive Key 响应负载。
func DecodeDeriveKeyResponse(item Item) (DeriveKeyResponse, error) {
	if item.Type != TypeStructure {
		return DeriveKeyResponse{}, errs.Detail(ErrMalformed, "Derive Key response payload is not a structure | Derive Key 响应负载不是结构")
	}
	var out DeriveKeyResponse
	var err error
	out.UniqueIdentifier, err = childText(item, TagUniqueIdentifier)
	if err != nil {
		return out, err
	}
	out.TemplateAttribute, err = optionalTemplateAttribute(item, TagTemplateAttribute)
	if err != nil {
		return out, err
	}
	if out.UniqueIdentifier == "" {
		return out, errs.Detail(ErrMalformed, "Derive Key response has no Unique Identifier | Derive Key 响应没有唯一标识符")
	}
	return out, nil
}

// decodeObjectTypeChild reads a required or optional Object Type child. | decodeObjectTypeChild 读取必需或可选的对象类型子项。
func decodeObjectTypeChild(item Item, required bool) (ObjectType, error) {
	child, ok := item.Child(TagObjectType)
	if !ok {
		if required {
			return 0, errs.Detail(ErrMalformed, "payload has no Object Type | 负载没有对象类型")
		}
		return 0, nil
	}
	v, err := child.AsEnumeration()
	if err != nil {
		return 0, err
	}
	if v == 0 {
		return 0, errs.Detail(ErrMalformed, "payload has invalid Object Type | 负载对象类型非法")
	}
	return ObjectType(v), nil
}
