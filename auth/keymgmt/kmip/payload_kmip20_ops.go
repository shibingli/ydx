package kmip

import "github.com/shibingli/ydx/errs"

// decodeRequiredAttributes decodes a required or optional KMIP 2.0 Attributes child. | decodeRequiredAttributes 解码
// 必需或可选的 KMIP 2.0 Attributes 子项。
func decodeRequiredAttributes(item Item, required bool) (AttributeList, error) {
	child, ok := item.Child(TagAttributes)
	if !ok {
		if required {
			return nil, errs.Detail(ErrMalformed, "KMIP 2.0 payload has no Attributes | KMIP 2.0 负载没有 Attributes")
		}
		return nil, nil
	}
	return decodeAttributes(child)
}

// templateFromAttributes wraps a KMIP 2.0 attribute list so existing server code can consume it. Name values stay in
// the Attributes list because recordFromTemplate recognizes Name attributes directly. | templateFromAttributes 把
// KMIP 2.0 属性列表包装为既有服务器代码可消费的形式。Name 值保留在 Attributes 中，因为 recordFromTemplate 可直接识别
// Name 属性。
func templateFromAttributes(attrs AttributeList) TemplateAttribute {
	return TemplateAttribute{Attributes: attrs}
}

// ItemForVersion encodes the Create request using the payload shape of version. | ItemForVersion 使用 version 的负载形状
// 编码 Create 请求。
func (p CreateRequest) ItemForVersion(version ProtocolVersion) (Item, error) {
	if !usesKMIP20Payloads(version) {
		return p.Item()
	}
	if p.ObjectType == 0 {
		return Item{}, errs.Detail(ErrInvalidRequest, "Create request has no object type | Create 请求没有对象类型")
	}
	attrs, err := attributesItem(TagAttributes, templateAttributeList(p.TemplateAttribute))
	if err != nil {
		return Item{}, err
	}
	return payloadItem(TagRequestPayload,
		NewEnumeration(TagObjectType, uint32(p.ObjectType)),
		attrs,
	), nil
}

// DecodeCreateRequestForVersion decodes a Create request using the payload shape of version. |
// DecodeCreateRequestForVersion 使用 version 的负载形状解码 Create 请求。
func DecodeCreateRequestForVersion(item Item, version ProtocolVersion) (CreateRequest, error) {
	if !usesKMIP20Payloads(version) {
		return DecodeCreateRequest(item)
	}
	if item.Type != TypeStructure {
		return CreateRequest{}, errs.Detail(ErrMalformed, "Create request payload is not a structure | Create 请求负载不是结构")
	}
	var out CreateRequest
	var hasAttributes bool
	for _, child := range item.Children {
		switch child.Tag {
		case TagObjectType:
			v, err := child.AsEnumeration()
			if err != nil {
				return out, err
			}
			out.ObjectType = ObjectType(v)
		case TagAttributes:
			attrs, err := decodeAttributes(child)
			if err != nil {
				return out, err
			}
			out.TemplateAttribute = templateFromAttributes(attrs)
			hasAttributes = true
		case TagTemplateAttribute, TagCommonTemplateAttribute, TagPrivateKeyTemplateAttribute, TagPublicKeyTemplateAttribute:
			return out, kmip20InvalidTag(child.Tag, "Create request")
		default:
			return out, kmip20InvalidTag(child.Tag, "Create request")
		}
	}
	if out.ObjectType == 0 {
		return out, errs.Detail(ErrMalformed, "Create request has no Object Type | Create 请求没有对象类型")
	}
	if !hasAttributes {
		return out, errs.Detail(ErrMalformed, "Create request has no Attributes | Create 请求没有 Attributes")
	}
	return out, nil
}

// ItemForVersion encodes the Create response using the payload shape of version. | ItemForVersion 使用 version 的负载形状
// 编码 Create 响应。
func (p CreateResponse) ItemForVersion(version ProtocolVersion) (Item, error) {
	if !usesKMIP20Payloads(version) {
		return p.Item()
	}
	if p.TemplateAttribute != nil {
		return Item{}, errs.Detail(ErrUnsupported, "KMIP 2.0 Create responses carry no Template-Attribute | KMIP 2.0 Create 响应不携带 Template-Attribute")
	}
	return payloadItem(TagResponsePayload,
		NewEnumeration(TagObjectType, uint32(p.ObjectType)),
		NewTextString(TagUniqueIdentifier, p.UniqueIdentifier),
	), nil
}

// DecodeCreateResponseForVersion decodes a Create response using the payload shape of version. |
// DecodeCreateResponseForVersion 使用 version 的负载形状解码 Create 响应。
func DecodeCreateResponseForVersion(item Item, version ProtocolVersion) (CreateResponse, error) {
	if !usesKMIP20Payloads(version) {
		return DecodeCreateResponse(item)
	}
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
	if out.UniqueIdentifier == "" {
		return out, errs.Detail(ErrMalformed, "Create response has no Unique Identifier | Create 响应没有唯一标识符")
	}
	for _, child := range item.Children {
		if child.Tag == TagObjectType || child.Tag == TagUniqueIdentifier {
			continue
		}
		return out, kmip20InvalidTag(child.Tag, "Create response")
	}
	return out, nil
}

// ItemForVersion encodes the Create Key Pair request using the payload shape of version. | ItemForVersion 使用 version
// 的负载形状编码 Create Key Pair 请求。
func (p CreateKeyPairRequest) ItemForVersion(version ProtocolVersion) (Item, error) {
	if !usesKMIP20Payloads(version) {
		return p.Item()
	}
	children := make([]Item, 0, 3)
	for _, entry := range []struct {
		tag      Tag
		template *TemplateAttribute
	}{
		{TagCommonAttributes, p.CommonTemplateAttribute},
		{TagPrivateKeyAttributes, p.PrivateKeyTemplateAttribute},
		{TagPublicKeyAttributes, p.PublicKeyTemplateAttribute},
	} {
		if entry.template == nil {
			continue
		}
		attrs, err := attributesItem(entry.tag, templateAttributeList(*entry.template))
		if err != nil {
			return Item{}, err
		}
		children = append(children, attrs)
	}
	return payloadItem(TagRequestPayload, children...), nil
}

// DecodeCreateKeyPairRequestForVersion decodes a Create Key Pair request using the payload shape of version. |
// DecodeCreateKeyPairRequestForVersion 使用 version 的负载形状解码 Create Key Pair 请求。
func DecodeCreateKeyPairRequestForVersion(item Item, version ProtocolVersion) (CreateKeyPairRequest, error) {
	if !usesKMIP20Payloads(version) {
		return DecodeCreateKeyPairRequest(item)
	}
	if item.Type != TypeStructure {
		return CreateKeyPairRequest{}, errs.Detail(ErrMalformed, "Create Key Pair request payload is not a structure | Create Key Pair 请求负载不是结构")
	}
	var out CreateKeyPairRequest
	for _, child := range item.Children {
		var target **TemplateAttribute
		switch child.Tag {
		case TagCommonAttributes:
			target = &out.CommonTemplateAttribute
		case TagPrivateKeyAttributes:
			target = &out.PrivateKeyTemplateAttribute
		case TagPublicKeyAttributes:
			target = &out.PublicKeyTemplateAttribute
		case TagCommonTemplateAttribute, TagPrivateKeyTemplateAttribute, TagPublicKeyTemplateAttribute:
			return out, kmip20InvalidTag(child.Tag, "Create Key Pair request")
		default:
			return out, kmip20InvalidTag(child.Tag, "Create Key Pair request")
		}
		attrs, err := decodeAttributes(child)
		if err != nil {
			return out, err
		}
		template := templateFromAttributes(attrs)
		*target = &template
	}
	return out, nil
}

// ItemForVersion encodes the Create Key Pair response using the payload shape of version. | ItemForVersion 使用
// version 的负载形状编码 Create Key Pair 响应。
func (p CreateKeyPairResponse) ItemForVersion(version ProtocolVersion) (Item, error) {
	if !usesKMIP20Payloads(version) {
		return p.Item()
	}
	if p.PrivateKeyTemplateAttribute != nil || p.PublicKeyTemplateAttribute != nil {
		return Item{}, errs.Detail(ErrUnsupported, "KMIP 2.0 Create Key Pair responses carry no Template-Attribute | KMIP 2.0 Create Key Pair 响应不携带 Template-Attribute")
	}
	return payloadItem(TagResponsePayload,
		NewTextString(TagPrivateKeyUniqueIdentifier, p.PrivateKeyUniqueIdentifier),
		NewTextString(TagPublicKeyUniqueIdentifier, p.PublicKeyUniqueIdentifier),
	), nil
}

// DecodeCreateKeyPairResponseForVersion decodes a Create Key Pair response using the payload shape of version. |
// DecodeCreateKeyPairResponseForVersion 使用 version 的负载形状解码 Create Key Pair 响应。
func DecodeCreateKeyPairResponseForVersion(item Item, version ProtocolVersion) (CreateKeyPairResponse, error) {
	if !usesKMIP20Payloads(version) {
		return DecodeCreateKeyPairResponse(item)
	}
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
	if out.PrivateKeyUniqueIdentifier == "" || out.PublicKeyUniqueIdentifier == "" {
		return out, errs.Detail(ErrMalformed, "Create Key Pair response has no key identifier | Create Key Pair 响应缺少密钥标识符")
	}
	for _, child := range item.Children {
		if child.Tag == TagPrivateKeyUniqueIdentifier || child.Tag == TagPublicKeyUniqueIdentifier {
			continue
		}
		return out, kmip20InvalidTag(child.Tag, "Create Key Pair response")
	}
	return out, nil
}

// ItemForVersion encodes the Register request using the payload shape of version. | ItemForVersion 使用 version 的
// 负载形状编码 Register 请求。
func (p RegisterRequest) ItemForVersion(version ProtocolVersion) (Item, error) {
	if !usesKMIP20Payloads(version) {
		return p.Item()
	}
	if p.ObjectType == 0 {
		return Item{}, errs.Detail(ErrInvalidRequest, "Register request has no object type | Register 请求没有对象类型")
	}
	attrs, err := attributesItem(TagAttributes, templateAttributeList(p.TemplateAttribute))
	if err != nil {
		return Item{}, err
	}
	object, err := p.Object.ItemForVersion(version)
	if err != nil {
		return Item{}, err
	}
	return payloadItem(TagRequestPayload,
		NewEnumeration(TagObjectType, uint32(p.ObjectType)),
		attrs,
		object,
	), nil
}

// DecodeRegisterRequestForVersion decodes a Register request using the payload shape of version. |
// DecodeRegisterRequestForVersion 使用 version 的负载形状解码 Register 请求。
func DecodeRegisterRequestForVersion(item Item, version ProtocolVersion) (RegisterRequest, error) {
	if !usesKMIP20Payloads(version) {
		return DecodeRegisterRequest(item)
	}
	if item.Type != TypeStructure {
		return RegisterRequest{}, errs.Detail(ErrMalformed, "Register request payload is not a structure | Register 请求负载不是结构")
	}
	var out RegisterRequest
	var hasAttributes bool
	for _, child := range item.Children {
		switch child.Tag {
		case TagObjectType:
			v, err := child.AsEnumeration()
			if err != nil {
				return out, err
			}
			out.ObjectType = ObjectType(v)
		case TagAttributes:
			attrs, err := decodeAttributes(child)
			if err != nil {
				return out, err
			}
			out.TemplateAttribute = templateFromAttributes(attrs)
			hasAttributes = true
		case TagSymmetricKey, TagPublicKey, TagPrivateKey, TagSecretData, TagCertificate, TagTemplate, TagOpaqueObject:
			v, err := DecodeObjectForVersion(child, version)
			if err != nil {
				return out, err
			}
			out.Object = v
		default:
			return out, kmip20InvalidTag(child.Tag, "Register request")
		}
	}
	if out.ObjectType == 0 {
		return out, errs.Detail(ErrMalformed, "Register request has no Object Type | Register 请求没有对象类型")
	}
	if !hasAttributes {
		return out, errs.Detail(ErrMalformed, "Register request has no Attributes | Register 请求没有 Attributes")
	}
	if out.Object.Type == 0 {
		return out, errs.Detail(ErrMalformed, "Register request has no Object | Register 请求没有对象")
	}
	if out.Object.Type != out.ObjectType {
		return out, errs.Detail(ErrInvalidRequest, "Register object type %s does not match %s | Register 对象类型 %s 与 %s 不一致", out.Object.Type, out.ObjectType, out.Object.Type, out.ObjectType)
	}
	return out, nil
}

// ItemForVersion encodes the Register response using the payload shape of version. | ItemForVersion 使用 version 的
// 负载形状编码 Register 响应。
func (p RegisterResponse) ItemForVersion(version ProtocolVersion) (Item, error) {
	if !usesKMIP20Payloads(version) {
		return p.Item()
	}
	if p.TemplateAttribute != nil {
		return Item{}, errs.Detail(ErrUnsupported, "KMIP 2.0 Register responses carry no Template-Attribute | KMIP 2.0 Register 响应不携带 Template-Attribute")
	}
	return payloadItem(TagResponsePayload, NewTextString(TagUniqueIdentifier, p.UniqueIdentifier)), nil
}

// DecodeRegisterResponseForVersion decodes a Register response using the payload shape of version. |
// DecodeRegisterResponseForVersion 使用 version 的负载形状解码 Register 响应。
func DecodeRegisterResponseForVersion(item Item, version ProtocolVersion) (RegisterResponse, error) {
	if !usesKMIP20Payloads(version) {
		return DecodeRegisterResponse(item)
	}
	if item.Type != TypeStructure {
		return RegisterResponse{}, errs.Detail(ErrMalformed, "Register response payload is not a structure | Register 响应负载不是结构")
	}
	var out RegisterResponse
	var err error
	out.UniqueIdentifier, err = childText(item, TagUniqueIdentifier)
	if err != nil {
		return out, err
	}
	if out.UniqueIdentifier == "" {
		return out, errs.Detail(ErrMalformed, "Register response has no Unique Identifier | Register 响应没有唯一标识符")
	}
	for _, child := range item.Children {
		if child.Tag == TagUniqueIdentifier {
			continue
		}
		return out, kmip20InvalidTag(child.Tag, "Register response")
	}
	return out, nil
}

// ItemForVersion encodes the Get request using the payload shape of version. | ItemForVersion 使用 version 的负载形状
// 编码 Get 请求。
func (p GetRequest) ItemForVersion(version ProtocolVersion) (Item, error) {
	if !usesKMIP20Payloads(version) {
		return p.Item()
	}
	if len(p.AttributeNames) > 0 {
		return Item{}, errs.Detail(ErrUnsupported,
			"KMIP 2.0 Get cannot select attributes; use Get Attributes | KMIP 2.0 Get 不能选择属性；请使用 Get Attributes")
	}
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
	return payloadItem(TagRequestPayload, children...), nil
}

// DecodeGetRequestForVersion decodes a Get request using the payload shape of version. | DecodeGetRequestForVersion
// 使用 version 的负载形状解码 Get 请求。
func DecodeGetRequestForVersion(item Item, version ProtocolVersion) (GetRequest, error) {
	if !usesKMIP20Payloads(version) {
		return DecodeGetRequest(item)
	}
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
		switch child.Tag {
		case TagUniqueIdentifier, TagKeyFormatType, TagKeyWrapType, TagKeyCompressionType, TagKeyWrappingSpecification:
		case TagAttributeName, TagAttributeReference:
			return out, kmip20InvalidTag(child.Tag, "Get request")
		default:
			return out, kmip20InvalidTag(child.Tag, "Get request")
		}
	}
	return out, nil
}

// ItemForVersion encodes the Get response using the payload shape of version. | ItemForVersion 使用 version 的负载形状
// 编码 Get 响应。
func (p GetResponse) ItemForVersion(version ProtocolVersion) (Item, error) {
	if !usesKMIP20Payloads(version) {
		return p.Item()
	}
	object, err := p.Object.ItemForVersion(version)
	if err != nil {
		return Item{}, err
	}
	return payloadItem(TagResponsePayload,
		NewEnumeration(TagObjectType, uint32(p.ObjectType)),
		NewTextString(TagUniqueIdentifier, p.UniqueIdentifier),
		object,
	), nil
}

// DecodeGetResponseForVersion decodes a Get response using the payload shape of version. | DecodeGetResponseForVersion
// 使用 version 的负载形状解码 Get 响应。
func DecodeGetResponseForVersion(item Item, version ProtocolVersion) (GetResponse, error) {
	if !usesKMIP20Payloads(version) {
		return DecodeGetResponse(item)
	}
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
		case TagSymmetricKey, TagPublicKey, TagPrivateKey, TagSecretData, TagCertificate, TagOpaqueObject, TagTemplate:
			v, err := DecodeObjectForVersion(child, version)
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

// ItemForVersion encodes the Get Attributes request using the payload shape of version. | ItemForVersion 使用 version
// 的负载形状编码 Get Attributes 请求。
func (p GetAttributesRequest) ItemForVersion(version ProtocolVersion) (Item, error) {
	if !usesKMIP20Payloads(version) {
		return p.Item()
	}
	if len(p.AttributeNames) == 0 {
		return Item{}, errs.Detail(ErrUnsupported,
			"KMIP 2.0 Get Attributes requires explicit Attribute References | KMIP 2.0 Get Attributes 需要显式 Attribute Reference")
	}
	children := appendText(nil, TagUniqueIdentifier, p.UniqueIdentifier)
	for _, name := range p.AttributeNames {
		ref, err := AttributeReference{Name: name}.Item()
		if err != nil {
			return Item{}, err
		}
		children = append(children, ref)
	}
	return payloadItem(TagRequestPayload, children...), nil
}

// DecodeGetAttributesRequestForVersion decodes a Get Attributes request using the payload shape of version. |
// DecodeGetAttributesRequestForVersion 使用 version 的负载形状解码 Get Attributes 请求。
func DecodeGetAttributesRequestForVersion(item Item, version ProtocolVersion) (GetAttributesRequest, error) {
	if !usesKMIP20Payloads(version) {
		return DecodeGetAttributesRequest(item)
	}
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
		switch child.Tag {
		case TagUniqueIdentifier:
		case TagAttributeReference:
			ref, err := DecodeAttributeReference(child)
			if err != nil {
				return out, err
			}
			if ref.VendorIdentification != "" {
				return out, errs.Detail(ErrUnsupported,
					"vendor Attribute References are not supported | 不支持厂商 Attribute Reference")
			}
			out.AttributeNames = append(out.AttributeNames, ref.Name)
		default:
			return out, kmip20InvalidTag(child.Tag, "Get Attributes request")
		}
	}
	return out, nil
}

// ItemForVersion encodes the Get Attributes response using the payload shape of version. | ItemForVersion 使用 version
// 的负载形状编码 Get Attributes 响应。
func (p GetAttributesResponse) ItemForVersion(version ProtocolVersion) (Item, error) {
	if !usesKMIP20Payloads(version) {
		return p.Item()
	}
	attrs, err := attributesItem(TagAttributes, p.AttributeList)
	if err != nil {
		return Item{}, err
	}
	return payloadItem(TagResponsePayload,
		NewTextString(TagUniqueIdentifier, p.UniqueIdentifier),
		attrs,
	), nil
}

// DecodeGetAttributesResponseForVersion decodes a Get Attributes response using the payload shape of version. |
// DecodeGetAttributesResponseForVersion 使用 version 的负载形状解码 Get Attributes 响应。
func DecodeGetAttributesResponseForVersion(item Item, version ProtocolVersion) (GetAttributesResponse, error) {
	if !usesKMIP20Payloads(version) {
		return DecodeGetAttributesResponse(item)
	}
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
	attrs, err := decodeRequiredAttributes(item, true)
	if err != nil {
		return out, err
	}
	out.AttributeList = attrs
	for _, child := range item.Children {
		switch child.Tag {
		case TagUniqueIdentifier, TagAttributes:
		case TagAttribute, TagCustomAttribute:
			return out, kmip20InvalidTag(child.Tag, "Get Attributes response")
		default:
			return out, kmip20InvalidTag(child.Tag, "Get Attributes response")
		}
	}
	return out, nil
}

// ItemForVersion encodes the Get Attribute List response using the payload shape of version. | ItemForVersion 使用
// version 的负载形状编码 Get Attribute List 响应。
func (p GetAttributeListResponse) ItemForVersion(version ProtocolVersion) (Item, error) {
	if !usesKMIP20Payloads(version) {
		return p.Item()
	}
	children := []Item{NewTextString(TagUniqueIdentifier, p.UniqueIdentifier)}
	for _, name := range p.AttributeNames {
		ref, err := AttributeReference{Name: name}.Item()
		if err != nil {
			return Item{}, err
		}
		children = append(children, ref)
	}
	return payloadItem(TagResponsePayload, children...), nil
}

// DecodeGetAttributeListResponseForVersion decodes a Get Attribute List response using the payload shape of version. |
// DecodeGetAttributeListResponseForVersion 使用 version 的负载形状解码 Get Attribute List 响应。
func DecodeGetAttributeListResponseForVersion(item Item, version ProtocolVersion) (GetAttributeListResponse, error) {
	if !usesKMIP20Payloads(version) {
		return DecodeGetAttributeListResponse(item)
	}
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
		switch child.Tag {
		case TagUniqueIdentifier:
		case TagAttributeReference:
			ref, err := DecodeAttributeReference(child)
			if err != nil {
				return out, err
			}
			if ref.VendorIdentification != "" {
				return out, errs.Detail(ErrUnsupported,
					"vendor Attribute References are not supported | 不支持厂商 Attribute Reference")
			}
			out.AttributeNames = append(out.AttributeNames, ref.Name)
		default:
			return out, kmip20InvalidTag(child.Tag, "Get Attribute List response")
		}
	}
	return out, nil
}

// ItemForVersion encodes the Locate request using the payload shape of version. | ItemForVersion 使用 version 的负载形状
// 编码 Locate 请求。
func (p LocateRequest) ItemForVersion(version ProtocolVersion) (Item, error) {
	if !usesKMIP20Payloads(version) {
		return p.Item()
	}
	children := appendInteger(nil, TagMaximumItems, int64(p.MaximumItems))
	children = appendInteger(children, TagOffsetItems, int64(p.OffsetItems))
	children = appendInteger(children, TagStorageStatusMask, int64(p.StorageStatusMask))
	children = appendEnum(children, TagObjectGroupMember, p.ObjectGroupMember)
	attrs, err := attributesItem(TagAttributes, p.Attributes)
	if err != nil {
		return Item{}, err
	}
	children = append(children, attrs)
	return payloadItem(TagRequestPayload, children...), nil
}

// DecodeLocateRequestForVersion decodes a Locate request using the payload shape of version. |
// DecodeLocateRequestForVersion 使用 version 的负载形状解码 Locate 请求。
func DecodeLocateRequestForVersion(item Item, version ProtocolVersion) (LocateRequest, error) {
	if !usesKMIP20Payloads(version) {
		return DecodeLocateRequest(item)
	}
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
	attrs, err := decodeRequiredAttributes(item, true)
	if err != nil {
		return out, err
	}
	out.Attributes = attrs
	for _, child := range item.Children {
		switch child.Tag {
		case TagMaximumItems, TagOffsetItems, TagStorageStatusMask, TagObjectGroupMember, TagAttributes:
		case TagAttribute, TagCustomAttribute:
			return out, kmip20InvalidTag(child.Tag, "Locate request")
		default:
			return out, kmip20InvalidTag(child.Tag, "Locate request")
		}
	}
	return out, nil
}

// ItemForVersion encodes the Derive Key request using the payload shape of version. | ItemForVersion 使用 version 的
// 负载形状编码 Derive Key 请求。
func (p DeriveKeyRequest) ItemForVersion(version ProtocolVersion) (Item, error) {
	if !usesKMIP20Payloads(version) {
		return p.Item()
	}
	if p.ObjectType == 0 {
		return Item{}, errs.Detail(ErrInvalidRequest, "Derive Key request has no object type | Derive Key 请求没有对象类型")
	}
	children := []Item{NewEnumeration(TagObjectType, uint32(p.ObjectType))}
	for _, id := range p.UniqueIdentifiers {
		children = append(children, NewTextString(TagUniqueIdentifier, id))
	}
	children = append(children, NewEnumeration(TagDerivationMethod, uint32(p.DerivationMethod)))
	children = append(children, p.DerivationParameters.Item())
	attrs, err := attributesItem(TagAttributes, templateAttributeList(p.TemplateAttribute))
	if err != nil {
		return Item{}, err
	}
	children = append(children, attrs)
	return payloadItem(TagRequestPayload, children...), nil
}

// DecodeDeriveKeyRequestForVersion decodes a Derive Key request using the payload shape of version. |
// DecodeDeriveKeyRequestForVersion 使用 version 的负载形状解码 Derive Key 请求。
func DecodeDeriveKeyRequestForVersion(item Item, version ProtocolVersion) (DeriveKeyRequest, error) {
	if !usesKMIP20Payloads(version) {
		return DecodeDeriveKeyRequest(item)
	}
	if item.Type != TypeStructure {
		return DeriveKeyRequest{}, errs.Detail(ErrMalformed, "Derive Key request payload is not a structure | Derive Key 请求负载不是结构")
	}
	var out DeriveKeyRequest
	var err error
	out.ObjectType, err = decodeObjectTypeChild(item, true)
	if err != nil {
		return out, err
	}
	var hasAttributes bool
	for _, child := range item.Children {
		switch child.Tag {
		case TagObjectType:
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
		case TagAttributes:
			attrs, err := decodeAttributes(child)
			if err != nil {
				return out, err
			}
			out.TemplateAttribute = templateFromAttributes(attrs)
			hasAttributes = true
		default:
			return out, kmip20InvalidTag(child.Tag, "Derive Key request")
		}
	}
	if len(out.UniqueIdentifiers) == 0 {
		return out, errs.Detail(ErrMalformed, "Derive Key request has no Unique Identifier | Derive Key 请求没有唯一标识符")
	}
	if !hasAttributes {
		return out, errs.Detail(ErrMalformed, "Derive Key request has no Attributes | Derive Key 请求没有 Attributes")
	}
	return out, nil
}

// ItemForVersion encodes the Derive Key response using the payload shape of version. | ItemForVersion 使用 version 的
// 负载形状编码 Derive Key 响应。
func (p DeriveKeyResponse) ItemForVersion(version ProtocolVersion) (Item, error) {
	if !usesKMIP20Payloads(version) {
		return p.Item()
	}
	if p.TemplateAttribute != nil {
		return Item{}, errs.Detail(ErrUnsupported, "KMIP 2.0 Derive Key responses carry no Template-Attribute | KMIP 2.0 Derive Key 响应不携带 Template-Attribute")
	}
	return payloadItem(TagResponsePayload, NewTextString(TagUniqueIdentifier, p.UniqueIdentifier)), nil
}

// DecodeDeriveKeyResponseForVersion decodes a Derive Key response using the payload shape of version. |
// DecodeDeriveKeyResponseForVersion 使用 version 的负载形状解码 Derive Key 响应。
func DecodeDeriveKeyResponseForVersion(item Item, version ProtocolVersion) (DeriveKeyResponse, error) {
	if !usesKMIP20Payloads(version) {
		return DecodeDeriveKeyResponse(item)
	}
	if item.Type != TypeStructure {
		return DeriveKeyResponse{}, errs.Detail(ErrMalformed, "Derive Key response payload is not a structure | Derive Key 响应负载不是结构")
	}
	var out DeriveKeyResponse
	var err error
	out.UniqueIdentifier, err = childText(item, TagUniqueIdentifier)
	if err != nil {
		return out, err
	}
	if out.UniqueIdentifier == "" {
		return out, errs.Detail(ErrMalformed, "Derive Key response has no Unique Identifier | Derive Key 响应没有唯一标识符")
	}
	for _, child := range item.Children {
		if child.Tag == TagUniqueIdentifier {
			continue
		}
		return out, kmip20InvalidTag(child.Tag, "Derive Key response")
	}
	return out, nil
}

// ItemForVersion encodes the Unwrap Key request using the payload shape of version. | ItemForVersion 使用 version 的
// 负载形状编码 Unwrap Key 请求。
func (p UnwrapKeyRequest) ItemForVersion(version ProtocolVersion) (Item, error) {
	if !usesKMIP20Payloads(version) {
		return p.Item()
	}
	object, err := p.Object.ItemForVersion(version)
	if err != nil {
		return Item{}, err
	}
	attrs, err := attributesItem(TagAttributes, templateAttributeList(p.TemplateAttribute))
	if err != nil {
		return Item{}, err
	}
	return payloadItem(TagRequestPayload, object, attrs), nil
}

// DecodeUnwrapKeyRequestForVersion decodes an Unwrap Key request using the payload shape of version. |
// DecodeUnwrapKeyRequestForVersion 使用 version 的负载形状解码 Unwrap Key 请求。
func DecodeUnwrapKeyRequestForVersion(item Item, version ProtocolVersion) (UnwrapKeyRequest, error) {
	if !usesKMIP20Payloads(version) {
		return DecodeUnwrapKeyRequest(item)
	}
	if item.Type != TypeStructure {
		return UnwrapKeyRequest{}, errs.Detail(ErrMalformed, "Unwrap Key request payload is not a structure | Unwrap Key 请求负载不是结构")
	}
	var out UnwrapKeyRequest
	var hasAttributes bool
	for _, child := range item.Children {
		switch child.Tag {
		case TagSymmetricKey, TagPublicKey, TagPrivateKey, TagSecretData, TagCertificate, TagOpaqueObject:
			object, err := DecodeObjectForVersion(child, version)
			if err != nil {
				return out, err
			}
			out.Object = object
		case TagAttributes:
			attrs, err := decodeAttributes(child)
			if err != nil {
				return out, err
			}
			out.TemplateAttribute = templateFromAttributes(attrs)
			hasAttributes = true
		default:
			return out, kmip20InvalidTag(child.Tag, "Unwrap Key request")
		}
	}
	if out.Object.Type == 0 {
		return out, errs.Detail(ErrMalformed, "Unwrap Key request has no Object | Unwrap Key 请求没有对象")
	}
	if !hasAttributes {
		return out, errs.Detail(ErrMalformed, "Unwrap Key request has no Attributes | Unwrap Key 请求没有 Attributes")
	}
	return out, nil
}

// ItemForVersion encodes the Wrap Key response using the payload shape of version. | ItemForVersion 使用 version 的
// 负载形状编码 Wrap Key 响应。
func (p WrapKeyResponse) ItemForVersion(version ProtocolVersion) (Item, error) {
	if !usesKMIP20Payloads(version) {
		return p.Item()
	}
	object, err := p.Object.ItemForVersion(version)
	if err != nil {
		return Item{}, err
	}
	return payloadItem(TagResponsePayload,
		NewTextString(TagUniqueIdentifier, p.UniqueIdentifier),
		object,
	), nil
}

// DecodeWrapKeyResponseForVersion decodes a Wrap Key response using the payload shape of version. |
// DecodeWrapKeyResponseForVersion 使用 version 的负载形状解码 Wrap Key 响应。
func DecodeWrapKeyResponseForVersion(item Item, version ProtocolVersion) (WrapKeyResponse, error) {
	if !usesKMIP20Payloads(version) {
		return DecodeWrapKeyResponse(item)
	}
	if item.Type != TypeStructure {
		return WrapKeyResponse{}, errs.Detail(ErrMalformed, "Wrap Key response payload is not a structure | Wrap Key 响应负载不是结构")
	}
	var out WrapKeyResponse
	var err error
	out.UniqueIdentifier, err = childText(item, TagUniqueIdentifier)
	if err != nil {
		return out, err
	}
	for _, child := range item.Children {
		switch child.Tag {
		case TagUniqueIdentifier:
		case TagSymmetricKey, TagPublicKey, TagPrivateKey, TagSecretData, TagCertificate, TagOpaqueObject:
			out.Object, err = DecodeObjectForVersion(child, version)
			if err != nil {
				return out, err
			}
		default:
			return out, kmip20InvalidTag(child.Tag, "Wrap Key response")
		}
	}
	if out.Object.Type == 0 {
		return out, errs.Detail(ErrMalformed, "Wrap Key response has no Object | Wrap Key 响应没有对象")
	}
	if out.UniqueIdentifier == "" {
		return out, errs.Detail(ErrMalformed, "Wrap Key response has no Unique Identifier | Wrap Key 响应没有唯一标识符")
	}
	return out, nil
}
