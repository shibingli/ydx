package kmip

import "github.com/shibingli/ydx/errs"

// usesKMIP20Payloads reports whether version selects the KMIP 2.0 payload shapes. | usesKMIP20Payloads 报告 version
// 是否选用 KMIP 2.0 负载形状。
func usesKMIP20Payloads(version ProtocolVersion) bool {
	return version.Major >= MajorVersion2
}

// kmip20InvalidTag builds the error returned for a tag that has no meaning in a KMIP 2.0 payload. | kmip20InvalidTag
// 构造 KMIP 2.0 负载中无意义标签对应的错误。
func kmip20InvalidTag(tag Tag, payload string) error {
	return errs.Detail(ErrUnsupported,
		"tag 0x%06X is not valid in the KMIP 2.0 %s payload | 标签 0x%06X 在 KMIP 2.0 %s 负载中无效",
		uint32(tag), payload, uint32(tag), payload)
}

// AttributeReference identifies one attribute in a KMIP 2.0 Get Attributes or Get Attribute List payload. |
// AttributeReference 标识 KMIP 2.0 Get Attributes 或 Get Attribute List 负载中的一个属性。
type AttributeReference struct {
	// Name is the standard attribute name, for example AttributeCryptographicAlgorithm. | Name 是标准属性名，例如
	// AttributeCryptographicAlgorithm。
	Name string
	// VendorIdentification marks a vendor attribute reference. It is empty for standard attributes. |
	// VendorIdentification 标记厂商属性引用；标准属性留空。
	VendorIdentification string
}

// Item encodes the attribute reference as a KMIP 2.0 Attribute Reference. Standard references use an Enumeration
// carrying the attribute tag; vendor references use a structure with the vendor identifier and attribute name. |
// Item 把属性引用编码为 KMIP 2.0 Attribute Reference。标准引用使用携带属性标签的 Enumeration；厂商引用使用包含厂商标识与
// 属性名的结构。
func (r AttributeReference) Item() (Item, error) {
	if r.Name == "" {
		return Item{}, errs.Detail(ErrInvalidRequest, "attribute reference has no name | 属性引用没有名称")
	}
	if r.VendorIdentification != "" {
		return NewStructure(TagAttributeReference,
			NewTextString(TagVendorIdentification, r.VendorIdentification),
			NewTextString(TagAttributeName, r.Name),
		), nil
	}
	tag, ok := AttributeTag(r.Name)
	if !ok {
		return Item{}, errs.Detail(ErrUnsupported, "attribute %q has no registered tag | 属性 %q 没有注册标签", r.Name, r.Name)
	}
	return NewEnumeration(TagAttributeReference, uint32(tag)), nil
}

// DecodeAttributeReference decodes a KMIP 2.0 Attribute Reference. | DecodeAttributeReference 解码 KMIP 2.0
// Attribute Reference。
func DecodeAttributeReference(item Item) (AttributeReference, error) {
	if item.Tag != TagAttributeReference {
		return AttributeReference{}, errs.Detail(ErrMalformed, "expected Attribute Reference | 需要 Attribute Reference")
	}
	switch item.Type {
	case TypeEnumeration:
		value, err := item.AsEnumeration()
		if err != nil {
			return AttributeReference{}, err
		}
		name, ok := AttributeNameForTag(Tag(value))
		if !ok {
			return AttributeReference{}, errs.Detail(ErrUnsupported,
				"unsupported attribute reference tag 0x%06X | 不支持的属性引用标签 0x%06X", value, value)
		}
		return AttributeReference{Name: name}, nil
	case TypeStructure:
		vendor, err := item.RequireChild(TagVendorIdentification)
		if err != nil {
			return AttributeReference{}, err
		}
		vendorID, err := vendor.AsTextString()
		if err != nil {
			return AttributeReference{}, err
		}
		nameItem, err := item.RequireChild(TagAttributeName)
		if err != nil {
			return AttributeReference{}, err
		}
		name, err := nameItem.AsTextString()
		if err != nil {
			return AttributeReference{}, err
		}
		if vendorID == "" || name == "" {
			return AttributeReference{}, errs.Detail(ErrMalformed,
				"vendor attribute reference is missing Vendor Identification or Attribute Name | 厂商属性引用缺少厂商标识或属性名")
		}
		return AttributeReference{Name: name, VendorIdentification: vendorID}, nil
	default:
		return AttributeReference{}, errs.Detail(ErrMalformed,
			"Attribute Reference has unexpected type %s | Attribute Reference 的类型 %s 非预期", item.Type, item.Type)
	}
}

// templateAttributeList converts a 1.4 Template-Attribute into a 2.0 attribute list, including its Name values as Name
// attributes. | templateAttributeList 把 1.4 Template-Attribute 转换为 2.0 属性列表，并把 Name 值作为 Name 属性纳入。
func templateAttributeList(template TemplateAttribute) AttributeList {
	out := make(AttributeList, 0, len(template.Names)+len(template.Attributes))
	for _, name := range template.Names {
		out = append(out, NewNameAttribute(name))
	}
	out = append(out, template.Attributes...)
	return out
}

// attributesItem encodes an attribute list as a KMIP 2.0 Attributes structure with the supplied wrapper tag. | attributesItem
// 把属性列表编码为带指定外层标签的 KMIP 2.0 Attributes 结构。
func attributesItem(tag Tag, attrs AttributeList) (Item, error) {
	children := make([]Item, 0, len(attrs))
	for _, attr := range attrs {
		item, err := attributeItem20(attr)
		if err != nil {
			return Item{}, err
		}
		children = append(children, item)
	}
	return NewStructure(tag, children...), nil
}

// attributeItem20 encodes one attribute using its KMIP 2.0 directly tagged form. | attributeItem20 使用 KMIP 2.0
// 的直接标签形式编码单个属性。
func attributeItem20(attr Attribute) (Item, error) {
	if attr.Name == "" {
		return Item{}, errs.Detail(ErrInvalidRequest, "attribute name is empty | 属性名为空")
	}
	if attr.Value.Type == 0 {
		return Item{}, errs.Detail(ErrInvalidRequest, "attribute %q has no value | 属性 %q 没有值", attr.Name, attr.Name)
	}
	value := attr.Value
	if attr.VendorIdentification != "" {
		value.Tag = TagAttributeValue
		return NewStructure(TagAttribute,
			NewTextString(TagVendorIdentification, attr.VendorIdentification),
			NewTextString(TagAttributeName, attr.Name),
			value,
		), nil
	}
	tag, ok := AttributeTag(attr.Name)
	if !ok {
		return Item{}, errs.Detail(ErrUnsupported, "attribute %q has no registered tag | 属性 %q 没有注册标签", attr.Name, attr.Name)
	}
	value.Tag = tag
	return value, nil
}

// decodeAttributes decodes the children of a KMIP 2.0 Attributes structure. The caller checks the wrapper tag. |
// decodeAttributes 解码 KMIP 2.0 Attributes 结构的子项；外层标签由调用方校验。
func decodeAttributes(item Item) (AttributeList, error) {
	if item.Type != TypeStructure {
		return nil, errs.Detail(ErrMalformed, "KMIP 2.0 Attributes is not a structure | KMIP 2.0 Attributes 不是结构")
	}
	out := make(AttributeList, 0, len(item.Children))
	for _, child := range item.Children {
		attr, err := decodeAttribute20(child)
		if err != nil {
			return nil, err
		}
		out = append(out, attr)
	}
	return out, nil
}

// decodeAttribute20 decodes one directly tagged KMIP 2.0 attribute or vendor Attribute structure. | decodeAttribute20
// 解码一个直接标签的 KMIP 2.0 属性或厂商 Attribute 结构。
func decodeAttribute20(item Item) (Attribute, error) {
	switch item.Tag {
	case TagAttribute:
		if item.Type != TypeStructure {
			return Attribute{}, errs.Detail(ErrMalformed, "vendor Attribute is not a structure | 厂商 Attribute 不是结构")
		}
		vendor, err := item.RequireChild(TagVendorIdentification)
		if err != nil {
			return Attribute{}, err
		}
		vendorID, err := vendor.AsTextString()
		if err != nil {
			return Attribute{}, err
		}
		nameItem, err := item.RequireChild(TagAttributeName)
		if err != nil {
			return Attribute{}, err
		}
		name, err := nameItem.AsTextString()
		if err != nil {
			return Attribute{}, err
		}
		value, ok := item.Child(TagAttributeValue)
		if !ok || value.Type == 0 {
			return Attribute{}, errs.Detail(ErrMalformed, "vendor attribute %q has no value | 厂商属性 %q 没有值", name, name)
		}
		if vendorID == "" || name == "" {
			return Attribute{}, errs.Detail(ErrMalformed,
				"vendor attribute is missing Vendor Identification or Attribute Name | 厂商属性缺少厂商标识或属性名")
		}
		return Attribute{Name: name, Value: value, VendorIdentification: vendorID}, nil
	case TagCustomAttribute:
		return Attribute{}, kmip20InvalidTag(item.Tag, "Attributes")
	}
	name, ok := AttributeNameForTag(item.Tag)
	if !ok {
		return Attribute{}, errs.Detail(ErrUnsupported,
			"unsupported KMIP 2.0 attribute tag 0x%06X | 不支持的 KMIP 2.0 属性标签 0x%06X", uint32(item.Tag), uint32(item.Tag))
	}
	if item.Type == 0 {
		return Attribute{}, errs.Detail(ErrMalformed, "attribute %q has no value | 属性 %q 没有值", name, name)
	}
	return Attribute{Name: name, Value: item}, nil
}

// ItemForVersion encodes the key value using the payload shape of version. | ItemForVersion 使用 version 的负载形状编码
// 密钥值。
func (kv KeyValue) ItemForVersion(version ProtocolVersion) (Item, error) {
	if !usesKMIP20Payloads(version) {
		return kv.Item()
	}
	material := kv.Material
	if material.Tag == 0 {
		material.Tag = TagKeyMaterial
	}
	if material.Tag != TagKeyMaterial || material.Type == 0 {
		return Item{}, errs.Detail(ErrInvalidRequest, "key value has no key material | 密钥值没有密钥材料")
	}
	children := []Item{material}
	if len(kv.Attributes) > 0 {
		attrs, err := attributesItem(TagAttributes, kv.Attributes)
		if err != nil {
			return Item{}, err
		}
		children = append(children, attrs)
	}
	return NewStructure(TagKeyValue, children...), nil
}

// DecodeKeyValueForVersion decodes a Key Value using the payload shape of version. | DecodeKeyValueForVersion 使用
// version 的负载形状解码 Key Value。
func DecodeKeyValueForVersion(item Item, version ProtocolVersion) (KeyValue, error) {
	if !usesKMIP20Payloads(version) {
		return DecodeKeyValue(item)
	}
	if item.Type != TypeStructure || item.Tag != TagKeyValue {
		return KeyValue{}, errs.Detail(ErrMalformed, "expected Key Value structure | 需要 Key Value 结构")
	}
	var out KeyValue
	var foundAttributes bool
	for _, child := range item.Children {
		switch child.Tag {
		case TagKeyMaterial:
			out.Material = child
		case TagAttributes:
			if foundAttributes {
				return KeyValue{}, errs.Detail(ErrMalformed, "Key Value has duplicate Attributes | Key Value 存在重复 Attributes")
			}
			foundAttributes = true
			attrs, err := decodeAttributes(child)
			if err != nil {
				return KeyValue{}, err
			}
			out.Attributes = attrs
		case TagAttribute, TagCustomAttribute:
			return KeyValue{}, kmip20InvalidTag(child.Tag, "Key Value")
		default:
			return KeyValue{}, kmip20InvalidTag(child.Tag, "Key Value")
		}
	}
	if out.Material.Tag == 0 {
		return KeyValue{}, errs.Detail(ErrMalformed, "Key Value has no Key Material | Key Value 没有 Key Material")
	}
	return out, nil
}

// ItemForVersion encodes the key block using the payload shape of version. | ItemForVersion 使用 version 的负载形状编码
// 密钥块。
func (kb KeyBlock) ItemForVersion(version ProtocolVersion) (Item, error) {
	if !usesKMIP20Payloads(version) {
		return kb.Item()
	}
	if kb.Format == 0 {
		return Item{}, errs.Detail(ErrInvalidRequest, "key block has no key format type | 密钥块没有密钥格式类型")
	}
	value, err := kb.Value.ItemForVersion(version)
	if err != nil {
		return Item{}, err
	}
	children := []Item{NewEnumeration(TagKeyFormatType, uint32(kb.Format))}
	if kb.Compression != 0 {
		children = append(children, NewEnumeration(TagKeyCompressionType, uint32(kb.Compression)))
	}
	children = append(children, value)
	if kb.Algorithm != 0 {
		children = append(children, NewEnumeration(TagCryptographicAlgorithm, uint32(kb.Algorithm)))
	}
	if kb.Length > 0 {
		children = append(children, NewInteger(TagCryptographicLength, int64(kb.Length)))
	}
	if kb.Wrapping != nil {
		wrapping, err := kb.Wrapping.Item()
		if err != nil {
			return Item{}, err
		}
		children = append(children, wrapping)
	}
	return NewStructure(TagKeyBlock, children...), nil
}

// DecodeKeyBlockForVersion decodes a Key Block using the payload shape of version. | DecodeKeyBlockForVersion 使用
// version 的负载形状解码 Key Block。
func DecodeKeyBlockForVersion(item Item, version ProtocolVersion) (KeyBlock, error) {
	if !usesKMIP20Payloads(version) {
		return DecodeKeyBlock(item)
	}
	if item.Type != TypeStructure || item.Tag != TagKeyBlock {
		return KeyBlock{}, errs.Detail(ErrMalformed, "expected Key Block structure | 需要 Key Block 结构")
	}
	var out KeyBlock
	for _, child := range item.Children {
		switch child.Tag {
		case TagKeyFormatType:
			v, err := child.AsEnumeration()
			if err != nil {
				return KeyBlock{}, err
			}
			out.Format = KeyFormatType(v)
		case TagKeyCompressionType:
			v, err := child.AsEnumeration()
			if err != nil {
				return KeyBlock{}, err
			}
			out.Compression = KeyCompressionType(v)
		case TagKeyValue:
			v, err := DecodeKeyValueForVersion(child, version)
			if err != nil {
				return KeyBlock{}, err
			}
			out.Value = v
		case TagCryptographicAlgorithm:
			v, err := child.AsEnumeration()
			if err != nil {
				return KeyBlock{}, err
			}
			out.Algorithm = CryptographicAlgorithm(v)
		case TagCryptographicLength:
			v, err := child.AsInteger()
			if err != nil {
				return KeyBlock{}, err
			}
			if v < 0 {
				return KeyBlock{}, errs.Detail(ErrMalformed, "negative cryptographic length | 密码长度为负")
			}
			out.Length = int(v)
		case TagKeyWrappingData:
			v, err := DecodeKeyWrappingData(child)
			if err != nil {
				return KeyBlock{}, err
			}
			out.Wrapping = &v
		default:
			return KeyBlock{}, kmip20InvalidTag(child.Tag, "Key Block")
		}
	}
	if out.Format == 0 {
		return KeyBlock{}, errs.Detail(ErrMalformed, "Key Block has no Key Format Type | Key Block 没有 Key Format Type")
	}
	if out.Value.Material.Tag == 0 || out.Value.Material.Type == 0 {
		return KeyBlock{}, errs.Detail(ErrMalformed, "Key Block has no Key Value | Key Block 没有 Key Value")
	}
	return out, nil
}

// ItemForVersion encodes the managed object using the payload shape of version. | ItemForVersion 使用 version 的负载形状
// 编码受管对象。
func (o Object) ItemForVersion(version ProtocolVersion) (Item, error) {
	if !usesKMIP20Payloads(version) {
		return o.Item()
	}
	if o.Type == ObjectTypeTemplate {
		return Item{}, errs.Detail(ErrUnsupported, "the Template object is removed in KMIP 2.0 | KMIP 2.0 已移除 Template 对象")
	}
	switch o.Type {
	case ObjectTypeSymmetricKey:
		if o.SymmetricKey == nil {
			break
		}
		kb, err := o.SymmetricKey.KeyBlock.ItemForVersion(version)
		if err != nil {
			return Item{}, err
		}
		return NewStructure(TagSymmetricKey, kb), nil
	case ObjectTypePublicKey:
		if o.PublicKey == nil {
			break
		}
		kb, err := o.PublicKey.KeyBlock.ItemForVersion(version)
		if err != nil {
			return Item{}, err
		}
		return NewStructure(TagPublicKey, kb), nil
	case ObjectTypePrivateKey:
		if o.PrivateKey == nil {
			break
		}
		kb, err := o.PrivateKey.KeyBlock.ItemForVersion(version)
		if err != nil {
			return Item{}, err
		}
		return NewStructure(TagPrivateKey, kb), nil
	case ObjectTypeSecretData:
		if o.SecretData == nil {
			break
		}
		typ := o.SecretData.SecretDataType
		if typ == 0 {
			typ = SecretDataTypePassword
		}
		kb, err := o.SecretData.KeyBlock.ItemForVersion(version)
		if err != nil {
			return Item{}, err
		}
		return NewStructure(TagSecretData,
			NewEnumeration(TagSecretDataType, uint32(typ)),
			kb,
		), nil
	case ObjectTypeCertificate, ObjectTypeOpaqueObject:
		return o.Item()
	}
	return Item{}, errs.Detail(ErrInvalidRequest, "object type %s has no matching value | 对象类型 %s 没有匹配的值", o.Type, o.Type)
}

// DecodeObjectForVersion decodes a managed object using the payload shape of version. | DecodeObjectForVersion 使用
// version 的负载形状解码受管对象。
func DecodeObjectForVersion(item Item, version ProtocolVersion) (Object, error) {
	if !usesKMIP20Payloads(version) {
		return DecodeObject(item)
	}
	if item.Type != TypeStructure {
		return Object{}, errs.Detail(ErrMalformed, "managed object is not a structure | 受管对象不是结构")
	}
	switch item.Tag {
	case TagSymmetricKey, TagPublicKey, TagPrivateKey:
		kbItem, err := item.RequireChild(TagKeyBlock)
		if err != nil {
			return Object{}, err
		}
		kb, err := DecodeKeyBlockForVersion(kbItem, version)
		if err != nil {
			return Object{}, err
		}
		switch item.Tag {
		case TagSymmetricKey:
			return NewSymmetricKeyObject(kb), nil
		case TagPublicKey:
			return NewPublicKeyObject(kb), nil
		default:
			return NewPrivateKeyObject(kb), nil
		}
	case TagSecretData:
		typeItem, err := item.RequireChild(TagSecretDataType)
		if err != nil {
			return Object{}, err
		}
		rawType, err := typeItem.AsEnumeration()
		if err != nil {
			return Object{}, err
		}
		kbItem, err := item.RequireChild(TagKeyBlock)
		if err != nil {
			return Object{}, err
		}
		kb, err := DecodeKeyBlockForVersion(kbItem, version)
		if err != nil {
			return Object{}, err
		}
		return NewSecretDataObject(SecretDataType(rawType), kb), nil
	case TagCertificate, TagOpaqueObject:
		return DecodeObject(item)
	case TagTemplate:
		return Object{}, errs.Detail(ErrUnsupported, "the Template object is removed in KMIP 2.0 | KMIP 2.0 已移除 Template 对象")
	default:
		return Object{}, kmip20InvalidTag(item.Tag, "managed object")
	}
}
