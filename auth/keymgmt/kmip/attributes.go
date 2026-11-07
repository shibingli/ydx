package kmip

import (
	"time"

	"github.com/shibingli/ydx/errs"
)

// The names of the KMIP attributes supported by this package. | 本包支持的 KMIP 属性名称。
const (
	AttributeUniqueIdentifier               = "Unique Identifier"
	AttributeName                           = "Name"
	AttributeObjectType                     = "Object Type"
	AttributeCryptographicAlgorithm         = "Cryptographic Algorithm"
	AttributeCryptographicLength            = "Cryptographic Length"
	AttributeKeyFormatType                  = "Key Format Type"
	AttributeCryptographicUsageMask         = "Cryptographic Usage Mask"
	AttributeCryptographicDomainParameters  = "Cryptographic Domain Parameters"
	AttributeCertificateType                = "Certificate Type"
	AttributeCertificateLength              = "Certificate Length"
	AttributeDigitalSignatureAlgorithm      = "Digital Signature Algorithm"
	AttributeDigest                         = "Digest"
	AttributeOperationPolicyName            = "Operation Policy Name"
	AttributeState                          = "State"
	AttributeInitialDate                    = "Initial Date"
	AttributeActivationDate                 = "Activation Date"
	AttributeDeactivationDate               = "Deactivation Date"
	AttributeCompromiseDate                 = "Compromise Date"
	AttributeCompromiseOccurrenceDate       = "Compromise Occurrence Date"
	AttributeDestroyDate                    = "Destroy Date"
	AttributeArchiveDate                    = "Archive Date"
	AttributeLastChangeDate                 = "Last Change Date"
	AttributeOriginalCreationDate           = "Original Creation Date"
	AttributeContactInformation             = "Contact Information"
	AttributeObjectGroup                    = "Object Group"
	AttributeApplicationSpecificInformation = "Application Specific Information"
	AttributeSensitive                      = "Sensitive"
	AttributeAlwaysSensitive                = "Always Sensitive"
	AttributeExtractable                    = "Extractable"
	AttributeNeverExtractable               = "Never Extractable"
	AttributeFresh                          = "Fresh"
	AttributeDescription                    = "Description"
	AttributeComment                        = "Comment"
	AttributeLink                           = "Link"
)

// attributeTags maps an attribute name onto its KMIP attribute-value tag. | attributeTags 把属性名映射到其 KMIP 属性值标签。
var attributeTags = map[string]Tag{
	AttributeUniqueIdentifier:               TagUniqueIdentifier,
	AttributeName:                           TagName,
	AttributeObjectType:                     TagObjectType,
	AttributeCryptographicAlgorithm:         TagCryptographicAlgorithm,
	AttributeCryptographicLength:            TagCryptographicLength,
	AttributeKeyFormatType:                  TagKeyFormatType,
	AttributeCryptographicUsageMask:         TagCryptographicUsageMask,
	AttributeCryptographicDomainParameters:  TagCryptographicDomainParameters,
	AttributeCertificateType:                TagCertificateType,
	AttributeCertificateLength:              TagCertificateLength,
	AttributeDigitalSignatureAlgorithm:      TagDigitalSignatureAlgorithm,
	AttributeDigest:                         TagDigest,
	AttributeOperationPolicyName:            TagOperationPolicyName,
	AttributeState:                          TagState,
	AttributeInitialDate:                    TagInitialDate,
	AttributeActivationDate:                 TagActivationDate,
	AttributeDeactivationDate:               TagDeactivationDate,
	AttributeCompromiseDate:                 TagCompromiseDate,
	AttributeCompromiseOccurrenceDate:       TagCompromiseOccurrenceDate,
	AttributeDestroyDate:                    TagDestroyDate,
	AttributeArchiveDate:                    TagArchiveDate,
	AttributeLastChangeDate:                 TagLastChangeDate,
	AttributeOriginalCreationDate:           TagOriginalCreationDate,
	AttributeContactInformation:             TagContactInformation,
	AttributeObjectGroup:                    TagObjectGroup,
	AttributeApplicationSpecificInformation: TagApplicationSpecificInformation,
	AttributeSensitive:                      TagSensitive,
	AttributeAlwaysSensitive:                TagAlwaysSensitive,
	AttributeExtractable:                    TagExtractable,
	AttributeNeverExtractable:               TagNeverExtractable,
	AttributeFresh:                          TagFresh,
	AttributeDescription:                    TagDescription,
	AttributeComment:                        TagComment,
	AttributeLink:                           TagLink,
}

// AttributeTag returns the KMIP attribute-value tag for a known attribute name. | AttributeTag 返回已知属性名对应的 KMIP 属性值标签。
func AttributeTag(name string) (Tag, bool) {
	tag, ok := attributeTags[name]
	return tag, ok
}

// attributeNamesByTag maps an attribute-value tag back onto its standard attribute name. | attributeNamesByTag
// 把属性值标签映射回标准属性名。
var attributeNamesByTag = func() map[Tag]string {
	names := make(map[Tag]string, len(attributeTags))
	for name, tag := range attributeTags {
		names[tag] = name
	}
	return names
}()

// AttributeNameForTag returns the standard attribute name for a KMIP attribute-value tag. | AttributeNameForTag
// 返回 KMIP 属性值标签对应的标准属性名。
func AttributeNameForTag(tag Tag) (string, bool) {
	name, ok := attributeNamesByTag[tag]
	return name, ok
}

// Name is a KMIP Name attribute value. | Name 是 KMIP Name 属性值。
type Name struct {
	// Value is the name text. | Value 是名称文本。
	Value string
	// Type is the name type; the zero value is treated as an uninterpreted text string by Item. | Type 是名称类型；Item 会把零值视为未解释文本字符串。
	Type NameType
}

// NewName builds an uninterpreted-text Name. | NewName 构造未解释文本 Name。
func NewName(value string) Name {
	return Name{Value: value, Type: NameTypeUninterpretedTextString}
}

// Item encodes the name as a KMIP Name structure. | Item 把名称编码为 KMIP Name 结构。
func (n Name) Item() Item {
	typ := n.Type
	if typ == 0 {
		typ = NameTypeUninterpretedTextString
	}
	return NewStructure(TagName,
		NewTextString(TagNameValue, n.Value),
		NewEnumeration(TagNameType, uint32(typ)),
	)
}

// DecodeName decodes a KMIP Name structure. | DecodeName 解码 KMIP Name 结构。
func DecodeName(item Item) (Name, error) {
	if item.Type != TypeStructure || item.Tag != TagName {
		return Name{}, errs.Detail(ErrMalformed, "expected Name structure | 需要 Name 结构")
	}
	value, err := item.RequireChild(TagNameValue)
	if err != nil {
		return Name{}, err
	}
	text, err := value.AsTextString()
	if err != nil {
		return Name{}, err
	}
	typItem, err := item.RequireChild(TagNameType)
	if err != nil {
		return Name{}, err
	}
	rawType, err := typItem.AsEnumeration()
	if err != nil {
		return Name{}, err
	}
	switch NameType(rawType) {
	case NameTypeUninterpretedTextString, NameTypeURI:
	default:
		return Name{}, errs.Detail(ErrUnsupported, "unsupported name type 0x%08X | 不支持的名称类型 0x%08X", rawType, rawType)
	}
	return Name{Value: text, Type: NameType(rawType)}, nil
}

// Attribute is a KMIP attribute name/value pair. | Attribute 是 KMIP 属性名/值对。
type Attribute struct {
	// Name is the KMIP attribute name, for example AttributeCryptographicAlgorithm. | Name 是 KMIP 属性名，例如 AttributeCryptographicAlgorithm。
	Name string
	// Value is the attribute value. Its Tag must be the KMIP attribute tag, for example TagCryptographicAlgorithm. | Value 是属性值；其 Tag 必须是 KMIP 属性标签，例如 TagCryptographicAlgorithm。
	Value Item
	// VendorIdentification marks a KMIP 2.0 vendor attribute. It is empty for standard attributes. |
	// VendorIdentification 标记 KMIP 2.0 厂商属性；标准属性留空。
	VendorIdentification string
}

// NewAttribute builds an attribute with an explicit value item. | NewAttribute 使用显式值项构造属性。
func NewAttribute(name string, value Item) Attribute {
	return Attribute{Name: name, Value: value}
}

// NewVendorAttribute builds a KMIP 2.0 vendor attribute. | NewVendorAttribute 构造 KMIP 2.0 厂商属性。
func NewVendorAttribute(vendorIdentification, name string, value Item) Attribute {
	return Attribute{Name: name, Value: value, VendorIdentification: vendorIdentification}
}

// NewTextAttribute builds a text-string attribute using the tag registered for name. | NewTextAttribute 使用 name 注册的标签构造文本字符串属性。
func NewTextAttribute(name, value string) Attribute {
	tag, _ := AttributeTag(name)
	return Attribute{Name: name, Value: NewTextString(tag, value)}
}

// NewIntegerAttribute builds a 64-bit integer attribute using the tag registered for name. | NewIntegerAttribute 使用 name 注册的标签构造 64 位整数属性。
func NewIntegerAttribute(name string, value int64) Attribute {
	tag, _ := AttributeTag(name)
	return Attribute{Name: name, Value: NewInteger(tag, value)}
}

// NewEnumerationAttribute builds an enumeration attribute using the tag registered for name. | NewEnumerationAttribute 使用 name 注册的标签构造枚举属性。
func NewEnumerationAttribute(name string, value uint32) Attribute {
	tag, _ := AttributeTag(name)
	return Attribute{Name: name, Value: NewEnumeration(tag, value)}
}

// NewBooleanAttribute builds a boolean attribute using the tag registered for name. | NewBooleanAttribute 使用 name 注册的标签构造布尔属性。
func NewBooleanAttribute(name string, value bool) Attribute {
	tag, _ := AttributeTag(name)
	return Attribute{Name: name, Value: NewBoolean(tag, value)}
}

// NewDateTimeAttribute builds a date-time attribute using the tag registered for name. | NewDateTimeAttribute 使用 name 注册的标签构造日期时间属性。
func NewDateTimeAttribute(name string, value time.Time) Attribute {
	tag, _ := AttributeTag(name)
	return Attribute{Name: name, Value: NewDateTime(tag, value)}
}

// NewUsageMaskAttribute builds a cryptographic-usage-mask attribute. | NewUsageMaskAttribute 构造密码学用法掩码属性。
func NewUsageMaskAttribute(mask CryptographicUsageMask) Attribute {
	return Attribute{Name: AttributeCryptographicUsageMask, Value: NewInteger(TagCryptographicUsageMask, int64(mask))}
}

// NewNameAttribute builds a Name attribute whose value is a Name structure. | NewNameAttribute 构造值为 Name 结构的 Name 属性。
func NewNameAttribute(name Name) Attribute {
	return Attribute{Name: AttributeName, Value: name.Item()}
}

// Item encodes the attribute as a KMIP Attribute structure. | Item 把属性编码为 KMIP Attribute 结构。
//
// The attribute value is carried under the generic Attribute Value tag as required by KMIP 1.4. When Value.Tag is
// zero the tag registered for Name is used to derive a typed value. | 按 KMIP 1.4 要求，属性值使用通用 Attribute Value
// 标签承载；当 Value.Tag 为零时使用 Name 注册的标签推导类型化值。
func (a Attribute) Item() (Item, error) {
	if a.Name == "" {
		return Item{}, errs.Detail(ErrInvalidRequest, "attribute name is empty | 属性名为空")
	}
	value := a.Value
	if value.Tag == 0 {
		tag, ok := AttributeTag(a.Name)
		if !ok {
			return Item{}, errs.Detail(ErrUnsupported, "attribute %q has no registered tag | 属性 %q 没有注册标签", a.Name, a.Name)
		}
		value.Tag = tag
	}
	if value.Type == 0 {
		return Item{}, errs.Detail(ErrInvalidRequest, "attribute %q has no value | 属性 %q 没有值", a.Name, a.Name)
	}
	value.Tag = TagAttributeValue
	return NewStructure(TagAttribute,
		NewTextString(TagAttributeName, a.Name),
		value,
	), nil
}

// DecodeAttribute decodes a KMIP Attribute structure. | DecodeAttribute 解码 KMIP Attribute 结构。
//
// Known attribute names have the generic Attribute Value tag replaced by the semantic tag registered for the name so
// that the decoded value can be re-encoded and inspected uniformly. | 已知属性名会把通用 Attribute Value 标签替换为
// 该名称注册的语义标签，以便解码后的值可以统一重新编码与检查。
func DecodeAttribute(item Item) (Attribute, error) {
	if item.Type != TypeStructure || item.Tag != TagAttribute && item.Tag != TagCustomAttribute {
		return Attribute{}, errs.Detail(ErrMalformed, "expected Attribute structure | 需要 Attribute 结构")
	}
	nameItem, err := item.RequireChild(TagAttributeName)
	if err != nil {
		return Attribute{}, err
	}
	name, err := nameItem.AsTextString()
	if err != nil {
		return Attribute{}, err
	}
	valueItem, ok := item.Child(TagAttributeValue)
	if !ok || valueItem.Type == 0 {
		return Attribute{}, errs.Detail(ErrMalformed, "attribute %q has no Attribute Value | 属性 %q 没有 Attribute Value", name, name)
	}
	value := valueItem
	if tag, known := AttributeTag(name); known {
		value.Tag = tag
	}
	if item.Tag == TagCustomAttribute && value.Tag == TagAttributeValue {
		value.Tag = 0
	}
	return Attribute{Name: name, Value: value}, nil
}

// AttributeList is an ordered list of attributes. | AttributeList 是有序属性列表。
type AttributeList []Attribute

// Lookup returns the first attribute with the given name. | Lookup 返回第一个具有给定名称的属性。
func (l AttributeList) Lookup(name string) (Attribute, bool) {
	for i := range l {
		if l[i].Name == name {
			return l[i], true
		}
	}
	return Attribute{}, false
}

// LookupString returns the first text-string attribute with the given name. | LookupString 返回第一个具有给定名称的文本字符串属性。
func (l AttributeList) LookupString(name string) (string, bool, error) {
	a, ok := l.Lookup(name)
	if !ok {
		return "", false, nil
	}
	value, err := a.Value.AsTextString()
	if err != nil {
		return "", true, err
	}
	return value, true, nil
}

// LookupInteger returns the first 64-bit integer attribute with the given name. | LookupInteger 返回第一个具有给定名称的 64 位整数属性。
func (l AttributeList) LookupInteger(name string) (int64, bool, error) {
	a, ok := l.Lookup(name)
	if !ok {
		return 0, false, nil
	}
	value, err := a.Value.AsInteger()
	if err != nil {
		return 0, true, err
	}
	return value, true, nil
}

// LookupEnumeration returns the first enumeration attribute with the given name. | LookupEnumeration 返回第一个具有给定名称的枚举属性。
func (l AttributeList) LookupEnumeration(name string) (uint32, bool, error) {
	a, ok := l.Lookup(name)
	if !ok {
		return 0, false, nil
	}
	value, err := a.Value.AsEnumeration()
	if err != nil {
		return 0, true, err
	}
	return value, true, nil
}

// LookupBoolean returns the first boolean attribute with the given name. | LookupBoolean 返回第一个具有给定名称的布尔属性。
func (l AttributeList) LookupBoolean(name string) (bool, bool, error) {
	a, ok := l.Lookup(name)
	if !ok {
		return false, false, nil
	}
	value, err := a.Value.AsBoolean()
	if err != nil {
		return false, true, err
	}
	return value, true, nil
}

// LookupDateTime returns the first date-time attribute with the given name. | LookupDateTime 返回第一个具有给定名称的日期时间属性。
func (l AttributeList) LookupDateTime(name string) (time.Time, bool, error) {
	a, ok := l.Lookup(name)
	if !ok {
		return time.Time{}, false, nil
	}
	value, err := a.Value.AsDateTime()
	if err != nil {
		return time.Time{}, true, err
	}
	return value, true, nil
}

// LookupUsageMask returns the cryptographic usage mask, accepting either an Integer or an Enumeration encoding. | LookupUsageMask 返回密码学用法掩码，接受 Integer 或 Enumeration 编码。
func (l AttributeList) LookupUsageMask() (CryptographicUsageMask, bool, error) {
	a, ok := l.Lookup(AttributeCryptographicUsageMask)
	if !ok {
		return 0, false, nil
	}
	switch a.Value.Type {
	case TypeInteger:
		v, err := a.Value.AsInteger()
		if err != nil {
			return 0, true, err
		}
		return CryptographicUsageMask(uint32(v)), true, nil
	case TypeEnumeration:
		v, err := a.Value.AsEnumeration()
		if err != nil {
			return 0, true, err
		}
		return CryptographicUsageMask(v), true, nil
	default:
		return 0, true, errs.Detail(ErrMalformed, "usage mask has type %s | 用法掩码类型为 %s", a.Value.Type, a.Value.Type)
	}
}

// Names extracts all Name attributes. | Names 提取全部 Name 属性。
func (l AttributeList) Names() ([]Name, error) {
	var out []Name
	for i := range l {
		if l[i].Name != AttributeName {
			continue
		}
		name, err := DecodeName(l[i].Value)
		if err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, nil
}

// ObjectGroups extracts all Object Group attributes. | ObjectGroups 提取全部 Object Group 属性。
func (l AttributeList) ObjectGroups() ([]string, error) {
	var out []string
	for i := range l {
		if l[i].Name != AttributeObjectGroup {
			continue
		}
		group, err := l[i].Value.AsTextString()
		if err != nil {
			return nil, err
		}
		out = append(out, group)
	}
	return out, nil
}

// TemplateAttribute is a KMIP Template-Attribute structure: zero or more Name values followed by zero or more
// Attribute values. | TemplateAttribute 是 KMIP Template-Attribute 结构：零个或多个 Name 值，后跟零个或多个 Attribute 值。
type TemplateAttribute struct {
	// Names holds the Name values. | Names 保存 Name 值。
	Names []Name
	// Attributes holds the named attribute values. | Attributes 保存命名属性值。
	Attributes AttributeList
}

// Item encodes the template attribute as a KMIP Template-Attribute structure. | Item 把模板属性编码为 KMIP Template-Attribute 结构。
func (t TemplateAttribute) Item() (Item, error) {
	children := make([]Item, 0, len(t.Names)+len(t.Attributes))
	for _, name := range t.Names {
		if name.Value == "" {
			return Item{}, errs.Detail(ErrInvalidRequest, "empty name value | 名称值为空")
		}
		children = append(children, name.Item())
	}
	for _, attr := range t.Attributes {
		item, err := attr.Item()
		if err != nil {
			return Item{}, err
		}
		children = append(children, item)
	}
	return NewStructure(TagTemplateAttribute, children...), nil
}

// DecodeTemplateAttribute decodes a Template-Attribute structure. | DecodeTemplateAttribute 解码 Template-Attribute 结构。
//
// The outer tag is not checked so that the same decoder handles Common Template-Attribute and private/public key
// Template-Attribute structures. | 不校验外层标签，因此同一个解码器可处理 Common、私钥与公钥 Template-Attribute 结构。
func DecodeTemplateAttribute(item Item) (TemplateAttribute, error) {
	if item.Type != TypeStructure {
		return TemplateAttribute{}, errs.Detail(ErrMalformed, "Template-Attribute is not a structure | Template-Attribute 不是结构")
	}
	var out TemplateAttribute
	for _, child := range item.Children {
		switch child.Tag {
		case TagName:
			name, err := DecodeName(child)
			if err != nil {
				return TemplateAttribute{}, err
			}
			out.Names = append(out.Names, name)
		case TagAttribute, TagCustomAttribute:
			attr, err := DecodeAttribute(child)
			if err != nil {
				return TemplateAttribute{}, err
			}
			out.Attributes = append(out.Attributes, attr)
		default:
			return TemplateAttribute{}, errs.Detail(ErrMalformed, "unexpected tag 0x%06X in Template-Attribute | Template-Attribute 中出现意外标签 0x%06X", uint32(child.Tag), uint32(child.Tag))
		}
	}
	return out, nil
}

// AllAttributes returns the names and attributes as one list in document order. | AllAttributes 按文档顺序把名称与属性合并为一个列表。
func (t TemplateAttribute) AllAttributes() AttributeList {
	out := make(AttributeList, 0, len(t.Names)+len(t.Attributes))
	for _, name := range t.Names {
		out = append(out, NewNameAttribute(name))
	}
	out = append(out, t.Attributes...)
	return out
}

// CloneAttributes returns a shallow copy of the list. | CloneAttributes 返回列表的浅拷贝。
func CloneAttributes(l AttributeList) AttributeList {
	if l == nil {
		return nil
	}
	return append(AttributeList(nil), l...)
}
