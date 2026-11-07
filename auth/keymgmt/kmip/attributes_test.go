package kmip

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

// TestAttributeTag covers known and unknown attribute names. | TestAttributeTag 覆盖已知与未知属性名。
func TestAttributeTag(t *testing.T) {
	if tag, ok := AttributeTag(AttributeState); !ok || tag != TagState {
		t.Fatalf("AttributeTag(State) = %v, %v | AttributeTag(State) = %v, %v", tag, ok, tag, ok)
	}
	if _, ok := AttributeTag("not-a-kmip-attribute"); ok {
		t.Fatal("unknown attribute name reported as known | 未知属性名被报告为已知")
	}
}

// TestNameEncoding covers Name round trips and validation. | TestNameEncoding 覆盖 Name 往返与校验。
func TestNameEncoding(t *testing.T) {
	uninterpreted := NewName("alpha")
	if uninterpreted.Type != NameTypeUninterpretedTextString {
		t.Fatalf("NewName type = %s | NewName 类型 = %s", uninterpreted.Type, uninterpreted.Type)
	}
	decoded, err := DecodeName(uninterpreted.Item())
	if err != nil {
		t.Fatalf("DecodeName: %v", err)
	}
	if decoded.Value != "alpha" || decoded.Type != NameTypeUninterpretedTextString {
		t.Fatalf("decoded name = %+v | 解码名称 = %+v", decoded, decoded)
	}
	uri := Name{Value: "https://example.test/key", Type: NameTypeURI}
	decoded, err = DecodeName(uri.Item())
	if err != nil || decoded.Type != NameTypeURI {
		t.Fatalf("URI name decode = %+v, %v | URI 名称解码 = %+v，%v", decoded, err, decoded, err)
	}
	zeroType := Name{Value: "beta"}
	if got := zeroType.Item().Children[1].Value; len(got) == 0 || got[3] != byte(NameTypeUninterpretedTextString) {
		t.Fatalf("zero Name type did not default to uninterpreted | 零 Name 类型未默认为未解释")
	}
	if _, err := DecodeName(NewStructure(TagTemplateAttribute)); err == nil {
		t.Fatal("wrong tag decoded without error | 错误标签未报错")
	}
	if _, err := DecodeName(NewStructure(TagName, NewTextString(TagNameValue, "x"))); err == nil {
		t.Fatal("Name without type decoded without error | 无类型 Name 未报错")
	}
	if _, err := DecodeName(NewStructure(TagName, NewTextString(TagNameValue, "x"), NewEnumeration(TagNameType, 99))); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unsupported name type error = %v | 不支持名称类型错误 = %v", err, err)
	}
}

// TestAttributeEncoding covers Attribute round trips and validation. | TestAttributeEncoding 覆盖 Attribute 往返与校验。
func TestAttributeEncoding(t *testing.T) {
	attributes := AttributeList{
		NewTextAttribute(AttributeName, "alpha"),
		NewIntegerAttribute(AttributeCryptographicLength, 256),
		NewEnumerationAttribute(AttributeState, uint32(StateActive)),
		NewBooleanAttribute(AttributeSensitive, true),
		NewDateTimeAttribute(AttributeInitialDate, testDate()),
		NewUsageMaskAttribute(UsageMaskEncrypt | UsageMaskDecrypt),
		NewNameAttribute(NewName("beta")),
	}
	for i := range attributes {
		item, err := attributes[i].Item()
		if err != nil {
			t.Fatalf("encode attribute %q: %v | 编码属性 %q：%v", attributes[i].Name, err, attributes[i].Name, err)
		}
		decoded, err := DecodeAttribute(item)
		if err != nil {
			t.Fatalf("decode attribute %q: %v | 解码属性 %q：%v", attributes[i].Name, err, attributes[i].Name, err)
		}
		if decoded.Name != attributes[i].Name || decoded.Value.Tag != attributes[i].Value.Tag || decoded.Value.Type != attributes[i].Value.Type {
			t.Fatalf("attribute %q round trip = %+v, want %+v | 属性 %q 往返 = %+v，期望 %+v", attributes[i].Name, decoded, attributes[i], attributes[i].Name, decoded, attributes[i])
		}
	}
	if _, err := (Attribute{Name: "", Value: NewTextString(TagName, "x")}).Item(); err == nil {
		t.Fatal("attribute without name encoded | 无名称属性被编码")
	}
	if _, err := (Attribute{Name: "unknown-attribute", Value: NewTextString(0, "x")}).Item(); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unknown attribute error = %v | 未知属性错误 = %v", err, err)
	}
	if _, err := (Attribute{Name: AttributeComment, Value: Item{}}).Item(); err == nil {
		t.Fatal("attribute without value encoded | 无值属性被编码")
	}
	custom := NewAttribute("x-custom", NewTextString(TagAttributeValue, "value"))
	customItem, err := custom.Item()
	if err != nil {
		t.Fatalf("custom attribute encode: %v | 自定义属性编码失败", err)
	}
	customItem.Tag = TagCustomAttribute
	decodedCustom, err := DecodeAttribute(customItem)
	if err != nil {
		t.Fatalf("custom attribute decode: %v | 自定义属性解码失败", err)
	}
	if decodedCustom.Value.Tag != 0 || decodedCustom.Name != "x-custom" {
		t.Fatalf("custom attribute = %+v | 自定义属性 = %+v", decodedCustom, decodedCustom)
	}
}

// TestDecodeAttributeValidation covers malformed Attribute structures. | TestDecodeAttributeValidation 覆盖畸形 Attribute 结构。
func TestDecodeAttributeValidation(t *testing.T) {
	cases := []struct {
		name string
		item Item
	}{
		{"wrong tag", NewStructure(TagTemplateAttribute, NewTextString(TagAttributeName, "x"), NewTextString(TagAttributeValue, "y"))},
		{"missing name", NewStructure(TagAttribute, NewTextString(TagAttributeValue, "y"))},
		{"empty value", NewStructure(TagAttribute, NewTextString(TagAttributeName, "x"))},
		{"zero value", NewStructure(TagAttribute, NewTextString(TagAttributeName, "x"), Item{Tag: TagAttributeValue})},
	}
	for _, testCase := range cases {
		if _, err := DecodeAttribute(testCase.item); err == nil {
			t.Fatalf("%s decoded without error | %s 未报错", testCase.name, testCase.name)
		}
	}
}

// TestAttributeLookups covers every lookup helper, including type mismatches. | TestAttributeLookups 覆盖所有查找辅助函数，含类型不匹配。
func TestAttributeLookups(t *testing.T) {
	list := AttributeList{
		NewTextAttribute(AttributeName, "alpha"),
		NewIntegerAttribute(AttributeCryptographicLength, 256),
		NewEnumerationAttribute(AttributeState, uint32(StateActive)),
		NewBooleanAttribute(AttributeSensitive, true),
		NewDateTimeAttribute(AttributeInitialDate, testDate()),
		NewUsageMaskAttribute(UsageMaskEncrypt),
		NewIntegerAttribute(AttributeCryptographicUsageMask, int64(UsageMaskDecrypt)),
	}
	if value, ok, err := list.LookupString(AttributeName); err != nil || !ok || value != "alpha" {
		t.Fatalf("LookupString = %q, %v, %v | LookupString = %q，%v，%v", value, ok, err, value, ok, err)
	}
	if value, ok, err := list.LookupInteger(AttributeCryptographicLength); err != nil || !ok || value != 256 {
		t.Fatalf("LookupInteger = %d, %v, %v | LookupInteger = %d，%v，%v", value, ok, err, value, ok, err)
	}
	if value, ok, err := list.LookupEnumeration(AttributeState); err != nil || !ok || State(value) != StateActive {
		t.Fatalf("LookupEnumeration = %d, %v, %v | LookupEnumeration = %d，%v，%v", value, ok, err, value, ok, err)
	}
	if value, ok, err := list.LookupBoolean(AttributeSensitive); err != nil || !ok || !value {
		t.Fatalf("LookupBoolean = %v, %v, %v | LookupBoolean = %v，%v，%v", value, ok, err, value, ok, err)
	}
	if value, ok, err := list.LookupDateTime(AttributeInitialDate); err != nil || !ok || !value.Equal(testDate()) {
		t.Fatalf("LookupDateTime = %v, %v, %v | LookupDateTime = %v，%v，%v", value, ok, err, value, ok, err)
	}
	if value, ok, err := list.LookupUsageMask(); err != nil || !ok || value != UsageMaskEncrypt {
		t.Fatalf("LookupUsageMask = %v, %v, %v | LookupUsageMask = %v，%v，%v", value, ok, err, value, ok, err)
	}
	if _, ok, err := list.LookupString(AttributeComment); ok || err != nil {
		t.Fatalf("missing lookup returned ok=%v err=%v | 缺失查找返回 ok=%v err=%v", ok, err, ok, err)
	}
	if _, _, err := list.LookupInteger(AttributeName); err == nil {
		t.Fatal("LookupInteger on text attribute did not fail | 对文本属性 LookupInteger 未失败")
	}
	if _, _, err := list.LookupString(AttributeCryptographicLength); err == nil {
		t.Fatal("LookupString on integer attribute did not fail | 对整数属性 LookupString 未失败")
	}
	if _, _, err := list.LookupEnumeration(AttributeName); err == nil {
		t.Fatal("LookupEnumeration on text attribute did not fail | 对文本属性 LookupEnumeration 未失败")
	}
	if _, _, err := list.LookupBoolean(AttributeName); err == nil {
		t.Fatal("LookupBoolean on text attribute did not fail | 对文本属性 LookupBoolean 未失败")
	}
	if _, _, err := list.LookupDateTime(AttributeName); err == nil {
		t.Fatal("LookupDateTime on text attribute did not fail | 对文本属性 LookupDateTime 未失败")
	}
	wrongMask := AttributeList{NewTextAttribute(AttributeCryptographicUsageMask, "mask")}
	if _, _, err := wrongMask.LookupUsageMask(); err == nil {
		t.Fatal("LookupUsageMask on text attribute did not fail | 对文本属性 LookupUsageMask 未失败")
	}
	enumMask := AttributeList{NewEnumerationAttribute(AttributeCryptographicUsageMask, uint32(UsageMaskSign))}
	if value, ok, err := enumMask.LookupUsageMask(); err != nil || !ok || value != UsageMaskSign {
		t.Fatalf("enumeration usage mask = %v, %v, %v | 枚举用法掩码 = %v，%v，%v", value, ok, err, value, ok, err)
	}
}

// TestAttributeNamesAndGroups covers Name and Object Group extraction. | TestAttributeNamesAndGroups 覆盖 Name 与 Object Group 提取。
func TestAttributeNamesAndGroups(t *testing.T) {
	list := AttributeList{
		NewNameAttribute(NewName("alpha")),
		NewTextAttribute(AttributeObjectGroup, "group-a"),
		NewTextAttribute(AttributeComment, "ignored"),
		NewNameAttribute(Name{Value: "https://example.test", Type: NameTypeURI}),
		NewTextAttribute(AttributeObjectGroup, "group-b"),
	}
	names, err := list.Names()
	if err != nil || len(names) != 2 || names[0].Value != "alpha" || names[1].Type != NameTypeURI {
		t.Fatalf("Names = %+v, %v | Names = %+v，%v", names, err, names, err)
	}
	groups, err := list.ObjectGroups()
	if err != nil || len(groups) != 2 || groups[0] != "group-a" || groups[1] != "group-b" {
		t.Fatalf("ObjectGroups = %v, %v | ObjectGroups = %v，%v", groups, err, groups, err)
	}
	broken := AttributeList{Attribute{Name: AttributeName, Value: NewTextString(TagName, "not-a-name")}}
	if _, err := broken.Names(); err == nil {
		t.Fatal("invalid Name value did not fail | 非法 Name 值未失败")
	}
	brokenGroup := AttributeList{Attribute{Name: AttributeObjectGroup, Value: NewInteger(TagObjectGroup, 1)}}
	if _, err := brokenGroup.ObjectGroups(); err == nil {
		t.Fatal("invalid Object Group value did not fail | 非法 Object Group 值未失败")
	}
}

// TestTemplateAttributeEncoding covers template round trips and validation. | TestTemplateAttributeEncoding 覆盖模板往返与校验。
func TestTemplateAttributeEncoding(t *testing.T) {
	template := testTemplate()
	item, err := template.Item()
	if err != nil {
		t.Fatalf("TemplateAttribute.Item: %v", err)
	}
	decoded, err := DecodeTemplateAttribute(item)
	if err != nil {
		t.Fatalf("DecodeTemplateAttribute: %v", err)
	}
	if !reflect.DeepEqual(decoded.Names, template.Names) {
		t.Fatalf("names = %+v, want %+v | 名称 = %+v，期望 %+v", decoded.Names, template.Names, decoded.Names, template.Names)
	}
	all := decoded.AllAttributes()
	if len(all) != len(template.Names)+len(template.Attributes) {
		t.Fatalf("AllAttributes length = %d | AllAttributes 长度 = %d", len(all), len(all))
	}
	names, err := all.Names()
	if err != nil || len(names) != 1 || names[0].Value != "alpha" {
		t.Fatalf("AllAttributes Names = %+v, %v | AllAttributes Names = %+v，%v", names, err, names, err)
	}
	if _, err := (TemplateAttribute{Names: []Name{{Value: ""}}}).Item(); err == nil {
		t.Fatal("empty template name encoded | 空模板名称被编码")
	}
	if _, err := DecodeTemplateAttribute(NewInteger(TagTemplateAttribute, 1)); err == nil {
		t.Fatal("non-structure template decoded | 非结构模板被解码")
	}
	if _, err := DecodeTemplateAttribute(NewStructure(TagTemplateAttribute, NewInteger(TagUniqueIdentifier, 1))); err == nil {
		t.Fatal("unexpected template child accepted | 意外模板子项被接受")
	}
}

// TestCloneAttributes verifies the copy is independent. | TestCloneAttributes 验证副本相互独立。
func TestCloneAttributes(t *testing.T) {
	if CloneAttributes(nil) != nil {
		t.Fatal("CloneAttributes(nil) is not nil | CloneAttributes(nil) 非 nil")
	}
	original := AttributeList{NewTextAttribute(AttributeComment, "one")}
	clone := CloneAttributes(original)
	clone[0].Name = AttributeDescription
	if original[0].Name != AttributeComment {
		t.Fatal("CloneAttributes aliased the original list | CloneAttributes 共享了原列表")
	}
}

// TestAttributeDateTimeTruncation documents second-level Date-Time precision. | TestAttributeDateTimeTruncation 说明 Date-Time 的秒级精度。
func TestAttributeDateTimeTruncation(t *testing.T) {
	value := time.Unix(1700000000, 500).UTC()
	attr := NewDateTimeAttribute(AttributeInitialDate, value)
	item, err := attr.Item()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := DecodeAttribute(item)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	got, ok, err := AttributeList{decoded}.LookupDateTime(AttributeInitialDate)
	if err != nil || !ok {
		t.Fatalf("lookup: ok=%v err=%v | 查找：ok=%v err=%v", ok, err, ok, err)
	}
	if got.Nanosecond() != 0 {
		t.Fatalf("decoded Date-Time kept sub-second precision: %v | 解码 Date-Time 保留了亚秒精度：%v", got.Nanosecond(), got.Nanosecond())
	}
}
