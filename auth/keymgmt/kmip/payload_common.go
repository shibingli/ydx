package kmip

import (
	"time"

	"github.com/shibingli/ydx/errs"
)

// RevocationReason is the KMIP Revocation Reason structure. | RevocationReason 是 KMIP 撤销原因结构。
type RevocationReason struct {
	// Code is the revocation reason code. | Code 是撤销原因代码。
	Code RevocationReasonCode
	// Message is an optional human-readable explanation that must not contain key material. | Message 是可选人类可读说明，绝不能包含密钥材料。
	Message string
}

// Item encodes the revocation reason. | Item 编码撤销原因。
func (r RevocationReason) Item() (Item, error) {
	if r.Code == 0 {
		return Item{}, errs.Detail(ErrInvalidRequest, "revocation reason has no code | 撤销原因没有代码")
	}
	children := []Item{NewEnumeration(TagRevocationReasonCode, uint32(r.Code))}
	if r.Message != "" {
		children = append(children, NewTextString(TagRevocationMessage, r.Message))
	}
	return NewStructure(TagRevocationReason, children...), nil
}

// DecodeRevocationReason decodes a Revocation Reason structure. | DecodeRevocationReason 解码撤销原因结构。
func DecodeRevocationReason(item Item) (RevocationReason, error) {
	if item.Type != TypeStructure || item.Tag != TagRevocationReason {
		return RevocationReason{}, errs.Detail(ErrMalformed, "expected Revocation Reason structure | 需要撤销原因结构")
	}
	codeItem, err := item.RequireChild(TagRevocationReasonCode)
	if err != nil {
		return RevocationReason{}, err
	}
	rawCode, err := codeItem.AsEnumeration()
	if err != nil {
		return RevocationReason{}, err
	}
	out := RevocationReason{Code: RevocationReasonCode(rawCode)}
	if msgItem, ok := item.Child(TagRevocationMessage); ok {
		out.Message, err = msgItem.AsTextString()
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

// DerivationParameters is the KMIP Derivation Parameters structure. | DerivationParameters 是 KMIP 派生参数结构。
type DerivationParameters struct {
	// CryptographicParameters is an optional nested Cryptographic Parameters structure. | CryptographicParameters 是可选嵌套密码参数结构。
	CryptographicParameters *CryptographicParameters
	// InitializationVector is an optional IV. | InitializationVector 是可选 IV。
	InitializationVector []byte
	// DerivationData is optional derivation data. | DerivationData 是可选派生数据。
	DerivationData []byte
	// Salt is an optional salt. | Salt 是可选盐值。
	Salt []byte
	// IterationCount is an optional iteration count. | IterationCount 是可选迭代计数。
	IterationCount int
}

// Item encodes the derivation parameters. | Item 编码派生参数。
func (p DerivationParameters) Item() Item {
	children := make([]Item, 0, 5)
	if p.CryptographicParameters != nil {
		children = append(children, p.CryptographicParameters.Item())
	}
	if len(p.InitializationVector) > 0 {
		children = append(children, NewByteString(TagInitializationVector, p.InitializationVector))
	}
	if len(p.DerivationData) > 0 {
		children = append(children, NewByteString(TagDerivationData, p.DerivationData))
	}
	if len(p.Salt) > 0 {
		children = append(children, NewByteString(TagSalt, p.Salt))
	}
	if p.IterationCount > 0 {
		children = append(children, NewInteger(TagIterationCount, int64(p.IterationCount)))
	}
	return NewStructure(TagDerivationParameters, children...)
}

// DecodeDerivationParameters decodes a Derivation Parameters structure. | DecodeDerivationParameters 解码派生参数结构。
func DecodeDerivationParameters(item Item) (DerivationParameters, error) {
	if item.Type != TypeStructure || item.Tag != TagDerivationParameters {
		return DerivationParameters{}, errs.Detail(ErrMalformed, "expected Derivation Parameters structure | 需要派生参数结构")
	}
	var out DerivationParameters
	for _, child := range item.Children {
		switch child.Tag {
		case TagCryptographicParameters:
			v, err := DecodeCryptographicParameters(child)
			if err != nil {
				return out, err
			}
			out.CryptographicParameters = &v
		case TagInitializationVector:
			v, err := child.AsByteString()
			if err != nil {
				return out, err
			}
			out.InitializationVector = append([]byte(nil), v...)
		case TagDerivationData:
			v, err := child.AsByteString()
			if err != nil {
				return out, err
			}
			out.DerivationData = append([]byte(nil), v...)
		case TagSalt:
			v, err := child.AsByteString()
			if err != nil {
				return out, err
			}
			out.Salt = append([]byte(nil), v...)
		case TagIterationCount:
			v, err := child.AsInteger()
			if err != nil {
				return out, err
			}
			if v < 0 {
				return out, errs.Detail(ErrMalformed, "negative iteration count | 迭代计数为负")
			}
			out.IterationCount = int(v)
		default:
			return out, errs.Detail(ErrMalformed, "unexpected tag 0x%06X in Derivation Parameters | 派生参数中出现意外标签 0x%06X", uint32(child.Tag), uint32(child.Tag))
		}
	}
	return out, nil
}

// payloadItem builds a structure with the supplied tag and children. | payloadItem 构造带指定标签与子项的结构。
func payloadItem(tag Tag, children ...Item) Item {
	return NewStructure(tag, children...)
}

// optionalTemplateAttribute extracts an optional Template-Attribute child with the given tag. | optionalTemplateAttribute 提取指定标签的可选 Template-Attribute 子项。
func optionalTemplateAttribute(item Item, tag Tag) (*TemplateAttribute, error) {
	child, ok := item.Child(tag)
	if !ok {
		return nil, nil
	}
	v, err := DecodeTemplateAttribute(child)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

// templateAttributeChildren appends an optional Template-Attribute with the given tag. | templateAttributeChildren 追加指定标签的可选 Template-Attribute。
func templateAttributeChildren(children []Item, tag Tag, t *TemplateAttribute) ([]Item, error) {
	if t == nil {
		return children, nil
	}
	item, err := t.Item()
	if err != nil {
		return nil, err
	}
	item.Tag = tag
	return append(children, item), nil
}

// childText reads an optional text-string child. | childText 读取可选文本字符串子项。
func childText(item Item, tag Tag) (string, error) {
	child, ok := item.Child(tag)
	if !ok {
		return "", nil
	}
	return child.AsTextString()
}

// childBytes reads an optional byte-string child, copying it. | childBytes 读取可选字节串子项并复制。
func childBytes(item Item, tag Tag) ([]byte, error) {
	child, ok := item.Child(tag)
	if !ok {
		return nil, nil
	}
	v, err := child.AsByteString()
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), v...), nil
}

// childEnumeration reads an optional enumeration child. | childEnumeration 读取可选枚举子项。
func childEnumeration(item Item, tag Tag) (uint32, error) {
	child, ok := item.Child(tag)
	if !ok {
		return 0, nil
	}
	return child.AsEnumeration()
}

// childInteger reads an optional integer child. | childInteger 读取可选整数子项。
func childInteger(item Item, tag Tag) (int64, bool, error) {
	child, ok := item.Child(tag)
	if !ok {
		return 0, false, nil
	}
	v, err := child.AsInteger()
	if err != nil {
		return 0, true, err
	}
	return v, true, nil
}

// appendText appends a text-string child when value is non-empty. | appendText 在值非空时追加文本字符串子项。
func appendText(children []Item, tag Tag, value string) []Item {
	if value == "" {
		return children
	}
	return append(children, NewTextString(tag, value))
}

// appendBytes appends a byte-string child when value is non-empty. | appendBytes 在值非空时追加字节串子项。
func appendBytes(children []Item, tag Tag, value []byte) []Item {
	if len(value) == 0 {
		return children
	}
	return append(children, NewByteString(tag, value))
}

// appendEnum appends an enumeration child when value is non-zero. | appendEnum 在值非零时追加枚举子项。
func appendEnum(children []Item, tag Tag, value uint32) []Item {
	if value == 0 {
		return children
	}
	return append(children, NewEnumeration(tag, value))
}

// appendInteger appends an integer child when value is non-zero. | appendInteger 在值非零时追加整数子项。
func appendInteger(children []Item, tag Tag, value int64) []Item {
	if value == 0 {
		return children
	}
	return append(children, NewInteger(tag, value))
}

// appendInterval appends an interval child. | appendInterval 追加间隔子项。
func appendInterval(children []Item, tag Tag, value time.Duration) []Item {
	return append(children, NewInterval(tag, value))
}

// decodeIntervalPtr decodes an optional interval pointer. | decodeIntervalPtr 解码可选间隔指针。
func decodeIntervalPtr(item Item, tag Tag) (*time.Duration, error) {
	child, ok := item.Child(tag)
	if !ok {
		return nil, nil
	}
	v, err := child.AsInterval()
	if err != nil {
		return nil, err
	}
	return &v, nil
}
