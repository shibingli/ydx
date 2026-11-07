package kmip

import "github.com/shibingli/ydx/errs"

// CryptographicParameters is the KMIP Cryptographic Parameters structure. | CryptographicParameters 是 KMIP 密码参数结构。
//
// Zero-valued optional enumerations and integers are omitted when encoding. | 编码时会省略取值为零的可选枚举与整数。
type CryptographicParameters struct {
	// BlockCipherMode is the block cipher mode. | BlockCipherMode 是分组密码模式。
	BlockCipherMode BlockCipherMode
	// PaddingMethod is the padding method. | PaddingMethod 是填充方法。
	PaddingMethod PaddingMethod
	// HashingAlgorithm is the hash algorithm. | HashingAlgorithm 是哈希算法。
	HashingAlgorithm HashingAlgorithm
	// DigitalSignatureAlgorithm is the signature algorithm. | DigitalSignatureAlgorithm 是签名算法。
	DigitalSignatureAlgorithm DigitalSignatureAlgorithm
	// CryptographicAlgorithm is an optional explicit cryptographic algorithm. | CryptographicAlgorithm 是可选显式密码算法。
	CryptographicAlgorithm CryptographicAlgorithm
	// RandomIV asks the server to generate a random IV. | RandomIV 请求服务器生成随机 IV。
	RandomIV bool
	// IVLength is the IV length in bytes. | IVLength 是 IV 长度（字节）。
	IVLength int
	// TagLength is the AEAD tag length in bytes. | TagLength 是 AEAD 标签长度（字节）。
	TagLength int
	// FixedFieldLength is the fixed field length for counter-mode constructions. | FixedFieldLength 是计数器模式的固定字段长度。
	FixedFieldLength int
	// InvocationFieldLength is the invocation field length for counter-mode constructions. | InvocationFieldLength 是计数器模式的调用字段长度。
	InvocationFieldLength int
	// CounterLength is the counter length. | CounterLength 是计数器长度。
	CounterLength int
	// InitialCounterValue is the initial counter value. | InitialCounterValue 是初始计数器值。
	InitialCounterValue int
	// SaltLength is the OAEP or PSS salt length. | SaltLength 是 OAEP 或 PSS 盐长度。
	SaltLength int
	// MaskGenerator is the mask generation function. | MaskGenerator 是掩码生成函数。
	MaskGenerator MaskGenerator
	// MaskGeneratorHashingAlgorithm is the mask generation hash algorithm. | MaskGeneratorHashingAlgorithm 是掩码生成哈希算法。
	MaskGeneratorHashingAlgorithm HashingAlgorithm
}

// Item encodes the cryptographic parameters. | Item 编码密码参数。
func (p CryptographicParameters) Item() Item {
	children := make([]Item, 0, 12)
	if p.BlockCipherMode != 0 {
		children = append(children, NewEnumeration(TagBlockCipherMode, uint32(p.BlockCipherMode)))
	}
	if p.PaddingMethod != 0 {
		children = append(children, NewEnumeration(TagPaddingMethod, uint32(p.PaddingMethod)))
	}
	if p.HashingAlgorithm != 0 {
		children = append(children, NewEnumeration(TagHashingAlgorithm, uint32(p.HashingAlgorithm)))
	}
	if p.DigitalSignatureAlgorithm != 0 {
		children = append(children, NewEnumeration(TagDigitalSignatureAlgorithm, uint32(p.DigitalSignatureAlgorithm)))
	}
	if p.CryptographicAlgorithm != 0 {
		children = append(children, NewEnumeration(TagCryptographicAlgorithm, uint32(p.CryptographicAlgorithm)))
	}
	if p.RandomIV {
		children = append(children, NewBoolean(TagRandomIV, true))
	}
	if p.IVLength > 0 {
		children = append(children, NewInteger(TagIVLength, int64(p.IVLength)))
	}
	if p.TagLength > 0 {
		children = append(children, NewInteger(TagTagLength, int64(p.TagLength)))
	}
	if p.FixedFieldLength > 0 {
		children = append(children, NewInteger(TagFixedFieldLength, int64(p.FixedFieldLength)))
	}
	if p.InvocationFieldLength > 0 {
		children = append(children, NewInteger(TagInvocationFieldLength, int64(p.InvocationFieldLength)))
	}
	if p.CounterLength > 0 {
		children = append(children, NewInteger(TagCounterLength, int64(p.CounterLength)))
	}
	if p.InitialCounterValue > 0 {
		children = append(children, NewInteger(TagInitialCounterValue, int64(p.InitialCounterValue)))
	}
	if p.SaltLength > 0 {
		children = append(children, NewInteger(TagSaltLength, int64(p.SaltLength)))
	}
	if p.MaskGenerator != 0 {
		children = append(children, NewEnumeration(TagMaskGenerator, uint32(p.MaskGenerator)))
	}
	if p.MaskGeneratorHashingAlgorithm != 0 {
		children = append(children, NewEnumeration(TagMaskGeneratorHashingAlgorithm, uint32(p.MaskGeneratorHashingAlgorithm)))
	}
	return NewStructure(TagCryptographicParameters, children...)
}

// DecodeCryptographicParameters decodes a Cryptographic Parameters structure. | DecodeCryptographicParameters 解码密码参数结构。
func DecodeCryptographicParameters(item Item) (CryptographicParameters, error) {
	if item.Type != TypeStructure || item.Tag != TagCryptographicParameters {
		return CryptographicParameters{}, errs.Detail(ErrMalformed, "expected Cryptographic Parameters structure | 需要密码参数结构")
	}
	var out CryptographicParameters
	for _, child := range item.Children {
		switch child.Tag {
		case TagBlockCipherMode:
			v, err := child.AsEnumeration()
			if err != nil {
				return out, err
			}
			out.BlockCipherMode = BlockCipherMode(v)
		case TagPaddingMethod:
			v, err := child.AsEnumeration()
			if err != nil {
				return out, err
			}
			out.PaddingMethod = PaddingMethod(v)
		case TagHashingAlgorithm:
			v, err := child.AsEnumeration()
			if err != nil {
				return out, err
			}
			out.HashingAlgorithm = HashingAlgorithm(v)
		case TagDigitalSignatureAlgorithm:
			v, err := child.AsEnumeration()
			if err != nil {
				return out, err
			}
			out.DigitalSignatureAlgorithm = DigitalSignatureAlgorithm(v)
		case TagCryptographicAlgorithm:
			v, err := child.AsEnumeration()
			if err != nil {
				return out, err
			}
			out.CryptographicAlgorithm = CryptographicAlgorithm(v)
		case TagRandomIV:
			v, err := child.AsBoolean()
			if err != nil {
				return out, err
			}
			out.RandomIV = v
		case TagIVLength:
			v, err := child.AsInteger()
			if err != nil {
				return out, err
			}
			out.IVLength = int(v)
		case TagTagLength:
			v, err := child.AsInteger()
			if err != nil {
				return out, err
			}
			out.TagLength = int(v)
		case TagFixedFieldLength:
			v, err := child.AsInteger()
			if err != nil {
				return out, err
			}
			out.FixedFieldLength = int(v)
		case TagInvocationFieldLength:
			v, err := child.AsInteger()
			if err != nil {
				return out, err
			}
			out.InvocationFieldLength = int(v)
		case TagCounterLength:
			v, err := child.AsInteger()
			if err != nil {
				return out, err
			}
			out.CounterLength = int(v)
		case TagInitialCounterValue:
			v, err := child.AsInteger()
			if err != nil {
				return out, err
			}
			out.InitialCounterValue = int(v)
		case TagSaltLength:
			v, err := child.AsInteger()
			if err != nil {
				return out, err
			}
			out.SaltLength = int(v)
		case TagMaskGenerator:
			v, err := child.AsEnumeration()
			if err != nil {
				return out, err
			}
			out.MaskGenerator = MaskGenerator(v)
		case TagMaskGeneratorHashingAlgorithm:
			v, err := child.AsEnumeration()
			if err != nil {
				return out, err
			}
			out.MaskGeneratorHashingAlgorithm = HashingAlgorithm(v)
		default:
			return out, errs.Detail(ErrMalformed, "unexpected tag 0x%06X in Cryptographic Parameters | 密码参数中出现意外标签 0x%06X", uint32(child.Tag), uint32(child.Tag))
		}
	}
	return out, nil
}

// EncryptionKeyInformation is the KMIP Encryption Key Information structure. | EncryptionKeyInformation 是 KMIP 加密密钥信息结构。
type EncryptionKeyInformation struct {
	// UniqueIdentifier identifies the wrapping key. | UniqueIdentifier 标识封装密钥。
	UniqueIdentifier string
	// CryptographicParameters holds optional wrapping parameters. | CryptographicParameters 保存可选封装参数。
	CryptographicParameters *CryptographicParameters
}

// Item encodes the encryption key information. | Item 编码加密密钥信息。
func (e EncryptionKeyInformation) Item() Item {
	children := []Item{NewTextString(TagUniqueIdentifier, e.UniqueIdentifier)}
	if e.CryptographicParameters != nil {
		children = append(children, e.CryptographicParameters.Item())
	}
	return NewStructure(TagEncryptionKeyInformation, children...)
}

// DecodeEncryptionKeyInformation decodes Encryption Key Information. | DecodeEncryptionKeyInformation 解码加密密钥信息。
func DecodeEncryptionKeyInformation(item Item) (EncryptionKeyInformation, error) {
	if item.Type != TypeStructure || item.Tag != TagEncryptionKeyInformation {
		return EncryptionKeyInformation{}, errs.Detail(ErrMalformed, "expected Encryption Key Information | 需要加密密钥信息")
	}
	idItem, err := item.RequireChild(TagUniqueIdentifier)
	if err != nil {
		return EncryptionKeyInformation{}, err
	}
	id, err := idItem.AsTextString()
	if err != nil {
		return EncryptionKeyInformation{}, err
	}
	out := EncryptionKeyInformation{UniqueIdentifier: id}
	if params, ok := item.Child(TagCryptographicParameters); ok {
		v, err := DecodeCryptographicParameters(params)
		if err != nil {
			return out, err
		}
		out.CryptographicParameters = &v
	}
	return out, nil
}

// MACSignatureKeyInformation is the KMIP MAC/Signature Key Information structure. | MACSignatureKeyInformation 是 KMIP MAC/签名密钥信息结构。
type MACSignatureKeyInformation struct {
	// UniqueIdentifier identifies the MAC or signature key. | UniqueIdentifier 标识 MAC 或签名密钥。
	UniqueIdentifier string
	// CryptographicParameters holds optional parameters. | CryptographicParameters 保存可选参数。
	CryptographicParameters *CryptographicParameters
}

// Item encodes the MAC/signature key information. | Item 编码 MAC/签名密钥信息。
func (m MACSignatureKeyInformation) Item() Item {
	children := []Item{NewTextString(TagUniqueIdentifier, m.UniqueIdentifier)}
	if m.CryptographicParameters != nil {
		children = append(children, m.CryptographicParameters.Item())
	}
	return NewStructure(TagMACSignatureKeyInformation, children...)
}

// DecodeMACSignatureKeyInformation decodes MAC/Signature Key Information. | DecodeMACSignatureKeyInformation 解码 MAC/签名密钥信息。
func DecodeMACSignatureKeyInformation(item Item) (MACSignatureKeyInformation, error) {
	if item.Type != TypeStructure || item.Tag != TagMACSignatureKeyInformation {
		return MACSignatureKeyInformation{}, errs.Detail(ErrMalformed, "expected MAC/Signature Key Information | 需要 MAC/签名密钥信息")
	}
	idItem, err := item.RequireChild(TagUniqueIdentifier)
	if err != nil {
		return MACSignatureKeyInformation{}, err
	}
	id, err := idItem.AsTextString()
	if err != nil {
		return MACSignatureKeyInformation{}, err
	}
	out := MACSignatureKeyInformation{UniqueIdentifier: id}
	if params, ok := item.Child(TagCryptographicParameters); ok {
		v, err := DecodeCryptographicParameters(params)
		if err != nil {
			return out, err
		}
		out.CryptographicParameters = &v
	}
	return out, nil
}

// KeyWrappingData is the KMIP Key Wrapping Data structure attached to a wrapped key block. | KeyWrappingData 是附加在已封装密钥块上的 KMIP 密钥封装数据结构。
type KeyWrappingData struct {
	// WrappingMethod is the wrapping method. | WrappingMethod 是封装方法。
	WrappingMethod WrappingMethod
	// EncryptionKeyInformation identifies the encryption key. | EncryptionKeyInformation 标识加密密钥。
	EncryptionKeyInformation *EncryptionKeyInformation
	// MACSignatureKeyInformation identifies the MAC or signature key. | MACSignatureKeyInformation 标识 MAC 或签名密钥。
	MACSignatureKeyInformation *MACSignatureKeyInformation
	// MACSignature is the MAC or signature value. | MACSignature 是 MAC 或签名值。
	MACSignature []byte
	// IVCounterNonce is the IV, counter or nonce. | IVCounterNonce 是 IV、计数器或随机数。
	IVCounterNonce []byte
	// EncodingOption is the wrapped key encoding option. | EncodingOption 是已封装密钥的编码选项。
	EncodingOption EncodingOption
}

// Item encodes the key wrapping data. | Item 编码密钥封装数据。
func (w KeyWrappingData) Item() (Item, error) {
	if w.WrappingMethod == 0 {
		return Item{}, errs.Detail(ErrInvalidRequest, "key wrapping data has no wrapping method | 密钥封装数据没有封装方法")
	}
	children := []Item{NewEnumeration(TagWrappingMethod, uint32(w.WrappingMethod))}
	if w.EncryptionKeyInformation != nil {
		children = append(children, w.EncryptionKeyInformation.Item())
	}
	if w.MACSignatureKeyInformation != nil {
		children = append(children, w.MACSignatureKeyInformation.Item())
	}
	if len(w.MACSignature) > 0 {
		children = append(children, NewByteString(TagMACSignature, w.MACSignature))
	}
	if len(w.IVCounterNonce) > 0 {
		children = append(children, NewByteString(TagIVCounterNonce, w.IVCounterNonce))
	}
	if w.EncodingOption != 0 {
		children = append(children, NewEnumeration(TagEncodingOption, uint32(w.EncodingOption)))
	}
	return NewStructure(TagKeyWrappingData, children...), nil
}

// DecodeKeyWrappingData decodes Key Wrapping Data. | DecodeKeyWrappingData 解码密钥封装数据。
func DecodeKeyWrappingData(item Item) (KeyWrappingData, error) {
	if item.Type != TypeStructure || item.Tag != TagKeyWrappingData {
		return KeyWrappingData{}, errs.Detail(ErrMalformed, "expected Key Wrapping Data structure | 需要密钥封装数据结构")
	}
	var out KeyWrappingData
	for _, child := range item.Children {
		switch child.Tag {
		case TagWrappingMethod:
			v, err := child.AsEnumeration()
			if err != nil {
				return out, err
			}
			out.WrappingMethod = WrappingMethod(v)
		case TagEncryptionKeyInformation:
			v, err := DecodeEncryptionKeyInformation(child)
			if err != nil {
				return out, err
			}
			out.EncryptionKeyInformation = &v
		case TagMACSignatureKeyInformation:
			v, err := DecodeMACSignatureKeyInformation(child)
			if err != nil {
				return out, err
			}
			out.MACSignatureKeyInformation = &v
		case TagMACSignature:
			v, err := child.AsByteString()
			if err != nil {
				return out, err
			}
			out.MACSignature = append([]byte(nil), v...)
		case TagIVCounterNonce:
			v, err := child.AsByteString()
			if err != nil {
				return out, err
			}
			out.IVCounterNonce = append([]byte(nil), v...)
		case TagEncodingOption:
			v, err := child.AsEnumeration()
			if err != nil {
				return out, err
			}
			out.EncodingOption = EncodingOption(v)
		default:
			return out, errs.Detail(ErrMalformed, "unexpected tag 0x%06X in Key Wrapping Data | 密钥封装数据中出现意外标签 0x%06X", uint32(child.Tag), uint32(child.Tag))
		}
	}
	if out.WrappingMethod == 0 {
		return out, errs.Detail(ErrMalformed, "Key Wrapping Data has no Wrapping Method | 密钥封装数据没有封装方法")
	}
	return out, nil
}

// KeyWrappingSpecification is the KMIP Key Wrapping Specification sent in requests. | KeyWrappingSpecification 是请求中发送的 KMIP 密钥封装规格。
type KeyWrappingSpecification struct {
	// WrappingMethod is the requested wrapping method. | WrappingMethod 是请求的封装方法。
	WrappingMethod WrappingMethod
	// EncryptionKeyInformation identifies the wrapping key. | EncryptionKeyInformation 标识封装密钥。
	EncryptionKeyInformation *EncryptionKeyInformation
	// MACSignatureKeyInformation identifies the MAC or signature key. | MACSignatureKeyInformation 标识 MAC 或签名密钥。
	MACSignatureKeyInformation *MACSignatureKeyInformation
	// AttributeNames selects attributes returned alongside the wrapped object. | AttributeNames 选择随已封装对象返回的属性。
	AttributeNames []string
	// EncodingOption is the requested encoding option. | EncodingOption 是请求的编码选项。
	EncodingOption EncodingOption
}

// Item encodes the key wrapping specification. | Item 编码密钥封装规格。
func (w KeyWrappingSpecification) Item() (Item, error) {
	if w.WrappingMethod == 0 {
		return Item{}, errs.Detail(ErrInvalidRequest, "key wrapping specification has no wrapping method | 密钥封装规格没有封装方法")
	}
	children := []Item{NewEnumeration(TagWrappingMethod, uint32(w.WrappingMethod))}
	if w.EncryptionKeyInformation != nil {
		children = append(children, w.EncryptionKeyInformation.Item())
	}
	if w.MACSignatureKeyInformation != nil {
		children = append(children, w.MACSignatureKeyInformation.Item())
	}
	for _, name := range w.AttributeNames {
		children = append(children, NewTextString(TagAttributeName, name))
	}
	if w.EncodingOption != 0 {
		children = append(children, NewEnumeration(TagEncodingOption, uint32(w.EncodingOption)))
	}
	return NewStructure(TagKeyWrappingSpecification, children...), nil
}

// DecodeKeyWrappingSpecification decodes a Key Wrapping Specification. | DecodeKeyWrappingSpecification 解码密钥封装规格。
func DecodeKeyWrappingSpecification(item Item) (KeyWrappingSpecification, error) {
	if item.Type != TypeStructure || item.Tag != TagKeyWrappingSpecification {
		return KeyWrappingSpecification{}, errs.Detail(ErrMalformed, "expected Key Wrapping Specification | 需要密钥封装规格")
	}
	var out KeyWrappingSpecification
	for _, child := range item.Children {
		switch child.Tag {
		case TagWrappingMethod:
			v, err := child.AsEnumeration()
			if err != nil {
				return out, err
			}
			out.WrappingMethod = WrappingMethod(v)
		case TagEncryptionKeyInformation:
			v, err := DecodeEncryptionKeyInformation(child)
			if err != nil {
				return out, err
			}
			out.EncryptionKeyInformation = &v
		case TagMACSignatureKeyInformation:
			v, err := DecodeMACSignatureKeyInformation(child)
			if err != nil {
				return out, err
			}
			out.MACSignatureKeyInformation = &v
		case TagAttributeName:
			v, err := child.AsTextString()
			if err != nil {
				return out, err
			}
			out.AttributeNames = append(out.AttributeNames, v)
		case TagEncodingOption:
			v, err := child.AsEnumeration()
			if err != nil {
				return out, err
			}
			out.EncodingOption = EncodingOption(v)
		default:
			return out, errs.Detail(ErrMalformed, "unexpected tag 0x%06X in Key Wrapping Specification | 密钥封装规格中出现意外标签 0x%06X", uint32(child.Tag), uint32(child.Tag))
		}
	}
	if out.WrappingMethod == 0 {
		return out, errs.Detail(ErrMalformed, "Key Wrapping Specification has no Wrapping Method | 密钥封装规格没有封装方法")
	}
	return out, nil
}
