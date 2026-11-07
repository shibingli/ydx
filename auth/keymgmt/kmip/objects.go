package kmip

import (
	"math/big"

	"github.com/shibingli/ydx/errs"
)

// TransparentSymmetricKey is the KMIP Transparent Symmetric Key structure. | TransparentSymmetricKey 是 KMIP 透明对称密钥结构。
type TransparentSymmetricKey struct {
	// Key is the raw symmetric key. | Key 是原始对称密钥。
	Key []byte
}

// Item encodes the transparent symmetric key. | Item 编码透明对称密钥。
func (k TransparentSymmetricKey) Item() Item {
	return NewStructure(TagKeyMaterial, NewByteString(TagKey, k.Key))
}

// DecodeTransparentSymmetricKey decodes a transparent symmetric key structure. | DecodeTransparentSymmetricKey 解码透明对称密钥结构。
func DecodeTransparentSymmetricKey(item Item) (TransparentSymmetricKey, error) {
	if item.Type != TypeStructure {
		return TransparentSymmetricKey{}, errs.Detail(ErrMalformed, "transparent symmetric key is not a structure | 透明对称密钥不是结构")
	}
	keyItem, err := item.RequireChild(TagKey)
	if err != nil {
		return TransparentSymmetricKey{}, err
	}
	key, err := keyItem.AsByteString()
	if err != nil {
		return TransparentSymmetricKey{}, err
	}
	return TransparentSymmetricKey{Key: append([]byte(nil), key...)}, nil
}

// TransparentRSAPublicKey is the KMIP Transparent RSA Public Key structure. | TransparentRSAPublicKey 是 KMIP 透明 RSA 公钥结构。
type TransparentRSAPublicKey struct {
	// Modulus is the RSA modulus n. | Modulus 是 RSA 模数 n。
	Modulus *big.Int
	// PublicExponent is the RSA public exponent e. | PublicExponent 是 RSA 公开指数 e。
	PublicExponent *big.Int
}

// Item encodes the transparent RSA public key. | Item 编码透明 RSA 公钥。
func (k TransparentRSAPublicKey) Item() Item {
	return NewStructure(TagKeyMaterial,
		NewBigInteger(TagModulus, k.Modulus),
		NewBigInteger(TagPublicExponent, k.PublicExponent),
	)
}

// DecodeTransparentRSAPublicKey decodes a transparent RSA public key structure. | DecodeTransparentRSAPublicKey 解码透明 RSA 公钥结构。
func DecodeTransparentRSAPublicKey(item Item) (TransparentRSAPublicKey, error) {
	if item.Type != TypeStructure {
		return TransparentRSAPublicKey{}, errs.Detail(ErrMalformed, "transparent RSA public key is not a structure | 透明 RSA 公钥不是结构")
	}
	nItem, err := item.RequireChild(TagModulus)
	if err != nil {
		return TransparentRSAPublicKey{}, err
	}
	eItem, err := item.RequireChild(TagPublicExponent)
	if err != nil {
		return TransparentRSAPublicKey{}, err
	}
	n, err := nItem.AsBigInteger()
	if err != nil {
		return TransparentRSAPublicKey{}, err
	}
	e, err := eItem.AsBigInteger()
	if err != nil {
		return TransparentRSAPublicKey{}, err
	}
	return TransparentRSAPublicKey{Modulus: n, PublicExponent: e}, nil
}

// TransparentRSAPrivateKey is the KMIP Transparent RSA Private Key structure. | TransparentRSAPrivateKey 是 KMIP 透明 RSA 私钥结构。
type TransparentRSAPrivateKey struct {
	// Modulus is n. | Modulus 是 n。
	Modulus *big.Int
	// PrivateExponent is d. | PrivateExponent 是 d。
	PrivateExponent *big.Int
	// PublicExponent is e. | PublicExponent 是 e。
	PublicExponent *big.Int
	// P is the first prime factor. | P 是第一个素因子。
	P *big.Int
	// Q is the second prime factor. | Q 是第二个素因子。
	Q *big.Int
	// PrimeExponentP is d mod (p-1). | PrimeExponentP 是 d mod (p-1)。
	PrimeExponentP *big.Int
	// PrimeExponentQ is d mod (q-1). | PrimeExponentQ 是 d mod (q-1)。
	PrimeExponentQ *big.Int
	// CRTCoefficient is q^-1 mod p. | CRTCoefficient 是 q^-1 mod p。
	CRTCoefficient *big.Int
}

// Item encodes the transparent RSA private key. | Item 编码透明 RSA 私钥。
func (k TransparentRSAPrivateKey) Item() Item {
	children := []Item{
		NewBigInteger(TagModulus, k.Modulus),
		NewBigInteger(TagPrivateExponent, k.PrivateExponent),
		NewBigInteger(TagPublicExponent, k.PublicExponent),
	}
	if k.P != nil {
		children = append(children, NewBigInteger(TagP, k.P))
	}
	if k.Q != nil {
		children = append(children, NewBigInteger(TagQ, k.Q))
	}
	if k.PrimeExponentP != nil {
		children = append(children, NewBigInteger(TagPrimeExponentP, k.PrimeExponentP))
	}
	if k.PrimeExponentQ != nil {
		children = append(children, NewBigInteger(TagPrimeExponentQ, k.PrimeExponentQ))
	}
	if k.CRTCoefficient != nil {
		children = append(children, NewBigInteger(TagCRTCoefficient, k.CRTCoefficient))
	}
	return NewStructure(TagKeyMaterial, children...)
}

// DecodeTransparentRSAPrivateKey decodes a transparent RSA private key structure. | DecodeTransparentRSAPrivateKey 解码透明 RSA 私钥结构。
func DecodeTransparentRSAPrivateKey(item Item) (TransparentRSAPrivateKey, error) {
	if item.Type != TypeStructure {
		return TransparentRSAPrivateKey{}, errs.Detail(ErrMalformed, "transparent RSA private key is not a structure | 透明 RSA 私钥不是结构")
	}
	read := func(tag Tag, required bool) (*big.Int, error) {
		child, ok := item.Child(tag)
		if !ok {
			if required {
				return nil, errs.Detail(ErrMalformed, "missing tag 0x%06X in transparent RSA private key | 透明 RSA 私钥缺少标签 0x%06X", uint32(tag), uint32(tag))
			}
			return nil, nil
		}
		return child.AsBigInteger()
	}
	var out TransparentRSAPrivateKey
	var err error
	if out.Modulus, err = read(TagModulus, true); err != nil {
		return out, err
	}
	if out.PrivateExponent, err = read(TagPrivateExponent, true); err != nil {
		return out, err
	}
	if out.PublicExponent, err = read(TagPublicExponent, true); err != nil {
		return out, err
	}
	if out.P, err = read(TagP, false); err != nil {
		return out, err
	}
	if out.Q, err = read(TagQ, false); err != nil {
		return out, err
	}
	if out.PrimeExponentP, err = read(TagPrimeExponentP, false); err != nil {
		return out, err
	}
	if out.PrimeExponentQ, err = read(TagPrimeExponentQ, false); err != nil {
		return out, err
	}
	if out.CRTCoefficient, err = read(TagCRTCoefficient, false); err != nil {
		return out, err
	}
	return out, nil
}

// TransparentECPrivateKey is the KMIP Transparent EC Private Key structure. | TransparentECPrivateKey 是 KMIP 透明 EC 私钥结构。
type TransparentECPrivateKey struct {
	// RecommendedCurve identifies the curve. | RecommendedCurve 标识曲线。
	RecommendedCurve RecommendedCurve
	// D is the private scalar. | D 是私有标量。
	D *big.Int
}

// Item encodes the transparent EC private key. | Item 编码透明 EC 私钥。
func (k TransparentECPrivateKey) Item() Item {
	return NewStructure(TagKeyMaterial,
		NewEnumeration(TagRecommendedCurve, uint32(k.RecommendedCurve)),
		NewBigInteger(TagD, k.D),
	)
}

// DecodeTransparentECPrivateKey decodes a transparent EC private key structure. | DecodeTransparentECPrivateKey 解码透明 EC 私钥结构。
func DecodeTransparentECPrivateKey(item Item) (TransparentECPrivateKey, error) {
	if item.Type != TypeStructure {
		return TransparentECPrivateKey{}, errs.Detail(ErrMalformed, "transparent EC private key is not a structure | 透明 EC 私钥不是结构")
	}
	curveItem, err := item.RequireChild(TagRecommendedCurve)
	if err != nil {
		return TransparentECPrivateKey{}, err
	}
	rawCurve, err := curveItem.AsEnumeration()
	if err != nil {
		return TransparentECPrivateKey{}, err
	}
	dItem, err := item.RequireChild(TagD)
	if err != nil {
		return TransparentECPrivateKey{}, err
	}
	d, err := dItem.AsBigInteger()
	if err != nil {
		return TransparentECPrivateKey{}, err
	}
	return TransparentECPrivateKey{RecommendedCurve: RecommendedCurve(rawCurve), D: d}, nil
}

// TransparentECPublicKey is the KMIP Transparent EC Public Key structure. | TransparentECPublicKey 是 KMIP 透明 EC 公钥结构。
type TransparentECPublicKey struct {
	// RecommendedCurve identifies the curve. | RecommendedCurve 标识曲线。
	RecommendedCurve RecommendedCurve
	// Q is the uncompressed or compressed point encoding. | Q 是未压缩或压缩点编码。
	Q []byte
}

// Item encodes the transparent EC public key. | Item 编码透明 EC 公钥。
func (k TransparentECPublicKey) Item() Item {
	return NewStructure(TagKeyMaterial,
		NewEnumeration(TagRecommendedCurve, uint32(k.RecommendedCurve)),
		NewByteString(TagQString, k.Q),
	)
}

// DecodeTransparentECPublicKey decodes a transparent EC public key structure. | DecodeTransparentECPublicKey 解码透明 EC 公钥结构。
func DecodeTransparentECPublicKey(item Item) (TransparentECPublicKey, error) {
	if item.Type != TypeStructure {
		return TransparentECPublicKey{}, errs.Detail(ErrMalformed, "transparent EC public key is not a structure | 透明 EC 公钥不是结构")
	}
	curveItem, err := item.RequireChild(TagRecommendedCurve)
	if err != nil {
		return TransparentECPublicKey{}, err
	}
	rawCurve, err := curveItem.AsEnumeration()
	if err != nil {
		return TransparentECPublicKey{}, err
	}
	qItem, err := item.RequireChild(TagQString)
	if err != nil {
		return TransparentECPublicKey{}, err
	}
	q, err := qItem.AsByteString()
	if err != nil {
		return TransparentECPublicKey{}, err
	}
	return TransparentECPublicKey{RecommendedCurve: RecommendedCurve(rawCurve), Q: append([]byte(nil), q...)}, nil
}

// KeyValue is the KMIP Key Value structure. | KeyValue 是 KMIP Key Value 结构。
type KeyValue struct {
	// Material is a TagKeyMaterial item, either a Byte String for encoded formats or a Structure for transparent formats. | Material 是 TagKeyMaterial 项：编码格式为字节串，透明格式为结构。
	Material Item
	// Attributes holds the attributes embedded in the key value. | Attributes 保存密钥值中内嵌的属性。
	Attributes AttributeList
}

// NewRawKeyValue builds a Key Value whose material is a raw byte string. | NewRawKeyValue 构造材料为原始字节串的 Key Value。
func NewRawKeyValue(material []byte) KeyValue {
	return KeyValue{Material: NewByteString(TagKeyMaterial, material)}
}

// Item encodes the key value as a KMIP Key Value structure. | Item 把密钥值编码为 KMIP Key Value 结构。
func (kv KeyValue) Item() (Item, error) {
	material := kv.Material
	if material.Tag == 0 {
		material.Tag = TagKeyMaterial
	}
	if material.Tag != TagKeyMaterial || material.Type == 0 {
		return Item{}, errs.Detail(ErrInvalidRequest, "key value has no key material | 密钥值没有密钥材料")
	}
	children := make([]Item, 0, 1+len(kv.Attributes))
	children = append(children, material)
	for _, attr := range kv.Attributes {
		item, err := attr.Item()
		if err != nil {
			return Item{}, err
		}
		children = append(children, item)
	}
	return NewStructure(TagKeyValue, children...), nil
}

// DecodeKeyValue decodes a KMIP Key Value structure. | DecodeKeyValue 解码 KMIP Key Value 结构。
func DecodeKeyValue(item Item) (KeyValue, error) {
	if item.Type != TypeStructure || item.Tag != TagKeyValue {
		return KeyValue{}, errs.Detail(ErrMalformed, "expected Key Value structure | 需要 Key Value 结构")
	}
	var out KeyValue
	for _, child := range item.Children {
		switch child.Tag {
		case TagKeyMaterial:
			out.Material = child
		case TagAttribute, TagCustomAttribute:
			attr, err := DecodeAttribute(child)
			if err != nil {
				return KeyValue{}, err
			}
			out.Attributes = append(out.Attributes, attr)
		default:
			return KeyValue{}, errs.Detail(ErrMalformed, "unexpected tag 0x%06X in Key Value | Key Value 中出现意外标签 0x%06X", uint32(child.Tag), uint32(child.Tag))
		}
	}
	if out.Material.Tag == 0 {
		return KeyValue{}, errs.Detail(ErrMalformed, "Key Value has no Key Material | Key Value 没有 Key Material")
	}
	return out, nil
}

// Raw returns the material bytes of an encoded key format. | Raw 返回编码格式密钥的字节。
func (kv KeyValue) Raw() ([]byte, error) {
	if kv.Material.Type != TypeByteString {
		return nil, errs.Detail(ErrUnsupported, "key material is not a byte string | 密钥材料不是字节串")
	}
	return kv.Material.Value, nil
}

// Symmetric returns the symmetric key bytes, accepting Raw and Transparent Symmetric Key formats. | Symmetric 返回对称密钥字节，接受 Raw 与 Transparent Symmetric Key 格式。
func (kv KeyValue) Symmetric() ([]byte, error) {
	if kv.Material.Type == TypeByteString {
		return kv.Material.Value, nil
	}
	if kv.Material.Type == TypeStructure {
		key, err := DecodeTransparentSymmetricKey(kv.Material)
		if err != nil {
			return nil, err
		}
		return key.Key, nil
	}
	return nil, errs.Detail(ErrUnsupported, "unsupported symmetric key material type %s | 不支持的对称密钥材料类型 %s", kv.Material.Type, kv.Material.Type)
}

// KeyBlock is the KMIP Key Block structure. | KeyBlock 是 KMIP Key Block 结构。
type KeyBlock struct {
	// Format is the key format type. | Format 是密钥格式类型。
	Format KeyFormatType
	// Compression is the optional key compression type. | Compression 是可选密钥压缩类型。
	Compression KeyCompressionType
	// Value holds the key value. | Value 保存密钥值。
	Value KeyValue
	// Algorithm is the optional cryptographic algorithm. | Algorithm 是可选密码算法。
	Algorithm CryptographicAlgorithm
	// Length is the optional cryptographic length in bits. | Length 是可选密码长度（位）。
	Length int
	// Wrapping holds optional key wrapping data. | Wrapping 保存可选密钥封装数据。
	Wrapping *KeyWrappingData
}

// Item encodes the key block. | Item 编码密钥块。
func (kb KeyBlock) Item() (Item, error) {
	if kb.Format == 0 {
		return Item{}, errs.Detail(ErrInvalidRequest, "key block has no key format type | 密钥块没有密钥格式类型")
	}
	value, err := kb.Value.Item()
	if err != nil {
		return Item{}, err
	}
	children := []Item{
		NewEnumeration(TagKeyFormatType, uint32(kb.Format)),
	}
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

// DecodeKeyBlock decodes a KMIP Key Block structure. | DecodeKeyBlock 解码 KMIP Key Block 结构。
func DecodeKeyBlock(item Item) (KeyBlock, error) {
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
			v, err := DecodeKeyValue(child)
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
			return KeyBlock{}, errs.Detail(ErrMalformed, "unexpected tag 0x%06X in Key Block | Key Block 中出现意外标签 0x%06X", uint32(child.Tag), uint32(child.Tag))
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

// SymmetricKeyObject is a KMIP Symmetric Key managed object. | SymmetricKeyObject 是 KMIP 对称密钥受管对象。
type SymmetricKeyObject struct {
	// KeyBlock is the key block. | KeyBlock 是密钥块。
	KeyBlock KeyBlock
}

// ObjectType returns ObjectTypeSymmetricKey. | ObjectType 返回 ObjectTypeSymmetricKey。
func (o *SymmetricKeyObject) ObjectType() ObjectType { return ObjectTypeSymmetricKey }

// PublicKeyObject is a KMIP Public Key managed object. | PublicKeyObject 是 KMIP 公钥受管对象。
type PublicKeyObject struct {
	// KeyBlock is the key block. | KeyBlock 是密钥块。
	KeyBlock KeyBlock
}

// ObjectType returns ObjectTypePublicKey. | ObjectType 返回 ObjectTypePublicKey。
func (o *PublicKeyObject) ObjectType() ObjectType { return ObjectTypePublicKey }

// PrivateKeyObject is a KMIP Private Key managed object. | PrivateKeyObject 是 KMIP 私钥受管对象。
type PrivateKeyObject struct {
	// KeyBlock is the key block. | KeyBlock 是密钥块。
	KeyBlock KeyBlock
}

// ObjectType returns ObjectTypePrivateKey. | ObjectType 返回 ObjectTypePrivateKey。
func (o *PrivateKeyObject) ObjectType() ObjectType { return ObjectTypePrivateKey }

// SecretDataObject is a KMIP Secret Data managed object. | SecretDataObject 是 KMIP 秘密数据受管对象。
type SecretDataObject struct {
	// SecretDataType is the secret data type. | SecretDataType 是秘密数据类型。
	SecretDataType SecretDataType
	// KeyBlock is the key block. | KeyBlock 是密钥块。
	KeyBlock KeyBlock
}

// ObjectType returns ObjectTypeSecretData. | ObjectType 返回 ObjectTypeSecretData。
func (o *SecretDataObject) ObjectType() ObjectType { return ObjectTypeSecretData }

// CertificateObject is a KMIP Certificate managed object. | CertificateObject 是 KMIP 证书受管对象。
type CertificateObject struct {
	// CertificateType is the certificate type. | CertificateType 是证书类型。
	CertificateType CertificateType
	// CertificateValue is the DER or PGP certificate bytes. | CertificateValue 是 DER 或 PGP 证书字节。
	CertificateValue []byte
}

// ObjectType returns ObjectTypeCertificate. | ObjectType 返回 ObjectTypeCertificate。
func (o *CertificateObject) ObjectType() ObjectType { return ObjectTypeCertificate }

// TemplateObject is a KMIP Template managed object. | TemplateObject 是 KMIP 模板受管对象。
type TemplateObject struct {
	// Attributes holds the template attributes. | Attributes 保存模板属性。
	Attributes AttributeList
}

// ObjectType returns ObjectTypeTemplate. | ObjectType 返回 ObjectTypeTemplate。
func (o *TemplateObject) ObjectType() ObjectType { return ObjectTypeTemplate }

// OpaqueObject is a KMIP Opaque Object managed object. | OpaqueObject 是 KMIP 不透明对象受管对象。
type OpaqueObject struct {
	// OpaqueDataType is the vendor-defined opaque data type. | OpaqueDataType 是厂商定义的不透明数据类型。
	OpaqueDataType uint32
	// OpaqueDataValue is the opaque payload. | OpaqueDataValue 是不透明负载。
	OpaqueDataValue []byte
}

// ObjectType returns ObjectTypeOpaqueObject. | ObjectType 返回 ObjectTypeOpaqueObject。
func (o *OpaqueObject) ObjectType() ObjectType { return ObjectTypeOpaqueObject }

// ManagedObject is a KMIP managed object. | ManagedObject 是 KMIP 受管对象。
type ManagedObject interface {
	// ObjectType returns the managed object type. | ObjectType 返回受管对象类型。
	ObjectType() ObjectType
}

// Object is a KMIP managed object union. The Type field selects the populated member. | Object 是 KMIP 受管对象联合体；Type 字段选择已填充的成员。
type Object struct {
	// Type is the managed object type. | Type 是受管对象类型。
	Type ObjectType
	// SymmetricKey is set when Type is ObjectTypeSymmetricKey. | 当 Type 为 ObjectTypeSymmetricKey 时 SymmetricKey 非空。
	SymmetricKey *SymmetricKeyObject
	// PublicKey is set when Type is ObjectTypePublicKey. | 当 Type 为 ObjectTypePublicKey 时 PublicKey 非空。
	PublicKey *PublicKeyObject
	// PrivateKey is set when Type is ObjectTypePrivateKey. | 当 Type 为 ObjectTypePrivateKey 时 PrivateKey 非空。
	PrivateKey *PrivateKeyObject
	// SecretData is set when Type is ObjectTypeSecretData. | 当 Type 为 ObjectTypeSecretData 时 SecretData 非空。
	SecretData *SecretDataObject
	// Certificate is set when Type is ObjectTypeCertificate. | 当 Type 为 ObjectTypeCertificate 时 Certificate 非空。
	Certificate *CertificateObject
	// Template is set when Type is ObjectTypeTemplate. | 当 Type 为 ObjectTypeTemplate 时 Template 非空。
	Template *TemplateObject
	// Opaque is set when Type is ObjectTypeOpaqueObject. | 当 Type 为 ObjectTypeOpaqueObject 时 Opaque 非空。
	Opaque *OpaqueObject
}

// NewSymmetricKeyObject wraps a key block in a Symmetric Key object. | NewSymmetricKeyObject 把密钥块包装为对称密钥对象。
func NewSymmetricKeyObject(kb KeyBlock) Object {
	return Object{Type: ObjectTypeSymmetricKey, SymmetricKey: &SymmetricKeyObject{KeyBlock: kb}}
}

// NewPublicKeyObject wraps a key block in a Public Key object. | NewPublicKeyObject 把密钥块包装为公钥对象。
func NewPublicKeyObject(kb KeyBlock) Object {
	return Object{Type: ObjectTypePublicKey, PublicKey: &PublicKeyObject{KeyBlock: kb}}
}

// NewPrivateKeyObject wraps a key block in a Private Key object. | NewPrivateKeyObject 把密钥块包装为私钥对象。
func NewPrivateKeyObject(kb KeyBlock) Object {
	return Object{Type: ObjectTypePrivateKey, PrivateKey: &PrivateKeyObject{KeyBlock: kb}}
}

// NewSecretDataObject wraps a key block in a Secret Data object. | NewSecretDataObject 把密钥块包装为秘密数据对象。
func NewSecretDataObject(typ SecretDataType, kb KeyBlock) Object {
	return Object{Type: ObjectTypeSecretData, SecretData: &SecretDataObject{SecretDataType: typ, KeyBlock: kb}}
}

// NewCertificateObject wraps certificate bytes in a Certificate object. | NewCertificateObject 把证书字节包装为证书对象。
func NewCertificateObject(typ CertificateType, der []byte) Object {
	return Object{Type: ObjectTypeCertificate, Certificate: &CertificateObject{CertificateType: typ, CertificateValue: append([]byte(nil), der...)}}
}

// NewTemplateObject wraps attributes in a Template object. | NewTemplateObject 把属性包装为模板对象。
func NewTemplateObject(attrs AttributeList) Object {
	return Object{Type: ObjectTypeTemplate, Template: &TemplateObject{Attributes: CloneAttributes(attrs)}}
}

// NewOpaqueObject wraps vendor bytes in an Opaque Object. | NewOpaqueObject 把厂商字节包装为不透明对象。
func NewOpaqueObject(typ uint32, value []byte) Object {
	return Object{Type: ObjectTypeOpaqueObject, Opaque: &OpaqueObject{OpaqueDataType: typ, OpaqueDataValue: append([]byte(nil), value...)}}
}

// Managed returns the managed object selected by Type. | Managed 返回由 Type 选择的受管对象。
func (o Object) Managed() (ManagedObject, error) {
	switch o.Type {
	case ObjectTypeSymmetricKey:
		if o.SymmetricKey == nil {
			break
		}
		return o.SymmetricKey, nil
	case ObjectTypePublicKey:
		if o.PublicKey == nil {
			break
		}
		return o.PublicKey, nil
	case ObjectTypePrivateKey:
		if o.PrivateKey == nil {
			break
		}
		return o.PrivateKey, nil
	case ObjectTypeSecretData:
		if o.SecretData == nil {
			break
		}
		return o.SecretData, nil
	case ObjectTypeCertificate:
		if o.Certificate == nil {
			break
		}
		return o.Certificate, nil
	case ObjectTypeTemplate:
		if o.Template == nil {
			break
		}
		return o.Template, nil
	case ObjectTypeOpaqueObject:
		if o.Opaque == nil {
			break
		}
		return o.Opaque, nil
	}
	return nil, errs.Detail(ErrInvalidRequest, "object type %s has no matching value | 对象类型 %s 没有匹配的值", o.Type, o.Type)
}

// KeyBlock returns the key block of a cryptographic object. | KeyBlock 返回密码对象的密钥块。
func (o Object) KeyBlock() (*KeyBlock, error) {
	switch o.Type {
	case ObjectTypeSymmetricKey:
		if o.SymmetricKey != nil {
			return &o.SymmetricKey.KeyBlock, nil
		}
	case ObjectTypePublicKey:
		if o.PublicKey != nil {
			return &o.PublicKey.KeyBlock, nil
		}
	case ObjectTypePrivateKey:
		if o.PrivateKey != nil {
			return &o.PrivateKey.KeyBlock, nil
		}
	case ObjectTypeSecretData:
		if o.SecretData != nil {
			return &o.SecretData.KeyBlock, nil
		}
	}
	return nil, errs.Detail(ErrInvalidRequest, "object type %s has no key block | 对象类型 %s 没有密钥块", o.Type, o.Type)
}

// Attributes returns the attributes embedded in the object's key value, or the template attributes. | Attributes 返回对象密钥值中内嵌的属性，或模板属性。
func (o Object) Attributes() AttributeList {
	switch o.Type {
	case ObjectTypeSymmetricKey:
		if o.SymmetricKey != nil {
			return o.SymmetricKey.KeyBlock.Value.Attributes
		}
	case ObjectTypePublicKey:
		if o.PublicKey != nil {
			return o.PublicKey.KeyBlock.Value.Attributes
		}
	case ObjectTypePrivateKey:
		if o.PrivateKey != nil {
			return o.PrivateKey.KeyBlock.Value.Attributes
		}
	case ObjectTypeSecretData:
		if o.SecretData != nil {
			return o.SecretData.KeyBlock.Value.Attributes
		}
	case ObjectTypeTemplate:
		if o.Template != nil {
			return o.Template.Attributes
		}
	}
	return nil
}

// Item encodes the managed object with its KMIP tag. | Item 使用 KMIP 标签编码受管对象。
func (o Object) Item() (Item, error) {
	switch o.Type {
	case ObjectTypeSymmetricKey:
		if o.SymmetricKey == nil {
			break
		}
		kb, err := o.SymmetricKey.KeyBlock.Item()
		if err != nil {
			return Item{}, err
		}
		return NewStructure(TagSymmetricKey, kb), nil
	case ObjectTypePublicKey:
		if o.PublicKey == nil {
			break
		}
		kb, err := o.PublicKey.KeyBlock.Item()
		if err != nil {
			return Item{}, err
		}
		return NewStructure(TagPublicKey, kb), nil
	case ObjectTypePrivateKey:
		if o.PrivateKey == nil {
			break
		}
		kb, err := o.PrivateKey.KeyBlock.Item()
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
		kb, err := o.SecretData.KeyBlock.Item()
		if err != nil {
			return Item{}, err
		}
		return NewStructure(TagSecretData,
			NewEnumeration(TagSecretDataType, uint32(typ)),
			kb,
		), nil
	case ObjectTypeCertificate:
		if o.Certificate == nil {
			break
		}
		typ := o.Certificate.CertificateType
		if typ == 0 {
			typ = CertificateTypeX509
		}
		return NewStructure(TagCertificate,
			NewEnumeration(TagCertificateType, uint32(typ)),
			NewByteString(TagCertificateValue, o.Certificate.CertificateValue),
		), nil
	case ObjectTypeTemplate:
		if o.Template == nil {
			break
		}
		children := make([]Item, 0, len(o.Template.Attributes))
		for _, attr := range o.Template.Attributes {
			item, err := attr.Item()
			if err != nil {
				return Item{}, err
			}
			children = append(children, item)
		}
		return NewStructure(TagTemplate, children...), nil
	case ObjectTypeOpaqueObject:
		if o.Opaque == nil {
			break
		}
		return NewStructure(TagOpaqueObject,
			NewEnumeration(TagOpaqueDataType, o.Opaque.OpaqueDataType),
			NewByteString(TagOpaqueDataValue, o.Opaque.OpaqueDataValue),
		), nil
	}
	return Item{}, errs.Detail(ErrInvalidRequest, "object type %s has no matching value | 对象类型 %s 没有匹配的值", o.Type, o.Type)
}

// DecodeObject decodes a managed object from its KMIP structure. | DecodeObject 从 KMIP 结构解码受管对象。
func DecodeObject(item Item) (Object, error) {
	if item.Type != TypeStructure {
		return Object{}, errs.Detail(ErrMalformed, "managed object is not a structure | 受管对象不是结构")
	}
	switch item.Tag {
	case TagSymmetricKey:
		kbItem, err := item.RequireChild(TagKeyBlock)
		if err != nil {
			return Object{}, err
		}
		kb, err := DecodeKeyBlock(kbItem)
		if err != nil {
			return Object{}, err
		}
		return NewSymmetricKeyObject(kb), nil
	case TagPublicKey:
		kbItem, err := item.RequireChild(TagKeyBlock)
		if err != nil {
			return Object{}, err
		}
		kb, err := DecodeKeyBlock(kbItem)
		if err != nil {
			return Object{}, err
		}
		return NewPublicKeyObject(kb), nil
	case TagPrivateKey:
		kbItem, err := item.RequireChild(TagKeyBlock)
		if err != nil {
			return Object{}, err
		}
		kb, err := DecodeKeyBlock(kbItem)
		if err != nil {
			return Object{}, err
		}
		return NewPrivateKeyObject(kb), nil
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
		kb, err := DecodeKeyBlock(kbItem)
		if err != nil {
			return Object{}, err
		}
		return NewSecretDataObject(SecretDataType(rawType), kb), nil
	case TagCertificate:
		typeItem, err := item.RequireChild(TagCertificateType)
		if err != nil {
			return Object{}, err
		}
		rawType, err := typeItem.AsEnumeration()
		if err != nil {
			return Object{}, err
		}
		valueItem, err := item.RequireChild(TagCertificateValue)
		if err != nil {
			return Object{}, err
		}
		value, err := valueItem.AsByteString()
		if err != nil {
			return Object{}, err
		}
		return NewCertificateObject(CertificateType(rawType), value), nil
	case TagTemplate:
		var attrs AttributeList
		for _, child := range item.Children {
			attr, err := DecodeAttribute(child)
			if err != nil {
				return Object{}, err
			}
			attrs = append(attrs, attr)
		}
		return NewTemplateObject(attrs), nil
	case TagOpaqueObject:
		typeItem, err := item.RequireChild(TagOpaqueDataType)
		if err != nil {
			return Object{}, err
		}
		rawType, err := typeItem.AsEnumeration()
		if err != nil {
			return Object{}, err
		}
		valueItem, err := item.RequireChild(TagOpaqueDataValue)
		if err != nil {
			return Object{}, err
		}
		value, err := valueItem.AsByteString()
		if err != nil {
			return Object{}, err
		}
		return NewOpaqueObject(rawType, value), nil
	default:
		return Object{}, errs.Detail(ErrUnsupported, "unsupported managed object tag 0x%06X | 不支持的受管对象标签 0x%06X", uint32(item.Tag), uint32(item.Tag))
	}
}

// Zeroize clears sensitive key material held by the object. | Zeroize 清除对象持有的敏感密钥材料。
func (o *Object) Zeroize() {
	if o == nil {
		return
	}
	if kb, err := o.KeyBlock(); err == nil {
		zeroizeKeyBlock(kb)
	}
	if o.Certificate != nil {
		zeroize(o.Certificate.CertificateValue)
	}
	if o.Opaque != nil {
		zeroize(o.Opaque.OpaqueDataValue)
	}
}

// zeroizeKeyBlock clears key material bytes in a key block. | zeroizeKeyBlock 清除密钥块中的密钥材料字节。
func zeroizeKeyBlock(kb *KeyBlock) {
	if kb == nil {
		return
	}
	zeroizeItemMaterial(&kb.Value.Material)
	if kb.Wrapping != nil {
		zeroize(kb.Wrapping.MACSignature)
		zeroize(kb.Wrapping.IVCounterNonce)
	}
}

// zeroizeItemMaterial clears byte-string material and transparent component bytes. | zeroizeItemMaterial 清除字节串材料与透明分量字节。
func zeroizeItemMaterial(item *Item) {
	if item == nil {
		return
	}
	zeroize(item.Value)
	for i := range item.Children {
		zeroizeItemMaterial(&item.Children[i])
	}
}
