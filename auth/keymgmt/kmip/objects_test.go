package kmip

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

// TestTransparentSymmetricKey covers transparent symmetric key round trips. | TestTransparentSymmetricKey 覆盖透明对称密钥往返。
func TestTransparentSymmetricKey(t *testing.T) {
	key := TransparentSymmetricKey{Key: []byte{1, 2, 3, 4}}
	decoded, err := DecodeTransparentSymmetricKey(key.Item())
	if err != nil {
		t.Fatalf("DecodeTransparentSymmetricKey: %v", err)
	}
	if !bytes.Equal(decoded.Key, key.Key) {
		t.Fatalf("decoded key = %x | 解码密钥 = %x", decoded.Key, decoded.Key)
	}
	if _, err := DecodeTransparentSymmetricKey(NewInteger(TagKeyMaterial, 1)); err == nil {
		t.Fatal("non-structure decoded without error | 非结构未报错")
	}
	if _, err := DecodeTransparentSymmetricKey(NewStructure(TagKeyMaterial, NewTextString(TagKey, "x"))); err == nil {
		t.Fatal("mistyped key accepted | 类型错误密钥被接受")
	}
}

// TestTransparentRSAKeys covers transparent RSA public and private keys. | TestTransparentRSAKeys 覆盖透明 RSA 公钥与私钥。
func TestTransparentRSAKeys(t *testing.T) {
	public := TransparentRSAPublicKey{Modulus: bigInt(3233), PublicExponent: bigInt(17)}
	decodedPublic, err := DecodeTransparentRSAPublicKey(public.Item())
	if err != nil {
		t.Fatalf("DecodeTransparentRSAPublicKey: %v", err)
	}
	if !reflect.DeepEqual(decodedPublic, public) {
		t.Fatalf("public key = %+v, want %+v | 公钥 = %+v，期望 %+v", decodedPublic, public, decodedPublic, public)
	}
	private := TransparentRSAPrivateKey{
		Modulus:         bigInt(3233),
		PrivateExponent: bigInt(2753),
		PublicExponent:  bigInt(17),
		P:               bigInt(61),
		Q:               bigInt(53),
		PrimeExponentP:  bigInt(53),
		PrimeExponentQ:  bigInt(49),
		CRTCoefficient:  bigInt(38),
	}
	decodedPrivate, err := DecodeTransparentRSAPrivateKey(private.Item())
	if err != nil {
		t.Fatalf("DecodeTransparentRSAPrivateKey: %v", err)
	}
	if !reflect.DeepEqual(decodedPrivate, private) {
		t.Fatalf("private key = %+v, want %+v | 私钥 = %+v，期望 %+v", decodedPrivate, private, decodedPrivate, private)
	}
	minimal := TransparentRSAPrivateKey{Modulus: bigInt(3233), PrivateExponent: bigInt(2753), PublicExponent: bigInt(17)}
	decodedMinimal, err := DecodeTransparentRSAPrivateKey(minimal.Item())
	if err != nil {
		t.Fatalf("decode minimal private key: %v", err)
	}
	if decodedMinimal.P != nil || decodedMinimal.CRTCoefficient != nil {
		t.Fatalf("optional CRT fields unexpectedly set | 可选 CRT 字段被意外设置")
	}
	if _, err := DecodeTransparentRSAPublicKey(NewStructure(TagKeyMaterial, NewBigInteger(TagModulus, bigInt(3233)))); err == nil {
		t.Fatal("public key without exponent decoded | 无指数公钥被解码")
	}
	if _, err := DecodeTransparentRSAPrivateKey(NewStructure(TagKeyMaterial, NewBigInteger(TagModulus, bigInt(3233)))); err == nil {
		t.Fatal("private key without exponent decoded | 无指数字段私钥被解码")
	}
}

// TestTransparentECKeys covers transparent EC public and private keys. | TestTransparentECKeys 覆盖透明 EC 公钥与私钥。
func TestTransparentECKeys(t *testing.T) {
	private := TransparentECPrivateKey{RecommendedCurve: CurveP256, D: bigInt(12345)}
	decodedPrivate, err := DecodeTransparentECPrivateKey(private.Item())
	if err != nil {
		t.Fatalf("DecodeTransparentECPrivateKey: %v", err)
	}
	if !reflect.DeepEqual(decodedPrivate, private) {
		t.Fatalf("EC private = %+v, want %+v | EC 私钥 = %+v，期望 %+v", decodedPrivate, private, decodedPrivate, private)
	}
	public := TransparentECPublicKey{RecommendedCurve: CurveP384, Q: []byte{4, 1, 2, 3}}
	decodedPublic, err := DecodeTransparentECPublicKey(public.Item())
	if err != nil {
		t.Fatalf("DecodeTransparentECPublicKey: %v", err)
	}
	if !reflect.DeepEqual(decodedPublic, public) {
		t.Fatalf("EC public = %+v, want %+v | EC 公钥 = %+v，期望 %+v", decodedPublic, public, decodedPublic, public)
	}
	if _, err := DecodeTransparentECPrivateKey(NewStructure(TagKeyMaterial, NewEnumeration(TagRecommendedCurve, uint32(CurveP256)))); err == nil {
		t.Fatal("EC private without D decoded | 无 D 的 EC 私钥被解码")
	}
	if _, err := DecodeTransparentECPublicKey(NewStructure(TagKeyMaterial, NewEnumeration(TagRecommendedCurve, uint32(CurveP256)))); err == nil {
		t.Fatal("EC public without Q decoded | 无 Q 的 EC 公钥被解码")
	}
}

// TestKeyValue covers Key Value encoding, decoding and accessors. | TestKeyValue 覆盖 Key Value 编码、解码与访问器。
func TestKeyValue(t *testing.T) {
	kv := NewRawKeyValue([]byte{1, 2, 3})
	kv.Attributes = AttributeList{NewIntegerAttribute(AttributeCryptographicLength, 24)}
	item, err := kv.Item()
	if err != nil {
		t.Fatalf("KeyValue.Item: %v", err)
	}
	decoded, err := DecodeKeyValue(item)
	if err != nil {
		t.Fatalf("DecodeKeyValue: %v", err)
	}
	raw, err := decoded.Raw()
	if err != nil || !bytes.Equal(raw, []byte{1, 2, 3}) {
		t.Fatalf("Raw = %x, %v | Raw = %x，%v", raw, err, raw, err)
	}
	symmetric, err := decoded.Symmetric()
	if err != nil || !bytes.Equal(symmetric, []byte{1, 2, 3}) {
		t.Fatalf("Symmetric = %x, %v | Symmetric = %x，%v", symmetric, err, symmetric, err)
	}
	if len(decoded.Attributes) != 1 || decoded.Attributes[0].Name != AttributeCryptographicLength {
		t.Fatalf("decoded attributes = %+v | 解码属性 = %+v", decoded.Attributes, decoded.Attributes)
	}
	transparent := KeyValue{Material: TransparentSymmetricKey{Key: []byte{9, 8}}.Item()}
	if _, err := transparent.Raw(); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Raw on transparent key error = %v | 透明密钥 Raw 错误 = %v", err, err)
	}
	if symmetric, err := transparent.Symmetric(); err != nil || !bytes.Equal(symmetric, []byte{9, 8}) {
		t.Fatalf("transparent Symmetric = %x, %v | 透明 Symmetric = %x，%v", symmetric, err, symmetric, err)
	}
	unsupported := KeyValue{Material: NewInteger(TagKeyMaterial, 5)}
	if _, err := unsupported.Symmetric(); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Symmetric on integer error = %v | 整数 Symmetric 错误 = %v", err, err)
	}
	badMaterial := KeyValue{Material: NewByteString(TagKey, []byte{1})}
	if _, err := badMaterial.Item(); err == nil {
		t.Fatal("key value with wrong material tag encoded | 错误材料标签的密钥值被编码")
	}
	if _, err := (KeyValue{}).Item(); err == nil {
		t.Fatal("empty key value encoded | 空密钥值被编码")
	}
	if _, err := DecodeKeyValue(NewStructure(TagKeyBlock)); err == nil {
		t.Fatal("wrong tag accepted | 错误标签被接受")
	}
	if _, err := DecodeKeyValue(NewStructure(TagKeyValue)); err == nil {
		t.Fatal("key value without material decoded | 无材料密钥值被解码")
	}
	if _, err := DecodeKeyValue(NewStructure(TagKeyValue, NewInteger(TagUniqueIdentifier, 1))); err == nil {
		t.Fatal("unexpected tag accepted | 意外标签被接受")
	}
	if _, err := DecodeKeyValue(NewStructure(TagKeyValue, NewInteger(TagAttributeName, 1))); err == nil {
		t.Fatal("malformed attribute accepted | 畸形属性被接受")
	}
	if _, err := DecodeKeyValue(NewStructure(TagKeyValue, NewByteString(TagKeyMaterial, []byte{1}))); err != nil {
		t.Fatalf("minimal key value: %v | 最小密钥值：%v", err, err)
	}
}

// TestKeyBlock covers Key Block encoding, decoding, wrapping and validation. | TestKeyBlock 覆盖密钥块编码、解码、封装与校验。
func TestKeyBlock(t *testing.T) {
	kb := testKeyBlock()
	kb.Compression = KeyCompressionECPublicKeyUncompressed
	kb.Wrapping = &KeyWrappingData{WrappingMethod: WrappingMethodEncrypt, IVCounterNonce: []byte{1, 2}}
	item, err := kb.Item()
	if err != nil {
		t.Fatalf("KeyBlock.Item: %v", err)
	}
	decoded, err := DecodeKeyBlock(item)
	if err != nil {
		t.Fatalf("DecodeKeyBlock: %v", err)
	}
	if !reflect.DeepEqual(decoded, kb) {
		t.Fatalf("decoded key block = %+v, want %+v | 解码密钥块 = %+v，期望 %+v", decoded, kb, decoded, kb)
	}
	if _, err := (KeyBlock{}).Item(); err == nil {
		t.Fatal("key block without format encoded | 无格式密钥块被编码")
	}
	if _, err := (KeyBlock{Format: KeyFormatRaw, Value: KeyValue{Material: NewByteString(TagKey, []byte{1})}}).Item(); err == nil {
		t.Fatal("key block with wrong material tag encoded | 错误材料标签密钥块被编码")
	}
	if _, err := (KeyBlock{Format: KeyFormatRaw}).Item(); err == nil {
		t.Fatal("key block without value encoded | 无值密钥块被编码")
	}
	if _, err := DecodeKeyBlock(NewStructure(TagKeyValue)); err == nil {
		t.Fatal("wrong tag accepted | 错误标签被接受")
	}
	if _, err := DecodeKeyBlock(NewStructure(TagKeyBlock)); err == nil {
		t.Fatal("key block without format decoded | 无格式密钥块被解码")
	}
	if _, err := DecodeKeyBlock(NewStructure(TagKeyBlock, NewEnumeration(TagKeyFormatType, uint32(KeyFormatRaw)))); err == nil {
		t.Fatal("key block without value decoded | 无值密钥块被解码")
	}
	negativeLength := NewStructure(TagKeyBlock,
		NewEnumeration(TagKeyFormatType, uint32(KeyFormatRaw)),
		mustItem(t, NewRawKeyValue([]byte{1})),
		NewInteger(TagCryptographicLength, -1))
	if _, err := DecodeKeyBlock(negativeLength); err == nil {
		t.Fatal("negative length accepted | 负长度被接受")
	}
	unexpected := NewStructure(TagKeyBlock,
		NewEnumeration(TagKeyFormatType, uint32(KeyFormatRaw)),
		mustItem(t, NewRawKeyValue([]byte{1})),
		NewInteger(TagUniqueIdentifier, 1))
	if _, err := DecodeKeyBlock(unexpected); err == nil {
		t.Fatal("unexpected tag accepted | 意外标签被接受")
	}
	badWrapping := NewStructure(TagKeyBlock,
		NewEnumeration(TagKeyFormatType, uint32(KeyFormatRaw)),
		mustItem(t, NewRawKeyValue([]byte{1})),
		NewStructure(TagKeyWrappingData))
	if _, err := DecodeKeyBlock(badWrapping); err == nil {
		t.Fatal("invalid wrapping data accepted | 非法封装数据被接受")
	}
	mistyped := NewStructure(TagKeyBlock,
		NewEnumeration(TagKeyFormatType, uint32(KeyFormatRaw)),
		mustItem(t, NewRawKeyValue([]byte{1})),
		NewInteger(TagKeyCompressionType, 1))
	if _, err := DecodeKeyBlock(mistyped); err == nil {
		t.Fatal("mistyped compression accepted | 类型错误压缩被接受")
	}
}

// TestObjectFactoriesAndAccessors covers every object union member. | TestObjectFactoriesAndAccessors 覆盖所有对象联合成员。
func TestObjectFactoriesAndAccessors(t *testing.T) {
	kb := testKeyBlock()
	objects := []Object{
		NewSymmetricKeyObject(kb),
		NewPublicKeyObject(kb),
		NewPrivateKeyObject(kb),
		NewSecretDataObject(SecretDataTypeSeed, kb),
		NewCertificateObject(CertificateTypeX509, []byte{1, 2, 3}),
		NewTemplateObject(AttributeList{NewTextAttribute(AttributeComment, "template")}),
		NewOpaqueObject(7, []byte{4, 5, 6}),
	}
	for _, object := range objects {
		managed, err := object.Managed()
		if err != nil {
			t.Fatalf("Managed(%s): %v | Managed(%s)：%v", object.Type, err, object.Type, err)
		}
		if managed.ObjectType() != object.Type {
			t.Fatalf("managed type = %s, want %s | 受管类型 = %s，期望 %s", managed.ObjectType(), object.Type, managed.ObjectType(), object.Type)
		}
		item, err := object.Item()
		if err != nil {
			t.Fatalf("Item(%s): %v | Item(%s)：%v", object.Type, err, object.Type, err)
		}
		decoded, err := DecodeObject(item)
		if err != nil {
			t.Fatalf("DecodeObject(%s): %v | DecodeObject(%s)：%v", object.Type, err, object.Type, err)
		}
		if decoded.Type != object.Type {
			t.Fatalf("decoded type = %s, want %s | 解码类型 = %s，期望 %s", decoded.Type, object.Type, decoded.Type, object.Type)
		}
		if _, err := decoded.Item(); err != nil {
			t.Fatalf("re-encode %s: %v | 重新编码 %s：%v", object.Type, err, object.Type, err)
		}
	}
	if _, err := (Object{Type: ObjectTypeSymmetricKey}).Managed(); err == nil {
		t.Fatal("empty symmetric object managed without error | 空对称对象未报错")
	}
	if _, err := (Object{Type: ObjectType(99)}).Managed(); err == nil {
		t.Fatal("unknown object type managed without error | 未知对象类型未报错")
	}
	if _, err := (Object{Type: ObjectType(99)}).Item(); err == nil {
		t.Fatal("unknown object type encoded | 未知对象类型被编码")
	}
	if _, err := (Object{Type: ObjectTypeSymmetricKey}).Item(); err == nil {
		t.Fatal("empty symmetric object encoded | 空对称对象被编码")
	}
	if _, err := (Object{Type: ObjectTypeCertificate}).Item(); err == nil {
		t.Fatal("empty certificate encoded | 空证书被编码")
	}
	if _, err := (Object{Type: ObjectTypeTemplate, Template: &TemplateObject{Attributes: AttributeList{{Name: "unknown", Value: NewTextString(0, "x")}}}}).Item(); err == nil {
		t.Fatal("invalid template attribute encoded | 非法模板属性被编码")
	}
	for _, object := range objects[:4] {
		if _, err := object.KeyBlock(); err != nil {
			t.Fatalf("KeyBlock(%s): %v | KeyBlock(%s)：%v", object.Type, err, object.Type, err)
		}
		if object.Attributes() != nil {
			t.Fatalf("Attributes(%s) = %+v, want nil | Attributes(%s) = %+v，期望 nil", object.Type, object.Attributes(), object.Type, object.Attributes())
		}
	}
	if _, err := objects[4].KeyBlock(); err == nil {
		t.Fatal("certificate returned a key block | 证书返回了密钥块")
	}
	if _, err := objects[5].KeyBlock(); err == nil {
		t.Fatal("template returned a key block | 模板返回了密钥块")
	}
	if attrs := objects[5].Attributes(); len(attrs) != 1 || attrs[0].Name != AttributeComment {
		t.Fatalf("template attributes = %+v | 模板属性 = %+v", attrs, attrs)
	}
}

// TestDecodeObjectValidation covers malformed managed objects. | TestDecodeObjectValidation 覆盖畸形受管对象。
func TestDecodeObjectValidation(t *testing.T) {
	if _, err := DecodeObject(NewInteger(TagSymmetricKey, 1)); err == nil {
		t.Fatal("non-structure object decoded | 非结构对象被解码")
	}
	if _, err := DecodeObject(NewStructure(TagSymmetricKey)); err == nil {
		t.Fatal("symmetric key without key block decoded | 无密钥块对称密钥被解码")
	}
	if _, err := DecodeObject(NewStructure(TagPublicKey)); err == nil {
		t.Fatal("public key without key block decoded | 无密钥块公钥被解码")
	}
	if _, err := DecodeObject(NewStructure(TagPrivateKey)); err == nil {
		t.Fatal("private key without key block decoded | 无密钥块私钥被解码")
	}
	if _, err := DecodeObject(NewStructure(TagSecretData)); err == nil {
		t.Fatal("secret data without type decoded | 无类型秘密数据被解码")
	}
	if _, err := DecodeObject(NewStructure(TagCertificate)); err == nil {
		t.Fatal("certificate without type decoded | 无类型证书被解码")
	}
	if _, err := DecodeObject(NewStructure(TagOpaqueObject)); err == nil {
		t.Fatal("opaque object without type decoded | 无类型不透明对象被解码")
	}
	if _, err := DecodeObject(NewStructure(TagTemplate, NewInteger(TagUniqueIdentifier, 1))); err == nil {
		t.Fatal("template with non-attribute child decoded | 含非属性子项的模板被解码")
	}
	if _, err := DecodeObject(NewStructure(Tag(0x4200FF))); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unsupported tag error = %v | 不支持标签错误 = %v", err, err)
	}
	badSecretType := NewStructure(TagSecretData,
		NewEnumeration(TagSecretDataType, uint32(SecretDataTypePassword)),
		mustItem(t, NewRawKeyValue([]byte{1})))
	if _, err := DecodeObject(badSecretType); err == nil {
		t.Fatal("secret data without key block decoded | 无密钥块秘密数据被解码")
	}
	badCertValue := NewStructure(TagCertificate,
		NewEnumeration(TagCertificateType, uint32(CertificateTypeX509)),
		NewInteger(TagCertificateValue, 1))
	if _, err := DecodeObject(badCertValue); err == nil {
		t.Fatal("certificate with mistyped value decoded | 类型错误证书值被解码")
	}
	badOpaqueValue := NewStructure(TagOpaqueObject,
		NewEnumeration(TagOpaqueDataType, 1),
		NewInteger(TagOpaqueDataValue, 1))
	if _, err := DecodeObject(badOpaqueValue); err == nil {
		t.Fatal("opaque object with mistyped value decoded | 类型错误不透明值被解码")
	}
}

// TestObjectZeroize covers key material, certificate and opaque erasure. | TestObjectZeroize 覆盖密钥材料、证书与不透明数据擦除。
func TestObjectZeroize(t *testing.T) {
	raw := []byte{1, 2, 3, 4}
	object := NewSymmetricKeyObject(KeyBlock{
		Format: KeyFormatRaw,
		Value:  NewRawKeyValue(raw),
		Wrapping: &KeyWrappingData{
			WrappingMethod: WrappingMethodEncrypt,
			MACSignature:   []byte{5, 6},
			IVCounterNonce: []byte{7, 8},
		},
	})
	object.Zeroize()
	stored := object.SymmetricKey.KeyBlock.Value.Material.Value
	if !bytes.Equal(stored, []byte{0, 0, 0, 0}) {
		t.Fatalf("raw key material = %x, want zeroes | 原始密钥材料 = %x，期望全零", stored, stored)
	}
	if !bytes.Equal(object.SymmetricKey.KeyBlock.Wrapping.MACSignature, []byte{0, 0}) ||
		!bytes.Equal(object.SymmetricKey.KeyBlock.Wrapping.IVCounterNonce, []byte{0, 0}) {
		t.Fatal("wrapping material was not zeroed | 封装材料未清零")
	}
	transparent := NewSymmetricKeyObject(KeyBlock{
		Format: KeyFormatTransparentSymmetricKey,
		Value:  KeyValue{Material: TransparentSymmetricKey{Key: []byte{9, 9, 9}}.Item()},
	})
	transparent.Zeroize()
	child := transparent.SymmetricKey.KeyBlock.Value.Material.Children[0]
	if !bytes.Equal(child.Value, []byte{0, 0, 0}) {
		t.Fatalf("transparent material = %x, want zeroes | 透明材料 = %x，期望全零", child.Value, child.Value)
	}
	certificate := NewCertificateObject(CertificateTypeX509, []byte{3, 2, 1})
	certificate.Zeroize()
	if !bytes.Equal(certificate.Certificate.CertificateValue, []byte{0, 0, 0}) {
		t.Fatal("certificate was not zeroed | 证书未清零")
	}
	opaque := NewOpaqueObject(1, []byte{4, 5})
	opaque.Zeroize()
	if !bytes.Equal(opaque.Opaque.OpaqueDataValue, []byte{0, 0}) {
		t.Fatal("opaque value was not zeroed | 不透明值未清零")
	}
	var nilObject *Object
	nilObject.Zeroize()
	zeroizeKeyBlock(nil)
	zeroizeItemMaterial(nil)
}
