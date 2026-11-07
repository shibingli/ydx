package kmip

import (
	"errors"
	"reflect"
	"testing"
)

// TestCryptographicParametersRoundTrip covers every cryptographic parameter field. | TestCryptographicParametersRoundTrip 覆盖所有密码参数字段。
func TestCryptographicParametersRoundTrip(t *testing.T) {
	params := CryptographicParameters{
		BlockCipherMode:               BlockCipherModeCTR,
		PaddingMethod:                 PaddingMethodNone,
		HashingAlgorithm:              HashingAlgorithmSHA384,
		DigitalSignatureAlgorithm:     DigitalSignatureECDSASHA256,
		CryptographicAlgorithm:        AlgorithmAES,
		RandomIV:                      true,
		IVLength:                      16,
		TagLength:                     16,
		FixedFieldLength:              4,
		InvocationFieldLength:         8,
		CounterLength:                 16,
		InitialCounterValue:           2,
		SaltLength:                    32,
		MaskGenerator:                 MaskGeneratorMGF1,
		MaskGeneratorHashingAlgorithm: HashingAlgorithmSHA512,
	}
	decoded, err := DecodeCryptographicParameters(params.Item())
	if err != nil {
		t.Fatalf("DecodeCryptographicParameters: %v", err)
	}
	if !reflect.DeepEqual(decoded, params) {
		t.Fatalf("decoded parameters = %+v, want %+v | 解码参数 = %+v，期望 %+v", decoded, params, decoded, params)
	}
	if _, err := DecodeCryptographicParameters(NewStructure(TagKeyWrappingData)); err == nil {
		t.Fatal("wrong tag decoded without error | 错误标签未报错")
	}
	unexpected := NewStructure(TagCryptographicParameters, NewInteger(TagUniqueIdentifier, 1))
	if _, err := DecodeCryptographicParameters(unexpected); err == nil {
		t.Fatal("unexpected tag accepted | 意外标签被接受")
	}
	wrongType := NewStructure(TagCryptographicParameters, NewInteger(TagIVLength, 16), NewTextString(TagTagLength, "x"))
	if _, err := DecodeCryptographicParameters(wrongType); err == nil {
		t.Fatal("mistyped integer accepted | 类型错误整数被接受")
	}
}

// TestEncryptionKeyInformation covers Encryption Key Information round trips and validation. | TestEncryptionKeyInformation 覆盖加密密钥信息往返与校验。
func TestEncryptionKeyInformation(t *testing.T) {
	info := EncryptionKeyInformation{UniqueIdentifier: "wrapping-key", CryptographicParameters: &CryptographicParameters{BlockCipherMode: BlockCipherModeGCM}}
	decoded, err := DecodeEncryptionKeyInformation(info.Item())
	if err != nil {
		t.Fatalf("DecodeEncryptionKeyInformation: %v", err)
	}
	if !reflect.DeepEqual(decoded, info) {
		t.Fatalf("decoded = %+v, want %+v | 解码 = %+v，期望 %+v", decoded, info, decoded, info)
	}
	if _, err := DecodeEncryptionKeyInformation(NewStructure(TagMACSignatureKeyInformation)); err == nil {
		t.Fatal("wrong tag decoded without error | 错误标签未报错")
	}
	if _, err := DecodeEncryptionKeyInformation(NewStructure(TagEncryptionKeyInformation)); err == nil {
		t.Fatal("missing identifier accepted | 缺少标识符被接受")
	}
	badParams := NewStructure(TagEncryptionKeyInformation,
		NewTextString(TagUniqueIdentifier, "key"),
		NewStructure(TagCryptographicParameters, NewInteger(TagUniqueIdentifier, 1)))
	if _, err := DecodeEncryptionKeyInformation(badParams); err == nil {
		t.Fatal("invalid parameters accepted | 非法参数被接受")
	}
}

// TestMACSignatureKeyInformation covers MAC/Signature Key Information. | TestMACSignatureKeyInformation 覆盖 MAC/签名密钥信息。
func TestMACSignatureKeyInformation(t *testing.T) {
	info := MACSignatureKeyInformation{UniqueIdentifier: "mac-key", CryptographicParameters: &CryptographicParameters{HashingAlgorithm: HashingAlgorithmSHA256}}
	decoded, err := DecodeMACSignatureKeyInformation(info.Item())
	if err != nil {
		t.Fatalf("DecodeMACSignatureKeyInformation: %v", err)
	}
	if !reflect.DeepEqual(decoded, info) {
		t.Fatalf("decoded = %+v, want %+v | 解码 = %+v，期望 %+v", decoded, info, decoded, info)
	}
	if _, err := DecodeMACSignatureKeyInformation(NewStructure(TagEncryptionKeyInformation)); err == nil {
		t.Fatal("wrong tag decoded without error | 错误标签未报错")
	}
	if _, err := DecodeMACSignatureKeyInformation(NewStructure(TagMACSignatureKeyInformation)); err == nil {
		t.Fatal("missing identifier accepted | 缺少标识符被接受")
	}
	badParams := NewStructure(TagMACSignatureKeyInformation,
		NewTextString(TagUniqueIdentifier, "key"),
		NewStructure(TagCryptographicParameters, NewInteger(TagUniqueIdentifier, 1)))
	if _, err := DecodeMACSignatureKeyInformation(badParams); err == nil {
		t.Fatal("invalid parameters accepted | 非法参数被接受")
	}
}

// TestKeyWrappingData covers Key Wrapping Data round trips and validation. | TestKeyWrappingData 覆盖密钥封装数据往返与校验。
func TestKeyWrappingData(t *testing.T) {
	data := KeyWrappingData{
		WrappingMethod:             WrappingMethodEncryptThenMACSign,
		EncryptionKeyInformation:   &EncryptionKeyInformation{UniqueIdentifier: "enc-key"},
		MACSignatureKeyInformation: &MACSignatureKeyInformation{UniqueIdentifier: "mac-key"},
		MACSignature:               []byte("signature"),
		IVCounterNonce:             []byte("nonce"),
		EncodingOption:             EncodingOptionTTLVEncoding,
	}
	item, err := data.Item()
	if err != nil {
		t.Fatalf("KeyWrappingData.Item: %v", err)
	}
	decoded, err := DecodeKeyWrappingData(item)
	if err != nil {
		t.Fatalf("DecodeKeyWrappingData: %v", err)
	}
	if !reflect.DeepEqual(decoded, data) {
		t.Fatalf("decoded = %+v, want %+v | 解码 = %+v，期望 %+v", decoded, data, decoded, data)
	}
	if _, err := (KeyWrappingData{}).Item(); err == nil {
		t.Fatal("wrapping data without method encoded | 无方法封装数据被编码")
	}
	if _, err := DecodeKeyWrappingData(NewStructure(TagKeyWrappingSpecification, NewEnumeration(TagWrappingMethod, uint32(WrappingMethodEncrypt)))); err == nil {
		t.Fatal("wrong tag decoded without error | 错误标签未报错")
	}
	if _, err := DecodeKeyWrappingData(NewStructure(TagKeyWrappingData)); err == nil {
		t.Fatal("wrapping data without method decoded | 无方法封装数据被解码")
	}
	unexpected := NewStructure(TagKeyWrappingData,
		NewEnumeration(TagWrappingMethod, uint32(WrappingMethodEncrypt)),
		NewInteger(TagUniqueIdentifier, 1))
	if _, err := DecodeKeyWrappingData(unexpected); err == nil {
		t.Fatal("unexpected tag accepted | 意外标签被接受")
	}
	badEKI := NewStructure(TagKeyWrappingData,
		NewEnumeration(TagWrappingMethod, uint32(WrappingMethodEncrypt)),
		NewStructure(TagEncryptionKeyInformation))
	if _, err := DecodeKeyWrappingData(badEKI); err == nil {
		t.Fatal("invalid encryption key information accepted | 非法加密密钥信息被接受")
	}
	badMSKI := NewStructure(TagKeyWrappingData,
		NewEnumeration(TagWrappingMethod, uint32(WrappingMethodEncrypt)),
		NewStructure(TagMACSignatureKeyInformation))
	if _, err := DecodeKeyWrappingData(badMSKI); err == nil {
		t.Fatal("invalid MAC key information accepted | 非法 MAC 密钥信息被接受")
	}
	badEnum := NewStructure(TagKeyWrappingData,
		NewEnumeration(TagWrappingMethod, uint32(WrappingMethodEncrypt)),
		NewInteger(TagEncodingOption, 1))
	if _, err := DecodeKeyWrappingData(badEnum); err == nil {
		t.Fatal("mistyped encoding option accepted | 类型错误编码选项被接受")
	}
}

// TestKeyWrappingSpecification covers wrapping specification round trips. | TestKeyWrappingSpecification 覆盖封装规格往返。
func TestKeyWrappingSpecification(t *testing.T) {
	spec := testWrappingSpec()
	spec.MACSignatureKeyInformation = &MACSignatureKeyInformation{UniqueIdentifier: "mac-key"}
	spec.EncodingOption = EncodingOptionTTLVEncoding
	item, err := spec.Item()
	if err != nil {
		t.Fatalf("KeyWrappingSpecification.Item: %v", err)
	}
	decoded, err := DecodeKeyWrappingSpecification(item)
	if err != nil {
		t.Fatalf("DecodeKeyWrappingSpecification: %v", err)
	}
	if !reflect.DeepEqual(decoded, spec) {
		t.Fatalf("decoded = %+v, want %+v | 解码 = %+v，期望 %+v", decoded, spec, decoded, spec)
	}
	if _, err := (KeyWrappingSpecification{}).Item(); err == nil {
		t.Fatal("specification without method encoded | 无方法规格被编码")
	}
	if _, err := DecodeKeyWrappingSpecification(NewStructure(TagKeyWrappingData, NewEnumeration(TagWrappingMethod, uint32(WrappingMethodEncrypt)))); err == nil {
		t.Fatal("wrong tag decoded without error | 错误标签未报错")
	}
	if _, err := DecodeKeyWrappingSpecification(NewStructure(TagKeyWrappingSpecification)); err == nil {
		t.Fatal("specification without method decoded | 无方法规格被解码")
	}
	unexpected := NewStructure(TagKeyWrappingSpecification,
		NewEnumeration(TagWrappingMethod, uint32(WrappingMethodEncrypt)),
		NewInteger(TagUniqueIdentifier, 1))
	if _, err := DecodeKeyWrappingSpecification(unexpected); err == nil {
		t.Fatal("unexpected tag accepted | 意外标签被接受")
	}
	badName := NewStructure(TagKeyWrappingSpecification,
		NewEnumeration(TagWrappingMethod, uint32(WrappingMethodEncrypt)),
		NewInteger(TagAttributeName, 1))
	if _, err := DecodeKeyWrappingSpecification(badName); err == nil {
		t.Fatal("mistyped attribute name accepted | 类型错误属性名被接受")
	}
	badEKI := NewStructure(TagKeyWrappingSpecification,
		NewEnumeration(TagWrappingMethod, uint32(WrappingMethodEncrypt)),
		NewStructure(TagEncryptionKeyInformation))
	if _, err := DecodeKeyWrappingSpecification(badEKI); err == nil {
		t.Fatal("invalid encryption key information accepted | 非法加密密钥信息被接受")
	}
	badMSKI := NewStructure(TagKeyWrappingSpecification,
		NewEnumeration(TagWrappingMethod, uint32(WrappingMethodEncrypt)),
		NewStructure(TagMACSignatureKeyInformation))
	if _, err := DecodeKeyWrappingSpecification(badMSKI); err == nil {
		t.Fatal("invalid MAC key information accepted | 非法 MAC 密钥信息被接受")
	}
	badEncoding := NewStructure(TagKeyWrappingSpecification,
		NewEnumeration(TagWrappingMethod, uint32(WrappingMethodEncrypt)),
		NewInteger(TagEncodingOption, 1))
	if _, err := DecodeKeyWrappingSpecification(badEncoding); err == nil {
		t.Fatal("mistyped encoding option accepted | 类型错误编码选项被接受")
	}
}

// TestWrappingErrorsAreClassified verifies sentinel classification. | TestWrappingErrorsAreClassified 验证哨兵错误分类。
func TestWrappingErrorsAreClassified(t *testing.T) {
	_, err := DecodeKeyWrappingData(NewInteger(TagKeyWrappingData, 1))
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("decode error = %v, want ErrMalformed | 解码错误 = %v，期望 ErrMalformed", err, err)
	}
	_, err = (KeyWrappingSpecification{}).Item()
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("encode error = %v, want ErrInvalidRequest | 编码错误 = %v，期望 ErrInvalidRequest", err, err)
	}
}
