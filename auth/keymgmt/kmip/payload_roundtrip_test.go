package kmip

import (
	"bytes"
	"math/big"
	"testing"
	"time"
)

// boolPointer returns a pointer to value. | boolPointer 返回 value 的指针。
func boolPointer(value bool) *bool { return &value }

// int64Pointer returns a pointer to value. | int64Pointer 返回 value 的指针。
func int64Pointer(value int64) *int64 { return &value }

// durationPointer returns a pointer to value. | durationPointer 返回 value 的指针。
func durationPointer(value time.Duration) *time.Duration { return &value }

// testKeyBlock returns a raw AES-256 key block. | testKeyBlock 返回原始 AES-256 密钥块。
func testKeyBlock() KeyBlock {
	return KeyBlock{
		Format:    KeyFormatRaw,
		Value:     NewRawKeyValue(bytes.Repeat([]byte{0x11}, 32)),
		Algorithm: AlgorithmAES,
		Length:    256,
	}
}

// testWrappingSpec returns a valid wrapping specification. | testWrappingSpec 返回合法的封装规格。
func testWrappingSpec() KeyWrappingSpecification {
	return KeyWrappingSpecification{
		WrappingMethod: WrappingMethodEncrypt,
		EncryptionKeyInformation: &EncryptionKeyInformation{
			UniqueIdentifier:        "wrapping-key",
			CryptographicParameters: &CryptographicParameters{BlockCipherMode: BlockCipherModeGCM},
		},
		AttributeNames: []string{AttributeCryptographicAlgorithm},
		EncodingOption: EncodingOptionNoEncoding,
	}
}

// testTemplate returns a populated template. | testTemplate 返回填充的模板。
func testTemplate() TemplateAttribute {
	return TemplateAttribute{
		Names: []Name{NewName("alpha")},
		Attributes: AttributeList{
			NewEnumerationAttribute(AttributeCryptographicAlgorithm, uint32(AlgorithmAES)),
			NewIntegerAttribute(AttributeCryptographicLength, 256),
			NewTextAttribute(AttributeObjectGroup, "group-a"),
		},
	}
}

// testDate returns a whole-second UTC timestamp. | testDate 返回整秒 UTC 时间戳。
func testDate() time.Time {
	return time.Unix(1700000000, 0).UTC()
}

// payloadCase is one table-driven payload round-trip check. | payloadCase 是一项表驱动的负载往返检查。
type payloadCase struct {
	name  string
	check func(t *testing.T)
}

// payloadCaseFor builds a round-trip case for a payload type. | payloadCaseFor 为负载类型构造往返用例。
func payloadCaseFor[T interface{ Item() (Item, error) }](name string, value T, decode func(Item) (T, error)) payloadCase {
	return payloadCase{name: name, check: func(t *testing.T) {
		checkPayloadRoundTrip(t, value, decode)
	}}
}

// checkPayloadRoundTrip verifies encode, TTLV decode and decode-stability. | checkPayloadRoundTrip 验证编码、TTLV 解码与解码稳定性。
func checkPayloadRoundTrip[T interface{ Item() (Item, error) }](t *testing.T, value T, decode func(Item) (T, error)) {
	t.Helper()
	raw, err := Encode(mustItem(t, value))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	item, err := Decode(raw)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	decoded, err := decode(item)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	reencoded, err := Encode(mustItem(t, decoded))
	if err != nil {
		t.Fatalf("re-Encode: %v", err)
	}
	if !bytes.Equal(raw, reencoded) {
		t.Fatalf("payload is not round-trip stable | 负载往返不稳定\nfirst:  %x\nsecond: %x", raw, reencoded)
	}
}

// TestPayloadCoreRoundTrip covers every core payload type. | TestPayloadCoreRoundTrip 覆盖所有核心负载类型。
func TestPayloadCoreRoundTrip(t *testing.T) {
	object := NewSymmetricKeyObject(testKeyBlock())
	cases := []payloadCase{
		payloadCaseFor("CreateRequest", CreateRequest{ObjectType: ObjectTypeSymmetricKey, TemplateAttribute: testTemplate()}, DecodeCreateRequest),
		payloadCaseFor("CreateResponse", CreateResponse{ObjectType: ObjectTypeSymmetricKey, UniqueIdentifier: "uid-create", TemplateAttribute: ptrTemplate(testTemplate())}, DecodeCreateResponse),
		payloadCaseFor("CreateKeyPairRequest", CreateKeyPairRequest{
			CommonTemplateAttribute:     ptrTemplate(testTemplate()),
			PrivateKeyTemplateAttribute: ptrTemplate(TemplateAttribute{Attributes: AttributeList{NewEnumerationAttribute(AttributeCryptographicAlgorithm, uint32(AlgorithmRSA))}}),
			PublicKeyTemplateAttribute:  ptrTemplate(testTemplate()),
		}, DecodeCreateKeyPairRequest),
		payloadCaseFor("CreateKeyPairResponse", CreateKeyPairResponse{
			PrivateKeyUniqueIdentifier:  "uid-private",
			PublicKeyUniqueIdentifier:   "uid-public",
			PrivateKeyTemplateAttribute: ptrTemplate(testTemplate()),
			PublicKeyTemplateAttribute:  ptrTemplate(testTemplate()),
		}, DecodeCreateKeyPairResponse),
		payloadCaseFor("RegisterRequest", RegisterRequest{ObjectType: ObjectTypeSymmetricKey, TemplateAttribute: testTemplate(), Object: object}, DecodeRegisterRequest),
		payloadCaseFor("RegisterResponse", RegisterResponse{UniqueIdentifier: "uid-register", TemplateAttribute: ptrTemplate(testTemplate())}, DecodeRegisterResponse),
		payloadCaseFor("GetRequest", GetRequest{
			UniqueIdentifier:         "uid-get",
			KeyFormatType:            KeyFormatPKCS8,
			KeyWrapType:              KeyWrapTypeNotWrapped,
			KeyCompressionType:       KeyCompressionNone,
			KeyWrappingSpecification: ptrWrappingSpec(testWrappingSpec()),
			AttributeNames:           []string{AttributeState, AttributeCryptographicAlgorithm},
		}, DecodeGetRequest),
		payloadCaseFor("GetResponse", GetResponse{ObjectType: ObjectTypeSymmetricKey, UniqueIdentifier: "uid-get", Object: object}, DecodeGetResponse),
		payloadCaseFor("GetAttributesRequest", GetAttributesRequest{UniqueIdentifier: "uid-attrs", AttributeNames: []string{AttributeState, AttributeName}}, DecodeGetAttributesRequest),
		payloadCaseFor("GetAttributesResponse", GetAttributesResponse{UniqueIdentifier: "uid-attrs", AttributeList: AttributeList{
			NewEnumerationAttribute(AttributeState, uint32(StateActive)),
			NewTextAttribute(AttributeName, "alpha"),
		}}, DecodeGetAttributesResponse),
		payloadCaseFor("GetAttributeListRequest", GetAttributeListRequest{UniqueIdentifier: "uid-list"}, DecodeGetAttributeListRequest),
		payloadCaseFor("GetAttributeListResponse", GetAttributeListResponse{UniqueIdentifier: "uid-list", AttributeNames: []string{AttributeState, AttributeName}}, DecodeGetAttributeListResponse),
		payloadCaseFor("ActivateRequest", ActivateRequest{UniqueIdentifier: "uid-activate"}, DecodeActivateRequest),
		payloadCaseFor("ActivateResponse", ActivateResponse{UniqueIdentifier: "uid-activate"}, DecodeActivateResponse),
		payloadCaseFor("RevokeRequest", RevokeRequest{
			UniqueIdentifier:         "uid-revoke",
			Reason:                   RevocationReason{Code: RevocationKeyCompromise, Message: "compromised | 已泄露"},
			CompromiseOccurrenceDate: testDate(),
		}, DecodeRevokeRequest),
		payloadCaseFor("RevokeResponse", RevokeResponse{UniqueIdentifier: "uid-revoke"}, DecodeRevokeResponse),
		payloadCaseFor("DestroyRequest", DestroyRequest{UniqueIdentifier: "uid-destroy"}, DecodeDestroyRequest),
		payloadCaseFor("DestroyResponse", DestroyResponse{UniqueIdentifier: "uid-destroy"}, DecodeDestroyResponse),
		payloadCaseFor("LocateRequest", LocateRequest{
			MaximumItems:      10,
			OffsetItems:       2,
			StorageStatusMask: 1,
			ObjectGroupMember: 3,
			Attributes:        AttributeList{NewTextAttribute(AttributeName, "alpha")},
		}, DecodeLocateRequest),
		payloadCaseFor("LocateResponse", LocateResponse{LocatedItems: 7, HasLocatedItems: true, UniqueIdentifiers: []string{"a", "b"}}, DecodeLocateResponse),
		payloadCaseFor("DeriveKeyRequest", DeriveKeyRequest{
			ObjectType:           ObjectTypeSymmetricKey,
			UniqueIdentifiers:    []string{"base-key"},
			DerivationMethod:     DerivationMethodHKDF,
			DerivationParameters: DerivationParameters{DerivationData: []byte("context"), Salt: []byte("salt"), IterationCount: 1000, CryptographicParameters: &CryptographicParameters{HashingAlgorithm: HashingAlgorithmSHA256}},
			TemplateAttribute:    testTemplate(),
		}, DecodeDeriveKeyRequest),
		payloadCaseFor("DeriveKeyResponse", DeriveKeyResponse{UniqueIdentifier: "uid-derived", TemplateAttribute: ptrTemplate(testTemplate())}, DecodeDeriveKeyResponse),
	}
	runPayloadCases(t, cases)
}

// ptrTemplate returns a pointer to a copy of t. | ptrTemplate 返回 t 副本的指针。
func ptrTemplate(t TemplateAttribute) *TemplateAttribute { return &t }

// ptrWrappingSpec returns a pointer to a copy of w. | ptrWrappingSpec 返回 w 副本的指针。
func ptrWrappingSpec(w KeyWrappingSpecification) *KeyWrappingSpecification { return &w }

// TestPayloadCryptoRoundTrip covers every cryptographic payload type. | TestPayloadCryptoRoundTrip 覆盖所有密码学负载类型。
func TestPayloadCryptoRoundTrip(t *testing.T) {
	params := &CryptographicParameters{
		BlockCipherMode:               BlockCipherModeCBC,
		PaddingMethod:                 PaddingMethodPKCS5,
		HashingAlgorithm:              HashingAlgorithmSHA256,
		RandomIV:                      true,
		IVLength:                      16,
		TagLength:                     16,
		FixedFieldLength:              4,
		InvocationFieldLength:         8,
		CounterLength:                 16,
		InitialCounterValue:           1,
		SaltLength:                    32,
		MaskGenerator:                 MaskGeneratorMGF1,
		MaskGeneratorHashingAlgorithm: HashingAlgorithmSHA256,
	}
	wrapped := Object{
		Type: ObjectTypeSymmetricKey,
		SymmetricKey: &SymmetricKeyObject{KeyBlock: KeyBlock{
			Format:    KeyFormatRaw,
			Value:     NewRawKeyValue([]byte{1, 2, 3, 4}),
			Algorithm: AlgorithmAES,
			Length:    256,
			Wrapping:  &KeyWrappingData{WrappingMethod: WrappingMethodEncrypt, IVCounterNonce: []byte{9}, MACSignature: []byte{8}},
		}},
	}
	cases := []payloadCase{
		payloadCaseFor("EncryptRequest", EncryptRequest{
			UniqueIdentifier:                      "uid-encrypt",
			CryptographicParameters:               params,
			Data:                                  []byte("plaintext"),
			IVCounterNonce:                        []byte("iv"),
			CorrelationValue:                      []byte("corr"),
			InitIndicator:                         boolPointer(true),
			FinalIndicator:                        boolPointer(false),
			AuthenticatedEncryptionAdditionalData: []byte("aad"),
		}, DecodeEncryptRequest),
		payloadCaseFor("EncryptResponse", EncryptResponse{
			UniqueIdentifier:           "uid-encrypt",
			Data:                       []byte("ciphertext"),
			IVCounterNonce:             []byte("iv"),
			CorrelationValue:           []byte("corr"),
			AuthenticatedEncryptionTag: []byte("tag"),
		}, DecodeEncryptResponse),
		payloadCaseFor("DecryptRequest", DecryptRequest{
			UniqueIdentifier:                      "uid-decrypt",
			CryptographicParameters:               params,
			Data:                                  []byte("ciphertext"),
			IVCounterNonce:                        []byte("iv"),
			CorrelationValue:                      []byte("corr"),
			InitIndicator:                         boolPointer(false),
			FinalIndicator:                        boolPointer(true),
			AuthenticatedEncryptionAdditionalData: []byte("aad"),
			AuthenticatedEncryptionTag:            []byte("tag"),
		}, DecodeDecryptRequest),
		payloadCaseFor("DecryptResponse", DecryptResponse{UniqueIdentifier: "uid-decrypt", Data: []byte("plaintext"), CorrelationValue: []byte("corr")}, DecodeDecryptResponse),
		payloadCaseFor("SignRequest", SignRequest{
			UniqueIdentifier:        "uid-sign",
			CryptographicParameters: params,
			Data:                    []byte("message"),
			CorrelationValue:        []byte("corr"),
			InitIndicator:           boolPointer(true),
			FinalIndicator:          boolPointer(false),
		}, DecodeSignRequest),
		payloadCaseFor("SignRequestDigested", SignRequest{
			UniqueIdentifier: "uid-sign",
			DigestedData:     []byte("digest"),
		}, DecodeSignRequest),
		payloadCaseFor("SignResponse", SignResponse{UniqueIdentifier: "uid-sign", SignatureData: []byte("signature"), CorrelationValue: []byte("corr")}, DecodeSignResponse),
		payloadCaseFor("VerifyRequest", VerifyRequest{
			UniqueIdentifier:        "uid-verify",
			CryptographicParameters: params,
			Data:                    []byte("message"),
			SignatureData:           []byte("signature"),
			CorrelationValue:        []byte("corr"),
			InitIndicator:           boolPointer(false),
			FinalIndicator:          boolPointer(true),
		}, DecodeVerifyRequest),
		payloadCaseFor("VerifyResponse", VerifyResponse{UniqueIdentifier: "uid-verify", ValidityIndicator: ValidityIndicatorValid, Data: []byte("data"), CorrelationValue: []byte("corr")}, DecodeVerifyResponse),
		payloadCaseFor("MACRequest", MACRequest{
			UniqueIdentifier:        "uid-mac",
			CryptographicParameters: params,
			Data:                    []byte("message"),
			CorrelationValue:        []byte("corr"),
			InitIndicator:           boolPointer(true),
			FinalIndicator:          boolPointer(true),
		}, DecodeMACRequest),
		payloadCaseFor("MACResponse", MACResponse{UniqueIdentifier: "uid-mac", MACData: []byte("mac"), CorrelationValue: []byte("corr")}, DecodeMACResponse),
		payloadCaseFor("MACVerifyRequest", MACVerifyRequest{
			UniqueIdentifier:        "uid-mac",
			CryptographicParameters: params,
			Data:                    []byte("message"),
			MACData:                 []byte("mac"),
			CorrelationValue:        []byte("corr"),
			InitIndicator:           boolPointer(true),
			FinalIndicator:          boolPointer(false),
		}, DecodeMACVerifyRequest),
		payloadCaseFor("MACVerifyResponse", MACVerifyResponse{UniqueIdentifier: "uid-mac", ValidityIndicator: ValidityIndicatorInvalid, CorrelationValue: []byte("corr")}, DecodeMACVerifyResponse),
		payloadCaseFor("WrapKeyRequest", WrapKeyRequest{UniqueIdentifier: "uid-wrap", KeyWrappingSpecification: testWrappingSpec()}, DecodeWrapKeyRequest),
		payloadCaseFor("WrapKeyResponse", WrapKeyResponse{UniqueIdentifier: "uid-wrap", Object: wrapped}, DecodeWrapKeyResponse),
		payloadCaseFor("UnwrapKeyRequest", UnwrapKeyRequest{Object: wrapped, TemplateAttribute: testTemplate()}, DecodeUnwrapKeyRequest),
		payloadCaseFor("UnwrapKeyResponse", UnwrapKeyResponse{UniqueIdentifier: "uid-unwrap", ObjectType: ObjectTypeSymmetricKey}, DecodeUnwrapKeyResponse),
	}
	runPayloadCases(t, cases)
}

// TestPayloadQueryRoundTrip covers Query, Discover Versions and Check payloads. | TestPayloadQueryRoundTrip 覆盖 Query、Discover Versions 与 Check 负载。
func TestPayloadQueryRoundTrip(t *testing.T) {
	info := NewStructure(TagServerInformation, NewTextString(TagVendorIdentification, "ydx"))
	cases := []payloadCase{
		payloadCaseFor("QueryRequest", QueryRequest{QueryFunctions: []QueryFunction{QueryFunctionOperations, QueryFunctionObjects, QueryFunctionServerInformation, QueryFunctionApplicationNamespaces}}, DecodeQueryRequest),
		payloadCaseFor("QueryResponse", QueryResponse{
			Operations:            []Operation{OpCreate, OpGet},
			ObjectTypes:           []ObjectType{ObjectTypeSymmetricKey, ObjectTypePrivateKey},
			VendorIdentification:  "ydx",
			ServerInformation:     info,
			ApplicationNamespaces: []string{"https://yun-dev.cn/kmip"},
		}, DecodeQueryResponse),
		payloadCaseFor("DiscoverVersionsRequest", DiscoverVersionsRequest{ProtocolVersions: []ProtocolVersion{ProtocolVersion14, ProtocolVersion20}}, DecodeDiscoverVersionsRequest),
		payloadCaseFor("DiscoverVersionsResponse", DiscoverVersionsResponse{ProtocolVersions: []ProtocolVersion{ProtocolVersion14}}, DecodeDiscoverVersionsResponse),
		payloadCaseFor("CheckRequest", CheckRequest{
			UniqueIdentifier:       "uid-check",
			UsageLimitsCount:       int64Pointer(9),
			CryptographicUsageMask: UsageMaskEncrypt | UsageMaskDecrypt,
			LeaseTime:              durationPointer(30 * time.Second),
		}, DecodeCheckRequest),
		payloadCaseFor("CheckResponse", CheckResponse{
			UniqueIdentifier:       "uid-check",
			UsageLimitsCount:       int64Pointer(8),
			CryptographicUsageMask: UsageMaskEncrypt,
			LeaseTime:              durationPointer(time.Minute),
		}, DecodeCheckResponse),
	}
	runPayloadCases(t, cases)
}

// runPayloadCases executes the table. | runPayloadCases 执行用例表。
func runPayloadCases(t *testing.T, cases []payloadCase) {
	t.Helper()
	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) { testCase.check(t) })
	}
}

// TestRevocationReasonRoundTrip covers the revocation reason encoding. | TestRevocationReasonRoundTrip 覆盖撤销原因编码。
func TestRevocationReasonRoundTrip(t *testing.T) {
	reason := RevocationReason{Code: RevocationCessationOfOperation, Message: "retired | 已退役"}
	item := mustItem(t, reason)
	decoded, err := DecodeRevocationReason(item)
	if err != nil {
		t.Fatalf("DecodeRevocationReason: %v", err)
	}
	if decoded.Code != reason.Code || decoded.Message != reason.Message {
		t.Fatalf("decoded reason = %+v, want %+v | 解码原因 = %+v，期望 %+v", decoded, reason, decoded, reason)
	}
	if _, err := (RevocationReason{}).Item(); err == nil {
		t.Fatal("zero revocation reason encoded without error | 零值撤销原因未报错")
	}
	if _, err := DecodeRevocationReason(NewStructure(TagRequestPayload)); err == nil {
		t.Fatal("wrong tag decoded without error | 错误标签未报错")
	}
}

// TestDerivationParametersRoundTrip covers derivation parameters. | TestDerivationParametersRoundTrip 覆盖派生参数。
func TestDerivationParametersRoundTrip(t *testing.T) {
	params := DerivationParameters{
		CryptographicParameters: &CryptographicParameters{HashingAlgorithm: HashingAlgorithmSHA256},
		InitializationVector:    []byte("iv"),
		DerivationData:          []byte("data"),
		Salt:                    []byte("salt"),
		IterationCount:          4096,
	}
	decoded, err := DecodeDerivationParameters(params.Item())
	if err != nil {
		t.Fatalf("DecodeDerivationParameters: %v", err)
	}
	if !bytes.Equal(decoded.InitializationVector, params.InitializationVector) ||
		!bytes.Equal(decoded.DerivationData, params.DerivationData) ||
		!bytes.Equal(decoded.Salt, params.Salt) ||
		decoded.IterationCount != params.IterationCount ||
		decoded.CryptographicParameters == nil {
		t.Fatalf("decoded parameters = %+v | 解码参数 = %+v", decoded, decoded)
	}
	if _, err := DecodeDerivationParameters(NewStructure(TagRequestPayload)); err == nil {
		t.Fatal("wrong tag decoded without error | 错误标签未报错")
	}
	negative := NewStructure(TagDerivationParameters, NewInteger(TagIterationCount, -1))
	if _, err := DecodeDerivationParameters(negative); err == nil {
		t.Fatal("negative iteration count accepted | 负迭代计数被接受")
	}
	unexpected := NewStructure(TagDerivationParameters, NewInteger(TagUniqueIdentifier, 1))
	if _, err := DecodeDerivationParameters(unexpected); err == nil {
		t.Fatal("unexpected tag accepted | 意外标签被接受")
	}
}

// TestPayloadDecodeRejectsWrongType verifies every decoder rejects a non-structure. | TestPayloadDecodeRejectsWrongType 验证所有解码器拒绝非结构输入。
func TestPayloadDecodeRejectsWrongType(t *testing.T) {
	notStructure := NewInteger(TagRequestPayload, 1)
	decoders := []struct {
		name   string
		decode func(Item) error
	}{
		{"CreateRequest", func(i Item) error { _, err := DecodeCreateRequest(i); return err }},
		{"CreateResponse", func(i Item) error { _, err := DecodeCreateResponse(i); return err }},
		{"CreateKeyPairRequest", func(i Item) error { _, err := DecodeCreateKeyPairRequest(i); return err }},
		{"CreateKeyPairResponse", func(i Item) error { _, err := DecodeCreateKeyPairResponse(i); return err }},
		{"RegisterRequest", func(i Item) error { _, err := DecodeRegisterRequest(i); return err }},
		{"RegisterResponse", func(i Item) error { _, err := DecodeRegisterResponse(i); return err }},
		{"GetRequest", func(i Item) error { _, err := DecodeGetRequest(i); return err }},
		{"GetResponse", func(i Item) error { _, err := DecodeGetResponse(i); return err }},
		{"GetAttributesRequest", func(i Item) error { _, err := DecodeGetAttributesRequest(i); return err }},
		{"GetAttributesResponse", func(i Item) error { _, err := DecodeGetAttributesResponse(i); return err }},
		{"GetAttributeListRequest", func(i Item) error { _, err := DecodeGetAttributeListRequest(i); return err }},
		{"GetAttributeListResponse", func(i Item) error { _, err := DecodeGetAttributeListResponse(i); return err }},
		{"ActivateRequest", func(i Item) error { _, err := DecodeActivateRequest(i); return err }},
		{"ActivateResponse", func(i Item) error { _, err := DecodeActivateResponse(i); return err }},
		{"RevokeRequest", func(i Item) error { _, err := DecodeRevokeRequest(i); return err }},
		{"RevokeResponse", func(i Item) error { _, err := DecodeRevokeResponse(i); return err }},
		{"DestroyRequest", func(i Item) error { _, err := DecodeDestroyRequest(i); return err }},
		{"DestroyResponse", func(i Item) error { _, err := DecodeDestroyResponse(i); return err }},
		{"LocateRequest", func(i Item) error { _, err := DecodeLocateRequest(i); return err }},
		{"LocateResponse", func(i Item) error { _, err := DecodeLocateResponse(i); return err }},
		{"DeriveKeyRequest", func(i Item) error { _, err := DecodeDeriveKeyRequest(i); return err }},
		{"DeriveKeyResponse", func(i Item) error { _, err := DecodeDeriveKeyResponse(i); return err }},
		{"EncryptRequest", func(i Item) error { _, err := DecodeEncryptRequest(i); return err }},
		{"EncryptResponse", func(i Item) error { _, err := DecodeEncryptResponse(i); return err }},
		{"DecryptRequest", func(i Item) error { _, err := DecodeDecryptRequest(i); return err }},
		{"DecryptResponse", func(i Item) error { _, err := DecodeDecryptResponse(i); return err }},
		{"SignRequest", func(i Item) error { _, err := DecodeSignRequest(i); return err }},
		{"SignResponse", func(i Item) error { _, err := DecodeSignResponse(i); return err }},
		{"VerifyRequest", func(i Item) error { _, err := DecodeVerifyRequest(i); return err }},
		{"VerifyResponse", func(i Item) error { _, err := DecodeVerifyResponse(i); return err }},
		{"MACRequest", func(i Item) error { _, err := DecodeMACRequest(i); return err }},
		{"MACResponse", func(i Item) error { _, err := DecodeMACResponse(i); return err }},
		{"MACVerifyRequest", func(i Item) error { _, err := DecodeMACVerifyRequest(i); return err }},
		{"MACVerifyResponse", func(i Item) error { _, err := DecodeMACVerifyResponse(i); return err }},
		{"WrapKeyRequest", func(i Item) error { _, err := DecodeWrapKeyRequest(i); return err }},
		{"WrapKeyResponse", func(i Item) error { _, err := DecodeWrapKeyResponse(i); return err }},
		{"UnwrapKeyRequest", func(i Item) error { _, err := DecodeUnwrapKeyRequest(i); return err }},
		{"UnwrapKeyResponse", func(i Item) error { _, err := DecodeUnwrapKeyResponse(i); return err }},
		{"QueryRequest", func(i Item) error { _, err := DecodeQueryRequest(i); return err }},
		{"QueryResponse", func(i Item) error { _, err := DecodeQueryResponse(i); return err }},
		{"DiscoverVersionsRequest", func(i Item) error { _, err := DecodeDiscoverVersionsRequest(i); return err }},
		{"DiscoverVersionsResponse", func(i Item) error { _, err := DecodeDiscoverVersionsResponse(i); return err }},
		{"CheckRequest", func(i Item) error { _, err := DecodeCheckRequest(i); return err }},
		{"CheckResponse", func(i Item) error { _, err := DecodeCheckResponse(i); return err }},
	}
	for _, decoder := range decoders {
		decoder := decoder
		t.Run(decoder.name, func(t *testing.T) {
			err := decoder.decode(notStructure)
			if err == nil {
				t.Fatal("non-structure payload decoded without error | 非结构负载未报错")
			}
		})
	}
}

// TestSignedPayloadEncoding covers request encoders that validate. | TestSignedPayloadEncoding 覆盖带校验的请求编码。
func TestSignedPayloadEncoding(t *testing.T) {
	if _, err := (RevokeRequest{UniqueIdentifier: "uid"}).Item(); err == nil {
		t.Fatal("Revoke without reason encoded | 无原因 Revoke 被编码")
	}
	if _, err := (WrapKeyRequest{UniqueIdentifier: "uid"}).Item(); err == nil {
		t.Fatal("Wrap Key without specification encoded | 无规格 Wrap Key 被编码")
	}
	if _, err := (UnwrapKeyRequest{}).Item(); err == nil {
		t.Fatal("Unwrap Key without object encoded | 无对象 Unwrap Key 被编码")
	}
	if _, err := (CheckRequest{UsageLimitsCount: int64Pointer(-1)}).Item(); err == nil {
		t.Fatal("Check with negative usage count encoded | 负使用次数 Check 被编码")
	}
	if _, err := (QueryRequest{QueryFunctions: []QueryFunction{0}}).Item(); err == nil {
		t.Fatal("Query with an empty function encoded | 空功能 Query 被编码")
	}
}

// bigInt is a small helper for transparent key tests. | bigInt 是透明密钥测试的小助手。
func bigInt(value int64) *big.Int { return big.NewInt(value) }
