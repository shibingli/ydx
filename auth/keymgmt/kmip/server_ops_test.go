package kmip

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// runOpItem executes one operation through the wire round trip and returns its response item. |
// runOpItem 通过线路往返执行单个操作并返回响应项。
func runOpItem(t *testing.T, server *Server, op Operation, encoder payloadEncoder) ResponseBatchItem {
	t.Helper()
	response := roundTrip(t, server, RequestMessage{
		Header:     testHeader(),
		BatchItems: []RequestBatchItem{{Operation: op, Payload: mustItem(t, encoder)}},
	})
	if len(response.BatchItems) != 1 {
		t.Fatalf("%s returned %d items | %s 返回 %d 个项", op, len(response.BatchItems), op, len(response.BatchItems))
	}
	return response.BatchItems[0]
}

// runOp executes one operation and fails the test on an error result. | runOp 执行单个操作并在错误结果时终止测试。
func runOp(t *testing.T, server *Server, op Operation, encoder payloadEncoder) Item {
	t.Helper()
	item := runOpItem(t, server, op, encoder)
	if err := item.Err(); err != nil {
		t.Fatalf("%s failed: %v | %s 失败：%v", op, err, op, err)
	}
	return item.Payload
}

// activateKey activates a key and fails on error. | activateKey 激活密钥，失败时终止测试。
func activateKey(t *testing.T, server *Server, uid string) {
	t.Helper()
	runOp(t, server, OpActivate, ActivateRequest{UniqueIdentifier: uid})
}

// createKeyPair creates a key pair and returns the private and public identifiers. |
// createKeyPair 创建密钥对并返回私钥与公钥标识符。
func createKeyPair(t *testing.T, server *Server, algorithm CryptographicAlgorithm, length int) (string, string) {
	t.Helper()
	item := runOp(t, server, OpCreateKeyPair, CreateKeyPairRequest{
		CommonTemplateAttribute: &TemplateAttribute{Attributes: AttributeList{
			NewEnumerationAttribute(AttributeCryptographicAlgorithm, uint32(algorithm)),
			NewIntegerAttribute(AttributeCryptographicLength, int64(length)),
		}},
	})
	response, err := DecodeCreateKeyPairResponse(item)
	if err != nil {
		t.Fatalf("DecodeCreateKeyPairResponse: %v", err)
	}
	return response.PrivateKeyUniqueIdentifier, response.PublicKeyUniqueIdentifier
}

// getObject loads one object with Get. | getObject 使用 Get 加载一个对象。
func getObject(t *testing.T, server *Server, request GetRequest) Object {
	t.Helper()
	response, err := DecodeGetResponse(runOp(t, server, OpGet, request))
	if err != nil {
		t.Fatalf("DecodeGetResponse: %v", err)
	}
	return response.Object
}

// TestServerCreateKeyPairAndGetFormats covers key pair generation and Get format conversion. |
// TestServerCreateKeyPairAndGetFormats 覆盖密钥对生成与 Get 格式转换。
func TestServerCreateKeyPairAndGetFormats(t *testing.T) {
	server := newTestServer(t)
	privateID, publicID := createKeyPair(t, server, AlgorithmRSA, 2048)
	privateObject := getObject(t, server, GetRequest{UniqueIdentifier: privateID})
	if privateObject.Type != ObjectTypePrivateKey {
		t.Fatalf("private object type = %s | 私钥对象类型 = %s", privateObject.Type, privateObject.Type)
	}
	if kb, err := privateObject.KeyBlock(); err != nil || kb.Algorithm != AlgorithmRSA || kb.Length != 2048 {
		t.Fatalf("private key block = %+v, %v | 私钥块 = %+v，%v", kb, err, kb, err)
	}
	pkcs1 := getObject(t, server, GetRequest{UniqueIdentifier: privateID, KeyFormatType: KeyFormatPKCS1})
	if kb, err := pkcs1.KeyBlock(); err != nil || kb.Format != KeyFormatPKCS1 {
		t.Fatalf("PKCS#1 conversion = %+v, %v | PKCS#1 转换 = %+v，%v", kb, err, kb, err)
	}
	publicObject := getObject(t, server, GetRequest{UniqueIdentifier: publicID})
	transparent := getObject(t, server, GetRequest{UniqueIdentifier: publicID, KeyFormatType: KeyFormatTransparentRSAPublicKey})
	if kb, err := transparent.KeyBlock(); err != nil || kb.Format != KeyFormatTransparentRSAPublicKey {
		t.Fatalf("transparent RSA conversion = %+v, %v | 透明 RSA 转换 = %+v，%v", kb, err, kb, err)
	}
	if _, err := transparent.KeyBlock(); err != nil {
		t.Fatalf("transparent block: %v", err)
	}
	if publicObject.Type != ObjectTypePublicKey {
		t.Fatalf("public object type = %s | 公钥对象类型 = %s", publicObject.Type, publicObject.Type)
	}

	ecdsaPrivate, ecdsaPublic := createKeyPair(t, server, AlgorithmECDSA, 256)
	sec1 := getObject(t, server, GetRequest{UniqueIdentifier: ecdsaPrivate, KeyFormatType: KeyFormatECPrivateKey})
	if kb, err := sec1.KeyBlock(); err != nil || kb.Format != KeyFormatECPrivateKey {
		t.Fatalf("SEC1 conversion = %+v, %v | SEC1 转换 = %+v，%v", kb, err, kb, err)
	}
	compressed := getObject(t, server, GetRequest{UniqueIdentifier: ecdsaPublic, KeyCompressionType: KeyCompressionECPublicKeyUncompressed})
	if compressed.Type != ObjectTypePublicKey {
		t.Fatalf("compressed get type = %s | 压缩获取类型 = %s", compressed.Type, compressed.Type)
	}
	if _, err := createKeyPairResponseFor(t, server, AlgorithmEd25519, 256); err != nil {
		t.Fatalf("Ed25519 key pair: %v | Ed25519 密钥对：%v", err, err)
	}
	if _, err := createKeyPairResponseFor(t, server, AlgorithmSM2, 256); err != nil {
		t.Fatalf("SM2 key pair: %v | SM2 密钥对：%v", err, err)
	}

	for _, testCase := range []struct {
		name      string
		algorithm CryptographicAlgorithm
		length    int
	}{
		{"unsupported algorithm", AlgorithmHMACSHA256, 256},
		{"short RSA", AlgorithmRSA, 1024},
		{"unsupported curve", AlgorithmECDSA, 123},
		{"bad Ed25519 length", AlgorithmEd25519, 128},
	} {
		item := runOpItem(t, server, OpCreateKeyPair, CreateKeyPairRequest{
			CommonTemplateAttribute: &TemplateAttribute{Attributes: AttributeList{
				NewEnumerationAttribute(AttributeCryptographicAlgorithm, uint32(testCase.algorithm)),
				NewIntegerAttribute(AttributeCryptographicLength, int64(testCase.length)),
			}},
		})
		if item.ResultStatus == ResultStatusSuccess {
			t.Fatalf("%s succeeded | %s 成功", testCase.name, testCase.name)
		}
	}
	if item := runOpItem(t, server, OpCreateKeyPair, CreateKeyPairRequest{}); item.ResultStatus == ResultStatusSuccess {
		t.Fatal("empty CreateKeyPair succeeded | 空 CreateKeyPair 成功")
	}
}

// createKeyPairResponseFor generates a key pair and decodes its response. | createKeyPairResponseFor 生成密钥对并解码响应。
func createKeyPairResponseFor(t *testing.T, server *Server, algorithm CryptographicAlgorithm, length int) (CreateKeyPairResponse, error) {
	t.Helper()
	item := runOpItem(t, server, OpCreateKeyPair, CreateKeyPairRequest{
		CommonTemplateAttribute: &TemplateAttribute{Attributes: AttributeList{
			NewEnumerationAttribute(AttributeCryptographicAlgorithm, uint32(algorithm)),
			NewIntegerAttribute(AttributeCryptographicLength, int64(length)),
		}},
	})
	if err := item.Err(); err != nil {
		return CreateKeyPairResponse{}, err
	}
	return DecodeCreateKeyPairResponse(item.Payload)
}

// TestServerRegisterObjects covers Register for every supported object type and its errors. |
// TestServerRegisterObjects 覆盖所有受支持对象类型的 Register 及其错误。
func TestServerRegisterObjects(t *testing.T) {
	server := newTestServer(t)
	template := TemplateAttribute{Attributes: AttributeList{
		NewBooleanAttribute(AttributeExtractable, false),
		NewTextAttribute(AttributeObjectGroup, "registered"),
	}}
	cases := []struct {
		name       string
		objectType ObjectType
		object     Object
	}{
		{"symmetric", ObjectTypeSymmetricKey, NewSymmetricKeyObject(rawKeyBlock(AlgorithmAES, testKeyMaterial()))},
		{"secret", ObjectTypeSecretData, NewSecretDataObject(SecretDataTypePassword, rawKeyBlock(AlgorithmAES, testKeyMaterial()))},
		{"certificate", ObjectTypeCertificate, NewCertificateObject(CertificateTypeX509, []byte{1, 2, 3})},
		{"template", ObjectTypeTemplate, NewTemplateObject(AttributeList{NewTextAttribute(AttributeComment, "template")})},
		{"opaque", ObjectTypeOpaqueObject, NewOpaqueObject(7, []byte{4, 5})},
	}
	for _, testCase := range cases {
		item := runOpItem(t, server, OpRegister, RegisterRequest{
			ObjectType:        testCase.objectType,
			TemplateAttribute: template,
			Object:            testCase.object,
		})
		if err := item.Err(); err != nil {
			t.Fatalf("Register %s: %v | 注册 %s 失败：%v", testCase.name, err, testCase.name, err)
		}
		response, err := DecodeRegisterResponse(item.Payload)
		if err != nil || response.UniqueIdentifier == "" {
			t.Fatalf("DecodeRegisterResponse %s = %+v, %v | 注册响应 %s = %+v，%v", testCase.name, response, err, testCase.name, response, err)
		}
		record, err := server.store.Get(context.Background(), response.UniqueIdentifier)
		if err != nil || record.Extractable || len(record.ObjectGroups) != 1 {
			t.Fatalf("registered record %s = %+v, %v | 注册记录 %s = %+v，%v", testCase.name, record, err, testCase.name, record, err)
		}
	}

	private := NewPrivateKeyObject(rawKeyBlock(AlgorithmAES, testKeyMaterial()))
	// Direct handler call because DecodeRegisterRequest rejects a type mismatch. | 直接调用处理器，因为解码器会拒绝类型不一致。
	if _, err := server.handleRegister(RegisterRequest{ObjectType: ObjectTypePublicKey, Object: private}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("type mismatch error = %v | 类型不一致错误 = %v", err, err)
	}
	invalid := NewSymmetricKeyObject(rawKeyBlock(AlgorithmRSA, []byte{1, 2, 3}))
	if _, err := server.handleRegister(RegisterRequest{ObjectType: ObjectTypeSymmetricKey, Object: invalid}); err == nil {
		t.Fatal("invalid key material was registered | 非法密钥材料被注册")
	}
	if _, err := server.handleRegister(RegisterRequest{ObjectType: ObjectType(0x7F), Object: Object{Type: ObjectType(0x7F)}}); err == nil {
		t.Fatal("unsupported object type was registered | 不支持的对象类型被注册")
	}
}

// TestServerAttributes covers Get Attributes and Get Attribute List. | TestServerAttributes 覆盖获取属性与属性列表。
func TestServerAttributes(t *testing.T) {
	server := newTestServer(t)
	uid := createSymmetric(t, server)
	item := runOp(t, server, OpGetAttributes, GetAttributesRequest{
		UniqueIdentifier: uid,
		AttributeNames:   []string{AttributeState, AttributeCryptographicAlgorithm, AttributeCryptographicLength, AttributeObjectType},
	})
	attrs, err := DecodeGetAttributesResponse(item)
	if err != nil {
		t.Fatalf("DecodeGetAttributesResponse: %v", err)
	}
	if value, ok, err := attrs.LookupEnumeration(AttributeObjectType); err != nil || !ok || ObjectType(value) != ObjectTypeSymmetricKey {
		t.Fatalf("object type = %d, %v, %v | 对象类型 = %d，%v，%v", value, ok, err, value, ok, err)
	}
	if value, ok, err := attrs.LookupEnumeration(AttributeCryptographicAlgorithm); err != nil || !ok || CryptographicAlgorithm(value) != AlgorithmAES {
		t.Fatalf("algorithm = %d, %v, %v | 算法 = %d，%v，%v", value, ok, err, value, ok, err)
	}
	if _, ok := attrs.Lookup(AttributeUniqueIdentifier); ok {
		t.Fatal("filtered attribute leaked | 过滤属性泄漏")
	}
	listItem := runOp(t, server, OpGetAttributeList, GetAttributeListRequest{UniqueIdentifier: uid})
	names, err := DecodeGetAttributeListResponse(listItem)
	if err != nil {
		t.Fatalf("DecodeGetAttributeListResponse: %v", err)
	}
	found := false
	for _, name := range names.AttributeNames {
		if name == AttributeState {
			found = true
		}
	}
	if !found {
		t.Fatalf("attribute list has no State: %v | 属性列表没有 State：%v", names.AttributeNames, names.AttributeNames)
	}
	missing := runOpItem(t, server, OpGetAttributes, GetAttributesRequest{UniqueIdentifier: "missing"})
	if !errors.Is(missing.Err(), ErrItemNotFound) {
		t.Fatalf("missing GetAttributes error = %v | 缺失对象获取属性错误 = %v", missing.Err(), missing.Err())
	}
	if item := runOpItem(t, server, OpGetAttributeList, GetAttributeListRequest{}); item.ResultStatus == ResultStatusSuccess {
		t.Fatal("empty GetAttributeList succeeded | 空 GetAttributeList 成功")
	}
}

// TestServerStateTransitions covers Activate, Revoke and Destroy including failure paths. |
// TestServerStateTransitions 覆盖 Activate、Revoke 与 Destroy 及失败路径。
func TestServerStateTransitions(t *testing.T) {
	server := newTestServer(t)
	uid := createSymmetric(t, server)
	if state := stateOf(t, server, uid); state != StatePreActive {
		t.Fatalf("initial state = %s | 初始状态 = %s", state, state)
	}
	activateKey(t, server, uid)
	if state := stateOf(t, server, uid); state != StateActive {
		t.Fatalf("activated state = %s | 激活后状态 = %s", state, state)
	}
	if item := runOpItem(t, server, OpActivate, ActivateRequest{UniqueIdentifier: uid}); !errors.Is(item.Err(), ErrIllegalOperation) {
		t.Fatalf("second Activate error = %v | 二次激活错误 = %v", item.Err(), item.Err())
	}
	if _, err := server.handleRevoke(RevokeRequest{UniqueIdentifier: uid}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Revoke without reason error = %v | 无原因撤销错误 = %v", err, err)
	}
	occurrence := testDate()
	runOp(t, server, OpRevoke, RevokeRequest{
		UniqueIdentifier:         uid,
		Reason:                   RevocationReason{Code: RevocationKeyCompromise, Message: "test"},
		CompromiseOccurrenceDate: occurrence,
	})
	if state := stateOf(t, server, uid); state != StateCompromised {
		t.Fatalf("compromised state = %s | 泄露后状态 = %s", state, state)
	}
	record, err := server.store.Get(context.Background(), uid)
	if err != nil || !record.CompromiseOccurrenceDate.Equal(occurrence) || !record.DeactivationDate.Equal(record.LastChangeDate) {
		t.Fatalf("compromised record = %+v, %v | 泄露记录 = %+v，%v", record, err, record, err)
	}
	if item := runOpItem(t, server, OpRevoke, RevokeRequest{UniqueIdentifier: uid, Reason: RevocationReason{Code: RevocationCessationOfOperation}}); !errors.Is(item.Err(), ErrIllegalOperation) {
		t.Fatalf("revoke compromised error = %v | 撤销泄露对象错误 = %v", item.Err(), item.Err())
	}
	if item := runOpItem(t, server, OpActivate, ActivateRequest{UniqueIdentifier: uid}); !errors.Is(item.Err(), ErrIllegalOperation) {
		t.Fatalf("activate compromised error = %v | 激活泄露对象错误 = %v", item.Err(), item.Err())
	}

	second := createSymmetric(t, server)
	runOp(t, server, OpRevoke, RevokeRequest{UniqueIdentifier: second, Reason: RevocationReason{Code: RevocationCessationOfOperation}})
	if state := stateOf(t, server, second); state != StateDeactivated {
		t.Fatalf("deactivated state = %s | 停用后状态 = %s", state, state)
	}
	runOp(t, server, OpDestroy, DestroyRequest{UniqueIdentifier: second})
	if state := stateOf(t, server, second); state != StateDestroyed {
		t.Fatalf("destroyed state = %s | 销毁后状态 = %s", state, state)
	}
	if record, err := server.store.Get(context.Background(), second); err != nil || record.Object != nil {
		t.Fatalf("destroyed record kept material: %+v, %v | 销毁记录保留了材料：%+v，%v", record, err, record, err)
	}
	if item := runOpItem(t, server, OpDestroy, DestroyRequest{UniqueIdentifier: second}); !errors.Is(item.Err(), ErrIllegalOperation) {
		t.Fatalf("second Destroy error = %v | 二次销毁错误 = %v", item.Err(), item.Err())
	}
	if item := runOpItem(t, server, OpGet, GetRequest{UniqueIdentifier: second}); !errors.Is(item.Err(), ErrIllegalOperation) {
		t.Fatalf("Get destroyed error = %v | 获取已销毁对象错误 = %v", item.Err(), item.Err())
	}
	if item := runOpItem(t, server, OpGet, GetRequest{UniqueIdentifier: "missing"}); !errors.Is(item.Err(), ErrItemNotFound) {
		t.Fatalf("Get missing error = %v | 获取缺失对象错误 = %v", item.Err(), item.Err())
	}
	if item := runOpItem(t, server, OpGet, GetRequest{}); !errors.Is(item.Err(), ErrMalformed) {
		t.Fatalf("Get empty identifier error = %v | 空标识符获取错误 = %v", item.Err(), item.Err())
	}
}

// TestServerGetExtractionRules covers non-extractable and key wrapping behavior. |
// TestServerGetExtractionRules 覆盖不可导出与密钥封装行为。
func TestServerGetExtractionRules(t *testing.T) {
	server := newTestServer(t)
	registered := runOp(t, server, OpRegister, RegisterRequest{
		ObjectType: ObjectTypeSymmetricKey,
		TemplateAttribute: TemplateAttribute{Attributes: AttributeList{
			NewBooleanAttribute(AttributeExtractable, false),
		}},
		Object: NewSymmetricKeyObject(rawKeyBlock(AlgorithmAES, testKeyMaterial())),
	})
	registeredResponse, err := DecodeRegisterResponse(registered)
	if err != nil {
		t.Fatalf("DecodeRegisterResponse: %v", err)
	}
	item := runOpItem(t, server, OpGet, GetRequest{UniqueIdentifier: registeredResponse.UniqueIdentifier})
	if !errors.Is(item.Err(), ErrPermissionDenied) || item.ResultReason != ResultReasonNotExtractable {
		t.Fatalf("non-extractable Get = %v, %s | 不可导出 Get = %v，%s", item.Err(), item.ResultReason, item.Err(), item.ResultReason)
	}
	wrappingUID := createSymmetric(t, server)
	activateKey(t, server, wrappingUID)
	targetUID := createSymmetric(t, server)
	spec := KeyWrappingSpecification{
		WrappingMethod:           WrappingMethodEncrypt,
		EncryptionKeyInformation: &EncryptionKeyInformation{UniqueIdentifier: wrappingUID},
	}
	wrapped := getObject(t, server, GetRequest{UniqueIdentifier: targetUID, KeyWrappingSpecification: &spec})
	kb, err := wrapped.KeyBlock()
	if err != nil || kb.Wrapping == nil || len(kb.Value.Material.Value) == 0 {
		t.Fatalf("wrapped key block = %+v, %v | 已封装密钥块 = %+v，%v", kb, err, kb, err)
	}
	if kb.Wrapping.EncryptionKeyInformation == nil || kb.Wrapping.EncryptionKeyInformation.UniqueIdentifier != wrappingUID {
		t.Fatalf("wrapping key information = %+v | 封装密钥信息 = %+v", kb.Wrapping.EncryptionKeyInformation, kb.Wrapping.EncryptionKeyInformation)
	}
	if item := runOpItem(t, server, OpGet, GetRequest{UniqueIdentifier: targetUID, KeyWrappingSpecification: &KeyWrappingSpecification{WrappingMethod: WrappingMethodEncrypt}}); !errors.Is(item.Err(), ErrMalformed) {
		t.Fatalf("wrapping without key error = %v | 无密钥封装错误 = %v", item.Err(), item.Err())
	}
	if item := runOpItem(t, server, OpGet, GetRequest{UniqueIdentifier: targetUID, KeyWrappingSpecification: &KeyWrappingSpecification{
		WrappingMethod:           WrappingMethodEncrypt,
		EncryptionKeyInformation: &EncryptionKeyInformation{UniqueIdentifier: "missing"},
	}}); !errors.Is(item.Err(), ErrItemNotFound) {
		t.Fatalf("wrapping with missing key error = %v | 缺失封装密钥错误 = %v", item.Err(), item.Err())
	}
	if item := runOpItem(t, server, OpGet, GetRequest{UniqueIdentifier: targetUID, KeyWrapType: KeyWrapTypeNotWrapped}); item.ResultStatus != ResultStatusSuccess {
		t.Fatalf("not-wrapped Get = %v | 未封装 Get = %v", item.Err(), item.Err())
	}
	if item := runOpItem(t, server, OpGet, GetRequest{UniqueIdentifier: targetUID, KeyWrapType: KeyWrapTypeAsRegistered}); item.ResultStatus != ResultStatusSuccess {
		t.Fatalf("as-registered Get = %v | 按注册 Get = %v", item.Err(), item.Err())
	}
	if item := runOpItem(t, server, OpGet, GetRequest{UniqueIdentifier: targetUID, KeyWrapType: KeyWrapType(0x7F)}); !errors.Is(item.Err(), ErrUnsupported) {
		t.Fatalf("bad wrap type error = %v | 非法封装类型错误 = %v", item.Err(), item.Err())
	}
	if item := runOpItem(t, server, OpGet, GetRequest{UniqueIdentifier: targetUID, KeyCompressionType: KeyCompressionECPublicKeyX962Prime}); !errors.Is(item.Err(), ErrUnsupported) {
		t.Fatalf("bad compression error = %v | 非法压缩错误 = %v", item.Err(), item.Err())
	}
}

// TestServerLocate covers Locate criteria, pagination and storage status. | TestServerLocate 覆盖 Locate 条件、分页与存储状态。
func TestServerLocate(t *testing.T) {
	server := newTestServer(t)
	first := createSymmetric(t, server)
	second := createSymmetric(t, server)
	runOp(t, server, OpGetAttributes, GetAttributesRequest{UniqueIdentifier: first})
	locate := func(request LocateRequest) LocateResponse {
		t.Helper()
		response, err := DecodeLocateResponse(runOp(t, server, OpLocate, request))
		if err != nil {
			t.Fatalf("DecodeLocateResponse: %v", err)
		}
		return response
	}
	all := locate(LocateRequest{Attributes: AttributeList{NewEnumerationAttribute(AttributeObjectType, uint32(ObjectTypeSymmetricKey))}})
	if all.LocatedItems != 2 || len(all.UniqueIdentifiers) != 2 {
		t.Fatalf("Locate all = %+v | 全部定位 = %+v", all, all)
	}
	page := locate(LocateRequest{OffsetItems: 1, MaximumItems: 1, Attributes: AttributeList{NewEnumerationAttribute(AttributeObjectType, uint32(ObjectTypeSymmetricKey))}})
	if page.LocatedItems != 2 || len(page.UniqueIdentifiers) != 1 ||
		(page.UniqueIdentifiers[0] != first && page.UniqueIdentifiers[0] != second) {
		t.Fatalf("Locate page = %+v | 分页定位 = %+v", page, page)
	}
	beyond := locate(LocateRequest{OffsetItems: 5, Attributes: AttributeList{NewEnumerationAttribute(AttributeObjectType, uint32(ObjectTypeSymmetricKey))}})
	if beyond.LocatedItems != 2 || len(beyond.UniqueIdentifiers) != 0 {
		t.Fatalf("Locate beyond offset = %+v | 越界偏移定位 = %+v", beyond, beyond)
	}
	byState := locate(LocateRequest{Attributes: AttributeList{NewEnumerationAttribute(AttributeState, uint32(StatePreActive))}})
	if byState.LocatedItems != 2 {
		t.Fatalf("Locate pre-active = %+v | 定位预活动 = %+v", byState, byState)
	}
	byID := locate(LocateRequest{Attributes: AttributeList{NewTextAttribute(AttributeUniqueIdentifier, first)}})
	if byID.LocatedItems != 1 || byID.UniqueIdentifiers[0] != first {
		t.Fatalf("Locate by id = %+v | 按标识符定位 = %+v", byID, byID)
	}
	offline := locate(LocateRequest{StorageStatusMask: 0x2, Attributes: AttributeList{NewEnumerationAttribute(AttributeObjectType, uint32(ObjectTypeSymmetricKey))}})
	if offline.LocatedItems != 0 || len(offline.UniqueIdentifiers) != 0 {
		t.Fatalf("Locate offline = %+v | 离线定位 = %+v", offline, offline)
	}
	none := locate(LocateRequest{Attributes: AttributeList{NewTextAttribute(AttributeUniqueIdentifier, "missing")}})
	if none.LocatedItems != 0 {
		t.Fatalf("Locate none = %+v | 无匹配定位 = %+v", none, none)
	}
}

// TestServerDeriveKey covers HKDF and PBKDF2 derivation and its errors. |
// TestServerDeriveKey 覆盖 HKDF 与 PBKDF2 派生及其错误。
func TestServerDeriveKey(t *testing.T) {
	server := newTestServer(t)
	uid := createSymmetric(t, server)
	if item := runOpItem(t, server, OpDeriveKey, DeriveKeyRequest{
		ObjectType:        ObjectTypeSymmetricKey,
		UniqueIdentifiers: []string{uid},
		DerivationMethod:  DerivationMethodHKDF,
		DerivationParameters: DerivationParameters{
			DerivationData: []byte("context"),
			Salt:           []byte("salt"),
		},
		TemplateAttribute: TemplateAttribute{Attributes: AttributeList{
			NewEnumerationAttribute(AttributeCryptographicAlgorithm, uint32(AlgorithmAES)),
			NewIntegerAttribute(AttributeCryptographicLength, 128),
		}},
	}); !errors.Is(item.Err(), ErrIllegalOperation) {
		t.Fatalf("derive from pre-active error = %v | 预活动派生错误 = %v", item.Err(), item.Err())
	}
	activateKey(t, server, uid)
	hkdfItem := runOp(t, server, OpDeriveKey, DeriveKeyRequest{
		ObjectType:        ObjectTypeSymmetricKey,
		UniqueIdentifiers: []string{uid},
		DerivationMethod:  DerivationMethodHKDF,
		DerivationParameters: DerivationParameters{
			DerivationData: []byte("context"),
			Salt:           []byte("salt"),
		},
		TemplateAttribute: TemplateAttribute{Attributes: AttributeList{
			NewEnumerationAttribute(AttributeCryptographicAlgorithm, uint32(AlgorithmAES)),
			NewIntegerAttribute(AttributeCryptographicLength, 128),
		}},
	})
	hkdfResponse, err := DecodeDeriveKeyResponse(hkdfItem)
	if err != nil || hkdfResponse.UniqueIdentifier == "" {
		t.Fatalf("HKDF response = %+v, %v | HKDF 响应 = %+v，%v", hkdfResponse, err, hkdfResponse, err)
	}
	pbkdfItem := runOp(t, server, OpDeriveKey, DeriveKeyRequest{
		ObjectType:        ObjectTypeSymmetricKey,
		UniqueIdentifiers: []string{uid},
		DerivationMethod:  DerivationMethodPBKDF2,
		DerivationParameters: DerivationParameters{
			Salt:           []byte("salt"),
			IterationCount: 1000,
		},
		TemplateAttribute: TemplateAttribute{Attributes: AttributeList{
			NewEnumerationAttribute(AttributeCryptographicAlgorithm, uint32(AlgorithmAES)),
			NewIntegerAttribute(AttributeCryptographicLength, 256),
		}},
	})
	pbkdfResponse, err := DecodeDeriveKeyResponse(pbkdfItem)
	if err != nil || pbkdfResponse.UniqueIdentifier == "" {
		t.Fatalf("PBKDF2 response = %+v, %v | PBKDF2 响应 = %+v，%v", pbkdfResponse, err, pbkdfResponse, err)
	}
	errorsToCheck := []struct {
		name    string
		request DeriveKeyRequest
	}{
		{"wrong object type", DeriveKeyRequest{ObjectType: ObjectTypePrivateKey, UniqueIdentifiers: []string{uid}, DerivationMethod: DerivationMethodHKDF}},
		{"missing key", DeriveKeyRequest{ObjectType: ObjectTypeSymmetricKey, UniqueIdentifiers: []string{"missing"}, DerivationMethod: DerivationMethodHKDF}},
		{"unsupported method", DeriveKeyRequest{ObjectType: ObjectTypeSymmetricKey, UniqueIdentifiers: []string{uid}, DerivationMethod: DerivationMethod(0x7F)}},
		{"bad template", DeriveKeyRequest{ObjectType: ObjectTypeSymmetricKey, UniqueIdentifiers: []string{uid}, DerivationMethod: DerivationMethodHKDF,
			TemplateAttribute: TemplateAttribute{Attributes: AttributeList{NewTextAttribute(AttributeCryptographicAlgorithm, "x")}}}},
	}
	for _, testCase := range errorsToCheck {
		if item := runOpItem(t, server, OpDeriveKey, testCase.request); item.ResultStatus == ResultStatusSuccess {
			t.Fatalf("%s succeeded | %s 成功", testCase.name, testCase.name)
		}
	}
}

// TestServerQueryAndDiscovery covers Query, Discover Versions and Check. |
// TestServerQueryAndDiscovery 覆盖 Query、Discover Versions 与 Check。
func TestServerQueryAndDiscovery(t *testing.T) {
	server := newTestServer(t)
	query := func(functions ...QueryFunction) QueryResponse {
		t.Helper()
		response, err := DecodeQueryResponse(runOp(t, server, OpQuery, QueryRequest{QueryFunctions: functions}))
		if err != nil {
			t.Fatalf("DecodeQueryResponse: %v", err)
		}
		return response
	}
	all := query(QueryFunctionOperations, QueryFunctionObjects, QueryFunctionServerInformation, QueryFunctionApplicationNamespaces, QueryFunction(0x7F))
	if len(all.Operations) == 0 || len(all.ObjectTypes) == 0 || all.ServerInformation.Type != TypeStructure ||
		len(all.ApplicationNamespaces) != 1 || all.VendorIdentification != "ydx" {
		t.Fatalf("Query response = %+v | Query 响应 = %+v", all, all)
	}
	if item := runOpItem(t, server, OpQuery, QueryRequest{}); !errors.Is(item.Err(), ErrMalformed) {
		t.Fatalf("empty Query error = %v | 空 Query 错误 = %v", item.Err(), item.Err())
	}
	discover := func(request DiscoverVersionsRequest) DiscoverVersionsResponse {
		t.Helper()
		response, err := DecodeDiscoverVersionsResponse(runOp(t, server, OpDiscoverVersions, request))
		if err != nil {
			t.Fatalf("DecodeDiscoverVersionsResponse: %v", err)
		}
		return response
	}
	if versions := discover(DiscoverVersionsRequest{}); len(versions.ProtocolVersions) != 2 ||
		versions.ProtocolVersions[0].Compare(ProtocolVersion20) != 0 || versions.ProtocolVersions[1].Compare(ProtocolVersion14) != 0 {
		t.Fatalf("Discover default = %+v | 默认版本发现 = %+v", versions, versions)
	}
	if versions := discover(DiscoverVersionsRequest{ProtocolVersions: []ProtocolVersion{ProtocolVersion14, ProtocolVersion20}}); len(versions.ProtocolVersions) != 2 {
		t.Fatalf("Discover common = %+v | 公共版本发现 = %+v", versions, versions)
	}
	if versions := discover(DiscoverVersionsRequest{ProtocolVersions: []ProtocolVersion{ProtocolVersion12}}); len(versions.ProtocolVersions) != 0 {
		t.Fatalf("Discover disjoint = %+v | 无交集版本发现 = %+v", versions, versions)
	}

	uid := createSymmetric(t, server)
	check, err := DecodeCheckResponse(runOp(t, server, OpCheck, CheckRequest{
		UniqueIdentifier:       uid,
		CryptographicUsageMask: UsageMaskEncrypt | UsageMaskDecrypt,
	}))
	if err != nil || check.UniqueIdentifier != uid || !check.CryptographicUsageMask.Has(UsageMaskEncrypt) {
		t.Fatalf("Check response = %+v, %v | Check 响应 = %+v，%v", check, err, check, err)
	}
	count := int64(1)
	if item := runOpItem(t, server, OpCheck, CheckRequest{UniqueIdentifier: uid, UsageLimitsCount: &count}); !errors.Is(item.Err(), ErrUnsupported) {
		t.Fatalf("usage limits Check error = %v | 使用次数 Check 错误 = %v", item.Err(), item.Err())
	}
	lease := time.Minute
	if item := runOpItem(t, server, OpCheck, CheckRequest{UniqueIdentifier: uid, LeaseTime: &lease}); !errors.Is(item.Err(), ErrUnsupported) {
		t.Fatalf("lease Check error = %v | 租用 Check 错误 = %v", item.Err(), item.Err())
	}
	if item := runOpItem(t, server, OpCheck, CheckRequest{UniqueIdentifier: uid, CryptographicUsageMask: UsageMaskSign}); !errors.Is(item.Err(), ErrUsageMask) {
		t.Fatalf("usage mask Check error = %v | 用法掩码 Check 错误 = %v", item.Err(), item.Err())
	}
	if item := runOpItem(t, server, OpCheck, CheckRequest{}); !errors.Is(item.Err(), ErrMalformed) {
		t.Fatalf("empty Check error = %v | 空 Check 错误 = %v", item.Err(), item.Err())
	}
}

// TestServerAuthorizer covers allow, deny, wrapping and request metadata. |
// TestServerAuthorizer 覆盖允许、拒绝、错误包装与请求元数据。
func TestServerAuthorizer(t *testing.T) {
	var seen AuthorizationRequest
	allowed := false
	server, err := NewServer(ServerConfig{
		AllowPlaintext: true,
		Store:          NewMemoryStore(),
		Authorizer: AuthorizerFunc(func(ctx context.Context, request AuthorizationRequest) error {
			seen = request
			if !allowed {
				return ErrPermissionDenied
			}
			return nil
		}),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	request := RequestMessage{
		Header: RequestHeader{
			ProtocolVersion: DefaultProtocolVersion,
			Authentication:  &Authentication{Credentials: []Credential{{Username: "user", Password: "secret"}}},
		},
		BatchItems: []RequestBatchItem{{
			Operation: OpCreate,
			Payload:   mustItem(t, CreateRequest{ObjectType: ObjectTypeSymmetricKey, TemplateAttribute: symmetricTemplate()}),
		}},
	}
	client, serverConn := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = serverConn.Close() }()
	response := server.handleMessage(serverConn, request)
	if len(response.BatchItems) != 1 || !errors.Is(response.BatchItems[0].Err(), ErrPermissionDenied) {
		t.Fatalf("denied response = %+v | 拒绝响应 = %+v", response.BatchItems, response.BatchItems)
	}
	if seen.Operation != OpCreate || seen.ObjectType != ObjectTypeSymmetricKey || len(seen.Credentials) != 1 ||
		seen.Credentials[0].Username != "user" || seen.RemoteAddr == "" {
		t.Fatalf("authorization request = %+v | 授权请求 = %+v", seen, seen)
	}

	allowed = true
	seen = AuthorizationRequest{}
	response = server.handleMessage(nil, request)
	if len(response.BatchItems) != 1 || response.BatchItems[0].Err() != nil {
		t.Fatalf("allowed response = %+v | 允许响应 = %+v", response.BatchItems, response.BatchItems)
	}
	if seen.Operation != OpCreate || seen.UniqueIdentifier != "" {
		t.Fatalf("allowed metadata = %+v | 允许元数据 = %+v", seen, seen)
	}

	wrapped, err := NewServer(ServerConfig{AllowPlaintext: true, Authorizer: AuthorizerFunc(func(context.Context, AuthorizationRequest) error {
		return errors.New("policy backend unavailable")
	})})
	if err != nil {
		t.Fatalf("NewServer wrapped: %v", err)
	}
	t.Cleanup(func() { _ = wrapped.Close() })
	response = wrapped.handleMessage(nil, request)
	if len(response.BatchItems) != 1 || !errors.Is(response.BatchItems[0].Err(), ErrPermissionDenied) {
		t.Fatalf("wrapped authorizer error = %+v | 包装的授权错误 = %+v", response.BatchItems, response.BatchItems)
	}
}

// failingListStore fails List after a configurable successful call count. | failingListStore 在可配置的成功调用次数后使 List 失败。
type failingListStore struct {
	Store
	calls     int
	failAfter int
}

// List implements Store. | List 实现 Store。
func (s *failingListStore) List(ctx context.Context) ([]ObjectRecord, error) {
	s.calls++
	if s.failAfter > 0 && s.calls >= s.failAfter {
		return nil, ErrClosed
	}
	return s.Store.List(ctx)
}

// TestServerBatchPolicies covers Stop, Continue, Undo, undo failure and version rejection. |
// TestServerBatchPolicies 覆盖 Stop、Continue、Undo、撤销失败与版本拒绝。
func TestServerBatchPolicies(t *testing.T) {
	server := newTestServer(t)
	createRequest := RequestBatchItem{
		Operation:         OpCreate,
		UniqueBatchItemID: []byte{1, 2, 3},
		Payload:           mustItem(t, CreateRequest{ObjectType: ObjectTypeSymmetricKey, TemplateAttribute: symmetricTemplate()}),
	}
	failingRequest := RequestBatchItem{
		Operation:         OpGet,
		UniqueBatchItemID: []byte{4},
		Payload:           mustItem(t, GetRequest{UniqueIdentifier: "missing"}),
	}
	stopResponse := server.handleMessage(nil, RequestMessage{
		Header:     RequestHeader{ProtocolVersion: DefaultProtocolVersion, BatchErrorContinuationOption: BatchStop},
		BatchItems: []RequestBatchItem{createRequest, failingRequest, createRequest},
	})
	if len(stopResponse.BatchItems) != 2 || stopResponse.BatchItems[0].Err() != nil || stopResponse.BatchItems[1].Err() == nil {
		t.Fatalf("Stop batch = %+v | Stop 批处理 = %+v", stopResponse.BatchItems, stopResponse.BatchItems)
	}
	if string(stopResponse.BatchItems[0].UniqueBatchItemID) != string(createRequest.UniqueBatchItemID) {
		t.Fatal("batch item ID was not echoed | 批处理项标识未回显")
	}
	if records, _ := server.store.List(context.Background()); len(records) != 1 {
		t.Fatalf("Stop created %d records | Stop 创建了 %d 条记录", len(records), len(records))
	}

	server2 := newTestServer(t)
	continueResponse := server2.handleMessage(nil, RequestMessage{
		Header:     RequestHeader{ProtocolVersion: DefaultProtocolVersion, BatchErrorContinuationOption: BatchContinue},
		BatchItems: []RequestBatchItem{createRequest, failingRequest, createRequest},
	})
	if len(continueResponse.BatchItems) != 3 || continueResponse.BatchItems[2].Err() != nil {
		t.Fatalf("Continue batch = %+v | Continue 批处理 = %+v", continueResponse.BatchItems, continueResponse.BatchItems)
	}
	if records, _ := server2.store.List(context.Background()); len(records) != 2 {
		t.Fatalf("Continue created %d records | Continue 创建了 %d 条记录", len(records), len(records))
	}

	server3 := newTestServer(t)
	undoResponse := server3.handleMessage(nil, RequestMessage{
		Header:     RequestHeader{ProtocolVersion: DefaultProtocolVersion, BatchErrorContinuationOption: BatchUndo},
		BatchItems: []RequestBatchItem{createRequest, failingRequest},
	})
	if len(undoResponse.BatchItems) != 2 || undoResponse.BatchItems[0].ResultStatus != ResultStatusOperationUndone ||
		undoResponse.BatchItems[0].Payload.Type != 0 {
		t.Fatalf("Undo batch = %+v | Undo 批处理 = %+v", undoResponse.BatchItems, undoResponse.BatchItems)
	}
	if records, _ := server3.store.List(context.Background()); len(records) != 0 {
		t.Fatalf("Undo left %d records | Undo 留下 %d 条记录", len(records), len(records))
	}

	failing := &failingListStore{Store: NewMemoryStore(), failAfter: 2}
	server4, err := NewServer(ServerConfig{AllowPlaintext: true, Store: failing})
	if err != nil {
		t.Fatalf("NewServer failing store: %v", err)
	}
	t.Cleanup(func() { _ = server4.Close() })
	undoFailure := server4.handleMessage(nil, RequestMessage{
		Header:     RequestHeader{ProtocolVersion: DefaultProtocolVersion, BatchErrorContinuationOption: BatchUndo},
		BatchItems: []RequestBatchItem{createRequest, failingRequest},
	})
	if len(undoFailure.BatchItems) != 2 || undoFailure.BatchItems[0].ResultStatus != ResultStatusOperationFailed ||
		undoFailure.BatchItems[0].ResultReason != ResultReasonGeneralFailure {
		t.Fatalf("Undo failure batch = %+v | Undo 失败批处理 = %+v", undoFailure.BatchItems, undoFailure.BatchItems)
	}

	unsupported := server.handleMessage(nil, RequestMessage{
		Header:     RequestHeader{ProtocolVersion: ProtocolVersion{Major: 3, Minor: 0}, BatchErrorContinuationOption: BatchContinue},
		BatchItems: []RequestBatchItem{createRequest, createRequest},
	})
	if len(unsupported.BatchItems) != 2 || unsupported.BatchItems[0].Err() == nil || unsupported.BatchItems[1].Err() == nil {
		t.Fatalf("unsupported version batch = %+v | 不支持版本批处理 = %+v", unsupported.BatchItems, unsupported.BatchItems)
	}
	if records, _ := server.store.List(context.Background()); len(records) != 1 {
		t.Fatalf("unsupported version created records | 不支持版本创建了记录")
	}
	empty := server.handleMessage(nil, RequestMessage{Header: testHeader()})
	if empty.Header.BatchCount != 0 || len(empty.BatchItems) != 0 {
		t.Fatalf("empty batch = %+v | 空批处理 = %+v", empty, empty)
	}
	if _, err := server.dispatch(RequestBatchItem{Operation: Operation(0x7F), Payload: mustItem(t, QueryRequest{QueryFunctions: []QueryFunction{QueryFunctionOperations}})}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unsupported operation error = %v | 不支持操作错误 = %v", err, err)
	}
}

// TestServerRegisterRejectsKeyLengthMismatch covers metadata that contradicts the key material.
// | TestServerRegisterRejectsKeyLengthMismatch 覆盖与密钥材料矛盾的元数据。
func TestServerRegisterRejectsKeyLengthMismatch(t *testing.T) {
	server := newTestServer(t)
	keyBlock := rawKeyBlock(AlgorithmAES, testKeyMaterial())
	keyBlock.Length = 128
	object := NewSymmetricKeyObject(keyBlock)
	if _, err := server.handleRegister(RegisterRequest{ObjectType: ObjectTypeSymmetricKey, Object: object}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("mismatched key length err = %v, want ErrInvalidRequest", err)
	}
}
