package kmip

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth/token/jose"
)

// versionedPayload is a payload that selects its wire shape by protocol version. | versionedPayload 是按协议版本选择
// 线格式的负载。
type versionedPayload interface {
	ItemForVersion(ProtocolVersion) (Item, error)
}

// mustVersionedItem encodes a versioned payload or fails the test. | mustVersionedItem 编码版本化负载，失败时终止测试。
func mustVersionedItem(t *testing.T, version ProtocolVersion, payload versionedPayload) Item {
	t.Helper()
	item, err := payload.ItemForVersion(version)
	if err != nil {
		t.Fatalf("ItemForVersion: %v", err)
	}
	return item
}

// runVersionedOp encodes with version, executes one operation and returns its response item. |
// runVersionedOp 按 version 编码，执行单个操作并返回响应项。
func runVersionedOp(t *testing.T, server *Server, version ProtocolVersion, op Operation, payload versionedPayload) ResponseBatchItem {
	t.Helper()
	response := roundTrip(t, server, RequestMessage{
		Header:     RequestHeader{ProtocolVersion: version},
		BatchItems: []RequestBatchItem{{Operation: op, Payload: mustVersionedItem(t, version, payload)}},
	})
	if len(response.BatchItems) != 1 {
		t.Fatalf("%s returned %d items | %s 返回 %d 个项", op, len(response.BatchItems), op, len(response.BatchItems))
	}
	return response.BatchItems[0]
}

// runPlainOpVersion executes an operation whose payload shape is identical in 1.4 and 2.0. |
// runPlainOpVersion 执行负载形状在 1.4 与 2.0 中相同的操作。
func runPlainOpVersion(t *testing.T, server *Server, version ProtocolVersion, op Operation, encoder payloadEncoder) ResponseBatchItem {
	t.Helper()
	response := roundTrip(t, server, RequestMessage{
		Header:     RequestHeader{ProtocolVersion: version},
		BatchItems: []RequestBatchItem{{Operation: op, Payload: mustItem(t, encoder)}},
	})
	if len(response.BatchItems) != 1 {
		t.Fatalf("%s returned %d items | %s 返回 %d 个项", op, len(response.BatchItems), op, len(response.BatchItems))
	}
	return response.BatchItems[0]
}

// runPlainOpVersionOK executes a same-shape operation and fails on an error result. |
// runPlainOpVersionOK 执行同形状操作并在错误结果时终止测试。
func runPlainOpVersionOK(t *testing.T, server *Server, version ProtocolVersion, op Operation, encoder payloadEncoder) Item {
	t.Helper()
	item := runPlainOpVersion(t, server, version, op, encoder)
	if err := item.Err(); err != nil {
		t.Fatalf("%s failed: %v | %s 失败：%v", op, err, op, err)
	}
	return item.Payload
}

// simpleTemplate20 returns a small AES-128 template. | simpleTemplate20 返回一个小的 AES-128 模板。
func simpleTemplate20() TemplateAttribute {
	return TemplateAttribute{
		Names: []Name{NewName("kmip20-key")},
		Attributes: AttributeList{
			NewEnumerationAttribute(AttributeCryptographicAlgorithm, uint32(AlgorithmAES)),
			NewIntegerAttribute(AttributeCryptographicLength, 128),
		},
	}
}

// TestPayloadKMIP20RoundTrip covers encode/decode of every versioned KMIP 2.0 operation payload. |
// TestPayloadKMIP20RoundTrip 覆盖每个版本化 KMIP 2.0 操作负载的编码/解码。
func TestPayloadKMIP20RoundTrip(t *testing.T) {
	v := ProtocolVersion20
	template := simpleTemplate20()
	rawObject := NewSymmetricKeyObject(rawKeyBlock(AlgorithmAES, []byte("0123456789abcdef")))

	createItem := mustVersionedItem(t, v, CreateRequest{ObjectType: ObjectTypeSymmetricKey, TemplateAttribute: template})
	if _, ok := createItem.Child(TagAttributes); !ok {
		t.Fatal("2.0 Create has no Attributes | 2.0 Create 没有 Attributes")
	}
	if _, ok := createItem.Child(TagTemplateAttribute); ok {
		t.Fatal("2.0 Create still carries Template-Attribute | 2.0 Create 仍携带 Template-Attribute")
	}
	createRequest, err := DecodeCreateRequestForVersion(createItem, v)
	if err != nil {
		t.Fatalf("DecodeCreateRequestForVersion: %v", err)
	}
	if createRequest.ObjectType != ObjectTypeSymmetricKey || len(createRequest.TemplateAttribute.Attributes) != 3 {
		t.Fatalf("Create request = %+v | Create 请求 = %+v", createRequest, createRequest)
	}
	createResponseItem := mustVersionedItem(t, v, CreateResponse{ObjectType: ObjectTypeSymmetricKey, UniqueIdentifier: "uid-create"})
	if _, ok := createResponseItem.Child(TagTemplateAttribute); ok {
		t.Fatal("2.0 Create response has Template-Attribute | 2.0 Create 响应带有 Template-Attribute")
	}
	if response, err := DecodeCreateResponseForVersion(createResponseItem, v); err != nil || response.UniqueIdentifier != "uid-create" {
		t.Fatalf("Create response = %+v, %v | Create 响应 = %+v，%v", response, err, response, err)
	}

	pairItem := mustVersionedItem(t, v, CreateKeyPairRequest{
		CommonTemplateAttribute:     &template,
		PrivateKeyTemplateAttribute: &template,
		PublicKeyTemplateAttribute:  &template,
	})
	if _, ok := pairItem.Child(TagCommonAttributes); !ok {
		t.Fatal("2.0 Create Key Pair has no Common Attributes | 2.0 Create Key Pair 没有 Common Attributes")
	}
	pairRequest, err := DecodeCreateKeyPairRequestForVersion(pairItem, v)
	if err != nil || pairRequest.CommonTemplateAttribute == nil || pairRequest.PrivateKeyTemplateAttribute == nil {
		t.Fatalf("Create Key Pair request = %+v, %v | Create Key Pair 请求 = %+v，%v", pairRequest, err, pairRequest, err)
	}
	pairResponseItem := mustVersionedItem(t, v, CreateKeyPairResponse{PrivateKeyUniqueIdentifier: "priv", PublicKeyUniqueIdentifier: "pub"})
	if response, err := DecodeCreateKeyPairResponseForVersion(pairResponseItem, v); err != nil ||
		response.PrivateKeyUniqueIdentifier != "priv" || response.PublicKeyUniqueIdentifier != "pub" {
		t.Fatalf("Create Key Pair response = %+v, %v | Create Key Pair 响应 = %+v，%v", response, err, response, err)
	}

	registerItem := mustVersionedItem(t, v, RegisterRequest{ObjectType: ObjectTypeSymmetricKey, TemplateAttribute: template, Object: rawObject})
	registerRequest, err := DecodeRegisterRequestForVersion(registerItem, v)
	if err != nil {
		t.Fatalf("DecodeRegisterRequestForVersion: %v", err)
	}
	if registerRequest.Object.Type != ObjectTypeSymmetricKey || len(registerRequest.TemplateAttribute.Attributes) != 3 {
		t.Fatalf("Register request = %+v | Register 请求 = %+v", registerRequest, registerRequest)
	}
	registerResponseItem := mustVersionedItem(t, v, RegisterResponse{UniqueIdentifier: "uid-register"})
	if response, err := DecodeRegisterResponseForVersion(registerResponseItem, v); err != nil || response.UniqueIdentifier != "uid-register" {
		t.Fatalf("Register response = %+v, %v | Register 响应 = %+v，%v", response, err, response, err)
	}

	getItem := mustVersionedItem(t, v, GetRequest{UniqueIdentifier: "uid-get", KeyFormatType: KeyFormatRaw, KeyWrappingSpecification: ptrWrappingSpec(testWrappingSpec())})
	if _, ok := getItem.Child(TagAttributeName); ok {
		t.Fatal("2.0 Get carries Attribute Name | 2.0 Get 携带 Attribute Name")
	}
	getRequest, err := DecodeGetRequestForVersion(getItem, v)
	if err != nil || getRequest.UniqueIdentifier != "uid-get" || getRequest.KeyFormatType != KeyFormatRaw || getRequest.KeyWrappingSpecification == nil {
		t.Fatalf("Get request = %+v, %v | Get 请求 = %+v，%v", getRequest, err, getRequest, err)
	}
	getResponseItem := mustVersionedItem(t, v, GetResponse{ObjectType: ObjectTypeSymmetricKey, UniqueIdentifier: "uid-get", Object: rawObject})
	getResponse, err := DecodeGetResponseForVersion(getResponseItem, v)
	if err != nil {
		t.Fatalf("Get response = %+v, %v | Get 响应 = %+v，%v", getResponse, err, getResponse, err)
	}
	if kb, err := getResponse.Object.KeyBlock(); err != nil || kb.Format != KeyFormatRaw {
		t.Fatalf("Get response key block = %+v, %v | Get 响应密钥块 = %+v，%v", kb, err, kb, err)
	}

	getAttrsItem := mustVersionedItem(t, v, GetAttributesRequest{UniqueIdentifier: "uid-attrs", AttributeNames: []string{AttributeState, AttributeCryptographicAlgorithm}})
	if refs := countTag(getAttrsItem, TagAttributeReference); refs != 2 {
		t.Fatalf("Attribute References = %d, want 2 | Attribute Reference 数 = %d，期望 2", refs, refs)
	}
	getAttrsRequest, err := DecodeGetAttributesRequestForVersion(getAttrsItem, v)
	if err != nil || len(getAttrsRequest.AttributeNames) != 2 {
		t.Fatalf("Get Attributes request = %+v, %v | Get Attributes 请求 = %+v，%v", getAttrsRequest, err, getAttrsRequest, err)
	}
	getAttrsResponseItem := mustVersionedItem(t, v, GetAttributesResponse{UniqueIdentifier: "uid-attrs", AttributeList: AttributeList{
		NewEnumerationAttribute(AttributeState, uint32(StateActive)),
		NewTextAttribute(AttributeCryptographicAlgorithm, "AES"),
	}})
	if response, err := DecodeGetAttributesResponseForVersion(getAttrsResponseItem, v); err != nil || len(response.AttributeList) != 2 {
		t.Fatalf("Get Attributes response = %+v, %v | Get Attributes 响应 = %+v，%v", response, err, response, err)
	}
	listResponseItem := mustVersionedItem(t, v, GetAttributeListResponse{UniqueIdentifier: "uid-list", AttributeNames: []string{AttributeState}})
	if response, err := DecodeGetAttributeListResponseForVersion(listResponseItem, v); err != nil || len(response.AttributeNames) != 1 {
		t.Fatalf("Get Attribute List response = %+v, %v | Get Attribute List 响应 = %+v，%v", response, err, response, err)
	}

	locateItem := mustVersionedItem(t, v, LocateRequest{MaximumItems: 5, OffsetItems: 1, StorageStatusMask: 1, ObjectGroupMember: 1, Attributes: AttributeList{
		NewEnumerationAttribute(AttributeCryptographicAlgorithm, uint32(AlgorithmAES)),
	}})
	locateRequest, err := DecodeLocateRequestForVersion(locateItem, v)
	if err != nil || locateRequest.MaximumItems != 5 || len(locateRequest.Attributes) != 1 {
		t.Fatalf("Locate request = %+v, %v | Locate 请求 = %+v，%v", locateRequest, err, locateRequest, err)
	}

	deriveItem := mustVersionedItem(t, v, DeriveKeyRequest{
		ObjectType:           ObjectTypeSymmetricKey,
		UniqueIdentifiers:    []string{"base"},
		DerivationMethod:     DerivationMethodHKDF,
		DerivationParameters: DerivationParameters{DerivationData: []byte("context"), Salt: []byte("salt")},
		TemplateAttribute:    template,
	})
	deriveRequest, err := DecodeDeriveKeyRequestForVersion(deriveItem, v)
	if err != nil || len(deriveRequest.UniqueIdentifiers) != 1 || len(deriveRequest.TemplateAttribute.Attributes) != 3 {
		t.Fatalf("Derive Key request = %+v, %v | Derive Key 请求 = %+v，%v", deriveRequest, err, deriveRequest, err)
	}
	deriveResponseItem := mustVersionedItem(t, v, DeriveKeyResponse{UniqueIdentifier: "uid-derived"})
	if response, err := DecodeDeriveKeyResponseForVersion(deriveResponseItem, v); err != nil || response.UniqueIdentifier != "uid-derived" {
		t.Fatalf("Derive Key response = %+v, %v | Derive Key 响应 = %+v，%v", response, err, response, err)
	}

	unwrapItem := mustVersionedItem(t, v, UnwrapKeyRequest{Object: rawObject, TemplateAttribute: template})
	if _, err := DecodeUnwrapKeyRequestForVersion(unwrapItem, v); err != nil {
		t.Fatalf("DecodeUnwrapKeyRequestForVersion: %v", err)
	}
	wrapResponseItem := mustVersionedItem(t, v, WrapKeyResponse{UniqueIdentifier: "uid-wrap", Object: rawObject})
	if response, err := DecodeWrapKeyResponseForVersion(wrapResponseItem, v); err != nil || response.Object.Type != ObjectTypeSymmetricKey {
		t.Fatalf("Wrap Key response = %+v, %v | Wrap Key 响应 = %+v，%v", response, err, response, err)
	}

	if _, err := DecodeCreateRequestForVersion(mustItem(t, CreateRequest{ObjectType: ObjectTypeSymmetricKey, TemplateAttribute: template}), v); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("1.4 Template-Attribute in 2.0 Create error = %v | 2.0 Create 中 1.4 Template-Attribute 错误 = %v", err, err)
	}
}

// countTag counts direct children with tag. | countTag 统计具有指定标签的直接子项。
func countTag(item Item, tag Tag) int {
	count := 0
	for _, child := range item.Children {
		if child.Tag == tag {
			count++
		}
	}
	return count
}

// TestPayloadKMIP20AttributesAndErrors covers 2.0 attribute encoding, attribute references and malformed payloads.
// | TestPayloadKMIP20AttributesAndErrors 覆盖 2.0 属性编码、属性引用与非法负载。
func TestPayloadKMIP20AttributesAndErrors(t *testing.T) {
	v := ProtocolVersion20
	vendor := NewVendorAttribute("acme", "license", NewTextString(TagAttributeValue, "gold"))
	encodedVendor, err := attributeItem20(vendor)
	if err != nil {
		t.Fatalf("attributeItem20: %v", err)
	}
	decodedVendor, err := decodeAttribute20(encodedVendor)
	if err != nil || decodedVendor.Name != "license" || decodedVendor.VendorIdentification != "acme" {
		t.Fatalf("vendor attribute = %+v, %v | 厂商属性 = %+v，%v", decodedVendor, err, decodedVendor, err)
	}
	vendorRefItem, err := AttributeReference{Name: "license", VendorIdentification: "acme"}.Item()
	if err != nil {
		t.Fatalf("vendor AttributeReference: %v", err)
	}
	vendorRef, err := DecodeAttributeReference(vendorRefItem)
	if err != nil || vendorRef.VendorIdentification != "acme" || vendorRef.Name != "license" {
		t.Fatalf("vendor reference = %+v, %v | 厂商引用 = %+v，%v", vendorRef, err, vendorRef, err)
	}
	if _, err := (AttributeReference{Name: "not-registered"}).Item(); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unknown attribute reference error = %v | 未知属性引用错误 = %v", err, err)
	}
	if _, err := DecodeAttributeReference(NewEnumeration(TagAttributeReference, 0x7FFFFF)); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unknown reference tag error = %v | 未知引用标签错误 = %v", err, err)
	}

	keyValue := KeyValue{Material: NewByteString(TagKeyMaterial, []byte{1, 2, 3}), Attributes: AttributeList{
		NewEnumerationAttribute(AttributeCryptographicAlgorithm, uint32(AlgorithmAES)),
	}}
	kvItem, err := keyValue.ItemForVersion(v)
	if err != nil {
		t.Fatalf("KeyValue.ItemForVersion: %v", err)
	}
	decodedKV, err := DecodeKeyValueForVersion(kvItem, v)
	if err != nil || len(decodedKV.Attributes) != 1 {
		t.Fatalf("Key Value = %+v, %v | Key Value = %+v，%v", decodedKV, err, decodedKV, err)
	}
	kb := KeyBlock{Format: KeyFormatRaw, Algorithm: AlgorithmAES, Length: 24, Value: keyValue}
	kbItem, err := kb.ItemForVersion(v)
	if err != nil {
		t.Fatalf("KeyBlock.ItemForVersion: %v", err)
	}
	decodedKB, err := DecodeKeyBlockForVersion(kbItem, v)
	if err != nil || decodedKB.Length != 24 || decodedKB.Algorithm != AlgorithmAES {
		t.Fatalf("Key Block = %+v, %v | Key Block = %+v，%v", decodedKB, err, decodedKB, err)
	}

	duplicate := NewStructure(TagKeyValue, NewByteString(TagKeyMaterial, []byte{1}), NewStructure(TagAttributes), NewStructure(TagAttributes))
	if _, err := DecodeKeyValueForVersion(duplicate, v); !errors.Is(err, ErrMalformed) {
		t.Fatalf("duplicate Attributes error = %v | 重复 Attributes 错误 = %v", err, err)
	}
	if _, err := DecodeKeyValueForVersion(NewStructure(TagKeyValue, NewStructure(TagAttributes)), v); !errors.Is(err, ErrMalformed) {
		t.Fatalf("Key Value without material error = %v | 无材料的 Key Value 错误 = %v", err, err)
	}
	if _, err := (KeyValue{}).ItemForVersion(v); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("empty Key Value error = %v | 空 Key Value 错误 = %v", err, err)
	}
	if _, err := (KeyBlock{}).ItemForVersion(v); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Key Block without format error = %v | 无格式 Key Block 错误 = %v", err, err)
	}
	if _, err := (Object{Type: ObjectTypeTemplate}).ItemForVersion(v); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Template object error = %v | Template 对象错误 = %v", err, err)
	}
	if _, err := DecodeObjectForVersion(NewStructure(TagTemplate), v); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("decoded Template object error = %v | 解码 Template 对象错误 = %v", err, err)
	}
	if _, err := (GetRequest{UniqueIdentifier: "uid", AttributeNames: []string{AttributeState}}).ItemForVersion(v); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Get attribute selection error = %v | Get 属性选择错误 = %v", err, err)
	}
	if _, err := (GetAttributesRequest{UniqueIdentifier: "uid"}).ItemForVersion(v); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Get Attributes without references error = %v | 无引用 Get Attributes 错误 = %v", err, err)
	}
	if _, err := (CreateRequest{TemplateAttribute: simpleTemplate20()}).ItemForVersion(v); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Create without object type error = %v | 无对象类型 Create 错误 = %v", err, err)
	}
	if _, err := (CreateResponse{UniqueIdentifier: "uid", TemplateAttribute: ptrTemplate(simpleTemplate20())}).ItemForVersion(v); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Create response with template error = %v | 带模板 Create 响应错误 = %v", err, err)
	}
	if _, err := DecodeCreateRequestForVersion(NewStructure(TagRequestPayload, NewEnumeration(TagObjectType, uint32(ObjectTypeSymmetricKey))), v); !errors.Is(err, ErrMalformed) {
		t.Fatalf("Create without Attributes error = %v | 无 Attributes Create 错误 = %v", err, err)
	}
	if _, err := DecodeCreateResponseForVersion(NewStructure(TagResponsePayload, NewEnumeration(TagObjectType, uint32(ObjectTypeSymmetricKey))), v); !errors.Is(err, ErrMalformed) {
		t.Fatalf("Create response without identifier error = %v | 无标识符 Create 响应错误 = %v", err, err)
	}
	if _, err := DecodeGetRequestForVersion(NewStructure(TagRequestPayload, NewTextString(TagUniqueIdentifier, "uid"), NewTextString(TagAttributeName, AttributeState)), v); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Get Attribute Name in 2.0 error = %v | 2.0 Get 中 Attribute Name 错误 = %v", err, err)
	}
	if _, err := DecodeGetAttributesResponseForVersion(NewStructure(TagResponsePayload, NewTextString(TagUniqueIdentifier, "uid")), v); !errors.Is(err, ErrMalformed) {
		t.Fatalf("Get Attributes response without Attributes error = %v | 无 Attributes Get Attributes 响应错误 = %v", err, err)
	}
	if _, err := DecodeGetAttributeListResponseForVersion(NewStructure(TagResponsePayload, NewTextString(TagUniqueIdentifier, "uid"), vendorRefItem), v); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("vendor reference in Get Attribute List error = %v | Get Attribute List 中厂商引用错误 = %v", err, err)
	}
	if _, err := DecodeAttributeReference(NewTextString(TagAttributeReference, "x")); !errors.Is(err, ErrMalformed) {
		t.Fatalf("malformed Attribute Reference error = %v | 非法 Attribute Reference 错误 = %v", err, err)
	}
	if _, err := decodeAttribute20(NewEnumeration(TagCustomAttribute, 1)); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("custom attribute error = %v | 自定义属性错误 = %v", err, err)
	}
	if _, err := decodeAttribute20(NewEnumeration(Tag(0x7FFFFF), 1)); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unknown attribute tag error = %v | 未知属性标签错误 = %v", err, err)
	}
	if _, err := attributesItem(TagAttributes, AttributeList{{Name: "x"}}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("attribute without value error = %v | 无值属性错误 = %v", err, err)
	}
}

// TestServerKMIP20Lifecycle covers the full lifecycle and cryptographic operations over 2.0 payloads. |
// TestServerKMIP20Lifecycle 覆盖 2.0 负载上的完整生命周期与密码学操作。
func TestServerKMIP20Lifecycle(t *testing.T) {
	server := newTestServer(t)
	v := ProtocolVersion20

	createdItem := runVersionedOp(t, server, v, OpCreate, CreateRequest{ObjectType: ObjectTypeSymmetricKey, TemplateAttribute: simpleTemplate20()})
	created, err := DecodeCreateResponseForVersion(createdItem.Payload, v)
	if err != nil || created.UniqueIdentifier == "" {
		t.Fatalf("Create = %+v, %v | Create = %+v，%v", created, err, created, err)
	}
	uid := created.UniqueIdentifier

	gotItem := runVersionedOp(t, server, v, OpGet, GetRequest{UniqueIdentifier: uid})
	got, err := DecodeGetResponseForVersion(gotItem.Payload, v)
	if err != nil || got.ObjectType != ObjectTypeSymmetricKey || got.UniqueIdentifier != uid {
		t.Fatalf("Get = %+v, %v | Get = %+v，%v", got, err, got, err)
	}
	got.Object.Zeroize()

	attrsItem := runVersionedOp(t, server, v, OpGetAttributes, GetAttributesRequest{UniqueIdentifier: uid, AttributeNames: []string{AttributeCryptographicAlgorithm, AttributeState}})
	attrs, err := DecodeGetAttributesResponseForVersion(attrsItem.Payload, v)
	if err != nil || len(attrs.AttributeList) != 2 {
		t.Fatalf("Get Attributes = %+v, %v | Get Attributes = %+v，%v", attrs, err, attrs, err)
	}
	listPayload := runPlainOpVersionOK(t, server, v, OpGetAttributeList, GetAttributeListRequest{UniqueIdentifier: uid})
	names, err := DecodeGetAttributeListResponseForVersion(listPayload, v)
	if err != nil || len(names.AttributeNames) == 0 {
		t.Fatalf("Get Attribute List = %+v, %v | Get Attribute List = %+v，%v", names, err, names, err)
	}

	runPlainOpVersionOK(t, server, v, OpActivate, ActivateRequest{UniqueIdentifier: uid})
	locatePayload := runVersionedOp(t, server, v, OpLocate, LocateRequest{Attributes: AttributeList{
		NewEnumerationAttribute(AttributeCryptographicAlgorithm, uint32(AlgorithmAES)),
	}})
	located, err := DecodeLocateResponse(locatePayload.Payload)
	if err != nil || !containsString(located.UniqueIdentifiers, uid) {
		t.Fatalf("Locate = %+v, %v | Locate = %+v，%v", located, err, located, err)
	}

	gcm := CryptographicParameters{BlockCipherMode: BlockCipherModeGCM, RandomIV: true}
	plaintext := []byte("kmip 2.0 payload")
	encryptedPayload := runPlainOpVersionOK(t, server, v, OpEncrypt, EncryptRequest{
		UniqueIdentifier: uid, CryptographicParameters: &gcm, Data: plaintext,
	})
	encrypted, err := DecodeEncryptResponse(encryptedPayload)
	if err != nil || len(encrypted.Data) == 0 {
		t.Fatalf("Encrypt = %+v, %v | Encrypt = %+v，%v", encrypted, err, encrypted, err)
	}
	decryptedPayload := runPlainOpVersionOK(t, server, v, OpDecrypt, DecryptRequest{
		UniqueIdentifier:           uid,
		CryptographicParameters:    &gcm,
		Data:                       encrypted.Data,
		IVCounterNonce:             encrypted.IVCounterNonce,
		AuthenticatedEncryptionTag: encrypted.AuthenticatedEncryptionTag,
	})
	decrypted, err := DecodeDecryptResponse(decryptedPayload)
	if err != nil || !bytes.Equal(decrypted.Data, plaintext) {
		t.Fatalf("Decrypt = %q, %v | Decrypt = %q，%v", decrypted.Data, err, decrypted.Data, err)
	}

	derivedItem := runVersionedOp(t, server, v, OpDeriveKey, DeriveKeyRequest{
		ObjectType:           ObjectTypeSymmetricKey,
		UniqueIdentifiers:    []string{uid},
		DerivationMethod:     DerivationMethodHKDF,
		DerivationParameters: DerivationParameters{DerivationData: []byte("context"), Salt: []byte("salt")},
		TemplateAttribute: TemplateAttribute{Attributes: AttributeList{
			NewEnumerationAttribute(AttributeCryptographicAlgorithm, uint32(AlgorithmAES)),
			NewIntegerAttribute(AttributeCryptographicLength, 128),
		}},
	})
	derived, err := DecodeDeriveKeyResponseForVersion(derivedItem.Payload, v)
	if err != nil || derived.UniqueIdentifier == "" {
		t.Fatalf("Derive Key = %+v, %v | Derive Key = %+v，%v", derived, err, derived, err)
	}

	pairItem := runVersionedOp(t, server, v, OpCreateKeyPair, CreateKeyPairRequest{CommonTemplateAttribute: &TemplateAttribute{Attributes: AttributeList{
		NewEnumerationAttribute(AttributeCryptographicAlgorithm, uint32(AlgorithmRSA)),
		NewIntegerAttribute(AttributeCryptographicLength, 2048),
	}}})
	pair, err := DecodeCreateKeyPairResponseForVersion(pairItem.Payload, v)
	if err != nil || pair.PrivateKeyUniqueIdentifier == "" {
		t.Fatalf("Create Key Pair = %+v, %v | Create Key Pair = %+v，%v", pair, err, pair, err)
	}
	for _, member := range []string{pair.PrivateKeyUniqueIdentifier, pair.PublicKeyUniqueIdentifier} {
		runPlainOpVersionOK(t, server, v, OpActivate, ActivateRequest{UniqueIdentifier: member})
	}
	rsaParams := CryptographicParameters{DigitalSignatureAlgorithm: DigitalSignatureRSAPKCS1SHA256}
	signPayload := runPlainOpVersionOK(t, server, v, OpSign, SignRequest{
		UniqueIdentifier: pair.PrivateKeyUniqueIdentifier, CryptographicParameters: &rsaParams, Data: plaintext,
	})
	signed, err := DecodeSignResponse(signPayload)
	if err != nil || len(signed.SignatureData) == 0 {
		t.Fatalf("Sign = %+v, %v | Sign = %+v，%v", signed, err, signed, err)
	}
	verifyPayload := runPlainOpVersionOK(t, server, v, OpSignatureVerify, VerifyRequest{
		UniqueIdentifier: pair.PublicKeyUniqueIdentifier, CryptographicParameters: &rsaParams,
		Data: plaintext, SignatureData: signed.SignatureData,
	})
	verified, err := DecodeVerifyResponse(verifyPayload)
	if err != nil || verified.ValidityIndicator != ValidityIndicatorValid {
		t.Fatalf("Verify = %+v, %v | Verify = %+v，%v", verified, err, verified, err)
	}

	registeredItem := runVersionedOp(t, server, v, OpRegister, RegisterRequest{
		ObjectType: ObjectTypeSymmetricKey,
		Object:     NewSymmetricKeyObject(rawKeyBlock(AlgorithmHMACSHA256, bytes.Repeat([]byte{0x11}, 32))),
	})
	registered, err := DecodeRegisterResponseForVersion(registeredItem.Payload, v)
	if err != nil || registered.UniqueIdentifier == "" {
		t.Fatalf("Register = %+v, %v | Register = %+v，%v", registered, err, registered, err)
	}
	runPlainOpVersionOK(t, server, v, OpActivate, ActivateRequest{UniqueIdentifier: registered.UniqueIdentifier})
	macPayload := runPlainOpVersionOK(t, server, v, OpMAC, MACRequest{UniqueIdentifier: registered.UniqueIdentifier, Data: plaintext})
	mac, err := DecodeMACResponse(macPayload)
	if err != nil || len(mac.MACData) == 0 {
		t.Fatalf("MAC = %+v, %v | MAC = %+v，%v", mac, err, mac, err)
	}
	macVerifyPayload := runPlainOpVersionOK(t, server, v, OpMACVerify, MACVerifyRequest{
		UniqueIdentifier: registered.UniqueIdentifier, Data: plaintext, MACData: mac.MACData,
	})
	macValid, err := DecodeMACVerifyResponse(macVerifyPayload)
	if err != nil || macValid.ValidityIndicator != ValidityIndicatorValid {
		t.Fatalf("MACVerify = %+v, %v | MACVerify = %+v，%v", macValid, err, macValid, err)
	}

	wrapTargetItem := runVersionedOp(t, server, v, OpCreate, CreateRequest{ObjectType: ObjectTypeSymmetricKey, TemplateAttribute: simpleTemplate20()})
	wrapTarget, err := DecodeCreateResponseForVersion(wrapTargetItem.Payload, v)
	if err != nil {
		t.Fatalf("Create wrap target: %v", err)
	}
	runPlainOpVersionOK(t, server, v, OpActivate, ActivateRequest{UniqueIdentifier: wrapTarget.UniqueIdentifier})
	wrapPayload := runPlainOpVersionOK(t, server, v, OpWrapKey, WrapKeyRequest{
		UniqueIdentifier: wrapTarget.UniqueIdentifier,
		KeyWrappingSpecification: KeyWrappingSpecification{
			WrappingMethod:           WrappingMethodEncrypt,
			EncryptionKeyInformation: &EncryptionKeyInformation{UniqueIdentifier: uid},
		},
	})
	wrapped, err := DecodeWrapKeyResponseForVersion(wrapPayload, v)
	if err != nil || wrapped.Object.Type != ObjectTypeSymmetricKey {
		t.Fatalf("Wrap Key = %+v, %v | Wrap Key = %+v，%v", wrapped, err, wrapped, err)
	}
	unwrappedItem := runVersionedOp(t, server, v, OpUnwrapKey, UnwrapKeyRequest{
		Object: wrapped.Object,
		TemplateAttribute: TemplateAttribute{Attributes: AttributeList{
			NewEnumerationAttribute(AttributeCryptographicAlgorithm, uint32(AlgorithmAES)),
			NewIntegerAttribute(AttributeCryptographicLength, 128),
		}},
	})
	unwrapped, err := DecodeUnwrapKeyResponse(unwrappedItem.Payload)
	if err != nil || unwrapped.UniqueIdentifier == "" {
		t.Fatalf("Unwrap Key = %+v, %v | Unwrap Key = %+v，%v", unwrapped, err, unwrapped, err)
	}

	queryPayload := runPlainOpVersionOK(t, server, v, OpQuery, QueryRequest{QueryFunctions: []QueryFunction{QueryFunctionOperations}})
	query, err := DecodeQueryResponse(queryPayload)
	if err != nil || len(query.Operations) == 0 {
		t.Fatalf("Query = %+v, %v | Query = %+v，%v", query, err, query, err)
	}
	discoverPayload := runPlainOpVersionOK(t, server, v, OpDiscoverVersions, DiscoverVersionsRequest{})
	discover, err := DecodeDiscoverVersionsResponse(discoverPayload)
	if err != nil || len(discover.ProtocolVersions) != 2 || discover.ProtocolVersions[0].Compare(ProtocolVersion20) != 0 {
		t.Fatalf("Discover Versions = %+v, %v | Discover Versions = %+v，%v", discover, err, discover, err)
	}

	unsupported := runPlainOpVersion(t, server, v, OpExport, GetRequest{UniqueIdentifier: uid})
	if !errors.Is(unsupported.Err(), ErrUnsupported) {
		t.Fatalf("2.0 unsupported operation error = %v | 2.0 不支持操作错误 = %v", unsupported.Err(), unsupported.Err())
	}

	runPlainOpVersionOK(t, server, v, OpRevoke, RevokeRequest{
		UniqueIdentifier: derived.UniqueIdentifier,
		Reason:           RevocationReason{Code: RevocationCessationOfOperation},
	})
	runPlainOpVersionOK(t, server, v, OpDestroy, DestroyRequest{UniqueIdentifier: derived.UniqueIdentifier})
}

// TestClientKMIP20Lifecycle covers version negotiation and the version-aware client codecs over TCP. |
// TestClientKMIP20Lifecycle 覆盖版本协商与 TCP 上版本感知的客户端编解码。
func TestClientKMIP20Lifecycle(t *testing.T) {
	_, address := startTestServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	client, err := DialContext(ctx, ClientConfig{Address: address, AllowPlaintext: true, ProtocolVersion: ProtocolVersion20})
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	created, err := client.Create(ctx, CreateRequest{ObjectType: ObjectTypeSymmetricKey, TemplateAttribute: simpleTemplate20()})
	if err != nil || created.UniqueIdentifier == "" {
		t.Fatalf("Create = %+v, %v | Create = %+v，%v", created, err, created, err)
	}
	got, err := client.Get(ctx, GetRequest{UniqueIdentifier: created.UniqueIdentifier})
	if err != nil || got.ObjectType != ObjectTypeSymmetricKey {
		t.Fatalf("Get = %+v, %v | Get = %+v，%v", got, err, got, err)
	}
	got.Object.Zeroize()
	if _, err := client.Get(ctx, GetRequest{UniqueIdentifier: created.UniqueIdentifier, AttributeNames: []string{AttributeState}}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("2.0 Get attribute selection error = %v | 2.0 Get 属性选择错误 = %v", err, err)
	}
	attrs, err := client.GetAttributes(ctx, GetAttributesRequest{UniqueIdentifier: created.UniqueIdentifier, AttributeNames: []string{AttributeCryptographicAlgorithm}})
	if err != nil || len(attrs.AttributeList) == 0 {
		t.Fatalf("Get Attributes = %+v, %v | Get Attributes = %+v，%v", attrs, err, attrs, err)
	}
	if _, err := client.GetAttributes(ctx, GetAttributesRequest{UniqueIdentifier: created.UniqueIdentifier}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("2.0 Get Attributes without references error = %v | 2.0 无引用 Get Attributes 错误 = %v", err, err)
	}
	names, err := client.GetAttributeList(ctx, GetAttributeListRequest{UniqueIdentifier: created.UniqueIdentifier})
	if err != nil || len(names.AttributeNames) == 0 {
		t.Fatalf("Get Attribute List = %+v, %v | Get Attribute List = %+v，%v", names, err, names, err)
	}
	if _, err := client.Activate(ctx, ActivateRequest{UniqueIdentifier: created.UniqueIdentifier}); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	located, err := client.Locate(ctx, LocateRequest{Attributes: AttributeList{
		NewEnumerationAttribute(AttributeCryptographicAlgorithm, uint32(AlgorithmAES)),
	}})
	if err != nil || !containsString(located.UniqueIdentifiers, created.UniqueIdentifier) {
		t.Fatalf("Locate = %+v, %v | Locate = %+v，%v", located, err, located, err)
	}
	derived, err := client.DeriveKey(ctx, DeriveKeyRequest{
		ObjectType:           ObjectTypeSymmetricKey,
		UniqueIdentifiers:    []string{created.UniqueIdentifier},
		DerivationMethod:     DerivationMethodHKDF,
		DerivationParameters: DerivationParameters{DerivationData: []byte("ctx"), Salt: []byte("salt")},
		TemplateAttribute: TemplateAttribute{Attributes: AttributeList{
			NewEnumerationAttribute(AttributeCryptographicAlgorithm, uint32(AlgorithmAES)),
			NewIntegerAttribute(AttributeCryptographicLength, 128),
		}},
	})
	if err != nil || derived.UniqueIdentifier == "" {
		t.Fatalf("Derive Key = %+v, %v | Derive Key = %+v，%v", derived, err, derived, err)
	}
	gcm := CryptographicParameters{BlockCipherMode: BlockCipherModeGCM, RandomIV: true}
	encrypted, err := client.Encrypt(ctx, EncryptRequest{UniqueIdentifier: created.UniqueIdentifier, CryptographicParameters: &gcm, Data: []byte("2.0 client")})
	if err != nil || len(encrypted.Data) == 0 {
		t.Fatalf("Encrypt = %+v, %v | Encrypt = %+v，%v", encrypted, err, encrypted, err)
	}
	decrypted, err := client.Decrypt(ctx, DecryptRequest{
		UniqueIdentifier: created.UniqueIdentifier, CryptographicParameters: &gcm,
		Data: encrypted.Data, IVCounterNonce: encrypted.IVCounterNonce, AuthenticatedEncryptionTag: encrypted.AuthenticatedEncryptionTag,
	})
	if err != nil || string(decrypted.Data) != "2.0 client" {
		t.Fatalf("Decrypt = %q, %v | Decrypt = %q，%v", decrypted.Data, err, decrypted.Data, err)
	}

	pair, err := client.CreateKeyPair(ctx, CreateKeyPairRequest{CommonTemplateAttribute: &TemplateAttribute{Attributes: AttributeList{
		NewEnumerationAttribute(AttributeCryptographicAlgorithm, uint32(AlgorithmRSA)),
		NewIntegerAttribute(AttributeCryptographicLength, 2048),
	}}})
	if err != nil || pair.PrivateKeyUniqueIdentifier == "" {
		t.Fatalf("Create Key Pair = %+v, %v | Create Key Pair = %+v，%v", pair, err, pair, err)
	}
	for _, member := range []string{pair.PrivateKeyUniqueIdentifier, pair.PublicKeyUniqueIdentifier} {
		if _, err := client.Activate(ctx, ActivateRequest{UniqueIdentifier: member}); err != nil {
			t.Fatalf("Activate key pair member: %v", err)
		}
	}
	rsaParams := CryptographicParameters{DigitalSignatureAlgorithm: DigitalSignatureRSAPKCS1SHA256}
	signed, err := client.Sign(ctx, SignRequest{UniqueIdentifier: pair.PrivateKeyUniqueIdentifier, CryptographicParameters: &rsaParams, Data: []byte("2.0 sign")})
	if err != nil || len(signed.SignatureData) == 0 {
		t.Fatalf("Sign = %+v, %v | Sign = %+v，%v", signed, err, signed, err)
	}
	verified, err := client.Verify(ctx, VerifyRequest{
		UniqueIdentifier: pair.PublicKeyUniqueIdentifier, CryptographicParameters: &rsaParams,
		Data: []byte("2.0 sign"), SignatureData: signed.SignatureData,
	})
	if err != nil || verified.ValidityIndicator != ValidityIndicatorValid {
		t.Fatalf("Verify = %+v, %v | Verify = %+v，%v", verified, err, verified, err)
	}

	secret := []byte("0123456789abcdef0123456789abcdef")
	hmacJWK, err := jose.FromHMAC("2.0-hmac", secret)
	if err != nil {
		t.Fatalf("FromHMAC: %v", err)
	}
	registered, err := client.Register(ctx, RegisterRequest{
		ObjectType: ObjectTypeSymmetricKey,
		Object: NewSymmetricKeyObject(KeyBlock{
			Format:    KeyFormatJWK,
			Algorithm: AlgorithmHMACSHA256,
			Value:     NewRawKeyValue(mustJWK(t, hmacJWK)),
		}),
	})
	if err != nil || registered.UniqueIdentifier == "" {
		t.Fatalf("Register JWK = %+v, %v | Register JWK = %+v，%v", registered, err, registered, err)
	}
	if _, err := client.Activate(ctx, ActivateRequest{UniqueIdentifier: registered.UniqueIdentifier}); err != nil {
		t.Fatalf("Activate JWK: %v", err)
	}
	mac, err := client.MAC(ctx, MACRequest{UniqueIdentifier: registered.UniqueIdentifier, Data: []byte("2.0 mac")})
	if err != nil || len(mac.MACData) == 0 {
		t.Fatalf("MAC = %+v, %v | MAC = %+v，%v", mac, err, mac, err)
	}
	macValid, err := client.MACVerify(ctx, MACVerifyRequest{UniqueIdentifier: registered.UniqueIdentifier, Data: []byte("2.0 mac"), MACData: mac.MACData})
	if err != nil || macValid.ValidityIndicator != ValidityIndicatorValid {
		t.Fatalf("MACVerify = %+v, %v | MACVerify = %+v，%v", macValid, err, macValid, err)
	}

	wrapTarget, err := client.Create(ctx, CreateRequest{ObjectType: ObjectTypeSymmetricKey, TemplateAttribute: simpleTemplate20()})
	if err != nil {
		t.Fatalf("Create wrap target: %v", err)
	}
	if _, err := client.Activate(ctx, ActivateRequest{UniqueIdentifier: wrapTarget.UniqueIdentifier}); err != nil {
		t.Fatalf("Activate wrap target: %v", err)
	}
	wrapped, err := client.WrapKey(ctx, WrapKeyRequest{
		UniqueIdentifier: wrapTarget.UniqueIdentifier,
		KeyWrappingSpecification: KeyWrappingSpecification{
			WrappingMethod:           WrappingMethodEncrypt,
			EncryptionKeyInformation: &EncryptionKeyInformation{UniqueIdentifier: created.UniqueIdentifier},
		},
	})
	if err != nil || wrapped.UniqueIdentifier == "" {
		t.Fatalf("Wrap Key = %+v, %v | Wrap Key = %+v，%v", wrapped, err, wrapped, err)
	}
	unwrapped, err := client.UnwrapKey(ctx, UnwrapKeyRequest{Object: wrapped.Object, TemplateAttribute: TemplateAttribute{Attributes: AttributeList{
		NewEnumerationAttribute(AttributeCryptographicAlgorithm, uint32(AlgorithmAES)),
		NewIntegerAttribute(AttributeCryptographicLength, 128),
	}}})
	if err != nil || unwrapped.UniqueIdentifier == "" {
		t.Fatalf("Unwrap Key = %+v, %v | Unwrap Key = %+v，%v", unwrapped, err, unwrapped, err)
	}
	if _, err := client.GetAttributeList(ctx, GetAttributeListRequest{UniqueIdentifier: unwrapped.UniqueIdentifier}); err != nil {
		t.Fatalf("Get Attribute List unwrapped: %v", err)
	}
	if _, err := client.Revoke(ctx, RevokeRequest{UniqueIdentifier: derived.UniqueIdentifier, Reason: RevocationReason{Code: RevocationCessationOfOperation}}); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := client.Destroy(ctx, DestroyRequest{UniqueIdentifier: derived.UniqueIdentifier}); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	versions, err := client.DiscoverVersions(ctx, DiscoverVersionsRequest{})
	if err != nil || len(versions.ProtocolVersions) != 2 {
		t.Fatalf("Discover Versions = %+v, %v | Discover Versions = %+v，%v", versions, err, versions, err)
	}
}

// TestPayloadKMIP20Objects covers every managed object kind and the remaining 2.0 key block fields. |
// TestPayloadKMIP20Objects 覆盖所有受管对象类型与其余 2.0 密钥块字段。
func TestPayloadKMIP20Objects(t *testing.T) {
	v := ProtocolVersion20
	objects := []Object{
		NewSymmetricKeyObject(rawKeyBlock(AlgorithmAES, []byte("0123456789abcdef"))),
		NewPublicKeyObject(rawKeyBlock(AlgorithmRSA, []byte("public-key-material"))),
		NewPrivateKeyObject(rawKeyBlock(AlgorithmRSA, []byte("private-key-material"))),
		NewSecretDataObject(SecretDataTypePassword, rawKeyBlock(AlgorithmAES, []byte("secret-data-value"))),
		NewCertificateObject(CertificateTypeX509, []byte{0x30, 0x01, 0x00}),
		NewOpaqueObject(7, []byte("opaque-value")),
	}
	for _, object := range objects {
		item, err := object.ItemForVersion(v)
		if err != nil {
			t.Fatalf("ItemForVersion(%s): %v | ItemForVersion(%s)：%v", object.Type, err, object.Type, err)
		}
		decoded, err := DecodeObjectForVersion(item, v)
		if err != nil {
			t.Fatalf("DecodeObjectForVersion(%s): %v | DecodeObjectForVersion(%s)：%v", object.Type, err, object.Type, err)
		}
		if decoded.Type != object.Type {
			t.Fatalf("object type = %s, want %s | 对象类型 = %s，期望 %s", decoded.Type, object.Type, decoded.Type, object.Type)
		}
		decoded.Zeroize()
	}
	secret := NewSecretDataObject(0, rawKeyBlock(AlgorithmAES, []byte("secret-data-value")))
	secretItem, err := secret.ItemForVersion(v)
	if err != nil {
		t.Fatalf("secret ItemForVersion: %v | 秘密数据 ItemForVersion：%v", err, err)
	}
	decodedSecret, err := DecodeObjectForVersion(secretItem, v)
	if err != nil || decodedSecret.SecretData == nil || decodedSecret.SecretData.SecretDataType != SecretDataTypePassword {
		t.Fatalf("default secret data type = %+v, %v | 默认秘密数据类型 = %+v，%v", decodedSecret, err, decodedSecret, err)
	}
	decodedSecret.Zeroize()

	compressed := KeyBlock{
		Format:      KeyFormatRaw,
		Compression: KeyCompressionECPublicKeyUncompressed,
		Value:       NewRawKeyValue([]byte("0123456789abcdef")),
	}
	compressedItem, err := compressed.ItemForVersion(v)
	if err != nil {
		t.Fatalf("compressed KeyBlock: %v | 压缩 KeyBlock：%v", err, err)
	}
	if kb, err := DecodeKeyBlockForVersion(compressedItem, v); err != nil || kb.Compression != KeyCompressionECPublicKeyUncompressed {
		t.Fatalf("compressed Key Block = %+v, %v | 压缩密钥块 = %+v，%v", kb, err, kb, err)
	}
	if _, err := DecodeKeyBlockForVersion(NewStructure(TagKeyBlock, NewStructure(TagKeyValue)), v); !errors.Is(err, ErrMalformed) {
		t.Fatalf("Key Block without format error = %v | 无格式 Key Block 错误 = %v", err, err)
	}
	if _, err := DecodeObjectForVersion(NewStructure(Tag(0x7FFFFF)), v); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unknown object tag error = %v | 未知对象标签错误 = %v", err, err)
	}
	if _, err := (Object{Type: ObjectTypePublicKey}).ItemForVersion(v); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil public object error = %v | 空公钥对象错误 = %v", err, err)
	}
}

// TestServerLegacyHandlerWrappers covers the 1.4 handler entry points retained for direct callers. |
// TestServerLegacyHandlerWrappers 覆盖为直接调用方保留的 1.4 处理器入口。
func TestServerLegacyHandlerWrappers(t *testing.T) {
	server := newTestServer(t)
	if _, err := server.handleCreate(CreateRequest{}); err == nil {
		t.Fatal("handleCreate accepted an empty request | handleCreate 接受了空请求")
	}
	if _, err := server.handleCreateKeyPair(CreateKeyPairRequest{}); err == nil {
		t.Fatal("handleCreateKeyPair accepted an empty request | handleCreateKeyPair 接受了空请求")
	}
	if _, err := server.handleRegister(RegisterRequest{}); err == nil {
		t.Fatal("handleRegister accepted an empty request | handleRegister 接受了空请求")
	}
	if _, err := server.handleGet(GetRequest{UniqueIdentifier: "missing"}); err == nil {
		t.Fatal("handleGet accepted a missing object | handleGet 接受了缺失对象")
	}
	if _, err := server.handleGetAttributes(GetAttributesRequest{UniqueIdentifier: "missing"}); err == nil {
		t.Fatal("handleGetAttributes accepted a missing object | handleGetAttributes 接受了缺失对象")
	}
	if _, err := server.handleGetAttributeList(GetAttributeListRequest{UniqueIdentifier: "missing"}); err == nil {
		t.Fatal("handleGetAttributeList accepted a missing object | handleGetAttributeList 接受了缺失对象")
	}
	if _, err := server.handleDeriveKey(DeriveKeyRequest{}); err == nil {
		t.Fatal("handleDeriveKey accepted an empty request | handleDeriveKey 接受了空请求")
	}
	if _, err := server.handleWrapKey(WrapKeyRequest{}); err == nil {
		t.Fatal("handleWrapKey accepted an empty request | handleWrapKey 接受了空请求")
	}
}
