package kmip

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
	"time"
)

// testKeyMaterial returns deterministic 32-byte symmetric key material. | testKeyMaterial 返回确定性的 32 字节对称密钥材料。
func testKeyMaterial() []byte {
	return bytes.Repeat([]byte{0x5A}, 32)
}

// testSymmetricRecord builds a symmetric-key record for store tests. | testSymmetricRecord 构造存储测试用的对称密钥记录。
func testSymmetricRecord(uid string, state State) ObjectRecord {
	object := NewSymmetricKeyObject(rawKeyBlock(AlgorithmAES, testKeyMaterial()))
	return ObjectRecord{
		UniqueIdentifier: uid,
		ObjectType:       ObjectTypeSymmetricKey,
		Object:           &object,
		State:            state,
		UsageMask:        UsageMaskEncrypt | UsageMaskDecrypt,
		Extractable:      true,
	}
}

// TestMemoryStoreLifecycle covers CRUD, ordering, cloning and context handling. |
// TestMemoryStoreLifecycle 覆盖增删改查、排序、克隆与上下文处理。
func TestMemoryStoreLifecycle(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	if err := store.Create(ctx, testSymmetricRecord("b", StatePreActive)); err != nil {
		t.Fatalf("Create b: %v | 创建 b 失败：%v", err, err)
	}
	if err := store.Create(ctx, testSymmetricRecord("a", StateActive)); err != nil {
		t.Fatalf("Create a: %v | 创建 a 失败：%v", err, err)
	}
	if err := store.Create(ctx, testSymmetricRecord("a", StateActive)); !errors.Is(err, ErrObjectExists) {
		t.Fatalf("duplicate Create error = %v | 重复创建错误 = %v", err, err)
	}
	if err := store.Create(ctx, ObjectRecord{}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("empty identifier error = %v | 空标识符错误 = %v", err, err)
	}

	records, err := store.List(ctx)
	if err != nil || len(records) != 2 || records[0].UniqueIdentifier != "a" || records[1].UniqueIdentifier != "b" {
		t.Fatalf("List = %+v, %v | List = %+v，%v", records, err, records, err)
	}

	record, err := store.Get(ctx, "a")
	if err != nil || record.State != StateActive {
		t.Fatalf("Get = %+v, %v | Get = %+v，%v", record, err, record, err)
	}
	record.State = StateDeactivated
	record.Names = append(record.Names, NewName("mutated"))
	record.Attributes = append(record.Attributes, NewTextAttribute(AttributeComment, "mutated"))
	record.Object.SymmetricKey.KeyBlock.Value.Material.Value[0] ^= 0xFF
	again, err := store.Get(ctx, "a")
	if err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if again.State != StateActive || len(again.Names) != 0 || len(again.Attributes) != 0 {
		t.Fatalf("store returned aliased metadata: %+v | 存储返回了共享元数据：%+v", again, again)
	}
	if again.Object.SymmetricKey.KeyBlock.Value.Material.Value[0] != 0x5A {
		t.Fatal("store returned aliased key material | 存储返回了共享密钥材料")
	}

	updated := testSymmetricRecord("a", StateDeactivated)
	updated.Names = []Name{NewName("updated")}
	if err := store.Update(ctx, updated); err != nil {
		t.Fatalf("Update: %v | 更新失败：%v", err, err)
	}
	record, err = store.Get(ctx, "a")
	if err != nil || record.State != StateDeactivated || len(record.Names) != 1 {
		t.Fatalf("updated record = %+v, %v | 更新记录 = %+v，%v", record, err, record, err)
	}
	if err := store.Update(ctx, testSymmetricRecord("missing", StateActive)); !errors.Is(err, ErrItemNotFound) {
		t.Fatalf("Update missing error = %v | 更新缺失对象错误 = %v", err, err)
	}
	if err := store.Delete(ctx, "a"); err != nil {
		t.Fatalf("Delete: %v | 删除失败：%v", err, err)
	}
	if _, err := store.Get(ctx, "a"); !errors.Is(err, ErrItemNotFound) {
		t.Fatalf("Get deleted error = %v | 获取已删除对象错误 = %v", err, err)
	}
	if err := store.Delete(ctx, "a"); !errors.Is(err, ErrItemNotFound) {
		t.Fatalf("Delete missing error = %v | 删除缺失对象错误 = %v", err, err)
	}
	if _, err := store.Get(ctx, "missing"); !errors.Is(err, ErrItemNotFound) {
		t.Fatalf("Get missing error = %v | 获取缺失对象错误 = %v", err, err)
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := store.Create(cancelled, testSymmetricRecord("c", StateActive)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Create error = %v | 取消的创建错误 = %v", err, err)
	}
	if _, err := store.Get(cancelled, "b"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Get error = %v | 取消的获取错误 = %v", err, err)
	}
	if err := store.Update(cancelled, testSymmetricRecord("b", StateActive)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Update error = %v | 取消的更新错误 = %v", err, err)
	}
	if err := store.Delete(cancelled, "b"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Delete error = %v | 取消的删除错误 = %v", err, err)
	}
	if _, err := store.List(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled List error = %v | 取消的列表错误 = %v", err, err)
	}
}

// TestMemoryStoreConcurrentUse exercises the store under -race. | TestMemoryStoreConcurrentUse 在 -race 下检验存储并发。
func TestMemoryStoreConcurrentUse(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	var wait sync.WaitGroup
	for index := 0; index < 16; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			uid := "uid-" + string(rune('a'+index))
			if err := store.Create(ctx, testSymmetricRecord(uid, StateActive)); err != nil {
				t.Errorf("Create %s: %v", uid, err)
			}
			if _, err := store.Get(ctx, uid); err != nil {
				t.Errorf("Get %s: %v", uid, err)
			}
			if records, err := store.List(ctx); err != nil || len(records) == 0 {
				t.Errorf("List = %d, %v", len(records), err)
			}
			if err := store.Delete(ctx, uid); err != nil {
				t.Errorf("Delete %s: %v", uid, err)
			}
		}(index)
	}
	wait.Wait()
	if records, err := store.List(ctx); err != nil || len(records) != 0 {
		t.Fatalf("final List = %d, %v | 最终列表 = %d，%v", len(records), err, len(records), err)
	}
}

// TestCloneHelpers covers deep copying of records, objects, key blocks and items. |
// TestCloneHelpers 覆盖记录、对象、密钥块与项的深拷贝。
func TestCloneHelpers(t *testing.T) {
	if cloneAttributeList(nil) != nil {
		t.Fatal("cloneAttributeList(nil) is not nil | cloneAttributeList(nil) 非 nil")
	}
	item := NewStructure(TagKeyMaterial, NewByteString(TagKey, []byte{1, 2, 3}), NewInteger(TagUniqueIdentifier, 7))
	clonedItem := cloneItem(item)
	item.Children[0].Value[0] = 9
	if clonedItem.Children[0].Value[0] != 1 {
		t.Fatal("cloneItem aliased child values | cloneItem 共享子项值")
	}
	list := AttributeList{NewTextAttribute(AttributeComment, "one")}
	clonedList := cloneAttributeList(list)
	list[0].Value.Value[0] = 'X'
	if clonedList[0].Value.Value[0] != 'o' {
		t.Fatal("cloneAttributeList aliased values | cloneAttributeList 共享值")
	}

	record := testSymmetricRecord("clone", StateActive)
	record.Names = []Name{NewName("alpha")}
	record.ObjectGroups = []string{"group"}
	record.Attributes = AttributeList{NewTextAttribute(AttributeComment, "comment")}
	cloned := cloneRecord(record)
	record.Names[0] = NewName("mutated")
	record.ObjectGroups[0] = "mutated"
	record.Attributes[0] = NewTextAttribute(AttributeComment, "mutated")
	record.Object.SymmetricKey.KeyBlock.Value.Material.Value[0] = 0
	if cloned.Names[0].Value != "alpha" || cloned.ObjectGroups[0] != "group" ||
		cloned.Attributes[0].Value.Value[0] != 'c' || cloned.Object.SymmetricKey.KeyBlock.Value.Material.Value[0] != 0x5A {
		t.Fatal("cloneRecord aliased record fields | cloneRecord 共享记录字段")
	}
	empty := cloneRecord(ObjectRecord{})
	if empty.Object != nil || empty.Names != nil || empty.ObjectGroups != nil || empty.Attributes != nil {
		t.Fatalf("cloneRecord(empty) = %+v | 空记录克隆 = %+v", empty, empty)
	}

	wrapping := &KeyWrappingData{
		WrappingMethod:             WrappingMethodEncrypt,
		EncryptionKeyInformation:   &EncryptionKeyInformation{UniqueIdentifier: "enc", CryptographicParameters: &CryptographicParameters{IVLength: 12}},
		MACSignatureKeyInformation: &MACSignatureKeyInformation{UniqueIdentifier: "mac", CryptographicParameters: &CryptographicParameters{TagLength: 16}},
		MACSignature:               []byte{1},
		IVCounterNonce:             []byte{2},
	}
	kb := KeyBlock{
		Format:    KeyFormatRaw,
		Algorithm: AlgorithmAES,
		Length:    256,
		Value: KeyValue{
			Material:   NewByteString(TagKeyMaterial, testKeyMaterial()),
			Attributes: AttributeList{NewTextAttribute(AttributeComment, "value")},
		},
		Wrapping: wrapping,
	}
	clonedBlock := cloneKeyBlock(kb)
	wrapping.EncryptionKeyInformation.CryptographicParameters.IVLength = 99
	wrapping.MACSignature[0] = 9
	wrapping.IVCounterNonce[0] = 9
	kb.Value.Material.Value[0] = 0
	if clonedBlock.Wrapping.EncryptionKeyInformation.CryptographicParameters.IVLength != 12 ||
		clonedBlock.Wrapping.MACSignature[0] != 1 || clonedBlock.Wrapping.IVCounterNonce[0] != 2 ||
		clonedBlock.Value.Material.Value[0] != 0x5A {
		t.Fatal("cloneKeyBlock aliased wrapping data | cloneKeyBlock 共享封装数据")
	}
	nilWrapping := cloneKeyBlock(KeyBlock{})
	if nilWrapping.Wrapping != nil {
		t.Fatal("cloneKeyBlock invented wrapping data | cloneKeyBlock 生成了封装数据")
	}

	object := Object{
		Type:         ObjectTypeSymmetricKey,
		SymmetricKey: &SymmetricKeyObject{KeyBlock: kb},
		PublicKey:    &PublicKeyObject{KeyBlock: kb},
		PrivateKey:   &PrivateKeyObject{KeyBlock: kb},
		SecretData:   &SecretDataObject{SecretDataType: SecretDataTypePassword, KeyBlock: kb},
		Certificate:  &CertificateObject{CertificateType: CertificateTypeX509, CertificateValue: []byte{1, 2}},
		Template:     &TemplateObject{Attributes: AttributeList{NewTextAttribute(AttributeComment, "t")}},
		Opaque:       &OpaqueObject{OpaqueDataType: 1, OpaqueDataValue: []byte{3, 4}},
	}
	clonedObject := cloneObject(object)
	object.Certificate.CertificateValue[0] = 9
	object.Opaque.OpaqueDataValue[0] = 9
	object.Template.Attributes[0] = NewTextAttribute(AttributeComment, "mutated")
	if clonedObject.Certificate.CertificateValue[0] != 1 || clonedObject.Opaque.OpaqueDataValue[0] != 3 ||
		clonedObject.Template.Attributes[0].Value.Value[0] != 't' {
		t.Fatal("cloneObject aliased object fields | cloneObject 共享对象字段")
	}
	if clonedObject.SymmetricKey == nil || clonedObject.PublicKey == nil || clonedObject.PrivateKey == nil ||
		clonedObject.SecretData == nil || clonedObject.SecretData.SecretDataType != SecretDataTypePassword {
		t.Fatalf("cloneObject lost fields: %+v | cloneObject 丢失字段：%+v", clonedObject, clonedObject)
	}
}

// TestRecordHelpers covers key block lookup, algorithms, lengths and lifecycle helpers. |
// TestRecordHelpers 覆盖密钥块查找、算法、长度与生命周期辅助函数。
func TestRecordHelpers(t *testing.T) {
	if _, err := recordKeyBlock(nil); !errors.Is(err, ErrState) {
		t.Fatalf("recordKeyBlock(nil) error = %v | 空记录密钥块错误 = %v", err, err)
	}
	if _, err := recordKeyBlock(&ObjectRecord{UniqueIdentifier: "empty"}); !errors.Is(err, ErrState) {
		t.Fatalf("recordKeyBlock without object error = %v | 无对象密钥块错误 = %v", err, err)
	}
	record := testSymmetricRecord("key", StateActive)
	kb, err := recordKeyBlock(&record)
	if err != nil || kb.Algorithm != AlgorithmAES || kb.Length != 256 {
		t.Fatalf("recordKeyBlock = %+v, %v | 记录密钥块 = %+v，%v", kb, err, kb, err)
	}
	if recordAlgorithm(&record) != AlgorithmAES || recordLength(&record) != 256 {
		t.Fatalf("record algorithm/length = %s/%d | 记录算法/长度 = %s/%d", recordAlgorithm(&record), recordLength(&record), recordAlgorithm(&record), recordLength(&record))
	}
	certificate := NewCertificateObject(CertificateTypeX509, []byte{1})
	certificateRecord := ObjectRecord{UniqueIdentifier: "cert", Object: &certificate}
	if recordAlgorithm(&certificateRecord) != 0 || recordLength(&certificateRecord) != 0 {
		t.Fatal("certificate record reported a key algorithm | 证书记录报告了密钥算法")
	}
	if recordID(nil) != "" || recordID(&record) != "key" {
		t.Fatalf("recordID = %q/%q | recordID = %q/%q", recordID(nil), recordID(&record), recordID(nil), recordID(&record))
	}

	now := testDate()
	deactivation := now.Add(time.Hour)
	activation := now.Add(-time.Hour)
	states := []struct {
		name   string
		record *ObjectRecord
		now    time.Time
		want   State
	}{
		{"nil", nil, now, StateDestroyed},
		{"active", &ObjectRecord{State: StateActive}, now, StateActive},
		{"active deactivated later", &ObjectRecord{State: StateActive, DeactivationDate: deactivation}, now, StateActive},
		{"active deactivated now", &ObjectRecord{State: StateActive, DeactivationDate: now}, now, StateDeactivated},
		{"preactive no date", &ObjectRecord{State: StatePreActive}, now, StatePreActive},
		{"preactive future", &ObjectRecord{State: StatePreActive, ActivationDate: deactivation}, now, StatePreActive},
		{"preactive activated", &ObjectRecord{State: StatePreActive, ActivationDate: activation}, now, StateActive},
		{"preactive expired", &ObjectRecord{State: StatePreActive, ActivationDate: activation, DeactivationDate: now}, now, StateDeactivated},
		{"deactivated", &ObjectRecord{State: StateDeactivated}, now, StateDeactivated},
		{"destroyed", &ObjectRecord{State: StateDestroyed}, now, StateDestroyed},
	}
	for _, testCase := range states {
		if got := effectiveState(testCase.record, testCase.now); got != testCase.want {
			t.Fatalf("%s effectiveState = %s, want %s | %s 有效状态 = %s，期望 %s", testCase.name, got, testCase.want, testCase.name, got, testCase.want)
		}
	}
	if err := activeForUse(nil, now); !errors.Is(err, ErrItemNotFound) {
		t.Fatalf("activeForUse(nil) error = %v | 空记录可用性错误 = %v", err, err)
	}
	if err := activeForUse(&ObjectRecord{UniqueIdentifier: "active", State: StateActive}, now); err != nil {
		t.Fatalf("activeForUse(active) error = %v | 活动记录可用性错误 = %v", err, err)
	}
	if err := activeForUse(&ObjectRecord{UniqueIdentifier: "pre", State: StatePreActive}, now); !errors.Is(err, ErrState) {
		t.Fatalf("activeForUse(preactive) error = %v | 预活动记录可用性错误 = %v", err, err)
	}
	if err := activeForUse(&ObjectRecord{UniqueIdentifier: "expired", State: StateActive, DeactivationDate: activation}, now); !errors.Is(err, ErrState) {
		t.Fatalf("activeForUse(expired) error = %v | 过期记录可用性错误 = %v", err, err)
	}

	masks := []struct {
		algorithm CryptographicAlgorithm
		object    ObjectType
		want      CryptographicUsageMask
	}{
		{AlgorithmRSA, ObjectTypePublicKey, UsageMaskEncrypt | UsageMaskVerify | UsageMaskWrapKey},
		{AlgorithmSM2, ObjectTypePublicKey, UsageMaskEncrypt | UsageMaskVerify},
		{AlgorithmECDSA, ObjectTypePublicKey, UsageMaskVerify},
		{AlgorithmRSA, ObjectTypePrivateKey, UsageMaskDecrypt | UsageMaskSign | UsageMaskUnwrapKey},
		{AlgorithmECDSA, ObjectTypePrivateKey, UsageMaskSign | UsageMaskDeriveKey},
		{0, ObjectTypeSymmetricKey, UsageMaskEncrypt | UsageMaskDecrypt | UsageMaskWrapKey | UsageMaskUnwrapKey | UsageMaskMACGenerate | UsageMaskMACVerify | UsageMaskDeriveKey},
		{AlgorithmAES, ObjectTypeSecretData, 0},
	}
	for _, testCase := range masks {
		if got := defaultUsageMask(testCase.algorithm, testCase.object); got != testCase.want {
			t.Fatalf("defaultUsageMask(%s, %s) = 0x%X, want 0x%X | 默认用法掩码 = 0x%X，期望 0x%X",
				testCase.algorithm, testCase.object, uint32(got), uint32(testCase.want), uint32(got), uint32(testCase.want))
		}
	}
}

// TestRecordAttributes covers attribute materialization and digest computation. |
// TestRecordAttributes 覆盖属性生成与摘要计算。
func TestRecordAttributes(t *testing.T) {
	if recordAttributes(nil, testDate()) != nil {
		t.Fatal("recordAttributes(nil) is not nil | 空记录属性非 nil")
	}
	record := testSymmetricRecord("attribute-key", StateActive)
	record.Names = []Name{NewName("alpha")}
	record.ObjectGroups = []string{"group-a"}
	record.Sensitive = true
	record.Fresh = true
	record.InitialDate = testDate()
	record.OriginalCreationDate = testDate()
	record.ActivationDate = testDate()
	record.DeactivationDate = testDate().Add(time.Hour)
	record.CompromiseDate = testDate()
	record.CompromiseOccurrenceDate = testDate()
	record.DestroyDate = testDate()
	record.ArchiveDate = testDate()
	record.LastChangeDate = testDate()
	record.Attributes = AttributeList{NewTextAttribute(AttributeComment, "custom")}
	attrs := recordAttributes(&record, testDate())

	if value, ok, err := attrs.LookupString(AttributeUniqueIdentifier); err != nil || !ok || value != "attribute-key" {
		t.Fatalf("UniqueIdentifier = %q, %v, %v | 唯一标识符 = %q，%v，%v", value, ok, err, value, ok, err)
	}
	if value, ok, err := attrs.LookupEnumeration(AttributeObjectType); err != nil || !ok || ObjectType(value) != ObjectTypeSymmetricKey {
		t.Fatalf("ObjectType = %d, %v, %v | 对象类型 = %d，%v，%v", value, ok, err, value, ok, err)
	}
	if value, ok, err := attrs.LookupEnumeration(AttributeCryptographicAlgorithm); err != nil || !ok || CryptographicAlgorithm(value) != AlgorithmAES {
		t.Fatalf("Algorithm = %d, %v, %v | 算法 = %d，%v，%v", value, ok, err, value, ok, err)
	}
	if value, ok, err := attrs.LookupInteger(AttributeCryptographicLength); err != nil || !ok || value != 256 {
		t.Fatalf("Length = %d, %v, %v | 长度 = %d，%v，%v", value, ok, err, value, ok, err)
	}
	if value, ok, err := attrs.LookupUsageMask(); err != nil || !ok || value != UsageMaskEncrypt|UsageMaskDecrypt {
		t.Fatalf("UsageMask = 0x%X, %v, %v | 用法掩码 = 0x%X，%v，%v", uint32(value), ok, err, uint32(value), ok, err)
	}
	if value, ok, err := attrs.LookupEnumeration(AttributeState); err != nil || !ok || State(value) != StateActive {
		t.Fatalf("State = %d, %v, %v | 状态 = %d，%v，%v", value, ok, err, value, ok, err)
	}
	if value, ok, err := attrs.LookupBoolean(AttributeSensitive); err != nil || !ok || !value {
		t.Fatalf("Sensitive = %v, %v, %v | 敏感 = %v，%v，%v", value, ok, err, value, ok, err)
	}
	if value, ok, err := attrs.LookupBoolean(AttributeFresh); err != nil || !ok || !value {
		t.Fatalf("Fresh = %v, %v, %v | 新鲜 = %v，%v，%v", value, ok, err, value, ok, err)
	}
	names, err := attrs.Names()
	if err != nil || len(names) != 1 || names[0].Value != "alpha" {
		t.Fatalf("Names = %+v, %v | 名称 = %+v，%v", names, err, names, err)
	}
	groups, err := attrs.ObjectGroups()
	if err != nil || len(groups) != 1 || groups[0] != "group-a" {
		t.Fatalf("ObjectGroups = %v, %v | 对象组 = %v，%v", groups, err, groups, err)
	}
	foundDigest := false
	for _, attr := range attrs {
		if attr.Name == AttributeDigest {
			foundDigest = true
			if attr.Value.Tag != TagDigest || attr.Value.Type != TypeStructure {
				t.Fatalf("Digest value = %+v | 摘要值 = %+v", attr.Value, attr.Value)
			}
		}
	}
	if !foundDigest {
		t.Fatal("record attributes have no digest | 记录属性没有摘要")
	}
	if !attributeListContains(attrs, AttributeComment) {
		t.Fatal("custom attribute was dropped | 自定义属性被丢弃")
	}

	certificate := NewCertificateObject(CertificateTypeX509, []byte{1, 2, 3})
	certificateRecord := ObjectRecord{UniqueIdentifier: "certificate", Object: &certificate, State: StateActive}
	certificateAttrs := recordAttributes(&certificateRecord, testDate())
	if _, ok, _ := certificateAttrs.LookupEnumeration(AttributeCryptographicAlgorithm); ok {
		t.Fatal("certificate reported a cryptographic algorithm | 证书报告了密码算法")
	}

	if digest := recordDigest(&KeyBlock{Value: NewRawKeyValue(testKeyMaterial())}); len(digest) != 32 {
		t.Fatalf("recordDigest length = %d | 摘要长度 = %d", len(digest), len(digest))
	}
	sum := sha256.Sum256(testKeyMaterial())
	if digest := recordDigest(&KeyBlock{Value: NewRawKeyValue(testKeyMaterial())}); !bytes.Equal(digest, sum[:]) {
		t.Fatal("recordDigest is not SHA-256 | 记录摘要不是 SHA-256")
	}
	if digest := recordDigest(&KeyBlock{Value: NewRawKeyValue(nil)}); digest != nil {
		t.Fatalf("empty material digest = %x | 空材料摘要 = %x", digest, digest)
	}
}

// attributeListContains reports whether the list holds an attribute with the given name. |
// attributeListContains 报告列表是否包含指定名称的属性。
func attributeListContains(attrs AttributeList, name string) bool {
	for _, attr := range attrs {
		if attr.Name == name {
			return true
		}
	}
	return false
}

// TestFilterAttributes covers requested-order filtering and multi-value attributes. |
// TestFilterAttributes 覆盖按请求顺序过滤与多值属性。
func TestFilterAttributes(t *testing.T) {
	attrs := AttributeList{
		NewTextAttribute(AttributeComment, "first"),
		NewNameAttribute(NewName("alpha")),
		NewTextAttribute(AttributeComment, "second"),
		NewNameAttribute(NewName("beta")),
		NewTextAttribute(AttributeObjectGroup, "group"),
	}
	if got := filterAttributes(attrs, nil); len(got) != len(attrs) {
		t.Fatalf("filterAttributes(nil names) length = %d | 空名称过滤长度 = %d", len(got), len(got))
	}
	filtered := filterAttributes(attrs, []string{AttributeName, AttributeComment, AttributeObjectGroup, "missing"})
	if len(filtered) != 4 {
		t.Fatalf("filtered length = %d, want 4 | 过滤长度 = %d，期望 4", len(filtered), len(filtered))
	}
	if filtered[0].Value.Children[0].Value[0] != 'a' || filtered[1].Value.Children[0].Value[0] != 'b' {
		t.Fatalf("Name attributes were not both returned | 未返回全部 Name 属性")
	}
	if filtered[2].Value.Value[0] != 'f' {
		t.Fatalf("Comment was deduplicated | Comment 被去重")
	}
	if filtered[3].Value.Value[0] != 'g' {
		t.Fatalf("ObjectGroup was deduplicated | ObjectGroup 被去重")
	}
	if got := attributeNames(attrs); len(got) != 3 || got[0] != AttributeComment || got[1] != AttributeName || got[2] != AttributeObjectGroup {
		t.Fatalf("attributeNames = %v | 属性名 = %v", got, got)
	}
	if got := attributeNames(nil); len(got) != 0 {
		t.Fatalf("attributeNames(nil) = %v | 空属性名 = %v", got, got)
	}
}

// TestNewUniqueIdentifier covers identifier shape and uniqueness. | TestNewUniqueIdentifier 覆盖标识符形态与唯一性。
func TestNewUniqueIdentifier(t *testing.T) {
	first, err := newUniqueIdentifier()
	if err != nil {
		t.Fatalf("newUniqueIdentifier: %v", err)
	}
	if len(first) != 32 {
		t.Fatalf("identifier length = %d | 标识符长度 = %d", len(first), len(first))
	}
	if _, err := hex.DecodeString(first); err != nil {
		t.Fatalf("identifier is not hex: %v | 标识符不是十六进制：%v", err, err)
	}
	second, err := newUniqueIdentifier()
	if err != nil || first == second {
		t.Fatalf("identifiers collided: %v | 标识符冲突：%v", err, err)
	}
}

// TestRecordFromTemplate covers record construction and template merging. |
// TestRecordFromTemplate 覆盖记录构建与模板合并。
func TestRecordFromTemplate(t *testing.T) {
	now := testDate()
	object := NewSymmetricKeyObject(rawKeyBlock(AlgorithmAES, testKeyMaterial()))
	record, err := recordFromTemplate(now, "generated", object, TemplateAttribute{}, true)
	if err != nil {
		t.Fatalf("recordFromTemplate: %v", err)
	}
	if record.State != StatePreActive || !record.Fresh || !record.Extractable || !record.Sensitive ||
		!record.InitialDate.Equal(now) || !record.LastChangeDate.Equal(now) {
		t.Fatalf("generated record = %+v | 生成记录 = %+v", record, record)
	}
	if record.UsageMask != defaultUsageMask(AlgorithmAES, ObjectTypeSymmetricKey) {
		t.Fatalf("default usage mask = 0x%X | 默认用法掩码 = 0x%X", uint32(record.UsageMask), uint32(record.UsageMask))
	}

	private := NewPrivateKeyObject(rawKeyBlock(AlgorithmAES, testKeyMaterial()))
	privateRecord, err := recordFromTemplate(now, "private", private, TemplateAttribute{}, false)
	if err != nil || !privateRecord.Sensitive || privateRecord.Fresh {
		t.Fatalf("private record sensitivity = %+v, %v | 私钥记录敏感性 = %+v，%v", privateRecord, err, privateRecord, err)
	}
	public := NewPublicKeyObject(rawKeyBlock(AlgorithmAES, testKeyMaterial()))
	publicRecord, err := recordFromTemplate(now, "public", public, TemplateAttribute{}, false)
	if err != nil || publicRecord.Sensitive {
		t.Fatalf("public record sensitivity = %+v, %v | 公钥记录敏感性 = %+v，%v", publicRecord, err, publicRecord, err)
	}
	secret := NewSecretDataObject(SecretDataTypePassword, rawKeyBlock(AlgorithmAES, testKeyMaterial()))
	secretRecord, err := recordFromTemplate(now, "secret", secret, TemplateAttribute{}, false)
	if err != nil || !secretRecord.Sensitive {
		t.Fatalf("secret record sensitivity = %+v, %v | 秘密记录敏感性 = %+v，%v", secretRecord, err, secretRecord, err)
	}

	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)
	activationObject := NewSymmetricKeyObject(rawKeyBlock(AlgorithmAES, testKeyMaterial()))
	activated, err := recordFromTemplate(now, "activated", activationObject, TemplateAttribute{
		Attributes: AttributeList{NewDateTimeAttribute(AttributeActivationDate, past)},
	}, true)
	if err != nil || activated.State != StateActive {
		t.Fatalf("activation in the past = %+v, %v | 过去激活时间 = %+v，%v", activated, err, activated, err)
	}
	futureObject := NewSymmetricKeyObject(rawKeyBlock(AlgorithmAES, testKeyMaterial()))
	pending, err := recordFromTemplate(now, "pending", futureObject, TemplateAttribute{
		Attributes: AttributeList{NewDateTimeAttribute(AttributeActivationDate, future)},
	}, true)
	if err != nil || pending.State != StatePreActive {
		t.Fatalf("activation in the future = %+v, %v | 未来激活时间 = %+v，%v", pending, err, pending, err)
	}

	templateObject := NewSymmetricKeyObject(rawKeyBlock(AlgorithmAES, testKeyMaterial()))
	tmpl := TemplateAttribute{
		Names: []Name{NewName("template-name")},
		Attributes: AttributeList{
			NewNameAttribute(NewName("attribute-name")),
			NewTextAttribute(AttributeObjectGroup, "group"),
			NewIntegerAttribute(AttributeCryptographicUsageMask, int64(UsageMaskEncrypt)),
			NewEnumerationAttribute(AttributeState, uint32(StateActive)),
			NewDateTimeAttribute(AttributeInitialDate, past),
			NewDateTimeAttribute(AttributeOriginalCreationDate, past),
			NewDateTimeAttribute(AttributeDeactivationDate, future),
			NewBooleanAttribute(AttributeSensitive, false),
			NewBooleanAttribute(AttributeExtractable, false),
			NewBooleanAttribute(AttributeFresh, false),
			NewEnumerationAttribute(AttributeCryptographicAlgorithm, uint32(AlgorithmAES)),
			NewIntegerAttribute(AttributeCryptographicLength, 256),
			NewTextAttribute(AttributeComment, "custom"),
		},
	}
	full, err := recordFromTemplate(now, "full", templateObject, tmpl, true)
	if err != nil {
		t.Fatalf("full template: %v | 完整模板失败：%v", err, err)
	}
	if len(full.Names) != 2 || full.Names[0].Value != "template-name" || full.Names[1].Value != "attribute-name" {
		t.Fatalf("merged names = %+v | 合并名称 = %+v", full.Names, full.Names)
	}
	if len(full.ObjectGroups) != 1 || full.ObjectGroups[0] != "group" {
		t.Fatalf("merged groups = %v | 合并对象组 = %v", full.ObjectGroups, full.ObjectGroups)
	}
	if full.UsageMask != UsageMaskEncrypt || full.State != StateActive || full.Sensitive || full.Extractable ||
		full.Fresh || !full.InitialDate.Equal(past) || !full.OriginalCreationDate.Equal(past) ||
		!full.DeactivationDate.Equal(future) || full.Attributes[0].Name != AttributeComment {
		t.Fatalf("full record = %+v | 完整记录 = %+v", full, full)
	}
	enumMaskObject := NewSymmetricKeyObject(rawKeyBlock(AlgorithmAES, testKeyMaterial()))
	enumMask, err := recordFromTemplate(now, "enum-mask", enumMaskObject, TemplateAttribute{
		Attributes: AttributeList{NewEnumerationAttribute(AttributeCryptographicUsageMask, uint32(UsageMaskDecrypt))},
	}, true)
	if err != nil || enumMask.UsageMask != UsageMaskDecrypt {
		t.Fatalf("enumeration usage mask = 0x%X, %v | 枚举用法掩码 = 0x%X，%v", uint32(enumMask.UsageMask), err, uint32(enumMask.UsageMask), err)
	}

	errorCases := []struct {
		name string
		tmpl TemplateAttribute
	}{
		{"empty name", TemplateAttribute{Names: []Name{{}}}},
		{"bad name value", TemplateAttribute{Attributes: AttributeList{{Name: AttributeName, Value: NewTextString(TagName, "bad")}}}},
		{"bad object group", TemplateAttribute{Attributes: AttributeList{NewIntegerAttribute(AttributeObjectGroup, 1)}}},
		{"bad usage mask", TemplateAttribute{Attributes: AttributeList{NewTextAttribute(AttributeCryptographicUsageMask, "x")}}},
		{"destroyed state", TemplateAttribute{Attributes: AttributeList{NewEnumerationAttribute(AttributeState, uint32(StateDestroyed))}}},
		{"bad state type", TemplateAttribute{Attributes: AttributeList{NewTextAttribute(AttributeState, "x")}}},
		{"bad initial date", TemplateAttribute{Attributes: AttributeList{NewTextAttribute(AttributeInitialDate, "x")}}},
		{"bad original date", TemplateAttribute{Attributes: AttributeList{NewTextAttribute(AttributeOriginalCreationDate, "x")}}},
		{"bad activation date", TemplateAttribute{Attributes: AttributeList{NewTextAttribute(AttributeActivationDate, "x")}}},
		{"bad deactivation date", TemplateAttribute{Attributes: AttributeList{NewTextAttribute(AttributeDeactivationDate, "x")}}},
		{"bad sensitive", TemplateAttribute{Attributes: AttributeList{NewTextAttribute(AttributeSensitive, "x")}}},
		{"bad extractable", TemplateAttribute{Attributes: AttributeList{NewTextAttribute(AttributeExtractable, "x")}}},
		{"bad fresh", TemplateAttribute{Attributes: AttributeList{NewTextAttribute(AttributeFresh, "x")}}},
		{"bad algorithm type", TemplateAttribute{Attributes: AttributeList{NewIntegerAttribute(AttributeCryptographicAlgorithm, 3)}}},
		{"bad length type", TemplateAttribute{Attributes: AttributeList{NewTextAttribute(AttributeCryptographicLength, "x")}}},
		{"algorithm mismatch", TemplateAttribute{Attributes: AttributeList{NewEnumerationAttribute(AttributeCryptographicAlgorithm, uint32(AlgorithmSM4))}}},
		{"length mismatch", TemplateAttribute{Attributes: AttributeList{NewIntegerAttribute(AttributeCryptographicLength, 128)}}},
	}
	for _, testCase := range errorCases {
		errorObject := NewSymmetricKeyObject(rawKeyBlock(AlgorithmAES, append([]byte(nil), testKeyMaterial()...)))
		if _, err := recordFromTemplate(now, "error", errorObject, testCase.tmpl, true); err == nil {
			t.Fatalf("%s accepted | %s 被接受", testCase.name, testCase.name)
		}
	}
	zeroizedObject := NewSymmetricKeyObject(rawKeyBlock(AlgorithmAES, append([]byte(nil), testKeyMaterial()...)))
	if _, err := recordFromTemplate(now, "error", zeroizedObject, TemplateAttribute{Names: []Name{{}}}, true); err == nil {
		t.Fatal("invalid template accepted | 非法模板被接受")
	}
	if !allZero(zeroizedObject.SymmetricKey.KeyBlock.Value.Material.Value) {
		t.Fatalf("failed creation did not zeroize key material: %x | 创建失败未清零密钥材料：%x",
			zeroizedObject.SymmetricKey.KeyBlock.Value.Material.Value, zeroizedObject.SymmetricKey.KeyBlock.Value.Material.Value)
	}
}

// allZero reports whether every byte is zero. | allZero 报告是否所有字节均为零。
func allZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}

// TestMatchAttributes covers every supported Locate criterion. | TestMatchAttributes 覆盖所有支持的 Locate 条件。
func TestMatchAttributes(t *testing.T) {
	now := testDate()
	record := testSymmetricRecord("locate-key", StateActive)
	record.Names = []Name{NewName("alpha"), {Value: "https://example.test", Type: NameTypeURI}}
	record.ObjectGroups = []string{"group-a"}
	record.Sensitive = true
	record.Extractable = true
	record.Fresh = true
	record.InitialDate = now
	record.OriginalCreationDate = now
	record.ActivationDate = now
	record.DeactivationDate = now.Add(time.Hour)
	record.CompromiseDate = now
	record.DestroyDate = now
	record.ArchiveDate = now
	record.LastChangeDate = now
	record.Attributes = AttributeList{NewTextAttribute(AttributeComment, "hello")}

	matches := []Attribute{
		NewTextAttribute(AttributeUniqueIdentifier, "locate-key"),
		NewEnumerationAttribute(AttributeObjectType, uint32(ObjectTypeSymmetricKey)),
		NewEnumerationAttribute(AttributeCryptographicAlgorithm, uint32(AlgorithmAES)),
		NewIntegerAttribute(AttributeCryptographicLength, 256),
		NewIntegerAttribute(AttributeCryptographicUsageMask, int64(UsageMaskEncrypt)),
		NewEnumerationAttribute(AttributeState, uint32(StateActive)),
		NewDateTimeAttribute(AttributeInitialDate, now),
		NewDateTimeAttribute(AttributeOriginalCreationDate, now),
		NewDateTimeAttribute(AttributeActivationDate, now),
		NewDateTimeAttribute(AttributeDeactivationDate, now.Add(time.Hour)),
		NewDateTimeAttribute(AttributeCompromiseDate, now),
		NewDateTimeAttribute(AttributeDestroyDate, now),
		NewDateTimeAttribute(AttributeArchiveDate, now),
		NewDateTimeAttribute(AttributeLastChangeDate, now),
		NewNameAttribute(NewName("alpha")),
		NewNameAttribute(Name{Value: "https://example.test", Type: NameTypeURI}),
		NewTextAttribute(AttributeObjectGroup, "group-a"),
		NewBooleanAttribute(AttributeSensitive, true),
		NewBooleanAttribute(AttributeExtractable, true),
		NewBooleanAttribute(AttributeFresh, true),
		NewTextAttribute(AttributeComment, "hello"),
	}
	for index := range matches {
		if !matchAttributes(&record, now, AttributeList{matches[index]}) {
			t.Fatalf("criterion %q did not match | 条件 %q 未匹配", matches[index].Name, matches[index].Name)
		}
	}
	if !matchAttributes(&record, now, AttributeList{matches[0], matches[1]}) {
		t.Fatal("combined criteria did not match | 组合条件未匹配")
	}
	if matchAttributes(&record, now, AttributeList{matches[0], NewTextAttribute(AttributeUniqueIdentifier, "other")}) {
		t.Fatal("record matched conflicting criteria | 记录匹配了冲突条件")
	}

	nonMatches := []Attribute{
		NewTextAttribute(AttributeUniqueIdentifier, "other"),
		NewEnumerationAttribute(AttributeObjectType, uint32(ObjectTypePublicKey)),
		NewEnumerationAttribute(AttributeCryptographicAlgorithm, uint32(AlgorithmSM4)),
		NewIntegerAttribute(AttributeCryptographicLength, 128),
		NewIntegerAttribute(AttributeCryptographicUsageMask, int64(UsageMaskSign)),
		NewEnumerationAttribute(AttributeState, uint32(StatePreActive)),
		NewDateTimeAttribute(AttributeInitialDate, now.Add(time.Second)),
		NewDateTimeAttribute(AttributeOriginalCreationDate, now.Add(time.Second)),
		NewDateTimeAttribute(AttributeActivationDate, now.Add(time.Second)),
		NewDateTimeAttribute(AttributeDeactivationDate, now.Add(time.Second)),
		NewDateTimeAttribute(AttributeCompromiseDate, now.Add(time.Second)),
		NewDateTimeAttribute(AttributeDestroyDate, now.Add(time.Second)),
		NewDateTimeAttribute(AttributeArchiveDate, now.Add(time.Second)),
		NewDateTimeAttribute(AttributeLastChangeDate, now.Add(time.Second)),
		NewNameAttribute(NewName("beta")),
		NewTextAttribute(AttributeObjectGroup, "group-b"),
		NewBooleanAttribute(AttributeSensitive, false),
		NewBooleanAttribute(AttributeExtractable, false),
		NewBooleanAttribute(AttributeFresh, false),
		NewTextAttribute(AttributeComment, "other"),
		NewTextAttribute("unknown-attribute", "other"),
	}
	for index := range nonMatches {
		if matchAttributes(&record, now, AttributeList{nonMatches[index]}) {
			t.Fatalf("criterion %q matched unexpectedly | 条件 %q 意外匹配", nonMatches[index].Name, nonMatches[index].Name)
		}
	}

	typeMismatches := []Attribute{
		NewIntegerAttribute(AttributeUniqueIdentifier, 1),
		NewTextAttribute(AttributeObjectType, "x"),
		NewTextAttribute(AttributeCryptographicAlgorithm, "x"),
		NewTextAttribute(AttributeCryptographicLength, "x"),
		NewTextAttribute(AttributeCryptographicUsageMask, "x"),
		NewTextAttribute(AttributeState, "x"),
		NewTextAttribute(AttributeInitialDate, "x"),
		NewTextAttribute(AttributeDeactivationDate, "x"),
		{Name: AttributeName, Value: NewTextString(TagName, "bad")},
		NewIntegerAttribute(AttributeObjectGroup, 1),
		NewTextAttribute(AttributeSensitive, "x"),
		NewTextAttribute(AttributeExtractable, "x"),
		NewTextAttribute(AttributeFresh, "x"),
	}
	for index := range typeMismatches {
		if matchAttribute(&record, now, typeMismatches[index]) {
			t.Fatalf("mistyped criterion %q matched | 类型错误条件 %q 匹配", typeMismatches[index].Name, typeMismatches[index].Name)
		}
	}

	zeroDate := &ObjectRecord{UniqueIdentifier: "zero", State: StatePreActive}
	if matchDate(NewDateTimeAttribute(AttributeInitialDate, now).Value, time.Time{}) {
		t.Fatal("zero date matched | 零日期匹配")
	}
	if matchDate(NewTextString(TagInitialDate, "x"), now) {
		t.Fatal("mistyped date matched | 类型错误日期匹配")
	}
	if !matchDate(NewDateTimeAttribute(AttributeInitialDate, now).Value, now) {
		t.Fatal("equal date did not match | 相等日期未匹配")
	}
	if matchDate(NewDateTimeAttribute(AttributeInitialDate, now).Value, now.Add(time.Second)) {
		t.Fatal("different date matched | 不同日期匹配")
	}
	if !matchAttribute(zeroDate, now, NewEnumerationAttribute(AttributeState, uint32(StatePreActive))) {
		t.Fatal("zero-state record did not match PreActive | 零状态记录未匹配预活动")
	}
}

// TestItemEqual covers structural item comparison. | TestItemEqual 覆盖结构化项比较。
func TestItemEqual(t *testing.T) {
	base := NewStructure(TagKeyMaterial, NewByteString(TagKey, []byte{1, 2}), NewInteger(TagUniqueIdentifier, 5))
	if !itemEqual(base, cloneItem(base)) {
		t.Fatal("identical items are not equal | 相同项不相等")
	}
	cases := []Item{
		NewStructure(TagKeyWrappingData, NewByteString(TagKey, []byte{1, 2}), NewInteger(TagUniqueIdentifier, 5)),
		NewStructure(TagKeyMaterial, NewByteString(TagKey, []byte{1, 3}), NewInteger(TagUniqueIdentifier, 5)),
		NewStructure(TagKeyMaterial, NewByteString(TagKey, []byte{1, 2, 3}), NewInteger(TagUniqueIdentifier, 5)),
		NewStructure(TagKeyMaterial, NewByteString(TagKey, []byte{1, 2})),
		NewStructure(TagKeyMaterial, NewInteger(TagKey, 1), NewInteger(TagUniqueIdentifier, 5)),
	}
	for index, other := range cases {
		if itemEqual(base, other) {
			t.Fatalf("case %d compared equal | 用例 %d 比较相等", index, index)
		}
	}
}
