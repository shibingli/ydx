package kmip

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"sync"
	"time"

	"github.com/shibingli/ydx/errs"
)

// ObjectRecord is the server-side state of a managed object. | ObjectRecord 是受管对象的服务器端状态。
type ObjectRecord struct {
	// UniqueIdentifier is the globally unique object identifier. | UniqueIdentifier 是全局唯一对象标识符。
	UniqueIdentifier string
	// ObjectType is the managed object type. | ObjectType 是受管对象类型。
	ObjectType ObjectType
	// Object holds the managed object. It is nil after destruction. | Object 保存受管对象；销毁后为 nil。
	Object *Object
	// State is the KMIP lifecycle state. | State 是 KMIP 生命周期状态。
	State State
	// Names holds the Name attributes. | Names 保存 Name 属性。
	Names []Name
	// ObjectGroups holds the Object Group attributes. | ObjectGroups 保存 Object Group 属性。
	ObjectGroups []string
	// Attributes holds additional and custom attributes. | Attributes 保存额外与自定义属性。
	Attributes AttributeList
	// Owner is an optional authorization owner. | Owner 是可选授权所有者。
	Owner string
	// UsageMask is the cryptographic usage mask. | UsageMask 是密码学用法掩码。
	UsageMask CryptographicUsageMask
	// Sensitive maps to the Sensitive attribute. | Sensitive 对应 Sensitive 属性。
	Sensitive bool
	// Extractable maps to the Extractable attribute. | Extractable 对应 Extractable 属性。
	Extractable bool
	// Fresh maps to the Fresh attribute. | Fresh 对应 Fresh 属性。
	Fresh bool
	// InitialDate is the object creation date. | InitialDate 是对象创建日期。
	InitialDate time.Time
	// OriginalCreationDate is the original creation date for registered objects. | OriginalCreationDate 是注册对象的原始创建日期。
	OriginalCreationDate time.Time
	// ActivationDate is the activation date. | ActivationDate 是激活日期。
	ActivationDate time.Time
	// DeactivationDate is the deactivation date. | DeactivationDate 是停用日期。
	DeactivationDate time.Time
	// CompromiseDate is the compromise date. | CompromiseDate 是泄露日期。
	CompromiseDate time.Time
	// CompromiseOccurrenceDate is the compromise occurrence date. | CompromiseOccurrenceDate 是泄露发生日期。
	CompromiseOccurrenceDate time.Time
	// DestroyDate is the destruction date. | DestroyDate 是销毁日期。
	DestroyDate time.Time
	// ArchiveDate is the archive date. | ArchiveDate 是归档日期。
	ArchiveDate time.Time
	// LastChangeDate is the last state or metadata change date. | LastChangeDate 是最后一次状态或元数据变更日期。
	LastChangeDate time.Time
	// RevocationReason records the last revocation reason. | RevocationReason 记录最后一次撤销原因。
	RevocationReason RevocationReason
}

// Store persists managed object records. Implementations must be safe for concurrent use. | Store 持久化受管对象记录；实现必须支持并发使用。
type Store interface {
	// Create stores a new record. It returns ErrObjectExists if the identifier is in use. | Create 存储新记录；标识符已使用时返回 ErrObjectExists。
	Create(ctx context.Context, record ObjectRecord) error
	// Get loads a record by unique identifier. | Get 按唯一标识符加载记录。
	Get(ctx context.Context, uniqueIdentifier string) (ObjectRecord, error)
	// Update replaces an existing record. | Update 替换既有记录。
	Update(ctx context.Context, record ObjectRecord) error
	// Delete removes a record. | Delete 删除记录。
	Delete(ctx context.Context, uniqueIdentifier string) error
	// List returns all records. | List 返回全部记录。
	List(ctx context.Context) ([]ObjectRecord, error)
}

// MemoryStore is an in-memory Store implementation. | MemoryStore 是内存 Store 实现。
type MemoryStore struct {
	mu      sync.RWMutex
	records map[string]ObjectRecord
}

// NewMemoryStore returns an empty in-memory store. | NewMemoryStore 返回空的内存存储。
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{records: make(map[string]ObjectRecord)}
}

// Create stores a new record. | Create 存储新记录。
func (s *MemoryStore) Create(ctx context.Context, record ObjectRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if record.UniqueIdentifier == "" {
		return errs.Detail(ErrInvalidRequest, "record has no unique identifier | 记录没有唯一标识符")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[record.UniqueIdentifier]; ok {
		return errs.Detail(ErrObjectExists, "object %q already exists | 对象 %q 已存在", record.UniqueIdentifier, record.UniqueIdentifier)
	}
	s.records[record.UniqueIdentifier] = cloneRecord(record)
	return nil
}

// Get loads a record by unique identifier. | Get 按唯一标识符加载记录。
func (s *MemoryStore) Get(ctx context.Context, uniqueIdentifier string) (ObjectRecord, error) {
	if err := ctx.Err(); err != nil {
		return ObjectRecord{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.records[uniqueIdentifier]
	if !ok {
		return ObjectRecord{}, errs.Detail(ErrItemNotFound, "object %q was not found | 未找到对象 %q", uniqueIdentifier, uniqueIdentifier)
	}
	return cloneRecord(record), nil
}

// Update replaces an existing record. | Update 替换既有记录。
func (s *MemoryStore) Update(ctx context.Context, record ObjectRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[record.UniqueIdentifier]; !ok {
		return errs.Detail(ErrItemNotFound, "object %q was not found | 未找到对象 %q", record.UniqueIdentifier, record.UniqueIdentifier)
	}
	s.records[record.UniqueIdentifier] = cloneRecord(record)
	return nil
}

// Delete removes a record. | Delete 删除记录。
func (s *MemoryStore) Delete(ctx context.Context, uniqueIdentifier string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[uniqueIdentifier]; !ok {
		return errs.Detail(ErrItemNotFound, "object %q was not found | 未找到对象 %q", uniqueIdentifier, uniqueIdentifier)
	}
	delete(s.records, uniqueIdentifier)
	return nil
}

// List returns all records in identifier order. | List 按标识符顺序返回全部记录。
func (s *MemoryStore) List(ctx context.Context) ([]ObjectRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]string, 0, len(s.records))
	for id := range s.records {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]ObjectRecord, 0, len(ids))
	for _, id := range ids {
		out = append(out, cloneRecord(s.records[id]))
	}
	return out, nil
}

// cloneRecord returns a deep copy of a record. | cloneRecord 返回记录的深拷贝。
func cloneRecord(record ObjectRecord) ObjectRecord {
	out := record
	if record.Object != nil {
		object := cloneObject(*record.Object)
		out.Object = &object
	}
	if record.Names != nil {
		out.Names = append([]Name(nil), record.Names...)
	}
	if record.ObjectGroups != nil {
		out.ObjectGroups = append([]string(nil), record.ObjectGroups...)
	}
	out.Attributes = cloneAttributeList(record.Attributes)
	out.RevocationReason.Message = record.RevocationReason.Message
	return out
}

// cloneAttributeList deep copies attributes and their values. | cloneAttributeList 深拷贝属性及其值。
func cloneAttributeList(list AttributeList) AttributeList {
	if list == nil {
		return nil
	}
	out := make(AttributeList, len(list))
	for i := range list {
		out[i] = Attribute{Name: list[i].Name, VendorIdentification: list[i].VendorIdentification, Value: cloneItem(list[i].Value)}
	}
	return out
}

// cloneItem deep copies an item tree. | cloneItem 深拷贝项树。
func cloneItem(item Item) Item {
	out := item
	if item.Value != nil {
		out.Value = append([]byte(nil), item.Value...)
	}
	if item.Children != nil {
		out.Children = make([]Item, len(item.Children))
		for i := range item.Children {
			out.Children[i] = cloneItem(item.Children[i])
		}
	}
	return out
}

// cloneObject deep copies a managed object. | cloneObject 深拷贝受管对象。
func cloneObject(object Object) Object {
	out := Object{Type: object.Type}
	if object.SymmetricKey != nil {
		out.SymmetricKey = &SymmetricKeyObject{KeyBlock: cloneKeyBlock(object.SymmetricKey.KeyBlock)}
	}
	if object.PublicKey != nil {
		out.PublicKey = &PublicKeyObject{KeyBlock: cloneKeyBlock(object.PublicKey.KeyBlock)}
	}
	if object.PrivateKey != nil {
		out.PrivateKey = &PrivateKeyObject{KeyBlock: cloneKeyBlock(object.PrivateKey.KeyBlock)}
	}
	if object.SecretData != nil {
		out.SecretData = &SecretDataObject{
			SecretDataType: object.SecretData.SecretDataType,
			KeyBlock:       cloneKeyBlock(object.SecretData.KeyBlock),
		}
	}
	if object.Certificate != nil {
		out.Certificate = &CertificateObject{
			CertificateType:  object.Certificate.CertificateType,
			CertificateValue: append([]byte(nil), object.Certificate.CertificateValue...),
		}
	}
	if object.Template != nil {
		out.Template = &TemplateObject{Attributes: cloneAttributeList(object.Template.Attributes)}
	}
	if object.Opaque != nil {
		out.Opaque = &OpaqueObject{
			OpaqueDataType:  object.Opaque.OpaqueDataType,
			OpaqueDataValue: append([]byte(nil), object.Opaque.OpaqueDataValue...),
		}
	}
	return out
}

// cloneKeyBlock deep copies a key block. | cloneKeyBlock 深拷贝密钥块。
func cloneKeyBlock(kb KeyBlock) KeyBlock {
	out := kb
	out.Value = KeyValue{
		Material:   cloneItem(kb.Value.Material),
		Attributes: cloneAttributeList(kb.Value.Attributes),
	}
	if kb.Wrapping != nil {
		wrapping := *kb.Wrapping
		wrapping.MACSignature = append([]byte(nil), kb.Wrapping.MACSignature...)
		wrapping.IVCounterNonce = append([]byte(nil), kb.Wrapping.IVCounterNonce...)
		if kb.Wrapping.EncryptionKeyInformation != nil {
			info := *kb.Wrapping.EncryptionKeyInformation
			if info.CryptographicParameters != nil {
				params := *info.CryptographicParameters
				info.CryptographicParameters = &params
			}
			wrapping.EncryptionKeyInformation = &info
		}
		if kb.Wrapping.MACSignatureKeyInformation != nil {
			info := *kb.Wrapping.MACSignatureKeyInformation
			if info.CryptographicParameters != nil {
				params := *info.CryptographicParameters
				info.CryptographicParameters = &params
			}
			wrapping.MACSignatureKeyInformation = &info
		}
		out.Wrapping = &wrapping
	}
	return out
}

// recordKeyBlock returns the key block of a record. | recordKeyBlock 返回记录的密钥块。
func recordKeyBlock(record *ObjectRecord) (*KeyBlock, error) {
	if record == nil || record.Object == nil {
		return nil, errs.Detail(ErrState, "object %q has no key material | 对象 %q 没有密钥材料", recordID(record), recordID(record))
	}
	return record.Object.KeyBlock()
}

// recordID returns a safe identifier for messages. | recordID 返回用于消息的安全标识符。
func recordID(record *ObjectRecord) string {
	if record == nil {
		return ""
	}
	return record.UniqueIdentifier
}

// recordAlgorithm returns the cryptographic algorithm of a record. | recordAlgorithm 返回记录的密码算法。
func recordAlgorithm(record *ObjectRecord) CryptographicAlgorithm {
	kb, err := recordKeyBlock(record)
	if err != nil {
		return 0
	}
	return kb.Algorithm
}

// recordLength returns the cryptographic length of a record in bits. | recordLength 返回记录的密码长度（位）。
func recordLength(record *ObjectRecord) int {
	kb, err := recordKeyBlock(record)
	if err != nil {
		return 0
	}
	return kb.Length
}

// effectiveState returns the lifecycle state at the given time, applying activation and deactivation dates. | effectiveState
// 返回给定时间的生命周期状态，并应用激活与停用日期。
func effectiveState(record *ObjectRecord, now time.Time) State {
	if record == nil {
		return StateDestroyed
	}
	if record.State == StateActive {
		if !record.DeactivationDate.IsZero() && !now.Before(record.DeactivationDate) {
			return StateDeactivated
		}
		return StateActive
	}
	if record.State == StatePreActive && !record.ActivationDate.IsZero() && !now.Before(record.ActivationDate) {
		if !record.DeactivationDate.IsZero() && !now.Before(record.DeactivationDate) {
			return StateDeactivated
		}
		return StateActive
	}
	return record.State
}

// activeForUse reports whether the record can be used for a cryptographic operation. | activeForUse 报告记录是否可用于密码操作。
func activeForUse(record *ObjectRecord, now time.Time) error {
	if record == nil {
		return errs.Detail(ErrItemNotFound, "object was not found | 未找到对象")
	}
	state := effectiveState(record, now)
	if state == StateActive {
		return nil
	}
	return errs.Detail(ErrState, "object %q is in state %s | 对象 %q 处于状态 %s", record.UniqueIdentifier, state, record.UniqueIdentifier, state)
}

// defaultUsageMask returns the default usage mask for an algorithm and object type. | defaultUsageMask 返回算法与对象类型的默认用法掩码。
func defaultUsageMask(algorithm CryptographicAlgorithm, objectType ObjectType) CryptographicUsageMask {
	switch objectType {
	case ObjectTypePublicKey:
		switch algorithm {
		case AlgorithmRSA:
			return UsageMaskEncrypt | UsageMaskVerify | UsageMaskWrapKey
		case AlgorithmSM2:
			return UsageMaskEncrypt | UsageMaskVerify
		default:
			return UsageMaskVerify
		}
	case ObjectTypePrivateKey:
		switch algorithm {
		case AlgorithmRSA:
			return UsageMaskDecrypt | UsageMaskSign | UsageMaskUnwrapKey
		default:
			return UsageMaskSign | UsageMaskDeriveKey
		}
	case ObjectTypeSymmetricKey:
		return UsageMaskEncrypt | UsageMaskDecrypt | UsageMaskWrapKey | UsageMaskUnwrapKey |
			UsageMaskMACGenerate | UsageMaskMACVerify | UsageMaskDeriveKey
	default:
		return 0
	}
}

// recordAttributes returns the KMIP attributes currently present on a record. The State attribute is the effective
// state, so date-driven transitions are visible without a separate update. | recordAttributes 返回记录当前存在的 KMIP
// 属性。State 属性使用有效状态，因此由日期驱动的迁移无需额外更新即可见。
func recordAttributes(record *ObjectRecord, now time.Time) AttributeList {
	if record == nil {
		return nil
	}
	attrs := AttributeList{
		NewTextAttribute(AttributeUniqueIdentifier, record.UniqueIdentifier),
		NewEnumerationAttribute(AttributeObjectType, uint32(record.ObjectType)),
	}
	if kb, err := recordKeyBlock(record); err == nil {
		if kb.Algorithm != 0 {
			attrs = append(attrs, NewEnumerationAttribute(AttributeCryptographicAlgorithm, uint32(kb.Algorithm)))
		}
		if kb.Length > 0 {
			attrs = append(attrs, NewIntegerAttribute(AttributeCryptographicLength, int64(kb.Length)))
		}
		if digest := recordDigest(kb); digest != nil {
			attrs = append(attrs, Attribute{
				Name: AttributeDigest,
				Value: NewStructure(TagDigest,
					NewEnumeration(TagHashingAlgorithm, uint32(HashingAlgorithmSHA256)),
					NewByteString(TagDigestValue, digest),
				),
			})
		}
	}
	attrs = append(attrs, NewIntegerAttribute(AttributeCryptographicUsageMask, int64(record.UsageMask)))
	attrs = append(attrs, NewEnumerationAttribute(AttributeState, uint32(effectiveState(record, now))))
	for _, name := range record.Names {
		attrs = append(attrs, NewNameAttribute(name))
	}
	for _, group := range record.ObjectGroups {
		attrs = append(attrs, NewTextAttribute(AttributeObjectGroup, group))
	}
	if !record.InitialDate.IsZero() {
		attrs = append(attrs, NewDateTimeAttribute(AttributeInitialDate, record.InitialDate))
	}
	if !record.OriginalCreationDate.IsZero() {
		attrs = append(attrs, NewDateTimeAttribute(AttributeOriginalCreationDate, record.OriginalCreationDate))
	}
	if !record.ActivationDate.IsZero() {
		attrs = append(attrs, NewDateTimeAttribute(AttributeActivationDate, record.ActivationDate))
	}
	if !record.DeactivationDate.IsZero() {
		attrs = append(attrs, NewDateTimeAttribute(AttributeDeactivationDate, record.DeactivationDate))
	}
	if !record.CompromiseDate.IsZero() {
		attrs = append(attrs, NewDateTimeAttribute(AttributeCompromiseDate, record.CompromiseDate))
	}
	if !record.CompromiseOccurrenceDate.IsZero() {
		attrs = append(attrs, NewDateTimeAttribute(AttributeCompromiseOccurrenceDate, record.CompromiseOccurrenceDate))
	}
	if !record.DestroyDate.IsZero() {
		attrs = append(attrs, NewDateTimeAttribute(AttributeDestroyDate, record.DestroyDate))
	}
	if !record.ArchiveDate.IsZero() {
		attrs = append(attrs, NewDateTimeAttribute(AttributeArchiveDate, record.ArchiveDate))
	}
	if !record.LastChangeDate.IsZero() {
		attrs = append(attrs, NewDateTimeAttribute(AttributeLastChangeDate, record.LastChangeDate))
	}
	attrs = append(attrs, NewBooleanAttribute(AttributeSensitive, record.Sensitive))
	attrs = append(attrs, NewBooleanAttribute(AttributeExtractable, record.Extractable))
	attrs = append(attrs, NewBooleanAttribute(AttributeFresh, record.Fresh))
	attrs = append(attrs, cloneAttributeList(record.Attributes)...)
	return attrs
}

// recordDigest computes the SHA-256 digest attribute value of key material. | recordDigest 计算密钥材料的 SHA-256 摘要属性值。
func recordDigest(kb *KeyBlock) []byte {
	material, err := keyMaterialBytes(*kb)
	if err != nil || len(material) == 0 {
		return nil
	}
	sum := sha256.Sum256(material)
	return sum[:]
}

// filterAttributes returns the requested attributes in request order, skipping names that are absent. | filterAttributes
// 按请求顺序返回请求的属性，跳过不存在的名称。
func filterAttributes(attrs AttributeList, names []string) AttributeList {
	if len(names) == 0 {
		return attrs
	}
	out := make(AttributeList, 0, len(names))
	for _, name := range names {
		for i := range attrs {
			if attrs[i].Name == name {
				out = append(out, attrs[i])
				if name != AttributeName && name != AttributeObjectGroup &&
					name != AttributeApplicationSpecificInformation && name != AttributeLink {
					break
				}
			}
		}
	}
	return out
}

// attributeNames returns unique attribute names in document order. | attributeNames 按文档顺序返回唯一属性名。
func attributeNames(attrs AttributeList) []string {
	seen := make(map[string]struct{}, len(attrs))
	out := make([]string, 0, len(attrs))
	for i := range attrs {
		if _, ok := seen[attrs[i].Name]; ok {
			continue
		}
		seen[attrs[i].Name] = struct{}{}
		out = append(out, attrs[i].Name)
	}
	return out
}

// newUniqueIdentifier returns a random KMIP unique identifier. | newUniqueIdentifier 返回随机 KMIP 唯一标识符。
func newUniqueIdentifier() (string, error) {
	raw, err := randomBytes(16)
	if err != nil {
		return "", err
	}
	defer zeroize(raw)
	return hex.EncodeToString(raw), nil
}

// recordFromTemplate builds a record from a generated or registered object and a template. | recordFromTemplate
// 从生成或注册的对象与模板构造记录。
func recordFromTemplate(now time.Time, uid string, object Object, tmpl TemplateAttribute, fresh bool) (ObjectRecord, error) {
	record := ObjectRecord{
		UniqueIdentifier: uid,
		ObjectType:       object.Type,
		Object:           &object,
		State:            StatePreActive,
		Fresh:            fresh,
		Extractable:      true,
		InitialDate:      now,
		LastChangeDate:   now,
	}
	switch object.Type {
	case ObjectTypePrivateKey, ObjectTypeSymmetricKey, ObjectTypeSecretData:
		record.Sensitive = true
	}
	record.UsageMask = defaultUsageMask(recordAlgorithm(&record), object.Type)
	if err := applyTemplate(&record, tmpl); err != nil {
		object.Zeroize()
		return ObjectRecord{}, err
	}
	if !record.ActivationDate.IsZero() && !now.Before(record.ActivationDate) {
		record.State = StateActive
	}
	return record, nil
}

// applyTemplate merges a Template-Attribute into a record. | applyTemplate 把 Template-Attribute 合并到记录。
func applyTemplate(record *ObjectRecord, tmpl TemplateAttribute) error {
	for _, name := range tmpl.Names {
		if name.Value == "" {
			return errs.Detail(ErrInvalidRequest, "empty name value | 名称值为空")
		}
		record.Names = append(record.Names, name)
	}
	for i := range tmpl.Attributes {
		attr := tmpl.Attributes[i]
		switch attr.Name {
		case AttributeName:
			name, err := DecodeName(attr.Value)
			if err != nil {
				return err
			}
			record.Names = append(record.Names, name)
		case AttributeObjectGroup:
			value, err := attr.Value.AsTextString()
			if err != nil {
				return err
			}
			record.ObjectGroups = append(record.ObjectGroups, value)
		case AttributeCryptographicUsageMask:
			mask, err := attr.Value.AsInteger()
			if err != nil {
				if enum, enumErr := attr.Value.AsEnumeration(); enumErr == nil {
					mask = int64(enum)
				} else {
					return err
				}
			}
			record.UsageMask = CryptographicUsageMask(uint32(mask))
		case AttributeState:
			value, err := attr.Value.AsEnumeration()
			if err != nil {
				return err
			}
			state := State(value)
			if state != StatePreActive && state != StateActive {
				return errs.Detail(ErrInvalidRequest, "cannot create an object in state %s | 不能以状态 %s 创建对象", state, state)
			}
			record.State = state
		case AttributeInitialDate:
			value, err := attr.Value.AsDateTime()
			if err != nil {
				return err
			}
			record.InitialDate = value
		case AttributeOriginalCreationDate:
			value, err := attr.Value.AsDateTime()
			if err != nil {
				return err
			}
			record.OriginalCreationDate = value
		case AttributeActivationDate:
			value, err := attr.Value.AsDateTime()
			if err != nil {
				return err
			}
			record.ActivationDate = value
		case AttributeDeactivationDate:
			value, err := attr.Value.AsDateTime()
			if err != nil {
				return err
			}
			record.DeactivationDate = value
		case AttributeSensitive:
			value, err := attr.Value.AsBoolean()
			if err != nil {
				return err
			}
			record.Sensitive = value
		case AttributeExtractable:
			value, err := attr.Value.AsBoolean()
			if err != nil {
				return err
			}
			record.Extractable = value
		case AttributeFresh:
			value, err := attr.Value.AsBoolean()
			if err != nil {
				return err
			}
			record.Fresh = value
		case AttributeCryptographicAlgorithm:
			value, err := attr.Value.AsEnumeration()
			if err != nil {
				return err
			}
			kb, kbErr := recordKeyBlock(record)
			if kbErr == nil && kb.Algorithm != 0 && CryptographicAlgorithm(value) != kb.Algorithm {
				return errs.Detail(ErrInvalidRequest, "attribute algorithm %s does not match key algorithm %s | 属性算法 %s 与密钥算法 %s 不一致",
					CryptographicAlgorithm(value), kb.Algorithm, CryptographicAlgorithm(value), kb.Algorithm)
			}
		case AttributeCryptographicLength:
			value, err := attr.Value.AsInteger()
			if err != nil {
				return err
			}
			kb, kbErr := recordKeyBlock(record)
			if kbErr == nil && kb.Length > 0 && int(value) != kb.Length {
				return errs.Detail(ErrInvalidRequest, "attribute length %d does not match key length %d | 属性长度 %d 与密钥长度 %d 不一致", value, kb.Length, value, kb.Length)
			}
		default:
			record.Attributes = append(record.Attributes, attr)
		}
	}
	return nil
}

// matchAttributes reports whether a record matches all Locate attributes. | matchAttributes 报告记录是否匹配全部 Locate 属性。
func matchAttributes(record *ObjectRecord, now time.Time, criteria AttributeList) bool {
	for i := range criteria {
		if !matchAttribute(record, now, criteria[i]) {
			return false
		}
	}
	return true
}

// matchAttribute reports whether one Locate criterion matches. | matchAttribute 报告单个 Locate 条件是否匹配。
func matchAttribute(record *ObjectRecord, now time.Time, criterion Attribute) bool {
	switch criterion.Name {
	case AttributeUniqueIdentifier:
		value, err := criterion.Value.AsTextString()
		return err == nil && value == record.UniqueIdentifier
	case AttributeObjectType:
		value, err := criterion.Value.AsEnumeration()
		return err == nil && ObjectType(value) == record.ObjectType
	case AttributeCryptographicAlgorithm:
		value, err := criterion.Value.AsEnumeration()
		return err == nil && CryptographicAlgorithm(value) == recordAlgorithm(record)
	case AttributeCryptographicLength:
		value, err := criterion.Value.AsInteger()
		return err == nil && int(value) == recordLength(record)
	case AttributeCryptographicUsageMask:
		value, err := criterion.Value.AsInteger()
		if err != nil {
			return false
		}
		return record.UsageMask.Has(CryptographicUsageMask(uint32(value)))
	case AttributeState:
		value, err := criterion.Value.AsEnumeration()
		return err == nil && State(value) == effectiveState(record, now)
	case AttributeInitialDate:
		return matchDate(criterion.Value, record.InitialDate)
	case AttributeOriginalCreationDate:
		return matchDate(criterion.Value, record.OriginalCreationDate)
	case AttributeActivationDate:
		return matchDate(criterion.Value, record.ActivationDate)
	case AttributeDeactivationDate:
		return matchDate(criterion.Value, record.DeactivationDate)
	case AttributeCompromiseDate:
		return matchDate(criterion.Value, record.CompromiseDate)
	case AttributeDestroyDate:
		return matchDate(criterion.Value, record.DestroyDate)
	case AttributeArchiveDate:
		return matchDate(criterion.Value, record.ArchiveDate)
	case AttributeLastChangeDate:
		return matchDate(criterion.Value, record.LastChangeDate)
	case AttributeName:
		name, err := DecodeName(criterion.Value)
		if err != nil {
			return false
		}
		for _, candidate := range record.Names {
			if candidate.Value == name.Value && candidate.Type == name.Type {
				return true
			}
		}
		return false
	case AttributeObjectGroup:
		value, err := criterion.Value.AsTextString()
		if err != nil {
			return false
		}
		for _, group := range record.ObjectGroups {
			if group == value {
				return true
			}
		}
		return false
	case AttributeSensitive:
		value, err := criterion.Value.AsBoolean()
		return err == nil && value == record.Sensitive
	case AttributeExtractable:
		value, err := criterion.Value.AsBoolean()
		return err == nil && value == record.Extractable
	case AttributeFresh:
		value, err := criterion.Value.AsBoolean()
		return err == nil && value == record.Fresh
	default:
		attrs := recordAttributes(record, now)
		for i := range attrs {
			if attrs[i].Name == criterion.Name && itemEqual(attrs[i].Value, criterion.Value) {
				return true
			}
		}
		return false
	}
}

// matchDate compares a date-time attribute value. | matchDate 比较日期时间属性值。
func matchDate(item Item, value time.Time) bool {
	if value.IsZero() {
		return false
	}
	actual, err := item.AsDateTime()
	if err != nil {
		return false
	}
	return actual.Equal(value)
}

// itemEqual reports whether two TTLV items encode the same tag, type, length and value tree. | itemEqual
// 报告两个 TTLV 项的标签、类型、长度与值树是否相同。
func itemEqual(a, b Item) bool {
	if a.Tag != b.Tag || a.Type != b.Type || len(a.Value) != len(b.Value) || len(a.Children) != len(b.Children) {
		return false
	}
	for i := range a.Value {
		if a.Value[i] != b.Value[i] {
			return false
		}
	}
	for i := range a.Children {
		if !itemEqual(a.Children[i], b.Children[i]) {
			return false
		}
	}
	return true
}
