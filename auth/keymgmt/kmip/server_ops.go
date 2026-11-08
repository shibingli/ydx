package kmip

import (
	"github.com/shibingli/ydx/errs"
)

// handleCreate implements Create for symmetric keys and secret data. | handleCreate 实现对称密钥与秘密数据的 Create。
func (s *Server) handleCreate(request CreateRequest) (Item, error) {
	return s.handleCreateForVersion(request, DefaultProtocolVersion)
}

// handleCreateForVersion implements Create using the payload shape of version. | handleCreateForVersion 使用
// version 的负载形状实现 Create。
func (s *Server) handleCreateForVersion(request CreateRequest, version ProtocolVersion) (Item, error) {
	algorithm, length, err := templateAlgorithmLength([]TemplateAttribute{request.TemplateAttribute})
	if err != nil {
		return Item{}, err
	}
	format, err := templateKeyFormat([]TemplateAttribute{request.TemplateAttribute})
	if err != nil {
		return Item{}, err
	}
	var object Object
	switch request.ObjectType {
	case ObjectTypeSymmetricKey:
		kb, err := generateSymmetricKeyBlock(algorithm, length)
		if err != nil {
			return Item{}, err
		}
		kb, err = convertRequestedFormat(kb, format)
		if err != nil {
			zeroizeKeyBlock(&kb)
			return Item{}, err
		}
		object = NewSymmetricKeyObject(kb)
	case ObjectTypeSecretData:
		bits := length
		if bits == 0 {
			bits = 256
		}
		if bits <= 0 || bits%8 != 0 || bits > 1<<20 {
			return Item{}, errs.Detail(ErrInvalidRequest, "invalid secret data length %d | 秘密数据长度 %d 非法", bits, bits)
		}
		value, err := randomBytes(bits / 8)
		if err != nil {
			return Item{}, err
		}
		kb := KeyBlock{
			Format:    KeyFormatRaw,
			Algorithm: algorithm,
			Length:    bits,
			Value:     NewRawKeyValue(value),
		}
		zeroize(value)
		kb, err = convertRequestedFormat(kb, format)
		if err != nil {
			zeroizeKeyBlock(&kb)
			return Item{}, err
		}
		object = NewSecretDataObject(SecretDataTypePassword, kb)
	default:
		return Item{}, operationFailed(ResultReasonInvalidObjectType,
			"Create supports only Symmetric Key and Secret Data | Create 仅支持对称密钥与秘密数据")
	}
	uid, err := newUniqueIdentifier()
	if err != nil {
		object.Zeroize()
		return Item{}, err
	}
	record, err := recordFromTemplate(s.now(), uid, object, request.TemplateAttribute, true)
	if err != nil {
		object.Zeroize()
		return Item{}, err
	}
	if record.Object != nil {
		defer record.Object.Zeroize()
	}
	if err := s.store.Create(s.ctx, record); err != nil {
		return Item{}, err
	}
	return CreateResponse{ObjectType: request.ObjectType, UniqueIdentifier: uid}.ItemForVersion(version)
}

// handleCreateKeyPair implements Create Key Pair. | handleCreateKeyPair 实现 Create Key Pair。
func (s *Server) handleCreateKeyPair(request CreateKeyPairRequest) (Item, error) {
	return s.handleCreateKeyPairForVersion(request, DefaultProtocolVersion)
}

// handleCreateKeyPairForVersion implements Create Key Pair using the payload shape of version. |
// handleCreateKeyPairForVersion 使用 version 的负载形状实现 Create Key Pair。
func (s *Server) handleCreateKeyPairForVersion(request CreateKeyPairRequest, version ProtocolVersion) (Item, error) {
	templates := []TemplateAttribute{}
	if request.CommonTemplateAttribute != nil {
		templates = append(templates, *request.CommonTemplateAttribute)
	}
	if request.PrivateKeyTemplateAttribute != nil {
		templates = append(templates, *request.PrivateKeyTemplateAttribute)
	}
	if request.PublicKeyTemplateAttribute != nil {
		templates = append(templates, *request.PublicKeyTemplateAttribute)
	}
	algorithm, length, err := templateAlgorithmLength(templates)
	if err != nil {
		return Item{}, err
	}
	privateFormat, err := templateKeyFormatPair(request.CommonTemplateAttribute, request.PrivateKeyTemplateAttribute)
	if err != nil {
		return Item{}, err
	}
	publicFormat, err := templateKeyFormatPair(request.CommonTemplateAttribute, request.PublicKeyTemplateAttribute)
	if err != nil {
		return Item{}, err
	}
	privateBlock, publicBlock, err := generateKeyPairKeyBlocks(algorithm, length)
	if err != nil {
		return Item{}, err
	}
	privateBlock, err = convertRequestedFormat(privateBlock, privateFormat)
	if err != nil {
		zeroizeKeyBlock(&privateBlock)
		zeroizeKeyBlock(&publicBlock)
		return Item{}, err
	}
	publicBlock, err = convertRequestedFormat(publicBlock, publicFormat)
	if err != nil {
		zeroizeKeyBlock(&privateBlock)
		zeroizeKeyBlock(&publicBlock)
		return Item{}, err
	}
	common := mergeTemplates(request.CommonTemplateAttribute, request.PrivateKeyTemplateAttribute)
	publicTemplate := mergeTemplates(request.CommonTemplateAttribute, request.PublicKeyTemplateAttribute)
	now := s.now()
	privateID, err := newUniqueIdentifier()
	if err != nil {
		zeroizeKeyBlock(&privateBlock)
		zeroizeKeyBlock(&publicBlock)
		return Item{}, err
	}
	publicID, err := newUniqueIdentifier()
	if err != nil {
		zeroizeKeyBlock(&privateBlock)
		zeroizeKeyBlock(&publicBlock)
		return Item{}, err
	}
	privateRecord, err := recordFromTemplate(now, privateID, NewPrivateKeyObject(privateBlock), common, true)
	if err != nil {
		zeroizeKeyBlock(&privateBlock)
		zeroizeKeyBlock(&publicBlock)
		return Item{}, err
	}
	publicRecord, err := recordFromTemplate(now, publicID, NewPublicKeyObject(publicBlock), publicTemplate, true)
	if err != nil {
		privateRecord.Object.Zeroize()
		zeroizeKeyBlock(&publicBlock)
		return Item{}, err
	}
	defer privateRecord.Object.Zeroize()
	defer publicRecord.Object.Zeroize()
	if err := s.store.Create(s.ctx, privateRecord); err != nil {
		return Item{}, err
	}
	if err := s.store.Create(s.ctx, publicRecord); err != nil {
		_ = s.store.Delete(s.ctx, privateID)
		return Item{}, err
	}
	return CreateKeyPairResponse{
		PrivateKeyUniqueIdentifier: privateID,
		PublicKeyUniqueIdentifier:  publicID,
	}.ItemForVersion(version)
}

// handleRegister implements Register. | handleRegister 实现 Register。
func (s *Server) handleRegister(request RegisterRequest) (Item, error) {
	return s.handleRegisterForVersion(request, DefaultProtocolVersion)
}

// handleRegisterForVersion implements Register using the payload shape of version. | handleRegisterForVersion 使用
// version 的负载形状实现 Register。
func (s *Server) handleRegisterForVersion(request RegisterRequest, version ProtocolVersion) (Item, error) {
	if request.Object.Type != request.ObjectType {
		return Item{}, errs.Detail(ErrInvalidRequest, "object type mismatch | 对象类型不一致")
	}
	switch request.ObjectType {
	case ObjectTypeSymmetricKey, ObjectTypePublicKey, ObjectTypePrivateKey, ObjectTypeSecretData:
		if kb, err := request.Object.KeyBlock(); err == nil && (kb.Algorithm != 0 || kb.Format == KeyFormatJWK) {
			parsed, err := parseKeyBlock(*kb)
			if err != nil {
				return Item{}, err
			}
			parsed.zeroize()
			if kb.Algorithm == 0 && parsed.algorithm != 0 {
				kb.Algorithm = parsed.algorithm
			}
			if kb.Length > 0 && parsed.length > 0 && kb.Length != parsed.length {
				return Item{}, errs.Detail(ErrInvalidRequest, "key length %d does not match material length %d | 密钥长度 %d 与材料长度 %d 不一致",
					kb.Length, parsed.length, kb.Length, parsed.length)
			}
			if kb.Length == 0 && parsed.length > 0 {
				kb.Length = parsed.length
			}
		}
	case ObjectTypeCertificate, ObjectTypeTemplate, ObjectTypeOpaqueObject:
	default:
		return Item{}, operationFailed(ResultReasonInvalidObjectType,
			"Register does not support this object type | Register 不支持该对象类型")
	}
	uid, err := newUniqueIdentifier()
	if err != nil {
		request.Object.Zeroize()
		return Item{}, err
	}
	record, err := recordFromTemplate(s.now(), uid, request.Object, request.TemplateAttribute, false)
	if err != nil {
		request.Object.Zeroize()
		return Item{}, err
	}
	defer record.Object.Zeroize()
	if err := s.store.Create(s.ctx, record); err != nil {
		return Item{}, err
	}
	return RegisterResponse{UniqueIdentifier: uid}.ItemForVersion(version)
}

// handleGet implements Get, including format conversion and key wrapping. | handleGet 实现 Get，包括格式转换与密钥封装。
func (s *Server) handleGet(request GetRequest) (Item, error) {
	return s.handleGetForVersion(request, DefaultProtocolVersion)
}

// handleGetForVersion implements Get using the payload shape of version. | handleGetForVersion 使用 version 的负载形状
// 实现 Get。
func (s *Server) handleGetForVersion(request GetRequest, version ProtocolVersion) (Item, error) {
	record, err := s.loadRecord(request.UniqueIdentifier)
	if err != nil {
		return Item{}, err
	}
	if record.Object == nil || record.State == StateDestroyed {
		return Item{}, errs.Detail(ErrState, "object %q was destroyed | 对象 %q 已销毁", record.UniqueIdentifier, record.UniqueIdentifier)
	}
	object := cloneObject(*record.Object)
	kb, kbErr := object.KeyBlock()
	if kbErr == nil {
		switch object.Type {
		case ObjectTypeSymmetricKey, ObjectTypePrivateKey, ObjectTypeSecretData:
			if !record.Extractable {
				return Item{}, resultErrorFor(ResultStatusOperationFailed, ResultReasonNotExtractable,
					"object is not extractable | 对象不可导出")
			}
		}
		if request.KeyCompressionType != 0 && request.KeyCompressionType != KeyCompressionNone &&
			request.KeyCompressionType != KeyCompressionECPublicKeyUncompressed {
			return Item{}, errs.Detail(ErrUnsupported, "requested key compression type is not supported | 请求的密钥压缩类型不受支持")
		}
		if request.KeyFormatType != 0 && request.KeyFormatType != kb.Format {
			converted, err := convertKeyBlockFormat(*kb, request.KeyFormatType)
			if err != nil {
				return Item{}, err
			}
			*kb = converted
		}
		if request.KeyWrappingSpecification != nil {
			wrapped, err := s.wrapForGet(kb, *request.KeyWrappingSpecification)
			if err != nil {
				return Item{}, err
			}
			*kb = wrapped
		} else if request.KeyWrapType == KeyWrapTypeAsRegistered {
			// Stored keys are always kept unwrapped. | 存储密钥始终保持未封装。
		} else if request.KeyWrapType != 0 && request.KeyWrapType != KeyWrapTypeNotWrapped {
			return Item{}, errs.Detail(ErrUnsupported, "requested key wrap type is not supported | 请求的密钥封装类型不受支持")
		}
	}
	return GetResponse{ObjectType: object.Type, UniqueIdentifier: record.UniqueIdentifier, Object: object}.ItemForVersion(version)
}

// wrapForGet wraps a key block for a Get response. | wrapForGet 为 Get 响应封装密钥块。
func (s *Server) wrapForGet(kb *KeyBlock, spec KeyWrappingSpecification) (KeyBlock, error) {
	if spec.EncryptionKeyInformation == nil {
		return KeyBlock{}, errs.Detail(ErrInvalidRequest, "wrapping specification has no encryption key | 封装规格没有加密密钥")
	}
	wrappingRecord, err := s.loadActive(spec.EncryptionKeyInformation.UniqueIdentifier, UsageMaskWrapKey)
	if err != nil {
		return KeyBlock{}, err
	}
	wrappingBlock, err := recordKeyBlock(&wrappingRecord)
	if err != nil {
		return KeyBlock{}, err
	}
	return wrapKeyBlock(*kb, *wrappingBlock, spec)
}

// handleGetAttributes implements Get Attributes. | handleGetAttributes 实现 Get Attributes。
func (s *Server) handleGetAttributes(request GetAttributesRequest) (Item, error) {
	return s.handleGetAttributesForVersion(request, DefaultProtocolVersion)
}

// handleGetAttributesForVersion implements Get Attributes using the payload shape of version. |
// handleGetAttributesForVersion 使用 version 的负载形状实现 Get Attributes。
func (s *Server) handleGetAttributesForVersion(request GetAttributesRequest, version ProtocolVersion) (Item, error) {
	record, err := s.loadRecord(request.UniqueIdentifier)
	if err != nil {
		return Item{}, err
	}
	attrs := filterAttributes(recordAttributes(&record, s.now()), request.AttributeNames)
	return GetAttributesResponse{UniqueIdentifier: record.UniqueIdentifier, AttributeList: attrs}.ItemForVersion(version)
}

// handleGetAttributeList implements Get Attribute List. | handleGetAttributeList 实现 Get Attribute List。
func (s *Server) handleGetAttributeList(request GetAttributeListRequest) (Item, error) {
	return s.handleGetAttributeListForVersion(request, DefaultProtocolVersion)
}

// handleGetAttributeListForVersion implements Get Attribute List using the payload shape of version. |
// handleGetAttributeListForVersion 使用 version 的负载形状实现 Get Attribute List。
func (s *Server) handleGetAttributeListForVersion(request GetAttributeListRequest, version ProtocolVersion) (Item, error) {
	record, err := s.loadRecord(request.UniqueIdentifier)
	if err != nil {
		return Item{}, err
	}
	return GetAttributeListResponse{
		UniqueIdentifier: record.UniqueIdentifier,
		AttributeNames:   attributeNames(recordAttributes(&record, s.now())),
	}.ItemForVersion(version)
}

// handleActivate implements Activate. | handleActivate 实现 Activate。
func (s *Server) handleActivate(request ActivateRequest) (Item, error) {
	record, err := s.loadRecord(request.UniqueIdentifier)
	if err != nil {
		return Item{}, err
	}
	state := effectiveState(&record, s.now())
	switch state {
	case StatePreActive:
		record.State = StateActive
		now := s.now()
		if record.ActivationDate.IsZero() || record.ActivationDate.After(now) {
			record.ActivationDate = now
		}
		record.LastChangeDate = now
	case StateActive:
		return Item{}, errs.Detail(ErrState, "object %q is already active | 对象 %q 已处于活动状态", record.UniqueIdentifier, record.UniqueIdentifier)
	default:
		return Item{}, errs.Detail(ErrState, "cannot activate an object in state %s | 无法激活处于状态 %s 的对象", state, state)
	}
	if err := s.store.Update(s.ctx, record); err != nil {
		return Item{}, err
	}
	return ActivateResponse{UniqueIdentifier: record.UniqueIdentifier}.Item()
}

// handleRevoke implements Revoke. | handleRevoke 实现 Revoke。
func (s *Server) handleRevoke(request RevokeRequest) (Item, error) {
	if request.Reason.Code == 0 {
		return Item{}, errs.Detail(ErrInvalidRequest, "revocation reason is required | 必须提供撤销原因")
	}
	record, err := s.loadRecord(request.UniqueIdentifier)
	if err != nil {
		return Item{}, err
	}
	state := effectiveState(&record, s.now())
	if state != StatePreActive && state != StateActive {
		return Item{}, errs.Detail(ErrState, "cannot revoke an object in state %s | 无法撤销处于状态 %s 的对象", state, state)
	}
	now := s.now()
	record.RevocationReason = request.Reason
	record.DeactivationDate = now
	if request.Reason.Code == RevocationKeyCompromise {
		record.State = StateCompromised
		record.CompromiseDate = now
		record.CompromiseOccurrenceDate = request.CompromiseOccurrenceDate
		if record.CompromiseOccurrenceDate.IsZero() {
			record.CompromiseOccurrenceDate = now
		}
	} else {
		record.State = StateDeactivated
	}
	record.LastChangeDate = now
	if err := s.store.Update(s.ctx, record); err != nil {
		return Item{}, err
	}
	return RevokeResponse{UniqueIdentifier: record.UniqueIdentifier}.Item()
}

// handleDestroy implements Destroy and zeroizes the stored key material. | handleDestroy 实现 Destroy 并清除存储的密钥材料。
func (s *Server) handleDestroy(request DestroyRequest) (Item, error) {
	record, err := s.loadRecord(request.UniqueIdentifier)
	if err != nil {
		return Item{}, err
	}
	if record.State == StateDestroyed {
		return Item{}, errs.Detail(ErrState, "object %q is already destroyed | 对象 %q 已销毁", record.UniqueIdentifier, record.UniqueIdentifier)
	}
	if record.Object != nil {
		record.Object.Zeroize()
	}
	record.Object = nil
	record.State = StateDestroyed
	now := s.now()
	record.DestroyDate = now
	record.LastChangeDate = now
	if err := s.store.Update(s.ctx, record); err != nil {
		return Item{}, err
	}
	return DestroyResponse{UniqueIdentifier: record.UniqueIdentifier}.Item()
}

// storageStatusOnline is the KMIP Storage Status Mask bit for online storage. Every object in this server's store is
// online. | storageStatusOnline 是在线存储的 KMIP 存储状态掩码位。本服务器存储中的对象全部在线。
const storageStatusOnline uint32 = 0x00000001

// handleLocate implements Locate. | handleLocate 实现 Locate。
func (s *Server) handleLocate(request LocateRequest) (Item, error) {
	if request.StorageStatusMask != 0 && request.StorageStatusMask&storageStatusOnline == 0 {
		return LocateResponse{LocatedItems: 0, HasLocatedItems: true}.Item()
	}
	records, err := s.store.List(s.ctx)
	if err != nil {
		return Item{}, err
	}
	now := s.now()
	matched := make([]string, 0, len(records))
	for i := range records {
		record := &records[i]
		if !matchAttributes(record, now, request.Attributes) {
			continue
		}
		matched = append(matched, record.UniqueIdentifier)
	}
	total := len(matched)
	if request.OffsetItems >= len(matched) {
		matched = nil
	} else {
		matched = matched[request.OffsetItems:]
	}
	if request.MaximumItems > 0 && len(matched) > request.MaximumItems {
		matched = matched[:request.MaximumItems]
	}
	return LocateResponse{
		LocatedItems:      total,
		HasLocatedItems:   true,
		UniqueIdentifiers: matched,
	}.Item()
}

// handleDeriveKey implements Derive Key with HKDF and PBKDF2. | handleDeriveKey 使用 HKDF 与 PBKDF2 实现 Derive Key。
func (s *Server) handleDeriveKey(request DeriveKeyRequest) (Item, error) {
	return s.handleDeriveKeyForVersion(request, DefaultProtocolVersion)
}

// handleDeriveKeyForVersion implements Derive Key using the payload shape of version. | handleDeriveKeyForVersion 使用
// version 的负载形状实现 Derive Key。
func (s *Server) handleDeriveKeyForVersion(request DeriveKeyRequest, version ProtocolVersion) (Item, error) {
	if request.ObjectType != ObjectTypeSymmetricKey {
		return Item{}, operationFailed(ResultReasonInvalidObjectType,
			"derived objects must be symmetric keys | 派生对象必须是对称密钥")
	}
	keys := make([]KeyBlock, 0, len(request.UniqueIdentifiers))
	for _, uid := range request.UniqueIdentifiers {
		record, err := s.loadActive(uid, UsageMaskDeriveKey)
		if err != nil {
			return Item{}, err
		}
		kb, err := recordKeyBlock(&record)
		if err != nil {
			return Item{}, err
		}
		keys = append(keys, *kb)
	}
	algorithm, length, err := templateAlgorithmLength([]TemplateAttribute{request.TemplateAttribute})
	if err != nil {
		return Item{}, err
	}
	derived, err := deriveKeyBlock(keys, request.DerivationMethod, request.DerivationParameters, algorithm, length)
	if err != nil {
		return Item{}, err
	}
	uid, err := newUniqueIdentifier()
	if err != nil {
		zeroizeKeyBlock(&derived)
		return Item{}, err
	}
	record, err := recordFromTemplate(s.now(), uid, NewSymmetricKeyObject(derived), request.TemplateAttribute, true)
	if err != nil {
		zeroizeKeyBlock(&derived)
		return Item{}, err
	}
	defer record.Object.Zeroize()
	if err := s.store.Create(s.ctx, record); err != nil {
		return Item{}, err
	}
	return DeriveKeyResponse{UniqueIdentifier: uid}.ItemForVersion(version)
}

// handleQuery implements Query. | handleQuery 实现 Query。
func (s *Server) handleQuery(request QueryRequest) (Item, error) {
	if len(request.QueryFunctions) == 0 {
		return Item{}, errs.Detail(ErrInvalidRequest, "Query requires at least one query function | Query 至少需要一个查询功能")
	}
	response := QueryResponse{VendorIdentification: "ydx"}
	for _, function := range request.QueryFunctions {
		switch function {
		case QueryFunctionOperations:
			response.Operations = SupportedOperations()
		case QueryFunctionObjects:
			response.ObjectTypes = supportedObjectTypes()
		case QueryFunctionServerInformation:
			response.ServerInformation = NewStructure(TagServerInformation,
				NewTextString(TagVendorIdentification, "ydx"),
			)
		case QueryFunctionApplicationNamespaces:
			response.ApplicationNamespaces = []string{"https://yun-dev.cn/kmip"}
		default:
			// Unknown query functions are simply not answered. | 未识别的查询功能直接忽略。
		}
	}
	return response.Item()
}

// handleDiscoverVersions implements Discover Versions. | handleDiscoverVersions 实现 Discover Versions。
func (s *Server) handleDiscoverVersions(request DiscoverVersionsRequest) (Item, error) {
	supported := SupportedProtocolVersions()
	if len(request.ProtocolVersions) == 0 {
		return DiscoverVersionsResponse{ProtocolVersions: supported}.Item()
	}
	common := make([]ProtocolVersion, 0, len(supported))
	for _, candidate := range supported {
		for _, requested := range request.ProtocolVersions {
			if candidate.Compare(requested) == 0 {
				common = append(common, candidate)
				break
			}
		}
	}
	return DiscoverVersionsResponse{ProtocolVersions: common}.Item()
}

// handleCheck implements Check. | handleCheck 实现 Check。
func (s *Server) handleCheck(request CheckRequest) (Item, error) {
	record, err := s.loadRecord(request.UniqueIdentifier)
	if err != nil {
		return Item{}, err
	}
	if request.UsageLimitsCount != nil {
		return Item{}, errs.Detail(ErrUnsupported, "usage limits are not tracked | 不跟踪使用次数限制")
	}
	if request.LeaseTime != nil {
		return Item{}, errs.Detail(ErrUnsupported, "lease time is not supported | 不支持租用时间")
	}
	if request.CryptographicUsageMask != 0 && !record.UsageMask.Has(request.CryptographicUsageMask) {
		return Item{}, errs.Detail(ErrUsageMask, "object usage mask does not contain %s | 对象用法掩码不包含 %s",
			request.CryptographicUsageMask, request.CryptographicUsageMask)
	}
	return CheckResponse{
		UniqueIdentifier:       record.UniqueIdentifier,
		CryptographicUsageMask: record.UsageMask,
	}.Item()
}

// loadRecord loads a record by unique identifier. | loadRecord 按唯一标识符加载记录。
func (s *Server) loadRecord(uniqueIdentifier string) (ObjectRecord, error) {
	if uniqueIdentifier == "" {
		return ObjectRecord{}, errs.Detail(ErrInvalidRequest, "missing unique identifier | 缺少唯一标识符")
	}
	return s.store.Get(s.ctx, uniqueIdentifier)
}

// loadActive loads a record and requires an active state and usage-mask bits. | loadActive 加载记录并要求活动状态与用法掩码位。
func (s *Server) loadActive(uniqueIdentifier string, mask CryptographicUsageMask) (ObjectRecord, error) {
	record, err := s.loadRecord(uniqueIdentifier)
	if err != nil {
		return ObjectRecord{}, err
	}
	if err := activeForUse(&record, s.now()); err != nil {
		return ObjectRecord{}, err
	}
	if mask != 0 && !record.UsageMask.Has(mask) {
		return ObjectRecord{}, errs.Detail(ErrUsageMask, "object %q usage mask does not allow %s | 对象 %q 的用法掩码不允许 %s",
			record.UniqueIdentifier, mask, record.UniqueIdentifier, mask)
	}
	return record, nil
}

// templateAlgorithmLength reads the cryptographic algorithm and length from templates. | templateAlgorithmLength
// 从模板读取密码算法与长度。
func templateAlgorithmLength(templates []TemplateAttribute) (CryptographicAlgorithm, int, error) {
	var algorithm CryptographicAlgorithm
	var length int
	for _, tmpl := range templates {
		if algorithm == 0 {
			if attr, ok := tmpl.Attributes.Lookup(AttributeCryptographicAlgorithm); ok {
				value, err := attributeUint32(attr)
				if err != nil {
					return 0, 0, err
				}
				algorithm = CryptographicAlgorithm(value)
			}
		}
		if length == 0 {
			if attr, ok := tmpl.Attributes.Lookup(AttributeCryptographicLength); ok {
				value, err := attributeInteger(attr)
				if err != nil {
					return 0, 0, err
				}
				length = int(value)
			}
		}
		for _, name := range tmpl.Names {
			_ = name
		}
	}
	if length < 0 {
		return 0, 0, errs.Detail(ErrInvalidRequest, "negative cryptographic length | 密码长度为负")
	}
	return algorithm, length, nil
}

// templateKeyFormat reads the requested Key Format Type from a template. A missing attribute returns zero. |
// templateKeyFormat 从模板读取请求的密钥格式类型；属性缺失时返回零。
func templateKeyFormat(templates []TemplateAttribute) (KeyFormatType, error) {
	for i := range templates {
		format, err := templateKeyFormatPair(nil, &templates[i])
		if err != nil {
			return 0, err
		}
		if format != 0 {
			return format, nil
		}
	}
	return 0, nil
}

// templateKeyFormatPair reads the requested Key Format Type, preferring the key-specific template over the common
// template. A missing attribute returns zero. | templateKeyFormatPair 读取请求的密钥格式类型，优先使用密钥专属模板；
// 属性缺失时返回零。
func templateKeyFormatPair(common, specific *TemplateAttribute) (KeyFormatType, error) {
	templates := []*TemplateAttribute{specific, common}
	for _, tmpl := range templates {
		if tmpl == nil {
			continue
		}
		attr, ok := tmpl.Attributes.Lookup(AttributeKeyFormatType)
		if !ok {
			continue
		}
		value, err := attributeUint32(attr)
		if err != nil {
			return 0, err
		}
		return KeyFormatType(value), nil
	}
	return 0, nil
}

// convertRequestedFormat converts a freshly generated key block into the requested format. Zero keeps the generated
// format. The source material is cleared after a successful conversion. | convertRequestedFormat 把新生成的密钥块转换为
// 请求的格式；零保留生成格式。转换成功后清除源材料。
func convertRequestedFormat(kb KeyBlock, format KeyFormatType) (KeyBlock, error) {
	if format == 0 || format == kb.Format {
		return kb, nil
	}
	converted, err := convertKeyBlockFormat(kb, format)
	if err != nil {
		return KeyBlock{}, err
	}
	zeroizeKeyBlock(&kb)
	return converted, nil
}

// attributeUint32 reads an enumeration or integer attribute value. | attributeUint32 读取枚举或整数属性值。
func attributeUint32(attr Attribute) (uint32, error) {
	switch attr.Value.Type {
	case TypeEnumeration:
		return attr.Value.AsEnumeration()
	case TypeInteger, TypeLongInteger:
		value, err := attr.Value.AsInteger()
		if err != nil {
			return 0, err
		}
		if value < 0 || value > 1<<32-1 {
			return 0, errs.Detail(ErrInvalidRequest, "attribute %q value %d is out of range | 属性 %q 的值 %d 超出范围", attr.Name, value, attr.Name, value)
		}
		return uint32(value), nil
	default:
		return 0, errs.Detail(ErrInvalidRequest, "attribute %q is not an enumeration | 属性 %q 不是枚举", attr.Name, attr.Name)
	}
}

// attributeInteger reads an integer attribute value. | attributeInteger 读取整数属性值。
func attributeInteger(attr Attribute) (int64, error) {
	switch attr.Value.Type {
	case TypeInteger, TypeLongInteger:
		return attr.Value.AsInteger()
	case TypeEnumeration:
		value, err := attr.Value.AsEnumeration()
		return int64(value), err
	default:
		return 0, errs.Detail(ErrInvalidRequest, "attribute %q is not an integer | 属性 %q 不是整数", attr.Name, attr.Name)
	}
}

// mergeTemplates concatenates two optional templates. | mergeTemplates 连接两个可选模板。
func mergeTemplates(first, second *TemplateAttribute) TemplateAttribute {
	var out TemplateAttribute
	if first != nil {
		out.Names = append(out.Names, first.Names...)
		out.Attributes = append(out.Attributes, first.Attributes...)
	}
	if second != nil {
		out.Names = append(out.Names, second.Names...)
		out.Attributes = append(out.Attributes, second.Attributes...)
	}
	return out
}

// objectWithKeyBlock builds an object of the given type around a key block. | objectWithKeyBlock 围绕密钥块构造指定类型的对象。
func objectWithKeyBlock(objectType ObjectType, source Object, kb KeyBlock) (Object, error) {
	switch objectType {
	case ObjectTypeSymmetricKey:
		return NewSymmetricKeyObject(kb), nil
	case ObjectTypePublicKey:
		return NewPublicKeyObject(kb), nil
	case ObjectTypePrivateKey:
		return NewPrivateKeyObject(kb), nil
	case ObjectTypeSecretData:
		secretType := SecretDataTypePassword
		if source.SecretData != nil && source.SecretData.SecretDataType != 0 {
			secretType = source.SecretData.SecretDataType
		}
		return NewSecretDataObject(secretType, kb), nil
	default:
		return Object{}, errs.Detail(ErrUnsupported, "object type %s has no key block | 对象类型 %s 没有密钥块", objectType, objectType)
	}
}
