package kms

import (
	"context"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/shibingli/ydx/errs"
)

// CreateKeyRequest describes a key to generate. | CreateKeyRequest 描述要生成的密钥。
type CreateKeyRequest struct {
	// ID is an optional caller-chosen identifier; empty generates a random one. | ID 是可选的自定义
	// 标识；为空时随机生成。
	ID string
	// Alias is an optional unique human-friendly name. | Alias 是可选且唯一的人类可读名称。
	Alias string
	// Type is the required key family. | Type 是必需的密钥族。
	Type KeyType
	// Bits is the key size; 0 selects the strongest supported default. | Bits 是密钥长度；0 选择支持的最强默认值。
	Bits int
	// Usage lists permitted operations; empty selects the type defaults. | Usage 列出允许的操作；空时使用类型默认值。
	Usage []KeyUsage
	// Metadata holds application-defined scalar attributes. | Metadata 保存应用自定义标量属性。
	Metadata map[string]string
	// Tags is a free-form label set used by list filters. | Tags 是供列表过滤使用的自由标签集合。
	Tags []string
	// ParentID links the key to a parent key. | ParentID 把密钥关联到父密钥。
	ParentID string
	// Exportable authorizes private export when the service policy also allows it. | Exportable 在服务策略也允许时授权私钥导出。
	Exportable bool
	// RotationInterval is the rotation recommendation; 0 uses Config.DefaultRotationInterval. | RotationInterval
	// 是轮换建议；0 使用 Config.DefaultRotationInterval。
	RotationInterval time.Duration
}

// ImportKeyRequest describes externally generated key material to import. | ImportKeyRequest 描述要导入的外部生成密钥材料。
type ImportKeyRequest struct {
	// CreateKeyRequest carries the identity, type, usage and metadata. | CreateKeyRequest 携带标识、类型、用途与元数据。
	CreateKeyRequest
	// Material is the private or symmetric material (PKCS#8/PEM for asymmetric keys, raw for
	// symmetric keys). It may be empty for a public-only verification key. | Material 是私钥或对称材料
	// （非对称密钥为 PKCS#8/PEM，对称密钥为原始字节）。仅公钥验签密钥可为空。
	Material []byte
	// PublicMaterial is the public half; it is derived from Material when empty. | PublicMaterial 是
	// 公钥部分；为空时从 Material 推导。
	PublicMaterial []byte
}

// UpdateKeyRequest describes mutable key metadata. | UpdateKeyRequest 描述可变密钥元数据。
//
// Nil fields leave the corresponding attribute unchanged; a non-nil empty Alias clears the alias. | nil
// 字段保持对应属性不变；指向空字符串的 Alias 会清除别名。
type UpdateKeyRequest struct {
	// Alias changes the unique alias. | Alias 修改唯一别名。
	Alias *string
	// Metadata replaces the metadata map when non-nil. | Metadata 非 nil 时替换元数据映射。
	Metadata map[string]string
	// Tags replaces the tag set when non-nil. | Tags 非 nil 时替换标签集合。
	Tags []string
	// RotationInterval changes the rotation recommendation when non-nil. | RotationInterval 非 nil 时修改轮换建议。
	RotationInterval *time.Duration
	// Exportable changes private-export authorization when non-nil. | Exportable 非 nil 时修改私钥导出授权。
	Exportable *bool
}

// CreateKey generates and stores a new key in StatePreActive. | CreateKey 生成并保存处于 StatePreActive
// 的新密钥。
//
// Callers must call Activate before cryptographic use. CreateKey audits key.create. | 调用方必须在
// 密码使用前调用 Activate。CreateKey 记录 key.create 审计。
func (s *Service) CreateKey(ctx context.Context, request CreateKeyRequest) (*Key, error) {
	now := s.Now()
	keyID, err := s.prepareID(request.ID)
	if err != nil {
		s.fail(ctx, OperationKeyCreate, request.ID, 0, err)
		return nil, err
	}
	if err := validateAlias(request.Alias); err != nil {
		s.fail(ctx, OperationKeyCreate, keyID, 0, err)
		return nil, err
	}
	if request.Type == "" {
		err := errs.Detail(ErrInvalidKeyType, "key type is required | 必须提供密钥类型")
		s.fail(ctx, OperationKeyCreate, keyID, 0, err)
		return nil, err
	}
	mask, err := filterUsages(request.Type, request.Usage)
	if err != nil {
		s.fail(ctx, OperationKeyCreate, keyID, 0, err)
		return nil, err
	}
	private, public, algorithm, bits, err := generateMaterial(request.Type, request.Bits)
	if err != nil {
		s.fail(ctx, OperationKeyCreate, keyID, 0, err)
		return nil, err
	}
	defer zeroBytes(private)
	rotation := request.RotationInterval
	if rotation == 0 {
		rotation = s.defaultRotation
	}
	if rotation < 0 {
		err := errs.Detail(ErrInvalidRequest, "negative rotation interval | 轮换间隔为负")
		s.fail(ctx, OperationKeyCreate, keyID, 0, err)
		return nil, err
	}
	key := &Key{
		ID:               keyID,
		Alias:            request.Alias,
		Type:             request.Type,
		Algorithm:        algorithm,
		Bits:             bits,
		Version:          1,
		State:            StatePreActive,
		UsageMask:        mask,
		CreatedAt:        now,
		RotationInterval: rotation,
		Material:         append([]byte(nil), private...),
		PublicMaterial:   append([]byte(nil), public...),
		Metadata:         copyMetadata(request.Metadata),
		Tags:             uniqueTags(request.Tags),
		ParentID:         request.ParentID,
		Exportable:       request.Exportable,
		Revision:         1,
		Versions: []*KeyVersion{{
			Version:        1,
			State:          StateActive,
			Material:       append([]byte(nil), private...),
			PublicMaterial: append([]byte(nil), public...),
			CreatedAt:      now,
		}},
	}
	stored, err := s.persistKey(ctx, key)
	if err != nil {
		s.fail(ctx, OperationKeyCreate, keyID, 0, err)
		return nil, err
	}
	if err := s.store.CreateKey(ctx, stored); err != nil {
		s.fail(ctx, OperationKeyCreate, keyID, 0, err)
		return nil, err
	}
	s.succeed(ctx, OperationKeyCreate, key.ID, key.Version, map[string]string{
		"type":       string(key.Type),
		"algorithm":  key.Algorithm,
		"bits":       strconvUint32(uint32(key.Bits)),
		"exportable": boolLabel(key.Exportable),
	})
	return key.PublicView(), nil
}

// ImportKey stores externally generated material in StatePreActive. | ImportKey 把外部生成的材料
// 保存为 StatePreActive。
//
// For asymmetric keys Material is PKCS#8 DER (or SM2 PEM) and PublicMaterial is PKIX DER (or SM2
// PEM); a public-only key may omit Material and receives only UsageVerify. The operation is audited
// as key.import. | 非对称密钥的 Material 为 PKCS#8 DER（或 SM2 PEM），PublicMaterial 为 PKIX DER
// （或 SM2 PEM）；仅公钥密钥可省略 Material，并只获得 UsageVerify。该操作以 key.import 写入审计。
func (s *Service) ImportKey(ctx context.Context, request ImportKeyRequest) (*Key, error) {
	now := s.Now()
	keyID, err := s.prepareID(request.ID)
	if err != nil {
		s.fail(ctx, OperationKeyImport, request.ID, 0, err)
		return nil, err
	}
	if err := validateAlias(request.Alias); err != nil {
		s.fail(ctx, OperationKeyImport, keyID, 0, err)
		return nil, err
	}
	if request.Type == "" {
		err := errs.Detail(ErrInvalidKeyType, "key type is required | 必须提供密钥类型")
		s.fail(ctx, OperationKeyImport, keyID, 0, err)
		return nil, err
	}
	private, public, bits, err := ValidateMaterial(request.Type, request.Bits, request.Material, request.PublicMaterial)
	if err != nil {
		s.fail(ctx, OperationKeyImport, keyID, 0, err)
		return nil, err
	}
	defer zeroBytes(private)
	var mask UsageMask
	if len(private) == 0 {
		if isSymmetricType(request.Type) {
			err := errs.Detail(ErrInvalidMaterial, "symmetric import requires private material | 对称密钥导入需要私钥材料")
			s.fail(ctx, OperationKeyImport, keyID, 0, err)
			return nil, err
		}
		if len(request.Usage) == 0 {
			mask = MaskVerify
		} else {
			requested, filterErr := filterUsages(request.Type, request.Usage)
			if filterErr != nil {
				s.fail(ctx, OperationKeyImport, keyID, 0, filterErr)
				return nil, filterErr
			}
			if requested&^MaskVerify != 0 {
				err := errs.Detail(ErrUsageNotAllowed, "public-only key supports only verify | 仅公钥密钥只支持验签")
				s.fail(ctx, OperationKeyImport, keyID, 0, err)
				return nil, err
			}
			mask = requested
		}
	} else {
		mask, err = filterUsages(request.Type, request.Usage)
		if err != nil {
			s.fail(ctx, OperationKeyImport, keyID, 0, err)
			return nil, err
		}
	}
	rotation := request.RotationInterval
	if rotation == 0 {
		rotation = s.defaultRotation
	}
	if rotation < 0 {
		err := errs.Detail(ErrInvalidRequest, "negative rotation interval | 轮换间隔为负")
		s.fail(ctx, OperationKeyImport, keyID, 0, err)
		return nil, err
	}
	key := &Key{
		ID:               keyID,
		Alias:            request.Alias,
		Type:             request.Type,
		Algorithm:        algorithmFor(request.Type, bits),
		Bits:             bits,
		Version:          1,
		State:            StatePreActive,
		UsageMask:        mask,
		CreatedAt:        now,
		RotationInterval: rotation,
		Material:         append([]byte(nil), private...),
		PublicMaterial:   append([]byte(nil), public...),
		Metadata:         copyMetadata(request.Metadata),
		Tags:             uniqueTags(request.Tags),
		ParentID:         request.ParentID,
		Exportable:       request.Exportable,
		Revision:         1,
		Versions: []*KeyVersion{{
			Version:        1,
			State:          StateActive,
			Material:       append([]byte(nil), private...),
			PublicMaterial: append([]byte(nil), public...),
			CreatedAt:      now,
		}},
	}
	stored, err := s.persistKey(ctx, key)
	if err != nil {
		s.fail(ctx, OperationKeyImport, keyID, 0, err)
		return nil, err
	}
	if err := s.store.CreateKey(ctx, stored); err != nil {
		s.fail(ctx, OperationKeyImport, keyID, 0, err)
		return nil, err
	}
	s.succeed(ctx, OperationKeyImport, key.ID, key.Version, map[string]string{
		"type":      string(key.Type),
		"algorithm": key.Algorithm,
		"bits":      strconvUint32(uint32(key.Bits)),
	})
	return key.PublicView(), nil
}

// GetKey returns a material-safe view of a key. | GetKey 返回密钥的材料安全视图。
func (s *Service) GetKey(ctx context.Context, id string) (*Key, error) {
	return s.keys.Get(ctx, id)
}

// ListKeys returns material-safe views of the matching keys. | ListKeys 返回匹配密钥的材料安全视图。
func (s *Service) ListKeys(ctx context.Context, filter KeyFilter) ([]*Key, error) {
	return s.keys.List(ctx, filter)
}

// Resolve resolves an identifier or alias to a material-safe key view. | Resolve 把标识或别名解析为
// 材料安全密钥视图。
func (s *Service) Resolve(ctx context.Context, aliasOrID string) (*Key, error) {
	return s.keys.Resolve(ctx, aliasOrID)
}

// ListVersions returns material-safe views of every retained version, ascending. | ListVersions 按
// 升序返回保留的全部版本的材料安全视图。
func (s *Service) ListVersions(ctx context.Context, id string) ([]*KeyVersion, error) {
	key, err := resolveStoredKey(ctx, s.store, id)
	if err != nil {
		return nil, err
	}
	out := make([]*KeyVersion, 0, len(key.Versions))
	for _, version := range key.Versions {
		if version == nil {
			continue
		}
		view := version.Clone()
		zeroBytes(view.Material)
		view.Material = nil
		out = append(out, view)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

// ListAudit returns audit events matching filter. | ListAudit 返回匹配 filter 的审计事件。
func (s *Service) ListAudit(ctx context.Context, filter AuditFilter) ([]*AuditEvent, error) {
	if s == nil || s.audit == nil {
		return nil, ErrStoreUnavailable
	}
	return s.audit.ListAudit(ctx, filter)
}

// UpdateKey mutates alias, metadata, tags, rotation interval or exportability. | UpdateKey 修改别名、
// 元数据、标签、轮换间隔或可导出性。
//
// It uses optimistic concurrency internally and retries a bounded number of conflicts. It never
// touches key material, so at-rest wrapping is preserved. The operation is audited. | 它内部使用乐观
// 并发并在有限次数内重试冲突。它绝不触碰密钥材料，因此静态包装保持不变。该操作会写入审计。
func (s *Service) UpdateKey(ctx context.Context, id string, request UpdateKeyRequest) (*Key, error) {
	if request.Alias != nil {
		if err := validateAlias(*request.Alias); err != nil {
			s.fail(ctx, OperationKeyUpdate, id, 0, err)
			return nil, err
		}
	}
	if request.RotationInterval != nil && *request.RotationInterval < 0 {
		err := errs.Detail(ErrInvalidRequest, "negative rotation interval | 轮换间隔为负")
		s.fail(ctx, OperationKeyUpdate, id, 0, err)
		return nil, err
	}
	updated, err := s.mutateStoredKey(ctx, id, func(key *Key) error {
		if request.Alias != nil {
			key.Alias = *request.Alias
		}
		if request.Metadata != nil {
			key.Metadata = copyMetadata(request.Metadata)
		}
		if request.Tags != nil {
			key.Tags = uniqueTags(request.Tags)
		}
		if request.RotationInterval != nil {
			key.RotationInterval = *request.RotationInterval
		}
		if request.Exportable != nil {
			key.Exportable = *request.Exportable
		}
		return nil
	})
	if err != nil {
		s.fail(ctx, OperationKeyUpdate, id, 0, err)
		return nil, err
	}
	s.succeed(ctx, OperationKeyUpdate, updated.ID, updated.Version, map[string]string{"revision": strconvUint32(uint32(updated.Revision))})
	return updated.PublicView(), nil
}

// mutateStoredKey loads the stored key, applies mutate and persists it with optimistic concurrency. | mutateStoredKey
// 加载存储密钥、应用 mutate 并以乐观并发持久化。
func (s *Service) mutateStoredKey(ctx context.Context, id string, mutate func(*Key) error) (*Key, error) {
	if s == nil || s.store == nil {
		return nil, ErrStoreUnavailable
	}
	target := id
	for attempt := 0; attempt < mutationRetries; attempt++ {
		key, err := resolveStoredKey(ctx, s.store, target)
		if err != nil {
			return nil, err
		}
		target = key.ID
		if err := mutate(key); err != nil {
			return nil, err
		}
		revision := key.Revision
		if err := s.store.UpdateKey(ctx, key); err != nil {
			if errorsIs(err, ErrConflict) {
				continue
			}
			return nil, err
		}
		key.Revision = revision + 1
		return key, nil
	}
	return nil, errs.Detail(ErrConflict, "key %[1]q changed repeatedly | 密钥 %[1]q 反复变更", target)
}

// prepareID validates a caller identifier or generates one. | prepareID 校验调用方标识或生成一个。
func (s *Service) prepareID(id string) (string, error) {
	if id == "" {
		generated, err := randomID()
		if err != nil {
			return "", err
		}
		return generated, nil
	}
	if err := validateKeyID(id); err != nil {
		return "", err
	}
	return id, nil
}

// validateKeyID checks the identifier alphabet and length. | validateKeyID 校验标识字符集与长度。
func validateKeyID(id string) error {
	if len(id) == 0 || len(id) > maxKeyIDLength {
		return errs.Detail(ErrInvalidRequest, "key id length %[1]d outside 1..%[2]d | 密钥 ID 长度 %[1]d 超出 1..%[2]d", len(id), maxKeyIDLength)
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-', c == '_', c == '.', c == ':', c == '@', c == '+':
		default:
			return errs.Detail(ErrInvalidRequest, "key id contains unsupported byte %[1]q | 密钥 ID 含不支持的字节 %[1]q", c)
		}
	}
	return nil
}

// validateAlias checks alias length and rejects control characters. | validateAlias 校验别名长度并拒绝控制字符。
func validateAlias(alias string) error {
	if alias == "" {
		return nil
	}
	if len(alias) > maxAliasLength || !utf8.ValidString(alias) {
		return errs.Detail(ErrInvalidRequest, "alias length or encoding is invalid | 别名长度或编码非法")
	}
	for _, r := range alias {
		if r < 0x20 || r == 0x7f {
			return errs.Detail(ErrInvalidRequest, "alias contains control characters | 别名包含控制字符")
		}
	}
	return nil
}

// copyMetadata returns a deep copy of metadata. | copyMetadata 返回 metadata 的深拷贝。
func copyMetadata(metadata map[string]string) map[string]string {
	if len(metadata) == 0 {
		return nil
	}
	out := make(map[string]string, len(metadata))
	for key, value := range metadata {
		out[key] = value
	}
	return out
}

// uniqueTags returns sorted, de-duplicated, non-empty tags. | uniqueTags 返回排序、去重、非空的标签。
func uniqueTags(tags []string) []string {
	if len(tags) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(tags))
	out := make([]string, 0, len(tags))
	for _, tag := range tags {
		if tag == "" {
			continue
		}
		if _, ok := seen[tag]; ok {
			continue
		}
		seen[tag] = struct{}{}
		out = append(out, tag)
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return out
}

// algorithmFor labels imported material. | algorithmFor 为导入材料生成算法标签。
func algorithmFor(keyType KeyType, bits int) string {
	switch keyType {
	case KeyTypeAES:
		return aesAlgorithm(bits, "GCM")
	case KeyTypeChaCha20:
		return "ChaCha20-Poly1305"
	case KeyTypeSM4:
		return "SM4-GCM"
	case KeyTypeRSA:
		return "RSA"
	case KeyTypeECDSA:
		return "ECDSA-P" + strconvUint32(uint32(bits))
	case KeyTypeEd25519:
		return "Ed25519"
	case KeyTypeSM2:
		return "SM2"
	default:
		return ""
	}
}

// isSymmetricType reports whether keyType is symmetric. | isSymmetricType 报告 keyType 是否为对称类型。
func isSymmetricType(keyType KeyType) bool {
	switch keyType {
	case KeyTypeAES, KeyTypeChaCha20, KeyTypeSM4:
		return true
	default:
		return false
	}
}

// boolLabel formats a boolean for audit detail. | boolLabel 为审计详情格式化布尔值。
func boolLabel(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

// wrapForStorage wraps one version of fresh material for persistence. | wrapForStorage 包装要持久化的
// 某一版本新材料。
func (s *Service) wrapForStorage(ctx context.Context, keyID string, version uint32, material []byte) ([]byte, error) {
	if len(material) == 0 {
		return nil, nil
	}
	if s.wrapper == nil {
		return append([]byte(nil), material...), nil
	}
	wrapped, err := s.wrapper.Wrap(ctx, keyID, version, material)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidMaterial, "wrap key material | 包装密钥材料")
	}
	return wrapped, nil
}

// mutationRetries bounds optimistic-concurrency retries for metadata mutations. | mutationRetries
// 限制元数据变更的乐观并发重试次数。
const mutationRetries = 4
