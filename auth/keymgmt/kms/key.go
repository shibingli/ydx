package kms

import (
	"sort"
	"time"

	"github.com/shibingli/ydx/errs"
)

// KeyState is the NIST SP 800-57 lifecycle state of a key or key version. | KeyState 是密钥或密钥
// 版本的 NIST SP 800-57 生命周期状态。
type KeyState string

// The lifecycle states defined by NIST SP 800-57 Part 1. | NIST SP 800-57 第 1 部分定义的生命周期状态。
const (
	// StatePreActive is a generated key that is not yet authorized for use. | StatePreActive 表示已生成但尚未授权使用的密钥。
	StatePreActive KeyState = "pre-active"
	// StateActive is a key authorized for its declared usages. | StateActive 表示已授权执行其声明用途的密钥。
	StateActive KeyState = "active"
	// StateDeactivated is a key no longer used for new protection but still usable for legacy
	// decryption and verification. | StateDeactivated 表示不再用于新的保护、但仍可用于历史解密与验签的密钥。
	StateDeactivated KeyState = "deactivated"
	// StateCompromised is a key whose secrecy or integrity is suspect; every use is refused. | StateCompromised 表示保密性或完整性可疑的密钥；一切使用都会被拒绝。
	StateCompromised KeyState = "compromised"
	// StateDestroyed is a key whose material has been erased; only metadata survives. | StateDestroyed 表示材料已擦除、仅保留元数据的密钥。
	StateDestroyed KeyState = "destroyed"
	// StatePendingDeletion is a key scheduled for destruction after DeleteAfter. | StatePendingDeletion 表示计划在 DeleteAfter 之后销毁的密钥。
	StatePendingDeletion KeyState = "pending-deletion"
)

// KeyUsage names one permitted cryptographic operation. | KeyUsage 命名一种允许的密码操作。
type KeyUsage string

// The key usages tracked by UsageMask. | UsageMask 跟踪的密钥用途。
const (
	// UsageEncrypt permits symmetric encryption. | UsageEncrypt 允许对称加密。
	UsageEncrypt KeyUsage = "encrypt"
	// UsageDecrypt permits symmetric decryption. | UsageDecrypt 允许对称解密。
	UsageDecrypt KeyUsage = "decrypt"
	// UsageSign permits digital signature generation. | UsageSign 允许生成数字签名。
	UsageSign KeyUsage = "sign"
	// UsageVerify permits digital signature verification. | UsageVerify 允许校验数字签名。
	UsageVerify KeyUsage = "verify"
	// UsageWrapKey permits wrapping another key. | UsageWrapKey 允许包装其它密钥。
	UsageWrapKey KeyUsage = "wrap-key"
	// UsageUnwrapKey permits unwrapping another key. | UsageUnwrapKey 允许解包其它密钥。
	UsageUnwrapKey KeyUsage = "unwrap-key"
	// UsageDeriveKey permits HKDF-based key derivation. | UsageDeriveKey 允许基于 HKDF 的密钥派生。
	UsageDeriveKey KeyUsage = "derive-key"
	// UsageGenerateDataKey permits data-key generation. | UsageGenerateDataKey 允许生成数据密钥。
	UsageGenerateDataKey KeyUsage = "generate-data-key"
)

// UsageMask is a bitset of KeyUsage values stored on a Key. | UsageMask 是保存在 Key 上的
// KeyUsage 位集。
type UsageMask uint32

// The bits of UsageMask. | UsageMask 的位定义。
const (
	// MaskEncrypt is the UsageEncrypt bit. | MaskEncrypt 是 UsageEncrypt 对应的位。
	MaskEncrypt UsageMask = 1 << iota
	// MaskDecrypt is the UsageDecrypt bit. | MaskDecrypt 是 UsageDecrypt 对应的位。
	MaskDecrypt
	// MaskSign is the UsageSign bit. | MaskSign 是 UsageSign 对应的位。
	MaskSign
	// MaskVerify is the UsageVerify bit. | MaskVerify 是 UsageVerify 对应的位。
	MaskVerify
	// MaskWrapKey is the UsageWrapKey bit. | MaskWrapKey 是 UsageWrapKey 对应的位。
	MaskWrapKey
	// MaskUnwrapKey is the UsageUnwrapKey bit. | MaskUnwrapKey 是 UsageUnwrapKey 对应的位。
	MaskUnwrapKey
	// MaskDeriveKey is the UsageDeriveKey bit. | MaskDeriveKey 是 UsageDeriveKey 对应的位。
	MaskDeriveKey
	// MaskGenerateDataKey is the UsageGenerateDataKey bit. | MaskGenerateDataKey 是 UsageGenerateDataKey 对应的位。
	MaskGenerateDataKey
)

// usageBits maps each usage to its bit, in declaration order. | usageBits 按声明顺序把用途映射到位。
var usageBits = []struct {
	usage KeyUsage
	bit   UsageMask
}{
	{UsageEncrypt, MaskEncrypt},
	{UsageDecrypt, MaskDecrypt},
	{UsageSign, MaskSign},
	{UsageVerify, MaskVerify},
	{UsageWrapKey, MaskWrapKey},
	{UsageUnwrapKey, MaskUnwrapKey},
	{UsageDeriveKey, MaskDeriveKey},
	{UsageGenerateDataKey, MaskGenerateDataKey},
}

// UsageMaskOf builds a mask from usages, ignoring unknown values. | UsageMaskOf 由用途构造掩码，忽略未知值。
func UsageMaskOf(usages ...KeyUsage) UsageMask {
	var mask UsageMask
	for _, usage := range usages {
		for _, entry := range usageBits {
			if entry.usage == usage {
				mask |= entry.bit
				break
			}
		}
	}
	return mask
}

// Has reports whether m contains usage. | Has 报告 m 是否包含 usage。
func (m UsageMask) Has(usage KeyUsage) bool {
	for _, entry := range usageBits {
		if entry.usage == usage {
			return m&entry.bit != 0
		}
	}
	return false
}

// Usages returns the usages present in m, in declaration order. | Usages 按声明顺序返回 m 中包含的用途。
func (m UsageMask) Usages() []KeyUsage {
	out := make([]KeyUsage, 0, len(usageBits))
	for _, entry := range usageBits {
		if m&entry.bit != 0 {
			out = append(out, entry.usage)
		}
	}
	return out
}

// Add returns m with usage enabled. | Add 返回启用 usage 后的 m。
func (m UsageMask) Add(usage KeyUsage) UsageMask {
	for _, entry := range usageBits {
		if entry.usage == usage {
			return m | entry.bit
		}
	}
	return m
}

// Remove returns m with usage disabled. | Remove 返回禁用 usage 后的 m。
func (m UsageMask) Remove(usage KeyUsage) UsageMask {
	for _, entry := range usageBits {
		if entry.usage == usage {
			return m &^ entry.bit
		}
	}
	return m
}

// KeyType names a cryptographic key family. | KeyType 命名一种密码密钥族。
type KeyType string

// The supported key types. | 支持的密钥类型。
const (
	// KeyTypeAES is an AES symmetric key used with GCM. | KeyTypeAES 是配合 GCM 使用的 AES 对称密钥。
	KeyTypeAES KeyType = "AES"
	// KeyTypeChaCha20 is a ChaCha20-Poly1305 symmetric key. | KeyTypeChaCha20 是 ChaCha20-Poly1305 对称密钥。
	KeyTypeChaCha20 KeyType = "ChaCha20"
	// KeyTypeRSA is an RSA key pair used with PKCS#1 v1.5 or PSS signatures. | KeyTypeRSA 是用于 PKCS#1 v1.5 或 PSS 签名的 RSA 密钥对。
	KeyTypeRSA KeyType = "RSA"
	// KeyTypeECDSA is an ECDSA key pair over NIST P-256/P-384/P-521. | KeyTypeECDSA 是 NIST P-256/P-384/P-521 上的 ECDSA 密钥对。
	KeyTypeECDSA KeyType = "ECDSA"
	// KeyTypeEd25519 is an Ed25519 key pair. | KeyTypeEd25519 是 Ed25519 密钥对。
	KeyTypeEd25519 KeyType = "Ed25519"
	// KeyTypeSM2 is a Chinese SM2 key pair. | KeyTypeSM2 是国密 SM2 密钥对。
	KeyTypeSM2 KeyType = "SM2"
	// KeyTypeSM4 is a Chinese SM4 symmetric key used with GCM. | KeyTypeSM4 是配合 GCM 使用的国密 SM4 对称密钥。
	KeyTypeSM4 KeyType = "SM4"
)

// Key is the canonical metadata and material record of a managed key. | Key 是受管密钥的规范元数据与材料记录。
//
// Material holds the private half (or the symmetric value) and is never serialized: the JSON tag is
// "-". PublicMaterial holds the PKIX DER or PEM public half for asymmetric keys and is empty for
// symmetric keys. Service.GetKey and KeyStore.Get strip Material from the returned copies. | Material
// 保存私钥部分（或对称密钥值），永不序列化：JSON 标签为 "-"。PublicMaterial 保存非对称密钥的
// PKIX DER 或 PEM 公钥部分，对称密钥为空。Service.GetKey 与 KeyStore.Get 会从返回副本中剥离 Material。
type Key struct {
	// ID is the immutable internal identifier. | ID 是不可变的内部标识。
	ID string `json:"id"`
	// Alias is the optional unique human-friendly name. | Alias 是可选的唯一人类可读名称。
	Alias string `json:"alias,omitempty"`
	// Type is the key family. | Type 是密钥族。
	Type KeyType `json:"type"`
	// Algorithm is the algorithm label, for example "AES-GCM" or "ES256". | Algorithm 是算法标签，例如 "AES-GCM" 或 "ES256"。
	Algorithm string `json:"algorithm,omitempty"`
	// Bits is the key size in bits; for RSA it is the modulus size. | Bits 是密钥位数；RSA 为模数长度。
	Bits int `json:"bits,omitempty"`
	// Version is the current (newest) key version number. | Version 是当前（最新）密钥版本号。
	Version uint32 `json:"version"`
	// State is the lifecycle state. | State 是生命周期状态。
	State KeyState `json:"state"`
	// UsageMask is the set of permitted operations. | UsageMask 是允许的操作集合。
	UsageMask UsageMask `json:"usageMask"`
	// CreatedAt is the UTC creation time. | CreatedAt 是 UTC 创建时间。
	CreatedAt time.Time `json:"createdAt"`
	// ActivatedAt is the UTC time the key entered the active state. | ActivatedAt 是密钥进入活动状态的 UTC 时间。
	ActivatedAt time.Time `json:"activatedAt,omitempty"`
	// DeactivatedAt is the UTC time the key entered the deactivated state. | DeactivatedAt 是密钥进入停用状态的 UTC 时间。
	DeactivatedAt time.Time `json:"deactivatedAt,omitempty"`
	// CompromisedAt is the UTC time the key was marked compromised. | CompromisedAt 是密钥被标记为泄露的 UTC 时间。
	CompromisedAt time.Time `json:"compromisedAt,omitempty"`
	// DestroyedAt is the UTC time the key material was erased. | DestroyedAt 是密钥材料被擦除的 UTC 时间。
	DestroyedAt time.Time `json:"destroyedAt,omitempty"`
	// DeleteAfter is the destruction deadline set by ScheduleDelete. | DeleteAfter 是 ScheduleDelete 设置的销毁期限。
	DeleteAfter time.Time `json:"deleteAfter,omitempty"`
	// RotationInterval is a rotation recommendation; RotateAllDue enforces it. | RotationInterval 是轮换建议；RotateAllDue 会据此执行。
	RotationInterval time.Duration `json:"rotationInterval,omitempty"`
	// Material is the private or symmetric key material and is never serialized. | Material 是私钥或对称密钥材料，永不序列化。
	Material []byte `json:"-"`
	// PublicMaterial is the public half of an asymmetric key, if any. | PublicMaterial 是非对称密钥的公钥部分（如有）。
	PublicMaterial []byte `json:"publicMaterial,omitempty"`
	// Metadata holds application-defined scalar attributes. | Metadata 保存应用自定义的标量属性。
	Metadata map[string]string `json:"metadata,omitempty"`
	// Tags is a free-form label set used by list filters. | Tags 是供列表过滤使用的自由标签集合。
	Tags []string `json:"tags,omitempty"`
	// ParentID links a derived or wrapped key to its parent. | ParentID 把派生或包装的密钥关联到父密钥。
	ParentID string `json:"parentId,omitempty"`
	// Versions holds every retained version, newest last. | Versions 保存保留的全部版本，最新在末尾。
	Versions []*KeyVersion `json:"versions,omitempty"`
	// Exportable authorizes private export when the service policy also allows it. | Exportable 在服务策略也允许时授权私钥导出。
	Exportable bool `json:"exportable,omitempty"`
	// Revision is the optimistic-concurrency revision, incremented by every store update. | Revision 是乐观并发修订号，每次存储更新递增。
	Revision uint64 `json:"revision,omitempty"`
}

// KeyVersion is one generation of a key. | KeyVersion 是密钥的一代材料。
type KeyVersion struct {
	// Version is the sequential version number. | Version 是顺序版本号。
	Version uint32 `json:"version"`
	// State is the lifecycle state of this version. | State 是该版本的生命周期状态。
	State KeyState `json:"state"`
	// Material is the private or symmetric material and is never serialized. | Material 是私钥或对称密钥材料，永不序列化。
	Material []byte `json:"-"`
	// PublicMaterial is the public half, if any. | PublicMaterial 是公钥部分（如有）。
	PublicMaterial []byte `json:"publicMaterial,omitempty"`
	// CreatedAt is the UTC creation time of this version. | CreatedAt 是该版本的 UTC 创建时间。
	CreatedAt time.Time `json:"createdAt"`
	// ActivatedAt is the UTC time this version entered the active state. | ActivatedAt 是该版本进入活动状态的 UTC 时间。
	ActivatedAt time.Time `json:"activatedAt,omitempty"`
	// DeactivatedAt is the UTC time this version entered the deactivated state. | DeactivatedAt 是该版本进入停用状态的 UTC 时间。
	DeactivatedAt time.Time `json:"deactivatedAt,omitempty"`
	// DestroyedAt is the UTC time this version's material was erased. | DestroyedAt 是该版本材料被擦除的 UTC 时间。
	DestroyedAt time.Time `json:"destroyedAt,omitempty"`
}

// Clone returns a deep copy of k. | Clone 返回 k 的深拷贝。
func (k *Key) Clone() *Key {
	if k == nil {
		return nil
	}
	c := *k
	c.Material = append([]byte(nil), k.Material...)
	c.PublicMaterial = append([]byte(nil), k.PublicMaterial...)
	c.Tags = append([]string(nil), k.Tags...)
	if len(k.Metadata) > 0 {
		c.Metadata = make(map[string]string, len(k.Metadata))
		for key, value := range k.Metadata {
			c.Metadata[key] = value
		}
	}
	if len(k.Versions) > 0 {
		c.Versions = make([]*KeyVersion, len(k.Versions))
		for i, version := range k.Versions {
			c.Versions[i] = version.Clone()
		}
	}
	return &c
}

// Clone returns a deep copy of v. | Clone 返回 v 的深拷贝。
func (v *KeyVersion) Clone() *KeyVersion {
	if v == nil {
		return nil
	}
	c := *v
	c.Material = append([]byte(nil), v.Material...)
	c.PublicMaterial = append([]byte(nil), v.PublicMaterial...)
	return &c
}

// HasUsage reports whether k permits usage. | HasUsage 报告 k 是否允许 usage。
func (k *Key) HasUsage(usage KeyUsage) bool {
	return k != nil && k.UsageMask.Has(usage)
}

// IsSymmetric reports whether k is a symmetric key family. | IsSymmetric 报告 k 是否为对称密钥族。
func (k *Key) IsSymmetric() bool {
	if k == nil {
		return false
	}
	switch k.Type {
	case KeyTypeAES, KeyTypeChaCha20, KeyTypeSM4:
		return true
	default:
		return false
	}
}

// IsSigning reports whether k is an asymmetric signing key family. | IsSigning 报告 k 是否为非对称签名密钥族。
func (k *Key) IsSigning() bool {
	if k == nil {
		return false
	}
	switch k.Type {
	case KeyTypeRSA, KeyTypeECDSA, KeyTypeEd25519, KeyTypeSM2:
		return true
	default:
		return false
	}
}

// CurrentVersion returns the version whose number equals k.Version, or nil. | CurrentVersion 返回编号等于 k.Version 的版本，缺失时返回 nil。
func (k *Key) CurrentVersion() *KeyVersion {
	if k == nil {
		return nil
	}
	for _, version := range k.Versions {
		if version != nil && version.Version == k.Version {
			return version
		}
	}
	return nil
}

// VersionAt returns the version with the given number, or nil. | VersionAt 返回指定编号的版本，缺失时返回 nil。
func (k *Key) VersionAt(number uint32) *KeyVersion {
	if k == nil {
		return nil
	}
	for _, version := range k.Versions {
		if version != nil && version.Version == number {
			return version
		}
	}
	return nil
}

// MaxVersion returns the highest version number present, or 0. | MaxVersion 返回存在的最高版本号，缺失时返回 0。
func (k *Key) MaxVersion() uint32 {
	if k == nil {
		return 0
	}
	var max uint32
	for _, version := range k.Versions {
		if version != nil && version.Version > max {
			max = version.Version
		}
	}
	if k.Version > max {
		max = k.Version
	}
	return max
}

// PublicView returns a deep copy with all private material removed. | PublicView 返回移除全部私钥材料的深拷贝。
//
// PublicMaterial is retained, because it is not secret. | 保留 PublicMaterial，因为它并非机密。
func (k *Key) PublicView() *Key {
	if k == nil {
		return nil
	}
	c := k.Clone()
	zeroBytes(c.Material)
	c.Material = nil
	for _, version := range c.Versions {
		if version == nil {
			continue
		}
		zeroBytes(version.Material)
		version.Material = nil
	}
	return c
}

// MetadataView returns a deep copy without private material, public material or version material. | MetadataView
// 返回移除私钥材料、公钥材料与版本材料的深拷贝。
func (k *Key) MetadataView() *Key {
	c := k.PublicView()
	if c == nil {
		return nil
	}
	c.PublicMaterial = nil
	for _, version := range c.Versions {
		if version == nil {
			continue
		}
		version.PublicMaterial = nil
	}
	return c
}

// Transition moves k to state to at time at, enforcing the NIST SP 800-57 transition graph. | Transition
// 在 at 时刻把 k 迁移到状态 to，并强制 NIST SP 800-57 的状态转换图。
//
// The transition graph is: pre-active → active/deactivated/compromised/pending-deletion;
// active → deactivated/compromised/pending-deletion; deactivated → compromised/destroyed/
// pending-deletion; compromised → destroyed/pending-deletion; pending-deletion → destroyed.
// Destroyed is terminal. A same-state transition returns ErrInvalidState. Destroying a key erases
// its material and the material of every version. | 转换图为：pre-active → active/deactivated/
// compromised/pending-deletion；active → deactivated/compromised/pending-deletion；deactivated →
// compromised/destroyed/pending-deletion；compromised → destroyed/pending-deletion；
// pending-deletion → destroyed。destroyed 为终态。同态转换返回 ErrInvalidState。销毁会擦除密钥
// 及其全部版本的材料。
func (k *Key) Transition(to KeyState, at time.Time) error {
	if k == nil {
		return ErrNotFound
	}
	if at.IsZero() {
		at = time.Now().UTC()
	} else {
		at = at.UTC()
	}
	current := k.State
	switch to {
	case StateActive:
		if current != StatePreActive {
			return invalidTransition(current, to)
		}
		k.State = StateActive
		k.ActivatedAt = at
	case StateDeactivated:
		if current != StateActive && current != StatePreActive {
			return invalidTransition(current, to)
		}
		k.State = StateDeactivated
		k.DeactivatedAt = at
	case StateCompromised:
		if current != StatePreActive && current != StateActive && current != StateDeactivated {
			return invalidTransition(current, to)
		}
		k.State = StateCompromised
		k.CompromisedAt = at
	case StatePendingDeletion:
		if current != StatePreActive && current != StateActive && current != StateDeactivated && current != StateCompromised {
			return invalidTransition(current, to)
		}
		k.State = StatePendingDeletion
		k.DeleteAfter = at
	case StateDestroyed:
		if current != StatePreActive && current != StateDeactivated && current != StateCompromised && current != StatePendingDeletion {
			return invalidTransition(current, to)
		}
		k.State = StateDestroyed
		k.DestroyedAt = at
		k.eraseMaterial()
	default:
		return errs.Detail(ErrInvalidState, "unknown target state %[1]q | 未知目标状态 %[1]q", to)
	}
	return nil
}

// CanTransition reports whether Transition(to, now) would succeed. | CanTransition 报告 Transition(to, now) 是否会成功。
func (k *Key) CanTransition(to KeyState) bool {
	if k == nil {
		return false
	}
	probe := k.Clone()
	return probe.Transition(to, time.Now()) == nil
}

// eraseMaterial zeroes and drops the private material of the key and every version. | eraseMaterial
// 擦除并丢弃密钥及其全部版本的私钥材料。
func (k *Key) eraseMaterial() {
	zeroBytes(k.Material)
	k.Material = nil
	zeroBytes(k.PublicMaterial)
	k.PublicMaterial = nil
	for _, version := range k.Versions {
		if version == nil {
			continue
		}
		zeroBytes(version.Material)
		version.Material = nil
		zeroBytes(version.PublicMaterial)
		version.PublicMaterial = nil
	}
}

// invalidTransition builds an ErrInvalidState detail. | invalidTransition 构造 ErrInvalidState 细节。
func invalidTransition(from, to KeyState) error {
	return errs.Detail(ErrInvalidState, "%[1]s -> %[2]s | %[1]s -> %[2]s", from, to)
}

// usableFor reports whether the key state permits usage at now. | usableFor 报告密钥状态在 now 时刻是否允许 usage。
//
// Active keys permit every declared usage. Deactivated keys permit only decryption, unwrapping and
// verification, matching the NIST rule that deactivated keys may protect already-protected data.
// Every other state refuses all cryptographic use. | active 密钥允许全部已声明用途。deactivated 密钥
// 仅允许解密、解包与验签，符合 NIST 关于已停用密钥仍可处理既有受保护数据的规则。其它状态拒绝
// 一切密码使用。
func (k *Key) usableFor(usage KeyUsage) error {
	if k == nil {
		return ErrNotFound
	}
	if !k.UsageMask.Has(usage) {
		return errs.Detail(ErrUsageNotAllowed, "usage %[1]q is not enabled | 未启用用途 %[1]q", usage)
	}
	switch k.State {
	case StateActive:
		return nil
	case StateDeactivated:
		switch usage {
		case UsageDecrypt, UsageUnwrapKey, UsageVerify:
			return nil
		}
		return errs.Detail(ErrKeyNotUsable, "state %[1]s forbids usage %[2]q | 状态 %[1]s 禁止用途 %[2]q", k.State, usage)
	default:
		return errs.Detail(ErrKeyNotUsable, "state %[1]s | 状态 %[1]s", k.State)
	}
}

// usableFor reports whether a version state permits usage. | usableFor 报告版本状态是否允许 usage。
func (v *KeyVersion) usableFor(usage KeyUsage) error {
	if v == nil {
		return ErrVersionNotFound
	}
	switch v.State {
	case StateActive:
		return nil
	case StateDeactivated:
		switch usage {
		case UsageDecrypt, UsageUnwrapKey, UsageVerify:
			return nil
		}
		return errs.Detail(ErrKeyNotUsable, "version state %[1]s forbids usage %[2]q | 版本状态 %[1]s 禁止用途 %[2]q", v.State, usage)
	default:
		return errs.Detail(ErrKeyNotUsable, "version state %[1]s | 版本状态 %[1]s", v.State)
	}
}

// KeyFilter filters ListKeys results. | KeyFilter 过滤 ListKeys 结果。
type KeyFilter struct {
	// State filters by lifecycle state. | State 按生命周期状态过滤。
	State KeyState
	// Type filters by key family. | Type 按密钥族过滤。
	Type KeyType
	// Usage requires the usage bit. | Usage 要求对应用途位。
	Usage KeyUsage
	// Tag requires the tag to be present. | Tag 要求包含该标签。
	Tag string
	// Query is a case-insensitive substring over ID, alias and metadata values. | Query 是作用于 ID、别名与元数据值的大小写不敏感子串。
	Query string
	// ParentID filters by parent key. | ParentID 按父密钥过滤。
	ParentID string
	// Offset is the number of matching keys to skip. | Offset 是要跳过的匹配密钥数量。
	Offset int
	// Limit is the maximum number of keys to return; 0 means no limit. | Limit 是返回密钥数量上限；0 表示不限。
	Limit int
}

// matches reports whether k passes the filter. | matches 报告 k 是否通过过滤器。
func (f KeyFilter) matches(k *Key) bool {
	if k == nil {
		return false
	}
	if f.State != "" && k.State != f.State {
		return false
	}
	if f.Type != "" && k.Type != f.Type {
		return false
	}
	if f.Usage != "" && !k.UsageMask.Has(f.Usage) {
		return false
	}
	if f.ParentID != "" && k.ParentID != f.ParentID {
		return false
	}
	if f.Tag != "" {
		found := false
		for _, tag := range k.Tags {
			if tag == f.Tag {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if f.Query != "" {
		query := lowerASCII(f.Query)
		if !containsFold(k.ID, query) && !containsFold(k.Alias, query) {
			found := false
			for _, value := range k.Metadata {
				if containsFold(value, query) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}
	return true
}

// sortKeys orders keys by creation time, then identifier, for deterministic listings. | sortKeys
// 按创建时间再按标识排序，使列表输出确定。
func sortKeys(keys []*Key) {
	sort.SliceStable(keys, func(i, j int) bool {
		if keys[i].CreatedAt.Equal(keys[j].CreatedAt) {
			return keys[i].ID < keys[j].ID
		}
		return keys[i].CreatedAt.Before(keys[j].CreatedAt)
	})
}

// ExportFormat selects the encoding of exported material. | ExportFormat 选择导出材料的编码。
type ExportFormat string

// The export formats. | 导出格式。
const (
	// ExportFormatJWK encodes an asymmetric public key as a JSON Web Key. | ExportFormatJWK 把非对称公钥编码为 JSON Web Key。
	ExportFormatJWK ExportFormat = "jwk"
	// ExportFormatPEM encodes a key as PEM (PKCS#8 or PKIX for standard keys, SM2 PEM for SM2). | ExportFormatPEM 把密钥编码为 PEM（标准密钥为 PKCS#8 或 PKIX，SM2 为 SM2 PEM）。
	ExportFormatPEM ExportFormat = "pem"
	// ExportFormatRaw returns raw key bytes (PKCS#8/PKIX DER, or the symmetric key). | ExportFormatRaw 返回原始密钥字节（PKCS#8/PKIX DER 或对称密钥）。
	ExportFormatRaw ExportFormat = "raw"
)

// ExportPolicy is the service-level export authorization. | ExportPolicy 是服务级导出授权。
//
// The zero value denies private export, so a deployment must opt in explicitly. | 零值拒绝私钥导出，
// 因此部署必须显式开启。
type ExportPolicy struct {
	// AllowPrivate permits exporting private or symmetric material when the key is Exportable. | AllowPrivate 允许在密钥为 Exportable 时导出私钥或对称材料。
	AllowPrivate bool
}

// ExportRequest describes one export call. | ExportRequest 描述一次导出调用。
type ExportRequest struct {
	// Format selects the encoding; empty means PEM for asymmetric keys and raw for symmetric keys. | Format 选择编码；为空时非对称密钥用 PEM、对称密钥用 raw。
	Format ExportFormat
	// Version selects the version; 0 means the current version. | Version 选择版本；0 表示当前版本。
	Version uint32
	// Private requests private or symmetric material. | Private 请求私钥或对称材料。
	Private bool
}

// ExportedKey is the result of ExportKey. | ExportedKey 是 ExportKey 的结果。
type ExportedKey struct {
	// KeyID is the key identifier. | KeyID 是密钥标识。
	KeyID string `json:"keyId"`
	// Version is the exported version. | Version 是导出的版本号。
	Version uint32 `json:"version"`
	// Type is the key family. | Type 是密钥族。
	Type KeyType `json:"type"`
	// Format is the used encoding. | Format 是使用的编码。
	Format ExportFormat `json:"format"`
	// Private reports whether private or symmetric material is included. | Private 表示是否包含私钥或对称材料。
	Private bool `json:"private"`
	// Material is the encoded key material: JWK JSON, PEM bytes or raw bytes. | Material 是编码后的密钥材料：JWK JSON、PEM 字节或原始字节。
	Material []byte `json:"material"`
	// PublicMaterial is the public half when Private is false and the key is asymmetric. | PublicMaterial 在 Private 为 false 且密钥为非对称时保存公钥部分。
	PublicMaterial []byte `json:"publicMaterial,omitempty"`
}
