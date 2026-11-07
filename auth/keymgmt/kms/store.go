package kms

import (
	"context"

	"github.com/shibingli/ydx/errs"
)

// Store persists keys, versions, aliases and audit records. | Store 持久化密钥、版本、别名与审计记录。
//
// Implementations must store deep copies and must never mutate the values they receive, so callers
// may keep using a value after a call. Reads also return deep copies. UpdateKey enforces optimistic
// concurrency: the incoming Revision must equal the stored Revision, and a successful update
// increments it. A missing record returns ErrNotFound (or ErrAliasNotFound / ErrVersionNotFound);
// a revision mismatch returns ErrConflict. | 实现必须保存深拷贝且不得修改收到的值，因此调用方在调用
// 后仍可继续使用该值。读取同样返回深拷贝。UpdateKey 强制乐观并发：传入的 Revision 必须等于存储
// 中的 Revision，成功更新会递增它。记录缺失返回 ErrNotFound（或 ErrAliasNotFound /
// ErrVersionNotFound）；修订号不匹配返回 ErrConflict。
type Store interface {
	// CreateKey stores a new key. | CreateKey 保存新密钥。
	CreateKey(ctx context.Context, key *Key) error
	// GetKey returns a key by identifier. | GetKey 按标识返回密钥。
	GetKey(ctx context.Context, id string) (*Key, error)
	// UpdateKey replaces a key using optimistic concurrency. | UpdateKey 使用乐观并发替换密钥。
	UpdateKey(ctx context.Context, key *Key) error
	// DeleteKey physically removes a key and its aliases. | DeleteKey 物理删除密钥及其别名。
	DeleteKey(ctx context.Context, id string) error
	// ListKeys returns the keys matching filter. | ListKeys 返回匹配过滤器的密钥。
	ListKeys(ctx context.Context, filter KeyFilter) ([]*Key, error)

	// ResolveAlias returns the key identifier bound to alias. | ResolveAlias 返回绑定到别名的密钥标识。
	ResolveAlias(ctx context.Context, alias string) (string, error)
	// SetAlias binds alias to keyID, replacing only an alias of the same key. | SetAlias 把别名绑定到 keyID，仅替换同一密钥的旧别名。
	SetAlias(ctx context.Context, alias, keyID string) error
	// DeleteAlias removes alias. | DeleteAlias 删除别名。
	DeleteAlias(ctx context.Context, alias string) error

	// SaveVersion appends a version to an existing key. | SaveVersion 向已有密钥追加版本。
	SaveVersion(ctx context.Context, keyID string, version *KeyVersion) error
	// GetVersion returns one version of a key. | GetVersion 返回密钥的一个版本。
	GetVersion(ctx context.Context, keyID string, version uint32) (*KeyVersion, error)
	// ListVersions returns every retained version, ascending. | ListVersions 按升序返回保留的全部版本。
	ListVersions(ctx context.Context, keyID string) ([]*KeyVersion, error)

	// AuditSink appends and lists audit records. | AuditSink 追加与列出审计记录。
	AuditSink
}

// KeyStore is a material-safe read facade over a Store. | KeyStore 是 Store 上的材料安全读取门面。
//
// Get, List and Resolve never return private material. Export returns private material only when the
// key is marked Exportable and the KeyStore policy allows private export. | Get、List 与 Resolve
// 永不返回私钥材料。仅当密钥标记为 Exportable 且 KeyStore 策略允许私钥导出时，Export 才返回私钥材料。
type KeyStore struct {
	// store is the backing persistence layer. | store 是底层持久层。
	store Store
	// policy is the export authorization applied to Export. | policy 是应用于 Export 的导出授权。
	policy ExportPolicy
}

// NewKeyStore returns a material-safe facade over store with policy. | NewKeyStore 返回带 policy 的、
// 对 store 的材料安全门面。
func NewKeyStore(store Store, policy ExportPolicy) *KeyStore {
	return &KeyStore{store: store, policy: policy}
}

// Store returns the backing store. | Store 返回底层存储。
func (k *KeyStore) Store() Store {
	if k == nil {
		return nil
	}
	return k.store
}

// Get returns a public view of a key. | Get 返回密钥的公开视图。
func (k *KeyStore) Get(ctx context.Context, id string) (*Key, error) {
	if k == nil || k.store == nil {
		return nil, ErrStoreUnavailable
	}
	key, err := k.store.GetKey(ctx, id)
	if err != nil {
		return nil, err
	}
	return key.PublicView(), nil
}

// Resolve resolves an identifier or alias and returns a public view. | Resolve 解析标识或别名并返回公开视图。
func (k *KeyStore) Resolve(ctx context.Context, aliasOrID string) (*Key, error) {
	if k == nil || k.store == nil {
		return nil, ErrStoreUnavailable
	}
	key, err := resolveStoredKey(ctx, k.store, aliasOrID)
	if err != nil {
		return nil, err
	}
	return key.PublicView(), nil
}

// List returns public views of the matching keys. | List 返回匹配密钥的公开视图。
func (k *KeyStore) List(ctx context.Context, filter KeyFilter) ([]*Key, error) {
	if k == nil || k.store == nil {
		return nil, ErrStoreUnavailable
	}
	keys, err := k.store.ListKeys(ctx, filter)
	if err != nil {
		return nil, err
	}
	out := make([]*Key, 0, len(keys))
	for _, key := range keys {
		out = append(out, key.MetadataView())
	}
	return out, nil
}

// Export returns key material subject to the key Exportable flag and the KeyStore policy. | Export
// 在密钥 Exportable 标志与 KeyStore 策略约束下返回密钥材料。
//
// It reads material exactly as stored; a KeyStore built directly over a Store does not undo the
// Service at-rest wrapper. Prefer Service.ExportKey when at-rest wrapping is configured. | 它按存储
// 原样读取材料；直接建于 Store 之上的 KeyStore 不会解除 Service 的静态包装。配置了静态包装时请
// 优先使用 Service.ExportKey。
func (k *KeyStore) Export(ctx context.Context, id string, request ExportRequest) (*ExportedKey, error) {
	if k == nil || k.store == nil {
		return nil, ErrStoreUnavailable
	}
	return exportStoredKey(ctx, k.store, k.policy, id, request)
}

// resolveStoredKey resolves id as a key identifier first, then as an alias. | resolveStoredKey 先按
// 密钥标识解析 id，再按别名解析。
func resolveStoredKey(ctx context.Context, store Store, aliasOrID string) (*Key, error) {
	if store == nil {
		return nil, ErrStoreUnavailable
	}
	if aliasOrID == "" {
		return nil, errs.Detail(ErrInvalidRequest, "empty key identifier | 密钥标识为空")
	}
	key, err := store.GetKey(ctx, aliasOrID)
	if err == nil {
		return key, nil
	}
	if !isNotFound(err) {
		return nil, err
	}
	keyID, aliasErr := store.ResolveAlias(ctx, aliasOrID)
	if aliasErr != nil {
		return nil, aliasErr
	}
	return store.GetKey(ctx, keyID)
}

// isNotFound reports whether err means a missing key, alias or version. | isNotFound 报告 err 是否表示密钥、别名或版本缺失。
func isNotFound(err error) bool {
	return err != nil && (errorsIs(err, ErrNotFound) || errorsIs(err, ErrAliasNotFound) || errorsIs(err, ErrVersionNotFound))
}
