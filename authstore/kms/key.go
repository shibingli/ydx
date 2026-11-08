package kms

import (
	"context"
	"errors"
	"sort"
	"strconv"

	goredis "github.com/redis/go-redis/v9"

	authkms "github.com/shibingli/ydx/auth/keymgmt/kms"
	"github.com/shibingli/ydx/errs"
)

// listBatchSize bounds the number of key hashes read by one pipeline batch. | listBatchSize 限定
// 单个管道批次读取的密钥哈希数量。
const listBatchSize = 128

// CreateKey stores a new key. | CreateKey 保存新密钥。
//
// It stores a deep copy, assigns Revision 1 when the incoming revision is zero, and binds the
// primary alias atomically with the record. A duplicate identifier reports ErrKeyExists; an alias
// bound to another key reports ErrAliasExists. | 它保存深拷贝，在传入修订号为零时赋值 1，并把主
// 别名与记录原子绑定。标识重复返回 ErrKeyExists；别名绑定到其它密钥返回 ErrAliasExists。
func (s *Store) CreateKey(ctx context.Context, key *authkms.Key) error {
	if err := s.ready(); err != nil {
		return err
	}
	if key == nil || key.ID == "" {
		return errs.Detail(authkms.ErrInvalidRequest, "key or id is empty | 密钥或 ID 为空")
	}
	data, err := encodeKey(key)
	if err != nil {
		return err
	}
	defer zeroBytes(data)
	revision := key.Revision
	if revision == 0 {
		revision = 1
	}
	count, versionArgs, err := encodeVersionArgs(key.Versions)
	if err != nil {
		return err
	}
	aliasKey := s.keys.dummy()
	hasAlias := "0"
	if key.Alias != "" {
		aliasKey = s.keys.alias(key.Alias)
		hasAlias = "1"
	}
	args := []any{
		key.ID, string(data), strconv.FormatUint(revision, 10), createdAtScore(key.CreatedAt),
		key.Alias, hasAlias, strconv.Itoa(count),
	}
	for _, arg := range versionArgs {
		args = append(args, arg)
	}
	code, err := s.runInt(ctx, scriptKeyCreate, "create key",
		[]string{s.keys.key(key.ID), s.keys.versions(key.ID), s.keys.keysAll(), aliasKey, s.keys.aliases(key.ID)}, args...)
	if err != nil {
		return err
	}
	switch code {
	case 0:
		return nil
	case 1:
		return errs.Detail(authkms.ErrKeyExists, "id %[1]q | ID %[1]q", key.ID)
	case 2:
		return errs.Detail(authkms.ErrAliasExists, "alias %[1]q is bound to another key | 别名 %[1]q 已绑定到其它密钥", key.Alias)
	default:
		return errs.Detail(authkms.ErrStoreUnavailable, "unexpected create reply %[1]d | 创建应答 %[1]d 非法", code)
	}
}

// GetKey returns a deep copy of the key with the given identifier. | GetKey 返回指定标识密钥的深拷贝。
func (s *Store) GetKey(ctx context.Context, id string) (*authkms.Key, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	return s.loadKey(ctx, id)
}

// UpdateKey replaces a key under optimistic concurrency. | UpdateKey 在乐观并发控制下替换密钥。
//
// The incoming Revision must equal the stored Revision; a mismatch reports ErrConflict. A
// successful update stores the incoming versions and increments the stored revision. | 传入的
// Revision 必须等于已存 Revision；不匹配返回 ErrConflict。成功更新会保存传入版本并递增已存修订号。
func (s *Store) UpdateKey(ctx context.Context, key *authkms.Key) error {
	if err := s.ready(); err != nil {
		return err
	}
	if key == nil || key.ID == "" {
		return errs.Detail(authkms.ErrInvalidRequest, "key or id is empty | 密钥或 ID 为空")
	}
	data, err := encodeKey(key)
	if err != nil {
		return err
	}
	defer zeroBytes(data)
	count, versionArgs, err := encodeVersionArgs(key.Versions)
	if err != nil {
		return err
	}
	newAliasKey := s.keys.dummy()
	if key.Alias != "" {
		newAliasKey = s.keys.alias(key.Alias)
	}
	for attempt := 0; attempt < maxCASRetries; attempt++ {
		storedRevision, storedAlias, err := s.loadRevision(ctx, key.ID)
		if err != nil {
			return err
		}
		if key.Revision != storedRevision {
			return errs.Detail(authkms.ErrConflict, "revision %[1]d, stored %[2]d | 修订号 %[1]d，存储为 %[2]d", key.Revision, storedRevision)
		}
		oldAliasKey := s.keys.dummy()
		hasOldAlias := "0"
		if storedAlias != "" {
			oldAliasKey = s.keys.alias(storedAlias)
			hasOldAlias = "1"
		}
		hasNewAlias := "0"
		if key.Alias != "" {
			hasNewAlias = "1"
		}
		args := []any{
			key.ID, strconv.FormatUint(storedRevision, 10), strconv.FormatUint(storedRevision+1, 10),
			string(data), createdAtScore(key.CreatedAt), key.Alias, hasNewAlias, storedAlias,
			hasOldAlias, strconv.Itoa(count),
		}
		for _, arg := range versionArgs {
			args = append(args, arg)
		}
		code, err := s.runInt(ctx, scriptKeyUpdate, "update key",
			[]string{
				s.keys.key(key.ID), s.keys.versions(key.ID), s.keys.keysAll(),
				s.keys.aliases(key.ID), newAliasKey, oldAliasKey,
			}, args...)
		if err != nil {
			return err
		}
		switch code {
		case 0:
			return nil
		case 1:
			return errs.Detail(authkms.ErrNotFound, "id %[1]q | ID %[1]q", key.ID)
		case 2:
			continue
		case 3:
			return errs.Detail(authkms.ErrAliasExists, "alias %[1]q is bound to another key | 别名 %[1]q 已绑定到其它密钥", key.Alias)
		default:
			return errs.Detail(authkms.ErrStoreUnavailable, "unexpected update reply %[1]d | 更新应答 %[1]d 非法", code)
		}
	}
	return errs.Detail(authkms.ErrConflict, "concurrent update retries exhausted | 并发更新重试耗尽")
}

// DeleteKey physically removes a key, its versions and every alias bound to it. | DeleteKey 物理
// 删除密钥、其版本以及绑定到它的全部别名。
func (s *Store) DeleteKey(ctx context.Context, id string) error {
	if err := s.ready(); err != nil {
		return err
	}
	code, err := s.runInt(ctx, scriptKeyDelete, "delete key",
		[]string{s.keys.key(id), s.keys.versions(id), s.keys.keysAll(), s.keys.aliases(id)},
		s.keys.aliasPrefix(), id)
	if err != nil {
		return err
	}
	switch code {
	case 0:
		return nil
	case 1:
		return errs.Detail(authkms.ErrNotFound, "id %[1]q | ID %[1]q", id)
	default:
		return errs.Detail(authkms.ErrStoreUnavailable, "unexpected delete reply %[1]d | 删除应答 %[1]d 非法", code)
	}
}

// ListKeys returns deep copies of the matching keys ordered by creation time then identifier.
// | ListKeys 返回匹配密钥的深拷贝，按创建时间再按标识排序。
func (s *Store) ListKeys(ctx context.Context, filter authkms.KeyFilter) ([]*authkms.Key, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	ids, err := s.client.ZRange(ctx, s.keys.keysAll(), 0, -1).Result()
	if err != nil {
		return nil, backend("list keys", err)
	}
	loaded, err := s.loadKeys(ctx, ids)
	if err != nil {
		return nil, err
	}
	matched := make([]*authkms.Key, 0, len(loaded))
	for _, key := range loaded {
		if filterMatches(filter, key) {
			matched = append(matched, key)
		}
	}
	sortKeys(matched)
	return paginateKeys(matched, filter.Offset, filter.Limit), nil
}

// loadKey reads one key hash and its versions hash and reassembles the record. | loadKey 读取单个
// 密钥哈希及其版本哈希并重组记录。
func (s *Store) loadKey(ctx context.Context, id string) (*authkms.Key, error) {
	pipe := s.client.Pipeline()
	keyCommand := pipe.HGetAll(ctx, s.keys.key(id))
	versionCommand := pipe.HGetAll(ctx, s.keys.versions(id))
	if _, err := pipe.Exec(ctx); err != nil {
		return nil, backend("get key", err)
	}
	fields := keyCommand.Val()
	if len(fields) == 0 {
		return nil, errs.Detail(authkms.ErrNotFound, "id %[1]q | ID %[1]q", id)
	}
	return decodeStoredKey(fields, versionCommand.Val())
}

// loadRevision reads the stored revision and primary alias of one key. | loadRevision 读取单个密钥的
// 已存修订号与主别名。
func (s *Store) loadRevision(ctx context.Context, id string) (uint64, string, error) {
	pipe := s.client.Pipeline()
	revisionCommand := pipe.HGet(ctx, s.keys.key(id), fieldRevision)
	aliasCommand := pipe.HGet(ctx, s.keys.key(id), fieldAlias)
	_, err := pipe.Exec(ctx)
	if err != nil && !errors.Is(err, goredis.Nil) {
		return 0, "", backend("get key", err)
	}
	revisionText, revisionErr := revisionCommand.Result()
	if errors.Is(revisionErr, goredis.Nil) {
		return 0, "", errs.Detail(authkms.ErrNotFound, "id %[1]q | ID %[1]q", id)
	}
	if revisionErr != nil {
		return 0, "", backend("get key", revisionErr)
	}
	alias, aliasErr := aliasCommand.Result()
	if aliasErr != nil && !errors.Is(aliasErr, goredis.Nil) {
		return 0, "", backend("get key", aliasErr)
	}
	revision, parseErr := strconv.ParseUint(revisionText, 10, 64)
	if parseErr != nil {
		return 0, "", errs.Detail(authkms.ErrStoreUnavailable, "stored key revision is corrupt | 存储的密钥修订号损坏")
	}
	return revision, alias, nil
}

// loadKeys reads every identifier in bounded pipeline batches. Identifiers removed between the
// index read and the hash read are skipped. | loadKeys 以有界管道批次读取全部标识。索引读取与哈希
// 读取之间被删除的标识会被跳过。
func (s *Store) loadKeys(ctx context.Context, ids []string) ([]*authkms.Key, error) {
	out := make([]*authkms.Key, 0, len(ids))
	for start := 0; start < len(ids); start += listBatchSize {
		end := start + listBatchSize
		if end > len(ids) {
			end = len(ids)
		}
		batch := ids[start:end]
		pipe := s.client.Pipeline()
		keyCommands := make([]*goredis.MapStringStringCmd, len(batch))
		versionCommands := make([]*goredis.MapStringStringCmd, len(batch))
		for i, id := range batch {
			keyCommands[i] = pipe.HGetAll(ctx, s.keys.key(id))
			versionCommands[i] = pipe.HGetAll(ctx, s.keys.versions(id))
		}
		if _, err := pipe.Exec(ctx); err != nil {
			return nil, backend("list keys", err)
		}
		for i := range batch {
			fields := keyCommands[i].Val()
			if len(fields) == 0 {
				continue
			}
			key, err := decodeStoredKey(fields, versionCommands[i].Val())
			if err != nil {
				return nil, err
			}
			out = append(out, key)
		}
	}
	return out, nil
}

// decodeStoredKey reassembles a key record from its hash fields and version hash.
// | decodeStoredKey 从密钥哈希字段与版本哈希重组密钥记录。
func decodeStoredKey(fields, rawVersions map[string]string) (*authkms.Key, error) {
	key, err := decodeKey(fields[fieldData])
	if err != nil {
		return nil, err
	}
	revision, err := strconv.ParseUint(fields[fieldRevision], 10, 64)
	if err != nil {
		return nil, errs.Detail(authkms.ErrStoreUnavailable, "stored key revision is corrupt | 存储的密钥修订号损坏")
	}
	key.Revision = revision
	if len(rawVersions) > 0 {
		versions := make([]*authkms.KeyVersion, 0, len(rawVersions))
		for field, data := range rawVersions {
			number, parseErr := strconv.ParseUint(field, 10, 32)
			if parseErr != nil {
				return nil, errs.Detail(authkms.ErrStoreUnavailable, "stored key version number is corrupt | 存储的密钥版本号损坏")
			}
			version, decodeErr := decodeVersion(data)
			if decodeErr != nil {
				return nil, decodeErr
			}
			if version.Version != uint32(number) {
				return nil, errs.Detail(authkms.ErrStoreUnavailable, "stored key version number is corrupt | 存储的密钥版本号损坏")
			}
			versions = append(versions, version)
		}
		sort.Slice(versions, func(i, j int) bool { return versions[i].Version < versions[j].Version })
		key.Versions = versions
	}
	return key, nil
}

// encodeVersionArgs serializes versions into Lua argument pairs and returns the pair count.
// | encodeVersionArgs 把版本序列化为 Lua 参数对并返回对数量。
func encodeVersionArgs(versions []*authkms.KeyVersion) (int, []string, error) {
	args := make([]string, 0, len(versions)*2)
	count := 0
	for _, version := range versions {
		if version == nil {
			continue
		}
		data, err := encodeVersion(version)
		if err != nil {
			return 0, nil, err
		}
		args = append(args, strconv.FormatUint(uint64(version.Version), 10), string(data))
		zeroBytes(data)
		count++
	}
	return count, args, nil
}
