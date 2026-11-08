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

// SaveVersion appends a version to an existing key and increments its revision. | SaveVersion 向
// 已有密钥追加版本并递增其修订号。
//
// The uniqueness check and the append run in one Lua script, so two instances cannot both store
// the same version number. | 唯一性检查与追加在同一个 Lua 脚本内执行，因此两个实例不可能同时保存
// 相同的版本号。
func (s *Store) SaveVersion(ctx context.Context, keyID string, version *authkms.KeyVersion) error {
	if err := s.ready(); err != nil {
		return err
	}
	if version == nil {
		return errs.Detail(authkms.ErrInvalidRequest, "nil key version | 密钥版本为空")
	}
	data, err := encodeVersion(version)
	if err != nil {
		return err
	}
	defer zeroBytes(data)
	field := strconv.FormatUint(uint64(version.Version), 10)
	code, err := s.runInt(ctx, scriptSaveVersion, "save version",
		[]string{s.keys.key(keyID), s.keys.versions(keyID)}, field, string(data))
	if err != nil {
		return err
	}
	switch code {
	case 0:
		return nil
	case 1:
		return errs.Detail(authkms.ErrNotFound, "id %[1]q | ID %[1]q", keyID)
	case 2:
		return errs.Detail(authkms.ErrVersionExists, "key %[1]q version %[2]d | 密钥 %[1]q 版本 %[2]d", keyID, version.Version)
	default:
		return errs.Detail(authkms.ErrStoreUnavailable, "unexpected save-version reply %[1]d | 保存版本应答 %[1]d 非法", code)
	}
}

// GetVersion returns a deep copy of one key version. | GetVersion 返回一个密钥版本的深拷贝。
func (s *Store) GetVersion(ctx context.Context, keyID string, version uint32) (*authkms.KeyVersion, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	pipe := s.client.Pipeline()
	existsCommand := pipe.HExists(ctx, s.keys.key(keyID), fieldData)
	versionCommand := pipe.HGet(ctx, s.keys.versions(keyID), strconv.FormatUint(uint64(version), 10))
	_, err := pipe.Exec(ctx)
	if err != nil && !errors.Is(err, goredis.Nil) {
		return nil, backend("get version", err)
	}
	if !existsCommand.Val() {
		return nil, errs.Detail(authkms.ErrNotFound, "id %[1]q | ID %[1]q", keyID)
	}
	data, err := versionCommand.Result()
	if errors.Is(err, goredis.Nil) {
		return nil, errs.Detail(authkms.ErrVersionNotFound, "key %[1]q version %[2]d | 密钥 %[1]q 版本 %[2]d", keyID, version)
	}
	if err != nil {
		return nil, backend("get version", err)
	}
	return decodeVersion(data)
}

// ListVersions returns deep copies of every retained version, ascending. | ListVersions 按升序返回
// 保留的全部版本深拷贝。
func (s *Store) ListVersions(ctx context.Context, keyID string) ([]*authkms.KeyVersion, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	pipe := s.client.Pipeline()
	existsCommand := pipe.HExists(ctx, s.keys.key(keyID), fieldData)
	versionsCommand := pipe.HGetAll(ctx, s.keys.versions(keyID))
	if _, err := pipe.Exec(ctx); err != nil {
		return nil, backend("list versions", err)
	}
	if !existsCommand.Val() {
		return nil, errs.Detail(authkms.ErrNotFound, "id %[1]q | ID %[1]q", keyID)
	}
	raw := versionsCommand.Val()
	versions := make([]*authkms.KeyVersion, 0, len(raw))
	for field, data := range raw {
		number, err := strconv.ParseUint(field, 10, 32)
		if err != nil {
			return nil, errs.Detail(authkms.ErrStoreUnavailable, "stored key version number is corrupt | 存储的密钥版本号损坏")
		}
		version, err := decodeVersion(data)
		if err != nil {
			return nil, err
		}
		if version.Version != uint32(number) {
			return nil, errs.Detail(authkms.ErrStoreUnavailable, "stored key version number is corrupt | 存储的密钥版本号损坏")
		}
		versions = append(versions, version)
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i].Version < versions[j].Version })
	return versions, nil
}
