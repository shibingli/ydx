package kms

import (
	"context"
	"errors"

	goredis "github.com/redis/go-redis/v9"

	authkms "github.com/shibingli/ydx/auth/keymgmt/kms"
	"github.com/shibingli/ydx/errs"
)

// ResolveAlias returns the key identifier bound to alias. | ResolveAlias 返回绑定到别名的密钥标识。
func (s *Store) ResolveAlias(ctx context.Context, alias string) (string, error) {
	if err := s.ready(); err != nil {
		return "", err
	}
	if alias == "" {
		return "", errs.Detail(authkms.ErrInvalidRequest, "empty alias | 别名为空")
	}
	id, err := s.client.Get(ctx, s.keys.alias(alias)).Result()
	if errors.Is(err, goredis.Nil) {
		return "", errs.Detail(authkms.ErrAliasNotFound, "alias %[1]q | 别名 %[1]q", alias)
	}
	if err != nil {
		return "", backend("resolve alias", err)
	}
	return id, nil
}

// SetAlias binds alias to keyID, replacing only an alias of the same key. | SetAlias 把别名绑定到
// keyID，仅替换同一密钥的旧别名。
func (s *Store) SetAlias(ctx context.Context, alias, keyID string) error {
	if err := s.ready(); err != nil {
		return err
	}
	if alias == "" || keyID == "" {
		return errs.Detail(authkms.ErrInvalidRequest, "empty alias or key id | 别名或密钥 ID 为空")
	}
	code, err := s.runInt(ctx, scriptSetAlias, "set alias",
		[]string{s.keys.key(keyID), s.keys.alias(alias), s.keys.aliases(keyID)}, alias, keyID)
	if err != nil {
		return err
	}
	switch code {
	case 0:
		return nil
	case 1:
		return errs.Detail(authkms.ErrNotFound, "id %[1]q | ID %[1]q", keyID)
	case 2:
		return errs.Detail(authkms.ErrAliasExists, "alias %[1]q is bound to another key | 别名 %[1]q 已绑定到其它密钥", alias)
	default:
		return errs.Detail(authkms.ErrStoreUnavailable, "unexpected set-alias reply %[1]d | 设置别名应答 %[1]d 非法", code)
	}
}

// DeleteAlias removes alias. | DeleteAlias 删除别名。
func (s *Store) DeleteAlias(ctx context.Context, alias string) error {
	if err := s.ready(); err != nil {
		return err
	}
	code, err := s.runInt(ctx, scriptDeleteAlias, "delete alias",
		[]string{s.keys.alias(alias)}, s.keys.aliasPrefix(), alias)
	if err != nil {
		return err
	}
	switch code {
	case 0:
		return nil
	case 1:
		return errs.Detail(authkms.ErrAliasNotFound, "alias %[1]q | 别名 %[1]q", alias)
	default:
		return errs.Detail(authkms.ErrStoreUnavailable, "unexpected delete-alias reply %[1]d | 删除别名应答 %[1]d 非法", code)
	}
}
