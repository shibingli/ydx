package redis

import (
	"context"
	"errors"
	"sort"

	goredis "github.com/redis/go-redis/v9"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/errs"
)

// identityStore implements auth.IdentityStore on Redis. | identityStore 在 Redis 上实现 auth.IdentityStore。
type identityStore struct {
	base
}

// identityStore satisfies auth.IdentityStore. | identityStore 满足 auth.IdentityStore。
var _ auth.IdentityStore = (*identityStore)(nil)

// CreateIdentity stores a new external identity link atomically.
// | CreateIdentity 原子保存新的外部身份关联。
func (s *identityStore) CreateIdentity(ctx context.Context, identity *auth.Identity) error {
	if identity == nil || identity.Provider == "" || identity.Subject == "" || identity.UserID == "" {
		return errs.Detail(auth.ErrInvalidRequest, "identity fields are empty | 身份字段为空")
	}
	data, err := encodeIdentity(identity)
	if err != nil {
		return err
	}
	identityKey := s.keys.identity(identity.Provider, identity.Subject)
	code, err := s.runInt(ctx, scriptIdentityCreate, "create identity",
		[]string{identityKey, s.keys.identitiesByUser(identity.UserID)},
		string(data), identity.UserID, identityKey,
	)
	if err != nil {
		return err
	}
	switch code {
	case 0:
		return nil
	case 1:
		return errs.Detail(auth.ErrIdentityExists, "provider %[1]q subject %[2]q | 提供方 %[1]q subject %[2]q",
			identity.Provider, identity.Subject)
	default:
		return errs.Detail(auth.ErrStoreUnavailable, "create identity returned %d | 创建身份返回 %d", code, code)
	}
}

// GetIdentity returns a link by provider and subject. | GetIdentity 按提供方与 subject 返回关联。
func (s *identityStore) GetIdentity(ctx context.Context, provider, subject string) (*auth.Identity, error) {
	data, err := s.client.HGet(ctx, s.keys.identity(provider, subject), "data").Result()
	if errors.Is(err, goredis.Nil) {
		return nil, errs.Detail(auth.ErrIdentityNotFound, "provider %[1]q subject %[2]q | 提供方 %[1]q subject %[2]q", provider, subject)
	}
	if err != nil {
		return nil, s.backend("get identity", err)
	}
	return decodeIdentity([]byte(data))
}

// ListIdentitiesByUser returns every link of a user, ordered by provider then subject.
// | ListIdentitiesByUser 返回用户的全部关联，按 provider 再按 subject 排序。
func (s *identityStore) ListIdentitiesByUser(ctx context.Context, userID string) ([]*auth.Identity, error) {
	members, err := s.client.SMembers(ctx, s.keys.identitiesByUser(userID)).Result()
	if err != nil {
		return nil, s.backend("list identities", err)
	}
	out := make([]*auth.Identity, 0, len(members))
	if len(members) == 0 {
		return out, nil
	}
	cmds := make([]*goredis.SliceCmd, len(members))
	_, _ = s.client.Pipelined(ctx, func(pipe goredis.Pipeliner) error {
		for i, member := range members {
			cmds[i] = pipe.HMGet(ctx, member, "data", "user")
		}
		return nil
	})
	for i := range members {
		values, err := cmds[i].Result()
		if err != nil {
			return nil, s.backend("list identities", err)
		}
		if len(values) < 2 || values[0] == nil || stringValue(values[1]) != userID {
			continue
		}
		identity, err := decodeIdentity([]byte(stringValue(values[0])))
		if err != nil {
			return nil, err
		}
		out = append(out, identity)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Provider == out[j].Provider {
			return out[i].Subject < out[j].Subject
		}
		return out[i].Provider < out[j].Provider
	})
	return out, nil
}

// UpdateIdentity replaces an existing link and reindexes its owner atomically.
// | UpdateIdentity 原子替换已有链接并重建其属主索引。
func (s *identityStore) UpdateIdentity(ctx context.Context, identity *auth.Identity) error {
	if identity == nil || identity.Provider == "" || identity.Subject == "" {
		return errs.Detail(auth.ErrInvalidRequest, "identity fields are empty | 身份字段为空")
	}
	data, err := encodeIdentity(identity)
	if err != nil {
		return err
	}
	identityKey := s.keys.identity(identity.Provider, identity.Subject)
	for attempt := 0; attempt < maxCASRetries; attempt++ {
		oldUser, err := s.client.HGet(ctx, identityKey, "user").Result()
		if errors.Is(err, goredis.Nil) {
			return errs.Detail(auth.ErrIdentityNotFound, "provider %[1]q subject %[2]q | 提供方 %[1]q subject %[2]q",
				identity.Provider, identity.Subject)
		}
		if err != nil {
			return s.backend("update identity", err)
		}
		code, err := s.runInt(ctx, scriptIdentityUpdate, "update identity",
			[]string{identityKey, s.keys.identitiesByUser(identity.UserID), s.keys.identitiesByUser(oldUser)},
			string(data), identity.UserID, oldUser, identityKey,
		)
		if err != nil {
			return err
		}
		switch code {
		case 0:
			return nil
		case 1:
			return errs.Detail(auth.ErrIdentityNotFound, "provider %[1]q subject %[2]q | 提供方 %[1]q subject %[2]q",
				identity.Provider, identity.Subject)
		case 2:
			continue
		default:
			return errs.Detail(auth.ErrStoreUnavailable, "update identity returned %d | 更新身份返回 %d", code, code)
		}
	}
	return errs.Detail(auth.ErrConflict, "update identity %[1]q/%[2]q is contended | 更新身份 %[1]q/%[2]q 存在竞争",
		identity.Provider, identity.Subject)
}

// DeleteIdentity removes a link and its membership atomically.
// | DeleteIdentity 原子删除关联及其成员关系。
func (s *identityStore) DeleteIdentity(ctx context.Context, provider, subject string) error {
	identityKey := s.keys.identity(provider, subject)
	for attempt := 0; attempt < maxCASRetries; attempt++ {
		user, err := s.client.HGet(ctx, identityKey, "user").Result()
		if errors.Is(err, goredis.Nil) {
			return errs.Detail(auth.ErrIdentityNotFound, "provider %[1]q subject %[2]q | 提供方 %[1]q subject %[2]q", provider, subject)
		}
		if err != nil {
			return s.backend("delete identity", err)
		}
		code, err := s.runInt(ctx, scriptIdentityDelete, "delete identity",
			[]string{identityKey, s.keys.identitiesByUser(user)},
			user, identityKey,
		)
		if err != nil {
			return err
		}
		switch code {
		case 0:
			return nil
		case 1:
			return errs.Detail(auth.ErrIdentityNotFound, "provider %[1]q subject %[2]q | 提供方 %[1]q subject %[2]q", provider, subject)
		case 2:
			continue
		default:
			return errs.Detail(auth.ErrStoreUnavailable, "delete identity returned %d | 删除身份返回 %d", code, code)
		}
	}
	return errs.Detail(auth.ErrConflict, "delete identity %[1]q/%[2]q is contended | 删除身份 %[1]q/%[2]q 存在竞争",
		provider, subject)
}
