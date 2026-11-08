package redis

import (
	"context"
	"errors"
	"sort"

	goredis "github.com/redis/go-redis/v9"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/errs"
)

// credentialStore implements auth.CredentialStore on Redis. | credentialStore 在 Redis 上实现 auth.CredentialStore。
type credentialStore struct {
	base
}

// credentialStore satisfies auth.CredentialStore. | credentialStore 满足 auth.CredentialStore。
var _ auth.CredentialStore = (*credentialStore)(nil)

// CreateCredential stores a new factor atomically. | CreateCredential 原子保存新的认证因素。
func (s *credentialStore) CreateCredential(ctx context.Context, credential *auth.Credential) error {
	if credential == nil || credential.ID == "" || credential.UserID == "" {
		return errs.Detail(auth.ErrInvalidRequest, "credential fields are empty | 凭据字段为空")
	}
	data, err := encodeCredential(credential)
	if err != nil {
		return err
	}
	code, err := s.runInt(ctx, scriptCredentialCreate, "create credential",
		[]string{s.keys.credential(credential.ID), s.keys.credentialsByUser(credential.UserID)},
		string(data), credential.UserID, credential.ID,
	)
	if err != nil {
		return err
	}
	switch code {
	case 0:
		return nil
	case 1:
		return errs.Detail(auth.ErrCredentialExists, "id %[1]q | ID %[1]q", credential.ID)
	default:
		return errs.Detail(auth.ErrStoreUnavailable, "create credential returned %d | 创建凭据返回 %d", code, code)
	}
}

// GetCredential returns a factor by ID. | GetCredential 按 ID 返回因素。
func (s *credentialStore) GetCredential(ctx context.Context, id string) (*auth.Credential, error) {
	data, err := s.client.HGet(ctx, s.keys.credential(id), "data").Result()
	if errors.Is(err, goredis.Nil) {
		return nil, errs.Detail(auth.ErrCredentialNotFound, "id %[1]q | ID %[1]q", id)
	}
	if err != nil {
		return nil, s.backend("get credential", err)
	}
	return decodeCredential([]byte(data))
}

// UpdateCredential replaces an existing factor and reindexes its owner atomically.
// | UpdateCredential 原子替换已有因素并重建其属主索引。
func (s *credentialStore) UpdateCredential(ctx context.Context, credential *auth.Credential) error {
	if credential == nil || credential.ID == "" {
		return errs.Detail(auth.ErrInvalidRequest, "credential or id is empty | 凭据或 ID 为空")
	}
	data, err := encodeCredential(credential)
	if err != nil {
		return err
	}
	credentialKey := s.keys.credential(credential.ID)
	for attempt := 0; attempt < maxCASRetries; attempt++ {
		oldUser, err := s.client.HGet(ctx, credentialKey, "user").Result()
		if errors.Is(err, goredis.Nil) {
			return errs.Detail(auth.ErrCredentialNotFound, "id %[1]q | ID %[1]q", credential.ID)
		}
		if err != nil {
			return s.backend("update credential", err)
		}
		code, err := s.runInt(ctx, scriptCredentialUpdate, "update credential",
			[]string{credentialKey, s.keys.credentialsByUser(credential.UserID), s.keys.credentialsByUser(oldUser)},
			string(data), credential.UserID, oldUser, credential.ID,
		)
		if err != nil {
			return err
		}
		switch code {
		case 0:
			return nil
		case 1:
			return errs.Detail(auth.ErrCredentialNotFound, "id %[1]q | ID %[1]q", credential.ID)
		case 2:
			continue
		default:
			return errs.Detail(auth.ErrStoreUnavailable, "update credential returned %d | 更新凭据返回 %d", code, code)
		}
	}
	return errs.Detail(auth.ErrConflict, "update credential %[1]q is contended | 更新凭据 %[1]q 存在竞争", credential.ID)
}

// DeleteCredential removes a factor and its membership atomically.
// | DeleteCredential 原子删除因素及其成员关系。
func (s *credentialStore) DeleteCredential(ctx context.Context, id string) error {
	credentialKey := s.keys.credential(id)
	for attempt := 0; attempt < maxCASRetries; attempt++ {
		user, err := s.client.HGet(ctx, credentialKey, "user").Result()
		if errors.Is(err, goredis.Nil) {
			return errs.Detail(auth.ErrCredentialNotFound, "id %[1]q | ID %[1]q", id)
		}
		if err != nil {
			return s.backend("delete credential", err)
		}
		code, err := s.runInt(ctx, scriptCredentialDelete, "delete credential",
			[]string{credentialKey, s.keys.credentialsByUser(user)},
			user, id,
		)
		if err != nil {
			return err
		}
		switch code {
		case 0:
			return nil
		case 1:
			return errs.Detail(auth.ErrCredentialNotFound, "id %[1]q | ID %[1]q", id)
		case 2:
			continue
		default:
			return errs.Detail(auth.ErrStoreUnavailable, "delete credential returned %d | 删除凭据返回 %d", code, code)
		}
	}
	return errs.Detail(auth.ErrConflict, "delete credential %[1]q is contended | 删除凭据 %[1]q 存在竞争", id)
}

// ListCredentialsByUser returns every factor of a user. | ListCredentialsByUser 返回用户的全部因素。
func (s *credentialStore) ListCredentialsByUser(ctx context.Context, userID string) ([]*auth.Credential, error) {
	return s.list(ctx, userID, false, "")
}

// ListCredentialsByUserType returns the factors of a user with one type.
// | ListCredentialsByUserType 返回用户某一类型的因素。
func (s *credentialStore) ListCredentialsByUserType(ctx context.Context, userID string, typ auth.CredentialType) ([]*auth.Credential, error) {
	return s.list(ctx, userID, true, typ)
}

// list returns the credentials of a user, optionally restricted to one type, ordered by
// creation time then ID. | list 返回用户的凭据，可限定单一类型，按创建时间再按 ID 排序。
func (s *credentialStore) list(ctx context.Context, userID string, filterType bool, typ auth.CredentialType) ([]*auth.Credential, error) {
	ids, err := s.client.SMembers(ctx, s.keys.credentialsByUser(userID)).Result()
	if err != nil {
		return nil, s.backend("list credentials", err)
	}
	out := make([]*auth.Credential, 0, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	cmds := make([]*goredis.SliceCmd, len(ids))
	_, _ = s.client.Pipelined(ctx, func(pipe goredis.Pipeliner) error {
		for i, id := range ids {
			cmds[i] = pipe.HMGet(ctx, s.keys.credential(id), "data", "user")
		}
		return nil
	})
	for i := range ids {
		values, err := cmds[i].Result()
		if err != nil {
			return nil, s.backend("list credentials", err)
		}
		if len(values) < 2 || values[0] == nil || stringValue(values[1]) != userID {
			continue
		}
		credential, err := decodeCredential([]byte(stringValue(values[0])))
		if err != nil {
			return nil, err
		}
		if filterType && credential.Type != typ {
			continue
		}
		out = append(out, credential)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}
