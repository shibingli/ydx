package scim

import (
	"context"
	"errors"
	"strings"

	goredis "github.com/redis/go-redis/v9"

	scimlib "github.com/shibingli/ydx/auth/directory/scim"
	"github.com/shibingli/ydx/errs"
)

// CreateUser stores user and returns the stored copy. | CreateUser 保存 user 并返回存储副本。
//
// A caller supplied identifier is preserved, which lets the SCIM server recreate a deleted
// resource with its original identifier during an atomic bulk rollback. An empty identifier is
// replaced by a random 32-character hexadecimal one. The userName is unique ignoring case and
// surrounding whitespace, and a duplicate is reported as scim.ErrUniqueness while a duplicate
// identifier is reported as scim.ErrConflict. A nil Active value is stored as true.
// | 调用方提供的标识会被保留，使 SCIM 服务端在批量原子回滚时用原标识重建已删除资源。空标识会被替换为
// 随机 32 字符十六进制标识。userName 在忽略大小写与首尾空白后唯一，重复返回 scim.ErrUniqueness，
// 标识重复返回 scim.ErrConflict。nil Active 会以 true 保存。
func (s *Store) CreateUser(ctx context.Context, user *scimlib.User) (*scimlib.User, error) {
	ctx = contextOrBackground(ctx)
	if err := s.contextError(ctx); err != nil {
		return nil, err
	}
	if user == nil {
		return nil, errs.Detail(scimlib.ErrInvalidValue, "nil User | User 为空")
	}
	stored := user.Clone()
	if strings.TrimSpace(stored.UserName) == "" {
		return nil, errs.Detail(scimlib.ErrInvalidValue, "userName is required | userName 为必需属性")
	}
	if stored.ID == "" {
		id, err := newResourceID()
		if err != nil {
			return nil, errs.WrapDetail(err, scimlib.ErrInternal, "cannot generate User id | 无法生成 User 标识")
		}
		stored.ID = id
	}
	stored.EnsureSchemas()
	if stored.Active == nil {
		stored.SetActive(true)
	}
	now := s.timestamp()
	stored.Meta = &scimlib.Meta{
		ResourceType: scimlib.ResourceTypeNameUser,
		Created:      now,
		LastModified: now,
	}
	data, err := encodeUser(stored)
	if err != nil {
		return nil, err
	}
	base := versionBase(scimlib.ResourceTypeNameUser, stored.ID)
	username := normalizeIndexValue(stored.UserName)
	external := normalizeIndexValue(stored.ExternalID)
	display := normalizeIndexValue(stored.DisplayName)
	reply, err := s.run(ctx, scriptUserCreate, "create user", []string{
		s.keys.usersOrder(),
		s.keys.user(stored.ID),
		s.keys.userNameIndex(username),
		s.keys.userExternalIndex(external),
		s.keys.userDisplayIndex(display),
		s.keys.usersSequence(),
		s.keys.revision(),
	}, string(data), base, stored.ID, username, external, display,
		flag(username != ""), flag(external != ""), flag(display != ""))
	if err != nil {
		return nil, err
	}
	switch replyInt(reply, 0) {
	case 0:
		stored.Meta.Version = etagFor(tagFor(base, replyInt(reply, 1)))
		return stored.Clone(), nil
	case 1:
		return nil, errs.Detail(scimlib.ErrConflict, "User %q already exists | User %q 已存在", stored.ID, stored.ID)
	case 2:
		return nil, errs.Detail(scimlib.ErrUniqueness, "userName %q already exists | userName %q 已存在", stored.UserName, stored.UserName)
	default:
		return nil, errs.Detail(scimlib.ErrInternal, "create user returned an unknown result | 创建用户返回未知结果")
	}
}

// GetUser returns the stored User with the given identifier. | GetUser 返回指定标识的已存储 User。
//
// The result is a deep copy, so mutating it cannot change stored state. A missing identifier is
// reported as scim.ErrNotFound. | 结果是深拷贝，修改它不会改变存储状态。标识不存在返回
// scim.ErrNotFound。
func (s *Store) GetUser(ctx context.Context, id string) (*scimlib.User, error) {
	ctx = contextOrBackground(ctx)
	if err := s.contextError(ctx); err != nil {
		return nil, err
	}
	values, err := s.client.HMGet(ctx, s.keys.user(id), "data", "version").Result()
	if err != nil {
		return nil, s.backend("get user", err)
	}
	if len(values) < 2 || values[0] == nil {
		return nil, errs.Detail(scimlib.ErrNotFound, "User %q not found | User %q 不存在", id, id)
	}
	return decodeUser([]byte(anyString(values[0])), anyString(values[1]))
}

// GetUserByUserName returns the User whose userName matches ignoring case and surrounding
// whitespace. | GetUserByUserName 返回 userName 在忽略大小写与首尾空白后匹配的 User。
//
// A missing name is reported as scim.ErrNotFound. | 名称不存在返回 scim.ErrNotFound。
func (s *Store) GetUserByUserName(ctx context.Context, userName string) (*scimlib.User, error) {
	ctx = contextOrBackground(ctx)
	if err := s.contextError(ctx); err != nil {
		return nil, err
	}
	name := normalizeIndexValue(userName)
	if name == "" {
		return nil, errs.Detail(scimlib.ErrNotFound, "userName %q not found | userName %q 不存在", userName, userName)
	}
	id, err := s.client.Get(ctx, s.keys.userNameIndex(name)).Result()
	if errors.Is(err, goredis.Nil) {
		return nil, errs.Detail(scimlib.ErrNotFound, "userName %q not found | userName %q 不存在", userName, userName)
	}
	if err != nil {
		return nil, s.backend("get user by userName", err)
	}
	if id == "" {
		return nil, errs.Detail(scimlib.ErrNotFound, "userName %q not found | userName %q 不存在", userName, userName)
	}
	return s.GetUser(ctx, id)
}

// GetUserByExternalID returns the oldest User whose externalId matches ignoring case and
// surrounding whitespace. | GetUserByExternalID 返回 externalId 在忽略大小写与首尾空白后匹配的最早 User。
//
// externalId is not unique: several Users may share it, and this method returns the first created
// one while ListUsers with a filter returns all of them. A missing value is reported as
// scim.ErrNotFound. | externalId 不唯一：多个 User 可共享同一值，本方法返回最早创建的一个，而带过滤器
// 的 ListUsers 返回全部。值不存在返回 scim.ErrNotFound。
func (s *Store) GetUserByExternalID(ctx context.Context, externalID string) (*scimlib.User, error) {
	ctx = contextOrBackground(ctx)
	if err := s.contextError(ctx); err != nil {
		return nil, err
	}
	value := normalizeIndexValue(externalID)
	if value == "" {
		return nil, errs.Detail(scimlib.ErrNotFound, "externalId %q not found | externalId %q 不存在", externalID, externalID)
	}
	ids, err := s.client.ZRange(ctx, s.keys.userExternalIndex(value), 0, 0).Result()
	if err != nil {
		return nil, s.backend("get user by externalId", err)
	}
	if len(ids) == 0 {
		return nil, errs.Detail(scimlib.ErrNotFound, "externalId %q not found | externalId %q 不存在", externalID, externalID)
	}
	return s.GetUser(ctx, ids[0])
}

// GetUserByDisplayName returns the oldest User whose displayName matches ignoring case and
// surrounding whitespace. | GetUserByDisplayName 返回 displayName 在忽略大小写与首尾空白后匹配的最早
// User。
//
// displayName is not unique: several Users may share it, and this method returns the first created
// one while ListUsers with a filter returns all of them. A missing value is reported as
// scim.ErrNotFound. | displayName 不唯一：多个 User 可共享同一值，本方法返回最早创建的一个，而带过滤器
// 的 ListUsers 返回全部。值不存在返回 scim.ErrNotFound。
func (s *Store) GetUserByDisplayName(ctx context.Context, displayName string) (*scimlib.User, error) {
	ctx = contextOrBackground(ctx)
	if err := s.contextError(ctx); err != nil {
		return nil, err
	}
	value := normalizeIndexValue(displayName)
	if value == "" {
		return nil, errs.Detail(scimlib.ErrNotFound, "displayName %q not found | displayName %q 不存在", displayName, displayName)
	}
	ids, err := s.client.ZRange(ctx, s.keys.userDisplayIndex(value), 0, 0).Result()
	if err != nil {
		return nil, s.backend("get user by displayName", err)
	}
	if len(ids) == 0 {
		return nil, errs.Detail(scimlib.ErrNotFound, "displayName %q not found | displayName %q 不存在", displayName, displayName)
	}
	return s.GetUser(ctx, ids[0])
}

// ReplaceUser replaces the stored User with the same identifier. | ReplaceUser 替换具有相同标识的已
// 存储 User。
//
// The prior creation instant is preserved, unknown metadata supplied by the caller is replaced,
// and a new entity tag is allocated. A missing identifier is reported as scim.ErrNotFound, a
// duplicate userName as scim.ErrUniqueness, and repeated compare-and-set contention as
// scim.ErrConflict. | 保留先前的创建时刻，调用方提供的未知元数据会被替换，并分配新的实体标签。标识不存在
// 返回 scim.ErrNotFound，userName 重复返回 scim.ErrUniqueness，反复比较并交换竞争返回
// scim.ErrConflict。
func (s *Store) ReplaceUser(ctx context.Context, user *scimlib.User) (*scimlib.User, error) {
	return s.replaceUser(ctx, user, "")
}

// ReplaceUserIfVersion replaces the stored User only when its entity tag matches expectedVersion.
// | ReplaceUserIfVersion 仅在已存储 User 的实体标签匹配 expectedVersion 时替换它。
//
// An empty expectedVersion disables the precondition. The caller supplied forms with or without
// the weak prefix and quotes compare equal because both sides are normalized. A mismatch is
// reported as scim.ErrPreconditionFailed and changes nothing. This is the primitive the SCIM
// server uses to restore a prior profile only when no other instance modified it.
// | expectedVersion 为空时禁用前置条件。无论是否带弱前缀与引号，双方都会规范化后比较，因此等价。
// 不匹配返回 scim.ErrPreconditionFailed 且不改变任何内容。SCIM 服务端用它仅在没有其它实例修改时恢复
// 先前资料。
func (s *Store) ReplaceUserIfVersion(ctx context.Context, user *scimlib.User, expectedVersion string) (*scimlib.User, error) {
	return s.replaceUser(ctx, user, expectedVersion)
}

// replaceUser implements ReplaceUser and ReplaceUserIfVersion. | replaceUser 实现 ReplaceUser 与
// ReplaceUserIfVersion。
func (s *Store) replaceUser(ctx context.Context, user *scimlib.User, expectedVersion string) (*scimlib.User, error) {
	ctx = contextOrBackground(ctx)
	if err := s.contextError(ctx); err != nil {
		return nil, err
	}
	if user == nil || user.ID == "" {
		return nil, errs.Detail(scimlib.ErrInvalidValue, "User id is required | User 标识为必需")
	}
	if strings.TrimSpace(user.UserName) == "" {
		return nil, errs.Detail(scimlib.ErrInvalidValue, "userName is required | userName 为必需属性")
	}
	expected := normalizeETag(expectedVersion)
	userKey := s.keys.user(user.ID)
	base := versionBase(scimlib.ResourceTypeNameUser, user.ID)
	for attempt := 0; attempt < maxCASRetries; attempt++ {
		values, err := s.client.HMGet(ctx, userKey, "data", "username", "external", "display", "versionTag").Result()
		if err != nil {
			return nil, s.backend("replace user", err)
		}
		if len(values) < 5 || values[0] == nil {
			return nil, errs.Detail(scimlib.ErrNotFound, "User %q not found | User %q 不存在", user.ID, user.ID)
		}
		oldData := anyString(values[0])
		oldUsername := anyString(values[1])
		oldExternal := anyString(values[2])
		oldDisplay := anyString(values[3])
		oldTag := normalizeETag(anyString(values[4]))
		if expected != "" && expected != oldTag {
			return nil, errs.Detail(scimlib.ErrPreconditionFailed, "User %q version changed | User %q 版本已变化", user.ID, user.ID)
		}
		oldUser, err := decodeUser([]byte(oldData), etagFor(oldTag))
		if err != nil {
			return nil, err
		}
		stored := user.Clone()
		stored.EnsureSchemas()
		if stored.Active == nil {
			stored.SetActive(true)
		}
		created := s.timestamp()
		if oldUser.Meta != nil && oldUser.Meta.Created != "" {
			created = oldUser.Meta.Created
		}
		stored.Meta = &scimlib.Meta{
			ResourceType: scimlib.ResourceTypeNameUser,
			Created:      created,
			LastModified: s.timestamp(),
		}
		data, err := encodeUser(stored)
		if err != nil {
			return nil, err
		}
		newUsername := normalizeIndexValue(stored.UserName)
		newExternal := normalizeIndexValue(stored.ExternalID)
		newDisplay := normalizeIndexValue(stored.DisplayName)
		usernameChanged := newUsername != oldUsername
		externalChanged := newExternal != oldExternal
		displayChanged := newDisplay != oldDisplay
		newNameKey, oldNameKey := userKey, userKey
		if usernameChanged {
			newNameKey = s.keys.userNameIndex(newUsername)
			if oldUsername != "" {
				oldNameKey = s.keys.userNameIndex(oldUsername)
			}
		}
		newExternalKey, oldExternalKey := userKey, userKey
		if externalChanged {
			if newExternal != "" {
				newExternalKey = s.keys.userExternalIndex(newExternal)
			}
			if oldExternal != "" {
				oldExternalKey = s.keys.userExternalIndex(oldExternal)
			}
		}
		newDisplayKey, oldDisplayKey := userKey, userKey
		if displayChanged {
			if newDisplay != "" {
				newDisplayKey = s.keys.userDisplayIndex(newDisplay)
			}
			if oldDisplay != "" {
				oldDisplayKey = s.keys.userDisplayIndex(oldDisplay)
			}
		}
		reply, err := s.run(ctx, scriptUserReplace, "replace user", []string{
			userKey,
			s.keys.revision(),
			newNameKey, oldNameKey,
			newExternalKey, oldExternalKey,
			newDisplayKey, oldDisplayKey,
		}, expected, oldTag, string(data), base, user.ID,
			newUsername, newExternal, newDisplay,
			flag(usernameChanged), flag(externalChanged), flag(displayChanged),
			flag(usernameChanged && oldUsername != ""),
			flag(externalChanged && oldExternal != ""),
			flag(displayChanged && oldDisplay != ""))
		if err != nil {
			return nil, err
		}
		switch replyInt(reply, 0) {
		case 0:
			stored.Meta.Version = etagFor(tagFor(base, replyInt(reply, 1)))
			return stored.Clone(), nil
		case 1:
			return nil, errs.Detail(scimlib.ErrNotFound, "User %q not found | User %q 不存在", user.ID, user.ID)
		case 2:
			continue
		case 3:
			return nil, errs.Detail(scimlib.ErrPreconditionFailed, "User %q version changed | User %q 版本已变化", user.ID, user.ID)
		case 4:
			return nil, errs.Detail(scimlib.ErrUniqueness, "userName %q already exists | userName %q 已存在", stored.UserName, stored.UserName)
		default:
			return nil, errs.Detail(scimlib.ErrInternal, "replace user returned an unknown result | 替换用户返回未知结果")
		}
	}
	return nil, errs.Detail(scimlib.ErrConflict, "User %q changed concurrently | User %q 被并发修改", user.ID, user.ID)
}

// DeleteUser removes the stored User with the given identifier. | DeleteUser 移除指定标识的已存储
// User。
//
// The record, its creation order entry and all indexes are removed atomically. A missing
// identifier is reported as scim.ErrNotFound, and repeated compare-and-set contention as
// scim.ErrConflict. | 记录、创建顺序条目与全部索引会原子删除。标识不存在返回 scim.ErrNotFound，
// 反复比较并交换竞争返回 scim.ErrConflict。
func (s *Store) DeleteUser(ctx context.Context, id string) error {
	ctx = contextOrBackground(ctx)
	if err := s.contextError(ctx); err != nil {
		return err
	}
	userKey := s.keys.user(id)
	for attempt := 0; attempt < maxCASRetries; attempt++ {
		values, err := s.client.HMGet(ctx, userKey, "data", "username", "external", "display", "versionTag").Result()
		if err != nil {
			return s.backend("delete user", err)
		}
		if len(values) < 5 || values[0] == nil {
			return errs.Detail(scimlib.ErrNotFound, "User %q not found | User %q 不存在", id, id)
		}
		username := anyString(values[1])
		external := anyString(values[2])
		display := anyString(values[3])
		tag := normalizeETag(anyString(values[4]))
		usernameKey, externalKey, displayKey := userKey, userKey, userKey
		if username != "" {
			usernameKey = s.keys.userNameIndex(username)
		}
		if external != "" {
			externalKey = s.keys.userExternalIndex(external)
		}
		if display != "" {
			displayKey = s.keys.userDisplayIndex(display)
		}
		reply, err := s.run(ctx, scriptUserDelete, "delete user", []string{
			userKey, s.keys.usersOrder(), usernameKey, externalKey, displayKey,
		}, id, tag, flag(username != ""), flag(external != ""), flag(display != ""))
		if err != nil {
			return err
		}
		switch replyInt(reply, 0) {
		case 0:
			return nil
		case 1:
			return errs.Detail(scimlib.ErrNotFound, "User %q not found | User %q 不存在", id, id)
		case 2:
			continue
		default:
			return errs.Detail(scimlib.ErrInternal, "delete user returned an unknown result | 删除用户返回未知结果")
		}
	}
	return errs.Detail(scimlib.ErrConflict, "User %q changed concurrently | User %q 被并发修改", id, id)
}

// ListUsers returns one page of stored Users and the total number of matches.
// | ListUsers 返回一页已存储 User 与匹配总数。
//
// Users are returned in creation order, then filtered, sorted and paged exactly like
// scim.MemoryStore: StartIndex below one becomes one, a negative Count returns every remaining
// match, zero Count returns an empty page, and the total is the number of matches before paging.
// An out-of-range page is an empty non-nil slice and a missing page is never an error.
// | User 先按创建顺序返回，随后与 scim.MemoryStore 完全一致地过滤、排序与分页：StartIndex 小于一视为一，
// 负数 Count 返回剩余全部匹配，零 Count 返回空页，总数是分页前的匹配数。越界页是非 nil 空切片，缺页
// 从不是错误。
func (s *Store) ListUsers(ctx context.Context, query scimlib.ListQuery) ([]*scimlib.User, int, error) {
	ctx = contextOrBackground(ctx)
	if err := s.contextError(ctx); err != nil {
		return nil, 0, err
	}
	ids, err := s.client.ZRange(ctx, s.keys.usersOrder(), 0, -1).Result()
	if err != nil {
		return nil, 0, s.backend("list users", err)
	}
	users := make([]*scimlib.User, 0, len(ids))
	if len(ids) > 0 {
		commands := make([]*goredis.SliceCmd, len(ids))
		if _, err := s.client.Pipelined(ctx, func(pipe goredis.Pipeliner) error {
			for i, id := range ids {
				commands[i] = pipe.HMGet(ctx, s.keys.user(id), "data", "version")
			}
			return nil
		}); err != nil {
			return nil, 0, s.backend("list users", err)
		}
		for i := range ids {
			if commands[i] == nil {
				return nil, 0, errs.Detail(scimlib.ErrInternal, "list users lost a record read | 列出用户时丢失记录读取")
			}
			values, err := commands[i].Result()
			if err != nil {
				return nil, 0, s.backend("list users", err)
			}
			if len(values) < 2 || values[0] == nil {
				continue
			}
			user, err := decodeUser([]byte(anyString(values[0])), anyString(values[1]))
			if err != nil {
				return nil, 0, err
			}
			users = append(users, user)
		}
	}
	if query.Filter != nil {
		matched := users[:0]
		for _, user := range users {
			if query.Filter.Match(user) {
				matched = append(matched, user)
			}
		}
		users = matched
	}
	scimlib.SortUsers(users, query.SortBy, query.SortOrder)
	total := len(users)
	return pageUsers(users, query.StartIndex, query.Count), total, nil
}

// pageUsers slices users according to the SCIM startIndex and count rules.
// | pageUsers 依据 SCIM StartIndex 与 Count 规则切分 users。
func pageUsers(users []*scimlib.User, startIndex, count int) []*scimlib.User {
	start, end := pageBounds(len(users), startIndex, count)
	if start >= end {
		return []*scimlib.User{}
	}
	return users[start:end]
}
