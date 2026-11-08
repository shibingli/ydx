package scim

import (
	"context"
	"errors"
	"strings"

	goredis "github.com/redis/go-redis/v9"

	scimlib "github.com/shibingli/ydx/auth/directory/scim"
	"github.com/shibingli/ydx/errs"
)

// CreateGroup stores group and returns the stored copy. | CreateGroup 保存 group 并返回存储副本。
//
// A caller supplied identifier is preserved for atomic bulk rollback recreation. An empty
// identifier is replaced by a random 32-character hexadecimal one. DisplayName is unique ignoring
// case and surrounding whitespace and a duplicate is reported as scim.ErrUniqueness, while a
// duplicate identifier is reported as scim.ErrConflict. Every member must carry a non-empty Value
// and member Values must be unique, otherwise scim.ErrInvalidValue is returned.
// | 调用方提供的标识会被保留，供批量原子回滚重建使用。空标识会被替换为随机 32 字符十六进制标识。
// DisplayName 在忽略大小写与首尾空白后唯一，重复返回 scim.ErrUniqueness，标识重复返回
// scim.ErrConflict。每个成员必须携带非空 Value 且成员 Value 必须唯一，否则返回 scim.ErrInvalidValue。
func (s *Store) CreateGroup(ctx context.Context, group *scimlib.Group) (*scimlib.Group, error) {
	ctx = contextOrBackground(ctx)
	if err := s.contextError(ctx); err != nil {
		return nil, err
	}
	if group == nil {
		return nil, errs.Detail(scimlib.ErrInvalidValue, "nil Group | Group 为空")
	}
	stored := group.Clone()
	if strings.TrimSpace(stored.DisplayName) == "" {
		return nil, errs.Detail(scimlib.ErrInvalidValue, "displayName is required | displayName 为必需属性")
	}
	if err := validateGroupMembers(stored.Members); err != nil {
		return nil, err
	}
	if stored.ID == "" {
		id, err := newResourceID()
		if err != nil {
			return nil, errs.WrapDetail(err, scimlib.ErrInternal, "cannot generate Group id | 无法生成 Group 标识")
		}
		stored.ID = id
	}
	stored.EnsureSchemas()
	now := s.timestamp()
	stored.Meta = &scimlib.Meta{
		ResourceType: scimlib.ResourceTypeNameGroup,
		Created:      now,
		LastModified: now,
	}
	data, err := encodeGroup(stored)
	if err != nil {
		return nil, err
	}
	base := versionBase(scimlib.ResourceTypeNameGroup, stored.ID)
	display := normalizeIndexValue(stored.DisplayName)
	external := normalizeIndexValue(stored.ExternalID)
	reply, err := s.run(ctx, scriptGroupCreate, "create group", []string{
		s.keys.groupsOrder(),
		s.keys.group(stored.ID),
		s.keys.groupDisplayIndex(display),
		s.keys.groupExternalIndex(external),
		s.keys.groupsSequence(),
		s.keys.revision(),
	}, string(data), base, stored.ID, display, external,
		flag(display != ""), flag(external != ""))
	if err != nil {
		return nil, err
	}
	switch replyInt(reply, 0) {
	case 0:
		stored.Meta.Version = etagFor(tagFor(base, replyInt(reply, 1)))
		return stored.Clone(), nil
	case 1:
		return nil, errs.Detail(scimlib.ErrConflict, "Group %q already exists | Group %q 已存在", stored.ID, stored.ID)
	case 2:
		return nil, errs.Detail(scimlib.ErrUniqueness, "displayName %q already exists | displayName %q 已存在", stored.DisplayName, stored.DisplayName)
	default:
		return nil, errs.Detail(scimlib.ErrInternal, "create group returned an unknown result | 创建组返回未知结果")
	}
}

// GetGroup returns the stored Group with the given identifier. | GetGroup 返回指定标识的已存储
// Group。
//
// The result is a deep copy. A missing identifier is reported as scim.ErrNotFound.
// | 结果是深拷贝。标识不存在返回 scim.ErrNotFound。
func (s *Store) GetGroup(ctx context.Context, id string) (*scimlib.Group, error) {
	ctx = contextOrBackground(ctx)
	if err := s.contextError(ctx); err != nil {
		return nil, err
	}
	values, err := s.client.HMGet(ctx, s.keys.group(id), "data", "version").Result()
	if err != nil {
		return nil, s.backend("get group", err)
	}
	if len(values) < 2 || values[0] == nil {
		return nil, errs.Detail(scimlib.ErrNotFound, "Group %q not found | Group %q 不存在", id, id)
	}
	return decodeGroup([]byte(anyString(values[0])), anyString(values[1]))
}

// GetGroupByDisplayName returns the Group whose displayName matches ignoring case and
// surrounding whitespace. | GetGroupByDisplayName 返回 displayName 在忽略大小写与首尾空白后匹配的
// Group。
//
// A missing name is reported as scim.ErrNotFound. | 名称不存在返回 scim.ErrNotFound。
func (s *Store) GetGroupByDisplayName(ctx context.Context, displayName string) (*scimlib.Group, error) {
	ctx = contextOrBackground(ctx)
	if err := s.contextError(ctx); err != nil {
		return nil, err
	}
	value := normalizeIndexValue(displayName)
	if value == "" {
		return nil, errs.Detail(scimlib.ErrNotFound, "displayName %q not found | displayName %q 不存在", displayName, displayName)
	}
	id, err := s.client.Get(ctx, s.keys.groupDisplayIndex(value)).Result()
	if errors.Is(err, goredis.Nil) {
		return nil, errs.Detail(scimlib.ErrNotFound, "displayName %q not found | displayName %q 不存在", displayName, displayName)
	}
	if err != nil {
		return nil, s.backend("get group by displayName", err)
	}
	if id == "" {
		return nil, errs.Detail(scimlib.ErrNotFound, "displayName %q not found | displayName %q 不存在", displayName, displayName)
	}
	return s.GetGroup(ctx, id)
}

// GetGroupByExternalID returns the oldest Group whose externalId matches ignoring case and
// surrounding whitespace. | GetGroupByExternalID 返回 externalId 在忽略大小写与首尾空白后匹配的最早
// Group。
//
// externalId is not unique: several Groups may share it, and this method returns the first created
// one while ListGroups with a filter returns all of them. A missing value is reported as
// scim.ErrNotFound. | externalId 不唯一：多个 Group 可共享同一值，本方法返回最早创建的一个，而带过滤器
// 的 ListGroups 返回全部。值不存在返回 scim.ErrNotFound。
func (s *Store) GetGroupByExternalID(ctx context.Context, externalID string) (*scimlib.Group, error) {
	ctx = contextOrBackground(ctx)
	if err := s.contextError(ctx); err != nil {
		return nil, err
	}
	value := normalizeIndexValue(externalID)
	if value == "" {
		return nil, errs.Detail(scimlib.ErrNotFound, "externalId %q not found | externalId %q 不存在", externalID, externalID)
	}
	ids, err := s.client.ZRange(ctx, s.keys.groupExternalIndex(value), 0, 0).Result()
	if err != nil {
		return nil, s.backend("get group by externalId", err)
	}
	if len(ids) == 0 {
		return nil, errs.Detail(scimlib.ErrNotFound, "externalId %q not found | externalId %q 不存在", externalID, externalID)
	}
	return s.GetGroup(ctx, ids[0])
}

// ReplaceGroup replaces the stored Group with the same identifier.
// | ReplaceGroup 替换具有相同标识的已存储 Group。
//
// The prior creation instant is preserved, members and all attributes are replaced, and a new
// entity tag is allocated. A missing identifier is reported as scim.ErrNotFound, a duplicate
// displayName as scim.ErrUniqueness, invalid members as scim.ErrInvalidValue and repeated
// compare-and-set contention as scim.ErrConflict. | 保留先前创建时刻，成员与全部属性被替换，并分配新的
// 实体标签。标识不存在返回 scim.ErrNotFound，displayName 重复返回 scim.ErrUniqueness，成员非法返回
// scim.ErrInvalidValue，反复比较并交换竞争返回 scim.ErrConflict。
func (s *Store) ReplaceGroup(ctx context.Context, group *scimlib.Group) (*scimlib.Group, error) {
	return s.replaceGroup(ctx, group, "")
}

// ReplaceGroupIfVersion replaces the stored Group only when its entity tag matches expectedVersion.
// An empty expectedVersion disables the precondition. This is the primitive the SCIM server uses to
// restore a prior group atomically during bulk rollback. | ReplaceGroupIfVersion 仅在已存储 Group 的
// 实体标签匹配 expectedVersion 时替换；expectedVersion 为空时禁用前置条件。SCIM 服务端用它批量回滚
// 时原子恢复先前 Group。
func (s *Store) ReplaceGroupIfVersion(ctx context.Context, group *scimlib.Group, expectedVersion string) (*scimlib.Group, error) {
	return s.replaceGroup(ctx, group, expectedVersion)
}

// replaceGroup implements ReplaceGroup and ReplaceGroupIfVersion. | replaceGroup 实现 ReplaceGroup
// 与 ReplaceGroupIfVersion。
func (s *Store) replaceGroup(ctx context.Context, group *scimlib.Group, expectedVersion string) (*scimlib.Group, error) {
	ctx = contextOrBackground(ctx)
	if err := s.contextError(ctx); err != nil {
		return nil, err
	}
	expected := normalizeETag(expectedVersion)
	if group == nil || group.ID == "" {
		return nil, errs.Detail(scimlib.ErrInvalidValue, "Group id is required | Group 标识为必需")
	}
	if strings.TrimSpace(group.DisplayName) == "" {
		return nil, errs.Detail(scimlib.ErrInvalidValue, "displayName is required | displayName 为必需属性")
	}
	if err := validateGroupMembers(group.Members); err != nil {
		return nil, err
	}
	groupKey := s.keys.group(group.ID)
	base := versionBase(scimlib.ResourceTypeNameGroup, group.ID)
	for attempt := 0; attempt < maxCASRetries; attempt++ {
		values, err := s.client.HMGet(ctx, groupKey, "data", "display", "external", "versionTag").Result()
		if err != nil {
			return nil, s.backend("replace group", err)
		}
		if len(values) < 4 || values[0] == nil {
			return nil, errs.Detail(scimlib.ErrNotFound, "Group %q not found | Group %q 不存在", group.ID, group.ID)
		}
		oldData := anyString(values[0])
		oldDisplay := anyString(values[1])
		oldExternal := anyString(values[2])
		oldTag := normalizeETag(anyString(values[3]))
		if expected != "" && expected != oldTag {
			return nil, errs.Detail(scimlib.ErrPreconditionFailed, "Group %q version changed | Group %q 版本已变化", group.ID, group.ID)
		}
		oldGroup, err := decodeGroup([]byte(oldData), etagFor(oldTag))
		if err != nil {
			return nil, err
		}
		stored := group.Clone()
		stored.EnsureSchemas()
		created := s.timestamp()
		if oldGroup.Meta != nil && oldGroup.Meta.Created != "" {
			created = oldGroup.Meta.Created
		}
		stored.Meta = &scimlib.Meta{
			ResourceType: scimlib.ResourceTypeNameGroup,
			Created:      created,
			LastModified: s.timestamp(),
		}
		data, err := encodeGroup(stored)
		if err != nil {
			return nil, err
		}
		newDisplay := normalizeIndexValue(stored.DisplayName)
		newExternal := normalizeIndexValue(stored.ExternalID)
		displayChanged := newDisplay != oldDisplay
		externalChanged := newExternal != oldExternal
		newDisplayKey, oldDisplayKey := groupKey, groupKey
		if displayChanged {
			newDisplayKey = s.keys.groupDisplayIndex(newDisplay)
			if oldDisplay != "" {
				oldDisplayKey = s.keys.groupDisplayIndex(oldDisplay)
			}
		}
		newExternalKey, oldExternalKey := groupKey, groupKey
		if externalChanged {
			if newExternal != "" {
				newExternalKey = s.keys.groupExternalIndex(newExternal)
			}
			if oldExternal != "" {
				oldExternalKey = s.keys.groupExternalIndex(oldExternal)
			}
		}
		reply, err := s.run(ctx, scriptGroupReplace, "replace group", []string{
			groupKey, s.keys.revision(),
			newDisplayKey, oldDisplayKey,
			newExternalKey, oldExternalKey,
		}, expected, oldTag, string(data), base, group.ID,
			newDisplay, newExternal,
			flag(displayChanged), flag(externalChanged),
			flag(displayChanged && oldDisplay != ""),
			flag(externalChanged && oldExternal != ""))
		if err != nil {
			return nil, err
		}
		switch replyInt(reply, 0) {
		case 0:
			stored.Meta.Version = etagFor(tagFor(base, replyInt(reply, 1)))
			return stored.Clone(), nil
		case 1:
			return nil, errs.Detail(scimlib.ErrNotFound, "Group %q not found | Group %q 不存在", group.ID, group.ID)
		case 2:
			continue
		case 3:
			return nil, errs.Detail(scimlib.ErrPreconditionFailed, "Group %q version changed | Group %q 版本已变化", group.ID, group.ID)
		case 4:
			return nil, errs.Detail(scimlib.ErrUniqueness, "displayName %q already exists | displayName %q 已存在", stored.DisplayName, stored.DisplayName)
		default:
			return nil, errs.Detail(scimlib.ErrInternal, "replace group returned an unknown result | 替换组返回未知结果")
		}
	}
	return nil, errs.Detail(scimlib.ErrConflict, "Group %q changed concurrently | Group %q 被并发修改", group.ID, group.ID)
}

// DeleteGroup removes the stored Group with the given identifier.
// | DeleteGroup 移除指定标识的已存储 Group。
//
// The record, its creation order entry and all indexes are removed atomically. A missing
// identifier is reported as scim.ErrNotFound, and repeated compare-and-set contention as
// scim.ErrConflict. | 记录、创建顺序条目与全部索引会原子删除。标识不存在返回 scim.ErrNotFound，
// 反复比较并交换竞争返回 scim.ErrConflict。
func (s *Store) DeleteGroup(ctx context.Context, id string) error {
	ctx = contextOrBackground(ctx)
	if err := s.contextError(ctx); err != nil {
		return err
	}
	groupKey := s.keys.group(id)
	for attempt := 0; attempt < maxCASRetries; attempt++ {
		values, err := s.client.HMGet(ctx, groupKey, "data", "display", "external", "versionTag").Result()
		if err != nil {
			return s.backend("delete group", err)
		}
		if len(values) < 4 || values[0] == nil {
			return errs.Detail(scimlib.ErrNotFound, "Group %q not found | Group %q 不存在", id, id)
		}
		display := anyString(values[1])
		external := anyString(values[2])
		tag := normalizeETag(anyString(values[3]))
		displayKey, externalKey := groupKey, groupKey
		if display != "" {
			displayKey = s.keys.groupDisplayIndex(display)
		}
		if external != "" {
			externalKey = s.keys.groupExternalIndex(external)
		}
		reply, err := s.run(ctx, scriptGroupDelete, "delete group", []string{
			groupKey, s.keys.groupsOrder(), displayKey, externalKey,
		}, id, tag, flag(display != ""), flag(external != ""))
		if err != nil {
			return err
		}
		switch replyInt(reply, 0) {
		case 0:
			return nil
		case 1:
			return errs.Detail(scimlib.ErrNotFound, "Group %q not found | Group %q 不存在", id, id)
		case 2:
			continue
		default:
			return errs.Detail(scimlib.ErrInternal, "delete group returned an unknown result | 删除组返回未知结果")
		}
	}
	return errs.Detail(scimlib.ErrConflict, "Group %q changed concurrently | Group %q 被并发修改", id, id)
}

// ListGroups returns one page of stored Groups and the total number of matches.
// | ListGroups 返回一页已存储 Group 与匹配总数。
//
// Groups are returned in creation order, then filtered, sorted and paged exactly like
// scim.MemoryStore: StartIndex below one becomes one, a negative Count returns every remaining
// match, zero Count returns an empty page, and the total is the number of matches before paging.
// An out-of-range page is an empty non-nil slice. | Group 先按创建顺序返回，随后与 scim.MemoryStore
// 完全一致地过滤、排序与分页：StartIndex 小于一视为一，负数 Count 返回剩余全部匹配，零 Count 返回空页，
// 总数是分页前的匹配数。越界页是非 nil 空切片。
func (s *Store) ListGroups(ctx context.Context, query scimlib.ListQuery) ([]*scimlib.Group, int, error) {
	ctx = contextOrBackground(ctx)
	if err := s.contextError(ctx); err != nil {
		return nil, 0, err
	}
	ids, err := s.client.ZRange(ctx, s.keys.groupsOrder(), 0, -1).Result()
	if err != nil {
		return nil, 0, s.backend("list groups", err)
	}
	groups := make([]*scimlib.Group, 0, len(ids))
	if len(ids) > 0 {
		commands := make([]*goredis.SliceCmd, len(ids))
		if _, err := s.client.Pipelined(ctx, func(pipe goredis.Pipeliner) error {
			for i, id := range ids {
				commands[i] = pipe.HMGet(ctx, s.keys.group(id), "data", "version")
			}
			return nil
		}); err != nil {
			return nil, 0, s.backend("list groups", err)
		}
		for i := range ids {
			if commands[i] == nil {
				return nil, 0, errs.Detail(scimlib.ErrInternal, "list groups lost a record read | 列出组时丢失记录读取")
			}
			values, err := commands[i].Result()
			if err != nil {
				return nil, 0, s.backend("list groups", err)
			}
			if len(values) < 2 || values[0] == nil {
				continue
			}
			group, err := decodeGroup([]byte(anyString(values[0])), anyString(values[1]))
			if err != nil {
				return nil, 0, err
			}
			groups = append(groups, group)
		}
	}
	if query.Filter != nil {
		matched := groups[:0]
		for _, group := range groups {
			if query.Filter.Match(group) {
				matched = append(matched, group)
			}
		}
		groups = matched
	}
	scimlib.SortGroups(groups, query.SortBy, query.SortOrder)
	total := len(groups)
	return pageGroups(groups, query.StartIndex, query.Count), total, nil
}

// pageGroups slices groups according to the SCIM startIndex and count rules.
// | pageGroups 依据 SCIM StartIndex 与 Count 规则切分 groups。
func pageGroups(groups []*scimlib.Group, startIndex, count int) []*scimlib.Group {
	start, end := pageBounds(len(groups), startIndex, count)
	if start >= end {
		return []*scimlib.Group{}
	}
	return groups[start:end]
}

// validateGroupMembers checks that every member has a value and that member values are unique.
// | validateGroupMembers 检查每个成员都具有 value 且成员 value 唯一。
func validateGroupMembers(members []scimlib.GroupMember) error {
	seen := make(map[string]bool, len(members))
	for i := range members {
		if strings.TrimSpace(members[i].Value) == "" {
			return errs.Detail(scimlib.ErrInvalidValue, "member value is required | 成员 value 为必需")
		}
		if seen[members[i].Value] {
			return errs.Detail(scimlib.ErrInvalidValue, "member %q is duplicated | 成员 %q 重复", members[i].Value, members[i].Value)
		}
		seen[members[i].Value] = true
	}
	return nil
}
