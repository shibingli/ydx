package scim

import (
	"context"
	"hash/fnv"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shibingli/ydx/errs"
)

// ListQuery is the normalized RFC 7644 section 3.4.2 list and search query. | ListQuery 是规范化
// 后的 RFC 7644 第 3.4.2 节列表与搜索查询。
type ListQuery struct {
	// Filter selects matching resources; nil selects all. | Filter 选择匹配资源；nil 表示全部。
	Filter Filter
	// SortBy is the attribute path used for sorting; empty uses the resource default. | SortBy 是
	// 排序使用的属性路径；空值使用资源默认属性。
	SortBy string
	// SortOrder is the sort direction; empty means ascending. | SortOrder 是排序方向；空值表示升序。
	SortOrder SortOrder
	// StartIndex is the 1-based first result index. | StartIndex 是 1 基的首个结果索引。
	StartIndex int
	// Count is the page size. A negative value returns every remaining result and zero returns no
	// resources while still reporting totalResults. | Count 是分页大小。负值返回余下全部结果，
	// 零值不返回资源但仍报告 totalResults。
	Count int
}

// Store persists SCIM User and Group resources. Implementations must return deep copies so callers
// cannot mutate stored state. Atomic bulk rollback recreates deleted resources through CreateUser
// and CreateGroup with the original identifier, and restores replaced resources through ReplaceUser
// and ReplaceGroup, so implementations should honor a caller-supplied identifier on create and
// treat replacement as an idempotent upsert of that identifier. A store that assigns new
// identifiers on create cannot preserve the original resource identifier during rollback. | Store
// 持久化 SCIM User 与 Group 资源。实现必须返回深拷贝，避免调用方修改存储状态。原子批量回滚通过
// CreateUser 与 CreateGroup 以原始标识重建已删除资源，并通过 ReplaceUser 与 ReplaceGroup 恢复被替换
// 的资源，因此实现应在创建时保留调用方提供的标识，并把替换视为该标识的幂等写入。创建时总是分配新
// 标识的存储在回滚期间无法保留原始资源标识。
type Store interface {
	// CreateUser stores a new User and returns the stored copy. | CreateUser 保存新 User 并返回
	// 存储副本。
	CreateUser(ctx context.Context, user *User) (*User, error)
	// GetUser returns the User with the given identifier. | GetUser 返回指定标识的 User。
	GetUser(ctx context.Context, id string) (*User, error)
	// ReplaceUser replaces the stored User with the same identifier. | ReplaceUser 替换具有相同标识
	// 的已存储 User。
	ReplaceUser(ctx context.Context, user *User) (*User, error)
	// DeleteUser removes the User with the given identifier. | DeleteUser 移除指定标识的 User。
	DeleteUser(ctx context.Context, id string) error
	// ListUsers returns one page of Users and the total number of matches. | ListUsers 返回一页
	// User 与匹配总数。
	ListUsers(ctx context.Context, query ListQuery) ([]*User, int, error)
	// CreateGroup stores a new Group and returns the stored copy. | CreateGroup 保存新 Group 并返回
	// 存储副本。
	CreateGroup(ctx context.Context, group *Group) (*Group, error)
	// GetGroup returns the Group with the given identifier. | GetGroup 返回指定标识的 Group。
	GetGroup(ctx context.Context, id string) (*Group, error)
	// ReplaceGroup replaces the stored Group with the same identifier. | ReplaceGroup 替换具有相同
	// 标识的已存储 Group。
	ReplaceGroup(ctx context.Context, group *Group) (*Group, error)
	// DeleteGroup removes the Group with the given identifier. | DeleteGroup 移除指定标识的 Group。
	DeleteGroup(ctx context.Context, id string) error
	// ListGroups returns one page of Groups and the total number of matches. | ListGroups 返回一页
	// Group 与匹配总数。
	ListGroups(ctx context.Context, query ListQuery) ([]*Group, int, error)
}

// UserVersionReplacer is an optional Store extension that replaces a User only when the stored
// entity tag still equals expectedVersion. The server uses it to compensate a failed password
// provisioning without overwriting a concurrent change. An empty expectedVersion disables the
// precondition. Implementations should return ErrPreconditionFailed when the tags differ. |
// UserVersionReplacer 是可选 Store 扩展，仅当已存储实体标签仍等于 expectedVersion 时替换 User。
// 服务端用它补偿失败的口令预配，同时不覆盖并发修改。expectedVersion 为空时禁用前置条件。实现应在
// 标签不同时返回 ErrPreconditionFailed。
type UserVersionReplacer interface {
	// ReplaceUserIfVersion replaces the User when its current entity tag matches expectedVersion.
	// | ReplaceUserIfVersion 在当前实体标签匹配 expectedVersion 时替换 User。
	ReplaceUserIfVersion(ctx context.Context, user *User, expectedVersion string) (*User, error)
}

// MemoryStore is a concurrency-safe in-memory Store. It keeps creation order so pagination is
// deterministic. | MemoryStore 是并发安全的内存 Store。它保留创建顺序，使分页结果确定。
type MemoryStore struct {
	// users indexes stored users by identifier. | users 按标识索引已存储用户。
	users map[string]*User
	// groups indexes stored groups by identifier. | groups 按标识索引已存储组。
	groups map[string]*Group
	// userNames and groupNames enforce case-insensitive unique names. | userNames 与 groupNames
	// 实施大小写不敏感的唯一名称约束。
	userNames  map[string]string
	groupNames map[string]string
	// now returns the current time and is replaceable in tests. | now 返回当前时间，可在测试中替换。
	now func() time.Time
	// userOrder and groupOrder preserve creation order. | userOrder 与 groupOrder 保留创建顺序。
	userOrder  []string
	groupOrder []string
	// revision produces a new entity tag for every mutation. | revision 为每次变更生成新的实体标签。
	revision uint64
	// mu guards every field below. | mu 保护以下所有字段。
	mu sync.RWMutex
}

// NewMemoryStore returns an empty MemoryStore. | NewMemoryStore 返回空的 MemoryStore。
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		users:      make(map[string]*User),
		groups:     make(map[string]*Group),
		userNames:  make(map[string]string),
		groupNames: make(map[string]string),
		now:        func() time.Time { return time.Now().UTC() },
	}
}

// CreateUser stores user and returns the stored copy. | CreateUser 保存 user 并返回存储副本。
func (s *MemoryStore) CreateUser(ctx context.Context, user *User) (*User, error) {
	if err := storeContextError(ctx); err != nil {
		return nil, err
	}
	if user == nil {
		return nil, errs.Detail(ErrInvalidValue, "nil User | User 为空")
	}
	stored := user.Clone()
	if strings.TrimSpace(stored.UserName) == "" {
		return nil, errs.Detail(ErrInvalidValue, "userName is required | userName 为必需属性")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if stored.ID == "" {
		id, err := newResourceID()
		if err != nil {
			return nil, errs.WrapDetail(err, ErrInternal, "cannot generate User id | 无法生成 User 标识")
		}
		stored.ID = id
	}
	if _, exists := s.users[stored.ID]; exists {
		return nil, errs.Detail(ErrConflict, "User %q already exists | User %q 已存在", stored.ID, stored.ID)
	}
	nameKey := strings.ToLower(strings.TrimSpace(stored.UserName))
	if _, exists := s.userNames[nameKey]; exists {
		return nil, errs.Detail(ErrUniqueness, "userName %q already exists | userName %q 已存在", stored.UserName, stored.UserName)
	}
	stored.EnsureSchemas()
	if stored.Active == nil {
		stored.SetActive(true)
	}
	now := formatTime(s.now())
	stored.Meta = &Meta{
		ResourceType: ResourceTypeNameUser,
		Created:      now,
		LastModified: now,
		Version:      s.nextVersionLocked(ResourceTypeNameUser, stored.ID),
	}
	s.users[stored.ID] = stored.Clone()
	s.userOrder = append(s.userOrder, stored.ID)
	s.userNames[nameKey] = stored.ID
	return stored.Clone(), nil
}

// GetUser returns the stored User with the given identifier. | GetUser 返回指定标识的已存储 User。
func (s *MemoryStore) GetUser(ctx context.Context, id string) (*User, error) {
	if err := storeContextError(ctx); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, ok := s.users[id]
	if !ok {
		return nil, errs.Detail(ErrNotFound, "User %q not found | User %q 不存在", id, id)
	}
	return user.Clone(), nil
}

// ReplaceUser replaces the stored User with the same identifier. | ReplaceUser 替换具有相同标识的
// 已存储 User。
func (s *MemoryStore) ReplaceUser(ctx context.Context, user *User) (*User, error) {
	return s.replaceUser(ctx, user, "")
}

// ReplaceUserIfVersion replaces the stored User only when its entity tag matches expectedVersion.
// An empty expectedVersion disables the precondition. | ReplaceUserIfVersion 仅在已存储 User 的实体
// 标签匹配 expectedVersion 时替换它。expectedVersion 为空时禁用前置条件。
func (s *MemoryStore) ReplaceUserIfVersion(ctx context.Context, user *User, expectedVersion string) (*User, error) {
	return s.replaceUser(ctx, user, expectedVersion)
}

// replaceUser implements ReplaceUser and ReplaceUserIfVersion. | replaceUser 实现 ReplaceUser 与
// ReplaceUserIfVersion。
func (s *MemoryStore) replaceUser(ctx context.Context, user *User, expectedVersion string) (*User, error) {
	if err := storeContextError(ctx); err != nil {
		return nil, err
	}
	if user == nil || user.ID == "" {
		return nil, errs.Detail(ErrInvalidValue, "User id is required | User 标识为必需")
	}
	stored := user.Clone()
	if strings.TrimSpace(stored.UserName) == "" {
		return nil, errs.Detail(ErrInvalidValue, "userName is required | userName 为必需属性")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.users[stored.ID]
	if !ok {
		return nil, errs.Detail(ErrNotFound, "User %q not found | User %q 不存在", stored.ID, stored.ID)
	}
	if expectedVersion != "" && normalizeETag(userVersion(existing)) != normalizeETag(expectedVersion) {
		return nil, errs.Detail(ErrPreconditionFailed, "User %q version changed | User %q 版本已变化",
			stored.ID, stored.ID)
	}
	nameKey := strings.ToLower(strings.TrimSpace(stored.UserName))
	if owner, exists := s.userNames[nameKey]; exists && owner != stored.ID {
		return nil, errs.Detail(ErrUniqueness, "userName %q already exists | userName %q 已存在", stored.UserName, stored.UserName)
	}
	stored.EnsureSchemas()
	if stored.Active == nil {
		stored.SetActive(true)
	}
	created := ""
	if existing.Meta != nil {
		created = existing.Meta.Created
	}
	if created == "" {
		created = formatTime(s.now())
	}
	stored.Meta = &Meta{
		ResourceType: ResourceTypeNameUser,
		Created:      created,
		LastModified: formatTime(s.now()),
		Version:      s.nextVersionLocked(ResourceTypeNameUser, stored.ID),
	}
	oldKey := strings.ToLower(strings.TrimSpace(existing.UserName))
	if oldKey != nameKey {
		delete(s.userNames, oldKey)
		s.userNames[nameKey] = stored.ID
	}
	s.users[stored.ID] = stored.Clone()
	return stored.Clone(), nil
}

// DeleteUser removes the stored User with the given identifier. | DeleteUser 移除指定标识的已存储
// User。
func (s *MemoryStore) DeleteUser(ctx context.Context, id string) error {
	if err := storeContextError(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[id]
	if !ok {
		return errs.Detail(ErrNotFound, "User %q not found | User %q 不存在", id, id)
	}
	delete(s.userNames, strings.ToLower(strings.TrimSpace(user.UserName)))
	delete(s.users, id)
	s.userOrder = removeOrderID(s.userOrder, id)
	return nil
}

// ListUsers returns one page of stored Users and the total number of matches. | ListUsers 返回一页
// 已存储 User 与匹配总数。
func (s *MemoryStore) ListUsers(ctx context.Context, query ListQuery) ([]*User, int, error) {
	if err := storeContextError(ctx); err != nil {
		return nil, 0, err
	}
	s.mu.RLock()
	users := make([]*User, 0, len(s.users))
	for _, id := range s.userOrder {
		if user, ok := s.users[id]; ok {
			users = append(users, user.Clone())
		}
	}
	s.mu.RUnlock()
	if query.Filter != nil {
		matched := users[:0]
		for _, user := range users {
			if query.Filter.Match(user) {
				matched = append(matched, user)
			}
		}
		users = matched
	}
	SortUsers(users, query.SortBy, query.SortOrder)
	total := len(users)
	page := pageUsers(users, query.StartIndex, query.Count)
	return page, total, nil
}

// CreateGroup stores group and returns the stored copy. | CreateGroup 保存 group 并返回存储副本。
func (s *MemoryStore) CreateGroup(ctx context.Context, group *Group) (*Group, error) {
	if err := storeContextError(ctx); err != nil {
		return nil, err
	}
	if group == nil {
		return nil, errs.Detail(ErrInvalidValue, "nil Group | Group 为空")
	}
	stored := group.Clone()
	if strings.TrimSpace(stored.DisplayName) == "" {
		return nil, errs.Detail(ErrInvalidValue, "displayName is required | displayName 为必需属性")
	}
	if err := validateGroupMembers(stored.Members); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if stored.ID == "" {
		id, err := newResourceID()
		if err != nil {
			return nil, errs.WrapDetail(err, ErrInternal, "cannot generate Group id | 无法生成 Group 标识")
		}
		stored.ID = id
	}
	if _, exists := s.groups[stored.ID]; exists {
		return nil, errs.Detail(ErrConflict, "Group %q already exists | Group %q 已存在", stored.ID, stored.ID)
	}
	nameKey := strings.ToLower(strings.TrimSpace(stored.DisplayName))
	if _, exists := s.groupNames[nameKey]; exists {
		return nil, errs.Detail(ErrUniqueness, "displayName %q already exists | displayName %q 已存在", stored.DisplayName, stored.DisplayName)
	}
	stored.EnsureSchemas()
	now := formatTime(s.now())
	stored.Meta = &Meta{
		ResourceType: ResourceTypeNameGroup,
		Created:      now,
		LastModified: now,
		Version:      s.nextVersionLocked(ResourceTypeNameGroup, stored.ID),
	}
	s.groups[stored.ID] = stored.Clone()
	s.groupOrder = append(s.groupOrder, stored.ID)
	s.groupNames[nameKey] = stored.ID
	return stored.Clone(), nil
}

// GetGroup returns the stored Group with the given identifier. | GetGroup 返回指定标识的已存储
// Group。
func (s *MemoryStore) GetGroup(ctx context.Context, id string) (*Group, error) {
	if err := storeContextError(ctx); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	group, ok := s.groups[id]
	if !ok {
		return nil, errs.Detail(ErrNotFound, "Group %q not found | Group %q 不存在", id, id)
	}
	return group.Clone(), nil
}

// ReplaceGroup replaces the stored Group with the same identifier. | ReplaceGroup 替换具有相同标识
// 的已存储 Group。
func (s *MemoryStore) ReplaceGroup(ctx context.Context, group *Group) (*Group, error) {
	if err := storeContextError(ctx); err != nil {
		return nil, err
	}
	if group == nil || group.ID == "" {
		return nil, errs.Detail(ErrInvalidValue, "Group id is required | Group 标识为必需")
	}
	stored := group.Clone()
	if strings.TrimSpace(stored.DisplayName) == "" {
		return nil, errs.Detail(ErrInvalidValue, "displayName is required | displayName 为必需属性")
	}
	if err := validateGroupMembers(stored.Members); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.groups[stored.ID]
	if !ok {
		return nil, errs.Detail(ErrNotFound, "Group %q not found | Group %q 不存在", stored.ID, stored.ID)
	}
	nameKey := strings.ToLower(strings.TrimSpace(stored.DisplayName))
	if owner, exists := s.groupNames[nameKey]; exists && owner != stored.ID {
		return nil, errs.Detail(ErrUniqueness, "displayName %q already exists | displayName %q 已存在", stored.DisplayName, stored.DisplayName)
	}
	stored.EnsureSchemas()
	created := ""
	if existing.Meta != nil {
		created = existing.Meta.Created
	}
	if created == "" {
		created = formatTime(s.now())
	}
	stored.Meta = &Meta{
		ResourceType: ResourceTypeNameGroup,
		Created:      created,
		LastModified: formatTime(s.now()),
		Version:      s.nextVersionLocked(ResourceTypeNameGroup, stored.ID),
	}
	oldKey := strings.ToLower(strings.TrimSpace(existing.DisplayName))
	if oldKey != nameKey {
		delete(s.groupNames, oldKey)
		s.groupNames[nameKey] = stored.ID
	}
	s.groups[stored.ID] = stored.Clone()
	return stored.Clone(), nil
}

// DeleteGroup removes the stored Group with the given identifier. | DeleteGroup 移除指定标识的已
// 存储 Group。
func (s *MemoryStore) DeleteGroup(ctx context.Context, id string) error {
	if err := storeContextError(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	group, ok := s.groups[id]
	if !ok {
		return errs.Detail(ErrNotFound, "Group %q not found | Group %q 不存在", id, id)
	}
	delete(s.groupNames, strings.ToLower(strings.TrimSpace(group.DisplayName)))
	delete(s.groups, id)
	s.groupOrder = removeOrderID(s.groupOrder, id)
	return nil
}

// ListGroups returns one page of stored Groups and the total number of matches. | ListGroups 返回
// 一页已存储 Group 与匹配总数。
func (s *MemoryStore) ListGroups(ctx context.Context, query ListQuery) ([]*Group, int, error) {
	if err := storeContextError(ctx); err != nil {
		return nil, 0, err
	}
	s.mu.RLock()
	groups := make([]*Group, 0, len(s.groups))
	for _, id := range s.groupOrder {
		if group, ok := s.groups[id]; ok {
			groups = append(groups, group.Clone())
		}
	}
	s.mu.RUnlock()
	if query.Filter != nil {
		matched := groups[:0]
		for _, group := range groups {
			if query.Filter.Match(group) {
				matched = append(matched, group)
			}
		}
		groups = matched
	}
	SortGroups(groups, query.SortBy, query.SortOrder)
	total := len(groups)
	page := pageGroups(groups, query.StartIndex, query.Count)
	return page, total, nil
}

// nextVersionLocked allocates the next entity tag. The caller must hold s.mu. | nextVersionLocked
// 分配下一个实体标签。调用方必须持有 s.mu。
func (s *MemoryStore) nextVersionLocked(resourceType, id string) string {
	s.revision++
	return resourceVersion(resourceType, id, s.revision)
}

// resourceVersion renders a weak entity tag from resource type, identifier and revision. |
// resourceVersion 依据资源类型、标识与修订号渲染弱实体标签。
func resourceVersion(resourceType, id string, revision uint64) string {
	hasher := fnv.New64a()
	hasher.Write([]byte(resourceType))
	hasher.Write([]byte{0})
	hasher.Write([]byte(id))
	hasher.Write([]byte{0})
	hasher.Write([]byte(strconv.FormatUint(revision, 10)))
	return `W/"` + strconv.FormatUint(hasher.Sum64(), 16) + `"`
}

// storeContextError converts a canceled context into a store error. | storeContextError 把已取消
// 的上下文转换为存储错误。
func storeContextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return errs.WrapDetail(err, ErrStoreUnavailable, "request context ended | 请求上下文已结束")
	}
	return nil
}

// validateGroupMembers checks that every member has a value. | validateGroupMembers 检查每个成员都
// 具有 value。
func validateGroupMembers(members []GroupMember) error {
	seen := make(map[string]bool, len(members))
	for i := range members {
		if strings.TrimSpace(members[i].Value) == "" {
			return errs.Detail(ErrInvalidValue, "member value is required | 成员 value 为必需")
		}
		if seen[members[i].Value] {
			return errs.Detail(ErrInvalidValue, "member %q is duplicated | 成员 %q 重复", members[i].Value, members[i].Value)
		}
		seen[members[i].Value] = true
	}
	return nil
}

// removeOrderID removes id from order. | removeOrderID 从 order 移除 id。
func removeOrderID(order []string, id string) []string {
	out := order[:0]
	for _, item := range order {
		if item != id {
			out = append(out, item)
		}
	}
	return out
}

// pageUsers slices users according to the SCIM startIndex and count rules. | pageUsers 依据 SCIM
// startIndex 与 count 规则切分 users。
func pageUsers(users []*User, startIndex, count int) []*User {
	start, end := pageBounds(len(users), startIndex, count)
	if start >= end {
		return []*User{}
	}
	return users[start:end]
}

// pageGroups slices groups according to the SCIM startIndex and count rules. | pageGroups 依据 SCIM
// startIndex 与 count 规则切分 groups。
func pageGroups(groups []*Group, startIndex, count int) []*Group {
	start, end := pageBounds(len(groups), startIndex, count)
	if start >= end {
		return []*Group{}
	}
	return groups[start:end]
}

// pageBounds computes the zero-based slice bounds for a SCIM page. | pageBounds 计算 SCIM 分页的
// 零基切片边界。
func pageBounds(total, startIndex, count int) (int, int) {
	start := startIndex
	if start < 1 {
		start = 1
	}
	if start > total {
		return total, total
	}
	begin := start - 1
	if count < 0 {
		return begin, total
	}
	end := begin + count
	if end > total {
		end = total
	}
	return begin, end
}
