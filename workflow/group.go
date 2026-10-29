package workflow

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
)

// Group is a workflow-owned approval group. A group carries its own members and may additionally
// be linked to one yd role, in which case every holder of that role is an implicit member. |
// Group 是流程自有的审批组。组拥有自己的成员，并可额外关联一个 yd 角色；关联后该角色的全部持有者
// 都是隐式成员。
type Group struct {
	// CreatedAt is the UTC creation instant. | CreatedAt 是 UTC 创建时刻。
	CreatedAt time.Time `json:"created_at" gorm:"column:created_at;autoCreateTime"`
	// UpdatedAt is the UTC last-write instant. | UpdatedAt 是 UTC 最后写入时刻。
	UpdatedAt time.Time `json:"updated_at" gorm:"column:updated_at;autoUpdateTime"`
	// ID is the primary key, prefixed "wfgrp_". | ID 是主键，前缀为 wfgrp_。
	ID string `json:"id" gorm:"column:id;type:varchar(64);primaryKey"`
	// TenantID is the owning tenant. | TenantID 是归属租户。
	TenantID string `json:"tenant_id" gorm:"column:tenant_id;type:varchar(64);not null;uniqueIndex:uidx_wf_group_key,priority:1;index:idx_wf_group_tenant_status_updated,priority:1"`
	// Key is the immutable group key referenced by a design. | Key 是设计引用的不可变组键。
	Key string `json:"key" gorm:"column:group_key;type:varchar(64);not null;uniqueIndex:uidx_wf_group_key,priority:2"`
	// Name is the Chinese display name. | Name 是中文展示名。
	Name string `json:"name" gorm:"column:name;type:varchar(120);not null"`
	// NameEN is the English display name. | NameEN 是英文展示名。
	NameEN string `json:"name_en,omitempty" gorm:"column:name_en;type:varchar(120)"`
	// Description explains the group's purpose. | Description 说明组用途。
	Description string `json:"description,omitempty" gorm:"column:description;type:varchar(500)"`
	// Role links the group to a yd role name; empty means no role link. | Role 把组关联到 yd 角色名；
	// 空表示没有角色关联。
	Role string `json:"role,omitempty" gorm:"column:linked_role;type:varchar(120)"`
	// Status is enabled or disabled. | Status 取 enabled 或 disabled。
	Status string `json:"status" gorm:"column:status;type:varchar(16);not null;index:idx_wf_group_tenant_status_updated,priority:2"`
	// MemberCount is a query projection, not a column. | MemberCount 是查询投影，不是表列。
	MemberCount int `json:"member_count" gorm:"-"`
}

// TableName pins the table name. | TableName 固定表名。
func (Group) TableName() string { return "yd_workflow_groups" }

// GroupMember is one explicit member of a workflow group. | GroupMember 是流程组的一名显式成员。
type GroupMember struct {
	// CreatedAt is the UTC creation instant. | CreatedAt 是 UTC 创建时刻。
	CreatedAt time.Time `json:"created_at" gorm:"column:created_at;autoCreateTime"`
	// ID is the primary key, prefixed "wfgpm_". A string key avoids dialect-specific identity
	// columns. | ID 是主键，前缀为 wfgpm_。字符串主键避免方言相关的自增列。
	ID string `json:"id" gorm:"column:id;type:varchar(64);primaryKey"`
	// TenantID is the owning tenant. | TenantID 是归属租户。
	TenantID string `json:"tenant_id" gorm:"column:tenant_id;type:varchar(64);not null;uniqueIndex:uidx_wf_group_member,priority:1;index:idx_wf_group_member_user,priority:1"`
	// GroupID is the owning group. | GroupID 是所属组。
	GroupID string `json:"group_id" gorm:"column:group_id;type:varchar(64);not null;uniqueIndex:uidx_wf_group_member,priority:2;index:idx_wf_group_member_user,priority:2"`
	// UserID is the member user id. | UserID 是成员用户 ID。
	UserID string `json:"user_id" gorm:"column:user_id;type:varchar(64);not null;uniqueIndex:uidx_wf_group_member,priority:3;index:idx_wf_group_member_user,priority:3"`
	// UserName is the display name at membership time. | UserName 是加入时的展示名。
	UserName string `json:"user_name,omitempty" gorm:"column:user_name;type:varchar(120)"`
}

// TableName pins the table name. | TableName 固定表名。
func (GroupMember) TableName() string { return "yd_workflow_group_members" }

// GroupInput is the editable payload of a group. | GroupInput 是组的可编辑载荷。
type GroupInput struct {
	// Key is required on creation and ignored on update. | Key 在创建时必填，更新时忽略。
	Key string
	// Name is the Chinese display name. | Name 是中文展示名。
	Name string
	// NameEN is the English display name. | NameEN 是英文展示名。
	NameEN string
	// Description explains the group. | Description 说明组用途。
	Description string
	// Role links the group to a yd role. | Role 把组关联到 yd 角色。
	Role string
	// Status is enabled or disabled; empty means enabled. | Status 取 enabled 或 disabled；空表示启用。
	Status string
}

// GroupFilter selects one page of groups. | GroupFilter 选择一页组。
type GroupFilter struct {
	// Query matches key, Chinese name and English name. | Query 匹配键、中文名与英文名。
	Query string
	// Status narrows to one lifecycle state. | Status 限定一个生命周期状态。
	Status string
	// Page and PageSize are 1-based. | Page 与 PageSize 从 1 开始。
	Page     int
	PageSize int
}

// GroupPage is one page of groups. | GroupPage 是一页组。
type GroupPage struct {
	// Items are the rows in this page. | Items 是本页记录。
	Items []Group `json:"items"`
	// Total is the number of matching groups. | Total 是匹配总数。
	Total int `json:"total"`
	// Page and PageSize echo the effective paging. | Page 与 PageSize 回显生效的分页。
	Page     int `json:"page"`
	PageSize int `json:"page_size"`
}

// CreateGroup inserts one workflow group. | CreateGroup 插入一个流程组。
func (s *Service) CreateGroup(ctx context.Context, tenantID string, in GroupInput) (Group, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return Group{}, ErrInvalidInput
	}
	in, err := s.normalizeGroupInput(in, true)
	if err != nil {
		return Group{}, err
	}
	if _, err := s.store.GetGroupByKey(ctx, tenantID, in.Key); err == nil {
		return Group{}, ErrConflict
	} else if !isNotFound(err) {
		return Group{}, err
	}
	id, err := s.options.NewID("wfgrp_")
	if err != nil {
		return Group{}, errs.Wrap(err, ErrUnavailable)
	}
	now := s.now()
	group := Group{
		CreatedAt:   now,
		UpdatedAt:   now,
		ID:          id,
		TenantID:    tenantID,
		Key:         in.Key,
		Name:        in.Name,
		NameEN:      in.NameEN,
		Description: in.Description,
		Role:        in.Role,
		Status:      in.Status,
	}
	if err := s.store.CreateGroup(ctx, group); err != nil {
		return Group{}, err
	}
	return group, nil
}

// UpdateGroup replaces the editable fields of one group. | UpdateGroup 覆盖组的可编辑字段。
func (s *Service) UpdateGroup(ctx context.Context, tenantID, id string, in GroupInput) (Group, error) {
	tenantID = strings.TrimSpace(tenantID)
	id = strings.TrimSpace(id)
	if tenantID == "" || id == "" {
		return Group{}, ErrInvalidInput
	}
	current, err := s.store.GetGroup(ctx, tenantID, id)
	if err != nil {
		return Group{}, err
	}
	if in.Status == "" {
		in.Status = current.Status
	}
	in, err = s.normalizeGroupInput(in, false)
	if err != nil {
		return Group{}, err
	}
	current.Name = in.Name
	current.NameEN = in.NameEN
	current.Description = in.Description
	current.Role = in.Role
	current.Status = in.Status
	current.UpdatedAt = s.now()
	if err := s.store.UpdateGroup(ctx, current); err != nil {
		return Group{}, err
	}
	return current, nil
}

// DeleteGroup removes one group and its explicit members. Running assignments are unaffected
// because a task keeps its resolved assignee. | DeleteGroup 删除一个组及其显式成员。运行中的指派不受影响，
// 因为任务保存的是解析后的处理人。
func (s *Service) DeleteGroup(ctx context.Context, tenantID, id string) error {
	tenantID = strings.TrimSpace(tenantID)
	id = strings.TrimSpace(id)
	if tenantID == "" || id == "" {
		return ErrInvalidInput
	}
	if _, err := s.store.GetGroup(ctx, tenantID, id); err != nil {
		return err
	}
	return s.store.DeleteGroup(ctx, tenantID, id)
}

// GetGroup reads one group. | GetGroup 读取一个组。
func (s *Service) GetGroup(ctx context.Context, tenantID, id string) (Group, error) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(id) == "" {
		return Group{}, ErrInvalidInput
	}
	return s.store.GetGroup(ctx, strings.TrimSpace(tenantID), strings.TrimSpace(id))
}

// GetGroupByKey reads one group by its key. | GetGroupByKey 按键读取一个组。
func (s *Service) GetGroupByKey(ctx context.Context, tenantID, key string) (Group, error) {
	tenantID = strings.TrimSpace(tenantID)
	key = strings.ToLower(strings.TrimSpace(key))
	if tenantID == "" || !keyRe.MatchString(key) {
		return Group{}, ErrInvalidInput
	}
	return s.store.GetGroupByKey(ctx, tenantID, key)
}

// ListGroups returns one page of groups. | ListGroups 返回一页组。
func (s *Service) ListGroups(ctx context.Context, tenantID string, filter GroupFilter) (GroupPage, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return GroupPage{}, ErrInvalidInput
	}
	filter.Query = strings.TrimSpace(filter.Query)
	filter.Page, filter.PageSize = s.page(filter.Page, filter.PageSize)
	items, total, err := s.store.ListGroups(ctx, tenantID, filter)
	if err != nil {
		return GroupPage{}, err
	}
	return GroupPage{Items: items, Total: total, Page: filter.Page, PageSize: filter.PageSize}, nil
}

// SetGroupMembers replaces the explicit member list of one group. | SetGroupMembers 替换组的显式成员列表。
func (s *Service) SetGroupMembers(ctx context.Context, tenantID, groupID string, userIDs []string) ([]GroupMember, error) {
	tenantID = strings.TrimSpace(tenantID)
	groupID = strings.TrimSpace(groupID)
	if tenantID == "" || groupID == "" {
		return nil, ErrInvalidInput
	}
	if _, err := s.store.GetGroup(ctx, tenantID, groupID); err != nil {
		return nil, err
	}
	if s.directory == nil {
		return nil, ErrUnavailable
	}
	users, err := s.directory.Users(ctx, tenantID, userIDs)
	if err != nil {
		return nil, err
	}
	if len(users) > s.options.MaxAssignees {
		return nil, errs.Detail(ErrLimit, "a group holds at most %[1]d members | 单个组最多 %[1]d 名成员", s.options.MaxAssignees)
	}
	members := make([]GroupMember, 0, len(users))
	err = s.store.WithTx(ctx, func(st Store) error {
		existing, err := st.ListGroupMembers(ctx, tenantID, groupID)
		if err != nil {
			return err
		}
		wanted := make(map[string]bool, len(users))
		for _, user := range users {
			wanted[user.ID] = true
		}
		for _, member := range existing {
			if !wanted[member.UserID] {
				if err := st.RemoveGroupMember(ctx, tenantID, groupID, member.UserID); err != nil {
					return err
				}
			}
		}
		for _, user := range users {
			memberID, err := s.options.NewID("wfgpm_")
			if err != nil {
				return errs.Wrap(err, ErrUnavailable)
			}
			member := GroupMember{
				CreatedAt: s.now(),
				ID:        memberID,
				TenantID:  tenantID,
				GroupID:   groupID,
				UserID:    user.ID,
				UserName:  user.Name,
			}
			if err := st.AddGroupMember(ctx, member); err != nil {
				return err
			}
			members = append(members, member)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return members, nil
}

// GroupMembers returns the explicit members of one group. | GroupMembers 返回组的显式成员。
func (s *Service) GroupMembers(ctx context.Context, tenantID, groupID string) ([]GroupMember, error) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(groupID) == "" {
		return nil, ErrInvalidInput
	}
	return s.store.ListGroupMembers(ctx, strings.TrimSpace(tenantID), strings.TrimSpace(groupID))
}

// resolveGroup expands one group reference into its explicit members plus the linked role holders. |
// resolveGroup 把一个组引用展开为显式成员与关联角色持有者。
func (s *Service) resolveGroup(ctx context.Context, tenantID, ref string) (Group, []Assignee, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return Group{}, nil, ErrInvalidInput
	}
	group, err := s.store.GetGroupByKey(ctx, tenantID, strings.ToLower(ref))
	if err != nil {
		if !isNotFound(err) {
			return Group{}, nil, err
		}
		group, err = s.store.GetGroup(ctx, tenantID, ref)
		if err != nil {
			return Group{}, nil, err
		}
	}
	if group.Status != GroupEnabled {
		return group, nil, nil
	}
	members, err := s.store.ListGroupMembers(ctx, tenantID, group.ID)
	if err != nil {
		return group, nil, err
	}
	ids := make([]string, 0, len(members))
	for _, member := range members {
		ids = append(ids, member.UserID)
	}
	var users []Assignee
	if len(ids) > 0 {
		if s.directory == nil {
			return group, nil, ErrUnavailable
		}
		users, err = s.directory.Users(ctx, tenantID, ids)
		if err != nil {
			return group, nil, err
		}
	}
	if group.Role != "" {
		if s.directory == nil {
			return group, nil, ErrUnavailable
		}
		roleUsers, err := s.directory.UsersByRole(ctx, tenantID, group.Role)
		if err != nil {
			return group, nil, err
		}
		users = append(users, roleUsers...)
	}
	for i := range users {
		users[i].Groups = append(users[i].Groups, group.Key)
	}
	return group, users, nil
}

// normalizeGroupInput validates one group payload. | normalizeGroupInput 校验一个组载荷。
func (s *Service) normalizeGroupInput(in GroupInput, requireKey bool) (GroupInput, error) {
	in.Key = strings.ToLower(strings.TrimSpace(in.Key))
	if requireKey && !keyRe.MatchString(in.Key) {
		return GroupInput{}, errs.Detail(ErrInvalidInput, "key=%[1]q | 键=%[1]q", in.Key)
	}
	var ok bool
	if in.Name, ok = trimLen(in.Name, s.options.MaxNameLen); !ok || in.Name == "" {
		return GroupInput{}, ErrInvalidInput
	}
	if in.NameEN, ok = trimLen(in.NameEN, s.options.MaxNameLen); !ok {
		return GroupInput{}, ErrInvalidInput
	}
	if in.Description, ok = trimLen(in.Description, 500); !ok {
		return GroupInput{}, ErrInvalidInput
	}
	if in.Role, ok = trimLen(in.Role, 120); !ok {
		return GroupInput{}, ErrInvalidInput
	}
	if in.Status == "" {
		in.Status = GroupEnabled
	}
	switch in.Status {
	case GroupEnabled, GroupDisabled:
	default:
		return GroupInput{}, ErrInvalidInput
	}
	return in, nil
}

// groupKeysOf returns the sorted group keys of one assignee. | groupKeysOf 返回一个审批人排序后的组键。
func groupKeysOf(assignee Assignee) []string {
	out := append([]string(nil), assignee.Groups...)
	sort.Strings(out)
	return out
}
