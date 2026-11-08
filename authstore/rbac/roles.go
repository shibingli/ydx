package rbac

import (
	"context"
	"errors"

	goredis "github.com/redis/go-redis/v9"

	authrbac "github.com/shibingli/ydx/auth/authz/rbac"
	"github.com/shibingli/ydx/errs"
)

// AddRole stores a new role atomically, rejecting duplicate names and inheritance cycles.
// | AddRole 原子保存新角色，拒绝重复名称与继承环。
func (s *Store) AddRole(ctx context.Context, role authrbac.Role) error {
	ctx = normalizeContext(ctx)
	if err := s.ensure(); err != nil {
		return err
	}
	if err := checkContext(ctx); err != nil {
		return err
	}
	if err := validateRole(role); err != nil {
		return err
	}
	data, err := encodeRole(role)
	if err != nil {
		return err
	}
	code, err := s.runInt(ctx, scriptRoleAdd, "add role",
		[]string{s.keys.roles(), s.keys.roleParents()},
		role.Name, string(data), encodeParentList(role.Parents),
	)
	if err != nil {
		return err
	}
	switch code {
	case 0:
		return nil
	case 1:
		return errs.Detail(authrbac.ErrRoleExists, "role %q | 角色 %q", role.Name, role.Name)
	case 2:
		return errs.Detail(authrbac.ErrRoleCycle, "role %q | 角色 %q", role.Name, role.Name)
	default:
		return errs.Detail(ErrStoreUnavailable, "add role returned %d | 添加角色返回 %d", code, code)
	}
}

// RemoveRole removes a role, every assignment holding it and every parent reference to it in one
// atomic script. | RemoveRole 在单个原子脚本中删除角色、持有它的全部分配以及所有指向它的父角色引用。
func (s *Store) RemoveRole(ctx context.Context, name string) error {
	ctx = normalizeContext(ctx)
	if err := s.ensure(); err != nil {
		return err
	}
	if err := checkContext(ctx); err != nil {
		return err
	}
	code, err := s.runInt(ctx, scriptRoleRemove, "remove role",
		[]string{
			s.keys.roles(),
			s.keys.roleParents(),
			s.keys.assignments(),
			s.keys.assignmentExpiry(),
			s.keys.assignmentSubjects(),
		},
		name, s.keys.assignmentSubjectPrefix(),
	)
	if err != nil {
		return err
	}
	switch code {
	case 0:
		return nil
	case 1:
		return errs.Detail(authrbac.ErrRoleNotFound, "role %q | 角色 %q", name, name)
	default:
		return errs.Detail(ErrStoreUnavailable, "remove role returned %d | 删除角色返回 %d", code, code)
	}
}

// GetRole returns a deep copy of one role. | GetRole 返回一个角色的深拷贝。
func (s *Store) GetRole(ctx context.Context, name string) (authrbac.Role, error) {
	ctx = normalizeContext(ctx)
	if err := s.ensure(); err != nil {
		return authrbac.Role{}, err
	}
	if err := checkContext(ctx); err != nil {
		return authrbac.Role{}, err
	}
	data, err := s.client.HGet(ctx, s.keys.roles(), name).Result()
	if errors.Is(err, goredis.Nil) {
		return authrbac.Role{}, errs.Detail(authrbac.ErrRoleNotFound, "role %q | 角色 %q", name, name)
	}
	if err != nil {
		return authrbac.Role{}, s.backend("get role", err)
	}
	role, err := decodeRole([]byte(data))
	if err != nil {
		return authrbac.Role{}, err
	}
	encoded, err := s.client.HGet(ctx, s.keys.roleParents(), name).Result()
	if errors.Is(err, goredis.Nil) {
		role.Parents = nil
		return role, nil
	}
	if err != nil {
		return authrbac.Role{}, s.backend("get role parents", err)
	}
	parents, err := decodeParentList(encoded)
	if err != nil {
		return authrbac.Role{}, err
	}
	role.Parents = parents
	return role, nil
}

// ListRoles returns deep copies of every role sorted by name. | ListRoles 按名称返回所有角色的深拷贝。
func (s *Store) ListRoles(ctx context.Context) ([]authrbac.Role, error) {
	ctx = normalizeContext(ctx)
	if err := s.ensure(); err != nil {
		return nil, err
	}
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	stored, err := s.client.HGetAll(ctx, s.keys.roles()).Result()
	if err != nil {
		return nil, s.backend("list roles", err)
	}
	parentsByRole, err := s.client.HGetAll(ctx, s.keys.roleParents()).Result()
	if err != nil {
		return nil, s.backend("list role parents", err)
	}
	roles := make([]authrbac.Role, 0, len(stored))
	for name, data := range stored {
		role, err := decodeRole([]byte(data))
		if err != nil {
			return nil, err
		}
		if encoded, ok := parentsByRole[name]; ok {
			parents, err := decodeParentList(encoded)
			if err != nil {
				return nil, err
			}
			role.Parents = parents
		} else {
			role.Parents = nil
		}
		roles = append(roles, role)
	}
	sortRoles(roles)
	return roles, nil
}
