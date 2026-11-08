package rbac

import (
	"context"
	"strings"
	"time"

	authrbac "github.com/shibingli/ydx/auth/authz/rbac"
	"github.com/shibingli/ydx/errs"
)

// Assign stores one subject-role-scope assignment atomically. An existing assignment whose
// deadline has passed is replaced, matching the in-memory store. | Assign 原子保存一条主体、角色与
// 作用域分配。已过期的同名分配会被替换，与内存存储一致。
func (s *Store) Assign(ctx context.Context, assignment authrbac.Assignment) error {
	ctx = normalizeContext(ctx)
	if err := s.ensure(); err != nil {
		return err
	}
	if err := checkContext(ctx); err != nil {
		return err
	}
	if err := validateAssignment(assignment); err != nil {
		return err
	}
	now := time.Now().UTC()
	stored := assignment.Clone()
	if stored.CreatedAt.IsZero() {
		stored.CreatedAt = now
	}
	normalizeAssignmentTimes(&stored)
	data, err := encodeAssignment(stored)
	if err != nil {
		return err
	}
	nowSeconds, nowNanoseconds := nowFields(now)
	code, err := s.runInt(ctx, scriptAssignmentAdd, "assign role",
		[]string{
			s.keys.assignments(),
			s.keys.assignmentExpiry(),
			s.keys.assignmentSubject(stored.Subject),
			s.keys.assignmentSubjects(),
			s.keys.roles(),
		},
		assignmentID(stored.Subject, stored.Role, stored.Scope),
		string(data),
		stored.Role,
		expiryString(stored.ExpiresAt),
		stored.Subject,
		nowSeconds,
		nowNanoseconds,
	)
	if err != nil {
		return err
	}
	switch code {
	case 0:
		return nil
	case 1:
		return errs.Detail(authrbac.ErrAssignmentExists, "subject %q role %q scope %q | 主体 %q 角色 %q 作用域 %q",
			stored.Subject, stored.Role, stored.Scope,
			stored.Subject, stored.Role, stored.Scope)
	case 2:
		return errs.Detail(authrbac.ErrRoleNotFound, "role %q | 角色 %q", stored.Role, stored.Role)
	default:
		return errs.Detail(ErrStoreUnavailable, "assign role returned %d | 分配角色返回 %d", code, code)
	}
}

// Unassign removes one exact subject-role-scope assignment atomically.
// | Unassign 原子删除一条主体、角色与作用域完全匹配的分配。
func (s *Store) Unassign(ctx context.Context, subject, role, scope string) error {
	ctx = normalizeContext(ctx)
	if err := s.ensure(); err != nil {
		return err
	}
	if err := checkContext(ctx); err != nil {
		return err
	}
	if strings.TrimSpace(subject) == "" || strings.TrimSpace(role) == "" {
		return errs.Detail(authrbac.ErrInvalidAssignment, "subject and role are required | 主体与角色必填")
	}
	code, err := s.runInt(ctx, scriptAssignmentRemove, "unassign role",
		[]string{
			s.keys.assignments(),
			s.keys.assignmentExpiry(),
			s.keys.assignmentSubject(subject),
			s.keys.assignmentSubjects(),
		},
		assignmentID(subject, role, scope), subject,
	)
	if err != nil {
		return err
	}
	switch code {
	case 0:
		return nil
	case 1:
		return errs.Detail(authrbac.ErrAssignmentNotFound, "subject %q role %q scope %q | 主体 %q 角色 %q 作用域 %q",
			subject, role, scope, subject, role, scope)
	default:
		return errs.Detail(ErrStoreUnavailable, "unassign role returned %d | 解除角色分配返回 %d", code, code)
	}
}

// Assignments returns deep copies of a subject's assignments, including expired ones, sorted by
// role and scope. | Assignments 返回某主体分配的深拷贝（包含已过期项），按角色与作用域排序。
func (s *Store) Assignments(ctx context.Context, subject string) ([]authrbac.Assignment, error) {
	ctx = normalizeContext(ctx)
	if err := s.ensure(); err != nil {
		return nil, err
	}
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	values, err := s.runSlice(ctx, scriptSubjectAssignments, "list subject assignments",
		[]string{s.keys.assignmentSubject(subject), s.keys.assignments()},
	)
	if err != nil {
		return nil, err
	}
	if len(values)%2 != 0 {
		return nil, errs.Detail(ErrStoreUnavailable, "stored assignment index is corrupt | 存储的分配索引已损坏")
	}
	assignments := make([]authrbac.Assignment, 0, len(values)/2)
	for index := 1; index < len(values); index += 2 {
		assignment, err := decodeAssignment([]byte(stringValue(values[index])))
		if err != nil {
			return nil, err
		}
		assignments = append(assignments, assignment)
	}
	sortAssignments(assignments)
	return assignments, nil
}

// ListAssignments returns deep copies of every assignment sorted by subject, role and scope.
// | ListAssignments 按主体、角色与作用域返回所有分配的深拷贝。
func (s *Store) ListAssignments(ctx context.Context) ([]authrbac.Assignment, error) {
	ctx = normalizeContext(ctx)
	if err := s.ensure(); err != nil {
		return nil, err
	}
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	stored, err := s.client.HGetAll(ctx, s.keys.assignments()).Result()
	if err != nil {
		return nil, s.backend("list assignments", err)
	}
	assignments := make([]authrbac.Assignment, 0, len(stored))
	for _, data := range stored {
		assignment, err := decodeAssignment([]byte(data))
		if err != nil {
			return nil, err
		}
		assignments = append(assignments, assignment)
	}
	sortAssignments(assignments)
	return assignments, nil
}
