package rbac

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/shibingli/ydx/errs"
)

// Store persists roles, assignments and policies. | Store 持久化角色、分配与策略。
//
// Implementations must return the package sentinels for the documented failures, store and return
// deep copies, and be safe for concurrent use. Engine methods never mutate values returned by a
// Store. | 实现必须为已记录的失败返回包哨兵错误，保存并返回深拷贝，并且并发安全。Engine 方法从不
// 修改 Store 返回的值。
type Store interface {
	// AddRole stores a new role, rejecting duplicates and inheritance cycles. | AddRole 保存新角色，拒绝重复与继承环。
	AddRole(ctx context.Context, role Role) error
	// RemoveRole removes a role, its assignments and parent references to it. | RemoveRole 删除角色、其分配以及指向它的父角色引用。
	RemoveRole(ctx context.Context, name string) error
	// GetRole returns a deep copy of one role. | GetRole 返回一个角色的深拷贝。
	GetRole(ctx context.Context, name string) (Role, error)
	// ListRoles returns deep copies of every role sorted by name. | ListRoles 按名称返回所有角色的深拷贝。
	ListRoles(ctx context.Context) ([]Role, error)
	// Assign stores a subject-role-scope assignment, rejecting duplicates that are still active. | Assign 保存主体、角色与作用域分配，拒绝仍然有效的重复项。
	Assign(ctx context.Context, assignment Assignment) error
	// Unassign removes one exact subject-role-scope assignment. | Unassign 删除一条主体、角色与作用域完全匹配的分配。
	Unassign(ctx context.Context, subject, role, scope string) error
	// Assignments returns deep copies of a subject's assignments, including expired ones. | Assignments 返回某主体的分配深拷贝，包含已过期项。
	Assignments(ctx context.Context, subject string) ([]Assignment, error)
	// ListAssignments returns deep copies of every assignment in deterministic order. | ListAssignments 按确定顺序返回所有分配的深拷贝。
	ListAssignments(ctx context.Context) ([]Assignment, error)
	// AddPolicy stores a new policy, rejecting duplicate identifiers and invalid definitions. | AddPolicy 保存新策略，拒绝重复标识与非法定义。
	AddPolicy(ctx context.Context, policy Policy) error
	// RemovePolicy removes a policy by identifier. | RemovePolicy 按标识删除策略。
	RemovePolicy(ctx context.Context, id string) error
	// GetPolicy returns a deep copy of one policy. | GetPolicy 返回一条策略的深拷贝。
	GetPolicy(ctx context.Context, id string) (Policy, error)
	// ListPolicies returns deep copies of every policy sorted by identifier. | ListPolicies 按标识返回所有策略的深拷贝。
	ListPolicies(ctx context.Context) ([]Policy, error)
	// Reset removes every role, assignment and policy. | Reset 删除所有角色、分配与策略。
	Reset(ctx context.Context) error
}

// MemoryStore is the in-memory Store used by New. | MemoryStore 是 New 使用的内存 Store。
//
// The zero value is ready for use and all methods are safe for concurrent use. | 零值即可使用，所有
// 方法均并发安全。
type MemoryStore struct {
	mu          sync.RWMutex
	roles       map[string]Role
	assignments map[assignmentKey]Assignment
	policies    map[string]Policy
}

// assignmentKey is the identity of an Assignment. | assignmentKey 是 Assignment 的标识。
type assignmentKey struct {
	subject string
	role    string
	scope   string
}

// Compile-time check that MemoryStore implements Store. | 编译期检查 MemoryStore 实现 Store。
var _ Store = (*MemoryStore)(nil)

// NewMemoryStore returns an empty in-memory store. | NewMemoryStore 返回空的内存存储。
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		roles:       make(map[string]Role),
		assignments: make(map[assignmentKey]Assignment),
		policies:    make(map[string]Policy),
	}
}

// normalizeContext replaces a nil context with context.Background. | normalizeContext 把空上下文替换为 context.Background。
func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

// checkContext reports a canceled or expired context as ErrCanceled. | checkContext 把已取消或超时的
// 上下文报告为 ErrCanceled。
func checkContext(ctx context.Context) error {
	if err := normalizeContext(ctx).Err(); err != nil {
		return errs.Wrap(err, ErrCanceled)
	}
	return nil
}

// ensureLocked initializes the maps of a zero-value MemoryStore. | ensureLocked 初始化零值 MemoryStore 的映射。
func (s *MemoryStore) ensureLocked() {
	if s.roles == nil {
		s.roles = make(map[string]Role)
	}
	if s.assignments == nil {
		s.assignments = make(map[assignmentKey]Assignment)
	}
	if s.policies == nil {
		s.policies = make(map[string]Policy)
	}
}

// validateRole reports whether role has a name, non-empty permissions and non-empty parents. | validateRole
// 报告角色是否具有名称、非空权限与非空父角色。
func validateRole(role Role) error {
	if strings.TrimSpace(role.Name) == "" {
		return errs.Detail(ErrInvalidRole, "empty role name | 角色名称为空")
	}
	for _, permission := range role.Permissions {
		if strings.TrimSpace(permission) == "" {
			return errs.Detail(ErrInvalidRole, "role %q has an empty permission | 角色 %q 含空权限", role.Name, role.Name)
		}
	}
	for _, parent := range role.Parents {
		if strings.TrimSpace(parent) == "" {
			return errs.Detail(ErrInvalidRole, "role %q has an empty parent | 角色 %q 含空父角色", role.Name, role.Name)
		}
	}
	return nil
}

// normalizePolicy validates a policy and returns its normalized form. | normalizePolicy 校验策略并返回其规范化形式。
func normalizePolicy(policy Policy) (Policy, error) {
	out := policy.Clone()
	if strings.TrimSpace(out.ID) == "" {
		return Policy{}, errs.Detail(ErrInvalidPolicy, "empty policy id | 策略标识为空")
	}
	effect := strings.ToLower(strings.TrimSpace(out.Effect))
	switch effect {
	case EffectPermit, EffectDeny:
		out.Effect = effect
	default:
		return Policy{}, errs.Detail(ErrInvalidPolicy, "policy %q has effect %q | 策略 %q 的效果为 %q", out.ID, out.Effect, out.ID, out.Effect)
	}
	for index, condition := range out.Conditions {
		condition = normalizeCondition(condition)
		if err := validateCondition(condition); err != nil {
			return Policy{}, errs.WrapDetail(err, ErrInvalidPolicy, "policy %q condition %d | 策略 %q 条件 %d", out.ID, index, out.ID, index)
		}
		out.Conditions[index] = condition
	}
	return out, nil
}

// validateAssignment reports whether an assignment has a subject, role and non-empty condition keys. | validateAssignment
// 报告分配是否具有主体、角色以及非空条件键。
func validateAssignment(assignment Assignment) error {
	if strings.TrimSpace(assignment.Subject) == "" {
		return errs.Detail(ErrInvalidAssignment, "empty subject | 主体为空")
	}
	if strings.TrimSpace(assignment.Role) == "" {
		return errs.Detail(ErrInvalidAssignment, "empty role | 角色为空")
	}
	for key := range assignment.Conditions {
		if strings.TrimSpace(key) == "" {
			return errs.Detail(ErrInvalidAssignment, "empty condition key | 条件键为空")
		}
	}
	return nil
}

// AddRole stores role. | AddRole 保存 role。
func (s *MemoryStore) AddRole(ctx context.Context, role Role) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if err := validateRole(role); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureLocked()
	if _, exists := s.roles[role.Name]; exists {
		return errs.Detail(ErrRoleExists, "role %q | 角色 %q", role.Name, role.Name)
	}
	if s.hasCycleLocked(role.Name, role.Parents) {
		return errs.Detail(ErrRoleCycle, "role %q | 角色 %q", role.Name, role.Name)
	}
	s.roles[role.Name] = role.Clone()
	return nil
}

// hasCycleLocked reports whether adding name with parents closes a cycle over stored roles. | hasCycleLocked
// 报告以 parents 添加 name 是否在已存角色上形成环。
func (s *MemoryStore) hasCycleLocked(name string, parents []string) bool {
	stack := append([]string(nil), parents...)
	visited := make(map[string]struct{}, len(s.roles))
	for len(stack) > 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if current == name {
			return true
		}
		if _, seen := visited[current]; seen {
			continue
		}
		visited[current] = struct{}{}
		if role, ok := s.roles[current]; ok {
			stack = append(stack, role.Parents...)
		}
	}
	return false
}

// RemoveRole removes a role and every reference to it. | RemoveRole 删除角色及其所有引用。
func (s *MemoryStore) RemoveRole(ctx context.Context, name string) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureLocked()
	if _, exists := s.roles[name]; !exists {
		return errs.Detail(ErrRoleNotFound, "role %q | 角色 %q", name, name)
	}
	delete(s.roles, name)
	for key, assignment := range s.assignments {
		if assignment.Role == name {
			delete(s.assignments, key)
		}
	}
	for roleName, role := range s.roles {
		if len(role.Parents) == 0 {
			continue
		}
		parents := make([]string, 0, len(role.Parents))
		for _, parent := range role.Parents {
			if parent != name {
				parents = append(parents, parent)
			}
		}
		if len(parents) != len(role.Parents) {
			role.Parents = parents
			s.roles[roleName] = role
		}
	}
	return nil
}

// GetRole returns a deep copy of the named role. | GetRole 返回指定角色的深拷贝。
func (s *MemoryStore) GetRole(ctx context.Context, name string) (Role, error) {
	if err := checkContext(ctx); err != nil {
		return Role{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	role, ok := s.roles[name]
	if !ok {
		return Role{}, errs.Detail(ErrRoleNotFound, "role %q | 角色 %q", name, name)
	}
	return role.Clone(), nil
}

// ListRoles returns deep copies of every role sorted by name. | ListRoles 按名称返回所有角色的深拷贝。
func (s *MemoryStore) ListRoles(ctx context.Context) ([]Role, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Role, 0, len(s.roles))
	for _, role := range s.roles {
		out = append(out, role.Clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Assign stores assignment. | Assign 保存 assignment。
func (s *MemoryStore) Assign(ctx context.Context, assignment Assignment) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if err := validateAssignment(assignment); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureLocked()
	if _, exists := s.roles[assignment.Role]; !exists {
		return errs.Detail(ErrRoleNotFound, "role %q | 角色 %q", assignment.Role, assignment.Role)
	}
	key := assignmentKey{subject: assignment.Subject, role: assignment.Role, scope: assignment.Scope}
	if existing, exists := s.assignments[key]; exists && !existing.Expired(time.Now().UTC()) {
		return errs.Detail(ErrAssignmentExists, "subject %q role %q scope %q | 主体 %q 角色 %q 作用域 %q",
			assignment.Subject, assignment.Role, assignment.Scope,
			assignment.Subject, assignment.Role, assignment.Scope)
	}
	stored := assignment.Clone()
	if stored.CreatedAt.IsZero() {
		stored.CreatedAt = time.Now().UTC()
	}
	s.assignments[key] = stored
	return nil
}

// Unassign removes one exact assignment. | Unassign 删除一条完全匹配的分配。
func (s *MemoryStore) Unassign(ctx context.Context, subject, role, scope string) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if strings.TrimSpace(subject) == "" || strings.TrimSpace(role) == "" {
		return errs.Detail(ErrInvalidAssignment, "subject and role are required | 主体与角色必填")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := assignmentKey{subject: subject, role: role, scope: scope}
	if _, exists := s.assignments[key]; !exists {
		return errs.Detail(ErrAssignmentNotFound, "subject %q role %q scope %q | 主体 %q 角色 %q 作用域 %q", subject, role, scope, subject, role, scope)
	}
	delete(s.assignments, key)
	return nil
}

// Assignments returns a subject's assignments sorted by role and scope. | Assignments 按角色与作用域返回某主体的分配。
func (s *MemoryStore) Assignments(ctx context.Context, subject string) ([]Assignment, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Assignment, 0, 4)
	for key, assignment := range s.assignments {
		if key.subject == subject {
			out = append(out, assignment.Clone())
		}
	}
	sortAssignments(out)
	return out, nil
}

// ListAssignments returns every assignment sorted by subject, role and scope. | ListAssignments 按主体、角色与作用域返回所有分配。
func (s *MemoryStore) ListAssignments(ctx context.Context) ([]Assignment, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Assignment, 0, len(s.assignments))
	for _, assignment := range s.assignments {
		out = append(out, assignment.Clone())
	}
	sortAssignments(out)
	return out, nil
}

// sortAssignments orders assignments deterministically. | sortAssignments 按确定顺序排列分配。
func sortAssignments(assignments []Assignment) {
	sort.Slice(assignments, func(i, j int) bool {
		left, right := assignments[i], assignments[j]
		if left.Subject != right.Subject {
			return left.Subject < right.Subject
		}
		if left.Role != right.Role {
			return left.Role < right.Role
		}
		return left.Scope < right.Scope
	})
}

// AddPolicy stores policy after validation and normalization. | AddPolicy 在校验与规范化后保存 policy。
func (s *MemoryStore) AddPolicy(ctx context.Context, policy Policy) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	normalized, err := normalizePolicy(policy)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureLocked()
	if _, exists := s.policies[normalized.ID]; exists {
		return errs.Detail(ErrPolicyExists, "policy %q | 策略 %q", normalized.ID, normalized.ID)
	}
	s.policies[normalized.ID] = normalized
	return nil
}

// RemovePolicy removes the named policy. | RemovePolicy 删除指定策略。
func (s *MemoryStore) RemovePolicy(ctx context.Context, id string) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureLocked()
	if _, exists := s.policies[id]; !exists {
		return errs.Detail(ErrPolicyNotFound, "policy %q | 策略 %q", id, id)
	}
	delete(s.policies, id)
	return nil
}

// GetPolicy returns a deep copy of the named policy. | GetPolicy 返回指定策略的深拷贝。
func (s *MemoryStore) GetPolicy(ctx context.Context, id string) (Policy, error) {
	if err := checkContext(ctx); err != nil {
		return Policy{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	policy, ok := s.policies[id]
	if !ok {
		return Policy{}, errs.Detail(ErrPolicyNotFound, "policy %q | 策略 %q", id, id)
	}
	return policy.Clone(), nil
}

// ListPolicies returns deep copies of every policy sorted by identifier. | ListPolicies 按标识返回所有策略的深拷贝。
func (s *MemoryStore) ListPolicies(ctx context.Context) ([]Policy, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Policy, 0, len(s.policies))
	for _, policy := range s.policies {
		out = append(out, policy.Clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Reset removes all data. | Reset 删除所有数据。
func (s *MemoryStore) Reset(ctx context.Context) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.roles = make(map[string]Role)
	s.assignments = make(map[assignmentKey]Assignment)
	s.policies = make(map[string]Policy)
	return nil
}
