package rbac

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/errs"
)

// Option configures an Engine. | Option 配置 Engine。
type Option func(*Engine)

// WithStore installs a custom Store; nil is ignored. | WithStore 安装自定义 Store；空值被忽略。
func WithStore(store Store) Option {
	return func(engine *Engine) {
		if store != nil {
			engine.store = store
		}
	}
}

// WithClock installs the time source used for assignment expiry; nil is ignored. | WithClock 安装用于
// 角色分配过期的时钟；空值被忽略。
func WithClock(clock func() time.Time) Option {
	return func(engine *Engine) {
		if clock != nil {
			engine.now = func() time.Time { return clock().UTC() }
		}
	}
}

// WithCombiningAlgorithm selects the policy combining algorithm; the default is DenyOverrides. | WithCombiningAlgorithm
// 选择策略合并算法；默认值为 DenyOverrides。
func WithCombiningAlgorithm(algorithm CombiningAlgorithm) Option {
	return func(engine *Engine) {
		engine.algorithm = algorithm
	}
}

// Engine evaluates roles and policies against authorization requests. | Engine 对授权请求求值角色与策略。
//
// An Engine is safe for concurrent use when its Store is safe for concurrent use. | 当 Store 并发安全时，
// Engine 也并发安全。
type Engine struct {
	store     Store
	algorithm CombiningAlgorithm
	now       func() time.Time
}

// New returns an Engine with an in-memory store, deny-overrides combining and the system clock. | New
// 返回使用内存存储、deny-overrides 合并与系统时钟的 Engine。
func New(opts ...Option) *Engine {
	engine := &Engine{
		store:     NewMemoryStore(),
		algorithm: DenyOverrides,
		now:       func() time.Time { return time.Now().UTC() },
	}
	for _, opt := range opts {
		if opt != nil {
			opt(engine)
		}
	}
	if engine.store == nil {
		engine.store = NewMemoryStore()
	}
	if engine.now == nil {
		engine.now = func() time.Time { return time.Now().UTC() }
	}
	return engine
}

// Store returns the backing store. | Store 返回底层存储。
func (e *Engine) Store() Store {
	return e.store
}

// AddRole stores a role. | AddRole 保存角色。
func (e *Engine) AddRole(ctx context.Context, role Role) error {
	return e.store.AddRole(normalizeContext(ctx), role)
}

// RemoveRole removes a role together with its assignments. | RemoveRole 删除角色及其分配。
func (e *Engine) RemoveRole(ctx context.Context, name string) error {
	return e.store.RemoveRole(normalizeContext(ctx), name)
}

// GetRole returns a deep copy of a role. | GetRole 返回角色的深拷贝。
func (e *Engine) GetRole(ctx context.Context, name string) (Role, error) {
	return e.store.GetRole(normalizeContext(ctx), name)
}

// Roles returns every role sorted by name. | Roles 按名称返回所有角色。
func (e *Engine) Roles(ctx context.Context) ([]Role, error) {
	return e.store.ListRoles(normalizeContext(ctx))
}

// Assign binds a subject to a role. | Assign 把主体绑定到角色。
func (e *Engine) Assign(ctx context.Context, assignment Assignment) error {
	return e.store.Assign(normalizeContext(ctx), assignment)
}

// Unassign removes one exact subject-role-scope assignment. | Unassign 删除一条主体、角色与作用域完全匹配的分配。
func (e *Engine) Unassign(ctx context.Context, subject, role, scope string) error {
	return e.store.Unassign(normalizeContext(ctx), subject, role, scope)
}

// Assignments returns a subject's assignments, including expired ones. | Assignments 返回某主体的分配，包含已过期项。
func (e *Engine) Assignments(ctx context.Context, subject string) ([]Assignment, error) {
	return e.store.Assignments(normalizeContext(ctx), subject)
}

// AddPolicy stores a policy. | AddPolicy 保存策略。
func (e *Engine) AddPolicy(ctx context.Context, policy Policy) error {
	return e.store.AddPolicy(normalizeContext(ctx), policy)
}

// RemovePolicy removes a policy. | RemovePolicy 删除策略。
func (e *Engine) RemovePolicy(ctx context.Context, id string) error {
	return e.store.RemovePolicy(normalizeContext(ctx), id)
}

// GetPolicy returns a deep copy of a policy. | GetPolicy 返回策略的深拷贝。
func (e *Engine) GetPolicy(ctx context.Context, id string) (Policy, error) {
	return e.store.GetPolicy(normalizeContext(ctx), id)
}

// Policies returns every policy sorted by identifier. | Policies 按标识返回所有策略。
func (e *Engine) Policies(ctx context.Context) ([]Policy, error) {
	return e.store.ListPolicies(normalizeContext(ctx))
}

// grantCandidate is one applicable permit or deny considered by the combining algorithm. | grantCandidate
// 是合并算法考虑的一条适用许可或拒绝。
type grantCandidate struct {
	effect     string
	policyID   string
	role       string
	permission string
	priority   int
}

// isPolicy reports whether the candidate came from a Policy. | isPolicy 报告候选项是否来自 Policy。
func (c grantCandidate) isPolicy() bool { return c.policyID != "" }

// reason returns the diagnostic reason of a decisive candidate. | reason 返回决定性候选项的诊断原因。
func (c grantCandidate) reason() string {
	if c.policyID != "" {
		return c.effect + " policy \"" + c.policyID + "\" matched"
	}
	return "role \"" + c.role + "\" grants \"" + c.permission + "\""
}

// Authorize evaluates request against roles and policies. | Authorize 针对角色与策略对 request 求值。
//
// The request subject and action are required. The result lists every effective role and every
// applicable policy regardless of the decisive outcome. Under OnlyOneApplicable, more than one
// applicable policy returns ErrMultiplePolicies together with a denying decision. | 请求主体与动作
// 必填。结果无论决定性结果如何都会列出所有有效角色与所有适用策略。在 OnlyOneApplicable 下，多于
// 一条策略适用时返回 ErrMultiplePolicies 与拒绝决策。
func (e *Engine) Authorize(ctx context.Context, request Request) (Decision, error) {
	ctx = normalizeContext(ctx)
	if err := checkContext(ctx); err != nil {
		return Decision{}, err
	}
	if strings.TrimSpace(request.Subject) == "" || strings.TrimSpace(request.Action) == "" {
		return Decision{}, errs.Detail(ErrInvalidRequest, "subject and action are required | 主体与动作必填")
	}
	switch e.algorithm {
	case DenyOverrides, PermitOverrides, FirstApplicable, OnlyOneApplicable:
	default:
		return Decision{}, errs.Detail(ErrInvalidAlgorithm, "%q | %q", string(e.algorithm), string(e.algorithm))
	}
	roleList, err := e.store.ListRoles(ctx)
	if err != nil {
		return Decision{}, err
	}
	policyList, err := e.store.ListPolicies(ctx)
	if err != nil {
		return Decision{}, err
	}
	assignments, err := e.store.Assignments(ctx, request.Subject)
	if err != nil {
		return Decision{}, err
	}

	roleMap := indexRoles(roleList)
	resolver := attributeResolver{req: &request}
	now := e.now().UTC()
	effective := make(map[string]struct{}, len(request.Roles))
	for _, role := range request.Roles {
		addEffectiveRole(role, roleMap, effective, request.Scope, true)
	}
	for _, assignment := range assignments {
		if assignment.Expired(now) {
			continue
		}
		if !scopeAllows(assignment.Scope, request.Scope) {
			continue
		}
		if !assignmentConditionsMatch(assignment, resolver) {
			continue
		}
		addEffectiveRole(assignment.Role, roleMap, effective, request.Scope, true)
	}
	matchedRoles := sortedSet(effective)

	candidates := make([]grantCandidate, 0, len(matchedRoles))
	seenGrants := make(map[string]struct{})
	for _, roleName := range matchedRoles {
		role, ok := roleMap[roleName]
		if !ok {
			continue
		}
		for _, permission := range role.Permissions {
			if !auth.MatchPermission(permission, request.Action) {
				continue
			}
			key := roleName + "\x00" + permission
			if _, seen := seenGrants[key]; seen {
				continue
			}
			seenGrants[key] = struct{}{}
			candidates = append(candidates, grantCandidate{
				effect:     EffectPermit,
				role:       roleName,
				permission: permission,
			})
		}
	}

	matchedPolicies := make([]string, 0, len(policyList))
	for _, policy := range policyList {
		if strings.TrimSpace(policy.ID) == "" || (policy.Effect != EffectPermit && policy.Effect != EffectDeny) {
			return Decision{}, errs.Detail(ErrInvalidPolicy, "stored policy %q is invalid | 已存策略 %q 非法", policy.ID, policy.ID)
		}
		if !policyMatches(policy, &request, matchedRoles, resolver) {
			continue
		}
		matchedPolicies = append(matchedPolicies, policy.ID)
		candidates = append(candidates, grantCandidate{
			effect:   policy.Effect,
			policyID: policy.ID,
			priority: policy.Priority,
		})
	}
	sort.Strings(matchedPolicies)
	sortCandidates(candidates)

	decision, err := combine(e.algorithm, candidates, matchedRoles, matchedPolicies)
	if err != nil {
		return decision, err
	}
	return decision, nil
}

// Permissions returns the effective permissions of subject inside scope. | Permissions 返回主体在
// scope 内的有效权限。
//
// The result is the sorted union of role permissions, including inherited roles. An empty scope
// disables scope filtering and returns the union across every assignment. Assignment conditions are
// evaluated only against the request subject and scope built-ins, because the method receives no
// attributes; conditional assignments that need other attributes are therefore excluded. | 结果是
// 角色权限（含继承角色）排序后的并集。空 scope 关闭作用域过滤并返回所有分配的并集。由于方法不接收
// 属性，分配条件只会针对请求主体与作用域内建键求值；需要其它属性的条件分配因此被排除。
func (e *Engine) Permissions(ctx context.Context, subject, scope string) ([]string, error) {
	ctx = normalizeContext(ctx)
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if strings.TrimSpace(subject) == "" {
		return nil, errs.Detail(ErrInvalidRequest, "empty subject | 主体为空")
	}
	assignments, err := e.store.Assignments(ctx, subject)
	if err != nil {
		return nil, err
	}
	roleList, err := e.store.ListRoles(ctx)
	if err != nil {
		return nil, err
	}
	roleMap := indexRoles(roleList)
	resolver := attributeResolver{req: &Request{Subject: subject, Scope: scope}}
	now := e.now().UTC()
	filterScope := scope != ""
	effective := make(map[string]struct{})
	for _, assignment := range assignments {
		if assignment.Expired(now) {
			continue
		}
		if filterScope && !scopeAllows(assignment.Scope, scope) {
			continue
		}
		if !assignmentConditionsMatch(assignment, resolver) {
			continue
		}
		addEffectiveRole(assignment.Role, roleMap, effective, scope, filterScope)
	}
	permissions := make(map[string]struct{})
	for roleName := range effective {
		role, ok := roleMap[roleName]
		if !ok {
			continue
		}
		for _, permission := range role.Permissions {
			if permission != "" {
				permissions[permission] = struct{}{}
			}
		}
	}
	return sortedSet(permissions), nil
}

// indexRoles builds a role-name index. | indexRoles 构建角色名索引。
func indexRoles(roles []Role) map[string]Role {
	out := make(map[string]Role, len(roles))
	for _, role := range roles {
		out[role.Name] = role
	}
	return out
}

// addEffectiveRole adds name and its ancestors to out, optionally filtering by role scope. | addEffectiveRole
// 把 name 及其祖先加入 out，并可选地按角色作用域过滤。
func addEffectiveRole(name string, roles map[string]Role, out map[string]struct{}, scope string, filterScope bool) {
	if name == "" {
		return
	}
	if _, seen := out[name]; seen {
		return
	}
	role, defined := roles[name]
	if defined && filterScope && role.Scope != "" && !globMatch(role.Scope, scope) {
		return
	}
	out[name] = struct{}{}
	if defined {
		for _, parent := range role.Parents {
			addEffectiveRole(parent, roles, out, scope, filterScope)
		}
	}
}

// assignmentConditionsMatch reports whether every equality condition of an assignment holds. | assignmentConditionsMatch
// 报告分配的所有等值条件是否成立。
func assignmentConditionsMatch(assignment Assignment, resolver attributeResolver) bool {
	for key, want := range assignment.Conditions {
		got, ok := resolver.lookup(key)
		if !ok || got != want {
			return false
		}
	}
	return true
}

// policyMatches reports whether policy applies to request. | policyMatches 报告 policy 是否适用于 request。
func policyMatches(policy Policy, request *Request, roles []string, resolver attributeResolver) bool {
	if !policySubjectMatches(policy.Subject, request.Subject, roles) {
		return false
	}
	if policy.Resource != "" && !globMatch(policy.Resource, request.Resource) {
		return false
	}
	if policy.Action != "" && !globMatch(policy.Action, request.Action) {
		return false
	}
	if !scopeAllows(policy.Scope, request.Scope) {
		return false
	}
	return evaluateConditions(policy.Conditions, resolver)
}

// sortCandidates orders candidates by priority, policies before role grants, then identifier. | sortCandidates
// 按优先级、策略优先于角色授权、再按标识排列候选项。
func sortCandidates(candidates []grantCandidate) {
	sort.SliceStable(candidates, func(i, j int) bool {
		left, right := candidates[i], candidates[j]
		if left.priority != right.priority {
			return left.priority > right.priority
		}
		if left.isPolicy() != right.isPolicy() {
			return left.isPolicy()
		}
		if left.isPolicy() {
			return left.policyID < right.policyID
		}
		if left.permission != right.permission {
			return left.permission < right.permission
		}
		return left.role < right.role
	})
}

// combine applies algorithm to the ordered candidates. | combine 对有序候选项应用 algorithm。
func combine(algorithm CombiningAlgorithm, candidates []grantCandidate, matchedRoles, matchedPolicies []string) (Decision, error) {
	decision := func(allowed bool, reason string) Decision {
		return Decision{
			Allowed:         allowed,
			Reason:          reason,
			MatchedRoles:    matchedRoles,
			MatchedPolicies: matchedPolicies,
		}
	}
	switch algorithm {
	case PermitOverrides:
		for _, candidate := range candidates {
			if candidate.effect == EffectPermit {
				return decision(true, candidate.reason()), nil
			}
		}
		for _, candidate := range candidates {
			if candidate.effect == EffectDeny {
				return decision(false, candidate.reason()), nil
			}
		}
		return decision(false, "no matching role permission or policy"), nil
	case FirstApplicable:
		if len(candidates) > 0 {
			first := candidates[0]
			return decision(first.effect == EffectPermit, first.reason()), nil
		}
		return decision(false, "no matching role permission or policy"), nil
	case OnlyOneApplicable:
		policyCount := 0
		var only grantCandidate
		for _, candidate := range candidates {
			if candidate.isPolicy() {
				policyCount++
				only = candidate
			}
		}
		switch {
		case policyCount > 1:
			reason := "multiple applicable policies: " + strings.Join(matchedPolicies, ", ")
			return decision(false, reason), errs.Detail(ErrMultiplePolicies, "policies %s | 策略 %s",
				strings.Join(matchedPolicies, ", "), strings.Join(matchedPolicies, ", "))
		case policyCount == 1:
			return decision(only.effect == EffectPermit, only.reason()), nil
		}
		for _, candidate := range candidates {
			if !candidate.isPolicy() && candidate.effect == EffectPermit {
				return decision(true, candidate.reason()), nil
			}
		}
		return decision(false, "no matching role permission or policy"), nil
	default:
		for _, candidate := range candidates {
			if candidate.effect == EffectDeny {
				return decision(false, candidate.reason()), nil
			}
		}
		for _, candidate := range candidates {
			if candidate.effect == EffectPermit {
				return decision(true, candidate.reason()), nil
			}
		}
		return decision(false, "no matching role permission or policy"), nil
	}
}
