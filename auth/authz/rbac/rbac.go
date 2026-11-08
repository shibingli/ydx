package rbac

import (
	"time"

	"github.com/shibingli/ydx/errs"
)

// The declared sentinels of the rbac package. | rbac 包声明的哨兵错误。
//
// Every failure path returns one of them directly or through errs.Detail / errs.Wrap, so callers can
// classify errors with errors.Is instead of matching text. | 所有失败路径都直接返回其中之一，或经由
// errs.Detail / errs.Wrap 包装，因此调用方可用 errors.Is 分类错误而无需匹配文案。
var (
	// ErrInvalidRole reports a role with a missing name or an empty permission or parent entry. | ErrInvalidRole 表示角色名称缺失，或权限、父角色条目为空。
	ErrInvalidRole = errs.New("rbac: invalid role | rbac：角色非法")
	// ErrInvalidPolicy reports a policy with a missing identifier, an unknown effect or an invalid condition. | ErrInvalidPolicy 表示策略缺少标识、效果未知或条件非法。
	ErrInvalidPolicy = errs.New("rbac: invalid policy | rbac：策略非法")
	// ErrInvalidAssignment reports an assignment with a missing subject or role, or an empty condition key. | ErrInvalidAssignment 表示角色分配缺少主体或角色，或条件键为空。
	ErrInvalidAssignment = errs.New("rbac: invalid assignment | rbac：角色分配非法")
	// ErrInvalidRequest reports malformed caller input. | ErrInvalidRequest 表示调用方输入非法。
	ErrInvalidRequest = errs.New("rbac: invalid request | rbac：请求非法")
	// ErrInvalidCondition reports a condition with a missing key or an unknown operator. | ErrInvalidCondition 表示条件缺少键或运算符未知。
	ErrInvalidCondition = errs.New("rbac: invalid condition | rbac：条件非法")
	// ErrInvalidAlgorithm reports an unknown combining algorithm. | ErrInvalidAlgorithm 表示合并算法未知。
	ErrInvalidAlgorithm = errs.New("rbac: invalid combining algorithm | rbac：合并算法非法")
	// ErrRoleExists reports a duplicate role name. | ErrRoleExists 表示角色名称重复。
	ErrRoleExists = errs.New("rbac: role already exists | rbac：角色已存在")
	// ErrRoleNotFound reports an unknown role. | ErrRoleNotFound 表示角色不存在。
	ErrRoleNotFound = errs.New("rbac: role not found | rbac：角色不存在")
	// ErrRoleCycle reports a cycle in role inheritance. | ErrRoleCycle 表示角色继承存在环。
	ErrRoleCycle = errs.New("rbac: role inheritance cycle | rbac：角色继承存在环")
	// ErrAssignmentExists reports a duplicate subject-role-scope assignment. | ErrAssignmentExists 表示主体、角色与作用域相同的分配已存在。
	ErrAssignmentExists = errs.New("rbac: assignment already exists | rbac：角色分配已存在")
	// ErrAssignmentNotFound reports an unknown assignment. | ErrAssignmentNotFound 表示角色分配不存在。
	ErrAssignmentNotFound = errs.New("rbac: assignment not found | rbac：角色分配不存在")
	// ErrPolicyExists reports a duplicate policy identifier. | ErrPolicyExists 表示策略标识重复。
	ErrPolicyExists = errs.New("rbac: policy already exists | rbac：策略已存在")
	// ErrPolicyNotFound reports an unknown policy. | ErrPolicyNotFound 表示策略不存在。
	ErrPolicyNotFound = errs.New("rbac: policy not found | rbac：策略不存在")
	// ErrMultiplePolicies reports more than one policy applicable under only-one-applicable. | ErrMultiplePolicies 表示 only-one-applicable 下有多条策略同时适用。
	ErrMultiplePolicies = errs.New("rbac: multiple applicable policies | rbac：多条策略同时适用")
	// ErrInvalidSnapshot reports malformed snapshot data or a version mismatch. | ErrInvalidSnapshot 表示快照数据非法或版本不匹配。
	ErrInvalidSnapshot = errs.New("rbac: invalid snapshot | rbac：快照非法")
	// ErrUnsupportedVersion reports a snapshot version this package cannot load. | ErrUnsupportedVersion 表示本包无法加载的快照版本。
	ErrUnsupportedVersion = errs.New("rbac: unsupported snapshot version | rbac：快照版本不受支持")
	// ErrSnapshotRestore reports that a failed snapshot load could not restore the previous engine
	// state. The returned error joins the load failure and the restore failure, so errors.Is also
	// matches both underlying sentinels. | ErrSnapshotRestore 表示快照装载失败后无法恢复先前的引擎状态。
	// 返回的错误会合并装载失败与恢复失败，因此 errors.Is 也能匹配两个底层哨兵。
	ErrSnapshotRestore = errs.New("rbac: snapshot restore failed | rbac：快照恢复失败")
	// ErrCanceled reports a canceled or expired context. | ErrCanceled 表示上下文已取消或超时。
	ErrCanceled = errs.New("rbac: operation canceled | rbac：操作已取消")
	// ErrNilEngine reports a nil engine passed to a middleware constructor. | ErrNilEngine 表示传给中间件构造函数的引擎为空。
	ErrNilEngine = errs.New("rbac: nil engine | rbac：引擎为空")
)

// The policy effects. | 策略效果。
const (
	// EffectPermit allows the request when the policy matches. | EffectPermit 表示策略匹配时允许请求。
	EffectPermit = "permit"
	// EffectDeny blocks the request when the policy matches. | EffectDeny 表示策略匹配时拒绝请求。
	EffectDeny = "deny"
)

// CombiningAlgorithm names the policy combining algorithm of an Engine. | CombiningAlgorithm 命名引擎的策略合并算法。
type CombiningAlgorithm string

// The supported combining algorithms. | 支持的合并算法。
const (
	// DenyOverrides denies when any matching deny exists, otherwise allows on any permit. | DenyOverrides 在存在匹配的拒绝时拒绝，否则任一许可即允许。
	DenyOverrides CombiningAlgorithm = "deny-overrides"
	// PermitOverrides allows when any matching permit exists, otherwise denies. | PermitOverrides 在存在匹配的许可时允许，否则拒绝。
	PermitOverrides CombiningAlgorithm = "permit-overrides"
	// FirstApplicable applies the highest-priority matching decision. | FirstApplicable 采用优先级最高的匹配决策。
	FirstApplicable CombiningAlgorithm = "first-applicable"
	// OnlyOneApplicable requires at most one matching policy and applies its effect. | OnlyOneApplicable 要求至多一条策略匹配并采用其效果。
	OnlyOneApplicable CombiningAlgorithm = "only-one-applicable"
)

// Role is a named permission set with optional inheritance. | Role 是带可选继承的命名权限集合。
type Role struct {
	// Name is the unique role identifier. | Name 是唯一角色标识。
	Name string `json:"name"`
	// Description is a human-readable summary. | Description 是人类可读的说明。
	Description string `json:"description,omitempty"`
	// Permissions are the permission strings granted by the role; "*" and "prefix:*" wildcards are
	// honoured when matching a requested action. | Permissions 是角色授予的权限字符串；匹配请求动作时支持
	// "*" 与 "prefix:*" 通配。
	Permissions []string `json:"permissions,omitempty"`
	// Parents lists inherited role names; missing parents are ignored at resolution time. | Parents 列出继承的父角色名称；解析时忽略不存在的父角色。
	Parents []string `json:"parents,omitempty"`
	// Scope, when non-empty, restricts the role to authorization requests in a matching scope; the
	// same "*" and "prefix:*" globs apply. | Scope 非空时把角色限制在匹配作用域的授权请求中；同样支持
	// "*" 与 "prefix:*" 通配。
	Scope string `json:"scope,omitempty"`
	// Metadata holds application-defined scalar attributes. | Metadata 保存应用自定义的标量属性。
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Clone returns a deep copy of r. | Clone 返回 r 的深拷贝。
func (r Role) Clone() Role {
	out := r
	out.Permissions = append([]string(nil), r.Permissions...)
	out.Parents = append([]string(nil), r.Parents...)
	if len(r.Metadata) > 0 {
		out.Metadata = make(map[string]string, len(r.Metadata))
		for k, v := range r.Metadata {
			out.Metadata[k] = v
		}
	}
	return out
}

// Assignment binds a subject to a role inside an optional scope. | Assignment 在可选作用域内把主体绑定到角色。
type Assignment struct {
	// Subject is the opaque subject identifier, normally a user identifier. | Subject 是不透明主体标识，通常是用户标识。
	Subject string `json:"subject"`
	// Role is the assigned role name. | Role 是所分配的角色名称。
	Role string `json:"role"`
	// Scope limits where the assignment applies; empty means every scope, and "*" or "prefix:*"
	// globs are honoured. | Scope 限制分配生效的作用域；空值表示所有作用域，并支持 "*" 与 "prefix:*" 通配。
	Scope string `json:"scope,omitempty"`
	// Conditions are equality constraints evaluated against the request before the role is granted;
	// keys may use attribute dot paths such as "subject.department". | Conditions 是在授予角色前对请求
	// 求值的等值约束；键可使用 "subject.department" 这类属性点路径。
	Conditions map[string]string `json:"conditions,omitempty"`
	// ExpiresAt is the exclusive deadline; the zero value means the assignment never expires. | ExpiresAt 是排他期限；零值表示永不过期。
	ExpiresAt time.Time `json:"expiresAt,omitempty"`
	// CreatedAt is the creation timestamp; zero is replaced with the store time on Assign. | CreatedAt 是创建时间；为零时在 Assign 中替换为存储时间。
	CreatedAt time.Time `json:"createdAt,omitempty"`
}

// Clone returns a deep copy of a. | Clone 返回 a 的深拷贝。
func (a Assignment) Clone() Assignment {
	out := a
	if len(a.Conditions) > 0 {
		out.Conditions = make(map[string]string, len(a.Conditions))
		for k, v := range a.Conditions {
			out.Conditions[k] = v
		}
	}
	return out
}

// Expired reports whether the assignment is inactive at now. | Expired 报告分配在 now 时刻是否已失效。
func (a Assignment) Expired(now time.Time) bool {
	return !a.ExpiresAt.IsZero() && !now.Before(a.ExpiresAt)
}

// Condition is one attribute predicate of a Policy. | Condition 是策略的一条属性谓词。
type Condition struct {
	// Key is the operand path, for example "subject.department", "resource.owner" or "env.ip". | Key 是操作数路径，例如 "subject.department"、"resource.owner" 或 "env.ip"。
	Key string `json:"key"`
	// Operator is one of the supported operators such as "eq", "in" or "starts_with". | Operator 是受支持的运算符之一，例如 "eq"、"in" 或 "starts_with"。
	Operator string `json:"operator"`
	// Value is the right-hand operand; in / not_in treat it as a comma-separated list. | Value 是右操作数；in / not_in 把它视为逗号分隔列表。
	Value string `json:"value,omitempty"`
}

// Policy is an attribute-based permit or deny rule. | Policy 是基于属性的许可或拒绝规则。
type Policy struct {
	// ID is the unique policy identifier. | ID 是唯一策略标识。
	ID string `json:"id"`
	// Effect is EffectPermit or EffectDeny. | Effect 取值为 EffectPermit 或 EffectDeny。
	Effect string `json:"effect"`
	// Subject matches the request subject or any effective role; empty means every subject. | Subject 匹配请求主体或任一有效角色；空值表示所有主体。
	Subject string `json:"subject,omitempty"`
	// Resource matches the request resource; empty means every resource. | Resource 匹配请求资源；空值表示所有资源。
	Resource string `json:"resource,omitempty"`
	// Action matches the requested action; empty means every action. | Action 匹配请求动作；空值表示所有动作。
	Action string `json:"action,omitempty"`
	// Scope matches the request scope; empty means every scope. | Scope 匹配请求作用域；空值表示所有作用域。
	Scope string `json:"scope,omitempty"`
	// Conditions must all hold for the policy to apply. | Conditions 必须全部成立，策略才适用。
	Conditions []Condition `json:"conditions,omitempty"`
	// Priority orders first-applicable evaluation; higher values are considered first. | Priority 决定 first-applicable 的求值顺序；数值越大越先考虑。
	Priority int `json:"priority,omitempty"`
	// Description is a human-readable summary. | Description 是人类可读的说明。
	Description string `json:"description,omitempty"`
}

// Clone returns a deep copy of p. | Clone 返回 p 的深拷贝。
func (p Policy) Clone() Policy {
	out := p
	out.Conditions = append([]Condition(nil), p.Conditions...)
	return out
}

// Request is one authorization question. | Request 是一次授权询问。
type Request struct {
	// Subject is the stable identifier of the requesting subject. | Subject 是请求主体的稳定标识。
	Subject string `json:"subject"`
	// Roles are trusted roles asserted by the caller, for example from an authenticated principal. | Roles 是调用方断言的可信角色，例如来自已认证主体。
	Roles []string `json:"roles,omitempty"`
	// Action is the permission being requested. | Action 是所请求的权限。
	Action string `json:"action"`
	// Resource is the resource identifier the action targets. | Resource 是动作所指向的资源标识。
	Resource string `json:"resource,omitempty"`
	// Scope is the optional authorization scope such as a tenant. | Scope 是可选授权作用域，例如租户。
	Scope string `json:"scope,omitempty"`
	// Attributes holds arbitrary scalar operands for conditions and assignments. | Attributes 保存条件与分配使用的任意标量操作数。
	Attributes map[string]string `json:"attributes,omitempty"`
	// Environment holds request-environment operands, addressed as "env.<name>". | Environment 保存请求环境操作数，以 "env.<name>" 寻址。
	Environment map[string]string `json:"environment,omitempty"`
}

// Decision is the outcome of one authorization request. | Decision 是一次授权请求的结果。
type Decision struct {
	// Allowed reports whether the request is permitted. | Allowed 报告请求是否被允许。
	Allowed bool `json:"allowed"`
	// Reason explains the decisive grant or denial in English. | Reason 用英文说明决定性的授予或拒绝原因。
	Reason string `json:"reason,omitempty"`
	// MatchedRoles lists the effective roles, including inherited ones, sorted by name. | MatchedRoles 列出有效角色（含继承角色），按名称排序。
	MatchedRoles []string `json:"matchedRoles,omitempty"`
	// MatchedPolicies lists every applicable policy identifier, sorted by identifier. | MatchedPolicies 列出所有适用策略标识，按标识排序。
	MatchedPolicies []string `json:"matchedPolicies,omitempty"`
}
