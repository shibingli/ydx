package rbac

import (
	"sort"
	"strconv"
	"strings"
	"time"

	authrbac "github.com/shibingli/ydx/auth/authz/rbac"
	"github.com/shibingli/ydx/errs"
	ydxjson "github.com/shibingli/ydx/json"
)

// encodeParentList renders a parent list with the length-prefixed encoding the Lua scripts share.
// | encodeParentList 用 Lua 脚本共享的长度前缀编码渲染父角色列表。
func encodeParentList(parents []string) string {
	var builder strings.Builder
	for _, parent := range parents {
		builder.WriteString(segment(parent))
	}
	return builder.String()
}

// decodeParentList parses the length-prefixed parent list written by encodeParentList and the Lua
// scripts. The parent hash is authoritative after a role removal rewrites it, so reads overlay it
// onto the role JSON. | decodeParentList 解析 encodeParentList 与 Lua 脚本写入的带长度前缀父角色
// 列表。角色删除重写父角色哈希后该哈希是权威来源，因此读取时用它覆盖角色 JSON。
func decodeParentList(encoded string) ([]string, error) {
	var parents []string
	for len(encoded) > 0 {
		colon := strings.IndexByte(encoded, ':')
		if colon <= 0 {
			return nil, errs.Detail(ErrStoreUnavailable, "stored parent list is corrupt | 存储的父角色列表损坏")
		}
		length, err := strconv.Atoi(encoded[:colon])
		if err != nil || length < 0 || colon+1+length > len(encoded) {
			return nil, errs.Detail(ErrStoreUnavailable, "stored parent list is corrupt | 存储的父角色列表损坏")
		}
		parents = append(parents, encoded[colon+1:colon+1+length])
		encoded = encoded[colon+1+length:]
	}
	return parents, nil
}

// assignmentID identifies an Assignment by its subject, role and scope. Every segment carries a
// byte-length prefix, so arbitrary identifiers cannot produce the same key.
// | assignmentID 以主体、角色与作用域标识一条 Assignment。每个段都带字节长度前缀，因此任意标识
// 都不会产生相同的键。
func assignmentID(subject, role, scope string) string {
	return segment(subject) + segment(role) + segment(scope)
}

// expiryString encodes an optional deadline as a flag, whole seconds and nanoseconds. The split
// keeps exact nanosecond comparisons possible inside Redis Lua, whose numbers cannot represent a
// Unix nanosecond timestamp without precision loss.
// | expiryString 把可选期限编码为标志、整秒与纳秒。拆分使 Redis Lua 内可以进行精确纳秒比较，
// 因为 Lua 数字无法无损表示 Unix 纳秒时间戳。
func expiryString(deadline time.Time) string {
	if deadline.IsZero() {
		return "0:0:0"
	}
	deadline = deadline.UTC()
	return "1:" + strconv.FormatInt(deadline.Unix(), 10) + ":" + strconv.FormatInt(int64(deadline.Nanosecond()), 10)
}

// nowFields encodes an instant as whole seconds and nanoseconds for the Lua expiry comparison.
// | nowFields 把时刻编码为整秒与纳秒，供 Lua 期限比较使用。
func nowFields(now time.Time) (string, string) {
	now = now.UTC()
	return strconv.FormatInt(now.Unix(), 10), strconv.FormatInt(int64(now.Nanosecond()), 10)
}

// utcTime normalizes non-zero times to UTC and keeps the zero value canonical.
// | utcTime 把非零时间规范化为 UTC，并保持零值的规范形态。
func utcTime(value time.Time) time.Time {
	if value.IsZero() {
		return time.Time{}
	}
	return value.UTC()
}

// normalizeAssignmentTimes normalizes every time carried by an assignment.
// | normalizeAssignmentTimes 规范化分配携带的每个时间。
func normalizeAssignmentTimes(assignment *authrbac.Assignment) {
	assignment.ExpiresAt = utcTime(assignment.ExpiresAt)
	assignment.CreatedAt = utcTime(assignment.CreatedAt)
}

// encodeRole serializes one role. | encodeRole 序列化单个角色。
func encodeRole(role authrbac.Role) ([]byte, error) {
	return marshalRecord(role, "role")
}

// decodeRole deserializes one role into a fresh value. | decodeRole 把单个角色反序列化为全新值。
func decodeRole(data []byte) (authrbac.Role, error) {
	var role authrbac.Role
	if err := unmarshalRecord(data, &role, "role"); err != nil {
		return authrbac.Role{}, err
	}
	return role, nil
}

// encodePolicy serializes one normalized policy. | encodePolicy 序列化单条规范化策略。
func encodePolicy(policy authrbac.Policy) ([]byte, error) {
	return marshalRecord(policy, "policy")
}

// decodePolicy deserializes one policy into a fresh value. | decodePolicy 把单条策略反序列化为全新值。
func decodePolicy(data []byte) (authrbac.Policy, error) {
	var policy authrbac.Policy
	if err := unmarshalRecord(data, &policy, "policy"); err != nil {
		return authrbac.Policy{}, err
	}
	return policy, nil
}

// encodeAssignment serializes one assignment after normalizing its times.
// | encodeAssignment 在规范化时间后序列化单条分配。
func encodeAssignment(assignment authrbac.Assignment) ([]byte, error) {
	stored := assignment.Clone()
	normalizeAssignmentTimes(&stored)
	return marshalRecord(stored, "assignment")
}

// decodeAssignment deserializes one assignment and normalizes its times.
// | decodeAssignment 反序列化单条分配并规范化其时间。
func decodeAssignment(data []byte) (authrbac.Assignment, error) {
	var assignment authrbac.Assignment
	if err := unmarshalRecord(data, &assignment, "assignment"); err != nil {
		return authrbac.Assignment{}, err
	}
	normalizeAssignmentTimes(&assignment)
	return assignment, nil
}

// marshalRecord converts one record and maps encoding failures to rbac.ErrInvalidRequest without
// exposing library internals. | marshalRecord 转换一条记录，并把编码失败映射为 rbac.ErrInvalidRequest，
// 且不暴露库内部信息。
func marshalRecord(value any, kind string) ([]byte, error) {
	data, err := ydxjson.Marshal(value)
	if err != nil {
		return nil, errs.Detail(authrbac.ErrInvalidRequest, "%s cannot be encoded | %s 无法编码", kind, kind)
	}
	return data, nil
}

// unmarshalRecord converts one stored record and maps corruption to ErrStoreUnavailable.
// | unmarshalRecord 转换一条已存记录，并把损坏映射为 ErrStoreUnavailable。
func unmarshalRecord(data []byte, out any, kind string) error {
	if len(data) == 0 {
		return errs.Detail(ErrStoreUnavailable, "stored %s is empty | 存储的 %s 为空", kind, kind)
	}
	if err := ydxjson.Unmarshal(data, out); err != nil {
		return errs.Detail(ErrStoreUnavailable, "stored %s is corrupt | 存储的 %s 数据损坏", kind, kind)
	}
	return nil
}

// validateRole reports whether role has a name, non-empty permissions and non-empty parents,
// matching the in-memory store. | validateRole 报告角色是否具有名称、非空权限与非空父角色，与内存
// 存储保持一致。
func validateRole(role authrbac.Role) error {
	if strings.TrimSpace(role.Name) == "" {
		return errs.Detail(authrbac.ErrInvalidRole, "empty role name | 角色名称为空")
	}
	for _, permission := range role.Permissions {
		if strings.TrimSpace(permission) == "" {
			return errs.Detail(authrbac.ErrInvalidRole, "role %q has an empty permission | 角色 %q 含空权限", role.Name, role.Name)
		}
	}
	for _, parent := range role.Parents {
		if strings.TrimSpace(parent) == "" {
			return errs.Detail(authrbac.ErrInvalidRole, "role %q has an empty parent | 角色 %q 含空父角色", role.Name, role.Name)
		}
	}
	return nil
}

// validateAssignment reports whether an assignment has a subject, role and non-empty condition
// keys, matching the in-memory store. | validateAssignment 报告分配是否具有主体、角色以及非空条件键，
// 与内存存储保持一致。
func validateAssignment(assignment authrbac.Assignment) error {
	if strings.TrimSpace(assignment.Subject) == "" {
		return errs.Detail(authrbac.ErrInvalidAssignment, "empty subject | 主体为空")
	}
	if strings.TrimSpace(assignment.Role) == "" {
		return errs.Detail(authrbac.ErrInvalidAssignment, "empty role | 角色为空")
	}
	for key := range assignment.Conditions {
		if strings.TrimSpace(key) == "" {
			return errs.Detail(authrbac.ErrInvalidAssignment, "empty condition key | 条件键为空")
		}
	}
	return nil
}

// normalizePolicy validates a policy and returns the normalized form used by the in-memory store.
// | normalizePolicy 校验策略并返回内存存储使用的规范化形式。
func normalizePolicy(policy authrbac.Policy) (authrbac.Policy, error) {
	out := policy.Clone()
	if strings.TrimSpace(out.ID) == "" {
		return authrbac.Policy{}, errs.Detail(authrbac.ErrInvalidPolicy, "empty policy id | 策略标识为空")
	}
	effect := strings.ToLower(strings.TrimSpace(out.Effect))
	switch effect {
	case authrbac.EffectPermit, authrbac.EffectDeny:
		out.Effect = effect
	default:
		return authrbac.Policy{}, errs.Detail(authrbac.ErrInvalidPolicy, "policy %q has effect %q | 策略 %q 的效果为 %q", out.ID, out.Effect, out.ID, out.Effect)
	}
	for index, condition := range out.Conditions {
		condition = normalizeCondition(condition)
		if err := validateCondition(condition); err != nil {
			return authrbac.Policy{}, errs.WrapDetail(err, authrbac.ErrInvalidPolicy, "policy %q condition %d | 策略 %q 条件 %d", out.ID, index, out.ID, index)
		}
		out.Conditions[index] = condition
	}
	return out, nil
}

// normalizeCondition returns condition with its operator trimmed and lower-cased.
// | normalizeCondition 返回运算符已去空白并转为小写的 condition。
func normalizeCondition(condition authrbac.Condition) authrbac.Condition {
	condition.Operator = strings.ToLower(strings.TrimSpace(condition.Operator))
	return condition
}

// validateCondition reports whether condition has a key and a supported operator.
// | validateCondition 报告 condition 是否具有键与受支持的运算符。
func validateCondition(condition authrbac.Condition) error {
	if strings.TrimSpace(condition.Key) == "" {
		return errs.Detail(authrbac.ErrInvalidCondition, "empty condition key | 条件键为空")
	}
	if !supportedOperator(condition.Operator) {
		return errs.Detail(authrbac.ErrInvalidCondition, "unsupported operator %q | 不支持的运算符 %q", condition.Operator, condition.Operator)
	}
	return nil
}

// supportedOperator reports whether operator is one of the declared condition operators.
// | supportedOperator 报告 operator 是否为已声明的条件运算符之一。
func supportedOperator(operator string) bool {
	switch strings.ToLower(strings.TrimSpace(operator)) {
	case authrbac.OperatorEquals, authrbac.OperatorNotEquals, authrbac.OperatorIn,
		authrbac.OperatorNotIn, authrbac.OperatorContains, authrbac.OperatorStartsWith,
		authrbac.OperatorEndsWith, authrbac.OperatorGreaterThan,
		authrbac.OperatorGreaterOrEqual, authrbac.OperatorLessThan,
		authrbac.OperatorLessOrEqual, authrbac.OperatorPresent, authrbac.OperatorAbsent:
		return true
	}
	return false
}

// sortRoles orders roles by name. | sortRoles 按名称排列角色。
func sortRoles(roles []authrbac.Role) {
	sort.Slice(roles, func(i, j int) bool { return roles[i].Name < roles[j].Name })
}

// sortPolicies orders policies by identifier. | sortPolicies 按标识排列策略。
func sortPolicies(policies []authrbac.Policy) {
	sort.Slice(policies, func(i, j int) bool { return policies[i].ID < policies[j].ID })
}

// sortAssignments orders assignments by subject, role and scope.
// | sortAssignments 按主体、角色与作用域排列分配。
func sortAssignments(assignments []authrbac.Assignment) {
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

// stringValue converts a go-redis reply element to a string. | stringValue 把 go-redis 应答元素转换为字符串。
func stringValue(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case []byte:
		return string(typed)
	case int64:
		return strconv.FormatInt(typed, 10)
	case uint64:
		return strconv.FormatUint(typed, 10)
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	default:
		return ""
	}
}
