package rbac

import (
	"sort"
	"strings"
)

// globMatch reports whether value is matched by pattern. | globMatch 报告 value 是否被 pattern 匹配。
//
// A pattern of "*" matches every value. A pattern ending in "*" matches every value with the same
// prefix, so "user:*" matches "user:read" and "/api/*" matches "/api/posts". Every other pattern is
// compared exactly. | 模式 "*" 匹配所有值。以 "*" 结尾的模式匹配具有相同前缀的所有值，因此
// "user:*" 匹配 "user:read"，"/api/*" 匹配 "/api/posts"。其它模式按精确值比较。
func globMatch(pattern, value string) bool {
	if pattern == value {
		return true
	}
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(value, strings.TrimSuffix(pattern, "*"))
	}
	return false
}

// scopeAllows reports whether an assignment or policy scope admits requestScope. | scopeAllows
// 报告分配或策略作用域是否接纳 requestScope。
//
// An empty assignment scope applies everywhere. A non-empty scope must match the request scope with
// globMatch, so "tenant:*" admits "tenant:1" but not an empty request scope. | 空的分配作用域适用于
// 所有请求。非空作用域必须与请求作用域经 globMatch 匹配，因此 "tenant:*" 接纳 "tenant:1"，但不接纳
// 空请求作用域。
func scopeAllows(scope, requestScope string) bool {
	if scope == "" {
		return true
	}
	return globMatch(scope, requestScope)
}

// policySubjectMatches reports whether a policy subject pattern matches the request subject or one
// of its effective roles. | policySubjectMatches 报告策略主体模式是否匹配请求主体或其任一有效角色。
//
// An empty pattern matches every request. Otherwise the pattern is matched against the subject
// identifier first and then against each role name, so a policy can target either a user or a
// role. | 空模式匹配所有请求。否则模式先与主体标识匹配，再依次与各角色名匹配，因此策略既可以按
// 用户也可以按角色圈定范围。
func policySubjectMatches(pattern, subject string, roles []string) bool {
	if pattern == "" {
		return true
	}
	if globMatch(pattern, subject) {
		return true
	}
	for _, role := range roles {
		if globMatch(pattern, role) {
			return true
		}
	}
	return false
}

// sortedSet returns the keys of set in ascending order. | sortedSet 按升序返回 set 的键。
func sortedSet(set map[string]struct{}) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
