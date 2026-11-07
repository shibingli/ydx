package rbac

import (
	"strconv"
	"strings"

	"github.com/shibingli/ydx/errs"
)

// The supported condition operators. | 支持的条件运算符。
const (
	// OperatorEquals compares the operand and the value for string equality. | OperatorEquals 比较操作数与值的字符串相等性。
	OperatorEquals = "eq"
	// OperatorNotEquals compares the operands for string inequality; an absent operand never matches. | OperatorNotEquals 比较操作数的字符串不等性；操作数缺失时永不匹配。
	OperatorNotEquals = "ne"
	// OperatorIn reports whether the operand appears in the comma-separated value list. | OperatorIn 报告操作数是否出现在逗号分隔的值列表中。
	OperatorIn = "in"
	// OperatorNotIn reports whether the operand is absent from the comma-separated value list. | OperatorNotIn 报告操作数是否不在逗号分隔的值列表中。
	OperatorNotIn = "not_in"
	// OperatorContains reports whether the operand contains the value. | OperatorContains 报告操作数是否包含值。
	OperatorContains = "contains"
	// OperatorStartsWith reports whether the operand starts with the value. | OperatorStartsWith 报告操作数是否以值开头。
	OperatorStartsWith = "starts_with"
	// OperatorEndsWith reports whether the operand ends with the value. | OperatorEndsWith 报告操作数是否以值结尾。
	OperatorEndsWith = "ends_with"
	// OperatorGreaterThan reports whether the operand is numerically greater than the value. | OperatorGreaterThan 报告操作数在数值上是否大于值。
	OperatorGreaterThan = "gt"
	// OperatorGreaterOrEqual reports whether the operand is numerically greater than or equal to the value. | OperatorGreaterOrEqual 报告操作数在数值上是否大于等于值。
	OperatorGreaterOrEqual = "ge"
	// OperatorLessThan reports whether the operand is numerically less than the value. | OperatorLessThan 报告操作数在数值上是否小于值。
	OperatorLessThan = "lt"
	// OperatorLessOrEqual reports whether the operand is numerically less than or equal to the value. | OperatorLessOrEqual 报告操作数在数值上是否小于等于值。
	OperatorLessOrEqual = "le"
	// OperatorPresent reports whether the operand key resolves to any value. | OperatorPresent 报告操作数键是否解析到任意值。
	OperatorPresent = "present"
	// OperatorAbsent reports whether the operand key does not resolve. | OperatorAbsent 报告操作数键是否无法解析。
	OperatorAbsent = "absent"
)

// attributeResolver resolves condition operands from a Request. | attributeResolver 从 Request 解析条件操作数。
type attributeResolver struct {
	req *Request
}

// lookup resolves key to a value and reports whether it is present. | lookup 把 key 解析为值并报告是否存在。
//
// Built-in keys subject, action, resource and scope resolve to the corresponding Request fields; an
// empty field counts as absent. An exact entry in Attributes wins next, followed by the env. /
// environment. prefix into Environment and the subject. / resource. prefix into Attributes with the
// prefix stripped, so "subject.department" finds Attributes["department"]. Unknown keys are finally
// looked up in Environment. | 内建键 subject、action、resource 与 scope 解析为对应 Request 字段；
// 空字段视为缺失。随后优先使用 Attributes 中的精确条目，再处理 env. / environment. 前缀到
// Environment 的映射，以及 subject. / resource. 前缀到 Attributes 去前缀后的映射，因此
// "subject.department" 可找到 Attributes["department"]。未知键最后在 Environment 中查找。
func (r attributeResolver) lookup(key string) (string, bool) {
	if key == "" {
		return "", false
	}
	switch key {
	case "subject":
		return r.req.Subject, r.req.Subject != ""
	case "action":
		return r.req.Action, r.req.Action != ""
	case "resource":
		return r.req.Resource, r.req.Resource != ""
	case "scope":
		return r.req.Scope, r.req.Scope != ""
	}
	if value, ok := r.req.Attributes[key]; ok {
		return value, true
	}
	switch {
	case strings.HasPrefix(key, "env."):
		value, ok := r.req.Environment[strings.TrimPrefix(key, "env.")]
		return value, ok && strings.TrimPrefix(key, "env.") != ""
	case strings.HasPrefix(key, "environment."):
		name := strings.TrimPrefix(key, "environment.")
		value, ok := r.req.Environment[name]
		return value, ok && name != ""
	case strings.HasPrefix(key, "subject."):
		name := strings.TrimPrefix(key, "subject.")
		if value, ok := r.req.Attributes[name]; ok {
			return value, true
		}
		if name == "id" {
			return r.req.Subject, r.req.Subject != ""
		}
		return "", false
	case strings.HasPrefix(key, "resource."):
		name := strings.TrimPrefix(key, "resource.")
		if value, ok := r.req.Attributes[name]; ok {
			return value, true
		}
		if name == "id" {
			return r.req.Resource, r.req.Resource != ""
		}
		return "", false
	}
	if value, ok := r.req.Environment[key]; ok {
		return value, true
	}
	return "", false
}

// normalizeOperator trims and lower-cases a condition operator. | normalizeOperator 去除条件运算符两端空白并转为小写。
func normalizeOperator(operator string) string {
	return strings.ToLower(strings.TrimSpace(operator))
}

// normalizeCondition returns c with its operator normalized. | normalizeCondition 返回运算符已规范化的 c。
func normalizeCondition(c Condition) Condition {
	c.Operator = normalizeOperator(c.Operator)
	return c
}

// validateCondition reports whether c has a key and a supported operator. | validateCondition 报告 c 是否具有键与受支持的运算符。
func validateCondition(c Condition) error {
	if strings.TrimSpace(c.Key) == "" {
		return errs.Detail(ErrInvalidCondition, "empty condition key | 条件键为空")
	}
	if !supportedOperator(c.Operator) {
		return errs.Detail(ErrInvalidCondition, "unsupported operator %q | 不支持的运算符 %q", c.Operator, c.Operator)
	}
	return nil
}

// supportedOperator reports whether operator is one of the declared operators. | supportedOperator
// 报告 operator 是否为已声明的运算符之一。
func supportedOperator(operator string) bool {
	switch normalizeOperator(operator) {
	case OperatorEquals, OperatorNotEquals, OperatorIn, OperatorNotIn, OperatorContains,
		OperatorStartsWith, OperatorEndsWith, OperatorGreaterThan, OperatorGreaterOrEqual,
		OperatorLessThan, OperatorLessOrEqual, OperatorPresent, OperatorAbsent:
		return true
	}
	return false
}

// evaluateCondition reports whether c holds for the request resolved by resolver. | evaluateCondition
// 报告 c 对 resolver 所解析的请求是否成立。
//
// Unknown operators and non-numeric operands of ordering operators do not match; policies are
// validated on insertion, so an unknown operator only appears through direct calls. | 未知运算符与
// 排序运算符的非数值操作数均不匹配；策略在插入时已校验，因此未知运算符只会在直接调用时出现。
func evaluateCondition(c Condition, resolver attributeResolver) bool {
	operand, present := resolver.lookup(c.Key)
	switch normalizeOperator(c.Operator) {
	case OperatorEquals:
		return present && operand == c.Value
	case OperatorNotEquals:
		return present && operand != c.Value
	case OperatorIn:
		return present && containsToken(c.Value, operand)
	case OperatorNotIn:
		return present && !containsToken(c.Value, operand)
	case OperatorContains:
		return present && strings.Contains(operand, c.Value)
	case OperatorStartsWith:
		return present && strings.HasPrefix(operand, c.Value)
	case OperatorEndsWith:
		return present && strings.HasSuffix(operand, c.Value)
	case OperatorGreaterThan:
		left, right, ok := compareNumbers(operand, c.Value)
		return present && ok && left > right
	case OperatorGreaterOrEqual:
		left, right, ok := compareNumbers(operand, c.Value)
		return present && ok && left >= right
	case OperatorLessThan:
		left, right, ok := compareNumbers(operand, c.Value)
		return present && ok && left < right
	case OperatorLessOrEqual:
		left, right, ok := compareNumbers(operand, c.Value)
		return present && ok && left <= right
	case OperatorPresent:
		return present
	case OperatorAbsent:
		return !present
	}
	return false
}

// evaluateConditions reports whether every condition holds. | evaluateConditions 报告是否所有条件都成立。
func evaluateConditions(conditions []Condition, resolver attributeResolver) bool {
	for _, condition := range conditions {
		if !evaluateCondition(condition, resolver) {
			return false
		}
	}
	return true
}

// containsToken reports whether operand exactly equals one of the comma-separated tokens. | containsToken
// 报告 operand 是否精确等于逗号分隔的某个标记。
func containsToken(list, operand string) bool {
	for _, token := range strings.Split(list, ",") {
		if strings.TrimSpace(token) == operand {
			return true
		}
	}
	return false
}

// compareNumbers parses both operands as float64. | compareNumbers 把两个操作数解析为 float64。
func compareNumbers(left, right string) (float64, float64, bool) {
	l, err := strconv.ParseFloat(strings.TrimSpace(left), 64)
	if err != nil {
		return 0, 0, false
	}
	r, err := strconv.ParseFloat(strings.TrimSpace(right), 64)
	if err != nil {
		return 0, 0, false
	}
	return l, r, true
}
