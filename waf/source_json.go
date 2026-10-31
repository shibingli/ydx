package waf

import (
	"strconv"
	"strings"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
)

// jsonRuleBundle is the native JSON rule format. | jsonRuleBundle 是原生 JSON 规则格式。
type jsonRuleBundle struct {
	Version string     `json:"version"`
	Mode    string     `json:"mode"`
	Rules   []jsonRule `json:"rules"`
}

// jsonRule is one rule in the native JSON format. | jsonRule 是原生 JSON 格式中的一条规则。
type jsonRule struct {
	Variables any         `json:"variables"`
	Operator  string      `json:"operator"`
	Pattern   string      `json:"pattern"`
	Actions   jsonActions `json:"actions"`
	ID        int         `json:"id"`
	Phase     int         `json:"phase"`
}

// jsonActions is the action set of one JSON rule. | jsonActions 是一条 JSON 规则的动作集合。
type jsonActions struct {
	Log             *bool    `json:"log"`
	AuditLog        *bool    `json:"auditlog"`
	Msg             string   `json:"msg"`
	Severity        string   `json:"severity"`
	SkipAfter       string   `json:"skip_after"`
	Redirect        string   `json:"redirect"`
	Tags            []string `json:"tags"`
	Transformations []string `json:"transformations"`
	SetVar          []string `json:"setvar"`
	ExpireVar       []string `json:"expirevar"`
	CTL             []string `json:"ctl"`
	Status          int      `json:"status"`
	Skip            int      `json:"skip"`
	Maturity        int      `json:"maturity"`
	Accuracy        int      `json:"accuracy"`
	Deny            bool     `json:"deny"`
	Drop            bool     `json:"drop"`
	Block           bool     `json:"block"`
	Pass            bool     `json:"pass"`
	Allow           bool     `json:"allow"`
	Capture         bool     `json:"capture"`
	MultiMatch      bool     `json:"multimatch"`
}

// jsonBundleToSecLang converts the native JSON format into SecLang directives. | jsonBundleToSecLang
// 把原生 JSON 格式转换为 SecLang 指令。
func jsonBundleToSecLang(data []byte) (string, error) {
	var bundle jsonRuleBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return "", errs.Wrap(err, ErrInvalidBundle)
	}
	if len(bundle.Rules) == 0 {
		return "", errs.Detail(ErrInvalidBundle, "json bundle has no rules | JSON 规则包没有规则")
	}
	var b strings.Builder
	b.Grow(len(data))
	switch strings.ToLower(bundle.Mode) {
	case "on", "block", "blocking":
		b.WriteString("SecRuleEngine On\n")
	case "detectiononly", "detection":
		b.WriteString("SecRuleEngine DetectionOnly\n")
	case "off":
		b.WriteString("SecRuleEngine Off\n")
	}
	for _, rule := range bundle.Rules {
		variables := jsonVariables(rule.Variables)
		if variables == "" {
			return "", errs.Detail(ErrInvalidBundle, "json rule %d has no variables | JSON 规则 %d 没有变量", rule.ID, rule.ID)
		}
		operator := strings.TrimSpace(rule.Operator)
		if operator == "" {
			operator = "@rx"
		}
		if !strings.HasPrefix(operator, "@") {
			operator = "@" + operator
		}
		operatorText := operator
		if strings.TrimSpace(rule.Pattern) != "" {
			operatorText += " " + rule.Pattern
		}
		actions := jsonActionList(rule)
		b.WriteString("SecRule ")
		b.WriteString(variables)
		b.WriteByte(' ')
		b.WriteString(quoteDouble(operatorText))
		if actions != "" {
			b.WriteByte(' ')
			b.WriteString(quoteDouble(actions))
		}
		b.WriteByte('\n')
	}
	return b.String(), nil
}

// jsonVariables normalizes a JSON variables value that may be a string or an array.
// | jsonVariables 归一化可能为字符串或数组的 JSON 变量值。
func jsonVariables(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case []any:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			if text, ok := item.(string); ok {
				parts = append(parts, text)
			}
		}
		return strings.Join(parts, "|")
	case []string:
		return strings.Join(v, "|")
	default:
		return ""
	}
}

// jsonActionList renders the action list of one JSON rule. | jsonActionList 渲染一条 JSON 规则的动作列表。
func jsonActionList(rule jsonRule) string {
	actions := make([]string, 0, 12)
	if rule.ID > 0 {
		actions = append(actions, "id:"+strconv.Itoa(rule.ID))
	}
	if rule.Phase > 0 {
		actions = append(actions, "phase:"+strconv.Itoa(rule.Phase))
	}
	switch {
	case rule.Actions.Drop:
		actions = append(actions, "drop")
	case rule.Actions.Block:
		actions = append(actions, "block")
	case rule.Actions.Redirect != "":
		actions = append(actions, "redirect:"+quoteSingle(rule.Actions.Redirect))
	case rule.Actions.Deny:
		actions = append(actions, "deny")
	case rule.Actions.Allow:
		actions = append(actions, "allow")
	case rule.Actions.Pass:
		actions = append(actions, "pass")
	}
	if rule.Actions.Log != nil {
		if *rule.Actions.Log {
			actions = append(actions, "log")
		} else {
			actions = append(actions, "nolog")
		}
	}
	if rule.Actions.AuditLog != nil {
		if *rule.Actions.AuditLog {
			actions = append(actions, "auditlog")
		} else {
			actions = append(actions, "noauditlog")
		}
	}
	if rule.Actions.Capture {
		actions = append(actions, "capture")
	}
	if rule.Actions.MultiMatch {
		actions = append(actions, "multiMatch")
	}
	if rule.Actions.Status > 0 {
		actions = append(actions, "status:"+strconv.Itoa(rule.Actions.Status))
	}
	if rule.Actions.Msg != "" {
		actions = append(actions, "msg:"+quoteSingle(rule.Actions.Msg))
	}
	if rule.Actions.Severity != "" {
		actions = append(actions, "severity:"+quoteSingle(rule.Actions.Severity))
	}
	for _, tag := range rule.Actions.Tags {
		actions = append(actions, "tag:"+quoteSingle(tag))
	}
	for _, transform := range rule.Actions.Transformations {
		actions = append(actions, "t:"+transform)
	}
	for _, setvar := range rule.Actions.SetVar {
		actions = append(actions, "setvar:"+quoteSingle(setvar))
	}
	for _, expirevar := range rule.Actions.ExpireVar {
		actions = append(actions, "expirevar:"+quoteSingle(expirevar))
	}
	for _, ctl := range rule.Actions.CTL {
		actions = append(actions, "ctl:"+quoteSingle(ctl))
	}
	if rule.Actions.Skip > 0 {
		actions = append(actions, "skip:"+strconv.Itoa(rule.Actions.Skip))
	}
	if rule.Actions.SkipAfter != "" {
		actions = append(actions, "skipAfter:"+quoteSingle(rule.Actions.SkipAfter))
	}
	if rule.Actions.Maturity > 0 {
		actions = append(actions, "maturity:"+strconv.Itoa(rule.Actions.Maturity))
	}
	if rule.Actions.Accuracy > 0 {
		actions = append(actions, "accuracy:"+strconv.Itoa(rule.Actions.Accuracy))
	}
	return strings.Join(actions, ",")
}

// quoteDouble quotes text for a double-quoted SecLang token, preserving backslashes through the
// lexer's unescape rules. | quoteDouble 把文本包装为双引号 SecLang 标记，并按词法器反转义规则
// 保留反斜杠。
func quoteDouble(value string) string {
	var b strings.Builder
	b.Grow(len(value) + 2)
	b.WriteByte('"')
	for i := 0; i < len(value); i++ {
		switch value[i] {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		default:
			b.WriteByte(value[i])
		}
	}
	b.WriteByte('"')
	return b.String()
}

// quoteSingle quotes text for a single-quoted action value. | quoteSingle 把文本包装为单引号动作值。
func quoteSingle(value string) string {
	var b strings.Builder
	b.Grow(len(value) + 2)
	b.WriteByte('\'')
	for i := 0; i < len(value); i++ {
		switch value[i] {
		case '\\':
			b.WriteString(`\\`)
		case '\'':
			b.WriteString(`\'`)
		default:
			b.WriteByte(value[i])
		}
	}
	b.WriteByte('\'')
	return b.String()
}
