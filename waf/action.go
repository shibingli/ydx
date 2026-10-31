package waf

import (
	"errors"
	"strconv"
	"strings"

	"github.com/shibingli/ydx/errs"
)

// blockingAction is the disruptive action selected by SecDefaultAction. The SecLang block action
// executes this action instead of always denying. | blockingAction 是 SecDefaultAction 选定的
// 破坏性动作。SecLang 的 block 动作执行该动作，而不是总是拒绝。
type blockingAction struct {
	action string
	data   string
	status int
}

// resolveBlocking derives the block action from a default action list. | resolveBlocking 从默认
// 动作列表推导 block 动作。
func resolveBlocking(defaults []actionSpec) blockingAction {
	result := blockingAction{action: "pass"}
	for _, spec := range defaults {
		switch spec.name {
		case "deny":
			result.action = "deny"
			result.data = ""
		case "drop":
			result.action = "drop"
			result.data = ""
		case "redirect":
			result.action = "redirect"
			result.data = spec.value
		case "pass":
			result.action = "pass"
			result.data = ""
		case "status":
			if status, err := strconv.Atoi(spec.value); err == nil && status >= 100 && status <= 599 {
				result.status = status
			}
		}
	}
	return result
}

// actionSpec is one unparsed action from a rule action list. | actionSpec 是规则动作列表中一个
// 未解析的动作。
type actionSpec struct {
	name  string
	value string
}

// parseActionSpecs splits an action list into lower-cased names and unquoted values. | parseActionSpecs
// 把动作列表拆分为小写名称与去引号取值。
func parseActionSpecs(raw string) []actionSpec {
	parts := splitActionList(raw)
	specs := make([]actionSpec, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, value, ok := strings.Cut(part, ":")
		if !ok {
			name = part
			value = ""
		}
		specs = append(specs, actionSpec{
			name:  strings.ToLower(strings.TrimSpace(name)),
			value: unquoteActionValue(value),
		})
	}
	return specs
}

// compileActions applies an ordered action list to a compiled rule. | compileActions 按顺序把动作
// 列表应用到已编译规则。
func compileActions(specs []actionSpec, rule *compiledRule, cc compileContext) error {
	for _, spec := range specs {
		if err := applyAction(spec, rule, cc); err != nil {
			if !cc.strict && errors.Is(err, ErrUnsupported) {
				if cc.warn != nil {
					cc.warn("action skipped: " + spec.name + " | 已跳过动作：" + spec.name)
				}
				continue
			}
			return err
		}
	}
	return nil
}

// applyAction applies one action. | applyAction 应用一个动作。
func applyAction(spec actionSpec, rule *compiledRule, cc compileContext) error {
	switch spec.name {
	case "id":
		id, err := strconv.Atoi(spec.value)
		if err != nil || id < 0 {
			return errs.Detail(ErrParse, "invalid rule id %q | 非法的规则 id %q", spec.value, spec.value)
		}
		rule.meta.ID = id
	case "phase":
		phase, err := parsePhase(spec.value)
		if err != nil {
			return err
		}
		rule.phase = phase
	case "rev":
		rule.meta.Rev = spec.value
	case "ver":
		rule.meta.Ver = spec.value
	case "msg":
		compiled, err := compileMacro(spec.value)
		if err != nil {
			return err
		}
		rule.meta.Msg = spec.value
		rule.msgMacro = compiled
	case "logdata":
		compiled, err := compileMacro(spec.value)
		if err != nil {
			return err
		}
		rule.meta.LogData = spec.value
		rule.logDataMacro = compiled
	case "tag":
		rule.meta.Tags = append(rule.meta.Tags, spec.value)
	case "severity":
		rule.meta.Severity = normalizeSeverity(spec.value)
	case "maturity":
		value, err := strconv.Atoi(spec.value)
		if err != nil {
			return errs.Detail(ErrParse, "invalid maturity %q | 非法的 maturity %q", spec.value, spec.value)
		}
		rule.meta.Maturity = value
	case "accuracy":
		value, err := strconv.Atoi(spec.value)
		if err != nil {
			return errs.Detail(ErrParse, "invalid accuracy %q | 非法的 accuracy %q", spec.value, spec.value)
		}
		rule.meta.Accuracy = value
	case "status":
		value, err := strconv.Atoi(spec.value)
		if err != nil || value < 100 || value > 599 {
			return errs.Detail(ErrParse, "invalid status %q | 非法的 status %q", spec.value, spec.value)
		}
		rule.status = value
	case "log":
		rule.log = true
	case "nolog":
		rule.log = false
	case "auditlog":
		rule.audit = true
	case "noauditlog":
		rule.audit = false
	case "capture":
		rule.capture = true
	case "multimatch":
		rule.multiMatch = true
	case "chain":
		// Chain structure is handled while grouping rules. | 链结构在分组规则时处理。
	case "skip":
		value, err := strconv.Atoi(spec.value)
		if err != nil || value < 0 {
			return errs.Detail(ErrParse, "invalid skip %q | 非法的 skip %q", spec.value, spec.value)
		}
		rule.skip = value
	case "skipafter":
		if spec.value == "" {
			return errs.Detail(ErrParse, "skipAfter requires a marker | skipAfter 需要标记")
		}
		rule.skipAfter = spec.value
	case "pass":
		rule.pass = true
		rule.deny = false
		rule.drop = false
		rule.block = false
		rule.redirect = ""
	case "allow":
		rule.allow = true
	case "deny":
		rule.deny = true
		rule.drop = false
		rule.block = false
		rule.redirect = ""
	case "drop":
		rule.drop = true
		rule.deny = false
		rule.block = false
		rule.redirect = ""
	case "block":
		switch rule.blocking.action {
		case "deny":
			rule.deny = true
			rule.drop = false
			rule.block = false
			rule.redirect = ""
		case "drop":
			rule.drop = true
			rule.deny = false
			rule.block = false
			rule.redirect = ""
		case "redirect":
			compiled, err := compileMacro(rule.blocking.data)
			if err != nil {
				return err
			}
			rule.redirect = rule.blocking.data
			rule.redirectMacro = compiled
			rule.deny = false
			rule.drop = false
			rule.block = false
		default:
			// SecDefaultAction uses pass, so block is non-disruptive. | SecDefaultAction 使用
			// pass 时，block 不产生破坏性动作。
		}
		if rule.status == 0 && rule.blocking.status > 0 {
			rule.status = rule.blocking.status
		}
	case "redirect":
		if spec.value == "" {
			return errs.Detail(ErrParse, "redirect requires a target | redirect 需要目标地址")
		}
		compiled, err := compileMacro(spec.value)
		if err != nil {
			return err
		}
		rule.redirect = spec.value
		rule.redirectMacro = compiled
		rule.deny = false
		rule.drop = false
		rule.block = false
	case "setvar":
		action, err := compileSetVar(spec.value)
		if err != nil {
			return err
		}
		rule.setvars = append(rule.setvars, action)
	case "expirevar":
		action, err := compileExpireVar(spec.value)
		if err != nil {
			return err
		}
		rule.expires = append(rule.expires, action)
	case "ctl":
		actions, err := compileCtl(spec.value)
		if err != nil {
			return err
		}
		rule.ctls = append(rule.ctls, actions...)
	case "t":
		if strings.EqualFold(spec.value, "none") {
			rule.transforms = nil
			rule.transformKey = ""
			rule.transformCacheable = false
			return nil
		}
		entry, ok := lookupTransform(spec.value)
		if !ok {
			return errs.Detail(ErrUnsupported, "unsupported transformation %q | 不支持的变换 %q", spec.value, spec.value)
		}
		if rule.transformKey == "" {
			rule.transformKey = entry.name
		} else {
			rule.transformKey += "\x00" + entry.name
		}
		rule.transforms = append(rule.transforms, entry.fn)
		if transformCacheWorthy(entry.name, len(rule.transforms)) {
			rule.transformCacheable = true
		}
	case "initcol", "setsid", "setuid", "setrsc", "setenv":
		// Accepted for OWASP CRS compatibility. The IP, SESSION and USER collections are not
		// persisted by this engine, so these actions have no runtime effect.
		// | 为兼容 OWASP CRS 而接受。本引擎不持久化 IP、SESSION 与 USER 集合，因此这些动作没有
		// 运行时效果。
	case "exec", "proxy", "pause":
		return errs.Detail(ErrUnsupported, "action %q is disabled | 动作 %q 已禁用", spec.name, spec.name)
	default:
		return errs.Detail(ErrUnsupported, "unsupported action %q | 不支持的动作 %q", spec.name, spec.name)
	}
	return nil
}

// parsePhase parses a phase number or name. | parsePhase 解析阶段编号或名称。
func parsePhase(value string) (Phase, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "request", "request_headers":
		return PhaseRequestHeaders, nil
	case "2", "request_body":
		return PhaseRequestBody, nil
	case "3", "response", "response_headers":
		return PhaseResponseHeaders, nil
	case "4", "response_body":
		return PhaseResponseBody, nil
	case "5", "logging":
		return PhaseLogging, nil
	default:
		return PhaseNone, errs.Detail(ErrParse, "invalid phase %q | 非法的 phase %q", value, value)
	}
}

// compileSetVar compiles one setvar action. | compileSetVar 编译一个 setvar 动作。
func compileSetVar(value string) (setVarAction, error) {
	action := setVarAction{op: '='}
	if strings.HasPrefix(value, "!") {
		name, err := txVariableName(value[1:])
		if err != nil {
			return setVarAction{}, err
		}
		action.name = name
		action.op = '!'
		return action, nil
	}
	name, raw, ok := strings.Cut(value, "=")
	if !ok {
		return setVarAction{}, errs.Detail(ErrParse, "invalid setvar %q | 非法的 setvar %q", value, value)
	}
	key, err := txVariableName(name)
	if err != nil {
		return setVarAction{}, err
	}
	action.name = key
	if strings.HasPrefix(raw, "+") {
		action.op = '+'
		raw = raw[1:]
	} else if strings.HasPrefix(raw, "-") {
		action.op = '-'
		raw = raw[1:]
	}
	compiled, err := compileMacro(raw)
	if err != nil {
		return setVarAction{}, err
	}
	action.value = compiled
	return action, nil
}

// txVariableName validates a TX variable reference and strips its collection prefix.
// | txVariableName 校验 TX 变量引用并去除集合前缀。
func txVariableName(value string) (string, error) {
	value = strings.TrimSpace(value)
	lower := strings.ToLower(value)
	if !strings.HasPrefix(lower, "tx.") || len(value) <= 3 {
		return "", errs.Detail(ErrUnsupported, "only TX variables are writable: %q | 仅 TX 变量可写：%q", value, value)
	}
	return strings.ToLower(value[3:]), nil
}

// compileExpireVar compiles one expirevar action. | compileExpireVar 编译一个 expirevar 动作。
func compileExpireVar(value string) (expireVarAction, error) {
	name, raw, ok := strings.Cut(value, "=")
	if !ok {
		return expireVarAction{}, errs.Detail(ErrParse, "invalid expirevar %q | 非法的 expirevar %q", value, value)
	}
	key, err := txVariableName(name)
	if err != nil {
		return expireVarAction{}, err
	}
	compiled, err := compileMacro(raw)
	if err != nil {
		return expireVarAction{}, err
	}
	return expireVarAction{name: key, ttl: compiled}, nil
}

// compileCtl compiles one ctl action. Some ctl forms expand into multiple actions.
// | compileCtl 编译一个 ctl 动作；部分 ctl 形式会展开为多个动作。
func compileCtl(value string) ([]ctlAction, error) {
	parts := strings.Split(value, ";")
	if len(parts) == 0 {
		return nil, errs.Detail(ErrParse, "empty ctl | 空的 ctl")
	}
	name, raw, ok := strings.Cut(parts[0], "=")
	if !ok {
		return nil, errs.Detail(ErrParse, "invalid ctl %q | 非法的 ctl %q", value, value)
	}
	name = strings.ToLower(strings.TrimSpace(name))
	raw = strings.TrimSpace(raw)
	switch name {
	case "ruleremovebyid":
		ids, err := parseIDList(raw)
		if err != nil {
			return nil, err
		}
		return []ctlAction{{kind: ctlRuleRemoveByID, ids: ids}}, nil
	case "ruleremovetargetbyid":
		id, err := strconv.Atoi(raw)
		if err != nil {
			return nil, errs.Detail(ErrParse, "invalid rule id in ctl %q | ctl 中的规则 id 非法 %q", value, value)
		}
		targets := parts[1:]
		if len(targets) == 0 {
			return nil, errs.Detail(ErrParse, "ctl ruleRemoveTargetById requires a target | ctl ruleRemoveTargetById 需要目标")
		}
		out := make([]ctlAction, 0, len(targets))
		for _, target := range targets {
			selector, _, err := parseVarSelector(target)
			if err != nil {
				return nil, err
			}
			out = append(out, ctlAction{kind: ctlRuleRemoveTargetByID, id: id, target: selector})
		}
		return out, nil
	case "ruleremovebytag":
		if strings.TrimSpace(raw) == "" {
			return nil, errs.Detail(ErrParse, "ctl ruleRemoveByTag requires a tag | ctl ruleRemoveByTag 需要标签")
		}
		return []ctlAction{{kind: ctlRuleRemoveByTag, value: raw}}, nil
	case "ruleremovetargetbytag":
		if strings.TrimSpace(raw) == "" || len(parts) < 2 {
			return nil, errs.Detail(ErrParse, "ctl ruleRemoveTargetByTag requires a tag and target | ctl ruleRemoveTargetByTag 需要标签与目标")
		}
		targets := parts[1:]
		out := make([]ctlAction, 0, len(targets))
		for _, target := range targets {
			selector, _, err := parseVarSelector(target)
			if err != nil {
				return nil, err
			}
			out = append(out, ctlAction{kind: ctlRuleRemoveTargetByTag, value: raw, target: selector})
		}
		return out, nil
	case "ruleengine":
		mode := ModeDefault
		switch strings.ToLower(raw) {
		case "on":
			mode = ModeBlock
		case "detectiononly":
			mode = ModeDetection
		case "off":
			mode = ModeOff
		default:
			return nil, errs.Detail(ErrParse, "invalid ctl ruleEngine %q | 非法的 ctl ruleEngine %q", raw, raw)
		}
		return []ctlAction{{kind: ctlRuleEngine, value: mode.String()}}, nil
	case "requestbodyprocessor":
		processor := strings.ToUpper(raw)
		switch processor {
		case "JSON", "XML", "URLENCODED", "MULTIPART", "RAW":
		default:
			return nil, errs.Detail(ErrParse, "invalid ctl requestBodyProcessor %q | 非法的 ctl requestBodyProcessor %q", raw, raw)
		}
		return []ctlAction{{kind: ctlRequestBodyProcessor, value: processor}}, nil
	case "forcerequestbodyvariable":
		on, err := parseOnOff(raw)
		if err != nil {
			return nil, err
		}
		return []ctlAction{{kind: ctlForceRequestBodyVariable, on: on}}, nil
	case "requestbodyaccess":
		on, err := parseOnOff(raw)
		if err != nil {
			return nil, err
		}
		return []ctlAction{{kind: ctlRequestBodyAccess, on: on}}, nil
	case "responsebodyaccess":
		on, err := parseOnOff(raw)
		if err != nil {
			return nil, err
		}
		return []ctlAction{{kind: ctlResponseBodyAccess, on: on}}, nil
	case "requestbodylimit":
		limit, err := strconv.Atoi(raw)
		if err != nil || limit <= 0 {
			return nil, errs.Detail(ErrParse, "invalid ctl requestBodyLimit %q | 非法的 ctl requestBodyLimit %q", raw, raw)
		}
		return []ctlAction{{kind: ctlRequestBodyLimit, limit: limit}}, nil
	case "bodylimitaction":
		action := LimitReject
		switch strings.ToLower(raw) {
		case "reject":
			action = LimitReject
		case "processpartial":
			action = LimitProcessPartial
		default:
			return nil, errs.Detail(ErrParse, "invalid ctl bodyLimitAction %q | 非法的 ctl bodyLimitAction %q", raw, raw)
		}
		return []ctlAction{{kind: ctlBodyLimitAction, limit: int(action)}}, nil
	case "auditengine":
		on := false
		switch strings.ToLower(raw) {
		case "on", "relevantonly":
			on = true
		case "off":
			on = false
		default:
			return nil, errs.Detail(ErrParse, "invalid ctl auditEngine %q | 非法的 ctl auditEngine %q", raw, raw)
		}
		return []ctlAction{{kind: ctlAuditEngine, on: on}}, nil
	default:
		return nil, errs.Detail(ErrUnsupported, "unsupported ctl directive %q | 不支持的 ctl 指令 %q", name, name)
	}
}

// parseOnOff parses On/Off values. | parseOnOff 解析 On/Off 取值。
func parseOnOff(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "on", "1", "true":
		return true, nil
	case "off", "0", "false":
		return false, nil
	default:
		return false, errs.Detail(ErrParse, "invalid On/Off value %q | 非法的 On/Off 取值 %q", value, value)
	}
}

// parseIDList parses comma or space separated rule ids and inclusive ranges. | parseIDList 解析
// 逗号或空格分隔的规则 id 与闭区间范围。
func parseIDList(value string) ([]int, error) {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	})
	out := make([]int, 0, len(fields))
	for _, field := range fields {
		if lowText, highText, ok := strings.Cut(field, "-"); ok {
			low, err := strconv.Atoi(lowText)
			if err != nil {
				return nil, errs.Detail(ErrParse, "invalid rule id range %q | 非法的规则 id 范围 %q", field, field)
			}
			high, err := strconv.Atoi(highText)
			if err != nil || high < low || high-low > 100000 {
				return nil, errs.Detail(ErrParse, "invalid rule id range %q | 非法的规则 id 范围 %q", field, field)
			}
			for id := low; id <= high; id++ {
				out = append(out, id)
			}
			continue
		}
		id, err := strconv.Atoi(field)
		if err != nil || id < 0 {
			return nil, errs.Detail(ErrParse, "invalid rule id %q | 非法的规则 id %q", field, field)
		}
		out = append(out, id)
	}
	if len(out) == 0 {
		return nil, errs.Detail(ErrParse, "empty rule id list | 空的规则 id 列表")
	}
	return out, nil
}
