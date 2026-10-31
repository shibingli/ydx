package waf

import (
	"strconv"
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
)

// ruleConfig is the inspection configuration accumulated from SecLang directives. | ruleConfig
// 是从 SecLang 指令累积的检测配置。
type ruleConfig struct {
	responseMime            []string
	requestBodyLimit        int
	responseBodyLimit       int
	argumentsLimit          int
	collectionTimeout       time.Duration
	engineMode              Mode
	requestBodyAccess       bool
	responseBodyAccess      bool
	requestBodyLimitAction  LimitAction
	responseBodyLimitAction LimitAction
	argumentSeparator       byte
	auditEngine             bool
}

// ruleSpec is a rule before compilation. | ruleSpec 是编译前的规则。
type ruleSpec struct {
	varsRaw    string
	opRaw      string
	actionsRaw string
	file       string
	raw        string
	msg        string

	tags []string

	chain []*ruleSpec

	extraTargets  []string
	extraRemovals []string
	extraActions  []string
	line          int

	id         int
	actionOnly bool

	phase   Phase
	chained bool

	removed bool
}

// specEntry keeps rules and markers in source order. | specEntry 按源码顺序保存规则与标记。
type specEntry struct {
	spec       *ruleSpec
	marker     string
	file       string
	line       int
	declaredAt int
	phase      Phase
}

// updateOp is a deferred SecRuleUpdate* or SecRuleRemove* operation. | updateOp 是延迟执行的
// SecRuleUpdate* 或 SecRuleRemove* 操作。
type updateOp struct {
	file string
	args []string
	line int
	kind directiveKind
}

// compileRuleSet turns parsed directives into an immutable rule snapshot. | compileRuleSet 把已
// 解析指令转换为不可变规则快照。
func compileRuleSet(directives []parsedDirective, opts Options, cc compileContext) (*ruleSet, []string, error) {
	cfg, err := defaultRuleConfig(opts)
	if err != nil {
		return nil, nil, err
	}
	var warnings []string
	userWarn := cc.warn
	warn := func(message string) {
		warnings = append(warnings, message)
		if userWarn != nil {
			userWarn(message)
		}
	}
	cc.warn = warn

	defaultActions := []actionSpec{{name: "pass"}}
	defaultPhase := PhaseNone
	lastPhase := PhaseRequestBody
	var entries []specEntry
	var pendingChain *ruleSpec
	var updates []updateOp
	sequence := 0

	for _, directive := range directives {
		if pendingChain != nil && directive.Kind != dirRule {
			return nil, warnings, errs.Detail(ErrParse, "%s:%d: chained rule expected before %s | %s:%d：%s 之前需要链式规则", directive.File, directive.Line, directive.Name, directive.File, directive.Line, directive.Name)
		}
		switch directive.Kind {
		case dirRule:
			spec := &ruleSpec{
				varsRaw:    directive.Args[0],
				opRaw:      directive.Args[1],
				actionsRaw: actionArg(directive.Args, 2),
				file:       directive.File,
				line:       directive.Line,
				raw:        directive.Raw,
			}
			scanSpecMeta(spec, directive)
			lastPhase = specPhase(spec, defaultPhase)
			if pendingChain != nil {
				pendingChain.chain = append(pendingChain.chain, spec)
			} else {
				sequence++
				entries = append(entries, specEntry{spec: spec, file: spec.file, line: spec.line, declaredAt: sequence})
			}
			if spec.chained {
				pendingChain = spec
			} else {
				pendingChain = nil
			}
		case dirAction:
			spec := &ruleSpec{
				opRaw:      "@unconditionalMatch",
				actionsRaw: directive.Args[0],
				file:       directive.File,
				line:       directive.Line,
				raw:        directive.Raw,
				actionOnly: true,
			}
			scanSpecMeta(spec, directive)
			lastPhase = specPhase(spec, defaultPhase)
			sequence++
			entries = append(entries, specEntry{spec: spec, file: spec.file, line: spec.line, declaredAt: sequence})
		case dirMarker:
			sequence++
			entries = append(entries, specEntry{
				marker:     directive.Args[0],
				phase:      lastPhase,
				file:       directive.File,
				line:       directive.Line,
				declaredAt: sequence,
			})
		case dirDefaultAction:
			defaultActions = parseActionSpecs(directive.Args[0])
			for _, action := range defaultActions {
				if action.name == "phase" {
					if phase, err := parsePhase(action.value); err == nil {
						defaultPhase = phase
						lastPhase = phase
					}
				}
			}
		case dirUpdateActionByID, dirUpdateTargetByID, dirUpdateTargetByTag,
			dirUpdateTargetByMsg, dirRemoveByID, dirRemoveByTag, dirRemoveByMsg,
			dirRemoveTargetByID:
			updates = append(updates, updateOp{kind: directive.Kind, args: directive.Args, file: directive.File, line: directive.Line})
		case dirConfig:
			if err := applyConfigDirective(directive, &cfg, cc); err != nil {
				return nil, warnings, err
			}
		}
	}
	if pendingChain != nil {
		return nil, warnings, errs.Detail(ErrParse, "unterminated rule chain at %s:%d | %s:%d 规则链未闭合", pendingChain.file, pendingChain.line, pendingChain.file, pendingChain.line)
	}
	applyUpdates(entries, updates, warn)
	if opts.Mode != ModeDefault {
		cfg.engineMode = opts.Mode
	}
	if cfg.engineMode == ModeDefault {
		cfg.engineMode = ModeBlock
	}
	return buildRuleSet(entries, defaultActions, defaultPhase, cfg, cc, warnings)
}

// specPhase returns the effective phase of a rule spec. SecRule defaults to phase 2 and SecAction
// to phase 1, matching ModSecurity, unless SecDefaultAction set a phase.
// | specPhase 返回规则规格的有效阶段。未被 SecDefaultAction 设置时，SecRule 默认 phase 2，
// SecAction 默认 phase 1，与 ModSecurity 一致。
func specPhase(spec *ruleSpec, defaultPhase Phase) Phase {
	if spec.phase != PhaseNone {
		return spec.phase
	}
	if defaultPhase != PhaseNone {
		return defaultPhase
	}
	if spec.actionOnly {
		return PhaseRequestHeaders
	}
	return PhaseRequestBody
}

// actionArg returns the actions argument or an empty string. | actionArg 返回动作参数或空串。
func actionArg(args []string, index int) string {
	if index >= len(args) {
		return ""
	}
	return args[index]
}

// scanSpecMeta reads id, phase, tags, message and chain flags from a rule's own actions.
// | scanSpecMeta 从规则自身动作读取 id、phase、标签、消息与 chain 标记。
func scanSpecMeta(spec *ruleSpec, directive parsedDirective) {
	for _, action := range parseActionSpecs(spec.actionsRaw) {
		switch action.name {
		case "id":
			if id, err := strconv.Atoi(action.value); err == nil {
				spec.id = id
			}
		case "phase":
			if phase, err := parsePhase(action.value); err == nil {
				spec.phase = phase
			}
		case "chain":
			spec.chained = true
		case "tag":
			spec.tags = append(spec.tags, action.value)
		case "msg":
			spec.msg = action.value
		}
	}
	if spec.id == 0 && directive.Kind == dirRule {
		spec.id = -1
	}
}

// applyUpdates applies deferred update and removal directives in source order. | applyUpdates
// 按源码顺序应用延迟的更新与移除指令。
func applyUpdates(entries []specEntry, updates []updateOp, warn func(string)) {
	for _, update := range updates {
		switch update.kind {
		case dirUpdateTargetByID:
			ids, err := parseIDList(update.args[0])
			if err != nil {
				warn(update.file + ":" + strconv.Itoa(update.line) + ": " + err.Error())
				continue
			}
			targets := strings.Join(update.args[1:], "|")
			forEachSpec(entries, func(spec *ruleSpec) {
				if containsID(ids, spec.id) {
					spec.varsRaw = appendTargetList(spec.varsRaw, targets)
				}
			})
		case dirUpdateTargetByTag, dirUpdateTargetByMsg:
			key := update.args[0]
			targets := strings.Join(update.args[1:], "|")
			forEachSpec(entries, func(spec *ruleSpec) {
				if (update.kind == dirUpdateTargetByTag && containsFoldString(spec.tags, key)) ||
					(update.kind == dirUpdateTargetByMsg && strings.Contains(spec.msg, key)) {
					spec.varsRaw = appendTargetList(spec.varsRaw, targets)
				}
			})
		case dirUpdateActionByID:
			ids, err := parseIDList(update.args[0])
			if err != nil {
				warn(update.file + ":" + strconv.Itoa(update.line) + ": " + err.Error())
				continue
			}
			actions := strings.Join(update.args[1:], ",")
			forEachSpec(entries, func(spec *ruleSpec) {
				if containsID(ids, spec.id) {
					spec.extraActions = append(spec.extraActions, actions)
				}
			})
		case dirRemoveTargetByID:
			ids, err := parseIDList(update.args[0])
			if err != nil {
				warn(update.file + ":" + strconv.Itoa(update.line) + ": " + err.Error())
				continue
			}
			targets := update.args[1:]
			forEachSpec(entries, func(spec *ruleSpec) {
				if containsID(ids, spec.id) {
					spec.extraRemovals = append(spec.extraRemovals, targets...)
				}
			})
		case dirRemoveByID:
			for _, arg := range update.args {
				ids, err := parseIDList(arg)
				if err != nil {
					warn(update.file + ":" + strconv.Itoa(update.line) + ": " + err.Error())
					continue
				}
				forEachSpec(entries, func(spec *ruleSpec) {
					if containsID(ids, spec.id) {
						spec.removed = true
					}
				})
			}
		case dirRemoveByTag:
			for _, tag := range update.args {
				forEachSpec(entries, func(spec *ruleSpec) {
					if containsFoldString(spec.tags, tag) {
						spec.removed = true
					}
				})
			}
		case dirRemoveByMsg:
			for _, message := range update.args {
				forEachSpec(entries, func(spec *ruleSpec) {
					if strings.Contains(spec.msg, message) {
						spec.removed = true
					}
				})
			}
		}
	}
}

// forEachSpec visits every rule spec, including chain members. | forEachSpec 访问每条规则，包括
// 链成员。
func forEachSpec(entries []specEntry, visit func(*ruleSpec)) {
	var walk func(*ruleSpec)
	walk = func(spec *ruleSpec) {
		if spec == nil {
			return
		}
		visit(spec)
		for _, child := range spec.chain {
			walk(child)
		}
	}
	for _, entry := range entries {
		walk(entry.spec)
	}
}

// appendTargetList adds targets to an existing SecLang target list. SecRuleUpdateTarget*
// directives add or exclude targets; they do not replace the original list.
// | appendTargetList 向已有 SecLang 目标列表追加目标。SecRuleUpdateTarget* 指令用于添加或排除
// 目标，不会替换原始列表。
func appendTargetList(existing, added string) string {
	added = strings.TrimSpace(added)
	if added == "" {
		return existing
	}
	if strings.TrimSpace(existing) == "" {
		return added
	}
	return existing + "|" + added
}

// containsID reports whether ids contains id. | containsID 报告 ids 是否包含 id。
func containsID(ids []int, id int) bool {
	for _, candidate := range ids {
		if candidate == id {
			return true
		}
	}
	return false
}

// containsFoldString reports whether values contains target, ignoring case. | containsFoldString
// 报告 values 是否包含 target，忽略大小写。
func containsFoldString(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(value, target) {
			return true
		}
	}
	return false
}

// defaultRuleConfig builds the configuration baseline from Options. | defaultRuleConfig 从 Options
// 构建配置基线。
func defaultRuleConfig(opts Options) (ruleConfig, error) {
	cfg := ruleConfig{
		engineMode:              opts.Mode,
		requestBodyAccess:       !opts.DisableRequestBodyAccess,
		responseBodyAccess:      opts.ResponseBodyAccess,
		requestBodyLimit:        opts.RequestBodyLimit,
		responseBodyLimit:       opts.ResponseBodyLimit,
		requestBodyLimitAction:  opts.RequestBodyLimitAction,
		responseBodyLimitAction: opts.ResponseBodyLimitAction,
		responseMime:            append([]string(nil), opts.ResponseBodyMimeTypes...),
		argumentsLimit:          opts.ArgumentsLimit,
		argumentSeparator:       '&',
		collectionTimeout:       60 * time.Second,
	}
	return cfg, nil
}

// applyConfigDirective applies one SecLang configuration directive. | applyConfigDirective 应用
// 一条 SecLang 配置指令。
func applyConfigDirective(directive parsedDirective, cfg *ruleConfig, cc compileContext) error {
	args := directive.Args
	first := ""
	if len(args) > 0 {
		first = strings.TrimSpace(args[0])
	}
	parseInt := func() (int, error) {
		value, err := strconv.Atoi(first)
		if err != nil || value < 0 {
			return 0, errs.Detail(ErrParse, "%s:%d: invalid value %q | %s:%d：非法的取值 %q",
				directive.File, directive.Line, first, directive.File, directive.Line, first)
		}
		return value, nil
	}
	switch directive.Name {
	case "SecRuleEngine":
		switch strings.ToLower(first) {
		case "on":
			cfg.engineMode = ModeBlock
		case "detectiononly":
			cfg.engineMode = ModeDetection
		case "off":
			cfg.engineMode = ModeOff
		default:
			return errs.Detail(ErrParse, "%s:%d: invalid SecRuleEngine %q | %s:%d：非法的 SecRuleEngine %q",
				directive.File, directive.Line, first, directive.File, directive.Line, first)
		}
	case "SecRequestBodyAccess":
		on, err := parseOnOff(first)
		if err != nil {
			return err
		}
		cfg.requestBodyAccess = on
	case "SecResponseBodyAccess":
		on, err := parseOnOff(first)
		if err != nil {
			return err
		}
		cfg.responseBodyAccess = on
	case "SecRequestBodyLimit":
		value, err := parseInt()
		if err != nil {
			return err
		}
		if value > maxBodyLimit {
			return ErrInvalidLimit
		}
		cfg.requestBodyLimit = value
	case "SecResponseBodyLimit":
		value, err := parseInt()
		if err != nil {
			return err
		}
		if value > maxBodyLimit {
			return ErrInvalidLimit
		}
		cfg.responseBodyLimit = value
	case "SecRequestBodyLimitAction":
		action, err := parseLimitAction(first)
		if err != nil {
			return err
		}
		cfg.requestBodyLimitAction = action
	case "SecResponseBodyLimitAction":
		action, err := parseLimitAction(first)
		if err != nil {
			return err
		}
		cfg.responseBodyLimitAction = action
	case "SecResponseBodyMimeType":
		for _, mime := range args {
			mime = strings.TrimSpace(mime)
			if mime == "" {
				continue
			}
			cfg.responseMime = appendUniqueFoldString(cfg.responseMime, mime)
		}
	case "SecArgumentsLimit":
		value, err := parseInt()
		if err != nil {
			return err
		}
		if value > maxArgumentsLimit {
			return ErrInvalidLimit
		}
		if value > 0 {
			cfg.argumentsLimit = value
		}
	case "SecArgumentSeparator":
		if first != "" {
			cfg.argumentSeparator = first[0]
		}
	case "SecCollectionTimeout":
		value, err := parseInt()
		if err != nil {
			return err
		}
		cfg.collectionTimeout = time.Duration(value) * time.Second
	case "SecAuditEngine":
		switch strings.ToLower(first) {
		case "on", "relevantonly":
			cfg.auditEngine = true
		case "off":
			cfg.auditEngine = false
		default:
			return errs.Detail(ErrParse, "%s:%d: invalid SecAuditEngine %q | %s:%d：非法的 SecAuditEngine %q",
				directive.File, directive.Line, first, directive.File, directive.Line, first)
		}
	}
	return nil
}

// parseLimitAction parses Reject or ProcessPartial. | parseLimitAction 解析 Reject 或 ProcessPartial。
func parseLimitAction(value string) (LimitAction, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "reject":
		return LimitReject, nil
	case "processpartial":
		return LimitProcessPartial, nil
	default:
		return LimitDefault, errs.Detail(ErrParse, "invalid limit action %q | 非法的超限动作 %q", value, value)
	}
}

// appendUniqueFoldString appends value when it is not already present, ignoring case.
// | appendUniqueFoldString 在值不存在时追加，忽略大小写。
func appendUniqueFoldString(values []string, value string) []string {
	for _, existing := range values {
		if strings.EqualFold(existing, value) {
			return values
		}
	}
	return append(values, value)
}
