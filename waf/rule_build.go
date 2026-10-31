package waf

import (
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/shibingli/ydx/errs"
)

// buildRuleSet compiles every spec entry into phase buckets. | buildRuleSet 把每个规格条目编译到
// 阶段桶中。
func buildRuleSet(entries []specEntry, defaults []actionSpec, defaultPhase Phase, cfg ruleConfig, cc compileContext, warnings []string) (*ruleSet, []string, error) {
	rs := &ruleSet{
		engineMode:              cfg.engineMode,
		requestBodyAccess:       cfg.requestBodyAccess,
		responseBodyAccess:      cfg.responseBodyAccess,
		requestBodyLimit:        cfg.requestBodyLimit,
		responseBodyLimit:       cfg.responseBodyLimit,
		requestBodyLimitAction:  cfg.requestBodyLimitAction,
		responseBodyLimitAction: cfg.responseBodyLimitAction,
		responseMime:            cfg.responseMime,
		argumentsLimit:          cfg.argumentsLimit,
		argumentSeparator:       cfg.argumentSeparator,
		collectionTimeout:       cfg.collectionTimeout,
		auditEngine:             cfg.auditEngine,
		byID:                    make(map[int]*compiledRule, len(entries)),
		byTag:                   make(map[string][]int, 16),
	}
	for i := range rs.markers {
		rs.markers[i] = make(map[string]int, 4)
	}
	warn := func(message string) {
		warnings = append(warnings, message)
		if cc.warn != nil {
			cc.warn(message)
		}
	}
	for _, entry := range entries {
		if entry.marker != "" {
			phase := entry.phase
			if phase < PhaseRequestHeaders || phase > PhaseLogging {
				phase = PhaseRequestBody
			}
			rs.phases[phase] = append(rs.phases[phase], phaseEntry{marker: entry.marker})
			continue
		}
		spec := entry.spec
		if spec == nil || spec.removed {
			continue
		}
		rule, err := compileRuleSpec(spec, defaults, defaultPhase, cc, false)
		if err != nil {
			if !cc.strict {
				warn(entry.file + ":" + strconv.Itoa(entry.line) + ": rule skipped: " + err.Error() +
					" | 规则已跳过")
				continue
			}
			return nil, warnings, err
		}
		if rule == nil {
			continue
		}
		phase := rule.phase
		if phase < PhaseRequestHeaders || phase > PhaseLogging {
			phase = PhaseRequestBody
		}
		rule.phase = phase
		rule.meta.Phase = phase
		rs.phases[phase] = append(rs.phases[phase], phaseEntry{rule: rule})
		var register func(*compiledRule) error
		register = func(candidate *compiledRule) error {
			if candidate == nil {
				return nil
			}
			rs.rules = append(rs.rules, candidate.meta)
			if id := candidate.meta.ID; id > 0 {
				if previous, ok := rs.byID[id]; ok {
					message := "duplicate rule id " + strconv.Itoa(id) + " at " + entry.file + ":" +
						strconv.Itoa(entry.line) + " (previous " + previous.meta.File + ":" +
						strconv.Itoa(previous.meta.Line) + ") | 重复的规则 id"
					if cc.strict {
						return errs.Detail(ErrBuild, "%s", message)
					}
					warn(message)
				}
				rs.byID[id] = candidate
			}
			for _, child := range candidate.chain {
				if err := register(child); err != nil {
					return err
				}
			}
			return nil
		}
		if err := register(rule); err != nil {
			return nil, warnings, err
		}
	}
	for phase := PhaseRequestHeaders; phase <= PhaseLogging; phase++ {
		for index, entry := range rs.phases[phase] {
			if entry.marker == "" {
				continue
			}
			if _, exists := rs.markers[phase][entry.marker]; exists {
				warn("duplicate marker " + entry.marker + " in phase " + phase.String() + " | 重复的标记")
			}
			rs.markers[phase][entry.marker] = index
		}
	}
	for id, rule := range rs.byID {
		for _, tag := range rule.meta.Tags {
			rs.byTag[tag] = append(rs.byTag[tag], id)
		}
	}
	prepareTransformCaching(rs)
	rs.computeNeeds()
	if len(rs.rules) == 0 {
		return nil, warnings, ErrNoRules
	}
	return rs, warnings, nil
}

// prepareTransformCaching assigns compact chain IDs used by the per-transaction transform cache.
// The cache is valuable even for a chain used by one rule because a rule may see repeated values
// across a collection. | prepareTransformCaching 为事务级变换缓存分配紧凑链 ID。即使一条变换链仅被
// 一条规则使用，规则在集合中也可能遇到重复取值，因此缓存仍有价值。
func prepareTransformCaching(rs *ruleSet) {
	ids := make(map[string]uint32, 32)
	seen := make(map[*compiledRule]bool, len(rs.rules))
	var assign func(*compiledRule)
	assign = func(rule *compiledRule) {
		if rule == nil || seen[rule] {
			return
		}
		seen[rule] = true
		if rule.transformCacheable && rule.transformKey != "" {
			id, ok := ids[rule.transformKey]
			if !ok {
				id = uint32(len(ids) + 1)
				ids[rule.transformKey] = id
			}
			rule.transformChainID = id
		}
		for _, child := range rule.chain {
			assign(child)
		}
	}
	for phase := PhaseRequestHeaders; phase <= PhaseLogging; phase++ {
		for _, entry := range rs.phases[phase] {
			assign(entry.rule)
		}
	}
}

// ruleBaseDir returns the directory used to resolve operator data files next to a rule file.
// | ruleBaseDir 返回用于解析规则文件旁算子数据文件的目录。
func ruleBaseDir(cc compileContext, file string) string {
	if file == "" || strings.HasPrefix(file, "<") {
		return ""
	}
	if cc.fsys != nil {
		return path.Dir(file)
	}
	return filepath.Dir(file)
}

// computeNeeds derives body and response inspection flags from the compiled rules.
// | computeNeeds 从已编译规则推导正文与响应检测标志。
func (rs *ruleSet) computeNeeds() {
	for phase := PhaseRequestBody; phase <= PhaseLogging; phase++ {
		for _, entry := range rs.phases[phase] {
			if entry.rule == nil {
				continue
			}
			if ruleNeedsBody(entry.rule) {
				rs.needsBody = true
			}
			if ruleNeedsResponseBody(entry.rule) {
				rs.needsResponseBody = true
			}
		}
	}
	for phase := PhaseResponseHeaders; phase <= PhaseResponseBody; phase++ {
		if rs.hasPhaseRules(phase) {
			rs.needsResponseHeaders = true
			break
		}
	}
	if rs.auditEngine {
		rs.needsBody = true
		rs.needsResponseHeaders = true
		if rs.responseBodyAccess {
			rs.needsResponseBody = true
		}
	}
}

// compileRuleSpec compiles one rule spec and its chain. | compileRuleSpec 编译一条规则及其链。
func compileRuleSpec(spec *ruleSpec, defaults []actionSpec, defaultPhase Phase, cc compileContext, chainMember bool) (*compiledRule, error) {
	meta := &Rule{
		ID:   spec.id,
		File: spec.file,
		Line: spec.line,
		Raw:  spec.raw,
	}
	rule := &compiledRule{meta: meta, log: true, audit: true}
	if meta.ID < 0 {
		meta.ID = 0
	}
	if !spec.actionOnly {
		varsRaw := spec.varsRaw
		for _, removal := range spec.extraRemovals {
			removal = strings.TrimSpace(removal)
			if removal == "" {
				continue
			}
			if !strings.HasPrefix(removal, "!") {
				removal = "!" + removal
			}
			if varsRaw == "" {
				varsRaw = removal
			} else {
				varsRaw += "|" + removal
			}
		}
		selectors, err := parseVarSelectors(varsRaw)
		if err != nil {
			return nil, err
		}
		rule.vars = selectors
		negated, name, arg := splitOperator(spec.opRaw)
		operatorContext := cc
		if base := ruleBaseDir(cc, spec.file); base != "" && base != "." {
			operatorContext.baseDir = base
		}
		op, err := compileOperator(negated, name, arg, operatorContext)
		if err != nil {
			return nil, err
		}
		rule.op = op
	} else {
		rule.actionOnly = true
	}
	if !chainMember {
		rule.blocking = resolveBlocking(defaults)
	}
	actions := make([]actionSpec, 0, len(defaults)+8)
	if chainMember {
		// A chain member inherits the base rule's phase and cannot add disruptive actions.
		// | 链成员继承基础规则的阶段，且不能添加破坏性动作。
	} else if len(defaults) > 0 {
		actions = append(actions, defaults...)
	}
	actions = append(actions, parseActionSpecs(spec.actionsRaw)...)
	for _, extra := range spec.extraActions {
		actions = append(actions, parseActionSpecs(extra)...)
	}
	if err := compileActions(actions, rule, cc); err != nil {
		return nil, err
	}
	if chainMember {
		rule.phase = defaultPhase
		rule.deny = false
		rule.drop = false
		rule.block = false
		rule.redirect = ""
		rule.allow = false
		rule.skip = 0
		rule.skipAfter = ""
		rule.log = false
		rule.audit = false
	} else if rule.phase == PhaseNone {
		switch {
		case defaultPhase != PhaseNone:
			rule.phase = defaultPhase
		case spec.actionOnly:
			rule.phase = PhaseRequestHeaders
		default:
			rule.phase = PhaseRequestBody
		}
	}
	if rule.phase == PhaseNone {
		rule.phase = PhaseRequestBody
	}
	meta.Phase = rule.phase
	for _, childSpec := range spec.chain {
		if childSpec == nil {
			continue
		}
		if childSpec.removed {
			// Removing any chain member removes the whole chain; continuing with a shorter chain
			// would silently weaken the rule. | 移除任一链成员会移除整条链；缩短链会悄悄削弱规则。
			return nil, nil
		}
		child, err := compileRuleSpec(childSpec, nil, rule.phase, cc, true)
		if err != nil {
			// A chain is meaningful only as a whole. A skipped member must not leave a weaker
			// prefix chain active. | 链只有完整才有意义；跳过成员不能让较弱的前缀链继续生效。
			return nil, err
		}
		if child == nil {
			return nil, nil
		}
		child.phase = rule.phase
		child.meta.Phase = rule.phase
		rule.chain = append(rule.chain, child)
		meta.Chain = append(meta.Chain, child.meta)
	}
	rule.usesMatchState = ruleUsesMatchState(rule)
	rule.usesCurrentRule = ruleUsesCurrentRule(rule)
	rule.parallelSafe = computeParallelSafe(rule, chainMember)
	rule.evalIndependent = computeEvalIndependent(rule, chainMember)
	return rule, nil
}

// mutableStateVariables are variables written by earlier rule commits but not by request
// collections. Rules reading them must stay in source order. | mutableStateVariables 是较早规则提交
// 写入、但不由请求集合提供的变量；读取它们的规则必须保持源码顺序。
var mutableStateVariables = map[string]struct{}{
	"TX": {}, "IP": {}, "SESSION": {}, "USER": {},
}

// ruleReadsMutableState reports whether evaluation reads TX-backed state. | ruleReadsMutableState
// 报告求值是否读取 TX 支撑的状态。
func ruleReadsMutableState(rule *compiledRule) bool {
	for _, selector := range rule.vars {
		if _, ok := mutableStateVariables[selector.Name]; ok {
			return true
		}
	}
	return rule.op != nil && rule.op.argMacro != nil && rule.op.argMacro.usesAny(mutableStateVariables)
}

// computeEvalIndependent marks rules whose match result can be computed before earlier rules in
// the same run commit. Unlike parallelSafe, these rules may have setvar, expirevar, capture or
// multiMatch actions: evaluation is pure, and commit still happens in source order. Rules with
// control-flow or state-reading behavior remain barriers. | computeEvalIndependent 标记可以在一段
// 规则提交前完成求值的规则。与 parallelSafe 不同，这些规则可以带 setvar、expirevar、capture 或
// multiMatch 动作：求值是纯的，提交仍按源码顺序进行。带控制流的规则仍是屏障；读取 TX 的规则由
// 收集器按写入依赖切段。 | Rules whose match result can be computed before earlier rules in the
// same run commit. Unlike parallelSafe, these rules may have setvar, expirevar, capture or
// multiMatch actions: evaluation is pure and commit still happens in source order. Control-flow
// rules remain barriers; TX readers are segmented by the collector according to write dependencies.
func computeEvalIndependent(rule *compiledRule, chainMember bool) bool {
	if chainMember || rule.actionOnly || len(rule.chain) > 0 || len(rule.ctls) > 0 ||
		rule.allow || rule.skip > 0 || rule.skipAfter != "" || rule.op == nil {
		return false
	}
	return !rule.usesMatchState && !rule.usesCurrentRule && !ruleReadsMutableState(rule)
}

// matchStateVariables are variables whose value changes as earlier rules commit.
// | matchStateVariables 是随较早规则提交而变化的变量。
var matchStateVariables = map[string]struct{}{
	"MATCHED_VAR": {}, "MATCHED_VAR_NAME": {}, "MATCHED_VARS": {},
	"MATCHED_VARS_NAMES": {}, "HIGHEST_SEVERITY": {},
}

// ruleVariableSet marks the RULE collection, which depends on the currently evaluated rule.
// | ruleVariableSet 标记依赖当前求值规则的 RULE 集合。
var ruleVariableSet = map[string]struct{}{"RULE": {}}

// ruleUsesMatchState reports whether evaluation depends on matches committed before it.
// | ruleUsesMatchState 报告求值是否依赖此前已提交的命中。
func ruleUsesMatchState(rule *compiledRule) bool {
	for _, selector := range rule.vars {
		if _, ok := matchStateVariables[selector.Name]; ok {
			return true
		}
	}
	return rule.op != nil && rule.op.argMacro != nil && rule.op.argMacro.usesAny(matchStateVariables)
}

// ruleUsesCurrentRule reports whether evaluation depends on the current rule context.
// | ruleUsesCurrentRule 报告求值是否依赖当前规则上下文。
func ruleUsesCurrentRule(rule *compiledRule) bool {
	for _, selector := range rule.vars {
		if selector.Name == "RULE" {
			return true
		}
	}
	return rule.op != nil && rule.op.argMacro != nil && rule.op.argMacro.usesAny(ruleVariableSet)
}

// computeParallelSafe marks rules that can be evaluated concurrently and committed later in
// order. Side-effecting rules are barriers. | computeParallelSafe 标记可并发求值、稍后按顺序提交的
// 规则；有副作用的规则作为屏障。
func computeParallelSafe(rule *compiledRule, chainMember bool) bool {
	if chainMember || rule.actionOnly || len(rule.chain) > 0 ||
		len(rule.setvars) > 0 || len(rule.expires) > 0 || len(rule.ctls) > 0 ||
		rule.capture || rule.multiMatch || rule.allow ||
		rule.skip > 0 || rule.skipAfter != "" || rule.op == nil {
		return false
	}
	return !rule.usesMatchState && !rule.usesCurrentRule
}
