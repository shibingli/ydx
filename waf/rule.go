package waf

import (
	"time"
)

// Rule is the exported metadata of one compiled SecLang rule. | Rule 是一条已编译 SecLang 规则的
// 导出元数据。
type Rule struct {
	Rev      string
	Ver      string
	Msg      string
	LogData  string
	Severity string
	File     string
	Raw      string
	Tags     []string
	Chain    []*Rule
	ID       int
	Maturity int
	Accuracy int
	Line     int
	Phase    Phase
}

// setVarAction is one compiled setvar. | setVarAction 是一个编译后的 setvar。
type setVarAction struct {
	name  string
	value macro
	op    byte
	ttl   time.Duration
}

// expireVarAction is one compiled expirevar. | expireVarAction 是一个编译后的 expirevar。
type expireVarAction struct {
	name string
	ttl  macro
}

// ctlKind enumerates supported ctl directives. | ctlKind 枚举受支持的 ctl 指令。
type ctlKind uint8

// Supported ctl directives. | 受支持的 ctl 指令。
const (
	ctlRuleRemoveByID ctlKind = iota
	ctlRuleRemoveTargetByID
	ctlRuleRemoveByTag
	ctlRuleRemoveTargetByTag
	ctlRuleEngine
	ctlRequestBodyProcessor
	ctlForceRequestBodyVariable
	ctlRequestBodyAccess
	ctlResponseBodyAccess
	ctlRequestBodyLimit
	ctlBodyLimitAction
	ctlAuditEngine
)

// ctlAction is one compiled ctl directive. | ctlAction 是一个编译后的 ctl 指令。
type ctlAction struct {
	value  string
	ids    []int
	target varSelector
	id     int
	limit  int
	kind   ctlKind
	on     bool
}

// compiledRule is the executable form of one rule. | compiledRule 是一条规则的可执行形式。
type compiledRule struct {
	meta *Rule
	op   *operator

	msgMacro      macro
	logDataMacro  macro
	redirectMacro macro

	skipAfter string

	redirect           string
	transformKey       string
	vars               []varSelector
	transforms         []transformFunc
	chain              []*compiledRule
	transformCacheable bool

	setvars  []setVarAction
	expires  []expireVarAction
	ctls     []ctlAction
	blocking blockingAction

	parallelSafe    bool
	evalIndependent bool
	usesMatchState  bool
	usesCurrentRule bool

	skip   int
	status int

	phase Phase

	capture    bool
	multiMatch bool
	log        bool
	audit      bool
	allow      bool
	pass       bool

	deny  bool
	drop  bool
	block bool

	// actionOnly marks SecAction and other operator-less rules. | actionOnly 标记 SecAction 等
	// 无算子的规则。
	actionOnly bool
}

// ruleSet is an immutable compiled rule snapshot. | ruleSet 是不可变的编译规则快照。
type ruleSet struct {
	markers [6]map[string]int
	byID    map[int]*compiledRule
	byTag   map[string][]int

	phases            [6][]phaseEntry
	rules             []*Rule
	responseMime      []string
	requestBodyLimit  int
	responseBodyLimit int
	argumentsLimit    int
	collectionTimeout time.Duration

	engineMode Mode

	needsBody            bool
	needsResponseHeaders bool
	needsResponseBody    bool

	requestBodyAccess       bool
	responseBodyAccess      bool
	requestBodyLimitAction  LimitAction
	responseBodyLimitAction LimitAction
	argumentSeparator       byte
	auditEngine             bool
}

// phaseEntry is one rule or marker in a phase stream. | phaseEntry 是阶段流中的一条规则或标记。
type phaseEntry struct {
	rule   *compiledRule
	marker string
}

// ruleNeedsBody reports whether the rule can observe the request body. | ruleNeedsBody 报告规则
// 是否能观察请求正文。
func ruleNeedsBody(rule *compiledRule) bool {
	for _, selector := range rule.vars {
		switch selector.Name {
		case "ARGS", "ARGS_NAMES", "ARGS_POST", "ARGS_POST_NAMES", "ARGS_COMBINED_SIZE",
			"REQUEST_BODY", "REQUEST_BODY_LENGTH", "FILES", "FILES_NAMES", "FILES_SIZES",
			"FILES_COMBINED_SIZE", "MULTIPART_PART_HEADERS", "MULTIPART_PART_HEADERS_NAMES",
			"MULTIPART_STRICT_ERROR", "MULTIPART_UNMATCHED_BOUNDARY", "URLENCODED_ERROR",
			"JSON", "XML", "REQBODY_ERROR", "REQBODY_ERROR_MSG", "REQBODY_PROCESSOR",
			"FULL_REQUEST", "FULL_REQUEST_LENGTH":
			return true
		}
	}
	for _, member := range rule.chain {
		if ruleNeedsBody(member) {
			return true
		}
	}
	return false
}

// ruleNeedsResponseHeaders reports whether the rule can observe response headers. | ruleNeedsResponseHeaders
// 报告规则是否能观察响应头。
func ruleNeedsResponseHeaders(rule *compiledRule) bool {
	if rule.phase >= PhaseResponseHeaders {
		return true
	}
	for _, member := range rule.chain {
		if ruleNeedsResponseHeaders(member) {
			return true
		}
	}
	return false
}

// ruleNeedsResponseBody reports whether the rule can observe the response body. | ruleNeedsResponseBody
// 报告规则是否能观察响应正文。
func ruleNeedsResponseBody(rule *compiledRule) bool {
	for _, selector := range rule.vars {
		switch selector.Name {
		case "RESPONSE_BODY", "RESPONSE_BODY_LENGTH":
			return true
		}
	}
	for _, member := range rule.chain {
		if ruleNeedsResponseBody(member) {
			return true
		}
	}
	return false
}

// mode resolves the effective engine mode. | mode 解析有效的引擎模式。
func (rs *ruleSet) mode(override Mode) Mode {
	if override != ModeDefault {
		return override
	}
	return rs.engineMode
}

// hasPhaseRules reports whether a phase contains at least one executable rule.
// | hasPhaseRules 报告某个阶段是否至少包含一条可执行规则。
func (rs *ruleSet) hasPhaseRules(phase Phase) bool {
	if int(phase) >= len(rs.phases) {
		return false
	}
	for _, entry := range rs.phases[phase] {
		if entry.rule != nil {
			return true
		}
	}
	return false
}

// hasMarker reports whether a marker name exists in any phase. skipAfter uses this to stop the
// current phase when the marker lives in a later phase, which is how CRS guards work.
// | hasMarker 报告某个标记名是否存在于任一阶段。skipAfter 用它在本阶段内找不到标记时结束当前
// 阶段，这正是 CRS 守卫规则的用法。
func (rs *ruleSet) hasMarker(name string) bool {
	for phase := range rs.markers {
		if _, ok := rs.markers[phase][name]; ok {
			return true
		}
	}
	return false
}

// markerIndex returns the index of a marker in one phase, or -1. | markerIndex 返回标记在某个
// 阶段中的下标，不存在时返回 -1。
func (rs *ruleSet) markerIndex(phase Phase, name string) int {
	if int(phase) >= len(rs.markers) {
		return -1
	}
	index, ok := rs.markers[phase][name]
	if !ok {
		return -1
	}
	return index
}
