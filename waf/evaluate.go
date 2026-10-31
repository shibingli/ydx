package waf

import (
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shibingli/ydx/log"
)

// maxMatchValue bounds the value stored in an event match. | maxMatchValue 限制事件命中中保存的取值。
const maxMatchValue = 1024

// ruleMatch pairs a compiled rule with the values that matched it. | ruleMatch 把已编译规则与其
// 命中取值配对。
type ruleMatch struct {
	rule     *compiledRule
	first    varValue
	values   []varValue
	hasFirst bool
}

// ruleEval is the operator result of one rule. A single match stays in first so the common
// non-multiMatch case allocates no slice. | ruleEval 是单条规则的算子结果。单次命中保存在 first 中，
// 使常见的非 multiMatch 情况不分配切片。
type ruleEval struct {
	first    varValue
	values   []varValue
	groups   []string
	matched  bool
	hasFirst bool
}

// chainResult is the outcome of evaluating a rule and its chain. | chainResult 是规则及其链的
// 求值结果。
type chainResult struct {
	base    ruleMatch
	members []ruleMatch
	matched bool
	hasBase bool
}

// initTransaction initializes a borrowed transaction for one request. | initTransaction 为单个
// 请求初始化借出的事务。
func (e *engine) initTransaction(tx *transaction, r *http.Request, clientIP string) {
	tx.id = e.newID()
	tx.rules = e.rules
	tx.req = r
	tx.clientIP = clientIP
	tx.start = time.Now()
	// Fix the TIME snapshot before any parallel rule evaluation; clock() then only reads it.
	// | 在任何并行规则求值之前固定 TIME 快照；此后 clock() 只读取它。
	tx.now = tx.start
	tx.nowInit = true
	tx.engineMode = ModeDefault
	tx.defaultMode = e.rules.engineMode
	tx.argLimit = e.rules.argumentsLimit
	tx.argSep = e.rules.argumentSeparator
	tx.bodyLimit = e.rules.requestBodyLimit
	tx.bodyLimitAction = e.rules.requestBodyLimitAction
	tx.requestBodyAccess = e.rules.requestBodyAccess
	tx.responseBodyAccess = e.rules.responseBodyAccess
	tx.responseBodyLimit = e.rules.responseBodyLimit
	tx.responseBodyLimitAction = e.rules.responseBodyLimitAction
	tx.auditEngine = e.rules.auditEngine
	tx.initRequest()
}

// processRequestHeaders runs phase 1. | processRequestHeaders 运行 phase 1。
func (e *engine) processRequestHeaders(tx *transaction) {
	e.processPhase(tx, PhaseRequestHeaders)
}

// processRequestBody runs phase 2. | processRequestBody 运行 phase 2。
func (e *engine) processRequestBody(tx *transaction) {
	e.processPhase(tx, PhaseRequestBody)
}

// processResponseHeaders runs phase 3. | processResponseHeaders 运行 phase 3。
func (e *engine) processResponseHeaders(tx *transaction) {
	e.processPhase(tx, PhaseResponseHeaders)
}

// processResponseBody runs phase 4. | processResponseBody 运行 phase 4。
func (e *engine) processResponseBody(tx *transaction) {
	e.processPhase(tx, PhaseResponseBody)
}

// processLogging runs phase 5. | processLogging 运行 phase 5。
func (e *engine) processLogging(tx *transaction) {
	e.processPhase(tx, PhaseLogging)
}

// mode resolves the effective mode for a transaction. | mode 解析事务的有效模式。
func (e *engine) mode(tx *transaction) Mode {
	if tx.engineMode != ModeDefault {
		return tx.engineMode
	}
	return e.rules.engineMode
}

// parallelRunThreshold is the minimum number of consecutive independent rules that makes goroutine
// scheduling worth trying. The work threshold below rejects tiny requests where scheduling costs
// more than concurrent evaluation saves. | parallelRunThreshold 是连续独立规则触发并行求值的最小
// 数量；下面的工作量门槛会拒绝调度成本高于并发收益的小请求。
const parallelRunThreshold = 4

// parallelWorkThreshold is the minimum estimated selector-value work for an independent run.
// | parallelWorkThreshold 是独立规则段触发并行求值的最小估算选择器-取值工作量。
const parallelWorkThreshold = 128

// processPhase evaluates one phase stream. Side-effect-free runs are evaluated concurrently and
// committed in source order; rules with setvar, ctl, capture, chain, skip or allow act as barriers.
// | processPhase 求值一个阶段流。无副作用规则段并发求值并按源码顺序提交；带 setvar、ctl、
// capture、chain、skip 或 allow 的规则作为屏障。
func (e *engine) processPhase(tx *transaction, phase Phase) {
	if tx == nil || tx.allow {
		return
	}
	mode := e.mode(tx)
	if mode == ModeOff {
		return
	}
	e.runHook(HookBeforePhase, tx, phase, nil, nil, nil)
	if tx.interruption != nil {
		return
	}
	defer e.runHook(HookAfterPhase, tx, phase, nil, nil, nil)
	entries := e.rules.phases[phase]
	parallel := e.allowParallel()
	hint := requestValueHint(tx)
	for index := 0; index < len(entries); {
		entry := &entries[index]
		if entry.marker != "" || entry.rule == nil {
			index++
			continue
		}
		rule := entry.rule
		if rule.meta.ID > 0 && tx.ruleRemoved(rule.meta.ID) {
			index++
			continue
		}
		if parallel {
			if rule.parallelSafe {
				end, indices, mask := collectParallelRun(entries, index, tx, true)
				work := e.parallelWork(entries, indices, hint)
				if len(indices) >= 8 && work >= 64 {
					tx.prewarm(mask)
					results := e.evalParallelRun(tx, entries, indices)
					if e.commitParallelRun(tx, entries, indices, results, mode) {
						return
					}
					index = end
					continue
				}
			} else if hint >= 8 && rule.evalIndependent {
				end, indices, mask := collectParallelRun(entries, index, tx, false)
				if len(indices) >= parallelRunThreshold &&
					e.parallelWork(entries, indices, hint) >= parallelWorkThreshold {
					tx.prewarm(mask)
					results := e.evalParallelRun(tx, entries, indices)
					if e.commitParallelRun(tx, entries, indices, results, mode) {
						return
					}
					index = end
					continue
				}
			}
		}
		next, stop := e.processRuleSequential(tx, entries, phase, index, mode)
		if stop {
			return
		}
		index = next
	}
}

// processRuleSequential evaluates and commits one rule with full skip/chain semantics.
// | processRuleSequential 以完整 skip/chain 语义求值并提交一条规则。
func (e *engine) processRuleSequential(tx *transaction, entries []phaseEntry, phase Phase, index int, mode Mode) (int, bool) {
	rule := entries[index].rule
	next := index + 1
	result := e.evalChain(tx, rule)
	if !result.matched {
		return next, false
	}
	e.commitChain(tx, result)
	if tx.allow || tx.interruption != nil {
		return 0, true
	}
	mode = e.mode(tx)
	if mode == ModeOff {
		return 0, true
	}
	if rule.skip > 0 {
		next = skipRuleEntries(entries, index, rule.skip) + 1
	}
	if rule.skipAfter != "" {
		if marker := e.rules.markerIndex(phase, rule.skipAfter); marker >= 0 {
			next = marker + 1
		} else if e.rules.hasMarker(rule.skipAfter) {
			// The marker belongs to another phase; skipping to it means the rest of this
			// phase is skipped and the next phase proceeds. | 标记属于其他阶段；跳到它意味着
			// 结束当前阶段的剩余规则并继续下一阶段。
			next = len(entries)
		} else {
			e.logger.Warn("waf skipAfter marker not found | WAF skipAfter 标记未找到",
				log.Int("rule_id", rule.meta.ID), log.Str("marker", rule.skipAfter),
				log.Str("phase", phase.String()))
		}
	}
	if !isDisruptive(rule) {
		return next, false
	}
	if mode == ModeDetection {
		if tx.detected == nil {
			tx.detected = buildInterruption(tx, rule)
		}
		return next, false
	}
	tx.interruption = buildInterruption(tx, rule)
	return 0, true
}

// collectParallelRun gathers a maximal run of parallel-safe rules and the collections they need.
// | collectParallelRun 收集一段最长的并行安全规则及其所需集合。
func collectParallelRun(entries []phaseEntry, start int, tx *transaction, safeOnly bool) (int, []int, uint8) {
	tx.parallelIndices = tx.parallelIndices[:0]
	end := start
	var mask uint8
	for end < len(entries) {
		if entries[end].marker != "" {
			end++
			continue
		}
		rule := entries[end].rule
		if rule == nil {
			break
		}
		if safeOnly {
			if !rule.parallelSafe {
				break
			}
		} else if !rule.evalIndependent {
			break
		}
		tx.parallelIndices = append(tx.parallelIndices, end)
		mask |= ruleCollectionMask(rule)
		end++
	}
	return end, tx.parallelIndices, mask
}

// ruleCollectionMask reports which request collections one rule needs prewarmed.
// | ruleCollectionMask 报告一条规则需要预热哪些请求集合。
func ruleCollectionMask(rule *compiledRule) uint8 {
	var mask uint8
	for _, selector := range rule.vars {
		mask |= selectorCollectionMask(selector.Name)
	}
	if rule.op != nil && rule.op.argMacro != nil {
		for _, part := range rule.op.argMacro.parts {
			if part.isVar {
				mask |= selectorCollectionMask(part.selector.Name)
			}
		}
	}
	return mask
}

// selectorCollectionMask maps one variable name to its collection cache bits. | selectorCollectionMask
// 把一个变量名映射到集合缓存位。
func selectorCollectionMask(name string) uint8 {
	switch name {
	case "ARGS", "ARGS_NAMES", "ARGS_COMBINED_SIZE", "REQUEST_BODY", "REQUEST_BODY_LENGTH",
		"REQBODY_ERROR", "REQBODY_ERROR_MSG", "REQBODY_PROCESSOR", "URLENCODED_ERROR",
		"MULTIPART_STRICT_ERROR", "MULTIPART_UNMATCHED_BOUNDARY":
		return collectQuery | collectPost
	case "FULL_REQUEST", "FULL_REQUEST_LENGTH":
		return collectQuery | collectPost | collectHeaders
	case "ARGS_GET", "ARGS_GET_NAMES":
		return collectQuery
	case "ARGS_POST", "ARGS_POST_NAMES":
		return collectPost
	case "REQUEST_HEADERS", "REQUEST_HEADERS_NAMES":
		return collectHeaders
	case "REQUEST_COOKIES", "REQUEST_COOKIES_NAMES":
		return collectCookies
	case "FILES", "FILES_NAMES", "FILES_SIZES", "FILES_COMBINED_SIZE",
		"MULTIPART_PART_HEADERS", "MULTIPART_PART_HEADERS_NAMES":
		return collectPost | collectFiles
	case "JSON":
		return collectPost | collectJSON
	case "XML":
		return collectPost | collectXML
	default:
		return 0
	}
}

// evalParallelRun evaluates one rule run across the configured workers. Every worker writes a
// distinct result index. | evalParallelRun 使用配置的工作协程求值一个规则段；每个工作协程写入
// 不同的结果下标。
func (e *engine) evalParallelRun(tx *transaction, entries []phaseEntry, indices []int) []ruleEval {
	if cap(tx.parallelResults) < len(indices) {
		tx.parallelResults = make([]ruleEval, len(indices))
	} else {
		tx.parallelResults = tx.parallelResults[:len(indices)]
		for index := range tx.parallelResults {
			tx.parallelResults[index] = ruleEval{}
		}
	}
	results := tx.parallelResults
	workers := e.parallelWorkers
	if workers > len(indices) {
		workers = len(indices)
	}
	if workers < 2 {
		for index, entryIndex := range indices {
			results[index] = e.evalRule(tx, entries[entryIndex].rule)
		}
		return results
	}
	// Workers share the transaction, so transform caching must stay off until they finish. |
	// 工作协程共享事务，因此变换缓存在它们结束前必须关闭。
	tx.parallelEval = true
	var next atomic.Int64
	var wait sync.WaitGroup
	wait.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer wait.Done()
			for {
				index := int(next.Add(1)) - 1
				if index >= len(indices) {
					return
				}
				rule := entries[indices[index]].rule
				if rule.meta.ID > 0 && tx.ruleRemoved(rule.meta.ID) {
					continue
				}
				results[index] = e.evalRule(tx, rule)
			}
		}()
	}
	wait.Wait()
	tx.parallelEval = false
	return results
}

// commitParallelRun commits parallel results in source order and applies blocking semantics.
// | commitParallelRun 按源码顺序提交并行结果并应用拦截语义。
func (e *engine) commitParallelRun(tx *transaction, entries []phaseEntry, indices []int, results []ruleEval, mode Mode) bool {
	for index := range results {
		result := results[index]
		if !result.matched {
			continue
		}
		rule := entries[indices[index]].rule
		if rule.capture && len(result.groups) > 0 {
			tx.setCapture(result.groups)
		}
		e.commitChain(tx, chainResult{
			matched: true,
			hasBase: true,
			base: ruleMatch{
				rule: rule, first: result.first, values: result.values, hasFirst: result.hasFirst,
			},
		})
		if tx.allow || tx.interruption != nil {
			return true
		}
		if !isDisruptive(rule) {
			continue
		}
		if mode == ModeDetection {
			if tx.detected == nil {
				tx.detected = buildInterruption(tx, rule)
			}
			continue
		}
		tx.interruption = buildInterruption(tx, rule)
		return true
	}
	return false
}

// parallelWork estimates the selector-value work in an independent rule run. Regex operators
// weigh more because their per-value cost dominates. | parallelWork 估算独立规则段的选择器-取值
// 工作量；正则算子权重更高，因为其单位取值成本占主导。
func (e *engine) parallelWork(entries []phaseEntry, indices []int, hint int) int {
	work := 0
	for _, index := range indices {
		rule := entries[index].rule
		weight := 1
		if rule.op != nil {
			switch rule.op.kind {
			case opRx, opPM, opPMFromFile, opDetectSQLi, opDetectXSS:
				weight = 4
			}
		}
		for _, selector := range rule.vars {
			if selectorCollectionMask(selector.Name) != 0 {
				work += weight * hint
			} else {
				work += weight
			}
			if work >= parallelWorkThreshold {
				return work
			}
		}
	}
	return work
}

// requestValueHint estimates how many values one rule evaluation may inspect. | requestValueHint
// 估算单条规则求值可能检查的取值数量。
func requestValueHint(tx *transaction) int {
	hint := 1
	if tx.req != nil {
		hint += strings.Count(tx.req.URL.RawQuery, "&")
		hint += len(tx.req.Header)
		if values := tx.req.Header.Values("Cookie"); len(values) > 0 {
			hint += len(values)
		}
		if tx.req.ContentLength > 0 {
			hint += int(tx.req.ContentLength / 64)
		}
	}
	if hint > 256 {
		hint = 256
	}
	return hint
}

// allowParallel reports whether this request may start per-request rule workers. Automatic mode
// yields to request-level concurrency once enough requests are in flight; explicit worker counts
// are honored as configured. | allowParallel 报告当前请求是否可启动每请求规则工作协程。自动模式在
// 足够多请求并发时让位于请求级并发；显式工作协程数按配置执行。
func (e *engine) allowParallel() bool {
	if e.parallelWorkers <= 1 || e.hasRuleMatchSubscribers() {
		return false
	}
	if e.autoParallel && e.active.Load() > e.parallelCap {
		return false
	}
	return true
}

// hasRuleMatchSubscribers reports whether hooks or plugins can mutate state during a match.
// | hasRuleMatchSubscribers 报告钩子或插件是否可能在命中时修改状态。
func (e *engine) hasRuleMatchSubscribers() bool {
	if e.hooks != nil && e.hooks.has(HookRuleMatch) {
		return true
	}
	return e.plugins != nil && e.plugins.has(HookRuleMatch)
}

// skipRuleEntries advances over count rule entries, ignoring markers. | skipRuleEntries 前进 count
// 个规则条目，忽略标记。
func skipRuleEntries(entries []phaseEntry, index, count int) int {
	for count > 0 {
		if index+1 >= len(entries) {
			return len(entries) - 1
		}
		index++
		if entries[index].rule != nil {
			count--
		}
	}
	return index
}

// evalChain evaluates a rule and its chain, applying captures as soon as each member matches.
// | evalChain 求值规则及其链，并在每个成员命中时立即应用捕获。
func (e *engine) evalChain(tx *transaction, rule *compiledRule) chainResult {
	result := e.evalRule(tx, rule)
	if !result.matched {
		return chainResult{}
	}
	if rule.capture && len(result.groups) > 0 {
		tx.setCapture(result.groups)
	}
	chain := chainResult{matched: true, hasBase: true, base: ruleMatch{
		rule: rule, first: result.first, values: result.values, hasFirst: result.hasFirst,
	}}
	for _, child := range rule.chain {
		if child.meta.ID > 0 && tx.ruleRemoved(child.meta.ID) {
			// Removing a chain member disables the whole chain. | 移除链成员会禁用整条链。
			return chainResult{}
		}
		childResult := e.evalRule(tx, child)
		if !childResult.matched {
			return chainResult{}
		}
		if child.capture && len(childResult.groups) > 0 {
			tx.setCapture(childResult.groups)
		}
		chain.members = append(chain.members, ruleMatch{
			rule: child, first: childResult.first, values: childResult.values, hasFirst: childResult.hasFirst,
		})
	}
	return chain
}

// evalRule evaluates one rule's selectors and operator without applying its actions.
// | evalRule 求值单条规则的选择器与算子，不应用其动作。
func (e *engine) evalRule(tx *transaction, rule *compiledRule) ruleEval {
	if !rule.parallelSafe && !rule.evalIndependent {
		tx.currentRule = rule
	}
	if rule.actionOnly {
		return ruleEval{matched: true}
	}
	if rule.op == nil {
		return ruleEval{}
	}
	var result ruleEval
	var transformed transformL1
	var operatorCache operatorL1
	checkTargets := len(tx.removedTargets) > 0
	for _, selector := range rule.vars {
		if checkTargets && rule.meta.ID > 0 && tx.targetRemoved(rule.meta.ID, selector) {
			continue
		}
		if value, found, handled := selector.fastValue(tx); handled {
			if !found {
				continue
			}
			matchedValue, captures, hit := evalRuleValue(tx, rule, value, &transformed, &operatorCache)
			if !hit {
				continue
			}
			if !rule.multiMatch {
				return ruleEval{first: matchedValue, groups: captures, matched: true, hasFirst: true}
			}
			result.values = append(result.values, matchedValue)
			if len(result.groups) == 0 && len(captures) > 0 {
				result.groups = captures
			}
			continue
		}
		values := selector.collect(tx)
		for _, value := range values {
			matchedValue, captures, hit := evalRuleValue(tx, rule, value, &transformed, &operatorCache)
			if !hit {
				continue
			}
			if !rule.multiMatch {
				return ruleEval{first: matchedValue, groups: captures, matched: true, hasFirst: true}
			}
			result.values = append(result.values, matchedValue)
			if len(result.groups) == 0 && len(captures) > 0 {
				result.groups = captures
			}
		}
	}
	result.matched = len(result.values) > 0
	return result
}

// evalRuleValue applies transforms and the operator to one value. | evalRuleValue 对一个取值应用
// 变换与算子。
func evalRuleValue(tx *transaction, rule *compiledRule, value varValue, transformedCache *transformL1, operatorCache *operatorL1) (varValue, []string, bool) {
	transformed := value.Value
	if len(rule.transforms) > 0 {
		if transformedCache != nil && transformedCache.valid && transformedCache.input == value.Value {
			transformed = transformedCache.output
		} else {
			transformed = applyCachedTransforms(tx, value.Value, rule.transforms, rule.transformChainID, rule.transformCacheable)
			if transformedCache != nil {
				transformedCache.input = value.Value
				transformedCache.output = transformed
				transformedCache.valid = true
			}
		}
	}
	if operatorCache != nil && operatorCache.valid && !operatorCache.hit && operatorCache.input == transformed {
		return varValue{}, nil, false
	}
	matched, captures := rule.op.evalWithBuffer(tx, transformed, rule.capture, !rule.multiMatch)
	if !matched {
		if operatorCache != nil {
			operatorCache.input = transformed
			operatorCache.hit = false
			operatorCache.valid = true
		}
		return varValue{}, nil, false
	}
	value.Value = transformed
	return value, captures, true
}

// commitChain records matches and applies non-disruptive actions for a fully matched chain.
// | commitChain 为完全命中的链记录命中并应用非破坏性动作。
func (e *engine) commitChain(tx *transaction, result chainResult) {
	hookMatch := e.hookSubscribed(HookRuleMatch)
	if result.hasBase {
		e.commitMember(tx, result.base, hookMatch)
	}
	for index := range result.members {
		e.commitMember(tx, result.members[index], hookMatch)
	}
}

// commitMember records one rule match and applies its non-disruptive actions. | commitMember 记录
// 一条规则命中并应用其非破坏性动作。
func (e *engine) commitMember(tx *transaction, member ruleMatch, hookMatch bool) {
	rule := member.rule
	tx.currentRule = rule
	if rule.actionOnly {
		e.commitValue(tx, rule, varValue{}, hookMatch, false)
		return
	}
	if member.hasFirst {
		e.commitValue(tx, rule, member.first, hookMatch, true)
	}
	for _, value := range member.values {
		e.commitValue(tx, rule, value, hookMatch, true)
	}
}

// commitValue records one matched value and applies the rule's non-disruptive actions.
// | commitValue 记录一个命中取值并应用规则的非破坏性动作。
func (e *engine) commitValue(tx *transaction, rule *compiledRule, value varValue, hookMatch, record bool) {
	if record {
		tx.setMatched(value)
		if rule.log || hookMatch {
			match := Match{
				RuleID:   rule.meta.ID,
				Phase:    rule.phase,
				Var:      value.Name,
				Key:      value.Key,
				Value:    truncateValue(value.Value),
				Message:  rule.msgMacro.expand(tx),
				Severity: rule.meta.Severity,
				Tags:     rule.meta.Tags,
			}
			if rule.log {
				tx.appendMatch(match)
			}
			if hookMatch {
				e.runHook(HookRuleMatch, tx, rule.phase, rule.meta, &match, nil)
			}
		}
	}
	if rule.allow {
		tx.allow = true
	}
	tx.applySetVars(rule.setvars)
	tx.applyExpireVars(rule.expires)
	tx.applyCtls(rule.ctls)
}

// applySetVars executes setvar actions with numeric addition and subtraction. | applySetVars 执行
// setvar 动作，支持数值加减。
func (tx *transaction) applySetVars(actions []setVarAction) {
	for _, action := range actions {
		raw := action.value.expand(tx)
		switch action.op {
		case '!':
			tx.deleteTXHash(action.hash, action.name)
		case '=':
			tx.setTXValueHash(action.hash, action.name, raw, action.ttl)
		case '+':
			current := tx.lastTXHash(action.hash, action.name)
			if current == "" {
				tx.setTXValueHash(action.hash, action.name, raw, action.ttl)
				continue
			}
			left, leftOK := parseNumber(current)
			right, rightOK := parseNumber(raw)
			if leftOK && rightOK {
				tx.setTXValueHash(action.hash, action.name, formatNumber(left+right), action.ttl)
				continue
			}
			tx.addTXHash(action.hash, action.name, raw, action.ttl)
		case '-':
			current := tx.lastTXHash(action.hash, action.name)
			left, leftOK := parseNumber(current)
			right, rightOK := parseNumber(raw)
			if leftOK && rightOK {
				tx.setTXValueHash(action.hash, action.name, formatNumber(left-right), action.ttl)
			}
		}
	}
}

// applyExpireVars applies expirevar actions to existing TX values. | applyExpireVars 对现有 TX
// 取值应用 expirevar 动作。
func (tx *transaction) applyExpireVars(actions []expireVarAction) {
	for _, action := range actions {
		seconds, err := strconv.Atoi(strings.TrimSpace(action.ttl.expand(tx)))
		if err != nil || seconds <= 0 {
			continue
		}
		current, ok := tx.txLookup(action.hash, action.name)
		if !ok || (!current.single && len(current.values) == 0) {
			continue
		}
		current.expiry = time.Now().Add(time.Duration(seconds) * time.Second)
		tx.txStore(action.hash, action.name, current)
	}
}

// applyCtls applies per-transaction ctl changes. | applyCtls 应用事务级 ctl 变更。
func (tx *transaction) applyCtls(actions []ctlAction) {
	for _, action := range actions {
		switch action.kind {
		case ctlRuleRemoveByID:
			for _, id := range action.ids {
				tx.removeRule(id)
			}
		case ctlRuleRemoveTargetByID:
			tx.removeTarget(action.id, action.target)
		case ctlRuleRemoveByTag:
			if tx.rules != nil {
				for _, id := range tx.rules.byTag[action.value] {
					tx.removeRule(id)
				}
			}
		case ctlRuleRemoveTargetByTag:
			if tx.rules != nil {
				for _, id := range tx.rules.byTag[action.value] {
					tx.removeTarget(id, action.target)
				}
			}
		case ctlRuleEngine:
			tx.engineMode = parseEngineMode(action.value)
		case ctlRequestBodyProcessor:
			tx.bodyProcessor = action.value
		case ctlForceRequestBodyVariable:
			tx.forceBodyVar = action.on
		case ctlRequestBodyAccess:
			tx.requestBodyAccess = action.on
		case ctlResponseBodyAccess:
			tx.responseBodyAccess = action.on
		case ctlRequestBodyLimit:
			tx.bodyLimit = action.limit
		case ctlBodyLimitAction:
			tx.bodyLimitAction = LimitAction(action.limit)
		case ctlAuditEngine:
			tx.auditEngine = action.on
		}
	}
}

// parseEngineMode parses a ctl ruleEngine value. | parseEngineMode 解析 ctl ruleEngine 取值。
func parseEngineMode(value string) Mode {
	switch strings.ToLower(value) {
	case "block":
		return ModeBlock
	case "detection":
		return ModeDetection
	case "off":
		return ModeOff
	default:
		return ModeDefault
	}
}

// isDisruptive reports whether a matched rule interrupts the transaction in blocking mode.
// | isDisruptive 报告命中的规则是否在拦截模式下中断事务。
func isDisruptive(rule *compiledRule) bool {
	return rule != nil && (rule.deny || rule.drop || rule.block || rule.redirect != "")
}

// buildInterruption materializes the interruption for a matched disruptive rule. | buildInterruption
// 为命中的破坏性规则生成中断。
func buildInterruption(tx *transaction, rule *compiledRule) *Interruption {
	action := "deny"
	switch {
	case rule.drop:
		action = "drop"
	case rule.redirect != "":
		action = "redirect"
	case rule.block:
		action = "block"
	}
	status := rule.status
	if status == 0 {
		if action == "redirect" {
			status = http.StatusFound
		} else {
			status = http.StatusForbidden
		}
	}
	data := ""
	if action == "redirect" {
		data = rule.redirectMacro.expand(tx)
	}
	return &Interruption{
		RuleID:   rule.meta.ID,
		Action:   action,
		Status:   status,
		Data:     data,
		Phase:    rule.phase,
		Message:  rule.msgMacro.expand(tx),
		Severity: rule.meta.Severity,
		Tags:     rule.meta.Tags,
	}
}

// hookSubscribed reports whether hooks or plugins listen to a point. | hookSubscribed 报告钩子或
// 插件是否监听某个事件点。
func (e *engine) hookSubscribed(point HookPoint) bool {
	if e.hooks != nil && e.hooks.has(point) {
		return true
	}
	return e.plugins != nil && e.plugins.has(point)
}

// runHook dispatches one hook event to the shared registry and engine plugins. | runHook 把一个
// 钩子事件分发给共享注册表与引擎插件。
func (e *engine) runHook(point HookPoint, tx *transaction, phase Phase, rule *Rule, match *Match, err error) {
	if tx == nil || !e.hookSubscribed(point) {
		return
	}
	ctx := &HookContext{
		Point:        point,
		Phase:        phase,
		Rule:         rule,
		Match:        match,
		Err:          err,
		tx:           tx,
		Request:      tx.req,
		Interruption: tx.interruption,
		Version:      e.version,
	}
	ctx.Tx = &Transaction{tx: tx}
	if e.hooks != nil {
		e.hooks.run(ctx)
	}
	if e.plugins != nil {
		e.plugins.runHook(ctx)
	}
	if ctx.Interruption != nil && tx.interruption == nil {
		tx.interruption = ctx.Interruption
	}
}

// parseNumber parses a numeric TX value. | parseNumber 解析数值 TX 取值。
func parseNumber(value string) (float64, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	if number, ok := parseSmallInteger(value); ok {
		return number, true
	}
	number, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(number) || math.IsInf(number, 0) {
		return 0, false
	}
	return number, true
}

// formatNumber renders a numeric result without trailing zeros. | formatNumber 渲染无数值尾随零的结果。
func formatNumber(value float64) string {
	if value == math.Trunc(value) && value >= math.MinInt64 && value <= math.MaxInt64 {
		return strconv.FormatInt(int64(value), 10)
	}
	return strconv.FormatFloat(value, 'f', -1, 64)
}

// truncateValue bounds an event value. | truncateValue 限制事件取值长度。
func truncateValue(value string) string {
	if len(value) <= maxMatchValue {
		return value
	}
	return value[:maxMatchValue]
}
