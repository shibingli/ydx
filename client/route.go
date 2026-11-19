package client

import (
	"context"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/shibingli/ydx/errs"
)

// Rewrite describes a path prefix rewrite applied after a rule matches. | Rewrite 描述规则命中后的路径前缀重写。
type Rewrite struct {
	// StripPrefix removes a leading path prefix at a segment boundary. | StripPrefix 在段边界上去除路径前缀。
	StripPrefix string
	// AddPrefix prepends a path prefix after stripping. | AddPrefix 在去除前缀后追加路径前缀。
	AddPrefix string
}

// Rule binds a path pattern to request policies. | Rule 把路径模式绑定到请求策略。
type Rule struct {
	// Guard overrides the client-wide guard for this rule. | Guard 为该规则覆盖客户端级守卫。
	Guard Guard
	// Condition optionally rejects a match after the path matched. | Condition 在路径命中后可选地拒绝该匹配。
	Condition func(*http.Request) bool
	// HostSet is a prebuilt host pool override; it wins over Hosts. The client
	// takes ownership and closes it on Close; a pool a rule stops referencing only
	// stops active health checks and is retained for in-flight requests. | HostSet
	// 是预构建的 Host 池覆盖；优先于 Hosts。客户端接管所有权并在 Close 时关闭；
	// 规则不再引用的池只停止主动健康检查，并保留给在途请求。
	HostSet *HostSet
	// Rewrite rewrites the path before the host base path is joined. | Rewrite 在拼接 Host base path 前重写路径。
	Rewrite *Rewrite
	// Headers are added to matching requests. | Headers 添加到命中请求。
	Headers http.Header
	// Retry overrides the client-wide retry policy. | Retry 覆盖客户端级重试策略。
	Retry *RetryPolicy
	// Cache enables response caching for this rule. | Cache 为该规则启用响应缓存。
	Cache *CachePolicy
	// Coalesce merges concurrent identical requests for this rule. | Coalesce 为该规则合并并发相同请求。
	Coalesce *CoalescePolicy
	// Mirror configures shadow replay or tee mirroring for this rule. | Mirror 为该规则配置影子重放或 tee 镜像。
	Mirror *MirrorPolicy
	// Name identifies the rule in metadata, hooks and stats. | Name 在元数据、钩子与统计中标识规则。
	Name string
	// Pattern is the path pattern matched against the logical request URL. | Pattern 是与逻辑请求 URL 匹配的路径模式。
	Pattern string
	// Connection selects the connection mode for this rule. | Connection 为该规则选择连接模式。
	Connection ConnMode
	// Methods restricts the rule; empty means every method. | Methods 限制方法；为空表示全部方法。
	Methods []string
	// Hosts overrides the default host pool for this rule. | Hosts 覆盖该规则的默认 Host 池。
	Hosts []string
	// Timeout bounds the request, including its response body. Forward treats it as
	// an upstream response-header timeout. | Timeout 限制请求（含响应正文）的总时长；
	// Forward 将其视为上游响应头超时。
	Timeout time.Duration
	// UA overrides the client User-Agent policy for this rule. | UA 为该规则覆盖客户端 User-Agent 策略。
	UA *UAPolicy
	// PreserveHost keeps the inbound Host header instead of the selected target. | PreserveHost 保留入站 Host 头而非目标 Host。
	PreserveHost bool

	// id distinguishes compiled rules with equal names in cache and coalesce
	// keys. | id 在缓存与合并键中区分同名规则。
	id uint64
}

// ruleIDCounter assigns a process-unique identity to every compiled rule. | ruleIDCounter
// 为每条已编译规则分配进程内唯一标识。
var ruleIDCounter atomic.Uint64

// patternScore is the deterministic specificity key used to order rules. | patternScore 是用于规则排序的确定性特异性键。
type patternScore struct {
	catchAll bool
	literals int
	params   int
	globs    int
}

// score computes the specificity key for a compiled pattern. | score 计算已编译模式的特性键。
func (p *Pattern) score() patternScore {
	var s patternScore
	for _, seg := range p.segments {
		if seg.catchAll {
			s.catchAll = true
			continue
		}
		for _, tok := range seg.tokens {
			switch tok.kind {
			case tokenLiteral:
				s.literals += len(tok.text)
			case tokenParam:
				s.params++
			case tokenGlob:
				s.globs++
			}
		}
	}
	return s
}

// ruleEntry is one compiled rule. | ruleEntry 是一条已编译规则。
type ruleEntry struct {
	rule    *Rule
	pattern *Pattern
	methods []string
	score   patternScore
	index   int
}

// RuleSet is an immutable, specificity-ordered rule snapshot. | RuleSet 是不可变、按特异性排序的规则快照。
type RuleSet struct {
	entries []ruleEntry
}

// hostSets returns the distinct host pools referenced by rules. | hostSets 返回规则引用的不同 Host 池。
func (rs *RuleSet) hostSets() []*HostSet {
	if rs == nil {
		return nil
	}
	seen := make(map[*HostSet]struct{}, len(rs.entries))
	var sets []*HostSet
	for _, entry := range rs.entries {
		if entry.rule.HostSet == nil {
			continue
		}
		if _, ok := seen[entry.rule.HostSet]; ok {
			continue
		}
		seen[entry.rule.HostSet] = struct{}{}
		sets = append(sets, entry.rule.HostSet)
	}
	return sets
}

// CompileRules validates and orders rules, returning an immutable snapshot. | CompileRules 校验并排序规则，返回不可变快照。
func CompileRules(rules ...Rule) (*RuleSet, error) {
	rs := &RuleSet{entries: make([]ruleEntry, 0, len(rules))}
	for i := range rules {
		rule := rules[i]
		if rule.UA != nil {
			prepared, err := prepareUA(rule.UA)
			if err != nil {
				return nil, err
			}
			rule.UA = prepared
		}
		if rule.Pattern == "" {
			return nil, errs.Detail(ErrBadPattern, "empty rule pattern | 空规则模式")
		}
		pattern, err := CompilePattern(rule.Pattern)
		if err != nil {
			return nil, err
		}
		if err := validateRewrite(rule.Rewrite); err != nil {
			return nil, err
		}
		methods := cloneSlice(rule.Methods)
		for _, method := range methods {
			if method == "" {
				return nil, errs.Detail(ErrInvalidConfig, "empty rule method | 空规则方法")
			}
		}
		rule.Methods = methods
		rule.Hosts = append([]string(nil), rule.Hosts...)
		if rule.Timeout < 0 {
			return nil, errs.Detail(ErrInvalidConfig, "negative rule timeout | 规则超时为负")
		}
		if rule.Retry != nil && rule.Retry.MaxAttempts < 0 {
			return nil, errs.Detail(ErrInvalidConfig, "negative rule max attempts | 规则最大尝试次数为负")
		}
		if rule.HostSet != nil && rule.HostSet.Len() == 0 {
			return nil, errs.Detail(ErrInvalidConfig, "empty rule host set | 空规则 Host 池")
		}
		if rule.HostSet == nil && len(rule.Hosts) > 0 {
			hosts := make([]Host, 0, len(rule.Hosts))
			for _, raw := range rule.Hosts {
				parsed, err := url.Parse(raw)
				if err != nil || !parsed.IsAbs() || parsed.Host == "" ||
					(parsed.Scheme != "http" && parsed.Scheme != "https") {
					return nil, errs.Detail(ErrInvalidConfig, "invalid rule host %q | 非法的规则 Host %q", raw, raw)
				}
				hosts = append(hosts, Host{URL: parsed, Weight: 1})
			}
			hostSet, err := NewHostSet(hosts...)
			if err != nil {
				return nil, err
			}
			rule.HostSet = hostSet
		}
		if rule.Headers != nil {
			rule.Headers = rule.Headers.Clone()
		}
		if rule.Rewrite != nil {
			rewrite := *rule.Rewrite
			rule.Rewrite = &rewrite
		}
		if rule.Mirror != nil {
			prepared, err := prepareMirror(rule.Mirror)
			if err != nil {
				return nil, err
			}
			rule.Mirror = prepared
		}
		if rule.Retry != nil {
			if rule.Retry.MaxAttempts < 0 {
				return nil, errs.Detail(ErrInvalidConfig, "negative rule max attempts | 规则最大尝试次数为负")
			}
			retry := *rule.Retry
			retry.Methods = cloneSlice(retry.Methods)
			retry.StatusCodes = cloneSlice(retry.StatusCodes)
			rule.Retry = &retry
		}
		if rule.Cache != nil {
			cache := *rule.Cache
			cache.Methods = cloneSlice(cache.Methods)
			cache.StatusCodes = cloneSlice(cache.StatusCodes)
			cache.Vary = cloneSlice(cache.Vary)
			rule.Cache = &cache
		}
		if rule.Coalesce != nil {
			coalesce := *rule.Coalesce
			coalesce.Methods = cloneSlice(coalesce.Methods)
			rule.Coalesce = &coalesce
		}
		if access, ok := rule.Guard.(*AccessPolicy); ok {
			cloned := cloneAccessPolicy(access)
			if err := cloned.prepare(); err != nil {
				return nil, err
			}
			rule.Guard = cloned
		}
		if rule.Connection != "" && !validConnMode(rule.Connection) {
			return nil, errs.Detail(ErrInvalidConfig, "unknown rule connection mode %q | 未知规则连接模式 %q", rule.Connection, rule.Connection)
		}
		rule.id = ruleIDCounter.Add(1)
		rs.entries = append(rs.entries, ruleEntry{
			rule:    &rule,
			pattern: pattern,
			methods: methods,
			score:   pattern.score(),
			index:   i,
		})
	}
	sort.SliceStable(rs.entries, func(i, j int) bool {
		a, b := rs.entries[i].score, rs.entries[j].score
		if a.catchAll != b.catchAll {
			return !a.catchAll
		}
		if a.literals != b.literals {
			return a.literals > b.literals
		}
		if a.params != b.params {
			return a.params < b.params
		}
		if a.globs != b.globs {
			return a.globs < b.globs
		}
		return rs.entries[i].index < rs.entries[j].index
	})
	return rs, nil
}

// Len returns the number of rules. | Len 返回规则数量。
func (rs *RuleSet) Len() int {
	if rs == nil {
		return 0
	}
	return len(rs.entries)
}

// Match returns the first rule matching method and path; conditions are not evaluated. | Match 返回首个匹配方法与路径的规则；不求值 Condition。
func (rs *RuleSet) Match(method, path string) (*Rule, Params, bool) {
	if rs == nil {
		return nil, Params{}, false
	}
	pathSegments, pathOK := splitMatchPath(path)
	if !pathOK {
		return nil, Params{}, false
	}
	for i := range rs.entries {
		entry := &rs.entries[i]
		if !methodAllowed(entry.methods, method) {
			continue
		}
		if params, ok := entry.pattern.matchSegments(pathSegments); ok {
			return entry.rule, params, true
		}
	}
	return nil, Params{}, false
}

// MatchRequest returns the first rule matching the request, including its condition. | MatchRequest 返回首个匹配请求的规则，并求值 Condition。
func (rs *RuleSet) MatchRequest(req *http.Request) (*Rule, Params, bool) {
	rule, params, ok, _ := rs.matchRequest(req)
	return rule, params, ok
}

// matchRequest evaluates conditions with panic isolation for engine routing. | matchRequest 带 panic 隔离地为引擎路由求值 Condition。
func (rs *RuleSet) matchRequest(req *http.Request) (rule *Rule, params Params, ok bool, err error) {
	if rs == nil || req == nil || req.URL == nil || len(rs.entries) == 0 {
		return nil, Params{}, false, nil
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			rule, params, ok = nil, Params{}, false
			err = errs.Detail(ErrHookPanic, "rule condition panic: %v | 规则 Condition panic：%v", recovered, recovered)
		}
	}()
	path := matchPath(req.URL)
	pathSegments, pathOK := splitMatchPath(path)
	if !pathOK {
		return nil, Params{}, false, nil
	}
	for i := range rs.entries {
		entry := &rs.entries[i]
		if !methodAllowed(entry.methods, req.Method) {
			continue
		}
		matched, matchOK := entry.pattern.matchSegments(pathSegments)
		if !matchOK {
			continue
		}
		if entry.rule.Condition != nil && !entry.rule.Condition(req) {
			continue
		}
		return entry.rule, matched, true, nil
	}
	return nil, Params{}, false, nil
}

// methodAllowed reports whether method is in the rule's method set. | methodAllowed 报告 method 是否在规则方法集合中。
func methodAllowed(methods []string, method string) bool {
	if len(methods) == 0 {
		return true
	}
	for _, candidate := range methods {
		if candidate == method {
			return true
		}
	}
	return false
}

// matchPath returns the path form used for matching, mirroring router semantics. | matchPath 返回用于匹配的路径形式，对齐 router 语义。
func matchPath(u *url.URL) string {
	if u.RawPath != "" {
		return u.RawPath
	}
	if u.Path == "" {
		return "/"
	}
	return u.Path
}

// validateRewrite rejects rewrite prefixes that are not absolute paths. | validateRewrite 拒绝非绝对路径的重写前缀。
func validateRewrite(rw *Rewrite) error {
	if rw == nil {
		return nil
	}
	for _, prefix := range []string{rw.StripPrefix, rw.AddPrefix} {
		if prefix == "" {
			continue
		}
		if prefix[0] != '/' {
			return errs.Detail(ErrBadPattern, "rewrite prefix %q must start with / | 重写前缀 %q 必须以 / 开头", prefix, prefix)
		}
		if strings.ContainsAny(prefix, "?#") {
			return errs.Detail(ErrBadPattern, "rewrite prefix %q must not contain query or fragment | 重写前缀 %q 不得包含查询或片段", prefix, prefix)
		}
	}
	return nil
}

// applyRewrite applies a rewrite at segment boundaries and preserves a leading slash. | applyRewrite 在段边界应用重写并保留前导斜杠。
func applyRewrite(rw *Rewrite, path string) string {
	if rw == nil {
		return path
	}
	if rw.StripPrefix != "" {
		prefix := strings.TrimSuffix(rw.StripPrefix, "/")
		if prefix != "" {
			switch {
			case path == prefix:
				path = "/"
			case strings.HasPrefix(path, prefix+"/"):
				path = path[len(prefix):]
			}
		}
	}
	if rw.AddPrefix != "" {
		prefix := strings.TrimSuffix(rw.AddPrefix, "/")
		if prefix != "" {
			if path == "/" {
				path = ""
			}
			path = prefix + path
		}
	}
	if path == "" {
		path = "/"
	}
	if path[0] != '/' {
		path = "/" + path
	}
	return path
}

// resolveLogicalURL resolves ref against base without mutating base. | resolveLogicalURL 在不修改 base 的前提下把 ref 解析为逻辑 URL。
func resolveLogicalURL(base *url.URL, ref string) (*url.URL, error) {
	parsed, err := url.Parse(ref)
	if err != nil {
		return nil, errs.Wrap(err, ErrInvalidRequest)
	}
	if parsed.IsAbs() {
		return parsed, nil
	}
	if base == nil {
		return nil, ErrRelativeURL
	}
	return base.ResolveReference(parsed), nil
}

// WithBaseURL sets the logical base URL used to resolve relative convenience requests. | WithBaseURL 设置用于解析相对便捷请求的逻辑 base URL。
func WithBaseURL(base string) Option {
	return func(o *options) error {
		parsed, err := url.Parse(base)
		if err != nil || !parsed.IsAbs() || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return errs.Detail(ErrInvalidConfig, "invalid base URL %q | 非法的 base URL %q", base, base)
		}
		o.BaseURL = parsed
		return nil
	}
}

// WithRule appends one rule to the client configuration. | WithRule 向客户端配置追加一条规则。
func WithRule(rule Rule) Option {
	return func(o *options) error {
		o.Rules = append(o.Rules, rule)
		return nil
	}
}

// WithRules appends several rules to the client configuration. | WithRules 向客户端配置追加多条规则。
func WithRules(rules ...Rule) Option {
	return func(o *options) error {
		o.Rules = append(o.Rules, rules...)
		return nil
	}
}

// UpdateRules atomically replaces the client's compiled rule snapshot. A rule
// host pool no longer referenced by the new snapshot stops active health checks
// but remains usable by in-flight requests until Client.Close. | UpdateRules
// 原子替换客户端已编译的规则快照。新快照不再引用的规则 Host 池会停止主动健康
// 检查，但在 Client.Close 前仍可供在途请求使用。
func (c *Client) UpdateRules(rules ...Rule) error {
	if c == nil || c.engine == nil {
		return ErrClosed
	}
	c.lifecycleMu.Lock()
	if c.closed.Load() {
		c.lifecycleMu.Unlock()
		return ErrClosed
	}
	rs, err := CompileRules(rules...)
	if err != nil {
		c.lifecycleMu.Unlock()
		return err
	}
	if err := c.engine.validateIPGuard(rs); err != nil {
		c.lifecycleMu.Unlock()
		return err
	}
	rs.detachDefaultHostSet(c.engine.hosts.Load())
	// Disable the policy-free fast path before publishing rules so a concurrent
	// request cannot observe new rules while bare is still true. | 发布规则前先
	// 关闭无策略快路径，避免并发请求在 bare 仍为 true 时绕过新规则。
	c.engine.bare.Store(false)
	c.engine.rules.Store(rs)
	c.engine.registerRuleHosts(rs)
	c.engine.retireRuleHosts(rs)
	c.engine.pruneTLS()
	c.engine.bare.Store(isBareEngine(c.opts, rs, c.engine.hosts.Load()))
	c.lifecycleMu.Unlock()
	return nil
}

// detachDefaultHostSet makes rules that reference the current default follow
// future default-pool replacements instead of retaining a closed pool. | detachDefaultHostSet
// 让引用当前默认池的规则跟随后续默认池替换，而不是保留已关闭的池。
func (rs *RuleSet) detachDefaultHostSet(def *HostSet) {
	if rs == nil || def == nil {
		return
	}
	for i := range rs.entries {
		if rs.entries[i].rule.HostSet == def {
			rs.entries[i].rule.HostSet = nil
		}
	}
}

// registerRuleHosts starts active health for rule-owned host pools. | registerRuleHosts 为规则持有的 Host 池启动主动健康检查。
func (e *engine) registerRuleHosts(rs *RuleSet) {
	if e == nil || e.closed.Load() {
		return
	}
	defaultSet := e.hosts.Load()
	for _, hs := range rs.hostSets() {
		if hs == nil || hs == defaultSet {
			continue
		}
		e.ruleHostsMu.Lock()
		if _, exists := e.ruleHosts[hs]; exists {
			e.ruleHostsMu.Unlock()
			continue
		}
		e.ruleHosts[hs] = struct{}{}
		e.ruleHostsMu.Unlock()
		hs.startHealth(context.Background(), e.healthTransport, e.opts.Logger)
	}
}

// retireRuleHosts stops health checks for rule host pools no longer referenced
// by active rules and retains them for in-flight requests until Client.Close. |
// retireRuleHosts 停止不再被活动规则引用的规则 Host 池的健康检查，并保留它们供
// 在途请求使用，直到 Client.Close。
func (e *engine) retireRuleHosts(rs *RuleSet) {
	if e == nil || rs == nil {
		return
	}
	active := make(map[*HostSet]struct{})
	for _, hs := range rs.hostSets() {
		if hs != nil {
			active[hs] = struct{}{}
		}
	}
	e.ruleHostsMu.Lock()
	var retired []*HostSet
	for hs := range e.ruleHosts {
		if _, ok := active[hs]; !ok {
			delete(e.ruleHosts, hs)
			retired = append(retired, hs)
		}
	}
	e.retiredHosts = append(e.retiredHosts, retired...)
	e.ruleHostsMu.Unlock()
	for _, hs := range retired {
		hs.stopHealth()
	}
}

// closeRuleHosts closes every rule-owned host pool. | closeRuleHosts 关闭全部规则持有的 Host 池。
func (e *engine) closeRuleHosts(ctx context.Context) {
	if e == nil {
		return
	}
	e.ruleHostsMu.Lock()
	sets := make([]*HostSet, 0, len(e.ruleHosts)+len(e.retiredHosts))
	for hs := range e.ruleHosts {
		sets = append(sets, hs)
	}
	sets = append(sets, e.retiredHosts...)
	e.ruleHosts = make(map[*HostSet]struct{})
	e.retiredHosts = nil
	e.ruleHostsMu.Unlock()
	for _, hs := range sets {
		_ = hs.CloseContext(ctx)
	}
}
