package core

import (
	"context"
	"net/netip"
	"strings"

	"github.com/shibingli/ydx/errs"
)

// Rule is one dynamic allow/deny matcher. | Rule 是一条动态允许/拒绝匹配规则。
//
// Empty fields are wildcards. A rule must set at least one field. | 空字段是通配符；一条规则
// 至少需要设置一个字段。
type Rule struct {
	// IP is a single address or CIDR prefix. | IP 是单个地址或 CIDR 前缀。
	IP string `json:"ip,omitempty"`
	// Country is an ISO 3166-1 alpha-2 country code. | Country 是 ISO 3166-1 alpha-2 国家代码。
	Country string `json:"country,omitempty"`
	// Action restricts the rule to one host action. | Action 把规则限制到一个宿主动作。
	Action string `json:"action,omitempty"`
	// Type restricts the rule to one challenge type. | Type 把规则限制到一种验证码类型。
	Type Type `json:"type,omitempty"`
}

// Policy is an immutable allow/deny snapshot. | Policy 是不可变的允许/拒绝快照。
//
// Deny rules are evaluated before allow rules: an explicit denial always wins. | 拒绝规则先于
// 允许规则评估：显式拒绝始终优先。
type Policy struct {
	// Allow lists exemptions from risk checks. | Allow 列出风险检查的豁免项。
	Allow []Rule `json:"allow,omitempty"`
	// Deny lists blocked requests. | Deny 列出被拦截的请求。
	Deny []Rule `json:"deny,omitempty"`
}

// PolicyProvider loads a fresh policy snapshot. | PolicyProvider 加载新的策略快照。
type PolicyProvider interface {
	// LoadPolicy returns the current policy. | LoadPolicy 返回当前策略。
	LoadPolicy(ctx context.Context) (*Policy, error)
}

// PolicyFunc adapts a function to PolicyProvider. | PolicyFunc 把函数适配为 PolicyProvider。
type PolicyFunc func(ctx context.Context) (*Policy, error)

// LoadPolicy implements PolicyProvider. | LoadPolicy 实现 PolicyProvider。
func (f PolicyFunc) LoadPolicy(ctx context.Context) (*Policy, error) {
	if f == nil {
		return nil, errs.Detail(ErrInvalidOptions, "nil policy function | 策略函数为 nil")
	}
	return f(ctx)
}

// CompiledRule is a validated rule ready for matching. | compiledRule 是可直接匹配的已校验规则。
type CompiledRule struct {
	prefix  netip.Prefix
	country string
	action  string
	typ     Type
	hasIP   bool
}

// PolicySnapshot is the immutable compiled policy. | policySnapshot 是编译后的不可变策略。
type PolicySnapshot struct {
	allow       []CompiledRule
	deny        []CompiledRule
	hasCountry  bool
	countryDeny bool
}

// EmptyPolicy is used before any policy is installed. | EmptyPolicy 在安装任何策略前使用。
var EmptyPolicy = &PolicySnapshot{}

// CompilePolicy validates and compiles a policy. | compilePolicy 校验并编译策略。
func CompilePolicy(p *Policy) (*PolicySnapshot, error) {
	if p == nil {
		return EmptyPolicy, nil
	}
	s := &PolicySnapshot{
		allow: make([]CompiledRule, 0, len(p.Allow)),
		deny:  make([]CompiledRule, 0, len(p.Deny)),
	}
	for i := range p.Allow {
		rule, err := compileRule(p.Allow[i])
		if err != nil {
			return nil, errs.WrapDetail(err, ErrInvalidOptions, "allow rule %d | 允许规则 %d", i, i)
		}
		if rule.country != "" {
			s.hasCountry = true
		}
		s.allow = append(s.allow, rule)
	}
	for i := range p.Deny {
		rule, err := compileRule(p.Deny[i])
		if err != nil {
			return nil, errs.WrapDetail(err, ErrInvalidOptions, "deny rule %d | 拒绝规则 %d", i, i)
		}
		if rule.country != "" {
			s.hasCountry = true
			s.countryDeny = true
		}
		s.deny = append(s.deny, rule)
	}
	return s, nil
}

// compileRule validates one rule. | compileRule 校验一条规则。
func compileRule(r Rule) (CompiledRule, error) {
	rule := CompiledRule{
		country: strings.ToUpper(strings.TrimSpace(r.Country)),
		action:  strings.TrimSpace(r.Action),
		typ:     r.Type,
	}
	if r.IP != "" {
		ip := strings.TrimSpace(r.IP)
		if prefix, err := netip.ParsePrefix(ip); err == nil {
			rule.prefix = prefix.Masked()
			rule.hasIP = true
		} else if addr, addrErr := netip.ParseAddr(ip); addrErr == nil {
			rule.prefix = netip.PrefixFrom(addr, addr.BitLen())
			rule.hasIP = true
		} else {
			return CompiledRule{}, errs.Detail(ErrInvalidOptions, "invalid rule IP %q | 非法规则 IP %q", r.IP, r.IP)
		}
	}
	if rule.country != "" && len(rule.country) != 2 {
		return CompiledRule{}, errs.Detail(ErrInvalidOptions, "invalid country %q | 非法国家代码 %q", r.Country, r.Country)
	}
	if !rule.hasIP && rule.country == "" && rule.action == "" && rule.typ == "" {
		return CompiledRule{}, errs.Detail(ErrInvalidOptions, "empty rule matches everything | 空规则会匹配一切")
	}
	return rule, nil
}

// matches reports whether the rule matches one request. | matches 报告规则是否匹配一次请求。
func (r CompiledRule) matches(ip netip.Addr, country, action string, typ Type) bool {
	if r.hasIP && (!ip.IsValid() || !r.prefix.Contains(ip)) {
		return false
	}
	if r.country != "" && !strings.EqualFold(r.country, country) {
		return false
	}
	if r.action != "" && r.action != action {
		return false
	}
	if r.typ != "" && r.typ != typ {
		return false
	}
	return true
}

// Decision is the policy outcome for one request. | Decision 是一次请求的策略结果。
type Decision struct {
	Denied        bool
	Allowed       bool
	DeniedCountry bool
}

// evaluate applies deny-first policy semantics. | evaluate 按拒绝优先语义评估策略。
// HasCountry reports whether any rule references a country. | HasCountry 报告是否有规则引用国家。
func (s *PolicySnapshot) HasCountry() bool {
	if s == nil {
		return false
	}
	return s.hasCountry
}

// CountryDeny reports whether any deny rule references a country. | CountryDeny 报告是否有拒绝规则引用国家。
func (s *PolicySnapshot) CountryDeny() bool {
	if s == nil {
		return false
	}
	return s.countryDeny
}

func (s *PolicySnapshot) Evaluate(ip netip.Addr, country, action string, typ Type) Decision {
	if s == nil {
		return Decision{}
	}
	for _, rule := range s.deny {
		if rule.matches(ip, country, action, typ) {
			return Decision{Denied: true, DeniedCountry: rule.country != ""}
		}
	}
	for _, rule := range s.allow {
		if rule.matches(ip, country, action, typ) {
			return Decision{Allowed: true}
		}
	}
	return Decision{}
}

// ClonePolicy deep-copies a policy so caller mutations cannot race evaluation. | clonePolicy 深拷贝策略，
// 使调用方修改不会与评估并发。
func ClonePolicy(p *Policy) *Policy {
	if p == nil {
		return nil
	}
	out := &Policy{
		Allow: append([]Rule(nil), p.Allow...),
		Deny:  append([]Rule(nil), p.Deny...),
	}
	return out
}
