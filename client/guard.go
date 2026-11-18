package client

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/shibingli/ydx/errs"
)

// GuardDecision is the outcome of one guard check. | GuardDecision 是一次守卫检查的结果。
type GuardDecision struct {
	// Action is the denial action, such as "deny". | Action 是拒绝动作，例如 "deny"。
	Action string
	// Message is a human-readable reason. | Message 是人类可读原因。
	Message string
	// Matched lists matched rule or policy names. | Matched 列出命中的规则或策略名。
	Matched []string
	// Status is the denial status; zero defaults to 403. | Status 是拒绝状态码；0 默认 403。
	Status int
	// RuleID identifies the matched WAF or policy rule. | RuleID 标识命中的 WAF 或策略规则。
	RuleID int
	// Allowed reports whether the request may proceed. | Allowed 报告请求是否可继续。
	Allowed bool
}

// Guard inspects a logical request before cache, coalescing or host selection. | Guard 在缓存、合并或 Host 选择前检查逻辑请求。
type Guard interface {
	// Check returns the decision for one request. | Check 返回单个请求的决策。
	Check(ctx context.Context, req *http.Request) (GuardDecision, error)
}

// GuardFunc adapts a function into a Guard. | GuardFunc 把函数适配为 Guard。
type GuardFunc func(ctx context.Context, req *http.Request) (GuardDecision, error)

// Check calls f. | Check 调用 f。
func (f GuardFunc) Check(ctx context.Context, req *http.Request) (GuardDecision, error) {
	return f(ctx, req)
}

// GuardChain runs guards in order and stops at the first denial or error. | GuardChain 顺序执行守卫，在首个拒绝或错误处停止。
type GuardChain []Guard

// Check implements Guard. | Check 实现 Guard。
func (c GuardChain) Check(ctx context.Context, req *http.Request) (GuardDecision, error) {
	for _, guard := range c {
		if guard == nil {
			continue
		}
		decision, err := guard.Check(ctx, req)
		if err != nil {
			return GuardDecision{}, err
		}
		if !decision.Allowed {
			return decision, nil
		}
	}
	return GuardDecision{Allowed: true}, nil
}

// AccessPolicy is a compiled scheme/host/method/port/CIDR allow-deny policy. | AccessPolicy 是已编译的 scheme/host/method/port/CIDR 允许-拒绝策略。
type AccessPolicy struct {
	prepErr     error
	allowPorts  map[int]bool
	denyPorts   map[int]bool
	allowScheme map[string]bool
	allowMethod map[string]bool
	denyMethod  map[string]bool
	// AllowSchemes limits URL schemes; empty allows http and https. | AllowSchemes 限制 URL scheme；为空允许 http 与 https。
	AllowSchemes []string
	// AllowHosts lists host globs; empty allows every host. | AllowHosts 列出 Host glob；为空允许全部 Host。
	AllowHosts []string
	// DenyHosts lists host globs checked after AllowHosts. | DenyHosts 列出在 AllowHosts 之后检查的 Host glob。
	DenyHosts []string
	// AllowCIDRs lists permitted remote CIDRs; empty allows every address. | AllowCIDRs 列出允许的远端 CIDR；为空允许全部地址。
	AllowCIDRs []string
	// DenyCIDRs lists denied remote CIDRs. | DenyCIDRs 列出拒绝的远端 CIDR。
	DenyCIDRs []string
	// AllowPorts limits destination ports; empty allows every port. | AllowPorts 限制目标端口；为空允许全部端口。
	AllowPorts []int
	// DenyPorts denies destination ports. | DenyPorts 拒绝目标端口。
	DenyPorts []int
	// AllowMethods limits HTTP methods; empty allows every method. | AllowMethods 限制 HTTP 方法；为空允许全部方法。
	AllowMethods []string
	// DenyMethods denies HTTP methods. | DenyMethods 拒绝 HTTP 方法。
	DenyMethods []string
	allowCIDRs  []netip.Prefix
	denyCIDRs   []netip.Prefix
	allowHosts  []string
	denyHosts   []string
	// MaxRequestBytes rejects known-length request bodies above the limit. | MaxRequestBytes 拒绝已知长度超过上限的请求正文。
	MaxRequestBytes int64

	once sync.Once
	// BlockPrivateIPs rejects loopback, private, link-local, multicast and unspecified addresses. | BlockPrivateIPs 拒绝回环、私网、链路本地、组播与未指定地址。
	BlockPrivateIPs bool
}

// WithGuard sets the client-wide guard. | WithGuard 设置客户端级守卫。
func WithGuard(guard Guard) Option {
	return func(o *options) error {
		o.Guard = guard
		return nil
	}
}

// WithAccessPolicy sets the client-wide access policy and its dial-time IP guard. | WithAccessPolicy 设置客户端级访问策略及其拨号期 IP 守卫。
func WithAccessPolicy(policy *AccessPolicy) Option {
	return func(o *options) error {
		if policy == nil {
			return errs.Detail(ErrInvalidConfig, "nil access policy | 空访问策略")
		}
		o.AccessPolicy = policy
		return nil
	}
}

// prepare compiles the policy once. | prepare 只编译一次策略。
func (p *AccessPolicy) prepare() error {
	if p == nil {
		return nil
	}
	p.once.Do(func() {
		p.allowScheme = stringSet(p.AllowSchemes, true)
		p.allowMethod = stringSet(p.AllowMethods, false)
		p.denyMethod = stringSet(p.DenyMethods, false)
		p.allowHosts = lowerAll(p.AllowHosts)
		p.denyHosts = lowerAll(p.DenyHosts)
		p.allowPorts = intSet(p.AllowPorts)
		p.denyPorts = intSet(p.DenyPorts)
		for _, pattern := range append(append([]string(nil), p.allowHosts...), p.denyHosts...) {
			if _, err := path.Match(pattern, "x"); err != nil {
				p.prepErr = errs.WrapDetail(err, ErrInvalidConfig, "host glob %q", pattern)
				return
			}
		}
		for _, raw := range p.AllowCIDRs {
			prefix, err := parseCIDR(raw)
			if err != nil {
				p.prepErr = errs.WrapDetail(err, ErrInvalidConfig, "allow CIDR %q", raw)
				return
			}
			p.allowCIDRs = append(p.allowCIDRs, prefix)
		}
		for _, raw := range p.DenyCIDRs {
			prefix, err := parseCIDR(raw)
			if err != nil {
				p.prepErr = errs.WrapDetail(err, ErrInvalidConfig, "deny CIDR %q", raw)
				return
			}
			p.denyCIDRs = append(p.denyCIDRs, prefix)
		}
	})
	return p.prepErr
}

// Check implements Guard. | Check 实现 Guard。
func (p *AccessPolicy) Check(ctx context.Context, req *http.Request) (GuardDecision, error) {
	if p == nil {
		return GuardDecision{Allowed: true}, nil
	}
	if err := p.prepare(); err != nil {
		return GuardDecision{}, errs.Wrap(err, ErrGuard)
	}
	if req == nil || req.URL == nil {
		return denyDecision(http.StatusBadRequest, "nil request"), nil
	}
	scheme := strings.ToLower(req.URL.Scheme)
	if len(p.allowScheme) > 0 {
		if !p.allowScheme[scheme] {
			return denyDecision(http.StatusForbidden, "scheme "+scheme+" denied"), nil
		}
	} else if scheme != "http" && scheme != "https" {
		return denyDecision(http.StatusForbidden, "scheme "+scheme+" denied"), nil
	}
	host := strings.ToLower(req.URL.Hostname())
	if len(p.allowHosts) > 0 && !matchAnyHost(p.allowHosts, host) {
		return denyDecision(http.StatusForbidden, "host "+host+" not allowed"), nil
	}
	if matchAnyHost(p.denyHosts, host) {
		return denyDecision(http.StatusForbidden, "host "+host+" denied"), nil
	}
	if len(p.allowMethod) > 0 && !p.allowMethod[req.Method] {
		return denyDecision(http.StatusForbidden, "method "+req.Method+" denied"), nil
	}
	if p.denyMethod[req.Method] {
		return denyDecision(http.StatusForbidden, "method "+req.Method+" denied"), nil
	}
	if p.MaxRequestBytes > 0 && req.ContentLength > p.MaxRequestBytes {
		return denyDecision(http.StatusRequestEntityTooLarge, "request body too large"), nil
	}
	port := urlPort(req.URL)
	if len(p.allowPorts) > 0 && !p.allowPorts[port] {
		return denyDecision(http.StatusForbidden, "port "+strconv.Itoa(port)+" not allowed"), nil
	}
	if p.denyPorts[port] {
		return denyDecision(http.StatusForbidden, "port "+strconv.Itoa(port)+" denied"), nil
	}
	if p.needsIPCheck() {
		if err := p.checkHostIPs(ctx, host); err != nil {
			return denyDecision(http.StatusForbidden, err.Error()), nil
		}
	}
	return GuardDecision{Allowed: true}, nil
}

// guardFor resolves the access policy, rule guard and client guard chain. | guardFor 解析访问策略、规则守卫与客户端守卫链。
func (e *engine) guardFor(rule *Rule) Guard {
	var guards []Guard
	if e.opts.AccessPolicy != nil {
		guards = append(guards, e.opts.AccessPolicy)
	}
	if rule != nil && rule.Guard != nil {
		guards = append(guards, rule.Guard)
	} else if e.opts.Guard != nil {
		guards = append(guards, e.opts.Guard)
	}
	switch len(guards) {
	case 0:
		return nil
	case 1:
		return guards[0]
	default:
		return GuardChain(guards)
	}
}

// needsIPCheck reports whether the policy must resolve and validate IPs. | needsIPCheck 报告策略是否需要解析并校验 IP。
func (p *AccessPolicy) needsIPCheck() bool {
	return p != nil && (p.BlockPrivateIPs || len(p.allowCIDRs) > 0 || len(p.denyCIDRs) > 0)
}

// checkHostIPs validates an IP literal or every resolved address of host. | checkHostIPs 校验 IP 字面量或 host 解析出的每个地址。
func (p *AccessPolicy) checkHostIPs(ctx context.Context, host string) error {
	if ip, err := netip.ParseAddr(host); err == nil {
		if !p.allowIP(ip) {
			return errs.Detail(ErrBlocked, "address %s denied | 地址 %s 被拒绝", ip, ip)
		}
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return errs.WrapDetail(err, ErrBlocked, "resolve %s", host)
	}
	for _, address := range addresses {
		if !p.allowIP(address) {
			return errs.Detail(ErrBlocked, "address %s denied | 地址 %s 被拒绝", address, address)
		}
	}
	return nil
}

// allowIP reports whether ip passes private and CIDR checks. | allowIP 报告 ip 是否通过私网与 CIDR 检查。
func (p *AccessPolicy) allowIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() {
		return false
	}
	if p.BlockPrivateIPs && isPrivateIP(ip) {
		return false
	}
	if len(p.allowCIDRs) > 0 {
		allowed := false
		for _, prefix := range p.allowCIDRs {
			if prefix.Contains(ip) {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}
	for _, prefix := range p.denyCIDRs {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

// dialControl validates the actual resolved address before connect. | dialControl 在连接前校验实际解析地址。
func (p *AccessPolicy) dialControl(network, address string, _ syscall.RawConn) error {
	if p == nil {
		return nil
	}
	if err := p.prepare(); err != nil {
		return err
	}
	if !p.needsIPCheck() {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return nil
	}
	if !p.allowIP(ip) {
		return errs.Detail(ErrBlocked, "dial address %s denied | 拨号地址 %s 被拒绝", ip, ip)
	}
	return nil
}

// denyDecision builds a denial with a default status. | denyDecision 构建带默认状态码的拒绝。
func denyDecision(status int, message string) GuardDecision {
	if status == 0 {
		status = http.StatusForbidden
	}
	return GuardDecision{
		Allowed: false,
		Status:  status,
		Action:  "deny",
		Message: message,
	}
}

// isPrivateIP reports whether ip is loopback, private, link-local, multicast or unspecified. | isPrivateIP 报告 ip 是否为回环、私网、链路本地、组播或未指定地址。
func isPrivateIP(ip netip.Addr) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified()
}

// matchAnyHost reports whether host matches any glob. | matchAnyHost 报告 host 是否匹配任一 glob。
func matchAnyHost(patterns []string, host string) bool {
	for _, pattern := range patterns {
		if pattern == "*" {
			return true
		}
		if matched, err := path.Match(pattern, host); err == nil && matched {
			return true
		}
	}
	return false
}

// urlPort returns the effective port for a URL. | urlPort 返回 URL 的有效端口。
func urlPort(u *url.URL) int {
	if u == nil {
		return 0
	}
	if value := u.Port(); value != "" {
		if port, err := strconv.Atoi(value); err == nil {
			return port
		}
		return 0
	}
	switch strings.ToLower(u.Scheme) {
	case "http":
		return 80
	case "https":
		return 443
	default:
		return 0
	}
}

// parseCIDR parses a CIDR or a bare IP. | parseCIDR 解析 CIDR 或裸 IP。
func parseCIDR(raw string) (netip.Prefix, error) {
	if strings.Contains(raw, "/") {
		return netip.ParsePrefix(raw)
	}
	ip, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(ip, ip.BitLen()), nil
}

// stringSet builds a lookup set with optional lowercasing. | stringSet 构建可选小写的查找集合。
func stringSet(values []string, lower bool) map[string]bool {
	if len(values) == 0 {
		return nil
	}
	set := make(map[string]bool, len(values))
	for _, value := range values {
		if lower {
			value = strings.ToLower(value)
		}
		set[value] = true
	}
	return set
}

// lowerAll lowercases every value. | lowerAll 把全部值转为小写。
func lowerAll(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = strings.ToLower(value)
	}
	return out
}

// intSet builds a lookup set. | intSet 构建查找集合。
func intSet(values []int) map[int]bool {
	if len(values) == 0 {
		return nil
	}
	set := make(map[int]bool, len(values))
	for _, value := range values {
		set[value] = true
	}
	return set
}
