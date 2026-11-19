package client

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/shibingli/ydx/errs"
	"golang.org/x/net/idna"
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

// dialPoliciesKey carries the effective IP-check policies for one request. | dialPoliciesKey
// 携带单个请求生效的 IP 检查策略。
type dialPoliciesKey struct{}

// dialPoliciesFrom returns the request's effective IP-check policies. | dialPoliciesFrom
// 返回请求生效的 IP 检查策略。
func dialPoliciesFrom(ctx context.Context) []*AccessPolicy {
	if ctx == nil {
		return nil
	}
	policies, _ := ctx.Value(dialPoliciesKey{}).([]*AccessPolicy)
	return policies
}

// dialPoliciesFor resolves the IP-check policies that apply to rule. | dialPoliciesFor
// 解析适用于 rule 的 IP 检查策略。
func dialPoliciesFor(o options, rule *Rule) []*AccessPolicy {
	var policies []*AccessPolicy
	appendPolicy := func(policy *AccessPolicy) {
		if policy == nil || !policy.needsIPCheck() {
			return
		}
		if err := policy.prepare(); err != nil {
			return
		}
		policies = append(policies, policy)
	}
	appendPolicy(o.AccessPolicy)
	guard := o.Guard
	if rule != nil && rule.Guard != nil {
		guard = rule.Guard
	}
	appendGuardPolicies(guard, appendPolicy)
	return policies
}

// appendGuardPolicies walks a guard or chain and reports AccessPolicy members. | appendGuardPolicies
// 遍历守卫或链并报告其中的 AccessPolicy。
func appendGuardPolicies(guard Guard, appendPolicy func(*AccessPolicy)) {
	switch typed := guard.(type) {
	case *AccessPolicy:
		appendPolicy(typed)
	case GuardChain:
		for _, child := range typed {
			appendGuardPolicies(child, appendPolicy)
		}
	}
}

// hasIPCheckPolicies reports whether any configured policy needs IP checks. | hasIPCheckPolicies
// 报告任一已配置策略是否需要 IP 检查。
func hasIPCheckPolicies(o options, rules *RuleSet) bool {
	if o.AccessPolicy != nil && o.AccessPolicy.needsIPCheck() {
		return true
	}
	guardHasIPCheck := func(guard Guard) bool {
		found := false
		appendGuardPolicies(guard, func(policy *AccessPolicy) {
			if policy.needsIPCheck() {
				found = true
			}
		})
		return found
	}
	if guardHasIPCheck(o.Guard) {
		return true
	}
	if rules != nil {
		for i := range rules.entries {
			if guardHasIPCheck(rules.entries[i].rule.Guard) {
				return true
			}
		}
	}
	return false
}

// installGuardedDial installs per-request policy dialing and proxy fail-closed
// behavior on a transport. | installGuardedDial 在传输上安装逐请求策略拨号与代理
// 失败关闭行为。
func installGuardedDial(transport *http.Transport, dialer *net.Dialer) {
	transport.DialContext = guardedDialContext(dialer)
	if transport.Proxy == nil {
		return
	}
	proxy := transport.Proxy
	transport.Proxy = func(req *http.Request) (*url.URL, error) {
		if len(dialPoliciesFrom(req.Context())) == 0 {
			return proxy(req)
		}
		resolved, err := proxy(req)
		if err != nil {
			return nil, err
		}
		if resolved != nil {
			return nil, errs.Detail(ErrBlocked, "IP guard cannot use an HTTP proxy | IP 守卫不能使用 HTTP 代理")
		}
		return nil, nil
	}
}

// guardedDialContext resolves and pins the checked address before dialing. | guardedDialContext
// 在拨号前解析并固定已检查的地址。
func guardedDialContext(dialer *net.Dialer) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		policies := dialPoliciesFrom(ctx)
		if len(policies) == 0 {
			return dialer.DialContext(ctx, network, addr)
		}
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return dialer.DialContext(ctx, network, addr)
		}
		if ip, parseErr := netip.ParseAddr(host); parseErr == nil {
			if !dialPoliciesAllow(policies, ip) {
				return nil, errs.Detail(ErrBlocked, "dial address %s denied | 拨号地址 %s 被拒绝", ip, ip)
			}
			return dialer.DialContext(ctx, network, addr)
		}
		addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrBlocked, "resolve %s", host)
		}
		allowed := 0
		var lastErr error
		for _, ip := range addresses {
			if !dialPoliciesAllow(policies, ip) {
				continue
			}
			allowed++
			conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
			if dialErr == nil {
				return conn, nil
			}
			lastErr = dialErr
		}
		if allowed == 0 {
			return nil, errs.Detail(ErrBlocked, "address for %s denied | %s 的地址被拒绝", host, host)
		}
		if lastErr == nil {
			lastErr = ErrNoHealthyHosts
		}
		return nil, lastErr
	}
}

// dialPoliciesAllow reports whether every policy allows ip. | dialPoliciesAllow
// 报告是否所有策略都允许 ip。
func dialPoliciesAllow(policies []*AccessPolicy, ip netip.Addr) bool {
	for _, policy := range policies {
		if !policy.allowIP(ip) {
			return false
		}
	}
	return true
}

// validateIPGuard rejects rule policies that a custom transport cannot guard. | validateIPGuard
// 拒绝自定义传输无法执行 IP 守卫的规则策略。
func (e *engine) validateIPGuard(rules *RuleSet) error {
	if e == nil || e.ipGuard {
		return nil
	}
	if hasIPCheckPolicies(e.opts, rules) {
		return errs.Detail(ErrInvalidConfig, "IP guard requires an *http.Transport without custom dialers | IP 守卫需要未自定义拨号器的 *http.Transport")
	}
	return nil
}

// callGuard invokes a guard with panic isolation and fails closed. | callGuard 以 panic 隔离调用守卫并失败关闭。
func callGuard(guard Guard, ctx context.Context, req *http.Request) (decision GuardDecision, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			decision = GuardDecision{}
			err = errs.Detail(ErrHookPanic, "guard panic: %v | guard panic：%v", recovered, recovered)
		}
	}()
	return guard.Check(ctx, req)
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
	// AllowHosts lists host globs; empty allows every host. Matching lowercases
	// hostnames, removes trailing root dots and applies IDNA lookup mapping. |
	// AllowHosts 列出 Host glob；为空允许全部 Host。匹配时主机名转小写、去掉末尾
	// 根点并应用 IDNA lookup 映射。
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

	dnsMu    sync.Mutex
	dnsCache map[string]dnsCacheEntry
	dnsTTL   time.Duration
	resolver func(context.Context, string, string) ([]netip.Addr, error)
	once     sync.Once
	// DNSCacheTTL caches host resolutions for this policy; <0 disables caching
	// and 0 means 30s. | DNSCacheTTL 为该策略缓存主机解析结果；<0 禁用缓存，
	// 0 表示 30s。
	DNSCacheTTL time.Duration
	// BlockPrivateIPs rejects loopback, private, link-local, multicast and
	// unspecified addresses. Client-wide and rule-level policies are rechecked at
	// dial time on the built-in transport; requests with IP checks fail closed when
	// an HTTP proxy is configured. Custom transports must be an *http.Transport
	// without custom dialers, otherwise construction/update is rejected. |
	// BlockPrivateIPs 拒绝回环、私网、链路本地、组播与未指定地址。客户端级与规则级
	// 策略在內置传输的拨号期复检；启用 IP 检查时若配置 HTTP 代理则失败关闭。自定义
	// 传输必须是无自定义拨号器的 *http.Transport，否则构造或更新会被拒绝。
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
		cloned := cloneAccessPolicy(policy)
		if err := cloned.prepare(); err != nil {
			return err
		}
		o.AccessPolicy = cloned
		return nil
	}
}

// cloneAccessPolicy snapshots the exported policy fields. | cloneAccessPolicy 快照访问策略的导出字段。
func cloneAccessPolicy(policy *AccessPolicy) *AccessPolicy {
	if policy == nil {
		return nil
	}
	cloned := &AccessPolicy{
		AllowSchemes:    append([]string(nil), policy.AllowSchemes...),
		AllowHosts:      append([]string(nil), policy.AllowHosts...),
		DenyHosts:       append([]string(nil), policy.DenyHosts...),
		AllowCIDRs:      append([]string(nil), policy.AllowCIDRs...),
		DenyCIDRs:       append([]string(nil), policy.DenyCIDRs...),
		AllowPorts:      append([]int(nil), policy.AllowPorts...),
		DenyPorts:       append([]int(nil), policy.DenyPorts...),
		AllowMethods:    append([]string(nil), policy.AllowMethods...),
		DenyMethods:     append([]string(nil), policy.DenyMethods...),
		MaxRequestBytes: policy.MaxRequestBytes,
		BlockPrivateIPs: policy.BlockPrivateIPs,
		DNSCacheTTL:     policy.DNSCacheTTL,
	}
	return cloned
}

// prepare compiles the policy once. | prepare 只编译一次策略。
func (p *AccessPolicy) prepare() error {
	if p == nil {
		return nil
	}
	p.once.Do(func() {
		switch {
		case p.DNSCacheTTL < 0:
			p.dnsTTL = 0
		case p.DNSCacheTTL == 0:
			p.dnsTTL = 30 * time.Second
		default:
			p.dnsTTL = p.DNSCacheTTL
		}
		p.allowScheme = stringSet(p.AllowSchemes, true)
		p.allowMethod = stringSet(p.AllowMethods, false)
		p.denyMethod = stringSet(p.DenyMethods, false)
		p.allowHosts = canonicalGuardPatterns(p.AllowHosts)
		p.denyHosts = canonicalGuardPatterns(p.DenyHosts)
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
	host := canonicalGuardHost(req.URL.Hostname())
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
	if p.MaxRequestBytes > 0 && req.ContentLength <= 0 && req.Body != nil && req.Body != http.NoBody {
		req.Body = &maxBytesBody{body: req.Body, remaining: p.MaxRequestBytes}
		if req.GetBody != nil {
			originalGetBody := req.GetBody
			limit := p.MaxRequestBytes
			req.GetBody = func() (io.ReadCloser, error) {
				body, err := originalGetBody()
				if err != nil {
					return nil, err
				}
				return &maxBytesBody{body: body, remaining: limit}, nil
			}
		}
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

// maxBytesBody enforces an unknown-length request body cap while reading. | maxBytesBody 在读取时限制未知长度的请求正文。
type maxBytesBody struct {
	body      io.ReadCloser
	remaining int64
	tooLarge  bool
}

// Read reads at most the remaining cap plus one byte. | Read 最多读取剩余上限加一字节。
func (b *maxBytesBody) Read(p []byte) (int, error) {
	if b.tooLarge {
		return 0, errs.Detail(ErrRequestTooLarge, "request body exceeds %d bytes | 请求正文超过 %d 字节", b.remaining, b.remaining)
	}
	if len(p) == 0 {
		return 0, nil
	}
	if b.remaining < int64(len(p)) {
		p = p[:b.remaining+1]
	}
	n, err := b.body.Read(p)
	b.remaining -= int64(n)
	if b.remaining < 0 {
		b.tooLarge = true
		return n, errs.Detail(ErrRequestTooLarge, "request body too large | 请求正文过大")
	}
	return n, err
}

// Close closes the wrapped body. | Close 关闭被包装的正文。
func (b *maxBytesBody) Close() error { return b.body.Close() }

// LimitedBody marks a streaming body capped by an access policy. | LimitedBody 标记由访问策略限长的流式正文。
func (b *maxBytesBody) LimitedBody() {}

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
	addresses, err := p.lookupHostIPs(ctx, host)
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

// dnsCacheEntry is one cached resolution. | dnsCacheEntry 是一次缓存的解析结果。
type dnsCacheEntry struct {
	expires   time.Time
	addresses []netip.Addr
}

// lookupHostIPs resolves host with a bounded per-policy TTL cache. | lookupHostIPs
// 以受限于策略的有界 TTL 缓存解析主机。
func (p *AccessPolicy) lookupHostIPs(ctx context.Context, host string) ([]netip.Addr, error) {
	ttl := p.dnsTTL
	if ttl > 0 {
		p.dnsMu.Lock()
		entry, ok := p.dnsCache[host]
		p.dnsMu.Unlock()
		if ok && time.Now().Before(entry.expires) {
			return entry.addresses, nil
		}
	}
	var (
		addresses []netip.Addr
		err       error
	)
	if p.resolver != nil {
		addresses, err = p.resolver(ctx, "ip", host)
	} else {
		addresses, err = net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}
	if err != nil {
		return nil, err
	}
	if ttl > 0 {
		p.dnsMu.Lock()
		if p.dnsCache == nil {
			p.dnsCache = make(map[string]dnsCacheEntry)
		}
		if len(p.dnsCache) >= 256 {
			for key := range p.dnsCache {
				delete(p.dnsCache, key)
				break
			}
		}
		p.dnsCache[host] = dnsCacheEntry{
			expires:   time.Now().Add(ttl),
			addresses: append([]netip.Addr(nil), addresses...),
		}
		p.dnsMu.Unlock()
	}
	return addresses, nil
}

// allowIP reports whether ip passes private and CIDR checks. | allowIP 报告 ip 是否通过私网与 CIDR 检查。
func (p *AccessPolicy) allowIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() {
		return false
	}
	// Prefix.Contains rejects zoned IPv6 addresses, so strip the zone before
	// CIDR checks while preserving it for the actual dial address. | Prefix.Contains
	// 会拒绝带 zone 的 IPv6 地址；CIDR 检查前先剥离 zone，实际拨号地址仍保留 zone。
	if ip.Is6() && ip.Zone() != "" {
		ip = ip.WithZone("")
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

// canonicalGuardHost lowercases a host, removes trailing root dots and applies
// the IDNA lookup mapping so Unicode and punycode forms compare equal. |
// canonicalGuardHost 把主机名转小写、去掉末尾根点，并应用 IDNA lookup 映射，使
// Unicode 与 punycode 形式可一致比较。
func canonicalGuardHost(host string) string {
	host = strings.ToLower(host)
	// An IPv6 zone is not part of the host name used for allow/deny matching. |
	// IPv6 zone 不属于用于 allow/deny 匹配的主机名。
	if zone := strings.IndexByte(host, '%'); zone >= 0 {
		host = host[:zone]
	}
	for strings.HasSuffix(host, ".") {
		host = strings.TrimSuffix(host, ".")
	}
	if ascii, err := idna.Lookup.ToASCII(host); err == nil {
		return strings.ToLower(ascii)
	}
	return host
}

// isPrivateIP reports whether ip is loopback, private, link-local, multicast,
// unspecified or otherwise non-public. | isPrivateIP 报告 ip 是否为回环、私网、
// 链路本地、组播、未指定或其它非公网地址。
func isPrivateIP(ip netip.Addr) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	if ip.Is4() {
		b := ip.As4()
		switch {
		case b[0] == 0: // 0.0.0.0/8
			return true
		case b[0] == 100 && b[1] >= 64 && b[1] <= 127: // 100.64.0.0/10
			return true
		case b[0] == 192 && b[1] == 0 && b[2] == 0: // 192.0.0.0/24
			return true
		case b[0] == 198 && (b[1] == 18 || b[1] == 19): // 198.18.0.0/15
			return true
		case b[0] >= 240: // 240.0.0.0/4
			return true
		}
	}
	return false
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

// canonicalGuardPatterns lowercases host globs and IDNA-normalizes literals. | canonicalGuardPatterns
// 把 Host glob 转小写，并对无通配符的字面量做 IDNA 归一化。
func canonicalGuardPatterns(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, len(values))
	for i, value := range values {
		value = strings.ToLower(value)
		if !strings.ContainsAny(value, "*?[\\]") {
			if ascii, err := idna.Lookup.ToASCII(value); err == nil {
				value = strings.ToLower(ascii)
			}
		}
		out[i] = value
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
