package cas

import (
	"context"
	"strings"
)

// ServiceRegistry decides which service URLs may receive tickets and whether a validation request
// matches the URL a ticket was bound to. | ServiceRegistry 决定哪些服务 URL 可以接收票据，以及校验
// 请求是否匹配票据绑定的 URL。
//
// The server calls Allows when it is about to redirect a browser to a service (login, logout and
// proxy target services) and Matches when it validates a ticket. A nil registry in ServerConfig
// allows every non-empty URL, which is convenient for development but should not be used in
// production. | 服务端在即将把浏览器重定向到服务（登录、登出与代理目标服务）时调用 Allows，在校验
// 票据时调用 Matches。ServerConfig 中为 nil 的注册表允许每个非空 URL，便于开发，但不应在生产使用。
type ServiceRegistry interface {
	// Allows reports whether service may receive a ticket. | Allows 报告 service 是否可以接收票据。
	Allows(ctx context.Context, service string) bool
	// Matches reports whether requested is an acceptable validation service for a ticket bound to
	// bound. | Matches 报告 requested 是否为绑定到 bound 的票据可接受的校验服务。
	Matches(bound, requested string) bool
}

// StaticServiceRegistry is a ServiceRegistry built from a fixed list of exact URLs and wildcard
// patterns. | StaticServiceRegistry 是由固定精确 URL 与通配模式列表构建的 ServiceRegistry。
//
// A pattern contains "*" wildcards that match any run of bytes, including the empty run, so
// "https://*.example.com/*" accepts "https://app.example.com/callback". Matching is byte-wise and
// deliberately does not use regular expressions. | 模式包含 "*" 通配符，匹配任意字节序列（包括空
// 序列），因此 "https://*.example.com/*" 接受 "https://app.example.com/callback"。匹配按字节进行，
// 刻意不使用正则表达式。
type StaticServiceRegistry struct {
	// exact holds registered URLs without wildcards. | exact 保存不含通配符的注册 URL。
	exact map[string]struct{}
	// patterns holds the registered wildcard patterns in registration order. | patterns 按注册顺序保存通配模式。
	patterns []string
	// services preserves the constructor input for introspection. | services 保留构造输入以便自省。
	services []string
	// allowAll accepts every non-empty URL. | allowAll 接受每个非空 URL。
	allowAll bool
}

// NewStaticServiceRegistry returns a registry for the given exact URLs and wildcard patterns. Empty
// entries are ignored. | NewStaticServiceRegistry 返回由给定精确 URL 与通配模式构成的注册表。空项
// 会被忽略。
func NewStaticServiceRegistry(services ...string) *StaticServiceRegistry {
	registry := &StaticServiceRegistry{
		exact:    make(map[string]struct{}),
		services: make([]string, 0, len(services)),
	}
	for _, service := range services {
		service = strings.TrimSpace(service)
		if service == "" {
			continue
		}
		registry.services = append(registry.services, service)
		if strings.Contains(service, "*") {
			registry.patterns = append(registry.patterns, service)
			continue
		}
		registry.exact[service] = struct{}{}
	}
	return registry
}

// NewAllowAllServiceRegistry returns a registry that accepts every non-empty URL. It is intended
// for tests and local development; validation still requires the requested URL to equal the URL
// bound to the ticket exactly. | NewAllowAllServiceRegistry 返回接受每个非空 URL 的注册表。它用于
// 测试与本地开发；校验仍要求请求 URL 与票据绑定的 URL 完全相等。
func NewAllowAllServiceRegistry() *StaticServiceRegistry {
	return &StaticServiceRegistry{allowAll: true}
}

// Allows reports whether service is registered. | Allows 报告 service 是否已注册。
func (r *StaticServiceRegistry) Allows(_ context.Context, service string) bool {
	if service == "" {
		return false
	}
	if r == nil || r.allowAll {
		return true
	}
	if _, ok := r.exact[service]; ok {
		return true
	}
	for _, pattern := range r.patterns {
		if wildcardMatch(pattern, service) {
			return true
		}
	}
	return false
}

// Matches reports whether requested may validate a ticket bound to bound. Exact equality always
// matches; otherwise both URLs must match one registered pattern. | Matches 报告 requested 是否可
// 校验绑定到 bound 的票据。完全相等总是匹配；否则两个 URL 必须匹配同一个已注册模式。
func (r *StaticServiceRegistry) Matches(bound, requested string) bool {
	if bound == "" || requested == "" {
		return false
	}
	if bound == requested {
		return true
	}
	if r == nil || r.allowAll {
		return false
	}
	for _, pattern := range r.patterns {
		if wildcardMatch(pattern, bound) && wildcardMatch(pattern, requested) {
			return true
		}
	}
	return false
}

// Services returns the registered exact URLs and patterns in registration order. | Services 按注册
// 顺序返回已注册的精确 URL 与模式。
func (r *StaticServiceRegistry) Services() []string {
	if r == nil {
		return nil
	}
	return append([]string(nil), r.services...)
}

// wildcardMatch reports whether pattern matches value, where "*" matches any byte sequence. | wildcardMatch
// 报告 pattern 是否匹配 value，其中 "*" 匹配任意字节序列。
//
// The implementation is the classic linear-time greedy matcher with backtracking to the most recent
// star; it never recurses and never uses regular expressions. | 实现是经典的线性时间贪婪匹配器，
// 回退到最近的星号；它不递归，也不使用正则表达式。
func wildcardMatch(pattern, value string) bool {
	pi, vi := 0, 0
	star, match := -1, 0
	for vi < len(value) {
		switch {
		case pi < len(pattern) && pattern[pi] == value[vi]:
			pi++
			vi++
		case pi < len(pattern) && pattern[pi] == '*':
			star = pi
			match = vi
			pi++
		case star >= 0:
			pi = star + 1
			match++
			vi = match
		default:
			return false
		}
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}
