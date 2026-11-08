package cas

import (
	"context"
	"strings"
	"sync"

	"github.com/shibingli/ydx/errs"
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

// FrontChannelLogoutResolver resolves the front-channel logout URL registered for a service. The
// server consults it during browser logout and renders one hidden frame per distinct URL so the
// browser can end the service sessions too. Implementations must only return URLs that were
// explicitly registered for the exact service URL; the server additionally requires every returned
// URL to be an absolute http(s) URL, which keeps an accidental or malicious value from becoming an
// open redirect or a script URL. | FrontChannelLogoutResolver 解析为服务注册的前端登出 URL。服务端在
// 浏览器登出时查询它，并为每个不同 URL 渲染一个隐藏框架，使浏览器也能结束服务会话。实现必须只返回
// 为精确服务 URL 显式注册的 URL；服务端还要求每个返回的 URL 都是绝对 http(s) URL，避免意外或恶意取值
// 变成开放重定向或脚本 URL。
type FrontChannelLogoutResolver interface {
	// FrontChannelLogoutURL returns the registered front-channel logout URL of service. The boolean
	// reports whether a URL is registered. | FrontChannelLogoutURL 返回 service 已注册的前端登出
	// URL。布尔值报告是否注册了 URL。
	FrontChannelLogoutURL(ctx context.Context, service string) (string, bool)
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
	// frontChannel maps an exact service URL to its registered front-channel logout URL. |
	// frontChannel 把精确服务 URL 映射到已注册的前端登出 URL。
	frontChannel map[string]string
	// patterns holds the registered wildcard patterns in registration order. | patterns 按注册顺序保存通配模式。
	patterns []string
	// services preserves the constructor input for introspection. | services 保留构造输入以便自省。
	services []string
	// allowAll accepts every non-empty URL. | allowAll 接受每个非空 URL。
	allowAll bool
	// mu guards frontChannel. | mu 保护 frontChannel。
	mu sync.RWMutex
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

// SetFrontChannelLogoutURL registers the front-channel logout URL of an already registered service.
// The service must pass Allows, and logoutURL must be an absolute http(s) URL without embedded user
// information, so browser logout can never be pointed at an arbitrary or script URL. Registering a
// second URL for the same service replaces the first. | SetFrontChannelLogoutURL 为已注册服务登记
// 前端登出 URL。服务必须通过 Allows，logoutURL 必须是不含内嵌用户信息的绝对 http(s) URL，因此浏览器
// 登出绝不会指向任意 URL 或脚本 URL。为同一服务重复登记会替换前一个 URL。
func (r *StaticServiceRegistry) SetFrontChannelLogoutURL(service, logoutURL string) error {
	if r == nil {
		return errs.Detail(ErrInvalidConfig, "service registry is nil | 服务注册表为空")
	}
	service = strings.TrimSpace(service)
	logoutURL = strings.TrimSpace(logoutURL)
	if !r.Allows(context.Background(), service) {
		return errs.Detail(ErrServiceNotRegistered, "service %[1]q is not registered | 服务 %[1]q 未注册", service)
	}
	if !validServiceURL(logoutURL) {
		return errs.Detail(ErrInvalidService, "front-channel logout URL %[1]q is not an absolute http(s) URL | 前端登出 URL %[1]q 不是绝对 http(s) URL", logoutURL)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.frontChannel == nil {
		r.frontChannel = make(map[string]string)
	}
	r.frontChannel[service] = logoutURL
	return nil
}

// FrontChannelLogoutURL returns the URL registered by SetFrontChannelLogoutURL for service. |
// FrontChannelLogoutURL 返回 SetFrontChannelLogoutURL 为 service 登记的 URL。
func (r *StaticServiceRegistry) FrontChannelLogoutURL(_ context.Context, service string) (string, bool) {
	if r == nil || service == "" {
		return "", false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	logoutURL, ok := r.frontChannel[service]
	if !ok || logoutURL == "" {
		return "", false
	}
	return logoutURL, true
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
