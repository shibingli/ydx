package cors

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/shibingli/ydx/middleware/reqlog"
	"github.com/shibingli/ydx/router"
)

// CORSOptions configures the CORS middleware.
// | CORSOptions 配置 CORS 中间件。
type CORSOptions struct {
	// AllowOrigins lists the allowed origins. | AllowOrigins 列出允许的来源。
	// "*" matches every origin and "*.example.com" matches the subdomains of example.com. | "*" 匹配任意来源，"*.example.com" 匹配 example.com 的子域。
	// Any other value is matched literally, optionally prefixed with a scheme. | 其余取值按字面量匹配，可以带协议前缀。
	// An empty list allows no cross-origin caller at all. | 列表为空时不允许任何跨源调用。
	AllowOrigins []string
	// AllowMethods lists the methods echoed on preflight requests. | AllowMethods 列出预检请求回显的方法。
	AllowMethods []string
	// AllowHeaders lists the request headers echoed on preflight requests. | AllowHeaders 列出预检请求回显的请求头。
	AllowHeaders []string
	// ExposeHeaders lists the response headers exposed to the browser. | ExposeHeaders 列出暴露给浏览器的响应头。
	ExposeHeaders []string
	// AllowCredentials allows cookies and Authorization on cross-origin requests. | AllowCredentials 允许跨源请求携带 cookie 与 Authorization。
	AllowCredentials bool
	// MaxAge is sent as Access-Control-Max-Age on preflight responses. | MaxAge 作为 Access-Control-Max-Age 写在预检响应上。
	MaxAge time.Duration
}

// originPattern is a parsed entry of CORSOptions.AllowOrigins.
// | originPattern 是 CORSOptions.AllowOrigins 中一条解析后的规则。
type originPattern struct {
	scheme string // "" means any scheme. | 空串表示不限协议。
	host   string // lowercase; a leading dot means subdomain matching. | 小写；以点开头表示子域匹配。
	any    bool   // "*" matches any host. | "*" 匹配任意主机。
}

// parseOriginPattern parses one AllowOrigins entry. | parseOriginPattern 解析一条 AllowOrigins 规则。
func parseOriginPattern(raw string) (originPattern, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return originPattern{}, false
	}
	p := originPattern{}
	if i := strings.Index(s, "://"); i >= 0 {
		p.scheme = strings.ToLower(s[:i])
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	s = strings.ToLower(s)
	switch {
	case s == "*":
		p.any = true
	case strings.HasPrefix(s, "*."):
		p.host = s[1:] // keep the leading dot: it marks subdomain matching. | 保留前导点：它标记子域匹配。
	default:
		p.host = s
	}
	if !p.any && p.host == "" {
		return originPattern{}, false
	}
	return p, true
}

// splitOrigin splits an Origin header into its lowercased scheme and host without allocating.
// | splitOrigin 在不分配的前提下把 Origin 头拆成小写协议与主机。
//
// url.Parse would accept the same shape but allocates a URL, a userinfo and a host string on every
// request. The Origin header is a narrow grammar (scheme://host[:port], optionally with userinfo or
// a trailing path that browsers never send), so a byte scan is both equivalent and allocation-free.
// | url.Parse 能接受同样的形态，但每请求都会分配 URL、用户信息与主机字符串。Origin 头是窄语法
// （scheme://host[:port]，浏览器不会附带用户信息或路径），逐字节扫描既等价又不分配。
func splitOrigin(origin string) (scheme, host string, ok bool) {
	i := strings.Index(origin, "://")
	if i <= 0 {
		return "", "", false
	}
	scheme = strings.ToLower(origin[:i])
	rest := origin[i+3:]
	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		rest = rest[:j]
	}
	if at := strings.LastIndexByte(rest, '@'); at >= 0 {
		rest = rest[at+1:]
	}
	if rest == "" {
		return "", "", false
	}
	return scheme, strings.ToLower(rest), true
}

// matchOrigin reports whether origin is allowed and which value the response header must carry.
// | matchOrigin 报告 origin 是否被允许，以及响应头应当携带的取值。
func matchOrigin(origin string, patterns []originPattern, credentials bool) (bool, string) {
	scheme, host, ok := splitOrigin(origin)
	if !ok {
		return false, ""
	}
	for _, p := range patterns {
		if p.scheme != "" && p.scheme != scheme {
			continue
		}
		switch {
		case p.any:
			// Wildcards may never be combined with credentials. | 通配绝不可与凭证同时使用。
			if credentials {
				return true, origin
			}
			return true, "*"
		case strings.HasPrefix(p.host, "."):
			if len(host) > len(p.host) && strings.HasSuffix(host, p.host) {
				return true, origin
			}
		case p.host == host:
			return true, origin
		}
	}
	return false, ""
}

// Canonical response header keys, precomputed once. Header.Set canonicalizes its key on every
// call; these keys are already canonical, so writing the map directly avoids a full byte scan in
// the request path. | 规范响应头 key，只计算一次。Header.Set 每次调用都会规范化 key；这些 key
// 本身已规范，直接写 map 可避免请求路径上的整串字节扫描。
var (
	headerAllowOrigin      = "Access-Control-Allow-Origin"
	headerAllowCredentials = "Access-Control-Allow-Credentials"
	headerAllowMethods     = "Access-Control-Allow-Methods"
	headerAllowHeaders     = "Access-Control-Allow-Headers"
	headerMaxAge           = "Access-Control-Max-Age"
	headerExposeHeaders    = "Access-Control-Expose-Headers"
)

// corsPolicy is the immutable, precomputed form of CORSOptions. Both the YD router middleware
// and the native net/http middleware execute the same policy object. | corsPolicy 是
// CORSOptions 的不可变预计算形态。YD 路由中间件与原生 net/http 中间件执行同一份策略对象。
type corsPolicy struct {
	patterns      []originPattern
	allowMethods  string
	allowHeaders  string
	exposeHeaders string
	maxAge        string
	credentials   bool
	hasAny        bool
}

// newCORSPolicy normalizes o once at wiring time. | newCORSPolicy 在装配期把 o 归一化一次。
func newCORSPolicy(o CORSOptions) corsPolicy {
	p := corsPolicy{
		patterns:      make([]originPattern, 0, len(o.AllowOrigins)),
		allowMethods:  strings.Join(o.AllowMethods, ", "),
		allowHeaders:  strings.Join(o.AllowHeaders, ", "),
		exposeHeaders: strings.Join(o.ExposeHeaders, ", "),
		credentials:   o.AllowCredentials,
	}
	for _, raw := range o.AllowOrigins {
		parsed, ok := parseOriginPattern(raw)
		if !ok {
			continue
		}
		p.patterns = append(p.patterns, parsed)
		if parsed.any {
			p.hasAny = true
		}
	}
	if o.MaxAge > 0 {
		p.maxAge = strconv.FormatInt(int64(o.MaxAge/time.Second), 10)
	}
	return p
}

// decide reports whether origin is allowed and the value written to Access-Control-Allow-Origin.
// | decide 报告 origin 是否被允许，以及写入 Access-Control-Allow-Origin 的取值。
func (p *corsPolicy) decide(origin string) (bool, string) {
	// A wildcard policy is by far the most common configuration and needs no origin parsing at
	// all. A bare scheme check still rejects malformed headers, matching the strict parser
	// below. | 通配策略是最常见的配置，完全不需要解析来源。仅校验协议前缀即可拒绝畸形头部，
	// 与下方严格解析器保持一致。
	if i := strings.Index(origin, "://"); p.hasAny && i > 0 && i+3 < len(origin) {
		if p.credentials {
			return true, origin
		}
		return true, "*"
	}
	if p.hasAny {
		return false, ""
	}
	return matchOrigin(origin, p.patterns, p.credentials)
}

// setHeaders applies the policy to one response and reports whether the request is a preflight
// that must short-circuit the chain. | setHeaders 把策略应用到一次响应，并报告该请求是否为必须
// 短路调用链的预检。
func (p *corsPolicy) setHeaders(h http.Header, r *http.Request, origin string) (allowed, preflight bool) {
	if origin != "" {
		var value string
		allowed, value = p.decide(origin)
		if allowed {
			h[headerAllowOrigin] = []string{value}
			if value != "*" {
				// Caches must key on the origin whenever it is echoed. | 只要回显来源，缓存就必须按来源区分。
				reqlog.AppendVary(h, "Origin")
			}
			if p.credentials {
				h[headerAllowCredentials] = []string{"true"}
			}
		}
	}

	if r.Method != http.MethodOptions ||
		reqlog.HeaderValue(r.Header, "Access-Control-Request-Method") == "" {
		if allowed && p.exposeHeaders != "" {
			h[headerExposeHeaders] = []string{p.exposeHeaders}
		}
		return false, false
	}

	if allowed {
		methods := p.allowMethods
		if methods == "" {
			// Fall back to the requested method when no list is configured. | 未配置方法列表时回退到请求中的方法。
			methods = reqlog.HeaderValue(r.Header, "Access-Control-Request-Method")
		}
		if methods != "" {
			h[headerAllowMethods] = []string{methods}
		}
		headers := p.allowHeaders
		if headers == "" {
			headers = reqlog.HeaderValue(r.Header, "Access-Control-Request-Headers")
		}
		if headers != "" {
			h[headerAllowHeaders] = []string{headers}
		}
		if p.maxAge != "" {
			h[headerMaxAge] = []string{p.maxAge}
		}
	}
	return allowed, true
}

// CORS returns a middleware that applies the given cross-origin policy. | CORS 返回应用给定跨源策略的中间件。
// Three rules are enforced. | 该中间件强制三条硬规则。
// With AllowCredentials the response never carries "*" and echoes the concrete origin instead. | 开启 AllowCredentials 时绝不回 "*"，改为回显具体来源。
// Preflight requests — OPTIONS plus Access-Control-Request-Method — are answered with 204 and
// short-circuit the chain. | 预检请求（OPTIONS 且带 Access-Control-Request-Method）直接以 204 短路。
// An unmatched origin receives no CORS headers at all instead of an error. | 来源未匹配时不写任何 CORS 头，而不是返回错误。
func CORS(o CORSOptions) router.Middleware {
	policy := newCORSPolicy(o)
	return func(c *router.Ctx) {
		_, preflight := policy.setHeaders(
			c.Writer.Header(), c.Request, reqlog.HeaderValue(c.Request.Header, "Origin"))
		if preflight {
			c.Abort()
			_ = c.NoContent(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

// Middleware returns the native net/http form of CORS. | Middleware 返回 CORS 的原生
// net/http 形态。
//
// It executes the same immutable policy as CORS directly on net/http, so the native path pays
// neither the router adapter nor a second policy construction per request. | 它直接在 net/http
// 上执行与 CORS 相同的不可变策略，因此原生路径既不支付路由适配器开销，也不每请求重建策略。
func Middleware(o CORSOptions) func(http.Handler) http.Handler {
	policy := newCORSPolicy(o)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, preflight := policy.setHeaders(
				w.Header(), r, reqlog.HeaderValue(r.Header, "Origin"))
			if preflight {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
