package client

import (
	"net/http"
	"strings"

	"github.com/shibingli/ydx/errs"
)

// cacheKey builds the logical cache key for a request. | cacheKey 为请求构建逻辑缓存键。
func cacheKey(req *http.Request, rule *Rule, policy *CachePolicy) (key string, err error) {
	if req == nil || req.URL == nil {
		return "", ErrInvalidRequest
	}
	if policy != nil && policy.KeyFunc != nil {
		defer func() {
			if recovered := recover(); recovered != nil {
				key = ""
				err = errs.Detail(ErrHookPanic, "cache key panic: %v | 缓存键 panic：%v", recovered, recovered)
			}
		}()
		return policy.KeyFunc(req), nil
	}
	var builder strings.Builder
	builder.WriteString(req.Method)
	builder.WriteByte(0)
	builder.WriteString(req.URL.Scheme)
	builder.WriteString("://")
	builder.WriteString(req.URL.Host)
	builder.WriteString(req.URL.EscapedPath())
	if req.URL.RawQuery != "" {
		builder.WriteByte('?')
		builder.WriteString(req.URL.RawQuery)
	}
	builder.WriteByte(0)
	builder.WriteString(req.Host)
	builder.WriteByte(0)
	if rule != nil {
		builder.WriteString(rule.Name)
	}
	builder.WriteByte(0)
	builder.WriteString(headerValue(req.Header, "Accept-Encoding"))
	if policy != nil && policy.AllowSensitive {
		for _, name := range [...]string{"Authorization", "Cookie", "Proxy-Authorization"} {
			builder.WriteByte(0)
			builder.WriteString(name)
			builder.WriteByte('=')
			builder.WriteString(headerValue(req.Header, name))
		}
	}
	if policy != nil {
		for _, name := range policy.Vary {
			builder.WriteByte(0)
			canonical := http.CanonicalHeaderKey(name)
			builder.WriteString(canonical)
			builder.WriteByte('=')
			builder.WriteString(headerValue(req.Header, canonical))
		}
	}
	return builder.String(), nil
}
