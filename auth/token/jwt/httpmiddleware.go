package jwt

import (
	"context"
	"io"
	"net/http"
	"strings"

	"github.com/shibingli/ydx/errs"
)

// HTTPMiddlewareOptions configures HTTPMiddleware. | HTTPMiddlewareOptions 配置 HTTPMiddleware。
type HTTPMiddlewareOptions struct {
	// KeyFunc resolves the verification key; a nil KeyFunc fails every request. | KeyFunc
	// 解析校验密钥；为空时每个请求都失败。
	KeyFunc KeyFunc
	// ErrorHandler renders the failure; nil means 401 with a short plain-text body. | ErrorHandler
	// 负责输出失败响应；为空表示返回 401 与简短纯文本正文。
	ErrorHandler func(http.ResponseWriter, error)
	// TokenLookup selects where the token is read from; the accepted forms match Middleware. | TokenLookup
	// 指定 token 的读取位置；可用形式与 Middleware 一致。
	TokenLookup string
	// ParseOptions is forwarded to Parse verbatim. | ParseOptions 原样转发给 Parse。
	ParseOptions ParseOptions
}

// httpTokenKey is the private request-context key for the verified token. | httpTokenKey 是
// 已校验令牌在请求上下文中的私有键。
type httpTokenKey struct{}

// HTTPMiddleware verifies the token of a request for a plain net/http server. | HTTPMiddleware
// 为原生 net/http 服务端校验请求携带的令牌。
//
// It is the native counterpart of Middleware: TokenLookup accepts the same forms, failures are
// reported through errors.Is-compatible sentinels, and a successful token is stored in the
// request context for FromRequest. The YD path keeps its own lookup closures, so this adapter
// adds no overhead to router.Middleware. | 它是 Middleware 的原生对应物：TokenLookup 接受相同
// 的形式，失败通过可用 errors.Is 判定的哨兵上报，成功的令牌存入请求上下文供 FromRequest 读取。
// YD 路径保留自己的提取闭包，因此该适配器不会给 router.Middleware 增加开销。
func HTTPMiddleware(o HTTPMiddlewareOptions) func(http.Handler) http.Handler {
	lookup, lookupErr := parseTokenLookupRequest(o.TokenLookup)
	handle := o.ErrorHandler
	if handle == nil {
		handle = defaultHTTPErrorHandler
	}
	keyFn := o.KeyFunc
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if lookupErr != nil {
				handle(w, lookupErr)
				return
			}
			if keyFn == nil {
				handle(w, ErrNoKeyFunc)
				return
			}
			raw, ok := lookup(r)
			if !ok {
				handle(w, ErrTokenNotFound)
				return
			}
			tok, err := Parse(raw, keyFn, o.ParseOptions)
			if err != nil {
				handle(w, err)
				return
			}
			ctx := context.WithValue(r.Context(), httpTokenKey{}, tok)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// FromRequest returns the verified *Token stored by HTTPMiddleware. | FromRequest 返回
// HTTPMiddleware 存入的已校验 *Token。
func FromRequest(r *http.Request) (*Token, bool) {
	if r == nil {
		return nil, false
	}
	tok, ok := r.Context().Value(httpTokenKey{}).(*Token)
	return tok, ok && tok != nil
}

// parseTokenLookupRequest compiles a TokenLookup specification into an extractor over a
// plain http.Request. It deliberately mirrors parseTokenLookup instead of sharing a
// closure with it, so the YD hot path keeps its exact code. | parseTokenLookupRequest 把
// TokenLookup 配置编译成面向原生 http.Request 的提取器。它刻意与 parseTokenLookup 保持平行
// 实现而不是共享闭包，从而使 YD 热路径保持原有代码。
func parseTokenLookupRequest(spec string) (func(*http.Request) (string, bool), error) {
	if spec == "" {
		spec = DefaultTokenLookup
	}
	kind, rest := spec, ""
	if i := strings.IndexByte(spec, ':'); i >= 0 {
		kind, rest = spec[:i], spec[i+1:]
	}
	switch kind {
	case "header":
		name, prefix := rest, ""
		if i := strings.IndexByte(rest, ':'); i >= 0 {
			name, prefix = rest[:i], rest[i+1:]
		}
		if name == "" {
			return nil, errs.Detail(ErrBadTokenLookup, "empty header name | 头部名称为空")
		}
		return func(r *http.Request) (string, bool) {
			return headerToken(r.Header.Get(name), prefix)
		}, nil
	case "query":
		if rest == "" {
			return nil, errs.Detail(ErrBadTokenLookup, "empty query name | 查询参数名为空")
		}
		return func(r *http.Request) (string, bool) {
			return nonEmptyToken(r.URL.Query().Get(rest))
		}, nil
	case "cookie":
		if rest == "" {
			return nil, errs.Detail(ErrBadTokenLookup, "empty cookie name | Cookie 名为空")
		}
		return func(r *http.Request) (string, bool) {
			c, err := r.Cookie(rest)
			if err != nil {
				return "", false
			}
			return nonEmptyToken(c.Value)
		}, nil
	}
	return func(r *http.Request) (string, bool) {
		return headerToken(r.Header.Get(spec), "")
	}, nil
}

// defaultHTTPErrorHandler writes a 401 with a short plain-text body and never echoes the
// failure reason. | defaultHTTPErrorHandler 写出 401 与简短纯文本正文，绝不回显失败原因。
func defaultHTTPErrorHandler(w http.ResponseWriter, _ error) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = io.WriteString(w, "unauthorized | 未授权")
}
