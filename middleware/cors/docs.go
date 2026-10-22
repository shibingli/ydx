// Package cors applies the given cross-origin policy. | Package cors 应用给定的跨源策略。
//
// Three rules are enforced: with AllowCredentials the response never carries "*" and echoes
// the concrete origin; preflight requests (OPTIONS plus Access-Control-Request-Method) are
// answered with 204 and short-circuit the chain; an unmatched origin receives no CORS
// headers at all instead of an error. | 强制三条硬规则：开启 AllowCredentials 时绝不回 "*"，
// 改为回显具体来源；预检请求（OPTIONS 且带 Access-Control-Request-Method）直接以 204 短路；
// 来源未匹配时不写任何 CORS 头，而不是返回错误。
//
// Both entry points share the same implementation: CORS returns a router.Middleware,
// Middleware returns the native net/http wrapper. | 两个入口共享同一份实现：CORS 返回
// router.Middleware，Middleware 返回原生 net/http 包装器。
//
// Typical usage | 典型用法：
//
//	r.Use(cors.CORS(cors.CORSOptions{AllowOrigins: []string{"*"}}))
//
//	// plain net/http | 原生 net/http
//	handler := cors.Middleware(cors.CORSOptions{AllowOrigins: []string{"*"}})(mux)
package cors
