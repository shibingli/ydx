// Package asyncafter moves work that does not participate in response generation off the
// request path. | Package asyncafter 把不参与响应生成的工作从请求路径上摘下来。
//
// The narrow contract: the middleware chain itself cannot run in parallel because every
// middleware shares one http.ResponseWriter, so the safe parallel axis is after the response.
// A finished request is copied into a value Record and handed to a worker pool that never
// sees the writer or the context. | 契约刻意保持狭窄：中间件链共享同一个 http.ResponseWriter，
// 因此链本身不能并行；安全的并行轴在响应之后。已完成的请求被复制成 Record 值并交给 worker 池，
// worker 永远看不到写入器或上下文。
//
// AccessLogAsync captures status and bytes with the shared reqlog capture and submits a
// Record; NewAsyncAfter owns the processing side. Middleware is the native net/http wrapper. |
// AccessLogAsync 用共享的 reqlog 捕获记录状态码与字节数并提交 Record；NewAsyncAfter 拥有处理侧。
// Middleware 是原生 net/http 包装器。
//
// Typical usage | 典型用法：
//
//	after := asyncafter.NewAsyncAfter(asyncafter.AsyncOptions{
//		Handler: asyncafter.AccessLogHandler(logger),
//	})
//	r.Use(requestid.RequestID(""), asyncafter.AccessLogAsync(logger, after))
//
//	// plain net/http | 原生 net/http
//	handler := asyncafter.Middleware(logger, after)(mux)
package asyncafter
