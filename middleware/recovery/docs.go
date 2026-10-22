// Package recovery catches panics raised by downstream handlers, logs the panic value and
// goroutine stack, aborts the remaining chain and writes a bare 500 response. | Package
// recovery 捕获下游处理器 panic，记录 panic 值与 goroutine 调用栈，终止链上剩余处理器，并写出
// 一个不含内部细节的 500 响应。
//
// When the response header has already been written the 500 is skipped, so a response that
// already started stays consistent. | 若响应头已写出则跳过 500，保证已经开始输出的响应不被破坏。
//
// Both entry points share the same implementation: Recover returns a router.Middleware,
// Middleware returns the native net/http wrapper. | 两个入口共享同一份实现：Recover 返回
// router.Middleware，Middleware 返回原生 net/http 包装器。
//
// Typical usage | 典型用法：
//
//	r.Use(recovery.Recover(logger))
//
//	// plain net/http | 原生 net/http
//	handler := recovery.Middleware(logger)(mux)
package recovery
