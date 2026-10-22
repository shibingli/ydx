// Package reqlog holds the request-logging machinery shared by the ydx middleware
// plugins: a pooled response-writer capture and the header helpers used on hot paths.
// | Package reqlog 保存 ydx 中间件插件共享的请求日志设施：池化的响应写入器捕获，以及热路径
// 使用的头部辅助函数。
//
// It is published as github.com/shibingli/ydx/middleware/reqlog so every plugin module can
// share one implementation; its API is a shared implementation detail rather than a
// stability promise. | 它以 github.com/shibingli/ydx/middleware/reqlog 发布，供各插件模块共享
// 同一份实现；其 API 属于共享实现细节，不构成稳定性承诺。
package reqlog
