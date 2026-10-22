// Package reqlog holds the request-logging machinery shared by the ydx middleware
// plugins: a pooled response-writer capture and the header helpers used on hot paths.
// | Package reqlog 保存 ydx 中间件插件共享的请求日志设施：池化的响应写入器捕获，以及热路径
// 使用的头部辅助函数。
//
// It is internal to github.com/shibingli/ydx/middleware and has no public compatibility
// promise. | 它属于 github.com/shibingli/ydx/middleware 的内部实现，不提供公开兼容承诺。
package reqlog
