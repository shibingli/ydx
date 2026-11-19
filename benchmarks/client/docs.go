// Package client contains HTTP client benchmarks that live outside the component
// module so github.com/shibingli/ydx/client never depends on benchmark-only code.
// | Package client 保存位于组件模块之外的 HTTP 客户端基准，使
// github.com/shibingli/ydx/client 不依赖基准专用代码。
//
// The benchmarks compare net/http, ydx/client, resty v2, req v3 and fasthttp on
// small GET, parallel GET, JSON POST, 1 MiB responses, short connections and TLS.
// Extended ydx-only benchmarks cover SSE parsing/forwarding, multipart uploads,
// guard DNS caching and coalescing. | 基准在小型 GET、并发 GET、JSON POST、
// 1 MiB 响应、短连接与 TLS 上对比 net/http、ydx/client、resty v2、req v3 与
// fasthttp。额外的 ydx 专项基准覆盖 SSE 解析/转发、multipart 上传、Guard DNS
// 缓存与请求合并。
//
// Run with | 运行方式：
//
//	cd benchmarks/client
//	GOWORK=off go test -bench . -benchmem -count=5 -timeout 20m
package client