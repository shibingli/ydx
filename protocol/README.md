# protocol — HTTP 协议判定

`github.com/shibingli/ydx/protocol` 提供路由器、WebSocket 层与中间件共用的 HTTP 协议
判定，重点是 RFC 8441 / RFC 9220 的 Extended CONNECT。把这些规则集中在一处，避免同一套
判断出现多份实现并逐渐漂移。

| 项 | 值 |
|---|---|
| 模块路径 | `github.com/shibingli/ydx/protocol` |
| 包名 | `protocol` |
| Go 版本 | 1.27.3 |
| 许可证 | Apache-2.0 |

## 功能

- `IsExtendedConnect(r)`：判断是否为 RFC 8441（HTTP/2）或 RFC 9220（HTTP/3）的
  WebSocket Extended CONNECT。
- `IsExtendedConnectProtocol(r, name)`：判断是否为指定协议 token 的 Extended CONNECT，
  例如 `"websocket"` 或 `"webtransport"`。
- `IsTunnelConnect(r)`：判断是否为任意 Extended CONNECT，不区分协议 token。
- `ExtendedConnectProtocol(r)`：返回 `:protocol` token，非 Extended CONNECT 返回空串。
- `H2ExtendedConnectEnabled()`：判断进程是否以 `GODEBUG=http2xconnect=1` 启动。
- `MergeGODEBUG(godebug, setting)`：在需要时安全追加 GODEBUG 设置。

## 特性

- **同时识别 HTTP/2 与 HTTP/3**：HTTP/2 从 `:protocol` 伪头读取 token；quic-go 的
  HTTP/3 服务端会移除该头，把 token 放进 `Request.Proto`，本包同时处理两种形态。
- **只认 CONNECT**：普通 GET/POST 即使带有 `:protocol` 头也不会被误判。
- **大小写不敏感**：协议 token 按 `strings.EqualFold` 比较，符合 HTTP 语义。
- **普通 HTTP/3 不误判**：请求的 `Proto` 为 `HTTP/3.0` 时不会被当成 Extended CONNECT。
- **与标准库一致**：`H2ExtendedConnectEnabled` 复刻 `net/http` HTTP/2 包在 `init`
  阶段读取 `GODEBUG` 的行为。
- **零分配结果**：只做请求头/字段判断，不解析 body、不构造 URL。

## 快速开始

```go
package main

import (
	"net/http"

	"github.com/shibingli/ydx/protocol"
)

func handler(w http.ResponseWriter, r *http.Request) {
	switch {
	case protocol.IsExtendedConnect(r):
		// RFC 8441/9220 WebSocket over HTTP/2 or HTTP/3.
	case protocol.IsExtendedConnectProtocol(r, "webtransport"):
		// WebTransport over HTTP/3.
	case protocol.IsTunnelConnect(r):
		// 其它 Extended CONNECT 隧道。
	default:
		http.NotFound(w, r)
	}
}
```

在启动 HTTP/2 服务前确保 GODEBUG 设置生效：

```go
if !protocol.H2ExtendedConnectEnabled() {
	// 通过环境变量或启动参数设置 GODEBUG=http2xconnect=1 后再启动进程。
}
```

## 应用场景

- **WebSocket over HTTP/2/3**：服务器在 Extended CONNECT 请求上执行 WebSocket 握手。
- **WebTransport**：识别 `:protocol = webtransport` 的 HTTP/3 会话。
- **路由器隧道分发**：把 Extended CONNECT 送到 GET 路由，普通 CONNECT 保持独立方法。
- **反向代理/网关**：判断是否允许升级或隧道，而不解析完整请求体。
- **GODEBUG 自检**：启动期确认 HTTP/2 Extended CONNECT 是否被标准库通告。

## 性能指标

本模块没有独立基准；每个函数都是 O(1) 的请求属性判断：

- `ExtendedConnectProtocol` 只读取 `Request.Method`、`:protocol` 头与 `Request.Proto`。
- `IsExtendedConnect` / `IsExtendedConnectProtocol` 在 token 上做一次大小写不敏感比较。
- `IsTunnelConnect` 只在 token 非空时返回 true。
- `H2ExtendedConnectEnabled` 每次调用读取 `GODEBUG` 环境变量；建议在启动期调用，不要放在
  逐请求热路径。
- 所有函数都不分配结果切片，也不读取请求体。

> 实际上限由 `net/http` 头读取与字符串比较决定；在路由器分发成本中可忽略。

## 第三方依赖与鸣谢

本模块只依赖 Go 标准库，没有第三方运行时依赖。

## 相关模块

- [`router`](../router/README.md)：使用 `IsTunnelConnect` 分发 Extended CONNECT。
- [`websocket`](../websocket/README.md)：HTTP/2/3 WebSocket 升级。
- [`webtransport`](../webtransport/README.md)：HTTP/3 WebTransport 会话。

## 许可证

Apache-2.0，见仓库根目录 [`LICENSE`](../LICENSE)。
