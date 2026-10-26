# webtransport — HTTP/3 WebTransport 服务端与客户端

`github.com/shibingli/ydx/webtransport` 是框架的 WebTransport 层：HTTP/3 上的 RFC 9297
会话，复用服务 HTTP/3 的同一条 QUIC 监听。它在 `*http3.Server` 之上持有一个
`webtransport.Server`，使同一个 UDP 端口同时服务普通 HTTP/3 请求、RFC 9220 WebSocket 与
WebTransport 会话。

| 项 | 值 |
|---|---|
| 模块路径 | `github.com/shibingli/ydx/webtransport` |
| 包名 | `webtransport` |
| Go 版本 | 1.27.3 |
| 许可证 | Apache-2.0 |
| 默认消息上限 | 1 MiB（`DefaultMaxMessageSize`） |

## 功能

- `New(Options)` / `NewWithH3(h3, Options)`：构造 WebTransport 服务端。
- `Server.H3()`：取得底层 `*http3.Server`，由其承载普通 HTTP/3 处理器。
- `Server.Upgrade(w, r)`：把 WebTransport CONNECT 升级为 `*Session`。
- `Server.Serve(conn)`：在 UDP 连接上提供服务。
- `Session.Accept(ctx)` / `Session.Open(ctx)`：接受/打开带帧消息 `Channel`。
- `Channel.Send` / `Receive` / `ReceiveAppend` / `Ping`：长度前缀消息帧。
- `Session.SendDatagram` / `ReceiveDatagram`：不可靠数据报。
- `SessionSet`：追踪活跃会话，退出时一次终止全部会话。
- `Dial(ctx, url, DialOptions)`：客户端会话。
- `Tracker`：自定义会话生命周期追踪。

## 特性

- **单端口多协议**：同一 QUIC 监听承载 HTTP/3、RFC 9220 WebSocket 与 WebTransport。
- **带帧消息通道**：首条双向流上提供带长度前缀的消息 Channel，`Send` 可并发，
  `Receive` 不可与自身并发。
- **会话追踪**：`SessionSet` 让生命周期持有者在关闭时一次终止全部会话。
- **数据报**：保留不可靠、无序的数据报入口，适合实时位置/游戏状态。
- **额外流**：`Open` / `Accept` 保留任意数量双向流的入口。
- **职责边界**：不实现 HTTP/3 本身、不拥有 TLS 证书、不决定路由；应用注册普通处理器，
  在请求为 WebTransport CONNECT 时调用 `Upgrade`。
- **优雅关闭**：`Server.Close` 关闭监听与会话；`SessionSet` 负责业务侧生命周期。

## 快速开始

```go
package main

import (
	"crypto/tls"
	"net"
	"net/http"

	"github.com/shibingli/ydx/webtransport"
)

func main() {
	tlsConf := &tls.Config{ /* 证书与 ALPN h3 */ }

	srv, err := webtransport.New(webtransport.Options{TLSConfig: tlsConf})
	if err != nil {
		return
	}
	defer func() { _ = srv.Close() }()

	srv.H3().Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, err := srv.Upgrade(w, r)
		if err != nil {
			return
		}
		ch, err := sess.Accept(r.Context())
		if err != nil {
			return
		}
		defer func() { _ = ch.Close() }()

		for {
			msg, err := ch.Receive()
			if err != nil {
				return
			}
			if err := ch.Send(msg); err != nil {
				return
			}
		}
	})

	udp, err := net.ListenPacket("udp", ":443")
	if err != nil {
		return
	}
	if err := srv.Serve(udp); err != nil {
		return
	}
}
```

客户端：

```go
sess, err := webtransport.Dial(ctx, "https://example.com/echo", webtransport.DialOptions{})
if err != nil {
	return err
}
defer func() { _ = sess.Close(0, "") }()

ch, err := sess.Open(ctx)
if err != nil {
	return err
}
_ = ch.Send([]byte("hello"))
```

## 应用场景

- **实时游戏**：低延迟输入、状态同步、数据报。
- **音视频/媒体**：双向流与不可靠数据报。
- **协同编辑/白板**：多路双向流，避免队头阻塞。
- **高频行情**：QUIC 上的低延迟推送。
- **与 WebSocket 共存**：同一 UDP 端口按协议升级分流。

## 性能指标

本模块没有独立基准；性能由 QUIC/HTTP/3 与网络条件决定：

- 每条消息经带长度前缀的帧通道传输，避免调用方自行处理消息边界。
- `Send` 可并发，`Receive` 单协程；多路流之间没有 TCP 队头阻塞。
- 数据报不可靠、无序，适合“最新状态优先”的场景；需要可靠传输时使用流。
- `DefaultMaxMessageSize` 为 1 MiB；超过上限的消息应分片或改用额外流。
- 握手、TLS 与 QUIC 拥塞控制的开销远大于帧编解码；请在目标网络下压测。

> 需要吞吐/延迟数字时，应以真实 QUIC 实现、TLS 配置与网络 RTT 为基准；本模块不实现
> HTTP/3 本身。

## 第三方依赖与鸣谢

| 依赖 | 版本 | 许可证 | 用途 |
|---|---|---|---|
| [`quic-go/quic-go`](https://github.com/quic-go/quic-go) | v0.64.1 | MIT | QUIC 与 HTTP/3 传输 |
| [`quic-go/webtransport-go`](https://github.com/quic-go/webtransport-go) | v0.13.0 | MIT | WebTransport over HTTP/3 协议实现 |

仓库内依赖：`errs`。

## 相关模块

- [`protocol`](../protocol/README.md)：Extended CONNECT 判定。
- [`websocket`](../websocket/README.md)：HTTP/1.1、HTTP/2、HTTP/3 WebSocket。
- [`realtime`](../realtime/README.md)：传输无关的实时中枢。
- [`router`](../router/README.md)：HTTP 路由与中间件。

## 许可证

Apache-2.0，见仓库根目录 [`LICENSE`](../LICENSE)。
