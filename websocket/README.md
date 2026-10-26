# websocket — RFC 6455 / 7692 / 8441 / 9220 WebSocket

`github.com/shibingli/ydx/websocket` 是完整的 WebSocket 实现，覆盖 RFC 6455 核心协议、
RFC 7692 permessage-deflate、RFC 7936 子协议规则、RFC 8441 HTTP/2 Extended CONNECT 与
RFC 9220 HTTP/3 Extended CONNECT。升级核心本身是原生 `net/http`，YD 路由只是入口之一。

| 项 | 值 |
|---|---|
| 模块路径 | `github.com/shibingli/ydx/websocket` |
| 包名 | `websocket` |
| Go 版本 | 1.27.3 |
| 许可证 | Apache-2.0 |

## 功能

- `Upgrade(w, r, Options)` / `Dial(ctx, url, DialOptions)`：服务端与客户端握手。
- `Conn`：消息读写、控制帧、关闭码、子协议、压缩开关、地址与底层连接。
  - `ReadMessage` / `NextReader` / `WriteMessage` / `WriteMessageBuffered` / `WriteBatch` /
    `Flush`。
- `Message`：`WriteBatch` 使用的完整消息（`Op` + `Payload`）。
- `ConnSet`：默认的进程内连接追踪器，支持一次关闭全部连接。
- `HtmxHandler` / `HtmxHTTPHandler`：htmx 读循环的 YD / 原生入口。
- `BufferedRead`：读取提示，帮助合并写出。
- `EnableWriteCompression`：permessage-deflate。
- `Tracker`：自定义连接生命周期追踪。
- `MessageReader`：分片消息流式读取。

## 特性

- **标准覆盖**：
  - RFC 6455：握手、帧、掩码、分片、控制帧与关闭码。
  - RFC 7692：两端可选的 permessage-deflate；服务端必须显式开启。
  - RFC 7936：子协议名按大小写敏感比较。
  - RFC 8441 / 9220：HTTP/2 / HTTP/3 Extended CONNECT。
- **传输自适应**：HTTP/1.1 通过 `http.Hijacker` 升级；HTTP/2（含 h2c）与 HTTP/3 使用
  Extended CONNECT，并把请求流适配为 `net.Conn`。
- **零拷贝写**：大于写缓冲的帧经 `net.Buffers` 一次 `writev` 发出，不复制载荷；小帧
  合并进写缓冲，一次传输层写。
- **批量写**：`WriteBatch` 把多条消息追加后一次 `Flush`，为广播/流水线省掉每条消息一次
  系统调用。
- **自动控制帧**：ping/pong/close 由读路径自动应答，调用方无需干预。
- **并发契约明确**：一个读协程 + 一个写协程；多个写协程由内部互斥锁串行化；
  `ReadMessage` 返回的切片在下一次读操作前有效。
- **连接追踪**：`ConnSet` 在关闭时遍历快照，不持锁写连接，慢对端不会阻塞其它连接关闭。
- **自动缓冲调优**：读写缓冲与单条消息上限默认由 `sysinfo` 按 CPU/内存推导。

## 快速开始

### YD 路由（htmx）

```go
package main

import (
	"net/http"

	"github.com/shibingli/ydx/router"
	"github.com/shibingli/ydx/websocket"
)

func main() {
	r := router.New()
	r.GET("/ws", websocket.HtmxHandler(websocket.HtmxOptions{
		OnMessage: func(c *websocket.Conn, m websocket.HtmxMessage) {
			_ = c.WriteHtmxFragment("#log", "beforeend", "<div>hello</div>")
		},
	}))
	_ = http.ListenAndServe(":8080", r)
}
```

### 原生 net/http

```go
mux := http.NewServeMux()
mux.Handle("/ws", websocket.HtmxHTTPHandler(websocket.HtmxOptions{}))
```

### 低层连接

```go
func echo(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Upgrade(w, r, websocket.Options{})
	if err != nil {
		return
	}
	defer func() { _ = conn.Close(websocket.CloseNormalClosure, "") }()

	for {
		op, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		if err := conn.WriteMessage(op, data); err != nil {
			return
		}
	}
}
```

批量写：

```go
msgs := []websocket.Message{
	{Op: websocket.TextMessage, Payload: []byte("a")},
	{Op: websocket.TextMessage, Payload: []byte("b")},
}
if err := conn.WriteBatch(msgs); err != nil {
	return err
}
```

## 应用场景

- **聊天/协作**：双向消息、低延迟广播、批量写。
- **实时游戏/行情**：HTTP/3 与批量帧。
- **htmx 局部刷新**：`HtmxHandler` 内置读循环与片段写出。
- **服务端推送**：与 `realtime` 的 `Sink` 适配器组合。
- **跨 HTTP 版本部署**：同一处理器服务 HTTP/1.1、HTTP/2 与 HTTP/3 客户端。
- **优雅退出**：`ConnSet` 在服务器排空前关闭全部连接。

## 性能指标

基准模块：[`benchmarks/websocket`](../benchmarks/websocket/README.md)。参考环境为
AMD Ryzen AI MAX+ 395、Go 1.27.3、Linux 回环，`-count=5`、`-benchtime=500ms` 中位数。

| 场景 | ydx/websocket | gorilla | coder | gobwas | gws |
|---|---:|---:|---:|---:|---:|
| 32 B 回显 | **4.068 µs** | 4.257 µs | 5.589 µs | 4.343 µs | 6.463 µs |
| 1 KiB 回显 | **4.276 µs** | 4.428 µs | 5.787 µs | 4.695 µs | 7.002 µs |
| 64 KiB 回显 | **16.59 µs** | 18.58 µs | 38.61 µs | 22.46 µs | 18.25 µs |
| 并发回显 | 2.301 µs（readahead **1.413**） | 2.331 µs | 2.385 µs | 2.333 µs | **2.003 µs** |
| 批量 16×1 KiB | **5.130 µs** | 27.73 µs | 19.26 µs | — | — |
| 批量 64×1 KiB | **14.06 µs** | 124.3 µs | 73.74 µs | — | — |

- 回显在 32 B–64 KiB 全部尺寸上最快；32 B 领先 gorilla 4%，64 KiB 领先 gorilla 11%。
- 批量写 16×/64× 分别比 coder 快 3.8×/5.2×、比 gorilla 快 5.4×/8.8×。
- 所有回显与批量用例稳态为 0 B/op、0 allocs/op；gorilla 为 4–6 allocs。
- 并发回显使用 `BufferedRead` 合并写出后为 1.413 µs，反超全部实现 30%–41%。

> 所有连接为本机回环，绝对微秒数受回环栈、`TCP_NODELAY` 与调度影响；完整表格与口径见
> 基准 README。

## 第三方依赖与鸣谢

| 依赖 | 版本 | 许可证 | 用途 |
|---|---|---|---|
| [`klauspost/compress`](https://github.com/klauspost/compress) | v1.20.3 | BSD-3-Clause | permessage-deflate 的 flate 实现 |

测试/互操作验证使用 [`coder/websocket`](https://github.com/coder/websocket)（ISC）、
[`quic-go/quic-go`](https://github.com/quic-go/quic-go)（MIT，HTTP/3 集成测试）与
`golang.org/x/net`（BSD-3-Clause，HTTP/2 测试）。

基准对比对象：[`gorilla/websocket`](https://github.com/gorilla/websocket)、
[`coder/websocket`](https://github.com/coder/websocket)、
[`gobwas/ws`](https://github.com/gobwas/ws) 与
[`lxzan/gws`](https://github.com/lxzan/gws)，仅出现在 `benchmarks/websocket`。

仓库内依赖：`base64`、`errs`、`json`、`log`、`protocol`、`regexpx`、`router`、`sysinfo`。

## 相关模块

- [`protocol`](../protocol/README.md)：Extended CONNECT 判定。
- [`router`](../router/README.md)：路由与中间件。
- [`realtime`](../realtime/README.md)：传输无关的实时中枢。
- [`webtransport`](../webtransport/README.md)：HTTP/3 WebTransport。
- [`sse`](../sse/README.md)：单向服务端推送。

## 许可证

Apache-2.0，见仓库根目录 [`LICENSE`](../LICENSE)。
