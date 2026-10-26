# sse — Server-Sent Events 写入器与广播器

`github.com/shibingli/ydx/sse` 实现 W3C Server-Sent Events（`text/event-stream`）写入器与
进程内发布订阅广播器。它严格遵循事件流格式，并同时提供 YD 路由与原生 `net/http` 两种
端点形态。

| 项 | 值 |
|---|---|
| 模块路径 | `github.com/shibingli/ydx/sse` |
| 包名 | `sse` |
| Go 版本 | 1.27.3 |
| 许可证 | Apache-2.0 |

## 功能

- `NewWriter(w, Options)`：低层事件流写入器，支持 `WriteData`、`WriteEvent`、`Comment`、
  `Heartbeat`、`Close`。
- `NewBroker(BrokerOptions)`：进程内主题广播器，支持 `Publish`、`PublishHTML`、
  `Subscribe`、`Clients`、`Dropped`。
- `Handler(b, topic, Options)`：YD 路由处理器。
- `HTTPHandler(b, topic, Options)`：原生 `http.Handler`，共享同一服务核心。
- `NewWriterSet(b)`：追踪活跃事件流，退出时一次关闭全部流。
- `LastEventID` / `LastEventIDRequest`：读取客户端断线重连回传的 `Last-Event-ID`。

## 特性

- **严格事件格式**：字段行顺序固定为 `comment → id → event → retry → data`，事件以空行
  结束；`data` 可跨多行，值中的 CR / CRLF / LF 都会规整为独立数据行。
- **心跳保活**：`Options.Heartbeat > 0` 时周期性发送 `: ping` 注释帧。
- **非阻塞广播**：每个订阅者一个带缓冲通道；慢消费者通道满时丢帧并计数，发布方永不
  阻塞。
- **Last-Event-ID**：`Event.ID` 写入 `id:` 字段，客户端重连时可通过请求头回传。
- **可追踪关闭**：`WriterSet` 在 HTTP 服务器排空前关闭全部流，避免流式处理器拖住优雅退出。
- **零分配编码**：稳态编码路径复用帧缓冲，32 B / 4 KiB 数据事件均为 0 B/op、0 allocs/op。
- **双入口共享核心**：YD 与原生入口共享同一份事件流语义。

## 快速开始

### YD 路由

```go
package main

import (
	"net/http"
	"time"

	"github.com/shibingli/ydx/router"
	"github.com/shibingli/ydx/sse"
)

func main() {
	b := sse.NewBroker(sse.BrokerOptions{QueueSize: 64})
	set := sse.NewWriterSet(b)
	defer set.Shutdown()

	r := router.New()
	r.GET("/events", sse.Handler(b, "ticker", sse.Options{
		Heartbeat: 15 * time.Second,
		Tracker:   set,
	}))

	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for now := range t.C {
			b.Publish("ticker", sse.Event{
				ID:   now.Format(time.RFC3339Nano),
				Name: "tick",
				Data: []byte(now.Format(time.RFC3339)),
			})
		}
	}()

	_ = http.ListenAndServe(":8080", r)
}
```

### 原生 net/http

```go
mux := http.NewServeMux()
mux.Handle("/events", sse.HTTPHandler(b, "ticker", sse.Options{}))
```

自定义事件流：

```go
w, err := sse.NewWriter(rw, sse.Options{})
if err != nil {
	return err
}
defer func() { _ = w.Close() }()

_ = w.WriteEvent(sse.Event{
	ID:      "42",
	Comment: "progress",
	Data:    []byte("line 1\nline 2"),
})
```

## 应用场景

- **实时仪表盘**：指标、日志、任务进度推送。
- **通知中心**：站内信、告警、系统事件。
- **LLM 流式输出**：把增量 token 推给浏览器。
- **构建/部署进度**：长任务的阶段与日志流。
- **HTMX 局部刷新**：`PublishHTML` 推送可交换的 HTML 片段。

## 性能指标

基准模块：[`benchmarks/sse`](../benchmarks/sse/README.md)。参考环境为 AMD Ryzen
AI MAX+ 395、Go 1.27.3、Linux，`-count=5`、`-benchtime=500ms` 中位数。

| 场景 | ydx/sse | gin-contrib/sse | 手写 `fmt.Fprintf` |
|---|---:|---:|---:|
| 32 B data | **14.07 ns** | 47.51 ns | 33.61 ns |
| 4 KiB data | **63.69 ns** | 1.453 µs | 52.27 ns |
| 完整事件 | **152.0 ns** | 190.2 ns | 127.7 ns |

- 小事件比 gin-contrib 快约 3.4 倍，比手写快约 2.4 倍。
- 4 KiB 事件比 gin-contrib 快约 23 倍；手写基线不做 CR/LF 规整、字段顺序组装或帧缓冲，
  不是等价实现。
- 三个编码用例均为 0 B/op、0 allocs/op；gin-contrib 为 1–2 allocs/op。
- Broker 扇出：1 个订阅者 53.41 ns，64 个订阅者 1.962 µs（约 31 ns/订阅者），投递非阻塞。

> 基准使用丢弃 `ResponseWriter`，不包含真实网络 flush、TLS 或客户端消费成本；完整表格与
> 口径见基准 README。

## 第三方依赖与鸣谢

本模块没有第三方运行时依赖，只依赖 Go 标准库与 ydx 内部模块（`errs`、`router`）。

基准对比对象：[`gin-contrib/sse`](https://github.com/gin-contrib/sse)（MIT）与手写
`fmt.Fprintf` 基线，仅出现在 `benchmarks/sse`。

## 相关模块

- [`realtime`](../realtime/README.md)：传输无关的实时中枢，含 SSE 适配器。
- [`router`](../router/README.md)：路由与中间件。
- [`middleware/compress`](../middleware/compress/README.md)：默认跳过 SSE 响应。
- [`websocket`](../websocket/README.md)：双向实时传输。

## 许可证

Apache-2.0，见仓库根目录 [`LICENSE`](../LICENSE)。
