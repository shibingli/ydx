# realtime — 传输无关的实时中枢

`github.com/shibingli/ydx/realtime` 是框架与传输无关的实时中枢：一条发布路径把消息扇出
给全部本地订阅者，配置 Redis 后端后同时送达每个节点上的订阅者。Hub 不认识 WebSocket、
SSE 或 WebTransport；传输用 `Sink` 自行适配，依赖方向保持单向。

| 项 | 值 |
|---|---|
| 模块路径 | `github.com/shibingli/ydx/realtime` |
| 包名 | `realtime` |
| Go 版本 | 1.27.3 |
| 许可证 | Apache-2.0 |
| 默认队列 | 256（`DefaultQueueSize`） |

## 功能

- `NewHub(Options)`：构造实时中枢。
- `Hub.Subscribe(ctx, topic, sink)`：订阅主题；`Sink` 把消息写到一条传输连接。
- `Hub.Publish(ctx, topic, body)`：本地扇出；配置后端后同时跨节点发布。
- `Hub.PublishRemote(ctx, msg)`：只发布到后端，不再本地扇出（供重试队列使用）。
- `Hub.Use(backend)`：挂载 `Backend`。
- `NewRedisBackend(client, RedisOptions)`：Redis Pub/Sub 多机后端。
- `Hub.Stats` / `SubscriberCount` / `NodeID`。
- `OptionsFromConfig` / `RedisOptionsFromConfig`：配置驱动。
- `SlowPolicy`：慢消费者策略（丢弃或关闭订阅）。
- `RetryQueue`：后端发布失败时的持久重试入口。
- 子包 `realtime/adapter`：SSE / WebSocket / WebTransport 适配器。

## 特性

- **单机零网络**：后端为 nil 时，`Publish` 在进程内扇出，不经过网络。
- **多机**：每个节点发布到后端，并只订阅本地存在订阅者的主题；携带本节点 id 的消息到达
  时被丢弃，因为已在本地投递。
- **至多一次、按节点保序**：Redis Pub/Sub 不持久；需要重放的调用方自行保存游标。
- **可持久化失败发布**：`Options.Retry` 接收后端发布失败的消息，交给 asynq 等持久队列，
  工作器稍后调用 `PublishRemote`（只发布、不重复本地扇出）。
- **慢消费者隔离**：每个订阅有有界队列与策略；慢消费者永不阻塞发布方。
- **稳定节点身份**：空 `NodeID` 经 `nodeid` 解析持久身份文件，没有文件时使用随机每进程 id。
- **授权钩子**：`Options.Authorize` 在订阅时决定是否允许该主题。
- **传输无关**：Hub 只处理主题与字节；SSE/WS/WT 适配器在 `realtime/adapter`。

## 快速开始

```go
package main

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
	"github.com/shibingli/ydx/realtime"
	"github.com/shibingli/ydx/websocket"
)

func main() {
	hub := realtime.NewHub(realtime.Options{
		NodeID:    "node-1",
		QueueSize: 256,
		SlowPolicy: realtime.SlowDrop,
	})

	rdb := redis.NewUniversalClient(&redis.UniversalOptions{Addrs: []string{"127.0.0.1:6379"}})
	hub.Use(realtime.NewRedisBackend(rdb, realtime.RedisOptions{}))

	ctx := context.Background()
	conn, err := websocket.Dial(ctx, "ws://127.0.0.1:8080/ws", websocket.DialOptions{})
	if err != nil {
		return
	}
	defer func() { _ = conn.Close(websocket.CloseNormalClosure, "") }()

	sub, err := hub.Subscribe(ctx, "chat:42", func(msg realtime.Message) error {
		return conn.WriteMessage(websocket.TextMessage, msg.Body)
	})
	if err != nil {
		return
	}
	defer sub.Close()

	if err := hub.Publish(ctx, "chat:42", []byte("hello")); err != nil {
		return
	}
	fmt.Println(hub.SubscriberCount("chat:42"))
}
```

持久化失败发布：

```go
hub := realtime.NewHub(realtime.Options{
	Retry: retryQueue, // 实现 RetryQueue，把消息入队到 asynq
})
// 工作器稍后：
_ = hub.PublishRemote(ctx, msg)
```

## 应用场景

- **聊天室/协作**：按主题扇出到 SSE/WS/WT 连接。
- **多机通知**：Redis 后端让所有节点上的订阅者收到同一消息。
- **实时仪表盘**：服务端事件推送到多个浏览器。
- **可靠广播兜底**：后端发布失败交给 asynq 重试。
- **慢消费者治理**：有界队列 + 丢弃/关闭策略，保护发布方。

## 性能指标

本模块没有独立基准；成本结构：

- 单机 `Publish` 是 O(本地订阅者数) 的内存扇出，无网络往返。
- 多机 `Publish` 先本地扇出，再向 Redis 发布一次；每个节点只订阅有本地订阅者的主题。
- 每个订阅有有界队列（默认 256）；满时按 `SlowPolicy` 丢弃或关闭，发布方不阻塞。
- `Sink` 的写连接成本由传输决定（WebSocket 批量写、SSE 帧写、WebTransport 流写）。
- 后端失败进入 `RetryQueue` 时只增加一次入队成本，不在发布路径重试。
- `Authorize` 只在订阅时调用，不在每条消息上调用。

> 扇出吞吐取决于订阅者数量、传输写成本与 Redis RTT；请在目标部署上压测。

## 第三方依赖与鸣谢

| 依赖 | 版本 | 许可证 | 用途 |
|---|---|---|---|
| [`redis/go-redis/v9`](https://github.com/redis/go-redis) | v9.23.0 | BSD-2-Clause | Redis Pub/Sub 多机后端 |
| [`spf13/afero`](https://github.com/spf13/afero) | v1.15.0 | Apache-2.0 | 配置来源文件系统（经 config） |

测试使用 [`alicebob/miniredis/v2`](https://github.com/alicebob/miniredis)（MIT）。

仓库内依赖：`afs`、`config`、`errs`、`nodeid`、`sse`、`websocket`、`webtransport`。

## 相关模块

- [`sse`](../sse/README.md)、[`websocket`](../websocket/README.md)、
  [`webtransport`](../webtransport/README.md)：传输适配器。
- [`nodeid`](../nodeid/README.md)：稳定节点身份。
- [`redis`](../redis/README.md)：Redis 客户端装配。
- [`asynq`](../asynq/README.md)：失败广播的持久重试队列。

## 许可证

Apache-2.0，见仓库根目录 [`LICENSE`](../LICENSE)。
