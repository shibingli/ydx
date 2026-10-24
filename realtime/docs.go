// Package realtime is the framework's transport-agnostic realtime hub: one
// publish path fans messages out to every local subscriber and, with a Redis
// backend, to subscribers on every node. | Package realtime 是框架与传输无关的实时
// 中枢：一条发布路径把消息扇出给全部本地订阅者，配置 Redis 后端后同时送达每个节点上的
// 订阅者。
//
// Design: | 设计：
//
//   - Single node is the nil-backend case: Publish fans out in-process without
//     any network hop. | 单机即后端为 nil 的形态：Publish 在进程内扇出，不经过网络。
//   - Multi-node adds a Backend. Every node publishes to the backend and
//     subscribes to the topics that have local subscribers; messages carrying
//     the local node id are dropped on arrival because they were already
//     delivered locally. | 多机形态增加 Backend。每个节点把消息发往后端，并只订阅本地
//     存在订阅者的主题；携带本节点 id 的消息在到达时被丢弃，因为它已在本地投递过。
//   - Live delivery is at-most-once with per-node ordering. Redis Pub/Sub is
//     not durable; callers that need replay keep a cursor in their own store.
//     A failed backend publish can be made durable with Options.Retry: the hub
//     enqueues the message (for example into asynq) and a worker later calls
//     PublishRemote, which only publishes and never fans out locally again. |
//     实时投递为至多一次并按节点保序。Redis Pub/Sub 不持久；需要重放的调用方自行保存游标。
//     后端发布失败可经 Options.Retry 变得持久：Hub 把消息入队（例如交给 asynq），工作器稍后调用
//     PublishRemote，后者只发布、绝不再本地扇出。
//   - Slow consumers never block a publisher: each subscription has a bounded
//     queue and a policy (drop the message, or close that subscription). |
//     慢消费者永不阻塞发布方：每个订阅者都有有界队列与策略（丢弃该消息，或关闭该订阅）。
//   - The hub knows nothing about WebSocket, SSE or WebTransport. A transport
//     adapts itself with a Sink, which keeps the dependency direction one-way. |
//     Hub 不认识 WebSocket、SSE 或 WebTransport；传输用 Sink 自行适配，依赖方向因此保持
//     单向。
//
// Typical usage | 典型用法：
//
//	hub := realtime.NewHub(realtime.Options{})
//	hub.Use(realtime.NewRedisBackend(rdb, realtime.RedisOptions{}))
//
//	sub, err := hub.Subscribe(r.Context(), "chat:42", func(msg realtime.Message) error {
//		return conn.WriteMessage(websocket.TextMessage, msg.Body)
//	})
//	defer sub.Close()
//	_ = hub.Publish(ctx, "chat:42", []byte("hello"))
package realtime
