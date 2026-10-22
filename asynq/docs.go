// Package asynq is the YunDev asynchronous task layer on top of github.com/hibiken/asynq. |
// Package asynq 是 YunDev 基于 github.com/hibiken/asynq 的异步任务层。
//
// Options and OptionsFromConfig describe one deployment (connection, weighted queues,
// concurrency, graceful-shutdown budget and retry policy); ParseQueues turns a
// "critical:3,default:2,low:1" string into a weight table. Registry is the declarative task table
// shared by clients and servers, mapping one task type to one Handler over a JSON Payload. Client
// enqueues tasks immediately, after a delay or at an instant and exposes the asynq Inspector;
// Server consumes tasks through a built-in chain that injects TaskContext/TraceID, logs each task
// and recovers handler panics. Logging goes through github.com/shibingli/ydx/log only. |
// Options 与 OptionsFromConfig 描述一套部署（连接、加权队列、并发度、优雅关闭预算与重试策略）；
// ParseQueues 把 "critical:3,default:2,low:1" 转为权重表。Registry 是客户端与服务端共享的声明式
// 任务表，把一种任务类型映射到以 JSON Payload 为入参的 Handler。Client 负责立即、延时或定时入队，
// 并暴露 asynq Inspector；Server 通过内置链消费任务：注入 TaskContext/TraceID、记录每条任务日志、
// 恢复处理器 panic。日志只经 github.com/shibingli/ydx/log。
//
// Native Go usage | 原生 Go 用法：
//
//	reg := asynq.NewRegistry()
//	reg.Register("mail:send", sendMail)
//	client, err := asynq.NewClient(asynq.RedisClientOpt{Addr: "127.0.0.1:6379"}, asynq.Options{})
//	if err != nil { return err }
//	_, err = client.Enqueue(ctx, "mail:send", payload)
//
// YD routing and HTTP are not involved; this module is infrastructure-only. |
// 本模块与 YD 路由、HTTP 无关，属于纯基础设施组件。
package asynq
