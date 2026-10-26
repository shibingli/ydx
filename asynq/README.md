# asynq — 异步任务层

`github.com/shibingli/ydx/asynq` 是 YunDev 基于
[`hibiken/asynq`](https://github.com/hibiken/asynq) 的异步任务层。它把连接、加权队列、
并发度、优雅关闭与重试策略收敛为 `Options`，并用声明式 `Registry` 统一客户端与服务端的
任务类型。

| 项 | 值 |
|---|---|
| 模块路径 | `github.com/shibingli/ydx/asynq` |
| 包名 | `asynq` |
| Go 版本 | 1.27.3 |
| 许可证 | Apache-2.0 |

## 功能

- `Options` / `OptionsFromConfig`：描述一套部署的连接、加权队列、并发度、优雅关闭预算与
  重试策略。
- `ParseQueues`：把 `"critical:3,default:2,low:1"` 解析为权重表。
- `Registry`：声明式任务表，把任务类型映射到以 JSON `Payload` 为入参的 `Handler`。
- `Client`：立即、延时或定时入队，并暴露 asynq Inspector。
- `Server`：消费任务，内置 TaskContext / TraceID 注入、逐任务日志与 panic 恢复。
- `ExponentialBackoff`：指数退避重试策略。
- `WithTraceID` / `TraceIDFrom`、`LoggerFrom` / `FromContext`：在任务上下文传递追踪与
  日志器。

## 特性

- **声明式注册**：客户端与服务端共享同一张 `Registry`，任务类型与处理器不会漂移。
- **加权队列**：关键任务优先消费，低优先级队列按权重分配。
- **JSON Payload**：任务载荷统一为 `Payload map[string]any`，经 `ydx/json` 编解码。
- **内置中间件链**：注入 `TaskContext` / TraceID、记录每条任务日志、恢复处理器 panic。
- **统一日志**：只经 `github.com/shibingli/ydx/log`，不引入 zap/zerolog/logrus。
- **优雅关闭**：`Options` 提供关闭预算；服务端停止时等待在途任务。
- **重试与退避**：支持固定/指数退避，失败任务按 asynq 语义重试。
- **配置驱动**：`OptionsFromConfig` 读取任务队列配置段。

## 快速开始

```go
package main

import (
	"context"
	"fmt"

	"github.com/shibingli/ydx/asynq"
	"github.com/shibingli/ydx/json"
	asynqio "github.com/hibiken/asynq"
)

type MailPayload struct {
	To      string `json:"to"`
	Subject string `json:"subject"`
}

func sendMail(ctx context.Context, p asynq.Payload) error {
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	var mail MailPayload
	if err := json.Unmarshal(raw, &mail); err != nil {
		return err
	}
	fmt.Println("send mail to", mail.To, asynq.TraceIDFrom(ctx))
	return nil
}

func main() {
	reg := asynq.NewRegistry()
	reg.Register("mail:send", sendMail)

	client, err := asynq.NewClient(asynqio.RedisClientOpt{Addr: "127.0.0.1:6379"}, asynq.Options{})
	if err != nil {
		return
	}
	defer func() { _ = client.Close() }()

	_, err = client.Enqueue(context.Background(), "mail:send", MailPayload{
		To: "user@example.com", Subject: "hello",
	})
	if err != nil {
		return
	}
}
```

服务端：

```go
srv := asynq.NewServer(reg, asynqio.RedisClientOpt{Addr: "127.0.0.1:6379"}, opts, logger)
if err := srv.Start(); err != nil {
	return err
}
defer srv.Shutdown()
```

> `Payload` 是已解码的 JSON 对象（`map[string]any`）；需要强类型时先用 `ydx/json`
> 重新编码/解码到目标结构体。数字按 JSON 数据模型解码为 `float64`。

## 应用场景

- **邮件/短信发送**：请求路径只入队，投递失败自动重试。
- **图片/视频处理**：耗时转码、缩略图生成。
- **Webhook 投递**：失败重试与退避。
- **定时任务**：延时入队或定时执行报表、清理任务。
- **异步副作用**：审计写入、搜索索引更新、通知推送。
- **多优先级业务**：critical/default/low 加权队列。

## 性能指标

本模块没有独立基准；性能主要由 Redis RTT、任务处理时间与并发度决定：

- 入队是一次 Redis 往返；批量入队可按 asynq 能力合并。
- 服务端并发度由 `Options` 控制；每个任务在独立 worker 中执行。
- 重试与退避把失败任务延后，不会在请求路径上阻塞。
- 内置链的日志与上下文注入是每任务固定开销，相对于业务处理通常可忽略。
- 任务载荷经 `ydx/json`；大载荷应改为对象存储引用，避免 Redis 带宽与内存压力。
- 优雅关闭预算决定退出时等待在途任务的上限。

> 队列吞吐取决于 Redis、任务粒度与 worker 数；请在目标部署上压测。

## 第三方依赖与鸣谢

| 依赖 | 版本 | 许可证 | 用途 |
|---|---|---|---|
| [`hibiken/asynq`](https://github.com/hibiken/asynq) | v0.26.0 | MIT | 任务队列核心（broker、worker、Inspector） |
| [`spf13/afero`](https://github.com/spf13/afero) | v1.15.0 | Apache-2.0 | 配置来源文件系统（经 config） |

测试使用 [`alicebob/miniredis/v2`](https://github.com/alicebob/miniredis)（MIT）作为
内存 Redis。

仓库内依赖：`afs`、`config`、`errs`、`json`、`log`。

## 相关模块

- [`redis`](../redis/README.md)：Redis 客户端装配。
- [`log`](../log/README.md)：任务日志。
- [`config`](../config/README.md)：队列与并发配置。
- [`cache`](../cache/README.md)：任务结果缓存。

## 许可证

Apache-2.0，见仓库根目录 [`LICENSE`](../LICENSE)。
