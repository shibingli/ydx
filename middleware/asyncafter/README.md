# middleware/asyncafter — 响应后异步管线

`github.com/shibingli/ydx/middleware/asyncafter` 把不参与响应生成的工作从请求路径上摘下来。
中间件链共享同一个 `http.ResponseWriter`，链本身不能并行；安全的并行轴在响应之后：已完成的
请求被复制成 `Record` 值并交给 worker 池，worker 永远看不到写入器或上下文。

| 项 | 值 |
|---|---|
| 模块路径 | `github.com/shibingli/ydx/middleware/asyncafter` |
| 包名 | `asyncafter` |
| Go 版本 | 1.27.3 |
| 许可证 | Apache-2.0 |
| 默认队列 | 1024（`QueueSize <= 0`） |
| 默认 worker | `GOMAXPROCS`（`Workers <= 0`） |

## 功能

- `NewAsyncAfter(AsyncOptions)`：创建管线并启动 worker。
- `AsyncAfter.Submit(Record)`：把记录复制为不可变快照并入队。
- `AsyncAfter.Close(ctx)`：停止接收、排空队列、等待 worker 退出。
- `AsyncAfter.Dropped()`：返回被溢出策略丢弃的记录数。
- `AccessLogAsync(logger, after, opts...)`：采集访问日志字段并提交 `Record`。
- `AccessLogHandler(logger)`：把 `Record` 写成访问日志。
- `Middleware(logger, after, opts...)`：原生 `net/http` 包装器。
- `AccessLogOptions`：`reqlog.Options` 的别名。

## 特性

- **值快照**：`Record` 不含 `*router.Ctx`、`http.ResponseWriter` 或请求期指针；所有字符串
  在 `Submit` 时克隆，离开请求协程后仍安全。
- **有界队列**：默认 1024；溢出策略：
  - `OverflowBlock`（默认）：阻塞提交方，绝不丢记录，但把背压传回请求协程。
  - `OverflowDropNew`：丢弃新记录，递增 `Dropped` 并调用 `OnDrop`。
  - `OverflowDropOldest`：挤掉最旧记录，再入队新记录。
- **关闭语义**：`Close` 后提交的记录在调用方协程同步执行，审计链不丢；上下文到期返回
  `ErrCloseTimeout`，worker 仍会排空已接收记录后退出。
- **panic 隔离**：`Handler` 与 `OnDrop` 都有单任务 recover，一个 panic 不会杀死 worker。
- **顺序可配**：多 worker 并发处理，完成顺序不等于提交顺序；需要严格顺序时用
  `Workers: 1`。
- **原生入口**：`Middleware` 与 YD 入口共享同一管线。

## 快速开始

```go
package main

import (
	"context"
	"time"

	"github.com/shibingli/ydx/log"
	"github.com/shibingli/ydx/middleware/asyncafter"
	"github.com/shibingli/ydx/middleware/requestid"
	"github.com/shibingli/ydx/router"
)

func main() {
	logger := log.New(log.Options{Service: "api"})

	after := asyncafter.NewAsyncAfter(asyncafter.AsyncOptions{
		Handler:  asyncafter.AccessLogHandler(logger),
		Workers:  4,
		QueueSize: 2048,
		Overflow: asyncafter.OverflowDropNew,
		OnDrop: func(rec asyncafter.Record) {
			logger.Warn("access record dropped | 访问记录被丢弃",
				log.Str("path", rec.Path))
		},
	})
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := after.Close(ctx); err != nil {
			logger.Error("async-after close failed | 异步管线关闭失败", log.Err(err))
		}
	}()

	r := router.New()
	r.Use(
		requestid.RequestID(""),
		asyncafter.AccessLogAsync(logger, after),
	)
	_ = r
}
```

自定义处理：

```go
after := asyncafter.NewAsyncAfter(asyncafter.AsyncOptions{
	Handler: func(rec asyncafter.Record) {
		// 写入审计表、指标或消息队列；不要接触请求对象。
		_ = rec
	},
})
```

## 应用场景

- **异步访问日志**：慢磁盘/远端日志目的地不阻塞请求。
- **审计写入**：请求完成后写审计表或消息队列。
- **指标上报**：按请求维度聚合后异步发送。
- **通知/事件**：响应已返回后触发非关键副作用。
- **削峰**：有界队列 + 丢弃策略保护服务端。

## 性能指标

基准模块：[`benchmarks/middleware`](../../benchmarks/middleware/README.md)。参考环境为
AMD Ryzen AI MAX+ 395、Go 1.27.3、Linux，`-count=5`、`-benchtime=500ms` 中位数。

| 场景 | 耗时 | 说明 |
|---|---:|---|
| 同步访问日志 + 100 µs 慢写入器 | 1.054 ms | 请求路径承担写入延迟 |
| 异步访问日志 + 同一慢写入器 | 487.2 ns | 请求路径只交接 |
| 异步提交 | 258.8 ns | 队列/克隆/溢出处理 |
| 异步吞吐 `workers1_queue16` | 49.79 ns | 处理侧 |
| 异步吞吐 `workers4_queue256` | 53.47 ns | 处理侧 |
| 异步吞吐 `workersN_queue4096` | 96.42 ns | 处理侧 |

过载指标（`OverflowDropNew`，故意不施压背压）：

| 场景 | drops | drop_ratio | handled/s |
|---|---:|---:|---:|
| `workers1_queue16` | 3.928M | 99.97% | 1,923 |
| `workers4_queue256` | 4.087M | 99.87% | 7,780 |
| `workersN_queue4096` | 5.225M | 99.59% | 34,270 |

- 异步在慢目的地场景把请求路径从 1.054 ms 降到 487.2 ns。
- 目的地为 `io.Discard` 时，异步反而比同步多约 0.77 µs（1.592 µs vs 821.5 ns），
  这是队列与交接的固定成本；异步的价值在慢目的地。
- 过载时的 drop 是“生产者远快于处理器”的预期结果，不是中间件缺陷；意义是请求路径不阻塞。
  需要不丢记录时增大队列/worker 或改用 `OverflowBlock`。

> 完整表格与口径见基准 README；`drops` / `handled` 是整轮累计值，会随 `-benchtime`、
> CPU 与机器变化。

## 第三方依赖与鸣谢

本模块没有第三方运行时依赖。仓库内依赖：

- [`middleware/accesslog`](../accesslog/README.md)：访问日志字段与处理器。
- [`middleware/reqlog`](../reqlog/README.md)：池化响应捕获。
- [`middleware/requestid`](../requestid/README.md)：请求 ID。
- [`log`](../../log/README.md)：日志器。
- [`sysinfo`](../../sysinfo/README.md)：默认 worker 数。
- [`router`](../../router/README.md)、`errs`、`json`。

## 相关模块

- [`middleware/accesslog`](../accesslog/README.md)：同步访问日志。
- [`middleware/reqlog`](../reqlog/README.md)：共享捕获设施。
- [`log`](../../log/README.md)：日志器。
- [`asynq`](../../asynq/README.md)：需要持久化的异步任务。

## 许可证

Apache-2.0，见仓库根目录 [`LICENSE`](../../LICENSE)。
