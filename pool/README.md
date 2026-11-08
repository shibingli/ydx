# ydx/pool — 超低延迟分片协程池

`github.com/shibingli/ydx/pool` 是面向**纳秒级任务粒度、超低延迟、高并发**场景的 Go 协程池。
它用分片无锁 MPMC 环替代全局任务通道，worker 优先消费 home 分片与 fallback，准备休眠前
窃取其它分片，全部队列为空时休眠；fire-and-forget 提交在预热后 **0 B/op、0 allocs/op**。

## 特性

- **同步 / 异步**：`Go`（fire-and-forget）、`Submit`（可等待 `Task`）、`Call`（同步往返）、
  `Future[R]`（类型化结果）。
- **参数传递**：`ParamPool[T, R]` 固定处理器、逐任务传参，不为每个任务分配闭包；
  `CallBatch` / `GoBatch` 批量提交，把入队与调度成本摊销到整批。
- **安全**：panic 恢复并携带栈与 worker 编号、context 取消、关闭后拒绝提交、
  立即/优雅关闭、`Wait`、无协程泄漏。
- **高性能**：分片 MPMC 环、工作窃取、缓存行填充、受限自旋、无锁唤醒通道、
  批量完成计数；高并发下 `RunParallel` 可达千万级 ops/s。
- **可观测**：`Stats` 提供提交/完成/失败/panic/排队/运行/拒绝/fallback/丢弃，
  统计读取不进入任务热路径。
- **可调**：worker 数、分片数、队列容量、阻塞/非阻塞、自旋次数、动态 `Resize`。
- **零第三方依赖**：仅依赖仓库内 `errs`；无 cgo、无 unsafe。

## 快速开始

```go
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/shibingli/ydx/pool"
)

func main() {
	p := pool.New(
		pool.WithWorkers(8),
		pool.WithQueueSize(4096),
		pool.WithFallbackQueueSize(1024),
	)
	defer p.Close()

	// 异步：不等待结果。
	if err := p.Go(func(context.Context) error {
		fmt.Println("background work")
		return nil
	}); err != nil {
		panic(err)
	}

	// 同步：提交并等待。
	if err := p.Call(context.Background(), func(ctx context.Context) error {
		return nil
	}); err != nil {
		panic(err)
	}

	// 可等待的异步任务。
	task := p.Submit(context.Background(), func(context.Context) error { return nil })
	if err := task.Wait(context.Background()); err != nil {
		panic(err)
	}
	p.Wait()
}
```

### 类型化参数、结果与批量

```go
p := pool.NewParamPool[int, int](func(_ context.Context, n int) (int, error) {
	return n * 2, nil
})
defer p.Close()

got, err := p.Call(context.Background(), 21) // 42
results, err := p.CallBatch(context.Background(), []int{1, 2, 3}) // [2 4 6]
future := p.Submit(context.Background(), 5)
value, err := future.Wait(context.Background()) // 10

// 复用结果缓冲：去掉每批结果切片分配。
dst := make([]int, 0, 64)
dst, err = p.CallBatchTo(dst[:0], []int{1, 2, 3}) // [2 4 6]

// 异步批量：返回 Future[[]R]。
batchFuture := p.SubmitBatch(context.Background(), []int{1, 2, 3})
batchResults, err := batchFuture.Wait(context.Background())

// GoBatch 取得 args 的所有权；批次完成前调用方不得修改或复用切片。
// 批次头由 sync.Pool 复用，预热后 0 allocs/op。
if err := p.GoBatch([]int{4, 5, 6}); err != nil {
	// ErrPoolClosed / ErrQueueFull
}
p.Wait()
```

### YD 路由集成

```go
// app.Post("/jobs", func(c *router.Ctx) error {
//     job := copyFrom(c) // 只复制值，不要传 *router.Ctx / http.ResponseWriter / 请求体
//     if err := p.Go(func(context.Context) error {
//         return process(job)
//     }); err != nil {
//         return err
//     }
//     return c.JSON(http.StatusAccepted, nil)
// })
```

## API 概览

| 类型 / 函数 | 说明 |
|---|---|
| `New(opts ...Option) *Pool` | 只关心错误的协程池 |
| `NewResultPool[R](opts ...Option) *ResultPool[R]` | 闭包返回类型化结果 |
| `NewParamPool[T, R](handler, opts ...Option) *ParamPool[T, R]` | 固定处理器 + 逐任务参数 |
| `(*Pool).Go` / `GoContext` | 异步提交，返回受理错误 |
| `(*Pool).Submit` | 返回 `*Task` |
| `(*Pool).Call` | 同步提交并等待 |
| `(*ResultPool[R]).Go` / `Submit` / `Call` | 类型化版本 |
| `(*ParamPool[T,R]).Go` / `Submit` / `Call` | 逐任务参数版本 |
| `(*ParamPool[T,R]).GoBatch` / `CallBatch` / `CallBatchTo` | 批量提交；`CallBatchTo` 复用调用方结果缓冲 |
| `(*ParamPool[T,R]).SubmitBatch` | 返回 `Future[[]R]` 的批量提交 |
| `(*Task).Wait` / `Done`，`(*Future[R]).Wait` / `Done` | 等待结果 / 完成通知 |
| `Wait` / `Close` / `Shutdown(ctx)` / `Resize(n)` / `Stats()` | 生命周期与观测 |

选项：

| 选项 | 默认值 | 说明 |
|---|---|---|
| `WithWorkers(n)` | `GOMAXPROCS` | worker 数 |
| `WithShards(n)` | 不小于 worker 数的下一个 2 的幂 | 队列分片数 |
| `WithQueueSize(n)` | 每分片 256 槽 | 请求的各分片合计容量，按分片向上取整到 2 的幂 |
| `WithFallbackQueueSize(n)` | 1024 | 共享溢出环容量，向上取整到 2 的幂 |
| `WithNonblocking()` | 关闭 | 队列满返回 `ErrQueueFull` 而非阻塞 |
| `WithSpinCount(n)` | 32 | 空闲 worker 休眠前轮询次数 |
| `WithPanicHandler(h)` | nil | panic 回调 |
| `WithErrorHandler(h)` | nil | 无等待者任务错误回调 |
| `WithoutMetrics()` | 开启 | 关闭完成/失败/panic 计数 |

哨兵错误：`ErrPoolClosed`、`ErrQueueFull`、`ErrTaskPanicked`、`ErrNilTask`。
panic 以 `*PanicError` 交付，可用 `errors.Is(err, pool.ErrTaskPanicked)` 判定。

## 设计

```
                 Submit / Go / Call
                        │
                 shard selection (round-robin)
                        │
        ┌───────────────┼────────────────┐
        ▼               ▼                ▼
   shard[0] ring   shard[1] ring   shard[N-1] ring      fallback ring
        │               │                │                   │
        └───────┬───────┴────────┬───────┘                   │
                ▼                ▼                           ▼
             worker 0         worker 1        ...          worker M
                │                │
         home ring → fallback → steal other shards → spin → park
```

- **环**：有界 MPMC，Vyukov 序列号算法；`head`/`tail`/slot 序列号按缓存行填充；
  出队即清零槽位，避免环持有闭包/context/结果。
- **分片**：提交按轮询计数器选择分片；当前分片满时扫描其它分片，全部满才进入 fallback。
- **worker**：home 分片 → fallback → 受限自旋（期间不扫描其它分片）→ 准备休眠前完整
  工作窃取 → 休眠；被令牌唤醒后立即做一次全分片扫描。`SpinCount` 控制空闲 worker 休眠
  前的轮询次数（默认 32）。
- **唤醒**：完全空闲时提交方通过直接握手通道把作业交给休眠 worker（一次 channel 操作
  同时完成传递与唤醒）；否则入环并向无锁唤醒通道非阻塞投递令牌，避免每任务
  `sync.Cond` 的互斥量交接。关闭时关闭 `stop` 通道广播唤醒。
- **批量**：批次头通过 `sync.Pool` 复用，`GoBatch` 预热后 0 allocs/op；`CallBatchTo`
  复用调用方结果缓冲，去掉每批结果切片分配。
- **统计**：提交数由各分片环 `tail`、fallback `tail`、直接握手计数与批量附加计数合成；
  完成/失败/panic 为 worker 独占原子计数（`WithoutMetrics` 时关闭）；共享 pending 计数
  按 64 个任务批量递减。`Wait` 返回后 `Submitted` 精确，启用指标时
  `Completed/Failed/Panicked` 也精确，`Queued/Running` 为并发下的近似快照。

## 性能

> 完整口径、全部场景与复现命令见 [`benchmarks/pool/README.md`](../benchmarks/pool/README.md)。
> 下表为 2026-11-03 同机实测中位数（5 次采样）。

环境：Linux AMD Ryzen AI MAX+ 395（Zen 5，16 核 32 线程），Go 1.27.3 linux/amd64，
`GOMAXPROCS=32`（远程 host-01）。所有实现使用 32 个 worker。

| 场景 | ydx | ants | pond | workerpool | conc | 裸 goroutine |
|---|---:|---:|---:|---:|---:|---:|
| `Go` 空任务 | **98.2 ns** | 198.3 ns | 506.1 ns | 294.3 ns | 191.1 ns | 200.7 ns |
| `Go` + 原子计数 | **98.7 ns** | 202.8 ns | 438.4 ns | 289.5 ns | 171.5 ns | 201.3 ns |
| `RunParallel` 高并发 | **67.6 ns** | 1083 ns | 1081 ns | 512.3 ns | 516.1 ns | 555.9 ns |
| `Call` 同步往返 | 3410 ns | — | 1812 ns | 513 ns | — | — |
| 64 任务批量 | **1821 ns** | 11771 ns | 60070 ns | 18983 ns | 10494 ns | — |
| 分配（`Go`） | **0 B / 0 allocs** | 0 / 0 | 227 B / 6 | 0 / 0 | 0 / 0 | 24 B / 1 |

- 空任务：ydx 比 ants 快约 **2.0×**、比 pond 快约 **5.2×**、比 workerpool 快约 **3.0×**、
  比 conc 快约 **1.95×**、比裸 goroutine 快约 **2.0×**。
- `RunParallel` 高并发：ydx 约 **67.6 ns/op**，比 ants/pond 快约 **16×**、比 workerpool/
  conc 快约 **7.6×**、比裸 goroutine 快约 **8.2×**。
- 批量行每次操作提交 **64** 个任务：ydx `GoBatch` 约 **28.5 ns/任务**；同为 ydx 的逐条
  `Go` 循环为 1299 ns/任务；conc 164 ns/任务，ants 184 ns/任务，workerpool 297 ns/任务，
  pond 939 ns/任务。`GoBatch` 比 conc 快约 **5.8×**、比 ants 快约 **6.5×**、比逐条 `Go`
  快约 **45.6×**。
- `GoBatch` 预热后为 **0 B/op、0 allocs/op**（批次头由 `sync.Pool` 复用）。
- `CallBatch` 与 `CallBatchTo`（64 任务/批）：`CallBatch` 3330 ns、3 allocs、695 B/op；
  `CallBatchTo` 3405 ns、2 allocs、178 B/op。复用结果缓冲把每批分配从 3 次/695 B 降到
  2 次/178 B；时间差异在同轮噪声内。
- `Call` 需要一次 worker 唤醒与完成通知，是调度器往返：ydx 3410 ns，比 pond 1812 ns、
  workerpool 513 ns 慢，但分配为 2 allocs/op（pond 为 7）。纳秒级同步批处理应使用
  `CallBatch`/`CallBatchTo`。
- 上述数字来自远程 host-01，绝对 ns/op 会随 CPU 频率/温度与后台负载漂移；只比较同表内的
  相对关系。
- 延迟：`TestLatency` 采用“最多 2×workers 在途”的闭环窗口，Linux 高分辨率时钟下
  ydx 的 p50 约 **7.8 µs**、p90 约 **50 µs**、p99 约 **160 µs**、p99.9 约 **250–266 µs**、
  max 约 **412–476 µs**；ants p99 约 61 µs、p99.9 约 67 µs，workerpool p99 约 3 µs、
  p99.9 约 6 µs。ydx 的吞吐更高但尾延迟更重，延迟敏感的逐任务同步场景应优先
  `CallBatchTo`/`GoBatch`，或按业务在自旋与队列容量之间调优。

## 语义与限制

- **顺序**：单分片 FIFO；多 worker 下完成顺序不保证全局有序。
- **`Go` / `GoContext` / `GoBatch`**：只返回受理结果；任务错误与 panic 交给
  `ErrorHandler`，panic 同时交给 `PanicHandler`。
- **`Call` / `CallBatch`**：返回任务错误；context 到期时返回 `ctx.Err()`，任务可能仍在
  执行，池不会强制终止。
- **批量**：`CallBatch` 按输入顺序返回结果，遇到错误继续执行其余元素并返回首个错误；
  context 取消后停止剩余元素；若 context 在批次完成前到期，结果切片为 nil（worker 可能
  仍在写入并读取 `args`）。`CallBatchTo` 无 context、阻塞到批次结束，返回后可复用 dst。
  `SubmitBatch` 返回 `Future[[]R]`。`GoBatch` 取得 `args` 的所有权。`CallBatch` 因
  context 到期返回时，调用方须先 `Wait` 再复用 `args`。
- **关闭**：`Close` 立即停止并丢弃排队任务（future 以 `ErrPoolClosed` 完成），
  等待运行中任务结束；`Shutdown(ctx)` 优雅排空。调用方应先停止提交再关闭；
  与关闭并发的提交可能被接受后丢弃。
- **`Resize`**：扩容立即生效；缩容在 worker 下次空闲时生效，不中断运行中任务。
- **空闲回收**：不自动回收空闲 worker。park 后不消耗 CPU，默认 worker 数等于
  `GOMAXPROCS`，常驻内存仅为协程栈；需要缩容时调用 `Resize`。
- **指标**：`WithoutMetrics` 关闭 `Completed/Failed/Panicked` 计数；
  `Submitted/Queued/Rejected` 等结构指标仍可用。
- **任务执行期数据**：不要把 `*router.Ctx`、`http.ResponseWriter` 或请求体交给 worker；
  响应已结束。只传递复制后的值。

## 调优建议

| 目标 | 建议 |
|---|---|
| 最大吞吐 | `WithSpinCount(64)`，队列按峰值 1–2 秒的任务量配置 |
| 最低尾延迟 | `WithSpinCount(16)`，`WithNonblocking()` 让过载快速失败 |
| 最低空闲 CPU | `WithSpinCount(0)`，worker 队列一空即休眠 |
| 内存受限 | 减少 worker/分片/队列；park 的 worker 仅占协程栈 |
| 同步批处理 | `ParamPool.CallBatch` / `GoBatch`，避免逐条调度往返 |
| 纯计数场景 | `WithoutMetrics()` 去掉每任务完成计数 |

## 依赖

仅依赖 `github.com/shibingli/ydx/errs`。不使用 cgo、unsafe、第三方日志或基准库；
组件模块不包含 `Benchmark*`，基准位于 `benchmarks/pool`。

## 验证

```bash
cd pool
GOWORK=off go build ./... && GOWORK=off go vet ./...
GOWORK=off CGO_ENABLED=1 CC=clang go test ./... -race

cd ../benchmarks/pool
GOWORK=off go test -run '^$' -bench . -benchmem -count 5 -benchtime 1s
```

基准模块在 `pool/v0.1.1` 子目录标签发布前，需在仓库外创建指向本地 `pool` 模块的临时
`go.work`（或临时 `replace`，不得提交）。
