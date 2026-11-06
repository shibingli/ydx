# benchmarks/pool — 协程池对比

> 环境、指标口径与公平性约定见 [../README.md](../README.md)。

`ydx/pool` 是面向纳秒级任务的分片协程池：每分片一个有界无锁 MPMC 环，worker 优先消费
home 分片、空闲时工作窃取、最后才自旋/休眠；完全空闲时走直接握手通道。本基准把它与
ants、pond、workerpool、conc 以及有界裸 goroutine 基线放在同一份任务、同一 worker 数下
对比。

## 对比对象

| 实现 | 版本 | 说明 |
|---|---|---|
| ydx/pool | v0.1.0（本地源码） | workers=`GOMAXPROCS`=32，shards=32，queue 4096，fallback 4096 |
| `github.com/panjf2000/ants/v2` | v2.12.1 | `WithPreAlloc(true)`，固定容量 |
| `github.com/alitto/pond/v2` | v2.7.3 | `WithQueueSize(4096)` |
| `github.com/gammazero/workerpool` | v1.3.0 | 无界等待队列 |
| `github.com/sourcegraph/conc/pool` | v0.3.0 | `WithMaxGoroutines(GOMAXPROCS)` |
| 裸 goroutine | Go 1.27.3 | 信号量限制并发为 `GOMAXPROCS` |

## 功能矩阵

> 基于各库公开 API 与文档；版本以本模块 `go.mod` 锁定为准。`—` 表示该库没有对应的一等
> API，而不是无法用其它方式实现。

| 特性 | ydx/pool | ants | pond | workerpool | conc |
|---|---|---|---|---|---|
| fire-and-forget | `Go`/`GoContext` | `Submit` | `Submit` | `Submit` | `Go` |
| 同步往返 | `Call` | — | `Submit(...).Wait` | `SubmitWait` | — |
| 可等待异步 | `Task`/`Future[R]` | — | `Task`/`ResultTask[R]` | — | `ResultPool` 批量 |
| 类型化结果 | `ResultPool[R]`/`Future[R]` | — | `ResultPool[R]` | — | `ResultPool[R]` |
| 逐任务参数（免闭包） | `ParamPool[T,R]` | `NewPoolWithFunc` | — | — | — |
| 批量提交 | `GoBatch`/`CallBatch`/`CallBatchTo`/`SubmitBatch` | — | — | — | — |
| 有界队列 | 分片环 + fallback | 阻塞提交者 | `WithQueueSize` | 无界 | 最大 goroutine 数 |
| 非阻塞拒绝 | `WithNonblocking` | `WithNonblocking` | `WithNonBlocking` | — | — |
| panic 恢复 | 内置 + handler | panic handler | 默认恢复 | — | 传播/重抛 |
| context | 逐任务 | — | pool/group/task | — | `ContextPool` |
| 优雅关闭 | `Shutdown(ctx)` | `ReleaseTimeout` | `StopAndWait` | `StopWait` | `Wait` |
| 动态扩缩容 | `Resize` | `Tune` | `Resize` | — | — |
| 运行指标 | `Stats` | Running/Free/Cap | 完整指标 | Size/QueueSize | — |
| 空闲 worker 回收 | 否（park 零 CPU） | 定时 purge | 自动 | 2s 超时 | goroutine 退出 |
| 常驻 worker 复用 | 是 | 是 | 是 | 是 | 否（每任务 goroutine） |
| fire-and-forget 分配 | 0 allocs/op | 0 allocs/op | 6 allocs/op | 0 allocs/op | 0 allocs/op¹ |

¹ conc 的 pool 本身不分配任务对象，但每个任务会启动一个 goroutine；其成本体现在 ns/op。

## 环境

- Linux（远程 host-01）：AMD Ryzen AI MAX+ 395（Zen 5，16 核 32 线程）
- Go **1.27.3** linux/amd64，`GOMAXPROCS=32`
- `-benchmem -count=5 -benchtime=1s`，取 5 次中位数；采样日期 2026-11-03
- CPU 频率/温度与后台负载会让绝对 ns/op 漂移数十个百分点，只比较同表内的相对关系。

## 吞吐（每操作一次提交）

| Benchmark | ydx | ants | pond | workerpool | conc | goroutine |
|---|---:|---:|---:|---:|---:|---:|
| `Go` 空任务 | **98.2 ns** | 198.3 ns | 506.1 ns | 294.3 ns | 191.1 ns | 200.7 ns |
| `Go` + 原子计数 | **98.7 ns** | 202.8 ns | 438.4 ns | 289.5 ns | 171.5 ns | 201.3 ns |
| `RunParallel` 高并发 | **67.6 ns** | 1083 ns | 1081 ns | 512.3 ns | 516.1 ns | 555.9 ns |

分配：

| 场景 | ydx | ants | pond | workerpool | conc | goroutine |
|---|---:|---:|---:|---:|---:|---:|
| `Go` 空任务 | **0 B / 0 allocs** | 0 / 0 | 227 B / 6 | 0 / 0 | 0 / 0 | 24 B / 1 |
| `Go` + 原子计数 | **0 B / 0 allocs** | 0 / 0 | 226 B / 6 | 0 / 0 | 0 / 0 | 24 B / 1 |
| `RunParallel` | **0 B / 0 allocs** | 0 / 0 | 225 B / 6 | 2 B / 0 | 0 / 0 | 24 B / 1 |

## 同步往返

| Benchmark | ns/op | B/op | allocs/op |
|---|---:|---:|---:|
| `Call/ydx` | 3410 | 144 | 2 |
| `Call/pond` | 1812 | 351 | 7 |
| `Call/workerpool` | 513 | 136 | 2 |

ants 与 conc 没有同步提交 API，不参与该组。`Call` 是经过 worker 唤醒与完成通知的完整
调度器往返；纳秒级同步工作应使用 `CallBatch`/`CallBatchTo`/`GoBatch`。ydx 的 `Call`
比 workerpool 慢，但分配为 2 allocs/op（pond 为 7）。

## 批量（每次操作 64 个任务）

| 实现 | ns/op（整批） | ns/任务 | B/op | allocs/op |
|---|---:|---:|---:|---:|
| **ydx `GoBatch`** | **1821** | **28.5** | 0 | 0 |
| ydx 逐条 `Go` | 83101 | 1298.5 | 2 | 0 |
| conc 逐条 `Go` | 10494 | 164.0 | 0 | 0 |
| ants 逐条 `Submit` | 11771 | 183.9 | 0 | 0 |
| workerpool 逐条 `Submit` | 18983 | 296.6 | 0 | 0 |
| pond 逐条 `Submit` | 60070 | 938.6 | 14956 | 420 |

只有 ydx 提供批量 API；其它实现按 64 次逐条提交计算整批时间。`GoBatch` 的批次头通过
`sync.Pool` 复用，预热后为 **0 B/op、0 allocs/op**；逐条 `Go` 也为 0 allocs/op。

## 批量同步结果（每次操作 64 个任务）

| 实现 | ns/op | B/op | allocs/op | 说明 |
|---|---:|---:|---:|---|
| `CallBatch/ydx` | 3330 | 695 | 3 | 每批分配结果切片 |
| `CallBatchTo/ydx` | 3405 | 178 | 2 | 复用调用方结果缓冲 |

时间差异在同一轮噪声内；`CallBatchTo` 把每批分配从 3 次/695 B 降到 2 次/178 B。

## 提交到执行延迟

`TestLatency` 使用“最多 2×workers 在途”的闭环窗口：提交方在窗口满时阻塞，任务开始执行
时释放窗口。这样比较的是相同并发下的分发延迟，而不是提交速率差异。

| 实现 | p50 | p90 | p99 | p99.9 | max | 耗时 |
|---|---:|---:|---:|---:|---:|---:|
| ydx（spin=16） | 7.7–7.9 µs | 50–52 µs | 159–163 µs | 250–266 µs | 412–476 µs | 52 ms |
| ants | 581 ns | 48 µs | 61 µs | 67 µs | 80 µs | 49–50 ms |
| pond | 18 µs | 48 µs | 73 µs | 122–133 µs | 226 µs | 110 ms |
| workerpool | 0.56 µs | 0.8–1 µs | 3 µs | 5–6 µs | 98–121 µs | 45–52 ms |
| conc | 0.23 µs | 49 µs | 57–63 µs | 60–72 µs | 126 µs | 27–40 ms |
| 裸 goroutine | 0.17–1.5 µs | 52 µs | 59–64 µs | 65–73 µs | 132–136 µs | 31–46 ms |

- Linux 高分辨率时钟下各分位数均有效；ydx 使用 `WithSpinCount(16)` 的延迟配置，吞吐表
  使用 spin=64。
- ydx 的吞吐更高但尾延迟更重：p99 约 160 µs，高于 ants（61 µs）与 workerpool（3 µs）。
  延迟敏感、逐任务同步的场景应优先 `CallBatchTo`/`GoBatch`，或按业务调整自旋、队列容量
  与 worker 数。
- 尾延迟对 CPU 饱和、调度量子与后台负载敏感，建议在目标机器上复测；不要把本表当作
  跨机 SLA。

## 口径与限制

- 吞吐基准的任务都会调用共享 `sync.WaitGroup.Done()`；所有实现支付同样的完成计数成本，
  因此它不改变相对排序，但会抬高绝对 ns/op。
- 所有实现使用 32 个 worker（`GOMAXPROCS=32`）。
- ydx 与 pond 使用 4096 的有界队列；ants 在 worker 满时阻塞提交；workerpool 的等待队列
  无界；conc 在 goroutine 数达到上限时阻塞；裸 goroutine 基线用容量 32 的信号量限制。
- ants 使用 `WithPreAlloc(true)`（其高吞吐配置）；其它库使用各自默认或等价的有界配置。
- `Call` 组只比较提供同步 API 的实现。
- 批量组只有 ydx 有批量 API，其余为 64 次逐条提交；该组衡量的是“批量摊销”能力，而不是
  完全等价的单任务路径。
- 延迟组的闭环窗口为 2×workers；ydx 的 spin=16 与吞吐组的 spin=64 均为公开选项。
- 所有对比库只出现在本模块的 `go.mod`，不进入产品模块。

## 复现

`pool/v0.1.1` 子目录标签发布后：

```bash
cd benchmarks/pool
GOWORK=off go test -run '^$' -bench . -benchmem -count 5 -benchtime 1s
GOWORK=off go test -run TestLatency -count 1 -v
```

标签发布前，在**仓库之外**创建临时 `go.work` 或临时 `replace` 指向本地 `pool` 模块
（不得提交）：

```bash
workdir=$(mktemp -d)
(cd "$workdir" && go work init /path/to/ydx/pool /path/to/ydx/benchmarks/pool)
GOWORK="$workdir/go.work" go test -run '^$' -bench . -benchmem -count 5 -benchtime 1s
GOWORK="$workdir/go.work" go test -run TestLatency -count 1 -v
```

若 `go.work` 因尚未发布的 `v0.1.0` 版本无法解析，可在临时目录复制本模块、对 `pool` 加
本地 `replace` 后运行；仓库内的 `go.mod` 必须保持无 `replace`。
