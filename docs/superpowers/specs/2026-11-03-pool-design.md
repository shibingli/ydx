# ydx/pool 超低延迟协程池设计

日期：2026-11-03
状态：已确认（用户委派全部技术决策，无人工干预）

## 1. 目标

在 ydx 仓库新增独立模块 `github.com/shibingli/ydx/pool`（目录 `pool`，包名 `pool`），
面向**纳秒级任务粒度、超低延迟、高并发**场景，提供：

- 异步提交：`Go` / `GoContext`，fire-and-forget，零任务分配。
- 同步调用：`Call`，提交并在当前协程等待结果。
- 可等待异步：`Submit` 返回 `*Task` / `*Future[R]`，支持 context 超时。
- 参数传递：`ParamPool[T, R]` 固定处理器、逐任务传参，避免每任务闭包分配；
  `CallBatch` / `GoBatch` 批量提交，摊销入队成本。
- 安全：panic 恢复并携带栈、context 取消、关闭后拒绝提交、优雅/立即关闭、
  `Wait` 等待、无协程泄漏。
- 高性能：分片 MPMC 环、工作窃取、自适应自旋/休眠、缓存行填充、批量化统计、
  零分配 fire-and-forget 快路径。
- 可观测：无锁读取的 `Stats`（提交/完成/失败/panic/排队/运行/拒绝/溢出）。
- 可调：worker 数、分片数、队列容量、阻塞/非阻塞、自旋次数、动态 `Resize`。

## 2. 非目标

- 不追求全局严格 FIFO；仅保证单个分片内 FIFO，worker 数大于 1 时完成顺序不保证。
- 不提供任务优先级、延迟队列、重试、持久化；这些属于 asynq/cron/workflow 模块。
- 不提供线程绑定（thread pinning）；它依赖平台且收益需按场景实测。
- 不做空闲 worker 的定时自动回收。worker park 后不消耗 CPU，默认数量等于
  `GOMAXPROCS`，常驻内存只有协程栈；需要缩容时显式调用 `Resize`。
- 不引入第三方依赖（仅依赖仓库内 `errs`），不使用 cgo、unsafe、SIMD。

## 3. 调研结论

| 方案 | 优点 | 对本设计的启示 |
|---|---|---|
| ants v2 | worker 栈 + 每 worker 任务通道，回收/清理，预分配，阻塞/非阻塞，panic handler | 提供 `Tune`/`Release` 类生命周期与 panic 安全 |
| pond v2 | 类型化 `ResultPool[R]`、任务组、子池、有界队列、`Resize`、完整指标 | 类型化结果、context、队列语义与指标 |
| conc | 结构化并发、panic 带栈传播 | `Done`/`Wait` 语义与 panic 栈 |
| gammazero/workerpool | 简单、空闲回收、`StopWait` | 关闭语义清晰 |
| Flock | 每 worker 无锁 MPSC 环 + 共享 fallback + 自旋/休眠 + 分片指标 | 分片本地队列 + fallback 是 ns 级最优形态 |
| mem-queue | Vyukov 序列号 MPMC 环，~28 ns/op 并行、0 alloc | 采用序列号 MPMC 环作为基础队列 |

结论：纳秒级场景下，**通道（channel）是瓶颈**。最优形态是每个 worker/分片拥有
独立的无锁环，提交方轮询分片，worker 本地消费、空闲时窃取、最后才休眠；共享队列
只作为过载缓冲。该形态同时保留动态 worker 数、工作窃取和低延迟唤醒能力。

## 4. 架构

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

### 4.1 分片 MPMC 环

- 每个分片一个有界 MPMC 环，容量为 2 的幂，采用 Vyukov 序列号算法：
  生产者 CAS `tail`、写值、发布 slot 序列号；消费者 CAS `head`、读值、清空槽位、
  发布下一轮序列号。
- `head`、`tail` 与每个 slot 的序列号均按缓存行填充，避免伪共享。
- 出队后立即将槽位置零，避免环持有闭包/context/结果的引用，降低 GC 扫描压力。
- 环的 `tail` 只统计成功入队次数，可作为无额外原子操作的“已提交”指标。

### 4.2 分片与 worker

- 分片数默认为不小于 worker 数的 2 的幂，可用 `WithShards` 覆盖。
- worker 有 home 分片（`id & mask`）；优先消费 home 与 fallback，空闲时扫描其它
  分片工作窃取，最后才进入自旋/休眠。
- worker 数与分片数解耦，因此 `Resize` 只增减 consumer，不影响队列归属；
  缩容后的分片由剩余 worker 窃取。

### 4.3 入队路由与背压

1. 按轮询计数器选择分片；尝试本地环。
2. 本地环满 → 尝试全局 fallback 环。
3. 仍满 → 阻塞等待空位（默认）或返回 `ErrQueueFull`（`WithNonblocking`）。
4. 若**全部 worker 都空闲**，优先通过直接握手通道把作业交给一个休眠 worker
   （一次 channel 操作同时完成传递与唤醒）；否则入环并向无锁唤醒通道非阻塞投递令牌。

阻塞提交先在 `spaceSpin`（32）次内自旋重试入队；持续满载时才进入独立的 `space`
条件变量。worker 每次出队后仅当存在等待者时 Signal，关闭时 Broadcast 唤醒全部。

### 4.4 自旋与休眠

- 每个 worker 自旋 `SpinCount` 次（默认 32），期间检查 home 与 fallback，
  每 16 次 `runtime.Gosched` 一次。
- `SpinCount` 是公开选项：0 让 worker 队列一空就休眠（最低空闲 CPU），较大值降低唤醒
  延迟但增加空闲 CPU。
- 休眠通过无锁唤醒通道 + 直接握手通道实现：worker 先登记 sleeper、刷新完成计数、
  重新检查工作，再 `select` 等待作业/令牌/关闭信号。完全空闲时提交方直接投递作业；
  部分 worker 忙碌时入环并投递唤醒令牌。稳态高负载下快路径只有一次原子 load 和一次
  非阻塞 channel 发送。
- 唤醒丢失用“登记 sleeper → 重新检查工作 → 等待令牌”的顺序消除。
- worker 被令牌唤醒后立即做一次全分片扫描，避免先自旋再窃取带来的额外延迟。

### 4.5 工作窃取

- worker 的 home 为空时，从 `home+1` 开始扫描其它分片，逐个 `tryDequeue`。
- 窃取使用 MPMC 出队，允许多个 worker 同时消费同一分片。
- 在自旋阶段不扫描其它分片（降低缓存行争用）；只在准备休眠前和被唤醒后做完整窃取。
  这样稳态吞吐更高，同时被唤醒的 worker 能立即找到目标分片中的任务。

### 4.6 生命周期

- `Close`：立即关闭。拒绝新提交，worker 丢弃队列中未执行的任务（future 以
  `ErrPoolClosed` 完成），等待正在执行的任务结束与 worker 退出。
- `Shutdown(ctx)`：优雅关闭。拒绝新提交，worker 排空并执行队列中全部任务后退出；
  `ctx` 到期返回错误，worker 在后台继续排空。
- `Wait()`：等待当前已接受的任务全部完成，不关闭池。
- `Resize(n)`：热调整 worker 数；扩容立即启动新 worker，缩容在 worker 下次空闲
  （准备休眠）时生效，不中断正在运行的任务。
- 关闭后提交返回 `ErrPoolClosed`。与关闭并发的提交可能被接受后丢弃，其 future 以
  `ErrPoolClosed` 完成；调用方应先停止提交再关闭。

### 4.7 统计

- 提交数：所有分片环 `tail` 与 fallback `tail` 之和，外加批量子任务的额外计数；
  不增加每任务原子操作。
- 完成/失败/panic：每个 worker 独占的原子计数器，每任务一次原子加，但其缓存行只由
  该 worker 写，因此没有跨核争用；`Wait` 返回后计数精确。
- 等待计数：提交方每任务递增一次共享 pending；worker 每 64 个完成批量递减，
  把等待路径上的跨核原子写减少 64 倍。worker 休眠/退出前必刷新。
- 运行中：每 worker 一个原子布尔，worker 独占写，`Stats` 读。
- 排队：环 `tail-head` 的近似值。
- 拒绝/fallback/丢弃：仅在冷路径累加。
- `WithoutMetrics` 关闭完成/失败/panic 计数，保留提交/排队等结构指标。

### 4.8 零分配快路径

- `Go` / `GoContext` / `ParamPool.Go` / `GoBatch` 不创建 future；任务结构体内联在
  环槽中，入队只复制结构体，稳态 0 allocs/op（调用方闭包捕获除外）。
- `Submit`/`Call` 每个任务分配一个 completion 与一个完成通知 channel；这是可等待
  语义的必要成本。
- `ParamPool` 的处理器在构造时固定，逐任务只传 `T`，避免每任务闭包分配。

### 4.9 panic 与 context

- 每个任务执行包裹 `recover`；panic 转为 `*PanicError`（含 panic 值与栈），
  同时调用可选 `PanicHandler`。
- `Submit`/`Call` 的 future 收到 `*PanicError`；`Go` 路径交给 `ErrorHandler`。
- 执行前检查 `ctx.Err()`；已取消的任务不执行，future 直接完成。
- 执行中取消依赖任务自身监听 context；池不强制中断。
- `Go` 路径把 `context.Background()` 传给函数，不检查取消；需要取消语义时用
  `GoContext`。

## 5. 公开 API

```go
type Pool struct{ /* ... */ }

func New(opts ...Option) *Pool
func (p *Pool) Go(fn func(context.Context) error) error
func (p *Pool) GoContext(ctx context.Context, fn func(context.Context) error) error
func (p *Pool) Submit(ctx context.Context, fn func(context.Context) error) *Task
func (p *Pool) Call(ctx context.Context, fn func(context.Context) error) error
func (p *Pool) Wait()
func (p *Pool) Close()
func (p *Pool) Shutdown(ctx context.Context) error
func (p *Pool) Resize(workers int) error
func (p *Pool) Stats() Stats

type ResultPool[R any] struct{ /* ... */ }

func NewResultPool[R any](opts ...Option) *ResultPool[R]
func (p *ResultPool[R]) Go(fn func(context.Context) (R, error)) error
func (p *ResultPool[R]) GoContext(ctx context.Context, fn func(context.Context) (R, error)) error
func (p *ResultPool[R]) Submit(ctx context.Context, fn func(context.Context) (R, error)) *Future[R]
func (p *ResultPool[R]) Call(ctx context.Context, fn func(context.Context) (R, error)) (R, error)

type ParamPool[T, R any] struct{ /* ... */ }

func NewParamPool[T, R any](handler func(context.Context, T) (R, error), opts ...Option) *ParamPool[T, R]
func (p *ParamPool[T, R]) Go(arg T) error
func (p *ParamPool[T, R]) GoContext(ctx context.Context, arg T) error
func (p *ParamPool[T, R]) Submit(ctx context.Context, arg T) *Future[R]
func (p *ParamPool[T, R]) Call(ctx context.Context, arg T) (R, error)
func (p *ParamPool[T, R]) GoBatch(args []T) error
func (p *ParamPool[T, R]) CallBatch(ctx context.Context, args []T) ([]R, error)
func (p *ParamPool[T, R]) CallBatchTo(dst []R, args []T) ([]R, error)
func (p *ParamPool[T, R]) SubmitBatch(ctx context.Context, args []T) *Future[[]R]

type Task struct{ /* ... */ }
func (t *Task) Wait(ctx context.Context) error
func (t *Task) Done() <-chan struct{}

type Future[R any] struct{ /* ... */ }
func (f *Future[R]) Wait(ctx context.Context) (R, error)
func (f *Future[R]) Done() <-chan struct{}
```

选项：

```go
func WithWorkers(n int) Option
func WithShards(n int) Option
func WithQueueSize(n int) Option
func WithFallbackQueueSize(n int) Option
func WithNonblocking() Option
func WithSpinCount(n int) Option
func WithPanicHandler(h func(PanicInfo)) Option
func WithErrorHandler(h func(error)) Option
func WithoutMetrics() Option
```

哨兵与错误：

```go
var ErrPoolClosed = errs.New("pool closed | 协程池已关闭")
var ErrQueueFull = errs.New("pool queue full | 协程池队列已满")
var ErrTaskPanicked = errs.New("task panicked | 任务发生 panic")

type PanicInfo struct { Value any; Stack []byte }
type PanicError struct { Value any; Stack []byte; Worker int }
func (e *PanicError) Error() string
func (e *PanicError) Unwrap() error // ErrTaskPanicked
```

`Stats`：

```go
type Stats struct {
    Workers       int
    TargetWorkers int
    Shards        int
    Capacity      int
    Queued        int
    Running       int
    Submitted     uint64
    Completed     uint64
    Failed        uint64
    Panicked      uint64
    Rejected      uint64
    Fallback      uint64
    Discarded     uint64
}
```

## 6. 语义细节

- `Go`/`GoContext`/`GoBatch` 只返回**受理结果**（`ErrPoolClosed`/`ErrQueueFull`），
  任务错误通过 `ErrorHandler` 或 future 交付。
- `Submit`/`Call` 返回任务错误；panic 返回 `*PanicError`。
- `Call(ctx)` 在 ctx 到期时返回 `ctx.Err()`，但任务可能仍在执行；池不会强制终止。
- 队列满时 `Call` 的阻塞入队不受 ctx 中断（与 ants 一致）；ctx 只影响结果等待。
- `CallBatch`/`GoBatch` 把整批作为一个环槽提交；批量长度为 0 返回 nil。
- `CallBatch` 顺序返回结果；遇到错误继续执行其余元素，返回首个错误；
  ctx 取消后停止处理剩余元素。`GoBatch` 的错误逐个交给 `ErrorHandler`。
- 批量子任务在统计中按元素计数（`Submitted`/`Completed`），环槽按作业计数。
- nil context 视为 `context.Background()`。

## 7. 性能决策

1. **不用 channel 作为主队列**：channel 的全局锁在纳秒级任务下成为瓶颈。
2. **分片环 + fallback**：正常路径无共享热队列，过载时 fallback 吸收突刺。
3. **缓存行填充**：`head`/`tail`/slot 序列号/轮询计数器/worker 统计独立成行。
4. **批量等待计数**：worker 每 64 个完成批量递减共享 pending；完成/失败/panic 使用
   worker 独占缓存行，避免跨核争用。
5. **快路径零分配**：任务内联在环槽；fire-and-forget 不分配 future。
6. **自旋后休眠**：空闲时最多自旋 `SpinCount`（默认 32）次即休眠；0 为最低空闲 CPU。
   热路径原子字段（`pending`、`sleepers`、`spaceWaiters`、生命周期标志）各自独占缓存行，
   避免生产者写 `pending` 与 worker 读 `spaceWaiters` 之间的伪共享。
7. **无锁唤醒通道**：每任务 `sync.Cond` 的互斥量交接被非阻塞令牌替代；这是消除
   纳秒级 paced 负载下约 3 倍开销的关键优化。
8. **工作窃取**：worker 数与分片数解耦，缩容/长任务不均衡时仍能利用全部 CPU。
9. **批量 API**：ns 级任务用 `GoBatch`/`CallBatch` 进一步摊销入队与调度成本。
10. **批量头复用与结果缓冲**：`batchJob` 通过 `sync.Pool` 复用，`GoBatch` 预热后
    0 allocs/op；`CallBatchTo(dst, args)` 复用调用方结果缓冲，`SubmitBatch` 提供可等待
    批量结果。

## 8. 基准对比

新增独立基准模块 `benchmarks/pool`，与以下实现同机对比：

- `panjf2000/ants/v2`（固定容量、预分配）
- `alitto/pond/v2`（现代 API，默认配置）
- `gammazero/workerpool`（极简池）
- `sourcegraph/conc/pool`（结构化并发）
- 裸 goroutine（基线）

场景：

- `Go` 空任务（fire-and-forget，异步吞吐）。
- `Go` + 原子计数（ns 级 CPU 任务）。
- `RunParallel` 高并发提交。
- `Call` 同步往返。
- `ParamPool.GoBatch` 批量提交。
- 提交到执行延迟 p50/p99/p99.9（独立延迟测试）。

口径：同一 worker 数（`GOMAXPROCS`）、同一任务、`-benchmem`、`-count=5`、
`-benchtime=1s`，取中位数；记录 CPU、Go 版本、GOMAXPROCS。对比库版本锁定在
`benchmarks/pool/go.mod`。

## 9. 验证

- 每个模块：`GOWORK=off go build ./... && go vet ./...`。
- race：`CGO_ENABLED=1 CC=clang go test ./... -race`。
- 环与池的并发压力测试、关闭/等待/扩容/窃取/panic/context/队列满测试。
- 仓库守卫 `repotest`。
- 基准模块通过仓库外临时 `go.work` 运行（`pool/v0.1.0` 标签发布前）。
