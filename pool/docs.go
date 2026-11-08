// Package pool provides a low-latency, sharded goroutine pool designed for
// nanosecond-scale tasks and high concurrency. | Package pool 提供面向纳秒级任务与高并发
// 场景的低延迟分片协程池。
//
// # Overview | 概览
//
// The pool owns a set of worker goroutines and a set of bounded lock-free MPMC
// rings. Submissions rotate across the rings; each worker checks its home ring
// and the fallback ring, spins briefly without scanning other shards, steals
// from the other rings before parking, and parks when all queues are empty. A
// token wakeup immediately scans every shard. A shared fallback ring absorbs
// bursts when every shard is full. | 协程池持有一组 worker 协程与一组有界无锁 MPMC
// 环。提交按分片轮询入队；worker 检查自己的 home 环与 fallback 环，短暂自旋期间不扫描
// 其它分片，准备休眠前从其它环窃取，全部队列为空时休眠。令牌唤醒后立即扫描所有分片。
// 所有分片都满时，共享 fallback 环吸收突发流量。
//
// Fire-and-forget submission keeps the job inline in the ring slot and allocates
// nothing per task. Panic recovery, context cancellation, graceful shutdown and
// exact statistics are built in. | fire-and-forget 提交把作业内联在环槽中，每任务零分配。
// panic 恢复、context 取消、优雅关闭与精确统计均为内置能力。
//
// # Quick start | 快速开始
//
//	p := pool.New(pool.WithWorkers(8))
//	defer p.Close()
//
//	if err := p.Go(func(context.Context) error {
//		// Do not capture request-scoped data here. | 不要在此捕获请求期数据。
//		return nil
//	}); err != nil {
//		// ErrPoolClosed or ErrQueueFull. | 可能为 ErrPoolClosed 或 ErrQueueFull。
//	}
//	p.Wait()
//
// # Synchronous calls | 同步调用
//
//	err := p.Call(ctx, func(ctx context.Context) error {
//		return doWork(ctx)
//	})
//
// Call is a full round trip through a worker goroutine. For nanosecond-scale
// work prefer Go, GoBatch or ParamPool, which avoid the scheduler wake on the
// caller side. | Call 是经过 worker 协程的完整往返。纳秒级工作应优先使用 Go、GoBatch 或
// ParamPool，它们避免调用方的调度器唤醒。
//
// # Typed parameters and results | 类型化参数与结果
//
//	typed := pool.NewParamPool[int, int](func(_ context.Context, n int) (int, error) {
//		return n * 2, nil
//	})
//	got, err := typed.Call(ctx, 21)                      // 42
//	results, err := typed.CallBatch(ctx, []int{1, 2, 3}) // [2 4 6]
//	dst, err := typed.CallBatchTo(buf[:0], args)         // reuse a result buffer
//	future := typed.SubmitBatch(ctx, args)               // *Future[[]R]
//
// The handler is fixed at construction, so Go and Submit copy the argument into
// the ring slot instead of allocating a closure per task. Batch headers are
// recycled through a sync.Pool, so GoBatch normally reaches zero allocations
// after warm-up; CallBatchTo lets the caller reuse the result buffer. | 处理器在构造时
// 固定，因此 Go 与 Submit 把参数复制进环槽，而不是为每个任务分配闭包。批次头通过
// sync.Pool 复用，因此 GoBatch 预热后通常达到零分配；CallBatchTo 允许调用方复用结果
// 缓冲区。
//
// # Awaitable submission | 可等待提交
//
//	future := typed.Submit(ctx, 21)
//	got, err := future.Wait(ctx)
//
//	// Error-only tasks use Task. | 只关心错误的任务使用 Task。
//	task := p.Submit(ctx, fn)
//	err := task.Wait(ctx)
//
// A Future or Task may be waited with a context deadline. When the context
// expires first, Wait returns the context error while the task keeps running. |
// Future 与 Task 可带 context 期限等待。若 context 先到期，Wait 返回 context 错误，
// 任务本身继续执行。
//
// # Safety | 安全
//
// A panicking task is recovered and reported as *PanicError, which unwraps to
// ErrTaskPanicked and carries the stack and worker id. A configured
// PanicHandler receives the recovered value and stack (PanicInfo has no worker
// id); a panic in the handler is swallowed. | 发生 panic 的任务会被恢复并报告为
// *PanicError，它可 Unwrap 到 ErrTaskPanicked，并携带栈与 worker 编号。配置的
// PanicHandler 会收到 panic 值与栈（PanicInfo 不含 worker 编号）；处理器自身的 panic
// 会被吞掉。
//
// Submit and Call check ctx before execution. A task canceled while queued is
// completed with the context error without running. | Submit 与 Call 在执行前检查
// ctx。排队期间被取消的任务不会执行，直接以 context 错误完成。
//
// Close stops immediately: queued tasks are discarded and their futures complete
// with ErrPoolClosed, while running tasks finish. Shutdown drains the queues and
// returns ctx.Err if its deadline expires; workers keep draining in the
// background. Wait blocks until every accepted task has completed or been
// discarded without closing the pool. | Close 立即停止：排队任务被丢弃，其 future 以
// ErrPoolClosed 完成，正在运行的任务结束。Shutdown 排空队列；期限到时返回 ctx.Err，
// worker 在后台继续排空。Wait 等待所有已接受任务完成或被丢弃，但不关闭池。
//
// Callers should stop submitting before calling Close or Shutdown. A submission
// racing with either may be accepted and then discarded with ErrPoolClosed. |
// 调用方应在 Close 或 Shutdown 之前停止提交。与关闭并发的提交可能被接受后以
// ErrPoolClosed 丢弃。
//
// # Tuning | 调优
//
// WithWorkers sets the worker count (default runtime.GOMAXPROCS(0)). WithShards
// sets the ring count (default the next power of two at or above the worker
// count). WithQueueSize sets the requested total ring capacity, rounded up per
// shard (default 256 slots per shard); WithFallbackQueueSize sets the shared
// overflow capacity, rounded up to a power of two (default 1024). | WithWorkers
// 设置 worker 数（默认 runtime.GOMAXPROCS(0)）。WithShards 设置环数（默认不小于 worker
// 数的下一个 2 的幂）。WithQueueSize 设置请求的环总容量，按分片向上取整（默认每分片
// 256 槽）；WithFallbackQueueSize 设置共享溢出容量，向上取整为 2 的幂（默认 1024）。
//
// WithNonblocking rejects a full queue with ErrQueueFull instead of blocking.
// WithSpinCount controls how long an idle worker polls before parking; 0
// minimizes idle CPU, larger values reduce wake latency, and the default 32 is a
// balance. WithoutMetrics removes the per-task completion counters. Resize
// changes the worker count at runtime; shrinkage takes effect as workers next
// become idle. | WithNonblocking 在队列满时以 ErrQueueFull 拒绝而不是阻塞。
// WithSpinCount 控制空闲 worker 休眠前的轮询次数；0 最小化空闲 CPU，较大值降低唤醒延迟，
// 默认 32 为折中。WithoutMetrics 关闭每任务完成计数。Resize 在运行时调整 worker 数；
// 缩容在 worker 下次空闲时生效。
//
// # YD integration | YD 集成
//
// A YD route handler can offload work after copying request-scoped values:
// | YD 路由处理器可在复制请求期数据后把工作卸载到池：
//
//	// app.Post("/jobs", func(c *router.Ctx) error {
//	//     job := copyFrom(c)
//	//     if err := p.Go(func(context.Context) error {
//	//         return process(job)
//	//     }); err != nil {
//	//         return err
//	//     }
//	//     return c.JSON(http.StatusAccepted, nil)
//	// })
//
// Do not pass *router.Ctx, http.ResponseWriter or the request body to a worker:
// the response has already completed when the task runs. | 不要向 worker 传递
// *router.Ctx、http.ResponseWriter 或请求体：任务运行时响应已经结束。
//
// # Performance | 性能
//
// The fire-and-forget paths are zero-allocation after warm-up. CallBatch and
// GoBatch amortize enqueue and scheduling cost across a whole batch. The
// benchmarks in github.com/shibingli/ydx/benchmarks/pool compare the pool with
// ants, pond, workerpool, conc and raw goroutines. | fire-and-forget 路径在预热后零
// 分配。CallBatch 与 GoBatch 把入队与调度成本摊销到整批任务。基准见
// github.com/shibingli/ydx/benchmarks/pool，对比 ants、pond、workerpool、conc 与裸
// goroutine。
package pool
