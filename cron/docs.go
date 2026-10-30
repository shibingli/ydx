// Package cron provides a production scheduler for recurring and one-shot jobs.
//
// The module is a complete lifecycle manager: definitions are validated and
// persisted, jobs can be paused, resumed, updated, removed or triggered on
// demand, and every run is timed, retried, panic-guarded and recorded. The
// scheduler is a single event loop over a min-heap plus a bounded worker pool,
// so adding or removing a job is O(log n) and firing never parses an
// expression. | Package cron 提供面向生产的定时任务调度器。
//
// 模块覆盖完整生命周期：定义校验与持久化、暂停、恢复、更新、删除、按需触发，每次运行都有计时、
// 重试、panic 防护与运行记录。调度器由单个事件循环、最小堆与有界工作池组成，增删任务为
// O(log n)，触发时不再解析表达式。
//
// Syntax | 语法：
//
// Five fields (minute hour day-of-month month day-of-week), six fields with
// seconds, seven fields with an explicit year; *, ?, ranges, lists, steps,
// English month and weekday names, L, L-n, W, LW, dayL and day#n; @yearly,
// @monthly, @weekly, @daily, @hourly, @every duration and @once RFC3339; a
// leading CRON_TZ= or TZ= selects the time zone. Weekdays follow Unix
// numbering (0 and 7 are Sunday), including the Quartz-style forms. | 支持五字段、
// 带秒的六字段、带年份的七字段；*、?、范围、列表、步长、英文月份与星期名、L、L-n、W、LW、
// dayL 与 day#n；@yearly、@monthly、@weekly、@daily、@hourly、@every 时长与 @once RFC3339；
// 前导 CRON_TZ= 或 TZ= 选择时区。星期沿用 Unix 编号（0 与 7 为周日），Quartz 风格形式同样如此。
//
// Execution | 执行：
//
// A fixed worker pool consumes a bounded queue. Each job controls timeout,
// retries with backoff, panic recovery, jitter, overlap policy (skip or allow)
// and an optional distributed Singleton claim. Run records are bounded per job
// and exposed newest first. | 固定工作池消费有界队列。每个任务可控制超时、退避重试、
// panic 恢复、抖动、并发策略（跳过或允许）以及可选的分布式 Singleton 抢占。运行记录按任务
// 有界保存并按最新在前暴露。
//
// Multi-node | 多机：
//
// A Locker claims one key per scheduled fire. The claim is refreshed while the
// run is in flight and is deliberately left to expire afterwards, so its TTL is
// the deduplication window and a node that wakes late cannot run the same fire
// again. Jobs without Singleton run on every node. cron/redis supplies Redis
// implementations of both Locker and Store. Definitions written on one node are
// picked up by others through Reload, which validates every row before applying
// additions, replacements and removals. | Locker 为每次计划触发抢占一个键；运行期间
// 自动续租，结束后刻意保留到 TTL 过期，因此 TTL 就是去重窗口，晚醒的节点不会重复执行同一次触发。
// 未设置 Singleton 的任务在每个节点都运行。cron/redis 提供 Locker 与 Store 的 Redis 实现。
// 一个节点写入的定义由其它节点通过 Reload 拾取；Reload 先校验全部行，再应用新增、替换与删除。
//
// YD routing usage (primary) | YD 路由用法（首选）：
//
//	scheduler := cron.New(cron.Options{})
//	_ = scheduler.Register("cleanup", func(ctx context.Context, job *cron.Job) error {
//		return cleanup(ctx)
//	})
//	_ = scheduler.Add(ctx, &cron.Job{
//		ID:       "nightly-cleanup",
//		Task:     "cleanup",
//		Schedule: cron.MustParse("0 3 * * *"),
//		Timeout:  10 * time.Minute,
//		Retries:  2,
//	})
//	go scheduler.Run(ctx)
//
//	r := router.New()
//	_ = scheduler.Mount(r, "/cron")
//
// Native net/http usage (adapter) | 原生 net/http 用法（适配层）：
//
//	mux.Handle("/cron/", scheduler.HTTPHandler("/cron"))
//
// Mount registers explicit routes, so YD router owns method matching, 404/405
// handling and route listing. HTTPHandler builds the same route table behind a
// plain http.Handler. | Mount 注册显式路由，由 YD 路由负责方法匹配、404/405 与路由列表；
// HTTPHandler 把同一张路由表包装为纯 http.Handler。
//
// The administrative API performs no authentication: wrap it with the
// application's admin middleware before exposing it. | 管理 API 不做认证：对外暴露前
// 请套用应用的管理中间件。
package cron
