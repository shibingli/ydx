# cron — 单机/多机全生命周期定时任务

`github.com/shibingli/ydx/cron` 是 ydx 的定时任务调度模块。它不依赖任何第三方调度库：
表达式解析、最小堆调度、工作池执行、超时/重试/panic 防护、生命周期管理与 HTTP 管理 API
全部由本模块实现；多机协调通过 `Locker` 接口接入，`cron/redis` 已提供 Redis 实现。

| 项 | 值 |
|---|---|
| 模块路径 | `github.com/shibingli/ydx/cron` |
| 包名 | `cron` |
| Go 版本 | 1.27.3 |
| 许可证 | Apache-2.0 |

## 功能

- **调度语法**：5 字段（分/时/日/月/周）、6 字段（秒开头）、7 字段（秒 + 年）；
  `*`、`?`、范围、列表、步长、英文月份/星期名；Quartz 的 `L`、`L-n`、`W`、`LW`、
  `dayL`、`day#n`；`@yearly` / `@monthly` / `@weekly` / `@daily` / `@hourly`、
  `@every 90m`、`@once RFC3339`；`CRON_TZ=` / `TZ=` 时区前缀。
- **完整生命周期**：`Add`、`Update`、`Remove`、`Pause`、`Resume`、`Trigger`、
  `Get`、`List`、`History`、`Stats`；定义可经 `Store` 持久化并在重启后恢复。
- **执行策略**：固定工作池 + 有界队列；每任务独立的超时、退避重试、panic 恢复、
  抖动、并发策略（`SkipIfRunning` / `AllowOverlap`）与可选的 `Singleton` 分布式抢占。
- **可观测性**：每任务运行次数、失败、跳过、丢弃、最后运行时间、最后错误、耗时与
  有界运行记录（最新在前）；全局统计；结构化日志经 `ydx/log`。
- **HTTP 管理 API**：`HTTPHandler` 提供列表、创建、更新、删除、暂停、恢复、触发、
  历史与统计接口，不绑定路由框架；不做认证，由调用方套管理中间件。

### 语法约定

- 星期编号沿用 Unix/Vixie：`0` 与 `7` 都表示周日，`1` 周一 … `6` 周六；Quartz 风格的
  `dayL` / `day#n` 也使用这套编号（不是 Quartz 的 1=周日）。
- 日与星期同时受限时按 POSIX 规则取 OR；`?` 视为 `*`。
- 每次触发严格晚于当前时刻；错过的时间点不补跑（例如进程暂停后恢复）。
- `@every` 按 Unix 纪元对齐，使多节点无需共享状态即可得到相同的触发时刻。
- 年份字段范围 1970–2099；`Next` 在 5 年（或显式年份范围）内找不到触发时返回零值。
- 一次性任务触发后仍保留在任务表中（`Next` 为零），可查询历史或显式删除。

## 特性

- **热路径零分配**：表达式在 `Parse` 阶段编译为位图；`Next` 只做位运算与时间跳转，
  单元测试断言 0 allocs/op。调度事件循环单协程运行，触发时不解析、不反射。
- **O(log n) 增删**：任务表 + 最小堆；暂停/恢复/更新/删除都只做堆内定位与修复。
- **低内存**：任务定义是不可变快照，每条记录有界；运行历史在第一次运行时才惰性分配，
  `HistoryLimit` 为负数可完全关闭记录。
- **多机单次执行**：`Singleton` 任务按“任务 ID + 计划触发时刻”抢占锁；运行期间自动
  续租，结束后保留到 TTL 过期，TTL 即去重窗口，晚醒节点不会重复执行同一次触发。
- **单机零依赖**：不配置 `Locker` / `Store` 时没有任何外部服务依赖；`MemoryStore` /
  `MemoryLocker` 可用于测试与单进程部署。
- **兼容主流调度实践**：POSIX 日期 OR 规则、严格晚于当前时刻、错过运行不补跑、
  时区/DST 由 `time.Location` 处理。

## 快速开始

```go
package main

import (
	"context"
	"time"

	"github.com/shibingli/ydx/cron"
)

func main() {
	scheduler := cron.New(cron.Options{Concurrency: 8})

	_ = scheduler.Register("cleanup", func(ctx context.Context, job *cron.Job) error {
		// 业务逻辑；ctx 会在超时、关闭或分布式锁丢失时取消。
		return nil
	})

	_ = scheduler.Add(context.Background(), &cron.Job{
		ID:       "nightly-cleanup",
		Name:     "nightly cleanup",
		Task:     "cleanup",
		Schedule: cron.MustParse("0 3 * * *"),
		Timeout:  10 * time.Minute,
		Retries:  2,
	})

	// 阻塞到 ctx 取消；也可以 Start/Stop 手动管理。
	_ = scheduler.Run(context.Background())
}
```

YD 路由（首选入口，显式注册全部管理路由）：

```go
r := router.New()
_ = scheduler.Mount(r, "/cron")
```

原生 `net/http`（适配层，使用同一张路由表）：

```go
mux.Handle("/cron/", scheduler.HTTPHandler("/cron"))
```

`Mount` 是 ydx/router 原生入口，`HTTPHandler` 把同一套管理 API 包装为纯
`http.Handler`；两者暴露相同的路由、状态码与 JSON 响应。

## 多机部署

```go
import (
	"context"

	"github.com/shibingli/ydx/cron"
	cronredis "github.com/shibingli/ydx/cron/redis"
	redisx "github.com/shibingli/ydx/redis"
)

client, err := redisx.Open(redisx.Options{Mode: redisx.ModeSingle, Addr: "127.0.0.1:6379"})
if err != nil {
	return err
}

scheduler := cron.New(cron.Options{
	Namespace: "billing",
	Locker:    cronredis.NewLocker(client),
	Store:     cronredis.NewStore(client, "billing"),
})
```

- `Store` 让所有节点看到同一份定义；`Scheduler.Start` 会先加载定义，再启动工作池。
- 一个节点上的 `Add` / `Update` / `Remove` 写穿 `Store`，但不会实时推送到其它节点；其它
  节点应周期调用 `Reload`（或管理 API `POST <prefix>/reload`）对齐定义。`Reload` 先校验
  全部定义再原子应用，单条坏数据不会污染运行中的任务表。

```go
ticker := time.NewTicker(30 * time.Second)
defer ticker.Stop()
go func() {
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := scheduler.Reload(ctx); err != nil {
				log.Warn("cron reload failed | 定时任务同步失败", log.Err(err))
			}
		}
	}
}()
```
- `Singleton: true` 的任务每次触发只在一个节点执行；未设置时每个节点都执行（适合本地缓存
  刷新等广播型任务）。
- 多机部署要求节点时钟由 NTP 同步；锁键包含计划触发时刻。
- `Singleton` 任务若设置 `Jitter`，应小于 `cron.lock_ttl`；超过时自动钳制到 TTL 的一半，
  否则晚到的节点可能在锁过期后重复执行。
- 语义是“每次触发至多一个节点执行”，不是跨故障的恰好一次：持有锁的进程崩溃时，该次触发
  不会转移给其它节点，也不会在锁过期后补跑。需要崩溃补偿时请让任务自身幂等并由业务重试。
- `cron/redis` 同时提供 `Locker` 与 `Store`，两者都接受 `go-redis` 的
  `UniversalClient`；也可以用其它实现替换 `cron.Locker` / `cron.Store`。

## 管理 API

| 方法 | 路径 | 作用 |
|---|---|---|
| GET | `<prefix>/jobs` | 列举任务快照 |
| POST | `<prefix>/jobs` | 按 `Definition` 创建任务 |
| GET | `<prefix>/jobs/{id}` | 读取任务快照 |
| PUT | `<prefix>/jobs/{id}` | 替换任务定义 |
| DELETE | `<prefix>/jobs/{id}` | 删除任务 |
| POST | `<prefix>/jobs/{id}/pause` | 暂停计划触发 |
| POST | `<prefix>/jobs/{id}/resume` | 恢复计划触发 |
| POST | `<prefix>/jobs/{id}/trigger` | 立即运行一次 |
| GET | `<prefix>/jobs/{id}/history` | 运行记录（最新在前） |
| GET | `<prefix>/stats` | 全局统计 |
| POST | `<prefix>/reload` | 与 `Store` 同步定义（需要 Store） |

任务 ID 不得包含 `/`。API 不内建认证与限流，请套用应用的管理中间件后再暴露。

## 配置键

`OptionsFromConfig` 读取以下键（均可选，零值回落到默认值）：

| 键 | 说明 | 默认 |
|---|---|---|
| `cron.concurrency` | 工作协程数 | `GOMAXPROCS` |
| `cron.queue_size` | 待运行队列容量 | 1024 |
| `cron.node_id` | 锁键中的节点标识 | 主机名 + PID |
| `cron.namespace` | 锁与存储键前缀 | `cron` |
| `cron.lock_ttl` | 锁有效期/去重窗口 | 30s |
| `cron.lock_timeout` | 单次加锁预算 | 5s |
| `cron.shutdown_timeout` | 优雅关闭预算 | 30s |
| `cron.history_limit` | 每任务运行记录环大小 | 8（负数关闭） |

`Store`、`Locker`、`Logger` 与 `Hooks` 属于进程内协作者，由应用自行装配。

## 应用场景

- **应用内调度中心**：替代系统 crontab，任务定义、暂停/恢复、手动触发与运行历史集中管理。
- **多副本服务**：同一镜像部署多个副本，`Singleton` 任务由 Redis 锁保证每次只跑一次。
- **批量与清理任务**：超时、退避重试、panic 隔离与并发跳过，避免单个任务拖垮进程。
- **运维入口**：`HTTPHandler` 直接挂到管理端口，配合现有认证中间件完成任务运维。

## 性能指标

与 `robfig/cron/v3`、`go-co-op/gocron/v2`、`adhocore/gronx` 的同机对比、完整表格与
复现命令见 [benchmarks/cron](../benchmarks/cron/README.md)。固定成本结构：

- `Parse` 只在定义装配期执行；运行期 `Next` 只做位图跳跃与 `time.Date` 构造，
  单元测试断言 0 allocs/op。
- 每个任务在最小堆中占一个 `*entry`；增删与改期 O(log n)。
- 运行队列有界且按值传递，常见手动触发路径 0 allocs/op；队列满时丢弃并计入 `Dropped`，
  不会阻塞调度事件循环。
- `List` 的 ID 顺序按版本缓存，只有新增/删除任务时才重新排序。
- 运行历史在第一次运行时分配，默认最多 8 条；`HistoryLimit < 0` 关闭。

## 第三方依赖

- `github.com/shibingli/ydx/errs`：哨兵错误。
- `github.com/shibingli/ydx/log`：结构化日志。
- `github.com/shibingli/ydx/json`：HTTP API 编解码。
- `github.com/shibingli/ydx/router`：YD 路由原生管理 API（`Mount`）。
- `github.com/shibingli/ydx/config`：`OptionsFromConfig`。
- `cron/redis` 子包：`github.com/redis/go-redis/v9`；测试使用
  `github.com/alicebob/miniredis/v2`。

本模块不引入任何第三方调度库。

## 验证

```bash
GOWORK=off go build ./... && GOWORK=off go vet ./...
GOWORK=off CGO_ENABLED=1 CC=clang go test ./... -race
```
