# cron 基准 — ydx 对比主流调度实现

本模块把 `github.com/shibingli/ydx/cron` 的解析、`Next` 计算、调度器增删/读取/列举、
手动触发与管理 API 与主流实现对比：

| 对比库 | 版本 | 用途 |
|---|---|---|
| `github.com/robfig/cron/v3` | v3.0.1 | 解析、`Next`、增删、列举、读取 |
| `github.com/go-co-op/gocron/v2` | v2.23.0 | 增删、列举、手动触发 |
| `github.com/adhocore/gronx` | v1.20.5 | “解析 + 下次触发”参考 |
| `github.com/shibingli/ydx/cron` | v0.1.0 | 被测实现 |

## 环境与口径

- 主机：Windows 11，Intel Core i9-10980HK（8 核 16 线程），Go 1.27.3，`GOMAXPROCS=16`。
- 采样：`-count=5 -benchtime=500ms -benchmem`，取中位数；同一轮内的相对关系有效，
  不同主机/不同时间的绝对值不要直接混比。
- GC 敏感项：`List`、`Get`、`HTTP list` 的每次操作会分配较大的快照/响应缓冲，
  连续跑整套基准时受 GC 与热漂移影响；表中这些项取自独立进程的单独运行。
- 正确性门禁：`TestNextAgreesWithRobfig` 对每个共享语法形式与 robfig 比较连续 200 次
  触发；性能更快但结果不一致视为回归。
- 复现：`benchmarks/cron` 依赖已发布的 `cron/v0.1.0` 子目录标签。标签推送前请在仓库外
  创建临时 `go.work` 指向 `cron` 与 `benchmarks/cron`；`go.work` 不得提交。

## 解析（每操作）

| 表达式 | ydx | robfig |
|---|---:|---:|
| `*/5 9-17 * * MON-FRI`（5 字段） | **1045 ns** / 470 B / 14 allocs | 1128 ns / 592 B / 23 allocs |
| `*/10 * * * * *`（秒字段） | **800 ns** / 320 B / 8 allocs | 1108 ns / 560 B / 21 allocs |
| `0 0 1 JAN-MAR MON`（名称） | **1021 ns** / 489 B / 15 allocs | 1272 ns / 568 B / 24 allocs |
| `@daily` | 136 ns / 128 B / 1 alloc | **75 ns** / 64 B / 1 alloc |
| `@every 90s` | 79 ns / 8 B / 1 alloc | **53 ns** / 8 B / 1 alloc |
| `0 0 12 L * *`（Quartz） | 686 ns / 304 B / 7 allocs | 不支持 |
| `0 0 12 ? * FRI#3`（Quartz） | 767 ns / 371 B / 9 allocs | 不支持 |

描述符走直接构造快路径后，`@daily` 从开发期约 914 ns / 11 allocs 降到
136 ns / 1 alloc，`@every` 从 203 ns / 3 allocs 降到 79 ns / 1 alloc。

## Next（已解析调度，固定参考时刻）

| 表达式 | ydx | robfig | gronx（每次重新解析） |
|---|---:|---:|---:|
| `*/5 * * * *` | **229 ns** | 920 ns | 9.84 µs / 106 allocs |
| `0 9-17 * * MON-FRI` | 157 ns | **119 ns** | 4.96 µs / 43 allocs |
| `*/10 * * * * *` | **157 ns** | 207 ns | 5.21 µs / 47 allocs |
| `@daily` | **141 ns** | 381 ns | 不支持 |
| `@every 90s` | 18 ns | **7 ns** | 不支持 |
| `0 0 12 L * *` | 356 ns | 不支持 | 不支持 |
| `0 0 12 ? * FRI#3` | 279 ns | 不支持 | 不支持 |
| `0 0 12 15W * *` | 555 ns | 不支持 | 不支持 |

`Next` 的 ydx/robfig 均为 0 allocs/op。gronx 的 `NextTickAfter` 每次调用都会重新解析，
其数字是“解析 + 下次触发”的合计，不能与“已解析调度的 Next”直接对比。

调度循环会以“上次结果”推进参考时刻（`BenchmarkNextWalk`）；该场景下 ydx 的位图跳跃优势
更明显：

| 表达式 | ydx | robfig |
|---|---:|---:|
| `*/5 * * * *` | **228 ns** | 930 ns |
| `0 9-17 * * MON-FRI` | **267 ns** | 1773 ns |
| `*/10 * * * * *` | **165 ns** | 209 ns |

## 调度器（1000 个任务）

| 操作 | ydx | robfig | gocron |
|---|---:|---:|---:|
| 增 + 删（未启动） | 553 ns / 2 allocs / 480 B | **88 ns** / 2 / 120 B | 19.1 µs / 39 / 3.1 KiB |
| 增 + 删（运行中） | **920 ns** / 2 / 480 B | 4.28 µs / 14 / 831 B | 22.8 µs / 42 / 3.3 KiB |
| 解析 + 增 + 删 | 1.62 µs / 10 / 800 B | **1.28 µs** / 23 / 664 B | 19.8 µs / 41 / 3.1 KiB |
| `List` / `Entries` / `Jobs` | **98 µs** / 2 / 272 KiB | **26 µs** / 2 / 104 KiB | 321 µs / 2003 / 126 KiB |
| 单点读取 | **186 ns** / 1 / 288 B | 26.6 µs / 2 / 104 KiB | 无按 ID 读取 API |
| 并发单点读取（16 goroutine） | **159 ns** / 1 / 288 B | 33.5 µs / 2 / 104 KiB | — |
| `Stats` | 19.3 µs / 1 / 64 B | 无统计 API | — |
| 手动触发到完成 | **988 ns** / **0 allocs** | 无手动触发 API | 21.9 µs / 30 / 2.8 KiB |
| 并发手动触发（16 goroutine） | 1.79 µs / 0 allocs | — | — |

- `ydx.List` 的 `Snapshot` 包含完整定义、下次触发与统计；robfig 的 `Entry` 更轻，
  gocron 返回 `Job` 接口切片。列举成本包含这些返回语义差异。
- `ydx.Get` 是 map 查找（O(1)）；robfig `Entry` 扫描切片（O(n)）。
- 增删“未启动”是装配期路径；运行中增删 ydx 约为 robfig 的 1/4.6。
- `ydx` 的 `List` ID 顺序按版本缓存，只有新增/删除任务时才重新排序。

## HTTP 管理 API（ydx 独有）

管理 API 以 `ydx/router` 为原生实现；`HTTPHandler` 是同一路由表上的 net/http 适配层。
1000 个任务的实测：

| 路由 | ns/op | B/op | allocs/op |
|---|---:|---:|---:|
| `GET /cron/jobs` | 645 µs | ~659 KiB | 6 |
| `GET /cron/jobs/{id}` | 1.69 µs | 627 B | 5 |
| `GET /cron/stats` | 21.3 µs | 196 B | 3 |

`GET /cron/jobs` 的主要成本是 1000 个快照的分配与 JSON 编码；单任务与统计路由处于
微秒级。HTTP 层没有可直接对比的第三方实现，因此只给出 ydx 绝对值。

## 本轮优化前后

| 项 | 优化前 | 优化后 |
|---|---:|---:|
| `Parse("@daily")` | ~914 ns / 11 allocs | ~136 ns / 1 alloc |
| `Parse("@every 90s")` | ~203 ns / 3 allocs | ~79 ns / 1 alloc |
| 手动触发到完成 | ~1.55 µs / 3 allocs / 160 B | ~988 ns / 0 allocs / 0 B |
| 并发手动触发 | ~1.87 µs / 3 allocs | ~1.79 µs / 0 allocs |
| 并发单点读取 | ~344 ns | ~159 ns |
| `List`（1000 任务，独立运行） | ~333–396 µs / 5 allocs | ~98 µs / 2 allocs |

优化点：

1. 描述符精确匹配与宏直接构造 `Spec`，避免二次解析；时区前缀不再分配 `Fields` 切片。
2. `runTask` 从指针改为按值入队，常见触发路径不再分配任务对象。
3. 仅 `Singleton` 任务创建可取消上下文；成功路径不构造日志字段切片。
4. 调度器锁改为 `RWMutex`；入队热路径用 `entry.removed` 原子标记，不再取全局锁。
5. `List` 缓存按 ID 的有序指针，使用零反射的 `slices.SortFunc`；快照复用缓存的
   `Definition`。
6. 最后错误改为原子指针，读取不再逐任务加锁。
7. 未启动时跳过无意义的事件循环唤醒。

代价：每个任务缓存一份 `Definition`，增删基准的分配从 320 B/op 升到 480 B/op；这是
`List` 从约 350 µs 降到约 98 µs 的交换。

## 复现

```bash
cd benchmarks/cron
GOWORK=off go test -run '^$' -bench . -benchmem -count=5 -benchtime=500ms
GOWORK=off go test -run TestNextAgreesWithRobfig ./...
```

依赖标签推送前，使用仓库外的临时 `go.work`：

```bash
workdir=$(mktemp -d)
cat > "$workdir/go.work" <<EOF
go 1.27.3
use (
	$(pwd)/../..
	$(pwd)
)
EOF
GOWORK="$workdir/go.work" go test ./... -run '^$' -bench . -benchmem
```

## 口径与限制

1. **`@every` 语义不同**：ydx 按 Unix 纪元对齐（多节点无共享状态也能得到相同触发时刻），
   robfig 从当前时刻加延迟并截断到秒；`Next` 数字只比较调用成本，不代表相同的触发时刻。
2. **Quartz 形式无对比**：robfig 不支持 `L`、`W`、`#`，表中这些行是 ydx 绝对值。
3. **gronx 是解析库**：`NextTickAfter` 每次重新解析，表中已标注；其 `IsValid` 也不构建
   调度对象，因此没有单独的解析对比行。
4. **gocron 复用 robfig 解析器**：`NewJob` 包含其自身任务模型、UUID 与调度器注册成本。
5. **快照语义不同**：`ydx.List` 返回定义 + 下次触发 + 统计；robfig `Entries` 只复制条目，
   gocron `Jobs` 返回接口切片。列举与读取的行不能只看 ns 不看返回内容。
6. **GC/热漂移**：`List`、`Get`、HTTP list 在整套基准连续运行时受 GC 影响可达数倍；
   表中使用独立进程的中位数。跨主机不可直接比较。
