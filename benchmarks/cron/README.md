# cron 基准 — ydx 对比主流调度实现

本模块把 `github.com/shibingli/ydx/cron` 的解析、`Next` 计算、调度器增删/读取/列举、
手动触发与管理 API 与主流实现对比：

| 对比库 | 版本 | 用途 |
|---|---|---|
| `github.com/robfig/cron/v3` | v3.0.1 | 解析、`Next`、增删、列举、读取 |
| `github.com/go-co-op/gocron/v2` | v2.23.0 | 增删、列举、手动触发 |
| `github.com/adhocore/gronx` | v1.20.5 | “解析 + 下次触发”参考 |
| `github.com/shibingli/ydx/cron` | v0.1.1 | 被测实现 |

## 环境与口径

- 主机：Windows 11，Intel Core i9-10980HK（8 核 16 线程），Go 1.27.3，`GOMAXPROCS=16`。
- 采样：`-count=5 -benchtime=500ms -benchmem`，取中位数；同一轮内的相对关系有效，
  不同主机/不同时间的绝对值不要直接混比。
- GC 敏感项：`List`、`Get`、`HTTP list` 的每次操作会分配较大的快照/响应缓冲，
  连续跑整套基准时受 GC 与热漂移影响；表中这些项取自独立进程的单独运行。
- 正确性门禁：`TestNextAgreesWithRobfig` 对每个共享语法形式与 robfig 比较连续 200 次
  触发；性能更快但结果不一致视为回归。
- 复现：`benchmarks/cron` 依赖已发布的 `cron/v0.1.1` 子目录标签。标签推送前请在仓库外
  创建临时 `go.work` 指向 `cron` 与 `benchmarks/cron`；`go.work` 不得提交。

## 解析（每操作）

| 表达式 | ydx | robfig |
|---|---:|---:|
| `*/5 9-17 * * MON-FRI`（5 字段） | **909 ns** / 470 B / 14 allocs | 1098 ns / 592 B / 23 allocs |
| `*/10 * * * * *`（秒字段） | **779 ns** / 320 B / 8 allocs | 981 ns / 560 B / 21 allocs |
| `0 0 1 JAN-MAR MON`（名称） | **1004 ns** / 489 B / 15 allocs | 1230 ns / 568 B / 24 allocs |
| `@daily` | 93 ns / 128 B / 1 alloc | **69 ns** / 64 B / 1 alloc |
| `@every 90s` | **27 ns** / 8 B / 1 alloc | 52 ns / 8 B / 1 alloc |
| `0 0 12 L * *`（Quartz） | 660 ns / 304 B / 7 allocs | 不支持 |
| `0 0 12 ? * FRI#3`（Quartz） | 725 ns / 371 B / 9 allocs | 不支持 |

`@daily` 的差距来自 `Spec` 需要容纳 Quartz 字段（128 B vs robfig 的 64 B）；`@every`
通过“整数字符串 + s/m/h”快解析反超 robfig。

## Next（已解析调度，固定参考时刻）

| 表达式 | ydx | robfig | gronx（每次重新解析） |
|---|---:|---:|---:|
| `*/5 * * * *` | **189 ns** | 905 ns | 9.76 µs / 106 allocs |
| `0 9-17 * * MON-FRI` | **116 ns** | 119 ns | 4.96 µs / 43 allocs |
| `*/10 * * * * *` | **122 ns** | 203 ns | 5.24 µs / 47 allocs |
| `@daily` | **103 ns** | 392 ns | 不支持 |
| `@every 90s` | 14 ns | **7 ns** | 不支持 |
| `0 0 12 L * *` | 317 ns | 不支持 | 不支持 |
| `0 0 12 ? * FRI#3` | 260 ns | 不支持 | 不支持 |
| `0 0 12 15W * *` | 523 ns | 不支持 | 不支持 |

`Next` 的 ydx/robfig 均为 0 allocs/op。`@every` 的 ydx 版本按 Unix 纪元对齐
（多节点无需共享状态即可得到相同触发时刻），robfig 则从当前时刻加延迟；14 ns 与 7 ns
的差异就是这次对齐除法的成本。调度循环对整秒间隔使用 `at+d` 重排快路径，实际触发路径
不再每次做对齐除法。

调度循环会以“上次结果”推进参考时刻（`BenchmarkNextWalk`）；该场景下 ydx 的位图跳跃与
年份上限（不再做 `AddDate(5y)`）优势更明显：

| 表达式 | ydx | robfig |
|---|---:|---:|
| `*/5 * * * *` | **191 ns** | 913 ns |
| `0 9-17 * * MON-FRI` | **233 ns** | 1781 ns |
| `*/10 * * * * *` | **125 ns** | 208 ns |

## 调度器（1000 个任务）

| 操作 | ydx | robfig | gocron |
|---|---:|---:|---:|
| 增 + 删（未启动） | 510 ns / 2 allocs / 480 B | **88 ns** / 2 / 120 B | 18.4 µs / 39 / 3.0 KiB |
| 增 + 删（运行中） | **786 ns** / 2 / 480 B | 3.96 µs / 14 / 831 B | 21.6 µs / 42 / 3.2 KiB |
| 解析 + 增 + 删 | 1.48 µs / 10 / 800 B | **1.17 µs** / 23 / 664 B | 18.8 µs / 41 / 3.1 KiB |
| `List` / `Entries` / `Jobs` | **95 µs** / 2 / 272 KiB | **27 µs** / 2 / 104 KiB | 338 µs / 2003 / 126 KiB |
| 单点读取 | **186 ns** / 1 / 288 B | 26.2 µs / 2 / 104 KiB | 无按 ID 读取 API |
| 并发单点读取（16 goroutine） | **169 ns** / 1 / 288 B | 32.6 µs / 2 / 104 KiB | — |
| `Stats` | 20.4 µs / 1 / 64 B | 无统计 API | — |
| 手动触发到完成 | **983 ns** / **0 allocs** | 无手动触发 API | 21.2 µs / 30 / 2.8 KiB |
| 并发手动触发（16 goroutine） | 1.51 µs / 0 allocs | — | — |

- 未启动增删的差距是设计取舍：ydx 在装配期就校验“是否有未来触发”并缓存完整
  `Definition`，robfig 把 `Next` 推迟到运行循环；运行中增删 ydx 约为 robfig 的 1/5。
- `ydx.List` 的 `Snapshot` 包含完整定义、下次触发与统计；robfig 的 `Entry` 更轻，
  gocron 返回 `Job` 接口切片。列举成本包含这些返回语义差异。
- `ydx.Get` 是 map 查找（O(1)）；robfig `Entry` 扫描切片（O(n)）。
- `ydx` 的 `List` ID 顺序按版本缓存，只有新增/删除任务时才重新排序。

## HTTP 管理 API（ydx 独有）

管理 API 以 `ydx/router` 为原生实现；`HTTPHandler` 是同一路由表上的 net/http 适配层。
1000 个任务的实测：

| 路由 | ns/op | B/op | allocs/op |
|---|---:|---:|---:|
| `GET /cron/jobs` | 690 µs | ~750 KiB | 7 |
| `GET /cron/jobs/{id}` | 1.63 µs | 627 B | 5 |
| `GET /cron/stats` | 20.9 µs | 195 B | 3 |

`GET /cron/jobs` 的主要成本是 1000 个快照的分配与 JSON 编码；单任务与统计路由处于
微秒级。HTTP 层没有可直接对比的第三方实现，因此只给出 ydx 绝对值。

## 本轮优化前后

| 项 | 优化前 | 优化后 |
|---|---:|---:|
| `Parse("@daily")` | ~914 ns / 11 allocs | ~93 ns / 1 alloc |
| `Parse("@every 90s")` | ~203 ns / 3 allocs | ~27 ns / 1 alloc |
| `Next` `*/5 * * * *` | ~229 ns | ~189 ns |
| `Next` `0 9-17 * * MON-FRI` | ~157 ns | ~116 ns |
| `Next` `@daily` | ~141 ns | ~103 ns |
| 手动触发到完成 | ~1.55 µs / 3 allocs / 160 B | ~983 ns / 0 allocs / 0 B |
| 并发手动触发 | ~1.87 µs / 3 allocs | ~1.51 µs / 0 allocs |
| 并发单点读取 | ~344 ns | ~169 ns |
| `List`（1000 任务，独立运行） | ~333–396 µs / 5 allocs | ~95 µs / 2 allocs |
| 增 + 删（未启动） | ~553 ns | ~510 ns |

优化点：

1. 描述符精确匹配与宏直接构造 `Spec`，避免二次解析；时区前缀不再分配 `Fields` 切片。
2. `@every` 的简单整数 s/m/h 走无分配快解析，`ContainsAny` 换成 ASCII 扫描。
3. 整秒间隔用 Unix 秒 + float64 商做纪元对齐，替代 64 位纳秒除法；调度循环再用
   `at+d` 重排快路径。
4. `Spec.Next` 用年份上限替代 `AddDate(5y)`，并用一次 `Add` 替代 `Truncate+Add`。
5. `runTask` 从指针改为按值入队，常见触发路径不再分配任务对象。
6. 仅 `Singleton` 任务创建可取消上下文；成功路径不构造日志字段切片。
7. 调度器锁改为 `RWMutex`；入队热路径用 `entry.removed` 原子标记，不再取全局锁。
8. `List` 缓存按 ID 的有序指针，使用零反射的 `slices.SortFunc`；快照复用缓存的
   `Definition`。
9. 最后错误改为原子指针，读取不再逐任务加锁。
10. 未启动时只维护映射，`Start` 一次性 O(n) 建堆；未启动时跳过无效唤醒。

代价：每个任务缓存一份 `Definition`，增删基准的分配从 320 B/op 升到 480 B/op；这是
`List` 从约 350 µs 降到约 95 µs 的交换。

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
3. **gronx 是解析库**：`NextTickAfter` 每次重新解析，表中已标注；它没有可复用的调度对象。
4. **gocron 复用 robfig 解析器**：`NewJob` 包含其自身任务模型、UUID 与调度器注册成本。
5. **快照语义不同**：`ydx.List` 返回定义 + 下次触发 + 统计；robfig `Entries` 只复制条目，
   gocron `Jobs` 返回接口切片。列举与读取的行不能只看 ns 不看返回内容。
6. **未启动增删**：ydx 在装配期校验未来触发并缓存定义，robfig 推迟到运行循环；这是
   两种 API 语义的差异，不是同一工作量。
7. **GC/热漂移**：`List`、`Get`、HTTP list 在整套基准连续运行时受 GC 影响可达数倍；
   表中使用独立进程的中位数。跨主机不可直接比较。
