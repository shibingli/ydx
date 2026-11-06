# benchmarks/wal — 预写日志与主流实现对比

> 环境、指标口径与公平性约定见 [../README.md](../README.md)。

`ydx/wal` 是分段、可崩溃恢复的预写日志：单写协程组提交、每批提交标记、META 双文件双槽、
MANIFEST 分片索引、`.idx` 侧车、快照隔离事务、AES-256-GCM / SM4-GCM、记录级压缩与
段内去重。本基准把它与 Go 生态两个主流 WAL 实现放在同一目录、同一负载下对比。

## 对比对象

| 实现 | 版本 | 说明 |
|---|---|---|
| ydx/wal | v0.1.0 | 本仓库实现；默认 `SyncAlways`，每批一次 fsync |
| `github.com/tidwall/wal` | v1.2.1 | 单文件追加 + 内存段缓存（默认 `SegmentCacheSize=2`） |
| `github.com/rosedblabs/wal` | v1.3.8 | 分段追加 + 位置句柄式读取 |

## 场景

- `Append`：单条 256 B 记录逐条写入，默认同步策略（每次确认前 fsync）。
- `AppendBatch512` / `WriteBatch512` / `WriteAll512`：512 条 256 B 记录为一批，每批一次
  写入 + 一次 fsync（tidwall `WriteBatch`、rosedb `PendingWrites`+`WriteAll`+`Sync`）。
- `AppendParallel8`：8 个 goroutine 并发 `Append`，考察组提交合并效率。
- `ReadRandom` / `ReadRandomSealed`：预填 10000 条后随机读取；后者关闭并重新打开 WAL，
  使侧车与缓存走冷启动路径。
- `Scan10000`：从首条顺序扫描 10000 条；tidwall 对应 `ReadAll10000`，rosedb 对应
  `ReadAll10000`（按位置逐条读取）。
- `Open1000`：预填 1000 条、关闭后测量“打开 + 关闭”一次循环的耗时。
- 全部场景 `b.ReportAllocs()`；读写均使用真实文件，不开内存模拟。

## 关键结果（2026-11-07，i9-10980HK + Windows 11 + Go 1.27.3）

每个场景 5 轮、每轮 `-benchtime 2s`，取中位数。

| 场景 | ydx/wal | tidwall/wal | rosedblabs/wal | 备注 |
|---|---:|---:|---:|---|
| Append（256 B，单条） | 960 µs | 939 µs | 936 µs | 三者均含一次 fsync，差异约 2.6% |
| AppendBatch512 | 1122 µs（117 MB/s） | 1139 µs（115 MB/s） | 1055 µs（124 MB/s） | rosedb 批头开销更小 |
| ReadRandom（10000 条） | 7.46 µs | 0.16 µs* | 9.28 µs | 比 rosedb 快约 20% |
| ReadRandomSealed | 7.81 µs | — | — | 冷启动后仍只有一个预读窗口 |
| Scan10000 | 2.32 ms | 1.17 ms* | 72.5 ms | ydx 比 rosedb 快约 31 倍 |
| Open1000（打开+关闭） | 1.21 ms | 1.07 ms | 0.33 ms | 已消除重复 META 写入 |
| Append 分配 | 8 allocs/op | 0 allocs/op | 1 allocs/op | 每条记录一次请求对象 |
| Batch512 分配 | 9 allocs/op | 29 allocs/op | 513 allocs/op | 批量越大优势越明显 |
| Scan 分配 | 11 allocs/op | 10000 allocs/op | 30079 allocs/op | 顺序读全程复用缓冲 |

\* tidwall/wal 默认把整个段缓存在内存中（`SegmentCacheSize=2`，基准段远小于段上限），
它的随机读与顺序读是内存命中，不与磁盘读路径直接等价；rosedb 与 ydx 都走真实文件读。
同一口径下应与 rosedb 横比：随机读 7.46 µs vs 9.28 µs，顺序扫描 2.32 ms vs 72.5 ms。

补充口径：`AppendBatch512` 中 fsync 约占 0.85–0.95 ms；关闭同步后的纯编码 + 写入路径
约 0.24–0.31 ms（约 425–540 MB/s），说明批量吞吐已接近该机器单次 `FlushFileBuffers`
的下限，用户态开销不是瓶颈。

## 结论

- **单条追加**：三者都被 fsync 主导，ydx 与另外两者差距在 3% 以内；ydx 额外提供提交
  标记、META 双槽与恢复截断，这些成本没有体现在稳态追加路径上。
- **批量写**：ydx 与 tidwall 基本持平，比 rosedb 慢约 6%；rosedb 的记录头更短
  （无提交标记与 48 B 头），每批少写约 10% 字节。ydx 的分配次数只有 rosedb 的 1.8%。
- **随机读**：ydx 快于 rosedb 约 20%，每次读取固定 3 次分配（记录副本 + 两个池化缓冲），
  并在 Windows 上绕过 `os.File.ReadAt` 的文件指针保存/恢复（每次读少两次 `Seek`）。
- **顺序扫描**：ydx 比 rosedb 快约 31 倍，且全程 11 次分配；tidwall 更快是因为整段在内存。
- **打开**：ydx 已与 tidwall 持平。此前每次打开/关闭都会重复写 META 双槽（4 次 fsync），
  现在只在恢复状态与持久化状态不一致时写入。

## 运行方式

本模块是运行门禁：`go.mod` 依赖已发布的 `github.com/shibingli/ydx/wal`，**不得提交
本地 `replace`**。发布 `wal/v0.1.0` 标签后直接运行：

```bash
cd benchmarks/wal
GOWORK=off go test -run '^$' -bench . -benchtime 2s -count 5
```

发布前需要本地联调时，把本目录复制到两个仓库之外的临时目录，并在副本的 `go.mod` 里加一条
开发用 `replace`（不要提交）：

```text
replace github.com/shibingli/ydx/wal => <本仓库>/wal
```

也可用 `go work` 指向两个模块，但消费方 `go.mod` 不能同时按版本号要求 `ydx/wal`，
否则工作区仍会尝试解析已发布版本。
