# benchmarks/wal — 预写日志与主流实现对比

> 环境、指标口径与公平性约定见 [../README.md](../README.md)。

`ydx/wal` 是分段、可崩溃恢复的预写日志：单写协程组提交、每批提交标记、META 双文件双槽、
MANIFEST 分片索引、`.idx` 侧车、快照隔离事务、AES-256-GCM / SM4-GCM、记录级压缩与
段内去重。本基准把它与 Go 生态两个主流 WAL 实现放在同一目录、同一负载下对比。

## 对比对象

| 实现 | 版本 | 说明 |
|---|---|---|
| ydx/wal | v0.2.0 | 本仓库实现；默认 `SyncAlways`，每批一次 fsync |
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
- `QueryKeyIndex` / `QueryKeyLinear`：预填 10000 条、每条不同 Key；前者开启
  `WithKeyIndex` 走索引，后者关闭索引走线性扫描。
- 全部场景 `b.ReportAllocs()`；读写均使用真实文件，不开内存模拟。

## 关键结果（2026-11-07 第五轮加固后，i9-10980HK + Windows 11 + Go 1.27.3）

每个场景 3 轮、每轮 `-benchtime 1s`，取中位数。本轮机器同时存在其它负载，
绝对值高于空载；同轮横向比较仍有效。

| 场景 | ydx/wal | tidwall/wal | rosedblabs/wal | 备注 |
|---|---:|---:|---:|---|
| Append（256 B，单条） | 944 µs | 956 µs | 945 µs | 三者均含一次 fsync；同量级 |
| AppendBatch512 | 1203 µs（109 MB/s） | 1531 µs（86 MB/s） | 1245 µs（105 MB/s） | 本轮 ydx 略快；记录头仍比 rosedb 长约 10%，受负载方差影响 |
| AppendBatch512（NoSync） | 293 µs（448 MB/s） | — | — | 纯编码 + 写入路径 |
| AppendParallel8 | 121 µs | — | — | 8 协程组提交 |
| ReadRandom（10000 条） | 15.5 µs | 0.21 µs* | 17.8 µs | 比 rosedb 快约 13%；两轮绝对值受负载影响 |
| ReadRandomSealed | 18.4 µs | — | — | 冷启动后按需建最新段稠密索引 |
| Scan10000 | 2.99 ms | 1.22 ms* | 77.6 ms | ydx 比 rosedb 快约 26 倍 |
| QueryKey（10000 条/单 Key） | 10.1 µs（KeyIndex） | — | — | 线性回退 3.16 ms；旧侧车只扫描单段并升级，不再全 WAL 回退 |
| Open1000（打开+关闭） | 0.90 ms | 1.27 ms | 0.48 ms | 干净打开不读写锚点（META 锚点标志命中）；ydx 做完整元数据恢复 |
| Append 分配 | **0** allocs/op | 0 allocs/op | 1 allocs/op | 请求、结果通道、批次缓冲全部池化 |
| Batch512 分配 | **0** allocs/op | 29 allocs/op | 513 allocs/op | 批量越大优势越明显 |
| ReadRandom 分配 | 1 allocs/op | 1 allocs/op | 3 allocs/op | 记录副本；`ReadInto` 直接写入调用方缓冲 |
| Scan 分配 | 11 allocs/op | 10000 allocs/op | 30080 allocs/op | 顺序读全程复用缓冲 |
| Open 分配 | 97 allocs/op | 35 allocs/op | 26 allocs/op | 路径、元数据与恢复结构 |

\* tidwall/wal 默认把整个段缓存在内存中（`SegmentCacheSize=2`，基准段远小于段上限），
它的随机读与顺序读是内存命中，不与磁盘读路径直接等价；rosedb 与 ydx 都走真实文件读。
同一口径下应与 rosedb 横比：随机读 15.5 µs vs 17.8 µs，顺序扫描 2.99 ms vs 77.6 ms。

补充口径：`AppendBatch512` 中 fsync 约占 0.85–0.95 ms；关闭同步后的纯编码 + 写入路径
约 0.29–0.30 ms（约 430–450 MB/s），说明批量吞吐已接近该机器单次
`FlushFileBuffers` 的下限，用户态开销不是瓶颈。

## 第五轮加固后复测（2026-11-07）

工作树新增恢复锚点、快照备份、旧侧车索引重建与数据读引擎路由。同机同负载口径下：

| 场景 | 复测中位数 | 变化 |
|---|---:|---|
| `Open1000` | 0.90 ms | 干净 Open 不读写锚点（META 锚点标志命中）；97 allocs/op（原 105、约 88 KB） |
| `Scan10000` | 2.99 ms | 原 5.50 ms；顺序读复用解压/去重缓冲 |
| `QueryKeyIndex` | 10.1 µs | 原 21.9 µs；批量 fd/缓冲读取，不再逐条 `Read` |
| `QueryKeyLinear` | 3.16 ms | 原 3.98 ms；线性扫描路径复用 Reader |
| `ReadRandom` | 15.5 µs | 机器存在其它负载；同轮仍快于 rosedb 17.8 µs |
| `AppendBatch512` | 1.20 ms（109 MB/s） | 受 fsync 主导；记录头 48 B 比 rosedb 长，但本轮略快于 1.24 ms |

旧侧车（v0.1.0 无 `keyIndexComplete`）不再触发全 WAL 线性扫描：首次查询只扫描
缺索引的**单段**并原子升级 `.idx`，之后直接走索引；索引溢出的段按目标 Key 做
单段定向扫描。`Stats.KeyIndexRebuilds`/`KeyIndexScans` 可观测。

## 第六轮读取路径优化（2026-11-07）

`wal v0.2.0`（发布前以临时 `replace` 联调）在第六轮移除了随机读路径上一次性的
`Reader` 结构体分配，并把记录头暂存块改为按 WAL 池化：

| 场景 | 第六轮 | 第五轮 | 说明 |
|---|---:|---:|---|
| `ReadRandom` 分配 | **1 allocs/op（261 B）** | 3 allocs/op（615 B） | 仅剩 `Record.Clone` 的记录副本；同轮 rosedb 3 allocs |
| `QueryKeyIndex` 分配 | **1 allocs/op（18 B）** | 3 allocs/op（373 B） | 批量索引读取不再逐条构造 `Reader` |
| `ReadInto` | 0 次新增分配（热身后） | 先克隆再复制 | 直接解码到池化缓冲并复制进调用方 `dst` |
| `ReadRandom` 耗时 | 8.9–9.2 µs | 15.5 µs | 同轮 rosedb 11.3–12.3 µs |
| `QueryKeyIndex` 耗时 | 6.3–7.6 µs | 10.1 µs | 同轮对比 |
| `Append` / `Batch512` / `Scan` | 0 / 0 / 11 allocs | 同左 | 写路径与顺序扫描无回退 |

同轮复测：`ReadRandom` 约 9 µs（rosedb 约 11–12 µs，3 allocs），`Append` 约
1.1–1.4 ms（fsync 主导，0 allocs），`AppendBatch512` 约 1.24–1.64 ms
（80–106 MB/s，0 allocs），`Scan10000` 约 2.9–3.2 ms（11 allocs），
`Open1000` 约 0.63–0.92 ms（97 allocs）。本轮机器仍有其它负载，绝对值有波动；
相对比较取同一轮。

`wal/zstd` 与 `wal/uring` 是可选的独立模块，不在本基准模块的默认依赖图中。需要
对比时，把本目录复制到两个仓库之外，在副本 `go.mod` 中添加到 `wal`、`wal/zstd`、
`wal/uring` 的临时 `replace`（不要提交）。WSL2（Linux 6.18）实测：uring 的批量
写分配更低（1 vs 13 allocs/op），但单 ring 串行化使随机读略慢于 pread；zstd 对
小记录有 CPU 开销，适合较大或高重复记录。两者均定位为可选后端，不改变默认路径。

## 结论

- **单条追加**：三者都被 fsync 主导；ydx 的中位数略低于另外两者，且稳态 **0 allocs/op**。
  ydx 额外提供提交标记、META 双槽与恢复截断，这些成本没有体现在稳态追加路径上。
- **批量写**：ydx 快于 tidwall，与本轮 rosedb 同量级或略快（1203 µs vs 1245 µs）；
  rosedb 的记录头更短（无提交标记与 48 B 头），每批少写约 10% 字节，因此 ydx 在
  空载/低负载时可能落后约 10%。ydx 批量写 0 allocs/op，rosedb 为 513。
- **随机读**：第六轮同轮 8.9–9.2 µs，快于 rosedb 11.3–12.3 µs；固定
  **1 allocs/op**（仅记录副本）+ 池化读缓冲，需要完全避免副本时用 `ReadInto`
  写入调用方缓冲；并在 Windows 上绕过 `os.File.ReadAt` 的文件指针保存/恢复。
- **顺序扫描**：ydx 2.99 ms 比 rosedb 77.6 ms 快约 26 倍，且全程 11 次分配；
  tidwall 更快是因为整段在内存。
- **Key 查询**：开启 `WithKeyIndex` 且相关分段索引完整时走 LSN 列表，比线性扫描快
  约两个数量级；旧侧车/检查点前缀/溢出时只扫描并升级**单个分段**，不再回退全 WAL
  线性扫描，结果不变。
- **打开**：干净打开不再读写恢复锚点（META 锚点标志命中），`Open1000` 约
  0.6–0.9 ms（快于 tidwall 1.27 ms）；仍慢于 rosedb 0.48 ms，因为 ydx 恢复并
  校验 META/MANIFEST、决定截断与加密策略。不得为跑分牺牲恢复语义。
- **批量写**：fsync 仍占 0.85–0.95 ms；ydx 的记录头（48 B）与提交标记比 rosedb
  长，批量字节数多约 10%。这是格式完整性（LSN/时间/事务/CRC）的成本，不通过
  删减恢复所需字段来换取跑分。
- **资源边界**：写路径 0 分配；稀疏/Key 索引走 `WithIndexCacheBytes` 的 LRU，稠密偏移表
  只为最新段构建，备份完成项及时释放，cleaner 删除失败会重试并上报；
  并发突发把索引/fd 缓存推过上限时，租约结束即回收，预算不会被永久突破。

## 运行方式

本模块是运行门禁：`go.mod` 锁定已发布的 `github.com/shibingli/ydx/wal v0.2.0`，
**不得提交本地 `replace`**。直接运行：

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
