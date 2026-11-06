# ydx/raft 基准：Dragonboat v4、etcd raft、hashicorp/raft、并发与 WAL

本模块在**相同条件**下对比 `ydx/raft`、`go.etcd.io/raft/v3 v3.7.0`、
`github.com/hashicorp/raft v1.8.0` 与 `github.com/lni/dragonboat/v4`，并单独测量
并发/并行扩展性与 FileStorage WAL。

- 实测日期：2026-11-05
- 环境：AMD AI Max 395，32 核，30 GiB，Ubuntu，Go 1.27.3 linux/amd64，
  `GOMAXPROCS=32`
- Dragonboat 版本：`v4.0.0-20250723143628-076c7f6497dc`（Pebble LogDB）
- 采样：`-benchtime=2s -count=3 -benchmem`，下表取中位数；WAL 表为 `-count=1`
- 负载：64 B 提案；等待状态机 apply 后计一次
- in-process 表使用内存存储与内存传输；Dragonboat 的 LogDB 是持久化 Pebble，
  `TMPDIR` 指向 `/dev/shm`，因此其 WAL 写入是内存文件系统上的真实编码/提交路径

## 1. In-process 对比

所有实现单组、100 ms 选举节奏、等待 apply。表中为 **ns/op**（越小越好）与
**allocs/op**。

| 场景 | ydx/raft | Dragonboat v4 | etcd raft v3.7 | hashicorp/raft v1.8 |
|---|---:|---:|---:|---:|
| 单节点顺序 | **1,779 ns** (7) | 11,981 ns (7) | 4,511 ns (39) | 3,812 ns (22) |
| 单节点并行 | **1,041 ns** (5) | 1,418 ns (2) | 3,407 ns (26) | 1,894 ns (15) |
| 三节点顺序 | **10,180 ns** (48) | 57,994 ns (106) | 14,188 ns (136) | 16,945 ns (109) |
| 三节点并行 | **2,342 ns** (12) | 3,278 ns (16) | 11,617 ns (129) | 3,051 ns (33) |

要点：

- 单节点顺序：ydx 比 etcd 快 **2.5×**、比 hashicorp 快 **2.1×**、比 Dragonboat
  快 **6.7×**；三节点顺序比 etcd 快 **1.4×**、比 hashicorp 快 **1.7×**。
- 三节点并行：ydx 比 Dragonboat 快 **1.4×**、比 hashicorp 快 **1.3×**、比 etcd
  快 **5.0×**；单节点并行比 Dragonboat 快 **1.4×**。
- ydx 的每提案分配数全面最低（单节点 5–7；三节点 12 vs 16–136）。
- Dragonboat 单节点顺序受 Pebble WAL 提交影响（12 µs）；其三节点并行在 tmpfs 上
  表现良好。ydx 的 FileStorage 在 tmpfs 上的三节点并行约 2.6–2.7 µs（见 WAL 节），
  与内存存储差距很小。

## 2. 并发与并行

### 2.1 流水线提案（单组三节点）

32 个 worker，每个保持 16 个在途提案，期间每 100k 条自动快照：

| 实现 | 聚合吞吐 |
|---|---:|
| ydx/raft（内存存储、内存传输） | **2.16M ops/s**（5,000,000 条 / 2.3 s） |

流水线把每批平均提案数从约 5 提升到约 30，摊销了持久化、复制、apply 与 Future
唤醒成本。

### 2.2 客户端并发扩展（单组三节点）

固定 32 核，增加并发客户端（`GOMAXPROCS` 即 worker 数）：

| 客户端并发 | ns/op | 聚合吞吐 |
|---:|---:|---:|
| 16 | 3,393 | 295k ops/s |
| 32 | 2,180 | 459k ops/s |
| 64 | 1,621 | 617k ops/s |
| 128 | 1,252 | 799k ops/s |
| 256 | 1,200 | 833k ops/s |
| 256 + `MaxBatchEntries=512` | **1,127** | **887k ops/s** |

单组吞吐随并发近线性增长到 128–256 客户端；峰值受单组事件循环与 apply 串行化
限制，继续增加客户端只会增加排队。

### 2.3 多组并行（NodeHost）

3 节点 NodeHost 集群，组数增加时每组客户端并发保持 32（`SetParallelism(groups)`）：

| 组数 | ns/op | 聚合吞吐 |
|---:|---:|---:|
| 1 | 2,433 | 411k ops/s |
| 2 | 1,546 | 647k ops/s |
| 4 | 1,054 | 949k ops/s |
| 8 | **974** | **1.027M ops/s** |
| 16 | 1,111 | 900k ops/s |

组是独立的 Raft 实例，各有事件循环/apply/WAL；8 组达到 1.03M ops/s，是单组的
2.5×。16 组时 32 核已饱和并开始下降。多组用于**故障隔离与水平扩展**，而不是让
单组突破状态机串行应用的上限。

### 2.4 本轮并发优化

- 提案入口改为 64 分片锁队列 + 位图就绪索引 + 每 P 随机选片，替代单通道；
  生产者在短锁下追加，事件循环批量取走。
- 同步 `Propose` 复用 Future 与 proposal 对象，消除每个提案的通道/结构体分配。
- `Future.Wait` 先非阻塞接收，已完成流水线提案不再进入多路 select。
- 控制平面独立高优先级队列：心跳/选举/领导权转移/快照不再排在复制积压之后。
- 快照传输中的过时 AppendEntries 响应被忽略，避免跟随者被重新拉回普通复制而
  饿死快照（修复高负载下 Future 不完成）。
- 分组多路复用使用不可变处理器快照，逐消息分发不加锁。
- Future 存储 64 分片；被同索引提案取代时显式失败旧 Future；停机时排空提案队列。
- apply 通知器无等待者时不做通道分配。
- 追随者确认路径在切片前限制到 `MaxBatchEntries`，避免扫描整段日志尾部。

## 3. WAL 与持久化

### 3.1 FileStorage 直接写入（NVMe ext4）

`BenchmarkYdxFileStoragePersist`，64 B 负载：

| 模式 | 批量 | ns/op | 有效带宽 |
|---|---:|---:|---:|
| NoSync | 1 | 586 | 109 MB/s |
| NoSync | 32 | 1,271 | 1.61 GB/s |
| NoSync | 128 | 3,049 | **2.69 GB/s** |
| fsync | 1 | 993,457 | 0.06 MB/s |
| fsync | 32 | 884,105 | 2.32 MB/s |
| fsync | 128 | 908,633 | 9.02 MB/s |

tmpfs 上 fsync 是空操作，NoSync 与 fsync 均约 2.0 µs/128 条（4.1 GB/s），说明
编码/写入路径本身不是瓶颈；NVMe 上的 ~0.9 ms 是设备 `fdatasync` 成本。

### 3.2 组提交窗口

三节点 FileStorage、NVMe、32 个并发客户端、`PersistBatchDelay`：

| 窗口 | ns/op | 聚合吞吐 |
|---|---:|---:|
| 0（仅合并已排队请求） | ~124,000 | ~8.1k ops/s |
| 25 µs | 101,684 | 9.8k ops/s |
| 50 µs | 100,459 | 10.0k ops/s |
| 100 µs | **95,811** | **10.4k ops/s** |
| 250 µs | 100,937 | 9.9k ops/s |
| 500 µs | 104,651 | 9.6k ops/s |

窗口只延迟持久化确认，不阻塞 Raft 事件循环；默认 0，fsync 主导的部署可设
50–100 µs。

### 3.3 本轮 WAL 优化

- WAL 记录一次 `write` 写出（头 + 类型 + 负载），不再三次系统调用。
- Linux 使用 `fdatasync`（不支持时回退 `fsync`）；新分段创建后同步目录项。
- 持久化循环复用请求数组；单请求走无额外切片分配的快速路径。
- 分组提交把并发请求合并为一次 fsync；`PersistBatchDelay` 提供可选窗口。

## 4. 跨主机 3 节点 TCP（主线网络）

3 台主机，`TickInterval=100ms`、心跳 2、选举 10、`MaxBatchEntries=128`、
`MaxInflightMsgs=128`、FileStorage `NoSync`、32 B 负载、50,000 提案 / 128 并发：

| 传输 / 持久化 | 中位吞吐 | p50 | p99 |
|---|---:|---:|---:|
| TCP over RoCE NIC / NoSync | 516k ops/s（3 轮 446k–603k） | 190 µs | 0.95 ms |
| TCP over RoCE NIC / fsync | 57.1k ops/s（2 轮 50.5k–57.1k） | 2.01 ms | 3.62 ms |

RDMA 传输已由 gordma 切换到 `ydx/rdma`（purego 加载 libibverbs，无 cgo）。同一
3 节点环境、NoSync、20,000 提案 / 128 并发：**409k ops/s**，p50 **282 µs**，
p99 **718 µs**，无错误；256 KiB 提案经自动分块/重组提交成功，SIGTERM 可优雅关闭。
RDMA 数据面为 libibverbs SEND/RECV，TCP 仅用于队列对参数交换。历史 gordma 数据
（verbs 64 B 同步 RTT 19.7 µs、4 KiB 729 MB/s）保留在仓库历史中。

## 5. 故障恢复实测（3 节点 TCP，NoSync）

- 领导者节点 2 上已提交 `fo=before`（index 3）。
- `kill -9` 领导者进程；节点 3/4 在 **517 ms** 内选出新领导者（节点 4，term 3）。
- 新领导者提交 `fo=after`（index 5），两个存活节点均读取到 `after`。
- 以同一 `FileStorage` 目录重启节点 2；它作为 follower 追平到 commit/applied
  index 5，读取到 `after`。
- 同一轮 `go test -race` 覆盖分区、Check-Quorum、领导者转移、快照追赶与重启。

### 5.1 选举故障转移（内存传输）

`BenchmarkYdxElectionFailover` 关闭当前领导者并等待另一个节点成为领导者；使用
`TickInterval=1ms`、`ElectionTicks=8`（8–16ms 超时窗口），另用 1ms 延迟存储模拟
fsync。Windows/i9-10980HK、3 次迭代，仅作趋势参考：

| voter 数 | 内存存储 | 模拟 1ms 持久化 |
|---:|---:|---:|
| 3 | 13.7 ms | 19.3 ms |
| 5 | 12.3 ms | 13.3 ms |
| 9 | 12.3 ms | 13.0 ms |
| 25 | 11.7 ms | 13.3 ms |
| 51 | 11.3 ms | 12.0 ms |
| 101 | 11.0 ms | 12.0 ms |

25 个以上 voter 默认启用有界 pre-vote 扇出；候选者自投票持久化与投票扇出、
领导者 no-op 持久化与复制分别重叠，因此 1ms 持久化只增加约 0–5ms；投票者响应前
的持久化仍在关键路径。算法细节见 [`raft/ELECTION.md`](../../raft/ELECTION.md)。

## 6. 复现

```bash
cd benchmarks/raft
# 发布前用仓库外临时 go.work，或开发期临时 replace 指向 ../../raft
TMPDIR=/dev/shm GOWORK=off GOMAXPROCS=32 \
  go test -run '^$' -bench . -benchmem -benchtime=2s -count=3
```

- WAL 磁盘数据：把 `TMPDIR` 指向目标文件系统的空目录，运行
  `-bench 'YdxFileStoragePersist|YdxThreeNodeGroupCommit'`。
- 多组：`-bench 'YdxNodeHostGroups'`。
- 流水线：`-bench 'YdxThreeNodePipelined' -benchtime=5000000x`。
- 客户端扩展：`-cpu 16,32,64,128,256 -bench 'YdxThreeNodeParallel'`。
- 依赖：etcd raft v3.7.0、hashicorp/raft v1.8.0、Dragonboat v4；Dragonboat 使用
  默认 Pebble LogDB。
