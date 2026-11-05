# ydx/raft — 高性能强一致 Raft

`github.com/shibingli/ydx/raft` 是 ydx 的可独立引用 Raft 模块：单组 Raft 核心 +
持久化 WAL + 快照 + 联合共识成员变更 + 线性一致读 + TCP/HTTP/RDMA 传输。默认构建
为纯 Go、无 cgo；RDMA 通过 `-tags rdma` 可选启用。

- 源码：<https://github.com/shibingli/ydx/tree/main/raft>
- 协议：Apache-2.0
- Go 版本：1.27.3
- 发布标签：`raft/v0.1.0`

## 功能与特性

| 能力 | ydx/raft | 说明 |
|---|---|---|
| 领导者选举 | ✅ | 随机化选举超时、优先级一致的日志新旧判定 |
| Pre-Vote | ✅ | 默认开启，避免分区节点打扰健康领导者 |
| Check-Quorum | ✅ | 领导者失联法定人数后主动降级 |
| 日志复制 | ✅ | 批量、流水线、字节级 in-flight 流控 |
| 快照 | ✅ | 自动/手动快照、安装、压缩、CRC32C + SHA-256 校验 |
| 成员变更 | ✅ | **联合共识（joint consensus）**、一次一个变更、自动 LeaveJoint |
| 学习者 | ✅ | AddLearner / Promote，不参与投票 |
| 领导者转移 | ✅ | 追平后 TimeoutNow，新领导者立即竞选 |
| 线性一致读 | ✅ | ReadIndex（领导者与跟随者转发）、租约读 |
| 持久化 WAL | ✅ | 分段、组提交、撕裂写检测、快照标记恢复 |
| 传输 | ✅ | 内存、TCP、HTTP、可选 RDMA |
| 安全 | ✅ | TCP/HTTP 可配 TLS；TCP/HTTP/RDMA 可配 HMAC-SHA256 |
| 可观测性 | ✅ | `Stats` 无锁计数器、`Status` 事件循环快照 |
| 多组 Raft | ✅ | `NodeHost` 共享传输/节点身份，每组独立 WAL/FSM/选举/快照 |
| 并发/并行 | ✅ | 控制面优先级队列、组提交窗口、流水线提案、多组并行 |
| 观测与调优 | ✅ | `Stats`/`Status`、`PersistBatchDelay`、批量/inflight/队列参数 |

与主流实现的定位对比：

| 项目 | 核心定位 | 联合共识 | ReadIndex | 内置 WAL | 内置传输 | RDMA |
|---|---|---|---|---|---|---|
| **ydx/raft** | 完整单组实现 + 运维设施 | ✅ | ✅（含跟随者转发） | ✅ | TCP / HTTP / 可选 RDMA | ✅（可选构建） |
| etcd raft v3.7 | 共识核心库 | ✅ | ✅ | ❌ | ❌ | ❌ |
| hashicorp/raft v1.8 | FSM 单组框架 | ❌ | ❌ | ✅（Bolt/MDB/WAL） | TCP | ❌ |
| Dragonboat v4 | 多组框架 | ❌ | ✅ | ✅ | 内置 + 自定义 | ❌ |

> etcd raft 与 hashicorp/raft 的详细特性来源见各自官方仓库；本表只列与本模块选型
> 直接相关的差异。

## 快速开始

### 单节点

```go
store := raft.NewMemStorage()
node, err := raft.New(raft.Config{
    ID:      1,
    Storage: store,
    FSM:     fsm,
})
if err != nil {
    return err
}
defer node.Close()

res, err := node.Propose(ctx, []byte("set key=value"))
```

### 三节点 TCP 集群

```go
tr, err := raft.NewTCPTransport(raft.TCPTransportOptions{
    ListenAddr: "192.168.2.2:22102",
    TLSConfig:  tlsConfig,        // 可选：TLS/mTLS
    SharedSecret: sharedSecret,   // 可选：帧级 HMAC-SHA256
})
if err != nil {
    return err
}
peers := []raft.Peer{
    {ID: 1, Addr: "192.168.2.2:22102"},
    {ID: 2, Addr: "192.168.2.3:22102"},
    {ID: 3, Addr: "192.168.2.4:22102"},
}
node, err := raft.New(raft.Config{
    ID:        1,
    Peers:     peers,
    Storage:   store,             // 推荐 FileStorage
    FSM:       fsm,
    Transport: tr,
})
```

每个节点使用相同的 `Peers`；`Config.Peers` 只在全新集群首次启动时用于初始化，
已有日志/快照时忽略。

### HTTP 传输（YD 路由优先 / 原生 net/http 兼容）

```go
tr, _ := raft.NewHTTPTransport(raft.HTTPTransportOptions{
    ID:           1,
    Path:         "/raft/message",
    SharedSecret: sharedSecret,
})

// YD 路由（一等公民）：共享路由器的中间件、认证与观测链
r := router.New()
if err := ydrouter.Mount(r, "/raft/message", tr); err != nil {
    return err
}

// 原生 net/http 兼容入口
http.Handle("/raft/message", tr.Handler())
```

`raft/ydrouter` 是独立子模块，核心 `raft` 不依赖 `ydx/router`；不使用 YD 路由的
应用只依赖 `raft` 并直接挂载 `tr.Handler()`。HTTP 对端地址使用基础 URL，例如
`http://192.168.2.2:23102`。TLS 由外层 HTTP 服务器/客户端提供；`SharedSecret`
负责消息认证。

### RDMA（可选）

真实 RDMA 在 Linux/amd64 或 Linux/arm64 + `rdma` 构建标签下编译，使用
[`ydx/rdma`](../rdma)：经 purego 在运行时加载 `libibverbs`，**不需要 cgo**；系统
需安装 `libibverbs.so.1`。默认纯 Go 构建请求 RDMA 会返回 `raft.ErrUnsupported`。
大于一个注册槽位的流帧会自动分块，快照和大批次无需注册超大槽位。

```bash
CGO_ENABLED=0 go build -tags rdma ./...
```

```go
cfg.RDMA = true
cfg.RDMAOptions = raft.RDMATransportOptions{
    ListenAddr:   "192.168.2.2:22102",
    Device:       "mlx5_0", // 可选，空则自动选择
    BufferSize:   64 << 10, // 分块/注册槽位，默认 64 KiB
    SharedSecret: sharedSecret,
}
```

`Config.Transport` 显式设置时优先于 `Config.RDMA`。同一集群的所有对端必须使用
相同的 `BufferSize`，并保证 `QueueDepth` 能容纳一个发送批次（32 个分块）；RDMA
消息不能超过接收方注册的槽位。RDMA 链路本身不加密；需要保密性时使用
IPsec/MACsec，或改用启用 TLS 的 TCP/HTTP 传输。

## 一致性语义

- `Propose` 成功返回时，日志项已被多数派提交并在本地状态机应用。
- `Propose` 在领导权变化后可能返回 `ErrLeadershipLost`：命令可能已提交，也可能
  没有；幂等命令可安全重试。提案入口满时返回 `ErrBusy`，调用方应施加背压后重试。
- `ReadIndex` 返回与调用线性一致的已提交索引；读取状态机前必须
  `WaitApplied(index)`（或直接使用 `Barrier`）。
- 领导者只有在当前任期已有提交日志项、且租约有效时才直接服务读；否则发起心跳
  法定人数确认。跟随者自动把 `ReadIndex` 转发给领导者，并等待本地应用追上。
- 默认关闭“任意本地读”；`ReadIndex`/`Barrier` 是唯一的线性一致读入口。

## 成员变更

```go
node.AddLearner(ctx, 4, "192.168.2.5:22102")
node.Promote(ctx, 4)
node.AddNode(ctx, 4, "192.168.2.5:22102")
node.RemoveNode(ctx, 4)
node.TransferLeader(ctx, 2)
```

- 投票成员变更走联合共识：旧配置多数 + 新配置多数同时满足才提交。
- 同一时间只允许一个成员变更；变更过程中新变更返回 `ErrConfChangeInProgress`。
- 领导者被移除时，会先完成 LeaveJoint 提交再主动降级；被移除节点会在收到最终
  配置后停止竞选。
- 学习者不参与投票，可用于预热/只读副本；提升时自动走联合共识。

## 持久化与恢复

`FileStorage` 目录布局：

```text
<dir>/
  wal/00000000000000000001.wal
  snapshots/00000000000000001234-00000000000000000009.snap
```

- WAL 记录带长度、CRC32C、类型；尾部撕裂写会被安全截断。
- 快照文件包含索引、任期、配置、数据长度、CRC32C 与 SHA-256。
- 快照先落盘，再写 WAL 标记；恢复只信任带标记的快照，避免“快照已写但未提交”
  的悬空状态。
- `InstallSnapshot` 标记会清除旧日志项；本地压缩快照保留快照之后的日志尾。
- `FileStorageOptions.NoSync` 只用于临时测试/基准；生产必须保持 fsync。

## 性能

以下为 2026-11-05 的单机 32 核 Linux 实测（AMD AI Max 395，30 GiB，Go 1.27.3，
`GOMAXPROCS=32`），64 B 提案、100 ms 选举节奏、等待 apply；跨主机结果使用 3 台
同型号主机与 TCP。完整方法与原始数据见
[`benchmarks/raft`](../benchmarks/raft/README.md)。

### 单组 in-process（ns/op，越小越好，括号为 allocs/op）

| 场景 | ydx/raft | Dragonboat v4 | etcd raft v3.7 | hashicorp/raft v1.8 |
|---|---:|---:|---:|---:|
| 单节点顺序 | **1,779** (7) | 11,981 (7) | 4,511 (39) | 3,812 (22) |
| 单节点并行 | **1,041** (5) | 1,418 (2) | 3,407 (26) | 1,894 (15) |
| 三节点顺序 | **10,180** (48) | 57,994 (106) | 14,188 (136) | 16,945 (109) |
| 三节点并行 | **2,342** (12) | 3,278 (16) | 11,617 (129) | 3,051 (33) |

- 单节点顺序比 etcd 快 2.5×、比 hashicorp 快 2.1×、比 Dragonboat 快 6.7×。
- 三节点并行比 Dragonboat 快 1.4×、比 hashicorp 快 1.3×、比 etcd 快 5.0×；
  每提案分配数最低。
- Dragonboat 的对比使用其默认 Pebble LogDB（tmpfs 上），比纯内存存储更重；
  ydx 的 FileStorage 三节点并行在 tmpfs 上约 2.6–2.7 µs，与内存存储差距很小。

### 并发与并行

- 32 个客户端各保持 16 个在途提案（流水线）时，三节点单组达到 **2.16M ops/s**。
- 单组三节点随客户端并发近线性扩展：32 客户端约 **459k ops/s**、128 客户端
  **799k ops/s**、256 客户端 **833k ops/s**；`MaxBatchEntries=512` 时 256 客户端
  达 **887k ops/s**。
- 3 节点 NodeHost 多组，每组客户端并发保持 32 时，聚合吞吐从 1 组的 **411k ops/s**
  提升到 8 组的 **1.027M ops/s**（2.5×）。多组用于故障隔离与水平扩展；单组状态机
  apply 仍按序串行。
- 提案入口使用 64 分片锁队列 + 位图就绪索引；同步 Propose 复用 Future/proposal；
  控制平面（选举/心跳/领导权转移/快照）走独立高优先级队列；复制积压不会饿死
  心跳或快照。

### WAL 与持久化（NVMe ext4）

| 模式 | 批量 | ns/op | 有效带宽 |
|---|---:|---:|---:|
| NoSync | 1 | 586 | 109 MB/s |
| NoSync | 128 | 3,049 | **2.69 GB/s** |
| fsync | 1 | 993,457 | 0.06 MB/s |
| fsync | 128 | 908,633 | 9.02 MB/s |

- WAL 记录一次 `write` 写出；Linux 使用 `fdatasync`；新分段同步目录项。
- 三节点 FileStorage + NVMe + 32 并发客户端：默认组提交约 **8.1k ops/s**，设置
  `PersistBatchDelay=100µs` 后约 **10.4k ops/s**；窗口只延迟持久化确认，不阻塞
  事件循环。默认 0，fsync 主导的部署可设 50–100 µs。
- tmpfs 上 fsync 是空操作，NoSync 与 fsync 均约 2.0 µs/128 条（4.1 GB/s），
  说明编码/写入路径本身不是瓶颈。

### 跨主机 3 节点 TCP

`TickInterval=100ms`、心跳 2、选举 10、`MaxBatchEntries=128`、
`MaxInflightMsgs=128`、32 B 负载、50,000 提案 / 128 并发：

| 持久化 | 中位吞吐 | p50 | p99 |
|---|---:|---:|---:|
| FileStorage NoSync | 516k ops/s（3 轮 446k–603k） | 190 µs | 0.95 ms |
| FileStorage fsync | 57.1k ops/s（2 轮 50.5k–57.1k） | 2.01 ms | 3.62 ms |

RDMA 传输仍作为可选构建保留（`-tags rdma`），本轮主线优化不以 RDMA 为目标；
其历史对比数据见 benchmarks 目录的提交记录。

## 测试

```bash
GOWORK=off go build ./...
GOWORK=off go vet ./...
GOWORK=off CGO_ENABLED=1 CC=clang go test ./... -race
```

测试覆盖：选举/预投票（含隔离节点不提升任期）、分区与 Check-Quorum、日志冲突
回退、批量/流水线并发提案、64 分片提案入口与对象复用、快照创建/安装/压缩/高负载
快照传输、带快照重启、WAL 撕裂写/损坏恢复/多分段轮转、持久化组提交窗口、联合
共识增删/提升/移除、领导者转移、领导者与跟随者 ReadIndex、HTTP/TCP 传输、编解码
fuzz、RDMA 不可用时的显式错误。仓库级守卫见 `repotest`。

## 多组 Raft（NodeHost）

`NodeHost` 在一个成员上运行多个 Raft 组：所有组共享节点身份与基础传输，消息按
`GroupID` 多路复用；每个组拥有独立的 WAL/快照目录、FSM、日志、选举状态、复制进度
与 apply 协程。

```go
host, err := raft.NewNodeHost(raft.NodeHostConfig{
    ID:        1,
    Transport: tcpTransport, // 共享基础传输
    Storage:   raft.FileStorageFactory("/data/raft", raft.FileStorageOptions{}),
    FSM: func(group raft.GroupID) (raft.FSM, error) {
        return openStateMachine(group) // 每个组独立状态机
    },
})
if err != nil {
    return err
}
defer host.Close()

peers := []raft.Peer{
    {ID: 1, Addr: "192.168.2.2:22102"},
    {ID: 2, Addr: "192.168.2.3:22102"},
    {ID: 3, Addr: "192.168.2.4:22102"},
}
if _, err := host.StartGroup(raft.GroupConfig{ID: 10, Peers: peers}); err != nil {
    return err
}
res, err := host.Propose(ctx, 10, []byte("set key=value"))
```

- 组 ID 必须非零且稳定；`ListGroups("/data/raft")` 可扫描已持久化组，配合
  `StartGroup` 完成重启恢复。
- `HTTPTransport`/`TCPTransport`/`RDMA` 的消息体携带 `GroupID`；同一节点只需一个
  监听端口即可承载任意多个组。
- 每个组独立选举、独立快照、独立成员变更；一个组不可用不会阻塞其它组。
- 每组的 `Node` 各有独立事件循环/apply 协程；大量组可共享基础传输与磁盘目录，
  但 CPU 调度由 Go runtime 负责。

## 限制与边界

- 每组使用独立 `Node`（独立事件循环与 apply 协程）；极多小热组场景可将多个组
  绑定到同一 `NodeHost` 以共享传输与端口，但调度仍按组隔离。
- FSM 的 `Apply`/`Snapshot`/`Restore` 串行执行；慢 FSM 会增加 apply 延迟与内存
  占用，但不会阻塞心跳。
- 错误与日志文案不泄露口令、DSN、密钥或完整请求体。
- 快照编码为一个帧；RDMA 传输会按 `BufferSize` 自动分块重组，TCP/HTTP 受单帧
  上限约束（默认 64 MiB，可配置 `MaxFrameBytes`/`MaxBodyBytes`）。超大状态机在
  TCP/HTTP 上应调大上限或自行分块。

## 依赖与鸣谢

- `github.com/shibingli/ydx/errs`：哨兵错误与上下文包装。
- `github.com/shibingli/ydx/log`：结构化日志（可选注入）。
- `github.com/shibingli/ydx/rdma`（仅 `-tags rdma`）：纯 Go RDMA verbs 传输，
  经 purego 运行时加载 `libibverbs`；默认构建不启用、不需要 cgo。
- 设计参考：Ongaro & Ousterhout, *In Search of an Understandable Consensus
  Algorithm*；etcd raft、hashicorp/raft 的公开接口与测试实践。

## License

Apache-2.0，见仓库根目录 `LICENSE`。
