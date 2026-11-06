# Raft 选主算法与延迟分析

本文分析 `ydx/raft` 的选举路径、可优化的关键路径，以及高并发/大节点数下哪些部分可以并行、哪些不能并行。实现以 Raft 论文和 etcd 的 pre-vote 语义为边界：**任何优化都不得降低安全性**。

## 1. 当前算法

一次无故障领导者变更的路径：

1. 跟随者在 `[ElectionTicks, 2*ElectionTicks)` 个 tick 后发起 pre-vote。
2. pre-vote 只比较任期、日志新旧和领导租约，不改变本地任期、不持久化；得到两个投票集合的多数后进入正式选举。
3. 候选者任期 `+1`、自投票，持久化 `term/vote`，向所有投票成员并发发送 `MsgVote`。
4. 投票者校验任期、日志新旧、每个任期只投一票，并在响应前持久化 `term/vote`。
5. 候选者收到多数选票后成为领导者，追加当前任期 no-op，持久化后复制；no-op 在多数副本持久化后提交。
6. 新领导者的 AppendEntries 重置跟随者选举计时器。

安全性依赖：任期单调、每个任期至多一票、日志新旧比较、投票与硬状态先持久化后响应、领导者只能提交当前任期日志项。这些约束没有被并行化绕过。

## 2. 延迟构成

近似关键路径：

```text
T_failover
  ≈ T_timeout
  + RTT(prevote request/response)
  + max(P_candidate,
        RTT(vote request) + P_voter + RTT(vote response))
  + max(P_leader_noop,
        RTT(append no-op) + P_follower)
  + commit/apply
```

其中 `P_*` 是一次 fsync/fdatasync 的尾延迟。`T_timeout` 通常占主导；在低延迟局域网里，存储持久化是第二大项。

## 3. 高并发/大节点数的瓶颈

- **超时量化与分裂投票**：默认 `TickInterval=100ms`、`ElectionTicks=10`，随机超时只有 10 个离散值，100ms tick 相位提供有限抖动。节点数增大时，同一超时档位的多个节点可能同时竞选，增加分裂投票和重试。
- **fsync 在关键路径**：候选者、投票者、新领导者 no-op 各有一次持久化；投票者那次无法并行化。
- **扇出 O(N)**：每个候选者向所有投票者发消息，选票计数和传输开销随 N 增长；实际只需要多数。
- **pre-vote 的额外 RTT**：它换来的是不被分区节点打断健康领导者，不能无条件删除。
- **多组选举**：`NodeHost` 的每个 group 有独立事件循环和 WAL，天然并行；跨 group 不需要共享选举状态。

## 4. 已实现的优化

### 4.1 候选者持久化与投票扇出重叠

`startVote` 在发起 `persistHardState` 后立即向所有投票者发送 `MsgVote`，不再等待 fsync 完成。安全性由 `selfVoteDurable` 门控：

- 自投票在硬状态持久化成功后才计入 `votes`；
- 只有 `selfVoteDurable && hasQuorum(votes)` 才执行 `becomeLeader`；
- 持久化失败或期间收到更高任期时，候选者不会成为领导者。

即使进程在持久化完成前崩溃，本次候选资格丢失，本节点不会在该任期执行领导者动作；其他节点对本轮候选的授权可能保留，但不会产生两个同任期、都已完成自投票持久化的领导者。若它已经执行过领导者动作，其 `term/vote` 必然已经持久化。

### 4.2 领导者 no-op 复制与本地持久化重叠

`becomeLeader` 追加 no-op 后立即 `broadcastAppend`，再等待本地持久化。领导者计算提交时使用 `persistedIndex`，本地 no-op 未持久化前不会被计入多数，因此不会提前提交；但跟随者可以在此期间持久化并响应，且选举计时器立即被重置。这把领导者的一次 fsync 与网络往返重叠。

同时，新领导者在本任期日志项提交前不会直接服务 `ReadIndex`：本地与转发的读会分别按 `MaxPendingReads` 暂存（零值按 `MessageQueue/8` 推导，范围 256–4096），提交推进后统一放行。否则新领导者可能尚未获知集群已提交索引，返回过期索引。领导权丢失或节点停止时这些读会立即失败。

该上限是背压参数，不是可并行计算出的“最优值”：可暂存的读数量由外部调用并发和消息队列容量决定，而待处理队列属于单线程 Raft 事件循环。并行计算上限只会引入额外同步，且无法改变放行时仍需串行维护 `readRound` 的事实；因此采用容量推导 + 可配置上限，释放时批量处理。

### 4.3 细粒度选举 timer

选举不再由 tick 边界触发。每个节点维护一个可复用的墙钟 `time.Timer`，超时值
为 `随机 tick 数 × TickInterval + [0, TickInterval)` 的纳秒级抖动，覆盖原来的
`[E,2E)` 窗口但不再只有 `E` 个量化档位。心跳/追加/投票重置同一个 timer，不为每条
AppendEntries 分配新 timer；旧 timer 事件通过当前 deadline 判定并丢弃。

### 4.4 优先级 stagger

`ElectionStagger > 0` 时，节点按 voter ID 升序排名，延迟增加
`min(rank*ElectionStagger, baseTimeout)`。低 ID 节点先竞选，减少大集群同一超时
窗口内的并发候选人；延迟上限避免首选节点故障时无限拖慢。排名由复制的 voter
集合推导，不需要额外传播优先级字段。

### 4.5 有界 pre-vote 扇出

voter 数超过 `PreVoteSubsetThreshold`（默认 16）时，首轮只联系“每个投票集合的
多数 + `PreVoteSubsetExtra`（默认 4）”个节点。首轮未达到多数且所有目标已响应时
立即扩展；若有目标无响应，则在下一个 tick 扩展。未联系的节点只在需要时收到
pre-vote，减少超大集群的 O(N) 首轮扇出。

### 4.6 既有优化

- 控制消息优先出站，选举/心跳不会被大批复制消息阻塞。
- pre-vote 带领导粘性；租约读在 `DisablePreVote` 或领导权转移期间禁用。
- 投票请求并行发送到所有投票者，响应到达即计数，不等待慢节点。
- 多组 `NodeHost` 选举彼此独立并行。

## 5. 哪些“并行选主”不可行

- **不能把 pre-vote 与正式 vote 并行发送**：`MsgVote` 携带更高任期，接收者会先推进任期/降级，再判断是否授权；这会绕过 pre-vote 对健康领导者的保护。
- **不能由某个节点并行“计算全局选举结果”**：Raft 的选票是各节点本地持久化状态，不存在可安全聚合的全局视图；引入协调者会形成新的单点/一致性问题。
- **不能省掉投票者的持久化**：响应前不落盘会在崩溃后允许同任期二次投票。
- **不能按节点优先级直接指定领导者**：在异步网络中无法区分“首选节点宕机”和“网络分区”，需要超时兜底；可以作为可选偏好，但不能替代随机超时和多数投票。

可并行的部分是**同一轮内的扇出、持久化与网络重叠、以及多个 Raft group 的独立选举**；这些已经利用。

## 6. 参数建议

| 场景 | TickInterval | ElectionTicks | HeartbeatTicks | 说明 |
|---|---:|---:|---:|---|
| 同机房/低延迟 LAN | 10–20ms | 5–10 | 1 | 要求 p99 RTT 远小于 tick；确保 fsync 设备稳定 |
| 一般生产 | 100ms | 10 | 1 | 默认值，网络抖动容忍度较好 |
| 跨地域/WAN | 200–500ms | 10–20 | 1–2 | 避免抖动触发误选举 |

大集群可设置 `ElectionStagger`（例如 1ms）偏好低 ID 节点；voter 数很大时保留
默认 `PreVoteSubsetThreshold=16` / `PreVoteSubsetExtra=4`，让首轮只联系多数加少量
余量。仍建议控制**投票成员数**（3/5/7 个 voter），其余节点作为 learner；Raft 的
选举和提交成本随 voter 数增长，learner 不参与 quorum。

`MaxPendingReads` 是新 leader 提交当前任期前暂存读的上限，零值按
`max(256, min(4096, MessageQueue/8))` 推导；它不是并行度参数。

## 7. 可继续演进的方向

- 允许配置显式 `ElectionPriority` 并由成员配置传播优先级，替代当前的 voter ID
  排名；需要扩展 ConfState 线格式与快照兼容性。
- 对正式 vote 也做“多数子集优先、超时扩展”的扇出；正式投票受任期与持久化约束，
  需要单独验证崩溃恢复与旧响应场景。
- 基于存储能力的持久化流水线（例如批量 fsync 投票），但仍需保证响应前持久化。
- 将 ReadIndex 暂存释放进一步分片到事件循环的多个批次，降低一次性释放数千个
  等待者的尾延迟；状态仍必须由单线程事件循环维护。

## 8. 实测

`benchmarks/raft/election_bench_test.go` 在内存传输、`TickInterval=1ms`、`ElectionTicks=8`、关闭旧领导者后测量到新领导者出现的墙钟时间（Windows/i9-10980HK，3 次迭代，仅作趋势参考）：

| voter 数 | 内存存储 | 模拟 1ms 持久化 |
|---:|---:|---:|
| 3 | 13.7 ms | 19.3 ms |
| 5 | 12.3 ms | 13.3 ms |
| 9 | 12.3 ms | 13.0 ms |
| 25 | 11.7 ms | 13.3 ms |
| 51 | 11.3 ms | 12.0 ms |
| 101 | 11.0 ms | 12.0 ms |

模拟持久化只给故障转移增加约 0–4ms，说明候选者自投票 fsync 与领导者 no-op fsync 已大部分被网络轮次和后续流程覆盖；投票者响应前的 fsync 仍在关键路径上。当前数据受随机超时和调度噪声影响；主要结论是故障转移时间接近 `ElectionTicks * TickInterval`，网络与 fsync 的优化只在存储/网络延迟占主导时体现。正式对比应使用 `benchstat` 和真实 TCP/RDMA 环境。
