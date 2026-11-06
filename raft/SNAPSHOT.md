# 整状态快照与 fsync 性能分析

本文聚焦 `ydx/raft` 的整状态快照（FSM 全量镜像）与持久化 fsync 路径，说明当前实现、实测数据、已完成的异步优化以及后续可继续推进的方向。

## 1. 快照路径

一次本地全量快照包含：

1. apply 协程调用 `FSM.Snapshot()`，在暂停 apply 的窗口内生成完整 `[]byte`。
2. `handleSnapshotReady` 创建 `Snapshot{Index,Term,ConfState,Data}`。
3. `FileStorage` 将镜像写入快照目录：临时文件 → 写入数据 → 计算 CRC32C 与 SHA-256 → `fdatasync` → 原子 rename → 目录 fsync。
4. 追加一条小型 WAL 快照标记并 `fdatasync`；恢复只信任带标记的镜像。
5. 压缩 WAL、清理旧快照、发布 `latestSnapshot`，供落后跟随者追赶。

整状态快照的成本主要不在编码/校验，而在：

- `FSM.Snapshot()` 的序列化时间与整份镜像驻留内存。
- 镜像文件写入与 fsync。
- 快照标记 WAL fsync。
- 快照期间 WAL 提交不能被阻塞，否则提案延迟和提交吞吐同时下降。

## 2. fsync 路径盘点

| 路径 | 频率 | 当前措施 | 可否消除 |
|---|---|---|---|
| 选举 term/vote HardState | 选举时 | 组提交；先持久化后响应 | 不可，安全性要求 |
| 提案/追加 WAL | 每批提交 | 单次 write + `fdatasync`；组提交合并 | 不可，提交需持久 |
| 快照镜像文件 | 每 N 条 | 一次遍历 CRC/SHA；`fdatasync`；rename 后目录 fsync | 不可，恢复需要 |
| 快照 WAL 标记 | 每次快照 | 小型追加 + `fdatasync` | 不可，恢复只信任标记 |
| WAL 轮转/目录 | 每段 | 新段 fsync + 目录 fsync | 不可，崩溃一致性需要 |
| 快照删除/保留 | 每次快照 | 目录操作，通常不逐文件 fsync | 可继续优化清理策略 |

Linux 上 `syncFile` 使用 `fdatasync`，避免 fsync 的元数据日志开销；快照文件同样使用 `fdatasync`，随后对目录执行 fsync 以保证 rename 持久化。

## 3. 已完成的优化

### 3.1 大型快照镜像移出 WAL 持久化关键路径

`FileStorage` 实现了可选的延迟标记路径：

- `WriteSnapshotFile` 在独立 goroutine 中写镜像并 fsync，不持有存储互斥锁，也不占用 WAL persist 协程。
- 镜像 fsync 完成后，事件循环才分配新的持久序号，并向 WAL persist 协程排队一条**仅含元数据**的小标记。
- 标记与后续 WAL 批次仍按序 fsync；快照镜像大 fsync 与 WAL 组提交重叠。
- `InstallSnapshot` 仍走同步路径：其标记会重置旧日志，不能和镜像后持久化的日志项竞争。

`TestAsyncSnapshotDoesNotBlockProposals` 验证快照文件 fsync 被阻塞时，提案仍能提交和应用。

### 3.2 WAL 组提交

- 单个 WAL 批次一次 `write` 后一次 `fdatasync`。
- `PersistBatchDelay` 可开启额外组提交窗口；并发请求合并为一组，fsync 成本按批次数摊销。
- `wal.append` 复用记录缓冲区，避免每批重新分配。

### 3.3 快照文件读写

- 写入时用 `io.MultiWriter` 一次遍历同时计算 CRC32C 与 SHA-256，避免两次全量扫描。
- 读取时流式校验，按头部长度精确分配，不把整个文件先读入再复制。
- `FileStorage` 内存中只保留最新快照的 `Index/Term` 元数据；镜像数据通过文件发送或由调用方持有。
- `MemStorage` 持久化快照时直接接管不可变指针，不复制大负载。

### 3.4 快照追赶

- 本地压缩后内存保留 `SnapshotCatchUpEntries` 条已覆盖日志，略落后的跟随者用 AppendEntries 追赶，避免频繁整份快照传输。
- 快照超过传输帧上限时通过 `Status.Peers[].SnapshotError` 暴露，而不是静默重试。

### 3.5 标记与后续 WAL 批次合并 fsync

异步镜像完成后，事件循环分配的标记不再总是单独写一条记录。若持久化队列中紧跟着
从快照基点开始的连续日志项，`persistMarkerGroup` 把它们合并为一条 WAL 记录：

- 编码顺序保持标记在前、日志项在后；恢复先应用标记再追加剧志项。
- 合并后仍只有一次 `fdatasync`，每个本地快照少一次独立 fsync。
- 只有连续性可证明时才合并；存在索引缺口、另一个快照或标记时保持分开。
- 压缩（`Storage.Compact`）仍在合并写持久化后执行。

### 3.6 流式 FSM 与文件支持镜像

新增可选接口：

```go
type StreamingFSM interface {
    FSM
    SnapshotTo(w io.Writer) error
}
```

与 `FileStorage` 配合时：

- apply 协程创建临时镜像文件并调用 `SnapshotTo`，不再生成完整 `[]byte`。
- 临时文件写入只进入页缓存；头部写入、`fdatasync`、rename、目录 fsync 与 WAL
  标记都在事件循环之外的协程完成。
- 大镜像发布后只保留 `file`、`dataSize`、`dataOffset`；发送时按需读取。
- 小镜像或未启用分块时仍保留内存副本，避免单条 `MsgSnap` 在事件循环上读文件。
- 失败路径删除临时文件；停止时由 WaitGroup 保证定稿协程先结束，再关闭存储。
- `InstallSnapshot` 仍走内存镜像与同步持久化，保证整段旧日志重置的顺序。

### 3.7 分块快照传输

`Config.SnapshotChunkBytes > 0` 时，超过配置或传输帧上限的快照使用
`MsgSnapChunk` / `MsgSnapChunkResp`：

- 每条分块是独立传输批次，避免与其他控制消息合并后再次超过帧上限。
- 逐块确认：领导者只在收到当前块确认后发送下一块；丢失的块按跟随者报告的连续
  偏移重传。
- 最后一块的安装响应丢失时，领导者发送零长度探测消息；跟随者已安装则重发
  `MsgSnapResp`，未安装则从缺失偏移继续。
- 文件支持的镜像逐块 `ReadAt`/`Seek` 读取，领导者峰值内存仅为一块负载。
- 接收端一次性重组完整镜像，因此协议总上限仍为 256 MiB；分块解除的是传输帧上限。
- 分块消息是显式扩展，要求所有对端支持；默认 `SnapshotChunkBytes=0` 保持旧线格式。

### 3.8 独立快照目录

`FileStorageOptions.SnapshotDir` 可把镜像放到与 WAL 不同的卷：

- WAL 仍在 `Dir/wal`，锁仍在 `Dir/LOCK`。
- 镜像写入、fsync、rename 与目录同步全部作用于 `SnapshotDir`。
- 恢复仍通过 WAL 标记找到镜像；目录不同不影响关联。
- `SnapshotDir` 应由单个存储实例独占（锁不覆盖该目录）。

### 3.9 自适应组提交窗口

`PersistBatchDelay` 现在是基础窗口而非固定值。`persistWindow` 根据：

- 实测持久批次耗时的指数移动平均（目标窗口约为 fsync 耗时的一半）；
- 当前持久化队列深度（8/32 个排队请求触发 2×/4×）；

自适应扩大窗口，并限制在 `[base, min(8*base, 5ms)]`。零值仍完全关闭额外等待。
它只影响提交确认延迟，不阻塞事件循环。

### 3.10 WAL 向量写

Linux、Darwin、OpenBSD、illumos 上，大日志项批次使用 `writev` 从条目切片直接
写出：

- 记录头/元数据与条目头仍然编码到小缓冲区；条目负载不再复制进 WAL 缓冲区。
- 仅在负载 ≥64 KiB 且 iovec 数量 ≤512 时启用；小批次继续走单次缓冲写。
- Windows 等平台自动回退到原路径。
- 记录字节与旧编码逐字节一致，由 `TestWALRecordPartsMatchContiguous` 校验。

### 3.11 快照校验策略

`FileStorageOptions.SnapshotChecksum`：

- 默认 `SnapshotChecksumCRC32CSHA256`：版本 1，CRC32C + SHA-256。
- `SnapshotChecksumCRC32C`：版本 2，带校验标志字节，只写 CRC32C，32 字节 SHA
  字段保留为零；恢复仍校验 CRC，检测意外损坏。
- 读取同时支持版本 1 与版本 2，切换配置后旧文件仍可恢复。
- 代价是失去 SHA-256 的更强完整性/篡改检测，不改变崩溃一致性边界。

## 4. 实测（Windows/i9-10980HK，Go 1.27.3）

### WAL fsync

`benchmarks/raft/BenchmarkYdxFileStoragePersist`，1s 采样：

| 模式 | 批大小 | ns/op | 吞吐 |
|---|---:|---:|---:|
| sync | 1 | ~0.915 ms | 0.07 MB/s |
| sync | 32 | ~0.920 ms | 2.23 MB/s |
| sync | 128 | ~0.916 ms | 8.94 MB/s |
| nosync | 128 | ~11 µs | 747 MB/s |

单次 fsync 约 0.9 ms；批大小从 1 到 128 时 fsync 次数不变、有效吞吐随批量线性提升。这正是组提交的核心收益。

### 快照文件

| 场景 | 8 MiB |
|---|---:|
| 写入 sync | ~33.9 ms（约 247 MB/s） |
| 写入 nosync | ~31.2 ms（约 269 MB/s） |
| 读取并校验 | ~32.4 ms（约 259 MB/s） |
| 写入分配 | 47 allocs/op |
| 读取分配 | 69 allocs/op |

这些数值受本机磁盘与页缓存影响，仅用于比较路径；正式发布应使用 Linux NVMe 与 benchstat。

### 大日志项向量写

`BenchmarkYdxFileStorageLargeEntry`，NoSync，50 次迭代：

| 平台 / 路径 | 64 KiB | 256 KiB | 1 MiB | allocs/op |
|---|---:|---:|---:|---:|
| Windows 缓冲写 | 718 MB/s | 1.46 GB/s | 1.67 GB/s | 3.9–53 KB |
| WSL Linux `writev` | 3.2 GB/s | 4.0 GB/s | 3.6–5.0 GB/s | **156–159 B** |

不同文件系统的绝对带宽不可直接比较；关键是 `writev` 把每条大日志项的分配从复制
整条负载降到约 160 B 的记录头/元数据。fsync 开启时 Linux 单条 1 MiB 约
3.2–3.4 ms（约 300–330 MB/s），瓶颈回到设备同步。

## 5. 后续可继续优化的方向

1. **流式恢复**：增加可选的 `FSM.RestoreFrom(io.Reader)` 与分块落盘接收，让跟随者
   边收边写临时镜像，而不是在内存重组完整 256 MiB 负载；需要先校验后应用，或引入
   分块校验与临时文件校验。
2. **非分块大镜像的异步单条发送**：当前未启用分块的文件镜像会在事件循环上整体读取；
   可增加读取协程，把单条 `MsgSnap` 的加载移出事件循环。启用分块已避免该问题。
3. **分块读取移出事件循环**：`sendSnapshotChunk` 的文件读取仍在事件循环；可预热
   页缓存或增加专用读取协程，进一步降低超大分块（>8 MiB）对心跳的抖动。
4. **更大的分块重组上限**：当前接收端仍受 256 MiB 协议上限约束；可增加
   `MaxSnapshotBytes` 配置并把重组缓冲落到临时文件。
5. **mmap / 页对齐读取**：对只读镜像使用 mmap 或 `O_DIRECT` 对齐读取，减少一次
   内核到用户态复制；需要处理文件截断、页对齐和跨平台差异。
6. **快照镜像 writev**：镜像头部与负载已在一次 `write` 中写出；可评估 `writev`
   或 `copy_file_range` 对超大镜像的收益，但当前实测主要受 `fdatasync` 限制。
7. **独立快照目录的多实例锁**：当前锁只覆盖 `Dir`；若多个存储实例共享同一个
   `SnapshotDir`，需要额外的目录锁或配置校验。
8. **自适应快照间隔**：根据 WAL 增长率、恢复时间目标与状态大小动态选择
   `SnapshotEntries`，而不是固定条数。

## 6. 参数建议

- 生产启用 fsync；`NoSync` 仅用于基准/临时测试。
- 高并发提交优先增大批处理收益：`PersistBatchDelay` 可从 50–200µs 开始压测，观察
  p99 提案延迟与 fsync 次数；新的自适应窗口会在 fsync 较慢时自动向上扩展。
- 快照间隔 `SnapshotEntries` 过小会造成频繁整份镜像 fsync；过大则恢复时间和 WAL
  体积增加。按状态大小与可接受 RTO 选择。
- 大状态优先实现 `StreamingFSM.SnapshotTo`，并设置
  `SnapshotChunkBytes`（建议 1–8 MiB）；分块要求所有对端升级到支持
  `MsgSnapChunk` 的版本。
- 对 GB 级状态，优先采用流式快照、分块传输与独立快照磁盘；仅 CRC 校验可在 CPU
  成为瓶颈时启用，但会失去 SHA-256 的更强完整性。

## 7. 新增配置速查

| 配置 | 默认 | 作用 |
|---|---|---|
| `Config.SnapshotChunkBytes` | 0 | 启用分块快照，值为单块目标负载字节数 |
| `GroupConfig.SnapshotChunkBytes` | 0 | NodeHost 组的对应配置 |
| `Config.PersistBatchDelay` | 0 | 组提交基础窗口；零关闭，实际窗口自适应 |
| `FileStorageOptions.SnapshotDir` | 空 | 快照镜像独立目录，空为 `Dir/snapshots` |
| `FileStorageOptions.SnapshotChecksum` | CRC32C+SHA256 | 选择仅 CRC32C 的 v2 镜像 |
| `FileStorageOptions.SnapshotKeep` | 2 | 保留的快照文件数量 |
| `Config.SnapshotCatchUpEntries` | 256 | 内存中保留的追赶日志条数 |

兼容性提示：`SnapshotChunkBytes > 0` 会发送新的 `MsgSnapChunk` /
`MsgSnapChunkResp` 消息类型，所有对端必须先升级；默认 0 保持旧线格式。仅 CRC
快照文件使用版本 2，旧版本节点无法读取该文件；需要回退旧版本时应在升级前保留
CRC+SHA 配置或先创建兼容快照。
