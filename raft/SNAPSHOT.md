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

## 5. 后续可继续优化的方向

1. **标记与后续 WAL 批次合并 fsync**：当前镜像 fsync 已异步，但标记仍单独 fsync 一次。若把“本地快照标记 + 紧随其后的日志项”合并为一个 WAL 批，可每个快照少一次 fsync。需要保证标记元数据与条目区间的编码顺序。
2. **流式 FSM 快照接口**：增加可选的 `SnapshotTo(io.Writer)`，让应用直接把状态写入快照临时文件，避免整份 `[]byte` 驻留内存和二次复制；旧 `FSM.Snapshot()` 保留兼容。
3. **快照数据懒加载/文件映射**：`latestSnapshot.Data` 当前长期驻留内存，便于向多个跟随者复用。可在 FileStorage 下改为按需从镜像文件读取或 mmap，降低大状态节点的常驻内存；代价是每次发送需要重新读取。
4. **快照分块传输与发送**：当前快照必须一次编码进一个传输帧；分块 InstallSnapshot 可消除帧上限限制，并允许边读边发，降低峰值内存。
5. **快照目录独立磁盘**：让镜像写入/fsync 与 WAL 位于不同设备或目录，减少两者对同一存储队列的争用；可作为 `FileStorageOptions` 的扩展。
6. **自适应组提交窗口**：根据 fsync 延迟、队列深度和客户端并发自动选择 `PersistBatchDelay`，在尾延迟与吞吐之间动态调节，而不是固定 0 或固定 50–200µs。
7. **WAL writev/零拷贝编码**：将记录头、条目头和条目数据用 writev 直接写出，减少 `encodeWALBatch` 到内核的第二次复制；需要跨平台写向量或文件抽象。
8. **快照校验取舍**：CRC32C 足以检测介质错误；SHA-256 用于更强完整性。对超大镜像可提供“仅 CRC”或“校验异步”策略，但会改变完整性边界。

## 6. 参数建议

- 生产启用 fsync；`NoSync` 仅用于基准/临时测试。
- 高并发提交优先增大批处理收益：`PersistBatchDelay` 可从 50–200µs 开始压测，观察 p99 提案延迟与 fsync 次数。
- 快照间隔 `SnapshotEntries` 过小会造成频繁整份镜像 fsync；过大则恢复时间和 WAL 体积增加。按状态大小与可接受 RTO 选择。
- 对 GB 级状态，优先采用流式快照、分块传输与独立快照磁盘，而不是继续压缩单次 fsync 的常数。
