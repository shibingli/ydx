# ydx/wal

通用、分段、可崩溃恢复的 Go 预写日志（WAL）。单目录、零外部服务、纯 Go、无 cgo。

- 模块路径：`github.com/shibingli/ydx/wal`
- 包名：`wal`
- 默认持久性：`SyncAlways`（零 RPO）
- 默认算法：AES-256-GCM（可选）+ SHA-256（默认）
- 支持平台：Linux / macOS / Windows（amd64 / arm64）

## 快速开始

```go
package main

import (
    "context"
    "log"

    "github.com/shibingli/ydx/wal"
)

func main() {
    w, err := wal.Open("/var/lib/app/wal")
    if err != nil {
        log.Fatal(err)
    }
    defer w.Close()

    ctx := context.Background()
    lsn, err := w.Append(ctx, wal.Record{
        Key:  []byte("user:1"),
        Data: []byte(`{"name":"alice"}`),
    })
    if err != nil {
        log.Fatal(err)
    }

    rec, err := w.Read(lsn)
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("read %d: %s", rec.LSN, rec.Data)
}
```

## 核心能力

| 能力 | 说明 |
|---|---|
| 组提交 | 单写协程把并发 `Append` 合并为一次位置写 + 一次同步 |
| 提交标记 | 每批末尾一条标记；恢复按已确认水位截断撕裂尾 |
| 分段 | 按大小/时间/记录数轮转；封段写 `.idx` 侧车 |
| 低 RTO | MANIFEST 分片 + 段摘要 + 检查点侧车，启动不扫描全部历史 |
| 事务 | 日志级 ACID；快照隔离；声明键的 Serializable OCC |
| 加密 | AES-256-GCM / SM4-GCM；HKDF 派生；KCV 检测同 ID 换钥 |
| 压缩 | 内置记录级 flate；可通过 `Codec` 接口注册 zstd 等其他算法 |
| 去重 | 段内内容去重 + `AppendOnce` 幂等 LRU |
| 流式 | `AppendStream` / `StreamReader`，恒定内存 |
| 备份 | 异步封段备份、`.bak` 标记、`BackupVerifier`、本地 `DirBackup`；`BackupNow` 发布含元数据的 `BACKUP.snap` |
| 定时备份 | 可选独立模块 `wal/cronbackup`：用 ydx/cron 调度 `BackupNow`，校验备份目标、默认跳过重入 |
| 恢复 | `RestoreDir`/`RestoreBackup` 原子还原完整备份集 |
| 自愈 | 独立恢复锚点（双槽原位写）+ 段头/侧车扫描；清理创建期残缺段；可写打开清理无对应 `.wal` 的孤儿 `.idx`/`.bak`；空段头原子替换；META、MANIFEST、锚点全失时默认重建 |
| 缺口 | 有序缺口区间集合持久化到锚点；默认自动接受并报告，可关闭自动修复 |
| 保留 | 自动保留（年龄/总量），严格从最旧段开始 |
| 读取 | `Reader`/`Follow`/`Scan`/`Query`/`ReadInto`，并发读；随机读 1 alloc；旧侧车 Key 索引按需重建 |
| 只读 | 共享目录锁，不写入、不截断、不删除 |

## 持久性语义

`SyncAlways` 下，`Append` 返回成功意味着：

1. 记录字节已写入活动段；
2. 文件已执行平台对应的同步调用（Linux `fdatasync`/`RWF_DSYNC`、macOS
   `F_FULLFSYNC`、Windows `FlushFileBuffers`）；
3. 若本批涉及新段，段头与目录项已同步（Windows 目录项为尽力而为）。

`SyncInterval` / `SyncNever` 明确降低保证：在对应 `Sync()` 成功前，已返回但未同步的记录可能丢失。
例外是 `Truncate`/自动保留：在持久化截断水位前会先同步已确认记录，避免掉电后 META
高水位超前于实际数据。

**边界**：提交标记的 CRC 链用于区分“尾部撕裂”和“已确认前缀损坏”。扫描到坏记录后会继续检查其后是否存在自身 CRC 有效的提交标记：存在则返回 `ErrCorrupt`，不再把已确认批次当作未确认尾部截断；该判断同样覆盖检查点前缀之后的损坏。只有坏记录之后没有任何有效标记时才按撕裂尾处理。结构合法但摘要不一致的提交标记若其后还有有效标记，同样报告 `ErrCorrupt`。`Verify` 会重新校验每条记录。零 RPO 承诺针对遵守 flush 语义的存储上的进程/主机崩溃，不针对任意介质位腐。加密记录的单条 AEAD 能检测篡改，但不保证日志不可截断/不可删除。

## 事务

```go
tx, err := w.Begin(ctx, wal.WithTxnIsolation(wal.IsolationSerializable))
if err != nil { return err }
if err := tx.Append(ctx, wal.Record{Key: []byte("a"), Data: v}); err != nil {
    _ = tx.Rollback()
    return err
}
if err := tx.WriteKey([]byte("a")); err != nil {
    _ = tx.Rollback()
    return err
}
info, err := tx.Commit(ctx)
```

- 未提交数据永不进入 WAL；`Commit` 是一个逻辑提交批（数据 + 事务控制 + 批提交标记 + 一次同步）。
- 默认 `IsolationSnapshot`；`IsolationSerializable` 需要 `ReadKey`/`WriteKey` 声明键，做有界 OCC。
- `WithSerializableDurability(true)` 把写键摘要持久化到事务控制记录，重启后可重建冲突窗口。
- `TxnMaxBytes` 默认 4 MiB（每条记录另计 96 字节缓冲开销）；`TxnMaxRecords` 默认 1,000,000。
- `Tx` 不是多协程安全的；一个 `Tx` 同一时刻只应由一个 goroutine 使用。

## 加密

```go
ring, err := wal.NewKeyRing(1,
    wal.Key{ID: 1, Suite: wal.SuiteAESGCM, Bytes: aesKey32},
    wal.Key{ID: 2, Suite: wal.SuiteSM4GCM, Bytes: sm4Key16},
)
w, err := wal.Open(dir, wal.WithEncryption(ring))

// 轮换：先封段，再切换后续记录的密钥
err = w.SetActiveKey(2)
```

- 同一 WAL 禁止明文/密文混用；加密策略由 META 权威决定。
- 记录头保持明文（LSN/时间/长度/flags/keyID/nonce）；Key/Data 内容加密。
- `WithKeyIndex(true)` 与加密组合默认拒绝，需显式 `WithPlaintextKeyIndex(true)`。
- ASCII 密钥环会深拷贝；派生密钥在最后一个读租约退出后清零。

## 压缩、去重、幂等

```go
w, _ := wal.Open(dir,
    wal.WithCompression(wal.Compression{
        Active:   1,
        Codecs:   []wal.Codec{wal.FlateCodec(6)},
        MinBytes: 1 << 10,
    }),
    wal.WithContentDedup(wal.DedupOptions{MinBytes: 1 << 10}),
    wal.WithIdempotency(wal.IdempotencyOptions{MaxEntries: 65536}),
)
```

- 压缩率不足时自动存原文；解压输出必须精确等于原始 `keyLen+dataLen`。
- 内容去重只引用**同一活动段内**更早的普通记录，轮转/截断天然安全。
- v1 格式禁止事务内写去重引用；事务记录按普通记录存储，之后未开启事务的
  `Append` 仍可把已提交的事务记录作为去重目标。
- `AppendOnce` 命中相同内容返回原 LSN 与 `duplicate=true`；内容不同返回
  `ErrIdempotencyConflict`。幂等窗口仅内存，重启清空。

## 流式

```go
info, err := w.AppendStream(ctx, r)
sr, err := w.NewStreamReader(info)
defer sr.Close()
_, err = io.Copy(dst, sr)
```

- 默认 1 MiB/块；每块是一条普通记录；end 记录标记完整。
- 不承诺单条流原子可见；中途失败留下无 end 的块，读取返回
  `ErrStreamIncomplete`。
- `Tx.AppendStream` 把块复制进事务缓冲，受 `TxnMaxBytes` 限制。

## 备份与保留

```go
w, _ := wal.Open(dir,
    wal.WithBackup(wal.DirBackup("/backup/wal")),
    wal.WithRetention(wal.Retention{MaxBytes: 100 << 30}),
)
err := w.BackupNow(ctx) // 轮转活动段并等待其备份完成
```

- `FlushBackups(ctx)` 只排空封段上传，不发布元数据快照。
- `BackupNow(ctx)` 轮转活动段、等待全部引用分段，并调用目标的
  `SnapshotBackup` 原子发布 `BACKUP.snap`；该文件是完整恢复集的提交点，包含
  `walID`、`firstLSN`/`lastLSN`/`nextLSN`、`nextSeq`、`commitSeq`、加密策略、
  KCV、缺口区间与全部 `SegmentMeta`。未实现 `SnapshotBackup` 的目标返回
  `ErrUnsupported`。
- `.bak` 是“已备份”的持久证据；`DirBackup` 同时实现 `BackupVerifier` 与
  `SnapshotBackup`。发布快照前会校验每个分段的大小与 CRC；任何分段未完整上传
  都不会被快照引用。已有 `.bak` 但目标实现 `BackupVerifier` 且校验失败时，该
  标记不被信任：worker 会重新上传分段并重写标记，避免远端对象丢失后永远不再
  上传。
- 自动保留必须看到匹配当前 `Backup.Target()` 的有效 `.bak`；目标实现
  `BackupVerifier` 时还要通过 `Verify`（目标对象存在且大小/CRC/walID 匹配）才
  删除。严格从最旧段开始，遇到未备份段停止。远程目标未实现 `BackupVerifier`
  时，自动保留的可靠性仅与远端一致，建议删除前人工或外部校验。
- 待办分段被 `Truncate` 退休时标记为 deleted 并立即移出待办；worker 在打开
  前检查该标记，已删除/ENOENT 视为终态跳过，不重试、不调用 `ErrorHandler`。
  `FlushBackups` 把 deleted 视为满足；`BackupNow` 取非严格语义：若并发的
  `Truncate` 删除了集合中的分段，快照校验会失败并返回 `ErrBackup`，不会发布
  缺段的恢复集。
- `RestoreDir(ctx, backupDir, walDir)` 在私有临时目录中校验并复制全部分段、
  重建 META/恢复锚点，最后用一次 rename 发布；目标已存在且非空时拒绝。复制时
  除大小/CRC 外还校验段头的 `seq`/`baseLSN`/`walID` 与集合条目一致。备份集解码
  同时拒绝重叠的分段 LSN 区间与缺少活动 KCV 的加密集合，避免发布无法打开或
  记录归属含糊的恢复集。
  `RestoreBackup` 在还原后直接 `Open`。加密备份不需要在还原阶段提供密钥，
  打开时用 KCV 校验密钥是否正确。

## 只读与并发

- 一个目录只允许一个写者（目录锁）；只读打开使用共享锁。只读打开**不会创建**锁文件；
  锁文件不存在时直接打开（说明从未有写者），不会向目录写入任何内容。
- 需要旁路检查活动 WAL 时使用 `WithReadOnly(true)` + `WithNoLock(true)`，并接受可能读到尾部残缺。
- 读者各有独立只读句柄；`Scan`/`Query` 会固定范围内的段引用，避免并发截断删段。
- `Reader.Next`、`Scan`、`Query` 返回的 `Record.Key`/`Data` 指向复用读取缓冲，
  仅在下次 `Next` 或回调返回前有效；需要保留请调用 `Record.Clone()`。
- WAL.Close 不等待读者；Reader 在 Close 前创建仍可读完。若跨进程删除不得影响它们，请先关闭 Reader。
- 每个 `Tx` 单协程使用；`Reader.Next` 串行化，不作为多协程并发读对象。
- 写路径 worker（writer/checkpoint/cleaner/retention）在首次写请求时按需启动；
  仅配置备份时在 Open 阶段启动备份对账。干净关闭不会为从未写入的 WAL 启动协程。

## 主要选项

| 选项 | 默认 | 说明 |
|---|---|---|
| `WithSyncPolicy` | `SyncAlways()` | 持久性策略 |
| `WithSegmentMaxBytes` | 64 MiB | 分段大小 |
| `WithSegmentMaxAge` | 0 | 分段年龄；0 关闭 |
| `WithSegmentMaxRecords` | 0 | 分段记录数；0 关闭 |
| `WithMaxRecordBytes` | 16 MiB | 单记录上限（硬上限 1 GiB） |
| `WithQueueSize` | 4096 | 写入队列 |
| `WithMaxBatchRecords` | 512 | 组提交记录上限 |
| `WithMaxBatchBytes` | 4 MiB | 组提交字节上限 |
| `WithCheckpointBytes` | 8 MiB | 活动段检查点间隔 |
| `WithIndexCacheBytes` | 64 MiB | 稀疏/Key 索引 LRU 上限 |
| `WithReadFDCacheSize` | 32 | 随机读 fd 缓存 |
| `WithManifest` | true | 分片 MANIFEST |
| `WithStreamChunkSize` | 1 MiB | 流分块 |
| `WithTxnMaxBytes` | 4 MiB | 事务缓冲上限 |
| `WithTxnConflictWindow` | 65536 | Serializable 窗口 |
| `WithSerializableDurability` | false | 持久化写键摘要 |
| `WithKeyIndex` | false | 内存 Key 索引 |
| `WithEncryption` | nil | 密钥环 |
| `WithCompression` | 关闭 | 记录级压缩 |
| `WithContentDedup` | 关闭 | 段内内容去重 |
| `WithIdempotency` | 关闭 | `AppendOnce` 幂等窗口 |
| `WithBackup` | nil | 异步备份 |
| `WithRetention` | 关闭 | 自动保留 |
| `WithReadOnly` | false | 只读 |
| `WithAllowLSNGaps` | false | 有损恢复 |
| `WithAutoRepair` | true | 元数据丢失时从段头/侧车/锚点自动重建并记录缺口 |

完整列表见 `options.go`。

## 平台能力

| 能力 | Linux | macOS | Windows |
|---|---|---|---|
| 数据写入 | `pwritev2`/`pwritev` | `pwritev` | 池化暂存 + `WriteAt` |
| 数据同步 | `fdatasync` / `RWF_DSYNC` | `F_FULLFSYNC` | `FlushFileBuffers` |
| 目录项同步 | `fsync(dir)` | `File.Sync`（ENOTSUP 容忍） | 尽力而为 |
| 目录锁 | `flock` | `flock` | `LockFileEx` |
| 备份加速 | `FICLONE` | `clonefile` | 无 |
| 预分配 | `fallocate(KEEP_SIZE)` | 无 | 无 |
| 页缓存回收 | `fadvise(DONTNEED)` | 无 | 无 |
| 可选 `wal/uring` | 原始 io_uring 系统调用（amd64/arm64） | 桩 `ErrUnsupported` | 桩 `ErrUnsupported` |

`EngineInfo()` 暴露探测结果。

## 已知限制

1. **最高创建段缺失且没有持久 lastLSN**：即使默认自愈，若最高创建分段只有
   kind=5（存在性）而没有 kind=1 的 `lastLSN` 证据，继续写入可能复用已分配的
   LSN，因此仍返回 `ErrMissingSegment`。请从备份恢复或提供外部高水位证据。
2. **全部元数据副本同时丢失**：恢复锚点、META 双副本、MANIFEST 与侧车全部丢失时，
   段头 + 记录扫描仍能恢复数据与 nextLSN/nextSeq；但“已截断但文件尚未删除”的
   旧段可能重新出现，因为没有任何持久化截断意图可读。常规的
   META+MANIFEST 同时丢失由锚点覆盖，不会触发此边界。
3. **介质位腐**：坏记录之后若存在自身 CRC 有效的提交标记，恢复返回 `ErrCorrupt`；
   若损坏位于未确认尾部且其后没有标记，则按撕裂尾截断。`Verify` 可全量校验。
4. **META 同扇区**：两个 128 字节槽位于同一文件；同文件另一槽不作为独立原子单元，
   依靠 `META.mirror` 与恢复锚点兜底。
5. **缺口集合上限**：恢复锚点最多保存 1024 个缺口区间，超出后坍缩为水位并置
   `Stats.RecoveryGapDegraded`。默认 `WithAutoRepair(true)` 会接受新缺口并通过
   `Stats.RecoveryMissingLSNs`/`ErrorHandler` 报告；严格审计可设置
   `WithAutoRepair(false)` 恢复 v1 拒绝行为，或显式 `WithAllowLSNGaps(true)`。
6. **Windows 目录项持久性**：平台不提供目录 fsync；依赖 MANIFEST kind=5/kind=1、
   META 双副本与恢复锚点。
7. **Close 与读者**：Close 释放目录锁但不等待读者；跨进程删除可能影响存活 Reader。
8. **控制请求**：`Sync`/`Rotate`/`SetActiveKey`/`Truncate` 无 ctx 参数，队列满时按背压等待。
9. **KeyIndex**：可选内存索引。完整、未溢出的索引直接按 LSN 列表读取；索引缺失、
   旧格式、检查点前缀或溢出时只扫描/重建**该分段**，不再回退全 WAL 线性扫描。
   重建成功会原子升级 `.idx`；溢出段按查询目标 Key 做单段扫描。
   `WithIndexCacheBytes` 限制按需索引内存；`KeyIndexRebuilds`/`KeyIndexScans`
   暴露升级与扫描次数。
10. **临时文件清理**：崩溃遗留的 `.tmp` 会被恢复忽略，并在目录扫描或同一路径的
    下一次原子写时清理；干净 Open 不再为扫描 `.tmp` 额外遍历目录。
11. **清理失败可观测**：cleaner 删除分段遇到平台级错误（如 Windows 共享冲突）会
    指数退避重试并通过 `ErrorHandler` 上报，`Stats.CleanupErrors` 递增；不再静默
    留下文件。
12. **备份目标能力**：`BackupNow` 需要目标实现 `SnapshotBackup`（内置
    `DirBackup` 已实现）；只实现 `Backup` 的目标仍可用 `FlushBackups` 上传分段，
    但不会发布元数据快照。`RestoreDir` 按 `DirBackup` 布局读取
    `BACKUP.snap`、`%020d.wal`、`%020d.idx`。
13. **wal/zstd 与 wal/uring**：`wal/zstd` 是纯 Go Zstandard codec（codec ID 2，
    依赖 `klauspost/compress`）；`wal/uring` 是 Linux amd64/arm64 的原始
    io_uring `IOEngine`，其它平台为返回 `ErrUnsupported` 的桩。两者都不 import
    `wal`，可独立构建发布；默认引擎仍是可移植同步引擎。uring 单 ring 由互斥量
    保护，并发 `ReadAt` 会串行化。可选的 `wal/cronbackup` 模块用 `ydx/cron`
    定时调用 `BackupNow`，同样不 import `wal`，以结构化 `Target` 接口校验备份
    目标，默认 `Overlap=SkipIfRunning`，错误进入 cron 历史并按策略重试。
14. **META v2**：v0.2.0 写入 META 版本 2（布局不变），读取 v1 并在首次持久化时
    升级；v0.1.x 读者遇到版本 2 返回 `ErrUnsupported`，不会按旧 kind=2 退休语义
    误读压缩后的 MANIFEST。记录、段头、MANIFEST 与侧车布局仍为 v1。
15. **LSN/序号耗尽**：`Append` 在 LSN 空间即将回绕前返回 `ErrTooLarge`，绝不会把 0
    作为 LSN 写入；分段序号耗尽同样返回 `ErrTooLarge`。
16. **创建期与空段头**：`META.nextSeq` 指向的残缺段（短于段头）在恢复时丢弃，
    由后续 Append 重建；空末尾段 base 过期时用原子整文件替换段头，不再原位重写。
    MANIFEST 已知分段短于段头视为损坏（`ErrCorrupt`），不会写退休水位而误伤更低
    序号的存活分段。恢复发现最高序号已退休时不会把退休段当作活动段。

## 测试与基准

```bash
GOWORK=off go build ./...
GOWORK=off go vet ./...
GOWORK=off CGO_ENABLED=1 CC=clang go test ./... -race

# 可选模块
cd zstd && GOWORK=off go test ./... -race
cd ../uring && GOWORK=off go test ./... -race   # Linux；其它平台运行桩测试
cd ../cronbackup && GOWORK=off go test ./... -race
```

测试矩阵包含原生 fuzz（`FuzzDecodeFormats`、`FuzzOpenMutatedSegment`、
`FuzzManifestReplay`）、IOEngine 故障注入（写/同步失败、并发 poison）、
崩溃目录复制（每次追加/轮转边界）、规模（数百分段、8 MiB 记录、2 万 Key）、
并发生命周期看门狗与 goroutine 泄漏检查。基准位于 `benchmarks/wal`（独立模块），
包含与 `tidwall/wal` 和 `rosedblabs/wal` 的对比；`wal/zstd` 与 `wal/uring`
的对比基准需要在两个仓库之外用临时 `go.work`/`replace` 运行。

## 许可证

Apache-2.0，见仓库根 `LICENSE`。
