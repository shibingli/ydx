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
| 备份 | 异步封段备份、`.bak` 标记、`BackupVerifier`、本地 `DirBackup` |
| 保留 | 自动保留（年龄/总量），严格从最旧段开始 |
| 读取 | `Reader`/`Follow`/`Scan`/`Query`/`ReadInto`，并发读 |
| 只读 | 共享目录锁，不写入、不截断、不删除 |

## 持久性语义

`SyncAlways` 下，`Append` 返回成功意味着：

1. 记录字节已写入活动段；
2. 文件已执行平台对应的同步调用（Linux `fdatasync`/`RWF_DSYNC`、macOS
   `F_FULLFSYNC`、Windows `FlushFileBuffers`）；
3. 若本批涉及新段，段头与目录项已同步（Windows 目录项为尽力而为）。

`SyncInterval` / `SyncNever` 明确降低保证：在对应 `Sync()` 成功前，已返回但未同步的记录可能丢失。

**边界**：提交标记的 CRC 链可以区分“尾部撕裂”和“已确认前缀损坏”的前提是损坏位于最后一个检查点前缀之前。若损坏落在检查点前缀之后，恢复可能把已确认记录视为未确认尾部；`Verify` 会报告这类损坏。零 RPO 承诺针对遵守 flush 语义的存储上的进程/主机崩溃，不针对任意介质位腐。加密记录的单条 AEAD 能检测篡改，但不保证日志不可截断/不可删除。

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

- 备份只处理封段；`Close` 会尝试把最终段入队，但可能被取消，需要确定完成时用
  `BackupNow(ctx)`。
- `.bak` 是“已备份”的持久证据；`DirBackup` 实现 `BackupVerifier`。
- 自动保留必须看到匹配当前 `Backup.Target()` 的 `.bak` 且通过 `Verify` 才删除；
  严格从最旧段开始，遇到未备份段停止。
- **备份不是完整恢复集**：它包含 `.wal` 与 `.idx`，不包含 META/MANIFEST。
  META 双副本 + MANIFEST 同时丢失时，需要外部元数据快照或人工确认
  `firstLSN`/`gapFloor`/`commitSeq`/加密策略。

## 只读与并发

- 一个目录只允许一个写者（目录锁）；只读打开使用共享锁。
- 需要旁路检查活动 WAL 时使用 `WithReadOnly(true)` + `WithNoLock(true)`，并接受可能读到尾部残缺。
- 读者各有独立只读句柄；`Scan`/`Query` 会固定范围内的段引用，避免并发截断删段。
- WAL.Close 不等待读者；Reader 在 Close 前创建仍可读完。若跨进程删除不得影响它们，请先关闭 Reader。
- 每个 `Tx` 单协程使用；`Reader.Next` 串行化，不作为多协程并发读对象。

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
| `WithIndexCacheBytes` | 64 MiB | 稀疏索引缓存 |
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

`EngineInfo()` 暴露探测结果。

## 已知限制

1. **META 双副本 + MANIFEST 同时丢失**：灾难恢复场景；备份不含元数据快照。
2. **WithManifest(false)**：没有 kind=4/kind=5 证据；META 双副本全失时
   `firstLSN`/seq/LSN 不复用保证降级。
3. **介质位腐**：检查点前缀之外的数据损坏可能被当作未确认尾部；`Verify` 报告。
4. **META 同扇区**：两个 128 字节槽位于同一文件；同文件另一槽不作为独立原子单元，
   依靠 `META.mirror` 文件兜底。
5. **gapFloor 是单上界**：只精确放行此前接受的缺口；审计场景请使用备份/外部校验。
6. **Windows 目录项持久性**：平台不提供目录 fsync；依赖 MANIFEST kind=5/kind=1 与 META 双副本。
7. **Close 与读者**：Close 释放目录锁但不等待读者；跨进程删除可能影响存活 Reader。
8. **控制请求**：`Sync`/`Rotate`/`SetActiveKey`/`Truncate` 无 ctx 参数，队列满时按背压等待。
9. **KeyIndex**：是可选内存索引；溢出或加密场景下查询会回退为扫描，结果仍正确。
10. **wal/zstd 与 wal/uring**：按设计为独立模块/可选后端，需在 `wal/v0.1.0`
    发布后实现并验证。

## 测试与基准

```bash
GOWORK=off go build ./...
GOWORK=off go vet ./...
GOWORK=off CGO_ENABLED=1 CC=clang go test ./... -race
```

基准位于 `benchmarks/wal`（独立模块），包含与 `tidwall/wal`、`rosedblabs/wal`
和 etcd WAL 的对比。

## 许可证

Apache-2.0，见仓库根 `LICENSE`。
