// Package wal implements a segmented, crash-recoverable write-ahead log for Go.
// | Package wal 为 Go 实现一个分段的、可崩溃恢复的预写日志。
//
// # Guarantees | 保证
//
// The default policy is SyncAlways: Append returns only after the record and its
// batch commit marker have been synchronized. A clean crash or power loss (on
// storage that honors flush semantics) therefore loses no acknowledged record.
// SyncInterval and SyncNever trade durability for throughput and are explicit
// opt-ins. | 默认策略为 SyncAlways：Append 只在记录与本批提交标记同步完成后
// 返回。因此在遵守 flush 语义的存储上，干净崩溃或掉电不会丢失已确认记录。
// SyncInterval 与 SyncNever 以持久性换吞吐，必须显式选择。
//
// A single writer goroutine performs group commit, so concurrent Append calls
// share one positional write and one synchronization. Readers use independent
// read-only handles and never block the writer. | 单写协程执行组提交，并发 Append
// 共享一次位置写与一次同步。读者使用独立只读句柄，永不阻塞写者。
//
// The on-disk format is checksummed with CRC32C. Optional AES-256-GCM or
// SM4-GCM encryption authenticates every record and binds it to the WAL ID,
// segment sequence, and record offset. | 磁盘格式使用 CRC32C 校验。可选的
// AES-256-GCM 或 SM4-GCM 加密会认证每条记录，并绑定 WAL ID、段序号与记录偏移。
//
// # Basic usage | 基本用法
//
//	w, err := wal.Open("/var/lib/app/wal")
//	if err != nil {
//		return err
//	}
//	defer w.Close()
//
//	lsn, err := w.Append(ctx, wal.Record{Key: []byte("user:1"), Data: payload})
//	if err != nil {
//		return err
//	}
//	rec, err := w.Read(lsn)
//
// # Transactions | 事务
//
//	tx, err := w.Begin(ctx, wal.WithTxnIsolation(wal.IsolationSerializable))
//	if err != nil {
//		return err
//	}
//	if err := tx.Append(ctx, wal.Record{Key: []byte("k"), Data: []byte("v")}); err != nil {
//		_ = tx.Rollback()
//		return err
//	}
//	if err := tx.WriteKey([]byte("k")); err != nil {
//		_ = tx.Rollback()
//		return err
//	}
//	info, err := tx.Commit(ctx)
//
// # Streams | 流
//
//	info, err := w.AppendStream(ctx, reader)
//	if err != nil {
//		return err
//	}
//	sr, err := w.NewStreamReader(info)
//	if err != nil {
//		return err
//	}
//	defer sr.Close()
//	_, err = io.Copy(dst, sr)
//
// # Operational notes | 运维说明
//
// The WAL is a single directory with no external service. It uses a directory
// lock so one writer owns the directory; read-only opens take a shared lock
// when the lock file already exists and never create it. Write workers start on
// first admission, so an opened-but-never-written WAL starts no goroutines.
// Use multiple WAL instances for horizontal scaling; there is no cross-instance
// global LSN ordering. | WAL 是单目录、零外部服务的。目录锁保证单写者；只读打开
// 在锁文件已存在时使用共享锁，且从不创建锁文件。写 worker 在首次准入时启动，
// 打开后从未写入的 WAL 不启动协程。水平扩展请使用多个 WAL 实例；不提供跨实例
// 的全局 LSN 排序。
//
// Encryption and compression are record-level. Unencrypted, uncompressed writes
// reference caller bytes directly on Unix. | 加密与压缩均为记录级。未加密、
// 未压缩的写入在 Unix 上直接引用调用方字节。
//
// # Recovery | 恢复
//
// META (two files, two slots), the sharded MANIFEST, and a two-slot recovery
// anchor are independent durable copies of the high-water state. When META,
// MANIFEST, and the anchor are all lost, Open rebuilds them from segment
// headers, sidecars, and a bounded scan; WithAutoRepair(false) restores the
// strict refusal behavior. Discovered LSN gaps are stored as intervals in the
// anchor and reported through Stats and ErrorHandler. |
// META（双文件双槽）、分片 MANIFEST 与双槽恢复锚点是高水位状态的独立副本。
// 三者全部丢失时，Open 从段头、侧车与有界扫描重建；WithAutoRepair(false) 恢复
// 严格拒绝行为。发现的 LSN 缺口以区间形式写入锚点，并通过 Stats 与
// ErrorHandler 报告。
//
// BackupNow publishes a restore-complete BackupSet containing metadata and all
// referenced segment summaries; RestoreDir/RestoreBackup restore it atomically.
// FlushBackups remains the segment-only drain API. | BackupNow 发布包含元数据与
// 全部引用分段摘要的完整恢复集；RestoreDir/RestoreBackup 原子还原。
// FlushBackups 仍是仅排空分段的 API。
//
// # Limits | 限制
//
// If the highest created segment is missing and no persisted lastLSN proves
// its high water, Open returns ErrMissingSegment even with auto repair, because
// continuing could reuse an acknowledged LSN. If every metadata copy and
// sidecar is lost, segment scanning cannot reconstruct a truncation watermark
// that occurred after the last surviving anchor write. | 最高创建分段缺失且没有
// 持久 lastLSN 证明其高水位时，即使开启自动修复也返回 ErrMissingSegment，因为
// 继续写入可能复用已确认 LSN。若所有元数据副本与侧车全部丢失，段扫描无法重建
// 最后一次存活锚点写入之后发生的截断水位。
//
// A damaged record followed by a self-CRC-valid commit marker is reported as
// ErrCorrupt instead of being truncated, even when the damage lies beyond a
// checkpoint prefix. Only damage with no later valid marker is treated as an
// unconfirmed torn tail. Verify re-checks every record and proves each segment
// summary describes its file. Zero RPO is promised for crashes on storage that
// honors flush semantics, not for arbitrary media corruption. | 损坏记录之后若
// 存在自身 CRC 有效的提交标记，即使损坏位于检查点前缀之后也返回 ErrCorrupt，
// 而不是截断；只有其后没有任何有效标记时才按未确认撕裂尾处理。Verify 会重新
// 校验每条记录，并证明每个分段摘要描述的就是该文件。零 RPO 承诺针对遵守 flush
// 语义的存储上的崩溃，不针对任意介质位腐。
//
// Append returns ErrTooLarge before the LSN or segment-sequence counter can
// wrap to zero. | Append 在 LSN 或分段序号计数器回绕为零之前返回 ErrTooLarge。
//
// WithReadOnly opens never write, truncate, or delete files. Readers created
// before Close may continue reading, but WAL.Close releases the directory lock;
// close Readers before opening the directory with another writer if cross-process
// deletion must not affect them. | WithReadOnly 打开从不写入、截断或删除文件。
// Close 前创建的 Reader 可以继续读，但 WAL.Close 会释放目录锁；若跨进程删除
// 不得影响 Reader，请在另一个写者打开目录前关闭 Reader。
package wal
