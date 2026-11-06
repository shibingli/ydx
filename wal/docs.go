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
// lock so one writer owns the directory; read-only opens take a shared lock.
// Use multiple WAL instances for horizontal scaling; there is no cross-instance
// global LSN ordering. | WAL 是单目录、零外部服务的。目录锁保证单写者；只读打开
// 使用共享锁。水平扩展请使用多个 WAL 实例；不提供跨实例的全局 LSN 排序。
//
// Encryption and compression are record-level. Unencrypted, uncompressed writes
// reference caller bytes directly on Unix. | 加密与压缩均为记录级。未加密、
// 未压缩的写入在 Unix 上直接引用调用方字节。
//
// # Limits | 限制
//
// The META double mirror plus the sharded MANIFEST are the durable metadata.
// Losing both is a disaster-recovery event, not a routine path; backups contain
// segments and sidecars, not META/MANIFEST snapshots (see README). |
// META 双副本与分片 MANIFEST 是持久元数据；两者同时丢失属于灾难恢复场景，
// 不是常规路径；备份包含分段与侧车，不包含 META/MANIFEST 快照（见 README）。
//
// A commit-marker CRC chain cannot distinguish a bit-rotten confirmed record
// from an unconfirmed torn tail once the corruption is outside the last
// checkpoint prefix. Verify reports such corruption; zero RPO is promised for
// crashes on storage that honors flush semantics, not for arbitrary media
// corruption. | 一旦损坏落在最后一个检查点前缀之外，提交标记 CRC 链无法区分
// “已确认记录位腐”与“未确认撕裂尾”；Verify 会报告这类损坏。零 RPO 承诺针对
// 遵守 flush 语义的存储上的崩溃，不针对任意介质位腐。
//
// WithReadOnly opens never write, truncate, or delete files. Readers created
// before Close may continue reading, but WAL.Close releases the directory lock;
// close Readers before opening the directory with another writer if cross-process
// deletion must not affect them. | WithReadOnly 打开从不写入、截断或删除文件。
// Close 前创建的 Reader 可以继续读，但 WAL.Close 会释放目录锁；若跨进程删除
// 不得影响 Reader，请在另一个写者打开目录前关闭 Reader。
package wal
