// Package cronbackup schedules restore-complete ydx/wal backups with ydx/cron.
// | Package cronbackup 使用 ydx/cron 为 ydx/wal 调度可完整恢复的备份。
//
// A scheduled run calls Target.BackupNow, which rotates the active segment,
// waits for the referenced segments to be uploaded, verifies their size and CRC,
// and atomically publishes BACKUP.snap. RestoreDir/RestoreBackup can restore the
// result. The target must be a SnapshotBackup implementation such as
// wal.DirBackup; New and Attach reject a WAL without a backup target or without
// snapshot support instead of silently scheduling a no-op. | 定时运行调用
// Target.BackupNow：轮转活动段、等待引用分段上传、校验大小与 CRC，并原子发布
// BACKUP.snap；结果可用 RestoreDir/RestoreBackup 还原。目标必须是
// wal.DirBackup 等 SnapshotBackup 实现；New/Attach 会拒绝没有备份目标或不支持
// 快照的 WAL，而不是静默调度一个空操作。
//
// The package uses a structural Target interface and deliberately does not
// import the wal module, so it can be versioned and built independently (like
// wal/zstd). *wal.WAL implements Target. | 本包使用结构化 Target 接口，刻意不
// import wal 模块，因此可以像 wal/zstd 一样独立版本化与构建；*wal.WAL 实现了
// Target。
//
// Dedicated scheduler | 专用调度器：
//
//	w, err := wal.Open(dir, wal.WithBackup(wal.DirBackup("/var/backups/orders")))
//	if err != nil {
//		return err
//	}
//	defer w.Close()
//
//	backup, err := cronbackup.New(ctx, w, cronbackup.Config{
//		Schedule: "0 3 * * *",
//		Timeout:  30 * time.Minute,
//		Retries:  2,
//	}, cron.Options{})
//	if err != nil {
//		return err
//	}
//	go func() {
//		if err := backup.Run(ctx); err != nil {
//			log.Printf("scheduled backup stopped: %v", err)
//		}
//	}()
//
// Attach to an existing scheduler | 附加到既有调度器：
//
//	scheduler := cron.New(cron.Options{Store: cron.NewMemoryStore()})
//	job, err := cronbackup.Attach(ctx, scheduler, w, cronbackup.Config{
//		JobID:    "orders-wal",
//		Schedule: "@hourly",
//	})
//	if err != nil {
//		return err
//	}
//	defer job.Remove(ctx)
//
// The default Overlap is cron.SkipIfRunning, so a backup longer than its
// interval does not start a second concurrent run. Errors are returned to cron,
// which records them in per-job history and applies the configured retry
// policy. Each WAL directory normally has one writer; leave Singleton false
// unless the backup target itself must be deduplicated across nodes. | 默认
// Overlap 为 cron.SkipIfRunning，长于间隔的备份不会并发重入。错误返回给 cron，
// 由其写入任务历史并按重试策略处理。每个 WAL 目录通常只有一个写者；除非备份目标
// 本身需要跨节点去重，否则 Singleton 保持 false。
//
// Administrative routes | 管理路由：
//
// Mount the cron scheduler on the YD router (primary) or expose the same table
// as a native net/http handler. The administrative API performs no
// authentication, so wrap it with the application's admin middleware. | 可把
// cron 调度器挂到 YD 路由（首选），或以原生 net/http 处理器暴露同一张路由表。
// 管理 API 不做认证，对外暴露前请套用应用的管理中间件。
//
//	r := router.New()
//	_ = backup.Cron().Mount(r, "/cron")
//
//	mux.Handle("/cron/", backup.Cron().HTTPHandler("/cron"))
package cronbackup
