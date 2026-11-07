# wal/cronbackup — 用 ydx/cron 定时备份 WAL

`wal/cronbackup` 把 `wal.BackupNow` 注册为 `ydx/cron` 任务，按 cron 表达式发布
`BACKUP.snap` 完整恢复集。它通过结构化 `Target` 接口工作，**不 import `wal`**：
`*wal.WAL` 直接满足接口，模块可独立构建、测试与打标签。

```go
w, err := wal.Open(dir, wal.WithBackup(wal.DirBackup("/var/backups/orders")))
if err != nil {
    return err
}
defer w.Close()

backup, err := cronbackup.New(ctx, w, cronbackup.Config{
    Schedule: "0 3 * * *",
    Timeout:  30 * time.Minute,
    Retries:  2,
}, cron.Options{})
if err != nil {
    return err
}
go func() {
    if err := backup.Run(ctx); err != nil {
        log.Printf("scheduled backup stopped: %v", err)
    }
}()
```

附加到应用已有的调度器：

```go
scheduler := cron.New(cron.Options{Store: cron.NewMemoryStore()})
job, err := cronbackup.Attach(ctx, scheduler, w, cronbackup.Config{
    JobID:    "orders-wal",
    Schedule: "@hourly",
})
if err != nil {
    return err
}
defer job.Remove(ctx)
```

## 构造期校验

`New` / `Attach` 会在启动前拒绝以下配置，避免“定时成功但什么也没备份”：

| 条件 | 错误 |
|---|---|
| `target == nil` | `ErrNilTarget` |
| WAL 未配置 `WithBackup` | `ErrNoBackupTarget` |
| 备份目标未实现 `SnapshotBackup`（例如只实现 `Backup`） | `ErrSnapshotUnsupported` |
| 调度表达式为空/非法 | `ErrInvalidSchedule` |
| `Attach` 传入 nil 调度器 | `ErrNilScheduler` |
| `Attach` 的 JobID 已存在 | `cron.ErrJobExists` |

`BackupNow` 本身要求快照目标（内置 `wal.DirBackup` 已实现）；只有 `WithBackup`
但没有 `SnapshotBackup` 的目标不能用于定时快照。只读打开的 WAL 仍可通过构造校验，
但每次触发会返回 `ErrReadOnly` 并记录到 cron 历史。

## 配置

| 字段 | 默认 | 说明 |
|---|---|---|
| `Schedule` | 必填 | ydx/cron 表达式：5/6/7 字段、`@daily`、`@every 1h`、`@once RFC3339` 等 |
| `Timezone` | `time.Local` | 墙上时间时区；表达式内 `CRON_TZ=`/`TZ=` 优先 |
| `JobID` | `wal-backup` | 任务 ID；共享调度器挂多个 WAL 时必须唯一 |
| `Task` | `wal-backup:<JobID>` | 处理器名（随定义持久化）；自定义时每个目标必须唯一 |
| `Name` | `WAL backup <JobID>` | 可读任务名 |
| `Overlap` | `cron.SkipIfRunning` | 上一次备份未结束时跳过本次触发 |
| `Timeout` | 0 | 单次备份超时；0 表示不设截止时间 |
| `Retries` | 0 | 失败后的额外尝试次数（cron 语义） |
| `RetryDelay` / `RetryBackoff` / `MaxRetryDelay` | cron 默认 | 退避重试 |
| `Jitter` | 0 | 分散同时触发的备份 |
| `Singleton` | false | 配置 Locker 时按次分布式抢占；每个 WAL 目录通常有自己的写者 |
| `Disabled` | false | 只添加定义，不参与计划触发；手动 `Trigger` 仍可用 |

## 行为

- 每次触发调用 `BackupNow`：轮转活动段、排空分段备份、校验大小/CRC 与
  `BackupVerifier`，随后原子发布 `BACKUP.snap`。
- 备份错误原样返回 cron，进入任务历史并触发重试；`BackupNow` 的 `Timeout` 由
  cron 的 `Timeout` 控制。
- 默认 `SkipIfRunning`，避免超过调度间隔的备份并发重入；确有需要才设
  `AllowOverlap`。
- 每个 WAL 目录只有一个写者；多实例部署时每台节点各自调度自己的 WAL。只有备份
  目标本身需要跨节点去重时才设置 `Singleton` 并配置 `cron.Options.Locker`。
- `Attach` 默认任务名按 JobID 派生，避免多个 WAL 共用一个调度器时互相覆盖处理器；
  自定义 `Task` 时需自行保证唯一。
- cron 没有反注册处理器 API；`Remove` 移除任务定义后，处理器会随调度器存续。
- 使用 `cron.Options.Store` 持久化定义时，重启后应在 `Start` 前再次调用 `New` 或
  `Attach` 以注册处理器；否则 cron 会因存储中的任务缺少处理器而快速失败。

## 管理路由

`New` 返回的 `Scheduler.Cron()` 可直接使用 cron 的管理 API。YD 路由与原生
`net/http` 都可用：

```go
r := router.New()
_ = backup.Cron().Mount(r, "/cron")

mux.Handle("/cron/", backup.Cron().HTTPHandler("/cron"))
```

管理 API 不做认证，对外暴露前必须套用应用的管理中间件。

## 验证

```bash
cd wal/cronbackup
GOWORK=off go build ./...
GOWORK=off go vet ./...
GOWORK=off CGO_ENABLED=1 CC=clang go test ./... -race
```

模块依赖已发布的 `github.com/shibingli/ydx/cron v0.1.2` 与
`github.com/shibingli/ydx/errs v0.1.4`；不依赖 `wal` 模块。发布标签：
`wal/cronbackup/v0.1.0`。
