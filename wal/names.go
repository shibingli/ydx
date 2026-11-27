package wal

// Durable layout names used by the WAL, META/MANIFEST sidecars, backups and
// recovery. Keep them in one place so recovery and tooling cannot drift. |
// WAL、META/MANIFEST 侧车、备份与恢复使用的持久布局名称。集中定义，避免恢复与
// 工具代码不一致。
const (
	segmentSuffix      = ".wal"
	indexSuffix        = ".idx"
	backupSnapshotName = "BACKUP.snap"
	metaFileName       = "META"
	metaMirrorName     = "META.mirror"
	recoveryFileName   = "RECOVERY"
	lockFileName       = "wal.lock"
	tempSuffix         = ".tmp"
	manifestDirName    = "manifest"
	manifestRebuild    = ".rebuild"
)

// segmentNameFormat and indexNameFormat render zero-padded sequence names. |
// segmentNameFormat 与 indexNameFormat 生成补零序列名。
const (
	segmentNameFormat = "%020d" + segmentSuffix
	indexNameFormat   = "%020d" + indexSuffix
)
