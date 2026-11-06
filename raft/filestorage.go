package raft

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/shibingli/ydx/errs"
)

const (
	snapshotMagic   = "YDRSNP01"
	snapshotVersion = byte(1)
	// snapshotVersionCRCOnly adds a checksum-flags byte and omits the SHA-256
	// comparison. The 32-byte hash field remains reserved for a fixed layout. |
	// snapshotVersionCRCOnly 增加校验和标志字节并省略 SHA-256 比较；32 字节哈希
	// 字段仍保留以维持固定布局。
	snapshotVersionCRCOnly = byte(2)
	snapshotFlagSHA256     = byte(1 << 0)
	maxConfBytes           = 4 << 20
)

// SnapshotChecksum selects the integrity check written for new snapshot images.
// CRC32C detects accidental corruption at negligible cost. Adding SHA-256 gives
// a stronger digest suitable for tamper detection. | SnapshotChecksum 选择新快照
// 镜像写入的完整性校验。CRC32C 以极低开销检测意外损坏；增加 SHA-256 提供适合
// 篡改检测的更强摘要。
type SnapshotChecksum uint8

const (
	// SnapshotChecksumCRC32CSHA256 writes the original layout with both checks.
	// | SnapshotChecksumCRC32CSHA256 写入同时包含两种校验的原始布局。
	SnapshotChecksumCRC32CSHA256 SnapshotChecksum = iota
	// SnapshotChecksumCRC32C writes CRC32C only, saving one full SHA-256 pass
	// over very large images. | SnapshotChecksumCRC32C 仅写入 CRC32C，对超大
	// 镜像节省一次完整 SHA-256 扫描。
	SnapshotChecksumCRC32C
)

// FileStorageOptions configures durable WAL and snapshot storage. | FileStorageOptions
// 配置持久化 WAL 与快照存储。
type FileStorageOptions struct {
	// Dir is the storage root. WAL lives in Dir/wal and snapshots default to
	// Dir/snapshots. | Dir 是存储根目录；WAL 位于 Dir/wal，快照默认为
	// Dir/snapshots。
	Dir string
	// SnapshotDir optionally places snapshot images on a different volume from
	// the WAL. Empty uses Dir/snapshots. The directory is owned exclusively by
	// this storage instance; the lock remains in Dir. | SnapshotDir 可选地将快照
	// 镜像放在与 WAL 不同的卷；为空时使用 Dir/snapshots。该目录由本存储实例独占；
	// 锁仍位于 Dir。
	SnapshotDir string
	// SegmentSize rotates the WAL after this many bytes. Default 64 MiB.
	// | SegmentSize 在达到该字节数后轮转 WAL，默认 64 MiB。
	SegmentSize int64
	// SnapshotKeep is the number of snapshot files retained. Default 2.
	// | SnapshotKeep 是保留的快照文件数量，默认 2。
	SnapshotKeep int
	// NoSync disables fsync. It is intended only for ephemeral benchmarks and
	// tests where crash durability is not under test. | NoSync 关闭 fsync，仅用于
	// 不测试崩溃持久性的临时基准与测试。
	NoSync bool
	// SnapshotChecksum selects the integrity check for new snapshot images.
	// Existing v1 and v2 files remain readable. Default CRC32C + SHA-256. |
	// SnapshotChecksum 选择新快照镜像的完整性校验。已有的 v1 与 v2 文件仍可读取。
	// 默认 CRC32C + SHA-256。
	SnapshotChecksum SnapshotChecksum
}

// FileStorage is a crash-safe Storage backed by WAL segments and snapshot files.
// | FileStorage 是由 WAL 分段与快照文件支撑的崩溃安全 Storage。
type FileStorage struct {
	wal              *wal
	snapshot         *Snapshot
	lockFile         *os.File
	dir              string
	walDir           string
	snapDir          string
	recovery         Recovery
	segmentSize      int64
	snapshotKeep     int
	snapshotChecksum SnapshotChecksum
	mu               sync.Mutex
	noSync           bool
	loaded           bool
	closed           bool
}

// NewFileStorage creates the directory layout. | NewFileStorage 创建目录布局。
func NewFileStorage(opts FileStorageOptions) (*FileStorage, error) {
	if opts.Dir == "" {
		return nil, errs.Detail(ErrInvalidConfig, "file storage Dir is required")
	}
	if opts.SegmentSize <= 0 {
		opts.SegmentSize = 64 << 20
	}
	if opts.SnapshotKeep <= 0 {
		opts.SnapshotKeep = 2
	}
	if opts.SnapshotChecksum != SnapshotChecksumCRC32CSHA256 &&
		opts.SnapshotChecksum != SnapshotChecksumCRC32C {
		return nil, errs.Detail(ErrInvalidConfig, "unknown SnapshotChecksum %d", opts.SnapshotChecksum)
	}
	snapDir := opts.SnapshotDir
	if snapDir == "" {
		snapDir = filepath.Join(opts.Dir, "snapshots")
	}
	s := &FileStorage{
		dir:              opts.Dir,
		walDir:           filepath.Join(opts.Dir, "wal"),
		snapDir:          snapDir,
		noSync:           opts.NoSync,
		segmentSize:      opts.SegmentSize,
		snapshotKeep:     opts.SnapshotKeep,
		snapshotChecksum: opts.SnapshotChecksum,
	}
	if err := os.MkdirAll(s.walDir, 0o700); err != nil {
		return nil, errs.Wrap(err, ErrStorage)
	}
	if err := os.MkdirAll(s.snapDir, 0o700); err != nil {
		return nil, errs.Wrap(err, ErrStorage)
	}
	lockPath := filepath.Join(opts.Dir, "LOCK")
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, errs.Wrap(err, ErrStorage)
	}
	if err := lockDirectory(lockFile); err != nil {
		_ = lockFile.Close()
		return nil, errs.WrapDetail(err, ErrStorageLocked, "%s", lockPath)
	}
	s.lockFile = lockFile
	// The directory lock makes it safe to remove temporary snapshot files left
	// by a process that crashed mid-write. | 目录锁使清理崩溃进程遗留的临时快照
	// 文件变得安全。
	cleanupSnapshotTemps(s.snapDir)
	return s, nil
}

// cleanupSnapshotTemps removes partial snapshot files from a prior crash. | cleanupSnapshotTemps
// 清理上次崩溃遗留的不完整快照文件。
func cleanupSnapshotTemps(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), ".snap-") {
			continue
		}
		_ = os.Remove(filepath.Join(dir, entry.Name()))
	}
}

// Load implements Storage. It must be called once before the first Persist; the
// returned entries and snapshot are transferred to the caller and must not be
// requested a second time. | Load 实现 Storage。必须在首次 Persist 前调用一次；
// 返回的日志项与快照移交给调用方，不得再次请求。
func (s *FileStorage) Load() (Recovery, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Recovery{}, ErrStopped
	}
	if s.loaded {
		return s.recovery, nil
	}
	return s.loadLocked()
}

// loadLocked opens the snapshot referenced by the WAL and replays segments.
// | loadLocked 打开 WAL 引用的快照并重放分段。
func (s *FileStorage) loadLocked() (Recovery, error) {
	w, rec, marker, err := openWAL(s.walDir, s.noSync, s.segmentSize)
	if err != nil {
		return Recovery{}, err
	}
	var snap *Snapshot
	if marker.found {
		snap, err = readSnapshotFile(s.snapshotPath(marker.index, marker.term))
		if err != nil {
			_ = w.close()
			return Recovery{}, errs.Wrap(err, ErrCorrupt)
		}
		if snap.Index != marker.index || snap.Term != marker.term {
			_ = w.close()
			return Recovery{}, errs.Detail(ErrCorrupt,
				"snapshot file %d/%d does not match marker %d/%d",
				snap.Index, snap.Term, marker.index, marker.term)
		}
	}
	s.wal = w
	s.snapshot = snap
	s.recovery = Recovery{HardState: rec.hs, Snapshot: snap, Entries: rec.entries}
	s.loaded = true
	return s.recovery, nil
}

// Persist implements Storage. | Persist 实现 Storage。
func (s *FileStorage) Persist(batch PersistBatch) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStopped
	}
	if !s.loaded {
		if _, err := s.loadLocked(); err != nil {
			return err
		}
	}
	if batch.Snapshot == nil {
		return s.wal.append(batch)
	}
	// Snapshots are monotonic. Ignoring an older image here protects the WAL
	// marker and in-memory base from a late local snapshot completing after a
	// newer InstallSnapshot; its hard state is still made durable. | 快照索引单调
	// 递增。此处忽略旧镜像，避免较晚完成的本地快照在更新的 InstallSnapshot 之后
	// 回退 WAL 标记与内存基点；其硬状态仍会持久化。
	if s.snapshot != nil && batch.Snapshot.Index <= s.snapshot.Index {
		if batch.HardState != nil {
			return s.wal.append(PersistBatch{HardState: batch.HardState})
		}
		return nil
	}
	// Ordering: the snapshot file is written first, then the WAL marker is made
	// durable. Recovery only trusts snapshots named by a marker, so a crash
	// before the marker leaves the previous log intact. | 顺序：先写快照文件，再持久化
	// WAL 标记。恢复只信任带标记的快照，因此标记前的崩溃会保留旧日志。
	if err := s.writeSnapshotFile(batch.Snapshot, s.noSync); err != nil {
		return err
	}
	// A local compaction snapshot can share the current segment: entries after
	// the snapshot base are still valid and recovery skips older ones. An
	// InstallSnapshot replaces the whole prior log, so rotate first; otherwise
	// stale entries already in the active segment would survive compactAll.
	// | 本地压缩快照可与当前分段共用：快照基点之后的日志项仍有效，恢复会跳过更旧的
	// 日志项。InstallSnapshot 替换整段旧日志，必须先轮转；否则活动分段中已有的过期
	// 日志项会在 compactAll 后残留。
	if batch.SnapshotReplacesLog {
		if err := s.wal.rotateLocked(); err != nil {
			return err
		}
	}
	marker := PersistBatch{
		HardState:           batch.HardState,
		Snapshot:            &Snapshot{Index: batch.Snapshot.Index, Term: batch.Snapshot.Term},
		SnapshotReplacesLog: batch.SnapshotReplacesLog,
	}
	if err := s.wal.append(marker); err != nil {
		return err
	}
	// Only the index and term of the newest snapshot are needed for staleness
	// checks and pruning. Keeping the full data here would duplicate a large
	// image in memory for the lifetime of the store. | 最新快照仅需索引与任期用于
	// 过期检查与清理；在存储生命周期内保留完整数据会复制一份大镜像。
	s.snapshot = &Snapshot{Index: batch.Snapshot.Index, Term: batch.Snapshot.Term}
	if batch.SnapshotReplacesLog {
		// An InstallSnapshot replaces the entire prior log. Compact(index) keeps
		// segments whose last entry is beyond the snapshot, including stale
		// entries from before the marker, so the reset path must remove them now.
		// Local snapshots are compacted by the node through Storage.Compact.
		// | InstallSnapshot 替换此前整段日志。Compact(index) 会保留末项超过快照的
		// 分段，其中包括标记之前的过期日志项，因此重置路径必须立即删除；本地快照
		// 由节点通过 Storage.Compact 压缩。
		_ = s.wal.compactAll()
	}
	s.pruneSnapshotsLocked()
	return nil
}

// Compact implements Storage. | Compact 实现 Storage。
func (s *FileStorage) Compact(index uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStopped
	}
	if !s.loaded {
		if _, err := s.loadLocked(); err != nil {
			return err
		}
	}
	if err := s.wal.compact(index); err != nil {
		return err
	}
	s.pruneSnapshotsLocked()
	return nil
}

// Close implements Storage. | Close 实现 Storage。
func (s *FileStorage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var err error
	if s.wal != nil {
		err = s.wal.close()
	}
	if s.lockFile != nil {
		if cerr := s.lockFile.Close(); cerr != nil && err == nil {
			err = errs.Wrap(cerr, ErrStorage)
		}
		s.lockFile = nil
	}
	return err
}
