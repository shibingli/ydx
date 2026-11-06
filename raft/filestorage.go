package raft

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/shibingli/ydx/errs"
)

const (
	snapshotMagic   = "YDRSNP01"
	snapshotVersion = byte(1)
	maxConfBytes    = 4 << 20
)

// FileStorageOptions configures durable WAL and snapshot storage. | FileStorageOptions
// 配置持久化 WAL 与快照存储。
type FileStorageOptions struct {
	// Dir is the storage root. WAL and snapshots live in subdirectories. | Dir
	// 是存储根目录；WAL 与快照位于其子目录。
	Dir string
	// NoSync disables fsync. It is intended only for ephemeral benchmarks and
	// tests where crash durability is not under test. | NoSync 关闭 fsync，仅用于
	// 不测试崩溃持久性的临时基准与测试。
	NoSync bool
	// SegmentSize rotates the WAL after this many bytes. Default 64 MiB.
	// | SegmentSize 在达到该字节数后轮转 WAL，默认 64 MiB。
	SegmentSize int64
	// SnapshotKeep is the number of snapshot files retained. Default 2.
	// | SnapshotKeep 是保留的快照文件数量，默认 2。
	SnapshotKeep int
}

// FileStorage is a crash-safe Storage backed by WAL segments and snapshot files.
// | FileStorage 是由 WAL 分段与快照文件支撑的崩溃安全 Storage。
type FileStorage struct {
	wal          *wal
	snapshot     *Snapshot
	lockFile     *os.File
	dir          string
	walDir       string
	snapDir      string
	recovery     Recovery
	segmentSize  int64
	snapshotKeep int
	mu           sync.Mutex
	noSync       bool
	loaded       bool
	closed       bool
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
	s := &FileStorage{
		dir:          opts.Dir,
		walDir:       filepath.Join(opts.Dir, "wal"),
		snapDir:      filepath.Join(opts.Dir, "snapshots"),
		noSync:       opts.NoSync,
		segmentSize:  opts.SegmentSize,
		snapshotKeep: opts.SnapshotKeep,
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
	if err := s.writeSnapshotFile(batch.Snapshot); err != nil {
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

// snapshotPath returns the canonical file name for an index and term. | snapshotPath
// 返回索引与任期的规范文件名。
func (s *FileStorage) snapshotPath(index, term uint64) string {
	return filepath.Join(s.snapDir, fmt.Sprintf("%020d-%020d.snap", index, term))
}

// writeSnapshotFile atomically writes one snapshot image. | writeSnapshotFile 原子
// 写入一个快照镜像。
func (s *FileStorage) writeSnapshotFile(snap *Snapshot) error {
	conf := appendConfState(nil, snap.ConfState)
	if len(conf) > maxConfBytes {
		return errs.Detail(ErrTooLarge, "snapshot conf state %d bytes", len(conf))
	}
	// Compute both checksums while the payload is written, not in two separate
	// full passes over a potentially large image. | 在写入负载时同时计算两种校验和，
	// 避免对可能很大的镜像做两次完整扫描。
	tmp, err := os.CreateTemp(s.snapDir, ".snap-*")
	if err != nil {
		return errs.Wrap(err, ErrStorage)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return errs.Wrap(err, ErrStorage)
	}
	headerLen := 8 + 1 + 8 + 8 + 4 + len(conf) + 8 + 4 + 32
	if _, err := tmp.Write(make([]byte, headerLen)); err != nil {
		return errs.Wrap(err, ErrStorage)
	}
	dataCRC := crc32.New(castagnoli)
	dataHash := sha256.New()
	if n, err := io.MultiWriter(tmp, dataCRC, dataHash).Write(snap.Data); err != nil {
		return errs.Wrap(err, ErrStorage)
	} else if n != len(snap.Data) {
		return errs.Detail(ErrStorage, "short snapshot write %d/%d | 快照写入不完整 %d/%d", n, len(snap.Data), n, len(snap.Data))
	}
	header := make([]byte, 0, headerLen)
	header = append(header, snapshotMagic...)
	header = append(header, snapshotVersion)
	header = binary.LittleEndian.AppendUint64(header, snap.Index)
	header = binary.LittleEndian.AppendUint64(header, snap.Term)
	header = binary.LittleEndian.AppendUint32(header, uint32(len(conf)))
	header = append(header, conf...)
	header = binary.LittleEndian.AppendUint64(header, uint64(len(snap.Data)))
	header = binary.LittleEndian.AppendUint32(header, dataCRC.Sum32())
	header = append(header, dataHash.Sum(nil)...)
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return errs.Wrap(err, ErrStorage)
	}
	if _, err := tmp.Write(header); err != nil {
		return errs.Wrap(err, ErrStorage)
	}
	if !s.noSync {
		if err := syncFile(tmp); err != nil {
			return errs.Wrap(err, ErrStorage)
		}
	}
	if err := tmp.Close(); err != nil {
		return errs.Wrap(err, ErrStorage)
	}
	final := s.snapshotPath(snap.Index, snap.Term)
	// os.Rename replaces the destination atomically on Unix and uses
	// MOVEFILE_REPLACE_EXISTING on Windows. Removing the destination first would
	// leave a window where a crash loses the only snapshot referenced by the WAL.
	// | 在 Unix 上 os.Rename 原子替换目标，在 Windows 上使用
	// MOVEFILE_REPLACE_EXISTING。先删除目标会在崩溃时留下丢失 WAL 所引用唯一快照的
	// 窗口。
	if err := os.Rename(tmpName, final); err != nil {
		return errs.Wrap(err, ErrStorage)
	}
	cleanup = false
	if !s.noSync {
		if err := syncDir(s.snapDir); err != nil {
			return errs.Wrap(err, ErrStorage)
		}
	}
	return nil
}

// readSnapshotFile loads and validates one snapshot image. | readSnapshotFile 加载
// 并校验一个快照镜像。
func readSnapshotFile(path string) (*Snapshot, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errs.Wrap(err, ErrStorage)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, errs.Wrap(err, ErrStorage)
	}
	const fixed = 8 + 1 + 8 + 8 + 4
	if info.Size() < int64(fixed+8+4+32) {
		return nil, errs.Detail(ErrCorrupt, "short snapshot %s", path)
	}
	header := make([]byte, fixed)
	if _, err := io.ReadFull(f, header); err != nil {
		return nil, errs.Detail(ErrCorrupt, "short snapshot header %s", path)
	}
	if string(header[:8]) != snapshotMagic {
		return nil, errs.Detail(ErrCorrupt, "bad snapshot magic %s", path)
	}
	if header[8] != snapshotVersion {
		return nil, errs.Detail(ErrCorrupt, "snapshot version %d", header[8])
	}
	pos := 9
	index := binary.LittleEndian.Uint64(header[pos:])
	pos += 8
	term := binary.LittleEndian.Uint64(header[pos:])
	pos += 8
	confLen := int(binary.LittleEndian.Uint32(header[pos:]))
	if confLen < 0 || confLen > maxConfBytes {
		return nil, errs.Detail(ErrCorrupt, "snapshot conf length %d", confLen)
	}
	confData := make([]byte, confLen)
	if _, err := io.ReadFull(f, confData); err != nil {
		return nil, errs.Detail(ErrCorrupt, "short snapshot conf %s", path)
	}
	conf, err := decodeConfStateBytes(confData)
	if err != nil {
		return nil, err
	}
	var trailer [8 + 4 + 32]byte
	if _, err := io.ReadFull(f, trailer[:]); err != nil {
		return nil, errs.Detail(ErrCorrupt, "short snapshot header %s", path)
	}
	dataLen := binary.LittleEndian.Uint64(trailer[:8])
	wantCRC := binary.LittleEndian.Uint32(trailer[8:12])
	var wantSum [32]byte
	copy(wantSum[:], trailer[12:])
	headerLen := int64(fixed + confLen + len(trailer))
	if dataLen > uint64(info.Size()-headerLen) || headerLen+int64(dataLen) != info.Size() {
		return nil, errs.Detail(ErrCorrupt, "snapshot data length %d", dataLen)
	}
	payload := make([]byte, int(dataLen))
	gotCRC := crc32.New(castagnoli)
	gotHash := sha256.New()
	if _, err := io.ReadFull(io.TeeReader(f, io.MultiWriter(gotCRC, gotHash)), payload); err != nil {
		return nil, errs.Detail(ErrCorrupt, "short snapshot payload %s", path)
	}
	if gotCRC.Sum32() != wantCRC {
		return nil, errs.Detail(ErrCorrupt, "snapshot CRC mismatch %s", path)
	}
	if !bytes.Equal(gotHash.Sum(nil), wantSum[:]) {
		return nil, errs.Detail(ErrCorrupt, "snapshot SHA-256 mismatch %s", path)
	}
	if index == 0 || term == 0 {
		return nil, errs.Detail(ErrCorrupt, "snapshot index=%d term=%d", index, term)
	}
	return &Snapshot{Index: index, Term: term, ConfState: conf, Data: payload}, nil
}

// pruneSnapshotsLocked removes old snapshot files beyond the retention count.
// | pruneSnapshotsLocked 删除超出保留数量的旧快照文件。
func (s *FileStorage) pruneSnapshotsLocked() {
	entries, err := os.ReadDir(s.snapDir)
	if err != nil {
		return
	}
	type snapFile struct {
		name  string
		index uint64
		term  uint64
	}
	var files []snapFile
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".snap") {
			continue
		}
		base := strings.TrimSuffix(entry.Name(), ".snap")
		parts := strings.Split(base, "-")
		if len(parts) != 2 {
			continue
		}
		index, err1 := strconv.ParseUint(parts[0], 10, 64)
		term, err2 := strconv.ParseUint(parts[1], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		files = append(files, snapFile{name: entry.Name(), index: index, term: term})
	}
	sort.Slice(files, func(i, j int) bool {
		if files[i].index != files[j].index {
			return files[i].index > files[j].index
		}
		return files[i].term > files[j].term
	})
	current := ""
	if s.snapshot != nil {
		current = filepath.Base(s.snapshotPath(s.snapshot.Index, s.snapshot.Term))
	}
	kept := 0
	for _, f := range files {
		if f.name == current {
			kept++
			continue
		}
		if kept < s.snapshotKeep {
			kept++
			continue
		}
		_ = os.Remove(filepath.Join(s.snapDir, f.name))
	}
}
