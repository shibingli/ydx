package raft

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash/crc32"
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
	mu           sync.Mutex
	dir          string
	walDir       string
	snapDir      string
	noSync       bool
	segmentSize  int64
	snapshotKeep int
	wal          *wal
	snapshot     *Snapshot
	recovery     Recovery
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
	return s, nil
}

// Load implements Storage. | Load 实现 Storage。
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
	marker, err := scanWALMarkers(s.walDir)
	if err != nil {
		return Recovery{}, err
	}
	var snap *Snapshot
	base := uint64(0)
	if marker.found {
		snap, err = readSnapshotFile(s.snapshotPath(marker.index, marker.term))
		if err != nil {
			return Recovery{}, errs.Wrap(err, ErrCorrupt)
		}
		base = snap.Index
	}
	w, rec, err := openWAL(s.walDir, base, s.noSync, s.segmentSize)
	if err != nil {
		return Recovery{}, err
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
	// Ordering: the snapshot file is written first, then the WAL marker is made
	// durable. Recovery only trusts snapshots named by a marker, so a crash
	// before the marker leaves the previous log intact. | 顺序：先写快照文件，再持久化
	// WAL 标记。恢复只信任带标记的快照，因此标记前的崩溃会保留旧日志。
	if err := s.writeSnapshotFile(batch.Snapshot); err != nil {
		return err
	}
	if err := s.wal.rotateLocked(); err != nil {
		return err
	}
	marker := PersistBatch{
		HardState:           batch.HardState,
		Snapshot:            &Snapshot{Index: batch.Snapshot.Index, Term: batch.Snapshot.Term},
		SnapshotReplacesLog: batch.SnapshotReplacesLog,
	}
	if err := s.wal.append(marker); err != nil {
		return err
	}
	s.snapshot = batch.Snapshot.clone()
	if batch.SnapshotReplacesLog {
		_ = s.wal.compactAll()
	} else {
		_ = s.wal.compact(batch.Snapshot.Index)
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
	if s.wal == nil {
		return nil
	}
	return s.wal.close()
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
	dataCRC := crc32.Checksum(snap.Data, castagnoli)
	sum := sha256.Sum256(snap.Data)
	header := make([]byte, 0, 8+1+8+8+4+len(conf)+8+4+32)
	header = append(header, snapshotMagic...)
	header = append(header, snapshotVersion)
	header = binary.LittleEndian.AppendUint64(header, snap.Index)
	header = binary.LittleEndian.AppendUint64(header, snap.Term)
	header = binary.LittleEndian.AppendUint32(header, uint32(len(conf)))
	header = append(header, conf...)
	header = binary.LittleEndian.AppendUint64(header, uint64(len(snap.Data)))
	header = binary.LittleEndian.AppendUint32(header, dataCRC)
	header = append(header, sum[:]...)
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
	if _, err := tmp.Write(header); err != nil {
		return errs.Wrap(err, ErrStorage)
	}
	if _, err := tmp.Write(snap.Data); err != nil {
		return errs.Wrap(err, ErrStorage)
	}
	if !s.noSync {
		if err := tmp.Sync(); err != nil {
			return errs.Wrap(err, ErrStorage)
		}
	}
	if err := tmp.Close(); err != nil {
		return errs.Wrap(err, ErrStorage)
	}
	final := s.snapshotPath(snap.Index, snap.Term)
	_ = os.Remove(final)
	if err := os.Rename(tmpName, final); err != nil {
		return errs.Wrap(err, ErrStorage)
	}
	cleanup = false
	syncDir(s.snapDir)
	return nil
}

// readSnapshotFile loads and validates one snapshot image. | readSnapshotFile 加载
// 并校验一个快照镜像。
func readSnapshotFile(path string) (*Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errs.Wrap(err, ErrStorage)
	}
	const fixed = 8 + 1 + 8 + 8 + 4
	if len(data) < fixed+8+4+32 {
		return nil, errs.Detail(ErrCorrupt, "short snapshot %s", path)
	}
	if string(data[:8]) != snapshotMagic {
		return nil, errs.Detail(ErrCorrupt, "bad snapshot magic %s", path)
	}
	if data[8] != snapshotVersion {
		return nil, errs.Detail(ErrCorrupt, "snapshot version %d", data[8])
	}
	pos := 9
	index := binary.LittleEndian.Uint64(data[pos:])
	pos += 8
	term := binary.LittleEndian.Uint64(data[pos:])
	pos += 8
	confLen := int(binary.LittleEndian.Uint32(data[pos:]))
	pos += 4
	if confLen < 0 || confLen > maxConfBytes || pos+confLen > len(data) {
		return nil, errs.Detail(ErrCorrupt, "snapshot conf length %d", confLen)
	}
	conf, err := decodeConfStateBytes(data[pos : pos+confLen])
	if err != nil {
		return nil, err
	}
	pos += confLen
	if pos+8+4+32 > len(data) {
		return nil, errs.Detail(ErrCorrupt, "short snapshot header %s", path)
	}
	dataLen := binary.LittleEndian.Uint64(data[pos:])
	pos += 8
	wantCRC := binary.LittleEndian.Uint32(data[pos:])
	pos += 4
	var wantSum [32]byte
	copy(wantSum[:], data[pos:pos+32])
	pos += 32
	if dataLen > uint64(len(data)-pos) {
		return nil, errs.Detail(ErrCorrupt, "snapshot data length %d", dataLen)
	}
	payload := data[pos : pos+int(dataLen)]
	if crc32.Checksum(payload, castagnoli) != wantCRC {
		return nil, errs.Detail(ErrCorrupt, "snapshot CRC mismatch %s", path)
	}
	if sum := sha256.Sum256(payload); sum != wantSum {
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

// syncDir makes a rename durable on platforms that support directory sync.
// | syncDir 在支持目录同步的平台上保证重命名持久化。
func syncDir(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	_ = f.Sync()
	_ = f.Close()
}
