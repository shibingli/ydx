package raft

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/shibingli/ydx/errs"
)

// snapshotPath returns the canonical file name for an index and term. | snapshotPath
// 返回索引与任期的规范文件名。
func (s *FileStorage) snapshotPath(index, term uint64) string {
	return filepath.Join(s.snapDir, fmt.Sprintf(snapshotNameFormat, index, term))
}

// WriteSnapshotFile writes and fsyncs one local snapshot image without touching
// the WAL. The caller must later call PersistLocalSnapshotMarker to make the
// image trusted by recovery. It is safe to run while WAL appends continue. |
// WriteSnapshotFile 写入并 fsync 一个本地快照镜像，不接触 WAL。调用方随后必须调用
// PersistLocalSnapshotMarker 使恢复信任该镜像。它可以与 WAL 追加并发执行。
func (s *FileStorage) WriteSnapshotFile(snap *Snapshot) error {
	if snap == nil {
		return errs.Detail(ErrInvalidConfig, "nil snapshot")
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrStopped
	}
	if !s.loaded {
		if _, err := s.loadLocked(); err != nil {
			s.mu.Unlock()
			return err
		}
	}
	noSync := s.noSync
	s.mu.Unlock()
	// The image is uniquely named and independent of the WAL. Do not hold the
	// storage mutex across the large fsync; WAL appends must continue. | 镜像名
	// 唯一且与 WAL 独立，不在大 fsync 期间持有存储锁，WAL 追加可以继续。
	return s.writeSnapshotFile(snap, noSync)
}

// PersistLocalSnapshotMarker appends the WAL marker for a local image written
// by WriteSnapshotFile. It is serialized with WAL appends and ignores an image
// older than the current snapshot base. | PersistLocalSnapshotMarker 为
// WriteSnapshotFile 写好的本地镜像追加 WAL 标记。它与 WAL 追加串行，并忽略比当前
// 快照基点更旧的镜像。
func (s *FileStorage) PersistLocalSnapshotMarker(snap *Snapshot, hs *HardState) error {
	return s.PersistLocalSnapshotMarkerBatch(snap, PersistBatch{HardState: hs})
}

// PersistLocalSnapshotMarkerBatch appends the deferred marker and the queued WAL
// batch in one WAL record. One write and one fsync cover both, so an ongoing
// proposal stream pays no extra snapshot fsync. Entry ordering is unchanged: the
// marker precedes entries in the record and recovery applies it first. |
// PersistLocalSnapshotMarkerBatch 将延迟标记与排队的 WAL 批次写入同一条 WAL
// 记录；一次 write 与一次 fsync 覆盖两者，因此持续提案流不再为快照多付一次 fsync。
// 日志项顺序不变：记录中标记在日志项之前，恢复也先应用标记。
func (s *FileStorage) PersistLocalSnapshotMarkerBatch(snap *Snapshot, batch PersistBatch) error {
	if snap == nil {
		return errs.Detail(ErrInvalidConfig, "nil snapshot")
	}
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
	if s.snapshot != nil && snap.Index <= s.snapshot.Index {
		if batch.HardState == nil && batch.Truncate == 0 && len(batch.Entries) == 0 {
			return nil
		}
		return s.wlog.append(batch)
	}
	batch.Snapshot = &Snapshot{Index: snap.Index, Term: snap.Term}
	batch.SnapshotReplacesLog = false
	if err := s.wlog.append(batch); err != nil {
		return err
	}
	// Only metadata is retained; the image file itself is already durable. |
	// 仅保留元数据；镜像文件本身已持久化。
	s.snapshot = &Snapshot{Index: snap.Index, Term: snap.Term}
	s.pruneSnapshotsLocked()
	return nil
}

// writeSnapshotFile atomically writes one snapshot image. | writeSnapshotFile 原子
// 写入一个快照镜像。
func (s *FileStorage) writeSnapshotFile(snap *Snapshot, noSync bool) error {
	conf := appendConfState(nil, snap.ConfState)
	if len(conf) > maxConfBytes {
		return errs.Detail(ErrTooLarge, "snapshot conf state %d bytes", len(conf))
	}
	// A received chunked snapshot is staged in a temp file and must be copied
	// through the normal header/checksum/encryption writer without loading it
	// into the heap. | 接收的分块快照暂存在临时文件，必须经过正常的头部/校验/加密
	// 写入器复制，而不能载入堆内存。
	dataLen := int64(len(snap.Data))
	var dataSrc io.Reader
	if snap.file != "" {
		src, err := os.Open(snap.file)
		if err != nil {
			return errs.Wrap(err, ErrStorage)
		}
		defer src.Close()
		if snap.dataSize > 0 {
			dataLen = snap.dataSize
		} else if info, err := src.Stat(); err == nil {
			dataLen = info.Size()
		}
		if dataLen <= 0 {
			return errs.Detail(ErrStorage, "empty staged snapshot")
		}
		dataSrc = src
	}
	// Compute checksums while the payload is written, not in separate full
	// passes over a potentially large image. CRC-only mode skips the SHA-256
	// scan entirely. | 在写入负载时计算校验和，避免对可能很大的镜像做多次完整扫描。
	// 仅 CRC 模式完全跳过 SHA-256 扫描。
	tmp, err := os.CreateTemp(s.snapDir, snapshotTempPattern)
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
	useSHA := s.snapshotChecksum != SnapshotChecksumCRC32C
	encrypted := s.cipher.encrypts(EncryptSnapshots)
	headerLen := snapshotHeaderSize(len(conf), useSHA)
	if encrypted {
		headerLen = encryptedSnapshotHeaderSize(len(conf))
	}
	if _, err := tmp.Write(make([]byte, headerLen)); err != nil {
		return errs.Wrap(err, ErrStorage)
	}
	dataCRC := crc32.New(castagnoli)
	sink := io.Writer(tmp)
	var meta *snapshotCrypto
	var seal *snapshotSealWriter
	if encrypted {
		key := s.cipher.activeKey()
		salt, err := snapshotSalt()
		if err != nil {
			return err
		}
		meta = &snapshotCrypto{
			cipher:    s.cipher,
			keyID:     key.id,
			suite:     key.suite,
			salt:      salt,
			chunkSize: s.cipher.chunkSize,
			index:     snap.Index,
			term:      snap.Term,
			dataLen:   dataLen,
			headerLen: int64(headerLen),
			prefixHash: snapshotPrefixHash(snap.Index, snap.Term, key.id, key.suite,
				snapshotChecksumFlag(useSHA), salt, s.cipher.chunkSize, conf),
		}
		seal, err = newSnapshotSealWriter(tmp, meta)
		if err != nil {
			return err
		}
		sink = seal
	}
	writers := []io.Writer{sink, dataCRC}
	var dataHash hash.Hash
	if useSHA {
		dataHash = sha256.New()
		writers = append(writers, dataHash)
	}
	var written int64
	var writeErr error
	if dataSrc != nil {
		written, writeErr = io.Copy(io.MultiWriter(writers...), dataSrc)
	} else {
		var n int
		n, writeErr = io.MultiWriter(writers...).Write(snap.Data)
		written = int64(n)
	}
	if writeErr != nil {
		return errs.Wrap(writeErr, ErrStorage)
	}
	if written != dataLen {
		return errs.Detail(ErrStorage, "short snapshot write %d/%d | 快照写入不完整 %d/%d", written, dataLen, written, dataLen)
	}
	if seal != nil {
		if err := seal.Close(uint64(dataLen)); err != nil {
			return errs.Wrap(err, ErrStorage)
		}
	}
	var sum []byte
	if dataHash != nil {
		sum = dataHash.Sum(nil)
	}
	var header []byte
	if encrypted {
		header = encodeEncryptedSnapshotHeader(make([]byte, 0, headerLen), conf,
			snap.Index, snap.Term, uint64(dataLen), dataCRC.Sum32(), sum, useSHA,
			meta.keyID, meta.suite, meta.salt, meta.chunkSize)
	} else {
		header = encodeSnapshotFileHeader(make([]byte, 0, headerLen), conf,
			snap.Index, snap.Term, uint64(dataLen), dataCRC.Sum32(), sum, useSHA)
	}
	if len(header) != headerLen {
		return errs.Detail(ErrStorage, "snapshot header size %d, want %d | 快照头部长度 %d，期望 %d",
			len(header), headerLen, len(header), headerLen)
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return errs.Wrap(err, ErrStorage)
	}
	if _, err := tmp.Write(header); err != nil {
		return errs.Wrap(err, ErrStorage)
	}
	if !noSync {
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
	if !noSync {
		if err := syncDir(s.snapDir); err != nil {
			return errs.Wrap(err, ErrStorage)
		}
	}
	if dataSrc != nil {
		// The input was a staged raw payload. Keep snap.file pointing at it for
		// the apply restore; the event loop publishes the final image fields
		// after this write is acknowledged. | 输入是暂存的原始负载。保持 snap.file
		// 指向它供 apply 还原；事件循环在写入确认后发布最终镜像字段。
		snap.finalFile = final
		snap.finalOffset = int64(headerLen)
		snap.finalCrypto = meta
		return nil
	}
	// Record the backing file so a completed local image can release its heap
	// payload and later senders can read it on demand. | 记录底层文件，使完成的本地
	// 镜像可释放堆负载，后续发送方也能按需读取。
	snap.file = final
	snap.dataSize = dataLen
	snap.dataOffset = int64(headerLen)
	snap.crypto = meta
	return nil
}

// readSnapshotFileWith loads and validates one snapshot image, decrypting a
// version 3 image when cipher is configured. | readSnapshotFileWith 加载并校验快照
// 镜像；配置 cipher 时解密版本 3 镜像。
func readSnapshotFileWith(path string, cipher *dataCipher) (*Snapshot, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errs.Wrap(err, ErrStorage)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, errs.Wrap(err, ErrStorage)
	}
	var prefix [9]byte
	if _, err := io.ReadFull(f, prefix[:]); err != nil {
		return nil, errs.Detail(ErrCorrupt, "short snapshot header %s", path)
	}
	if string(prefix[:8]) != snapshotMagic {
		return nil, errs.Detail(ErrCorrupt, "bad snapshot magic %s", path)
	}
	version := prefix[8]
	if version != snapshotVersion && version != snapshotVersionCRCOnly &&
		version != snapshotVersionEncrypted {
		return nil, errs.Detail(ErrCorrupt, "snapshot version %d", version)
	}
	if version != snapshotVersionEncrypted && cipher != nil &&
		cipher.encrypts(EncryptSnapshots) && !cipher.allowPlaintextFiles {
		return nil, errs.Detail(ErrInvalidConfig,
			"plaintext snapshot with snapshot encryption enabled | 启用快照加密时遇到明文快照")
	}
	var fixed [20]byte
	if _, err := io.ReadFull(f, fixed[:]); err != nil {
		return nil, errs.Detail(ErrCorrupt, "short snapshot header %s", path)
	}
	index := binary.LittleEndian.Uint64(fixed[0:8])
	term := binary.LittleEndian.Uint64(fixed[8:16])
	confLen := int(binary.LittleEndian.Uint32(fixed[16:20]))
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
	var tail [8 + 4]byte
	if _, err := io.ReadFull(f, tail[:]); err != nil {
		return nil, errs.Detail(ErrCorrupt, "short snapshot header %s", path)
	}
	dataLen := binary.LittleEndian.Uint64(tail[:8])
	wantCRC := binary.LittleEndian.Uint32(tail[8:12])
	if version == snapshotVersionEncrypted {
		return readEncryptedSnapshot(path, f, info, conf, confData, confLen, index, term, dataLen, wantCRC, cipher)
	}
	hasSHA := version == snapshotVersion
	trailerLen := int64(32)
	if version == snapshotVersionCRCOnly {
		var flags [1]byte
		if _, err := io.ReadFull(f, flags[:]); err != nil {
			return nil, errs.Detail(ErrCorrupt, "short snapshot flags %s", path)
		}
		if flags[0]&^snapshotFlagSHA256 != 0 {
			return nil, errs.Detail(ErrCorrupt, "snapshot checksum flags %d", flags[0])
		}
		hasSHA = flags[0]&snapshotFlagSHA256 != 0
		trailerLen = 1 + 32
	}
	var wantSum [32]byte
	if _, err := io.ReadFull(f, wantSum[:]); err != nil {
		return nil, errs.Detail(ErrCorrupt, "short snapshot header %s", path)
	}
	headerLen := int64(9+20+confLen+12) + trailerLen
	if headerLen > info.Size() || dataLen != uint64(info.Size()-headerLen) {
		return nil, errs.Detail(ErrCorrupt, "snapshot data length %d", dataLen)
	}
	payload := make([]byte, int(dataLen))
	gotCRC := crc32.New(castagnoli)
	writers := []io.Writer{gotCRC}
	var gotHash hash.Hash
	if hasSHA {
		gotHash = sha256.New()
		writers = append(writers, gotHash)
	}
	if _, err := io.ReadFull(io.TeeReader(f, io.MultiWriter(writers...)), payload); err != nil {
		return nil, errs.Detail(ErrCorrupt, "short snapshot payload %s", path)
	}
	if gotCRC.Sum32() != wantCRC {
		return nil, errs.Detail(ErrCorrupt, "snapshot CRC mismatch %s", path)
	}
	if hasSHA && !bytes.Equal(gotHash.Sum(nil), wantSum[:]) {
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
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), snapshotFileSuffix) {
			continue
		}
		base := strings.TrimSuffix(entry.Name(), snapshotFileSuffix)
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
