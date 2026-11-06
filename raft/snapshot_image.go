package raft

import (
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"hash/crc32"
	"io"
	"os"

	"github.com/shibingli/ydx/errs"
)

// snapshotImage is a streaming image target. The apply goroutine writes the
// state machine's bytes, Seal closes the data section, and Finalize performs the
// expensive header write and fsync on a separate goroutine. | snapshotImage 是
// 流式镜像目标。apply 协程写入状态机字节，Seal 关闭数据段，Finalize 在独立协程
// 完成开销较大的头部写入与 fsync。
type snapshotImage interface {
	io.Writer
	Seal() error
	Finalize() error
	Abort()
}

// streamingSnapshotStorage opens a streaming snapshot image. | streamingSnapshotStorage
// 打开一个流式快照镜像。
type streamingSnapshotStorage interface {
	NewSnapshotImage(snap *Snapshot, conf ConfState) (snapshotImage, error)
}

// snapshotHeaderSize returns the fixed header plus configuration size for the
// selected checksum layout. | snapshotHeaderSize 返回所选校验布局的固定头部加
// 配置字节数。
func snapshotHeaderSize(confLen int, useSHA bool) int {
	size := 8 + 1 + 8 + 8 + 4 + confLen + 8 + 4 + 32
	if useSHA {
		return size
	}
	return size + 1
}

// encodeSnapshotFileHeader serializes the snapshot header. A CRC-only image uses
// version 2 with a flags byte and keeps the 32-byte hash field zeroed. |
// encodeSnapshotFileHeader 序列化快照头部。仅 CRC 镜像使用版本 2、带标志字节，
// 并将 32 字节哈希字段置零。
func encodeSnapshotFileHeader(dst []byte, conf []byte, index, term, dataLen uint64, crc uint32, sum []byte, useSHA bool) []byte {
	version := snapshotVersion
	if !useSHA {
		version = snapshotVersionCRCOnly
	}
	dst = append(dst, snapshotMagic...)
	dst = append(dst, version)
	dst = binary.LittleEndian.AppendUint64(dst, index)
	dst = binary.LittleEndian.AppendUint64(dst, term)
	dst = binary.LittleEndian.AppendUint32(dst, uint32(len(conf)))
	dst = append(dst, conf...)
	dst = binary.LittleEndian.AppendUint64(dst, dataLen)
	dst = binary.LittleEndian.AppendUint32(dst, crc)
	if !useSHA {
		dst = append(dst, 0)
	}
	if useSHA {
		dst = append(dst, sum...)
	} else {
		dst = append(dst, make([]byte, 32)...)
	}
	return dst
}

// fileSnapshotImage streams one local image into a temporary file. The file is
// not renamed into place until Finalize succeeds, so recovery never trusts a
// partial image. | fileSnapshotImage 将一个本地镜像流式写入临时文件，直到
// Finalize 成功才重命名就位，因此恢复不会信任不完整镜像。
type fileSnapshotImage struct {
	storage *FileStorage
	snap    *Snapshot
	tmp     *os.File
	crc     hash.Hash32
	sha     hash.Hash
	tmpName string
	size    int64
	header  int
	sealed  bool
	done    bool
	useSHA  bool
}

// NewSnapshotImage creates a temporary image writer for one snapshot. | NewSnapshotImage
// 为一个快照创建临时镜像写入器。
func (s *FileStorage) NewSnapshotImage(snap *Snapshot, conf ConfState) (snapshotImage, error) {
	if snap == nil {
		return nil, errs.Detail(ErrInvalidConfig, "nil snapshot")
	}
	confBytes := appendConfState(nil, conf)
	if len(confBytes) > maxConfBytes {
		return nil, errs.Detail(ErrTooLarge, "snapshot conf state %d bytes", len(confBytes))
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, ErrStopped
	}
	if !s.loaded {
		if _, err := s.loadLocked(); err != nil {
			s.mu.Unlock()
			return nil, err
		}
	}
	dir := s.snapDir
	useSHA := s.snapshotChecksum != SnapshotChecksumCRC32C
	s.mu.Unlock()
	tmp, err := os.CreateTemp(dir, ".snap-*")
	if err != nil {
		return nil, errs.Wrap(err, ErrStorage)
	}
	header := snapshotHeaderSize(len(confBytes), useSHA)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return nil, errs.Wrap(err, ErrStorage)
	}
	// Reserve the header without allocating or writing zeros. The current file
	// offset must move past the sparse prefix before payload writes. | 以稀疏方式
	// 预留头部，无需分配或写入零；写负载前必须把当前偏移移动到前缀之后。
	if err := tmp.Truncate(int64(header)); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return nil, errs.Wrap(err, ErrStorage)
	}
	if _, err := tmp.Seek(int64(header), io.SeekStart); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return nil, errs.Wrap(err, ErrStorage)
	}
	img := &fileSnapshotImage{
		storage: s,
		snap:    snap,
		tmp:     tmp,
		tmpName: tmp.Name(),
		crc:     crc32.New(castagnoli),
		header:  header,
		useSHA:  useSHA,
	}
	if useSHA {
		img.sha = sha256.New()
	}
	return img, nil
}

// Write implements io.Writer. | Write 实现 io.Writer。
func (w *fileSnapshotImage) Write(p []byte) (int, error) {
	if w.tmp == nil || w.sealed || w.done {
		return 0, errs.Detail(ErrStorage, "snapshot image is closed | 快照镜像已关闭")
	}
	n, err := w.tmp.Write(p)
	if n > 0 {
		_, _ = w.crc.Write(p[:n])
		if w.sha != nil {
			_, _ = w.sha.Write(p[:n])
		}
		w.size += int64(n)
	}
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	return n, err
}

// Seal closes the payload section. | Seal 关闭负载段。
func (w *fileSnapshotImage) Seal() error {
	if w.sealed {
		return nil
	}
	if w.done {
		return errs.Detail(ErrStorage, "snapshot image already finalized | 快照镜像已定稿")
	}
	w.sealed = true
	if w.tmp == nil {
		return nil
	}
	err := w.tmp.Close()
	w.tmp = nil
	if err != nil {
		return errs.Wrap(err, ErrStorage)
	}
	return nil
}

// Finalize writes the header, fsyncs the image, and atomically renames it. |
// Finalize 写入头部、fsync 镜像并原子重命名。
func (w *fileSnapshotImage) Finalize() error {
	if w.done {
		return nil
	}
	if err := w.Seal(); err != nil {
		w.Abort()
		return err
	}
	f, err := os.OpenFile(w.tmpName, os.O_RDWR, 0o600)
	if err != nil {
		w.Abort()
		return errs.Wrap(err, ErrStorage)
	}
	conf := appendConfState(nil, w.snap.ConfState)
	var sum []byte
	if w.sha != nil {
		sum = w.sha.Sum(nil)
	}
	header := encodeSnapshotFileHeader(nil, conf, w.snap.Index, w.snap.Term,
		uint64(w.size), w.crc.Sum32(), sum, w.useSHA)
	if len(header) != w.header {
		_ = f.Close()
		w.Abort()
		return errs.Detail(ErrStorage, "snapshot header size %d, want %d", len(header), w.header)
	}
	if _, err := f.WriteAt(header, 0); err != nil {
		_ = f.Close()
		w.Abort()
		return errs.Wrap(err, ErrStorage)
	}
	if !w.storage.noSync {
		if err := syncFile(f); err != nil {
			_ = f.Close()
			w.Abort()
			return errs.Wrap(err, ErrStorage)
		}
	}
	if err := f.Close(); err != nil {
		w.Abort()
		return errs.Wrap(err, ErrStorage)
	}
	final := w.storage.snapshotPath(w.snap.Index, w.snap.Term)
	if err := os.Rename(w.tmpName, final); err != nil {
		w.Abort()
		return errs.Wrap(err, ErrStorage)
	}
	if !w.storage.noSync {
		if err := syncDir(w.storage.snapDir); err != nil {
			_ = os.Remove(final)
			return errs.Wrap(err, ErrStorage)
		}
	}
	w.snap.file = final
	w.snap.dataSize = w.size
	w.snap.dataOffset = int64(w.header)
	w.snap.Data = nil
	w.done = true
	w.tmpName = ""
	return nil
}

// Abort removes any temporary or uncommitted final image. | Abort 删除临时或尚未提交
// 的最终镜像。
func (w *fileSnapshotImage) Abort() {
	if w.tmp != nil {
		_ = w.tmp.Close()
		w.tmp = nil
	}
	if w.tmpName != "" {
		_ = os.Remove(w.tmpName)
		w.tmpName = ""
	}
	if w.snap != nil && w.snap.file != "" {
		_ = os.Remove(w.snap.file)
		w.snap.file = ""
	}
	w.done = true
}
