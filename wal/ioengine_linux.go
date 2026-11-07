//go:build linux

package wal

import (
	"errors"
	"io"
	"os"

	"github.com/shibingli/ydx/errs"
	"golang.org/x/sys/unix"
)

const maxIovecs = 1024

// initPlatform enables the Linux fast path. | initPlatform 启用 Linux 快路径。
func (e *defaultEngine) initPlatform() {
	e.dirSyncDurable = true
	enabled := e.fastPath.Mode == FastPathAuto ||
		(e.fastPath.Mode == FastPathCustom && e.fastPath.Pwritev2DSync)
	e.pwritev2.Store(enabled)
}

// WriteAt writes parts at off with pwritev2(RWF_DSYNC) or pwritev + fdatasync. | WriteAt
// 使用 pwritev2(RWF_DSYNC) 或 pwritev + fdatasync 在 off 处写入。
func (e *defaultEngine) WriteAt(f *os.File, parts [][]byte, off int64, syncData bool) error {
	if err := e.writeAt(f, parts, off, syncData); err != nil {
		return wrapStorage("pwritev", err)
	}
	return nil
}

// writeAt is the raw Linux write path. | writeAt 是 Linux 原始写入路径。
func (e *defaultEngine) writeAt(f *os.File, parts [][]byte, off int64, syncData bool) error {
	bufs := compactParts(parts)
	if len(bufs) == 0 {
		if syncData {
			return syncDataFile(f, e.macFullFsync)
		}
		return nil
	}
	fd := int(f.Fd())
	limit := e.maxIovecs
	if e.pwritev2.Load() && len(bufs) <= limit {
		n, err := pwritev2All(fd, bufs, off, syncData)
		if err == nil {
			if n == lenParts(bufs) {
				return nil
			}
			bufs = advanceParts(bufs, n)
			off += int64(n)
			if len(bufs) == 0 {
				return nil
			}
			if err := pwritevAllChunks(fd, bufs, off, limit); err != nil {
				return err
			}
			if syncData {
				return syncDataFile(f, e.macFullFsync)
			}
			return nil
		}
		if !errors.Is(err, unix.EOPNOTSUPP) && !errors.Is(err, unix.EINVAL) && !errors.Is(err, unix.ENOSYS) {
			return err
		}
		e.pwritev2.Store(false)
	}
	if err := pwritevAllChunks(fd, bufs, off, limit); err != nil {
		return err
	}
	if syncData {
		return syncDataFile(f, e.macFullFsync)
	}
	return nil
}

// syncDataFile synchronizes file data. | syncDataFile 同步文件数据。
func syncDataFile(f *os.File, fullFsync bool) error {
	return unix.Fdatasync(int(f.Fd()))
}

// syncMetaFile synchronizes file data and metadata. | syncMetaFile 同步文件数据与元数据。
func syncMetaFile(f *os.File) error { return f.Sync() }

// preallocateFile reserves space without changing the logical size. | preallocateFile
// 预分配空间但不改变逻辑大小。
func preallocateFile(f *os.File, off, size int64) error {
	return unix.Fallocate(int(f.Fd()), unix.FALLOC_FL_KEEP_SIZE, off, size)
}

// fadviseDontNeed drops clean page cache for a sealed segment. | fadviseDontNeed
// 回收封段的干净页缓存。
func fadviseDontNeed(f *os.File) error {
	return unix.Fadvise(int(f.Fd()), 0, 0, unix.FADV_DONTNEED)
}

// pwritev2All retries EINTR around Pwritev2. RWF_DSYNC is used only when the
// caller asked for durable data; SyncInterval/SyncNever must not force a disk
// flush on every write. | pwritev2All 在 EINTR 时重试 Pwritev2；只有调用方要求
// 持久化时才使用 RWF_DSYNC，SyncInterval/SyncNever 不得强制每次写盘。
func pwritev2All(fd int, bufs [][]byte, off int64, syncData bool) (int, error) {
	var flags int
	if syncData {
		flags = unix.RWF_DSYNC
	}
	for {
		n, err := unix.Pwritev2(fd, bufs, off, flags)
		if err == unix.EINTR {
			continue
		}
		return n, err
	}
}

// pwritevAllChunks writes bufs in groups of at most limit iovecs. |
// pwritevAllChunks 以每组最多 limit 个分片写入 bufs。
func pwritevAllChunks(fd int, bufs [][]byte, off int64, limit int) error {
	for len(bufs) > 0 {
		chunk := bufs
		if len(chunk) > limit {
			chunk = chunk[:limit]
		}
		n, err := pwritevAll(fd, chunk, off)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		off += int64(n)
		bufs = advanceParts(bufs, n)
	}
	return nil
}

// pwritevAll retries EINTR around Pwritev. | pwritevAll 在 EINTR 时重试 Pwritev。
func pwritevAll(fd int, bufs [][]byte, off int64) (int, error) {
	for {
		n, err := unix.Pwritev(fd, bufs, off)
		if err == unix.EINTR {
			continue
		}
		return n, err
	}
}

// cloneFile tries a Linux reflink clone. | cloneFile 尝试 Linux reflink 克隆。
func cloneFile(dst, src *os.File) error {
	if err := unix.IoctlFileClone(int(dst.Fd()), int(src.Fd())); err != nil {
		return errs.Wrap(err, ErrUnsupported)
	}
	return nil
}
