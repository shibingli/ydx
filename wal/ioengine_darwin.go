//go:build darwin

package wal

import (
	"io"
	"os"

	"golang.org/x/sys/unix"
)

const maxIovecs = 1024

// initPlatform enables the Darwin fast path. | initPlatform 启用 Darwin 快路径。
func (e *defaultEngine) initPlatform() {
	e.dirSyncDurable = true
}

// WriteAt writes parts with pwritev and the platform sync primitive. | WriteAt
// 使用 pwritev 与平台同步原语写入 parts。
func (e *defaultEngine) WriteAt(f *os.File, parts [][]byte, off int64, syncData bool) error {
	if err := e.writeAt(f, parts, off, syncData); err != nil {
		return wrapStorage("pwritev", err)
	}
	return nil
}

// writeAt is the raw Darwin write path. | writeAt 是 Darwin 原始写入路径。
func (e *defaultEngine) writeAt(f *os.File, parts [][]byte, off int64, syncData bool) error {
	bufs := compactParts(parts)
	if len(bufs) == 0 {
		if syncData {
			return syncDataFile(f, e.macFullFsync)
		}
		return nil
	}
	fd := int(f.Fd())
	for len(bufs) > 0 {
		chunk := bufs
		if len(chunk) > maxIovecs {
			chunk = chunk[:maxIovecs]
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
	if syncData {
		return syncDataFile(f, e.macFullFsync)
	}
	return nil
}

// syncDataFile uses F_FULLFSYNC unless explicitly disabled. | syncDataFile
// 默认使用 F_FULLFSYNC，除非显式关闭。
func syncDataFile(f *os.File, fullFsync bool) error {
	if fullFsync {
		return f.Sync()
	}
	return unix.Fsync(int(f.Fd()))
}

// syncMetaFile synchronizes file data and metadata. | syncMetaFile 同步文件数据与元数据。
func syncMetaFile(f *os.File) error { return f.Sync() }

// preallocateFile is not supported on Darwin. | preallocateFile 在 Darwin 上不支持。
func preallocateFile(*os.File, int64, int64) error { return nil }

// fadviseDontNeed is not supported on Darwin. | fadviseDontNeed 在 Darwin 上不支持。
func fadviseDontNeed(*os.File) error { return nil }

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

// cloneFile tries an APFS clonefile. | cloneFile 尝试 APFS clonefile。
func cloneFile(dst, src *os.File) error {
	srcName := src.Name()
	dstName := dst.Name()
	if err := unix.Clonefile(srcName, dstName, 0); err != nil {
		return err
	}
	return nil
}
