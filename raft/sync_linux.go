//go:build linux

package raft

import (
	"errors"
	"os"
	"syscall"
)

// syncFile flushes file data and the metadata required to read it. fdatasync
// avoids the metadata journal traffic of fsync and is measurably cheaper for
// append-only WAL files. Filesystems without fdatasync fall back to fsync.
// | syncFile 刷新文件数据及读取所需元数据。对只追加的 WAL 文件，fdatasync 避免
// fsync 的元数据日志写入，成本明显更低；不支持 fdatasync 的文件系统回退到 fsync。
func syncFile(f *os.File) error {
	err := syscall.Fdatasync(int(f.Fd()))
	if errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.EINVAL) {
		return f.Sync()
	}
	return err
}
