//go:build !windows

package wal

import (
	"errors"
	"os"
	"syscall"
)

// syncDir flushes directory entries on Unix. | syncDir 在 Unix 上刷新目录项。
//
// Some filesystems (notably network mounts on macOS) reject fsync on a
// directory with EINVAL, ENOTSUP or ENOTTY; those are treated as a best-effort
// success so the WAL can still open. | 某些文件系统（尤其是 macOS 的网络挂载）
// 会以 EINVAL、ENOTSUP 或 ENOTTY 拒绝目录 fsync；这些错误按尽力而为成功处理，
// 以便 WAL 仍可打开。
func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	err = f.Sync()
	if err == nil {
		return nil
	}
	if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.ENOTTY) {
		return nil
	}
	return err
}
