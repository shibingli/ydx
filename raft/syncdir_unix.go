//go:build linux || darwin || dragonfly || freebsd || netbsd || openbsd || illumos || solaris

package raft

import (
	"errors"
	"os"
	"syscall"
)

// syncDir makes directory entry changes durable. Filesystems that do not
// support fsync on a directory report EINVAL/ENOTSUP; that is not a storage
// failure. | syncDir 使目录项变更持久化。不支持对目录 fsync 的文件系统会返回
// EINVAL/ENOTSUP，这不属于存储故障。
func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	err = f.Sync()
	cerr := f.Close()
	if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) {
		err = nil
	}
	if err != nil {
		return err
	}
	return cerr
}
