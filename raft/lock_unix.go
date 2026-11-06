//go:build linux || darwin || dragonfly || freebsd || netbsd || openbsd || illumos

package raft

import (
	"os"
	"syscall"
)

// lockDirectory takes a non-blocking exclusive advisory lock on f. Closing the
// file releases it. | lockDirectory 对 f 加非阻塞排他建议锁；关闭文件即释放。
func lockDirectory(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}
