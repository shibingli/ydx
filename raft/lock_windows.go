//go:build windows

package raft

import (
	"os"
	"syscall"
	"unsafe"
)

const (
	lockfileFailImmediately = 0x00000001
	lockfileExclusiveLock   = 0x00000002
)

var procLockFileEx = syscall.NewLazyDLL("kernel32.dll").NewProc("LockFileEx")

// lockDirectory takes a non-blocking exclusive lock on one byte of f. Closing
// the handle releases the lock. | lockDirectory 对 f 的一个字节加非阻塞排他锁；
// 关闭句柄即释放。
func lockDirectory(f *os.File) error {
	var overlapped syscall.Overlapped
	r1, _, err := procLockFileEx.Call(
		f.Fd(),
		lockfileExclusiveLock|lockfileFailImmediately,
		0, 1, 0,
		uintptr(unsafe.Pointer(&overlapped)),
	)
	if r1 == 0 {
		if err != nil && err != syscall.Errno(0) {
			return err
		}
		return syscall.EINVAL
	}
	return nil
}
