//go:build !windows

package wal

import (
	"errors"
	"os"

	"github.com/shibingli/ydx/errs"
	"golang.org/x/sys/unix"
)

// dirLock holds the process-wide directory lock. | dirLock 持有进程级目录锁。
type dirLock struct {
	f    *os.File
	noop bool
}

// acquireDirLock takes an exclusive writer lock or a shared read-only lock. | acquireDirLock
// 获取写者排他锁或只读者共享锁。
func acquireDirLock(path string, readOnly, noLock bool) (*dirLock, error) {
	if noLock {
		return &dirLock{noop: true}, nil
	}
	var f *os.File
	var err error
	if readOnly {
		// A read-only open must not create or write any file. If the lock file
		// does not exist, no writer has ever created the directory, so there is
		// nothing to coordinate with. | 只读打开不得创建或写入任何文件；锁文件
		// 不存在说明从未有写者创建该目录，无需协调。
		f, err = os.Open(path)
		if os.IsNotExist(err) {
			return &dirLock{noop: true}, nil
		}
	} else {
		f, err = os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	}
	if err != nil {
		return nil, errs.WrapDetail(err, ErrStorage, "open lock file %s | 打开锁文件 %s 失败", path, path)
	}
	how := unix.LOCK_EX
	if readOnly {
		how = unix.LOCK_SH
	}
	if err := unix.Flock(int(f.Fd()), how|unix.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, errs.Detail(ErrLocked, "another process holds %s | 其它进程持有 %s", path, path)
		}
		return nil, errs.WrapDetail(err, ErrStorage, "flock %s | 锁定 %s 失败", path, path)
	}
	return &dirLock{f: f}, nil
}

// Close releases the lock. | Close 释放锁。
func (l *dirLock) Close() error {
	if l == nil || l.noop || l.f == nil {
		return nil
	}
	_ = unix.Flock(int(l.f.Fd()), unix.LOCK_UN)
	return l.f.Close()
}
