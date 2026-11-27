//go:build windows

package wal

import (
	"errors"
	"os"

	"github.com/shibingli/ydx/errs"
	"golang.org/x/sys/windows"
)

// dirLock holds the process-wide directory lock. | dirLock 持有进程级目录锁。
type dirLock struct {
	f    *os.File
	noop bool
	ol   windows.Overlapped
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
		f, err = os.Open(path)
		if os.IsNotExist(err) {
			// The lock file is the rendezvous between readers and writers. Without
			// it a reader would run unlocked and a writer creating it later would
			// not conflict with that reader. Creating the empty lock file is the
			// only write a read-only open performs; directories where that is not
			// allowed must pass WithNoLock explicitly. | 锁文件是读写双方的汇合点。
			// 缺少它时读者会在无锁状态运行，后来创建锁文件的写者也不会与其冲突。创建空
			// 锁文件是只读打开唯一执行的写入；不允许创建的目录必须显式传入 WithNoLock。
			f, err = os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
		}
	} else {
		f, err = os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	}
	if err != nil {
		return nil, errs.WrapDetail(err, ErrStorage, "open lock file %s | 打开锁文件 %s 失败", path, path)
	}
	l := &dirLock{f: f}
	flags := uint32(windows.LOCKFILE_FAIL_IMMEDIATELY)
	if !readOnly {
		flags |= windows.LOCKFILE_EXCLUSIVE_LOCK
	}
	if err := windows.LockFileEx(windows.Handle(f.Fd()), flags, 0, 1, 0, &l.ol); err != nil {
		_ = f.Close()
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			return nil, errs.Detail(ErrLocked, "another process holds %s | 其它进程持有 %s", path, path)
		}
		return nil, errs.WrapDetail(err, ErrStorage, "LockFileEx %s | 锁定 %s 失败", path, path)
	}
	return l, nil
}

// Close releases the lock. | Close 释放锁。
func (l *dirLock) Close() error {
	if l == nil || l.noop || l.f == nil {
		return nil
	}
	_ = windows.UnlockFileEx(windows.Handle(l.f.Fd()), 0, 1, 0, &l.ol)
	return l.f.Close()
}
