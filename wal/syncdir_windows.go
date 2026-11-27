//go:build windows

package wal

import "golang.org/x/sys/windows"

// syncDir makes a best effort to flush a directory entry on Windows. NTFS does
// not expose the POSIX fsync-on-directory guarantee, but FlushFileBuffers on a
// directory handle opened with FILE_FLAG_BACKUP_SEMANTICS can flush the volume
// metadata on some filesystems. Unsupported or access-denied results are
// intentionally ignored: EngineInfo.DirSyncDurable stays false on Windows so
// callers never mistake SyncAlways for directory-entry durability. |
// syncDir 在 Windows 上尽力刷新目录项。NTFS 不提供 POSIX 的目录 fsync 保证，但对以
// FILE_FLAG_BACKUP_SEMANTICS 打开的目录句柄调用 FlushFileBuffers 可能刷新部分文件
// 系统的卷元数据。不支持或拒绝访问的结果被有意忽略：Windows 上
// EngineInfo.DirSyncDurable 保持 false，调用方不会把 SyncAlways 误认为目录项持久化。
func syncDir(path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil
	}
	h, err := windows.CreateFile(p,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(h)
	if err := windows.FlushFileBuffers(h); err != nil {
		if err == windows.ERROR_INVALID_FUNCTION || err == windows.ERROR_NOT_SUPPORTED ||
			err == windows.ERROR_ACCESS_DENIED {
			return nil
		}
		return nil
	}
	return nil
}
