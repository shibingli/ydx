//go:build !linux && !darwin && !dragonfly && !freebsd && !netbsd && !openbsd && !illumos && !solaris

package raft

// syncDir is a no-op where the platform does not support syncing a directory
// handle. File contents are still flushed by the caller. | syncDir 在不支持同步
// 目录句柄的平台上为空操作；文件内容仍由调用方刷新。
func syncDir(string) error { return nil }
