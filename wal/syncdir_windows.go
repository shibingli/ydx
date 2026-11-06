//go:build windows

package wal

// syncDir is a no-op on Windows because the platform does not expose a
// directory-entry flush. | syncDir 在 Windows 上是空操作，因为平台不提供目录项刷新。
func syncDir(string) error { return nil }
