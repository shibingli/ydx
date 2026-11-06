//go:build !linux && !darwin && !dragonfly && !freebsd && !netbsd && !openbsd && !illumos && !windows

package raft

import "os"

// lockDirectory is a no-op on platforms without standard-library advisory file
// locking. | lockDirectory 在不提供标准库建议文件锁的平台上为空操作。
func lockDirectory(*os.File) error { return nil }
