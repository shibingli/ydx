//go:build !linux

package raft

import "os"

// syncFile flushes file data and metadata using the platform's file Sync.
// | syncFile 使用平台的 File.Sync 刷新文件数据与元数据。
func syncFile(f *os.File) error {
	return f.Sync()
}
