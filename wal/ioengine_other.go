//go:build !linux && !darwin && !windows

package wal

import "os"

// initPlatform leaves the portable defaults. | initPlatform 使用可移植默认值。
func (e *defaultEngine) initPlatform() { e.dirSyncDurable = true }

// WriteAt writes parts sequentially and synchronizes explicitly. | WriteAt 顺序写入 parts 并显式同步。
func (e *defaultEngine) WriteAt(f *os.File, parts [][]byte, off int64, syncData bool) error {
	if err := writePartsSequential(f, parts, off); err != nil {
		return wrapStorage("WriteAt", err)
	}
	if syncData {
		if err := syncDataFile(f, true); err != nil {
			return wrapStorage("Sync", err)
		}
	}
	return nil
}

// syncDataFile flushes file data. | syncDataFile 刷新文件数据。
func syncDataFile(f *os.File, _ bool) error { return f.Sync() }

// syncMetaFile flushes file data and metadata. | syncMetaFile 刷新文件数据与元数据。
func syncMetaFile(f *os.File) error { return f.Sync() }

// preallocateFile is not supported. | preallocateFile 不支持。
func preallocateFile(*os.File, int64, int64) error { return nil }

// fadviseDontNeed is not supported. | fadviseDontNeed 不支持。
func fadviseDontNeed(*os.File) error { return nil }

// cloneFile is not supported. | cloneFile 不支持。
func cloneFile(*os.File, *os.File) error { return ErrUnsupported }
