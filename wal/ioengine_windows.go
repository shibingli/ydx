//go:build windows

package wal

import (
	"os"

	"github.com/shibingli/ydx/buffpool"
)

// stagingLimit is the largest batch merged into one Windows staging buffer. | stagingLimit
// 是 Windows 合并到单个暂存缓冲的最大批次字节数。
const stagingLimit = 4 << 20

// initPlatform records Windows capabilities. | initPlatform 记录 Windows 能力。
func (e *defaultEngine) initPlatform() {
	e.dirSyncDurable = false
}

// WriteAt merges small batches into one WriteAt and synchronizes explicitly. | WriteAt
// 把小批次合并为一次 WriteAt 并显式同步。
func (e *defaultEngine) WriteAt(f *os.File, parts [][]byte, off int64, syncData bool) error {
	total, _ := totalParts(parts)
	if total > 0 && total <= stagingLimit {
		buf := buffpool.Get(int(total))
		buf = buf[:total]
		pos := 0
		for _, p := range parts {
			pos += copy(buf[pos:], p)
		}
		err := writeFullAt(f, buf, off)
		buffpool.Put(buf[:0])
		if err != nil {
			return wrapStorage("WriteAt", err)
		}
	} else if err := writePartsSequential(f, parts, off); err != nil {
		return wrapStorage("WriteAt", err)
	}
	if syncData {
		if err := syncDataFile(f, true); err != nil {
			return wrapStorage("FlushFileBuffers", err)
		}
	}
	return nil
}

// syncDataFile flushes file buffers. | syncDataFile 刷新文件缓冲。
func syncDataFile(f *os.File, _ bool) error { return f.Sync() }

// syncMetaFile flushes file buffers. | syncMetaFile 刷新文件缓冲。
func syncMetaFile(f *os.File) error { return f.Sync() }

// preallocateFile is not supported on Windows. | preallocateFile 在 Windows 上不支持。
func preallocateFile(*os.File, int64, int64) error { return nil }

// fadviseDontNeed is not supported on Windows. | fadviseDontNeed 在 Windows 上不支持。
func fadviseDontNeed(*os.File) error { return nil }

// cloneFile always reports unsupported; DirBackup falls back to copy. | cloneFile
// 始终返回不支持；DirBackup 回退到复制。
func cloneFile(*os.File, *os.File) error { return ErrUnsupported }
