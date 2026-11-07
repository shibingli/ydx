//go:build windows

package wal

import (
	"io"
	"os"

	"github.com/shibingli/ydx/buffpool"
	"golang.org/x/sys/windows"
)

// stagingJoinMax is the learned largest batch merged into one Windows staging
// buffer. Above it, parts are written sequentially: avoiding a full-payload copy
// costs one or two extra WriteAt calls and wins for large records. The size
// policy sets it from observed write latency and copy bandwidth. |
// stagingJoinMax 是学习得到的、合并到单个 Windows 暂存缓冲的最大批次。超过该值时
// 按分片顺序写出：省去整条负载复制只多一两次 WriteAt，对大记录更划算。大小策略
// 根据观测到的写延迟与复制带宽设置它。

// initPlatform records Windows capabilities. | initPlatform 记录 Windows 能力。
func (e *defaultEngine) initPlatform() {
	e.dirSyncDurable = false
}

// WriteAt merges small batches into one write and synchronizes explicitly. |
// WriteAt 把小批次合并为一次写入并显式同步。
func (e *defaultEngine) WriteAt(f *os.File, parts [][]byte, off int64, syncData bool) error {
	total, _ := totalParts(parts)
	if total > 0 {
		if !e.lastValid || e.lastFile != f || e.lastOff != off {
			if _, err := f.Seek(off, io.SeekStart); err != nil {
				e.lastValid = false
				return writePositional(f, parts, off, total, syncData)
			}
			e.lastFile, e.lastOff, e.lastValid = f, off, true
		}
	}
	if limit := e.stagingJoinMax.Load(); limit > 0 && len(parts) > 1 && total > 0 && total <= limit {
		buf := buffpool.Get(int(total))
		buf = buf[:total]
		pos := 0
		for _, p := range parts {
			pos += copy(buf[pos:], p)
		}
		err := writeFull(f, buf)
		buffpool.Put(buf[:0])
		if err != nil {
			e.lastValid = false
			return wrapStorage("WriteAt", err)
		}
	} else if err := writePartsAtEnd(f, parts); err != nil {
		e.lastValid = false
		return wrapStorage("WriteAt", err)
	}
	e.lastOff += total
	if syncData {
		if err := syncDataFile(f, true); err != nil {
			return wrapStorage("FlushFileBuffers", err)
		}
	}
	return nil
}

// writePositional is the fallback for non-seekable handles. | writePositional
// 是不可定位句柄的回退路径。
func writePositional(f *os.File, parts [][]byte, off, total int64, syncData bool) error {
	if total > 0 && total <= defaultStagingJoinBytes {
		buf := buffpool.Get(int(total))
		buf = buf[:total]
		pos := 0
		for _, p := range parts {
			pos += copy(buf[pos:], p)
		}
		err := writeFullAtRaw(f, buf, off)
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

// writePartsAtEnd writes parts in order through the current file position. |
// writePartsAtEnd 通过当前文件位置按顺序写出分片。
func writePartsAtEnd(f *os.File, parts [][]byte) error {
	for _, p := range parts {
		if len(p) == 0 {
			continue
		}
		if err := writeFull(f, p); err != nil {
			return err
		}
	}
	return nil
}

// writeFull writes p through f, retrying short writes. | writeFull 通过 f 写入 p，
// 并重试短写。
func writeFull(f *os.File, p []byte) error {
	for len(p) > 0 {
		n, err := f.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

// writeFullAtRaw writes p at off with WriteFile and an explicit OVERLAPPED
// offset. Go's os.File.WriteAt saves and restores the file pointer with two
// extra Seek calls on blocking handles; the WAL never uses that handle's file
// pointer, so those syscalls are pure overhead on the append hot path. |
// writeFullAtRaw 用 WriteFile 与显式 OVERLAPPED 偏移写出 p。Go 的
// os.File.WriteAt 在阻塞句柄上会额外执行两次 Seek 保存/恢复文件指针；WAL 从不使用
// 该句柄的文件指针，因此这些系统调用在追加热路径上是纯开销。
func writeFullAtRaw(f *os.File, p []byte, off int64) error {
	handle := windows.Handle(f.Fd())
	for len(p) > 0 {
		var n uint32
		ol := windows.Overlapped{Offset: uint32(off), OffsetHigh: uint32(uint64(off) >> 32)}
		if err := windows.WriteFile(handle, p, &n, &ol); err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
		off += int64(n)
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
// 始终报告不支持；DirBackup 回退到复制。
func cloneFile(*os.File, *os.File) error { return ErrUnsupported }
