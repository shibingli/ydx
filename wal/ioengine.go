package wal

import (
	"io"
	"os"
	"sync/atomic"

	"github.com/shibingli/ydx/errs"
)

// defaultEngine is the portable positional I/O engine. | defaultEngine 是可移植的位置写 I/O 引擎。
type defaultEngine struct {
	// Windows sequential-write state. The writer appends records in order, so
	// the file position only needs one Seek when the file or expected offset
	// changes; subsequent writes use the faster pointer-based Write. |
	// Windows 顺序写状态。写入方按顺序追加记录，只有文件或预期偏移变化时需要一次
	// Seek；后续写入使用更快的基于指针的 Write。
	lastFile       *os.File
	maxIovecs      int
	lastOff        int64
	stagingJoinMax atomic.Int64
	pwritev2       atomic.Bool
	fastPath       FastPathOptions
	macFullFsync   bool
	dirSyncDurable bool
	lastValid      bool
}

// defaultIOEngine builds the platform engine. | defaultIOEngine 构建平台引擎。
func defaultIOEngine(o *options) *defaultEngine {
	n := o.maxWritevParts
	if n <= 0 {
		n = 1
	}
	if n > 1024 {
		n = 1024
	}
	e := &defaultEngine{fastPath: o.fastPath, macFullFsync: o.macFullFsync, maxIovecs: n}
	e.stagingJoinMax.Store(defaultStagingJoinBytes)
	e.initPlatform()
	return e
}

// SetStagingJoinMax overrides the staging-join threshold. The size policy
// learns this value from observed write latency and copy bandwidth. |
// SetStagingJoinMax 覆盖暂存合并阈值；大小策略根据观测到的写延迟与复制带宽学习
// 该值。
func (e *defaultEngine) SetStagingJoinMax(n int) {
	if n < 0 {
		n = 0
	}
	e.stagingJoinMax.Store(int64(n))
}

// ReadAt reads exactly len(dst) bytes unless the file ends first. | ReadAt 精确读取 len(dst) 字节，除非文件提前结束。
func (e *defaultEngine) ReadAt(f *os.File, dst []byte, off int64) (int, error) {
	total := 0
	for total < len(dst) {
		n, err := readAtOnce(f, dst[total:], off+int64(total))
		total += n
		if err != nil {
			if err == io.EOF && total == len(dst) {
				return total, nil
			}
			return total, err
		}
		if n == 0 {
			return total, io.ErrNoProgress
		}
	}
	return total, nil
}

// Sync synchronizes data through the engine. | Sync 通过引擎同步数据。
func (e *defaultEngine) Sync(f *os.File) error {
	return syncDataFile(f, e.macFullFsync)
}

// Close releases engine resources. | Close 释放引擎资源。
func (e *defaultEngine) Close() error {
	e.lastFile = nil
	e.lastOff = 0
	e.lastValid = false
	return nil
}

// readAtFull is the shared exact-read helper used by recovery and readers. | readAtFull
// 是恢复与读取共用的精确读取辅助函数。
func readAtFull(f *os.File, dst []byte, off int64) error {
	return readFullAt(f, dst, off)
}

// readAtFull routes data-file reads through the configured IOEngine so an
// io_uring or other positional backend also serves random reads. Metadata files
// and directory scans keep using the portable helper. | readAtFull 让数据文件
// 读取经过配置的 IOEngine，使 io_uring 等位置读后端也能服务随机读；元数据文件
// 与目录扫描仍使用可移植辅助函数。
func (w *WAL) readAtFull(f *os.File, dst []byte, off int64) error {
	if w.engine == nil {
		return readFullAt(f, dst, off)
	}
	n, err := w.engine.ReadAt(f, dst, off)
	if err != nil {
		if err == io.EOF && n == len(dst) {
			return nil
		}
		return err
	}
	if n != len(dst) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

// writePartsSequential writes parts with WriteAt and no batching. | writePartsSequential
// 使用 WriteAt 顺序写入各分片而不合并。
func writePartsSequential(f *os.File, parts [][]byte, off int64) error {
	for _, p := range parts {
		if len(p) == 0 {
			continue
		}
		if err := writeFullAt(f, p, off); err != nil {
			return err
		}
		off += int64(len(p))
	}
	return nil
}

// totalParts returns the total byte count and iovec count. | totalParts 返回总字节数与分片数。
func totalParts(parts [][]byte) (int64, int) {
	var total int64
	var count int
	for _, p := range parts {
		if len(p) > 0 {
			total += int64(len(p))
			count++
		}
	}
	return total, count
}

// wrapStorage annotates an I/O failure with ErrStorage. | wrapStorage 用 ErrStorage 注解 I/O 失败。
func wrapStorage(op string, err error) error {
	return errs.WrapDetail(err, ErrStorage, "%s | %s 失败", op, op)
}

// compactParts drops zero-length parts, returning the input slice when possible. | compactParts
// 去掉零长度分片；可能时直接复用输入切片。
func compactParts(parts [][]byte) [][]byte {
	hasEmpty := false
	for _, p := range parts {
		if len(p) == 0 {
			hasEmpty = true
			break
		}
	}
	if !hasEmpty {
		return parts
	}
	out := make([][]byte, 0, len(parts))
	for _, p := range parts {
		if len(p) > 0 {
			out = append(out, p)
		}
	}
	return out
}

// lenParts returns the total byte count. | lenParts 返回总字节数。
func lenParts(parts [][]byte) int {
	total := 0
	for _, p := range parts {
		total += len(p)
	}
	return total
}

// advanceParts removes n written bytes from the front of parts. | advanceParts
// 从 parts 头部移除已写入的 n 字节。
func advanceParts(parts [][]byte, n int) [][]byte {
	for n > 0 && len(parts) > 0 {
		if n >= len(parts[0]) {
			n -= len(parts[0])
			parts = parts[1:]
			continue
		}
		parts[0] = parts[0][n:]
		n = 0
	}
	return parts
}
