//go:build linux && (amd64 || arm64)

package uring

import (
	"encoding/binary"
	"io"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/shibingli/ydx/errs"
	"golang.org/x/sys/unix"
)

// io_uring constants used by this minimal engine. | 本最小引擎使用的 io_uring 常量。
const (
	ioringOffSQRing      = 0
	ioringOffCQRing      = 0x8000000
	ioringOffSQEs        = 0x10000000
	ioringEnterGetEvents = 1
	ioringFsyncDataSync  = 1
	ioringOpWritev       = 2
	ioringOpFsync        = 3
	ioringOpRead         = 22
	ioringFeatSingleMmap = 1 << 0
	iovecMax             = 1024
	sqeSize              = 64
	cqeSize              = 16
	ioURingParamsSize    = 120
	maxRingEntries       = 1 << 16
)

// sqe mirrors struct io_uring_sqe (64 bytes). | sqe 对应 struct io_uring_sqe。
type sqe struct {
	opcode      uint8
	flags       uint8
	ioprio      uint16
	fd          int32
	off         uint64
	addr        uint64
	length      uint32
	rwFlags     uint32
	userData    uint64
	bufIndex    uint16
	personality uint16
	spliceFD    int32
	pad         [2]uint64
}

// cqe mirrors struct io_uring_cqe (16 bytes). | cqe 对应 struct io_uring_cqe。
type cqe struct {
	userData uint64
	res      int32
	flags    uint32
}

// ring is one single-issuer io_uring instance. | ring 是一个单提交者 io_uring 实例。
type ring struct {
	fd         int
	sqRing     []byte
	cqRing     []byte
	sqesMem    []byte
	singleMmap bool
	depth      uint32

	sqHead  *uint32
	sqTail  *uint32
	sqMask  uint32
	sqArray []uint32
	sqes    []sqe
	cqHead  *uint32
	cqTail  *uint32
	cqMask  uint32
	cqes    []cqe

	mu     sync.Mutex
	failed error
	closed bool
}

// newRing sets up the ring and maps its SQ/CQ/SQE regions. | newRing 初始化
// ring 并映射 SQ/CQ/SQE 区域。
func newRing(depth int, setupFlags uint32) (*ring, error) {
	if unsafe.Sizeof(sqe{}) != sqeSize || unsafe.Sizeof(cqe{}) != cqeSize {
		return nil, errs.Detail(ErrSetup, "unexpected io_uring struct sizes | io_uring 结构体大小异常")
	}
	params := make([]byte, ioURingParamsSize)
	// io_uring_params.flags lives at offset 8; io_uring_setup itself takes only
	// (entries, params). | io_uring_params.flags 位于偏移 8；io_uring_setup 只
	// 接受 (entries, params) 两个参数。
	binary.LittleEndian.PutUint32(params[8:], setupFlags)
	fd, _, errno := unix.Syscall(unix.SYS_IO_URING_SETUP,
		uintptr(depth), uintptr(unsafe.Pointer(&params[0])), 0)
	if errno != 0 {
		switch errno {
		case unix.ENOSYS, unix.EPERM, unix.EACCES, unix.EINVAL:
			return nil, errs.WrapDetail(errno, ErrUnsupported, "io_uring_setup unavailable | io_uring_setup 不可用")
		default:
			return nil, errs.WrapDetail(errno, ErrSetup, "io_uring_setup | io_uring_setup 失败")
		}
	}
	unix.CloseOnExec(int(fd))
	r := &ring{fd: int(fd)}
	cleanup := func() {
		if r.sqesMem != nil {
			_ = unix.Munmap(r.sqesMem)
		}
		if r.singleMmap {
			if r.sqRing != nil {
				_ = unix.Munmap(r.sqRing)
			}
		} else {
			if r.sqRing != nil {
				_ = unix.Munmap(r.sqRing)
			}
			if r.cqRing != nil {
				_ = unix.Munmap(r.cqRing)
			}
		}
		_ = unix.Close(int(fd))
	}
	sqEntries := binary.LittleEndian.Uint32(params[0:])
	cqEntries := binary.LittleEndian.Uint32(params[4:])
	features := binary.LittleEndian.Uint32(params[20:])
	if sqEntries == 0 || cqEntries == 0 || sqEntries > maxRingEntries || cqEntries > maxRingEntries {
		cleanup()
		return nil, errs.Detail(ErrSetup, "invalid ring entries %d/%d | ring 条目数 %d/%d 非法", sqEntries, cqEntries, sqEntries, cqEntries)
	}
	sqHeadOff := binary.LittleEndian.Uint32(params[40:])
	sqTailOff := binary.LittleEndian.Uint32(params[44:])
	sqMaskOff := binary.LittleEndian.Uint32(params[48:])
	sqArrayOff := binary.LittleEndian.Uint32(params[64:])
	cqHeadOff := binary.LittleEndian.Uint32(params[80:])
	cqTailOff := binary.LittleEndian.Uint32(params[84:])
	cqMaskOff := binary.LittleEndian.Uint32(params[88:])
	cqesOff := binary.LittleEndian.Uint32(params[100:])
	sqRingSize := int(sqArrayOff) + int(sqEntries)*4
	cqRingSize := int(cqesOff) + int(cqEntries)*cqeSize
	if sqRingSize <= 0 || cqRingSize <= 0 || sqRingSize > 1<<30 || cqRingSize > 1<<30 {
		cleanup()
		return nil, errs.Detail(ErrSetup, "invalid ring layout sizes | ring 布局大小非法")
	}
	prot := unix.PROT_READ | unix.PROT_WRITE
	flags := unix.MAP_SHARED
	mmap := func(off int64, size int) ([]byte, error) {
		b, err := unix.Mmap(int(fd), off, size, prot, flags|unix.MAP_POPULATE)
		if err != nil {
			b, err = unix.Mmap(int(fd), off, size, prot, flags)
		}
		return b, err
	}
	r.singleMmap = features&ioringFeatSingleMmap != 0
	var err error
	if r.singleMmap {
		size := sqRingSize
		if cqRingSize > size {
			size = cqRingSize
		}
		r.sqRing, err = mmap(ioringOffSQRing, size)
		if err != nil {
			cleanup()
			return nil, errs.WrapDetail(err, ErrSetup, "mmap SQ/CQ ring | 映射 SQ/CQ ring 失败")
		}
		r.cqRing = r.sqRing
	} else {
		r.sqRing, err = mmap(ioringOffSQRing, sqRingSize)
		if err != nil {
			cleanup()
			return nil, errs.WrapDetail(err, ErrSetup, "mmap SQ ring | 映射 SQ ring 失败")
		}
		r.cqRing, err = mmap(ioringOffCQRing, cqRingSize)
		if err != nil {
			cleanup()
			return nil, errs.WrapDetail(err, ErrSetup, "mmap CQ ring | 映射 CQ ring 失败")
		}
	}
	r.sqesMem, err = mmap(ioringOffSQEs, int(sqEntries)*sqeSize)
	if err != nil {
		cleanup()
		return nil, errs.WrapDetail(err, ErrSetup, "mmap SQEs | 映射 SQE 失败")
	}
	r.depth = sqEntries
	r.sqHead = (*uint32)(unsafe.Pointer(&r.sqRing[sqHeadOff]))
	r.sqTail = (*uint32)(unsafe.Pointer(&r.sqRing[sqTailOff]))
	r.sqMask = *(*uint32)(unsafe.Pointer(&r.sqRing[sqMaskOff]))
	r.sqArray = unsafe.Slice((*uint32)(unsafe.Pointer(&r.sqRing[sqArrayOff])), int(sqEntries))
	r.sqes = unsafe.Slice((*sqe)(unsafe.Pointer(&r.sqesMem[0])), int(sqEntries))
	r.cqHead = (*uint32)(unsafe.Pointer(&r.cqRing[cqHeadOff]))
	r.cqTail = (*uint32)(unsafe.Pointer(&r.cqRing[cqTailOff]))
	r.cqMask = *(*uint32)(unsafe.Pointer(&r.cqRing[cqMaskOff]))
	r.cqes = unsafe.Slice((*cqe)(unsafe.Pointer(&r.cqRing[cqesOff])), int(cqEntries))
	return r, nil
}

// submit pushes one SQE and waits for its completion. A failed
// io_uring_enter leaves the submission state ambiguous, so the ring is marked
// unusable instead of letting a later call consume a stale completion. |
// submit 提交一条 SQE 并等待完成。io_uring_enter 失败后提交状态不确定，因此把
// ring 标记为不可用，避免后续调用消费到陈旧完成项。
func (r *ring) submit(op uint8, fd int32, off, addr uint64, length, flags uint32, userData uint64) (int32, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, ErrClosed
	}
	if r.failed != nil {
		return 0, r.failed
	}
	head := atomic.LoadUint32(r.sqHead)
	tail := atomic.LoadUint32(r.sqTail)
	if tail-head >= r.depth {
		return r.failLocked(errs.Detail(ErrIO, "submission queue is full | 提交队列已满"))
	}
	idx := tail & r.sqMask
	s := &r.sqes[idx]
	*s = sqe{opcode: op, fd: fd, off: off, addr: addr, length: length, rwFlags: flags, userData: userData}
	r.sqArray[idx] = idx
	atomic.StoreUint32(r.sqTail, tail+1)
	for {
		_, _, errno := unix.Syscall6(unix.SYS_IO_URING_ENTER,
			uintptr(r.fd), 1, 1, ioringEnterGetEvents, 0, 0)
		if errno == unix.EINTR {
			continue
		}
		if errno != 0 {
			return r.failLocked(errs.WrapDetail(errno, ErrIO, "io_uring_enter | io_uring_enter 失败"))
		}
		break
	}
	for {
		cqHead := atomic.LoadUint32(r.cqHead)
		cqTail := atomic.LoadUint32(r.cqTail)
		if cqHead == cqTail {
			_, _, errno := unix.Syscall6(unix.SYS_IO_URING_ENTER,
				uintptr(r.fd), 0, 1, ioringEnterGetEvents, 0, 0)
			if errno == unix.EINTR {
				continue
			}
			if errno != 0 {
				return r.failLocked(errs.WrapDetail(errno, ErrIO, "io_uring_enter wait | io_uring_enter 等待失败"))
			}
			continue
		}
		c := r.cqes[cqHead&r.cqMask]
		atomic.StoreUint32(r.cqHead, cqHead+1)
		if c.userData != userData {
			return r.failLocked(errs.Detail(ErrIO, "completion user_data mismatch | 完成项 user_data 不匹配"))
		}
		return c.res, nil
	}
}

// close unmaps the rings and closes the ring fd. | close 解除映射并关闭 ring fd。
// failLocked latches a ring failure. The caller holds r.mu. | failLocked
// 锁定一次性 ring 故障；调用方持有 r.mu。
func (r *ring) failLocked(err error) (int32, error) {
	if r.failed == nil {
		r.failed = err
	}
	return 0, r.failed
}

func (r *ring) close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	var first error
	if r.sqesMem != nil {
		if err := unix.Munmap(r.sqesMem); err != nil && first == nil {
			first = err
		}
		r.sqesMem = nil
	}
	if r.singleMmap {
		if r.sqRing != nil {
			if err := unix.Munmap(r.sqRing); err != nil && first == nil {
				first = err
			}
		}
	} else {
		if r.sqRing != nil {
			if err := unix.Munmap(r.sqRing); err != nil && first == nil {
				first = err
			}
		}
		if r.cqRing != nil {
			if err := unix.Munmap(r.cqRing); err != nil && first == nil {
				first = err
			}
		}
	}
	r.sqRing, r.cqRing = nil, nil
	if err := unix.Close(r.fd); err != nil && first == nil {
		first = err
	}
	return first
}

// Engine is the io_uring IOEngine. | Engine 是 io_uring IOEngine。
type Engine struct {
	r       *ring
	writeMu sync.Mutex
	iovecs  []unix.Iovec
}

// New creates an io_uring engine. | New 创建 io_uring 引擎。
func New(opts ...Option) (*Engine, error) {
	var o Options
	for _, fn := range opts {
		if fn != nil {
			fn(&o)
		}
	}
	o.normalize()
	r, err := newRing(o.QueueDepth, o.SetupFlags)
	if err != nil {
		return nil, err
	}
	return &Engine{r: r, iovecs: make([]unix.Iovec, 0, iovecMax)}, nil
}

// Supported probes io_uring_setup without keeping a ring. | Supported 探测
// io_uring_setup，不保留 ring。
var (
	supportedOnce sync.Once
	supportedFlag bool
)

// Supported reports whether the running kernel accepts io_uring_setup. |
// Supported 返回当前内核是否接受 io_uring_setup。
func Supported() bool {
	supportedOnce.Do(func() {
		var params [ioURingParamsSize]byte
		fd, _, errno := unix.Syscall(unix.SYS_IO_URING_SETUP, 2, uintptr(unsafe.Pointer(&params[0])), 0)
		if errno == 0 {
			supportedFlag = true
			_ = unix.Close(int(fd))
		}
	})
	return supportedFlag
}

// WriteAt submits WRITEV chunks and optionally a data sync. | WriteAt 提交
// WRITEV 分块，并按需执行数据同步。
func (e *Engine) WriteAt(f *os.File, parts [][]byte, off int64, syncData bool) error {
	if e == nil || e.r == nil {
		return ErrUnsupported
	}
	parts = compactParts(parts)
	e.writeMu.Lock()
	defer e.writeMu.Unlock()
	for len(parts) > 0 {
		chunk := parts
		if len(chunk) > iovecMax {
			chunk = chunk[:iovecMax]
		}
		e.iovecs = e.iovecs[:0]
		for _, p := range chunk {
			if len(p) == 0 {
				continue
			}
			e.iovecs = append(e.iovecs, unix.Iovec{Base: &p[0], Len: uint64(len(p))})
		}
		if len(e.iovecs) == 0 {
			break
		}
		res, err := e.r.submit(ioringOpWritev, int32(f.Fd()), uint64(off),
			uint64(uintptr(unsafe.Pointer(&e.iovecs[0]))), uint32(len(e.iovecs)), 0, 0)
		runtime.KeepAlive(f)
		runtime.KeepAlive(e.iovecs)
		if err != nil {
			return err
		}
		if res < 0 {
			errno := unix.Errno(-res)
			if errno == unix.EINTR || errno == unix.EAGAIN {
				continue
			}
			return errs.WrapDetail(errno, ErrIO, "WRITEV | WRITEV 失败")
		}
		total := 0
		for _, p := range chunk {
			total += len(p)
		}
		n := int(res)
		if n <= 0 || n > total {
			return errs.Detail(ErrIO, "WRITEV returned %[1]d of %[2]d | WRITEV 返回 %[1]d/%[2]d", n, total)
		}
		parts = advanceParts(parts, n)
		off += int64(n)
	}
	if syncData {
		return e.Sync(f)
	}
	return nil
}

// ReadAt submits READ until dst is full or EOF. | ReadAt 提交 READ 直到 dst 填满
// 或到达 EOF。
func (e *Engine) ReadAt(f *os.File, dst []byte, off int64) (int, error) {
	if e == nil || e.r == nil {
		return 0, ErrUnsupported
	}
	total := 0
	for total < len(dst) {
		res, err := e.r.submit(ioringOpRead, int32(f.Fd()), uint64(off+int64(total)),
			uint64(uintptr(unsafe.Pointer(&dst[total]))), uint32(len(dst)-total), 0, 0)
		runtime.KeepAlive(f)
		runtime.KeepAlive(dst)
		if err != nil {
			return total, err
		}
		if res < 0 {
			errno := unix.Errno(-res)
			if errno == unix.EINTR || errno == unix.EAGAIN {
				continue
			}
			return total, errs.WrapDetail(errno, ErrIO, "READ | READ 失败")
		}
		n := int(res)
		if n == 0 {
			return total, io.EOF
		}
		total += n
	}
	return total, nil
}

// Sync submits FSYNC with IORING_FSYNC_DATASYNC. | Sync 提交带
// IORING_FSYNC_DATASYNC 的 FSYNC。
func (e *Engine) Sync(f *os.File) error {
	if e == nil || e.r == nil {
		return ErrUnsupported
	}
	res, err := e.r.submit(ioringOpFsync, int32(f.Fd()), 0, 0, 0, ioringFsyncDataSync, 0)
	runtime.KeepAlive(f)
	if err != nil {
		return err
	}
	if res < 0 {
		return errs.WrapDetail(unix.Errno(-res), ErrIO, "FSYNC | FSYNC 失败")
	}
	return nil
}

// Close releases the ring. | Close 释放 ring。
func (e *Engine) Close() error {
	if e == nil || e.r == nil {
		return nil
	}
	return e.r.close()
}

// compactParts drops empty parts. | compactParts 去掉空分片。
func compactParts(parts [][]byte) [][]byte {
	for _, p := range parts {
		if len(p) == 0 {
			out := make([][]byte, 0, len(parts))
			for _, q := range parts {
				if len(q) > 0 {
					out = append(out, q)
				}
			}
			return out
		}
	}
	return parts
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
