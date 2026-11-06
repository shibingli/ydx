package rdma

import (
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/shibingli/ydx/errs"
)

// Access is the set of memory region permissions requested from the device. |
// Access 是向设备申请的内存区权限集合。
type Access uint32

// Memory region access flags mirroring ibv_access_flags. | 与 ibv_access_flags
// 对应的内存区访问标志。
const (
	// AccessLocalWrite allows the local device to write the region. |
	// AccessLocalWrite 允许本地设备写入。
	AccessLocalWrite Access = 1 << 0
	// AccessRemoteWrite allows remote RDMA writes. | AccessRemoteWrite 允许远端
	// RDMA 写。
	AccessRemoteWrite Access = 1 << 1
	// AccessRemoteRead allows remote RDMA reads. | AccessRemoteRead 允许远端
	// RDMA 读。
	AccessRemoteRead Access = 1 << 2
	// AccessRemoteAtomic allows remote atomic operations. | AccessRemoteAtomic
	// 允许远端原子操作。
	AccessRemoteAtomic Access = 1 << 3
	// AccessRelaxedOrdering enables relaxed PCIe ordering. |
	// AccessRelaxedOrdering 启用宽松 PCIe 排序。
	AccessRelaxedOrdering Access = 1 << 4
	// AccessDefault is the usual zero-copy messaging permission set. |
	// AccessDefault 是零拷贝消息常用权限集合。
	AccessDefault = AccessLocalWrite | AccessRemoteWrite | AccessRemoteRead | AccessRemoteAtomic
)

// String returns a short English description of the access set. | String 返回
// 权限集合的简短英文描述。
func (a Access) String() string {
	const names = "LWRAO"
	out := make([]byte, 0, len(names))
	flags := []Access{AccessLocalWrite, AccessRemoteWrite, AccessRemoteRead, AccessRemoteAtomic, AccessRelaxedOrdering}
	for i, f := range flags {
		if a&f != 0 {
			out = append(out, names[i])
		}
	}
	if len(out) == 0 {
		return "none"
	}
	return string(out)
}

// MR is a registered memory region. Its backing memory may be a huge-page
// mmap owned by the library or a caller slice. Close releases the registration
// and any library-owned memory. | MR 是已注册内存区。其内存可能由库管理的
// 大页 mmap 提供，也可能是调用方切片。Close 释放注册及库拥有的内存。
type MR struct {
	closeErr error
	dev      *Device
	ptr      unsafe.Pointer
	release  func() error
	mem      []byte
	addr     uintptr
	size     int
	closeMu  sync.Mutex
	lkey     uint32
	rkey     uint32
	access   Access
	closed   atomic.Bool
}

// Bytes returns the registered memory as a byte slice. The slice aliases
// device-visible memory and stays valid until Close. | Bytes 将注册内存返回为
// 字节切片。切片别名设备可见内存，在 Close 前有效。
func (m *MR) Bytes() []byte {
	if m == nil {
		return nil
	}
	if m.mem != nil {
		return m.mem
	}
	if m.ptr == nil || m.size == 0 {
		return nil
	}
	return unsafe.Slice((*byte)(m.ptr), m.size)
}

// Addr returns the virtual base address of the region. | Addr 返回内存区虚拟基地址。
func (m *MR) Addr() uintptr {
	if m == nil {
		return 0
	}
	return m.addr
}

// Len returns the region length in bytes. | Len 返回内存区字节长度。
func (m *MR) Len() int {
	if m == nil {
		return 0
	}
	return m.size
}

// LKey returns the local access key. | LKey 返回本地访问键。
func (m *MR) LKey() uint32 {
	if m == nil {
		return 0
	}
	return m.lkey
}

// RKey returns the remote access key. | RKey 返回远端访问键。
func (m *MR) RKey() uint32 {
	if m == nil {
		return 0
	}
	return m.rkey
}

// Access returns the registered permissions. | Access 返回注册的权限集合。
func (m *MR) Access() Access {
	if m == nil {
		return 0
	}
	return m.access
}

// Close deregisters the region and releases library-owned memory. It is
// idempotent and serializes concurrent callers. | Close 注销内存区并释放库拥有的
// 内存，可重复调用并串行化并发调用方。
func (m *MR) Close() error {
	if m == nil {
		return nil
	}
	// Serialize concurrent closes: the loser must observe the winner's result
	// rather than return before deregistration has actually completed. | 串行化
	// 并发关闭：后到的调用必须看到先到者的结果，而不是在注销真正完成前返回。
	m.closeMu.Lock()
	defer m.closeMu.Unlock()
	if m.closed.Load() {
		return m.closeErr
	}
	if m.release != nil {
		if err := m.release(); err != nil {
			m.closeErr = err
			return err
		}
		m.release = nil
	}
	m.closed.Store(true)
	m.closeErr = nil
	m.mem = nil
	m.ptr = nil
	m.addr = 0
	m.size = 0
	if m.dev != nil {
		m.dev.releaseChild()
	}
	return nil
}

// Buffer is one fixed-size slot of a registered memory pool. Buffers are owned
// by the pool and returned with Release. | Buffer 是注册内存池中的一个定长
// 槽位。缓冲区由池拥有，通过 Release 归还。
type Buffer struct {
	owner  *Pool
	data   []byte
	addr   uintptr
	lkey   uint32
	index  uint32
	inUse  atomic.Bool
	posted atomic.Bool
	rx     bool
}

// Bytes returns the slot memory. | Bytes 返回槽位内存。
func (b *Buffer) Bytes() []byte { return b.data }

// Addr returns the virtual address of the slot. | Addr 返回槽位虚拟地址。
func (b *Buffer) Addr() uintptr { return b.addr }

// LKey returns the local access key of the slot. | LKey 返回槽位本地访问键。
func (b *Buffer) LKey() uint32 { return b.lkey }

// Len returns the slot size in bytes. | Len 返回槽位字节长度。
func (b *Buffer) Len() int { return len(b.data) }

// Release returns a send-pool buffer to its pool. Buffers returned by
// Conn.RecvBuffer or Conn.RecvBuffers are receive-owned and must be returned
// with Conn.Release or Conn.ReleaseBatch; calling Release on them is a no-op.
// Releasing a buffer twice after the slot has been re-acquired by another
// caller is a caller bug and is not detectable here; release every acquisition
// exactly once. Releasing an in-flight posted buffer is ignored. | Release 将
// 发送池缓冲区归还其内存池。Conn.RecvBuffer 或 Conn.RecvBuffers 返回的接收缓冲区
// 必须通过 Conn.Release 或 Conn.ReleaseBatch 归还；对它们调用 Release 是空操作。
// 槽位被其它调用方重新获取后再次释放属于调用方错误，此处无法检测；每次获取必须恰好
// 释放一次。对仍在途且已提交的缓冲区释放会被忽略。
func (b *Buffer) Release() {
	if b == nil || b.owner == nil {
		return
	}
	// A buffer whose WQE or receive request is still posted must not re-enter
	// the free list; that would let another owner reuse live DMA memory.
	// | 仍处于已提交 WQE 或接收请求中的缓冲区不得回到空闲列表，否则其它所有者会
	// 复用在途 DMA 内存。
	if b.rx || b.posted.Load() {
		// Receive buffers are reposted through Conn.Release; returning them to
		// the pool would let a sender reuse a slot the RQ still owns. | 接收缓冲区
		// 必须经 Conn.Release 重新提交；归还内存池会让发送方复用 RQ 仍持有的槽位。
		return
	}
	b.owner.Release(b)
}

// Pool is a registered arena split into fixed-size slots. Acquire and Release
// are lock-free and safe for concurrent use. | Pool 是切分为定长槽位的注册
// 内存区。Acquire 与 Release 无锁且可并发使用。
type Pool struct {
	closeErr error
	mr       *MR
	free     *slotStack
	buffers  []*Buffer
	slotSize int
	closeMu  sync.Mutex
	closed   atomic.Bool
}

// newPool splits mr into slots of slotSize. slotSize must be a multiple of
// align (a power of two); zero align means 64-byte slots. | newPool 将 mr 切分为
// slotSize 大小的槽位。slotSize 必须是 2 的幂 align 的整数倍；align 为零表示
// 64 字节。

func newPool(mr *MR, slotSize, align int) (*Pool, error) {
	return newPoolMax(mr, slotSize, align, 0)
}

// newPoolMax is newPool with an optional upper bound on the number of slots.
// A huge-page arena is rounded up to 2 MiB; without the bound, Pool.Slots()
// would expose more buffers than PoolConfig.Slots requested. | newPoolMax 是带
// 可选槽位上限的 newPool。大页内存区会向上取整到 2 MiB；没有上限时 Pool.Slots()
// 会暴露超过 PoolConfig.Slots 请求的缓冲区。
func newPoolMax(mr *MR, slotSize, align, maxSlots int) (*Pool, error) {
	if mr == nil || mr.Len() <= 0 {
		return nil, errs.Detail(ErrInvalidConfig, "empty memory region | 内存区为空")
	}
	if align <= 0 {
		align = 64
	}
	if align&(align-1) != 0 {
		return nil, errs.Detail(ErrInvalidConfig, "align %d is not a power of two | 对齐 %d 不是 2 的幂", align, align)
	}
	if slotSize <= 0 || slotSize%align != 0 {
		return nil, errs.Detail(ErrInvalidConfig, "slot size %d is not a multiple of %d | 槽位大小 %d 不是 %d 的倍数", slotSize, align, slotSize, align)
	}
	if mr.Addr()%uintptr(align) != 0 {
		return nil, errs.Detail(ErrInvalidConfig, "arena address %#x is not aligned to %d | 内存区地址 %#x 未按 %d 对齐",
			mr.Addr(), align, mr.Addr(), align)
	}
	slots := mr.Len() / slotSize
	if maxSlots > 0 && slots > maxSlots {
		slots = maxSlots
	}
	if slots < 1 {
		return nil, errs.Detail(ErrInvalidConfig, "slot size %d exceeds region %d | 槽位大小 %d 超过内存区 %d", slotSize, mr.Len(), slotSize, mr.Len())
	}
	p := &Pool{
		mr:       mr,
		slotSize: slotSize,
		buffers:  make([]*Buffer, slots),
		free:     newSlotStack(slots),
	}
	for i := 0; i < slots; i++ {
		off := i * slotSize
		p.buffers[i] = &Buffer{
			data:  mr.Bytes()[off : off+slotSize],
			addr:  mr.Addr() + uintptr(off),
			lkey:  mr.LKey(),
			index: uint32(i),
			owner: p,
		}
	}
	return p, nil
}

// SlotSize returns the size of one slot in bytes. | SlotSize 返回单个槽位的
// 字节长度。
func (p *Pool) SlotSize() int { return p.slotSize }

// Slots returns the number of slots in the pool. | Slots 返回池中槽位数量。
func (p *Pool) Slots() int { return len(p.buffers) }

// Bytes returns the whole arena. | Bytes 返回整个内存区。
func (p *Pool) Bytes() []byte { return p.mr.Bytes() }

// MR returns the backing memory region. | MR 返回底层内存区。
func (p *Pool) MR() *MR { return p.mr }

// Buffers returns the pool's slot buffers. The slice is owned by the pool and
// must not be modified. | Buffers 返回池的槽位缓冲区；切片由池拥有，不得修改。
func (p *Pool) Buffers() []*Buffer { return p.buffers }

// Acquire removes and returns one free slot. It reports false when the pool is
// exhausted or closed. | Acquire 取出并返回一个空闲槽位；池耗尽或已关闭时返回
// false。
func (p *Pool) Acquire() (*Buffer, bool) {
	if p == nil || p.closed.Load() || p.free == nil {
		return nil, false
	}
	for {
		idx, ok := p.free.pop()
		if !ok {
			return nil, false
		}
		b := p.buffers[idx]
		if b.inUse.CompareAndSwap(false, true) {
			if p.closed.Load() {
				b.inUse.Store(false)
				return nil, false
			}
			b.posted.Store(false)
			return b, true
		}
		// The stack handed us a slot already marked in use; drop it and retry.
		// | 栈返回了已标记占用的槽位；丢弃并重试。
	}
}

// Release returns b to the pool. Buffers from another pool and double releases
// are ignored. | Release 将 b 归还池。来自其它池的缓冲区与重复释放会被忽略。
func (p *Pool) Release(b *Buffer) {
	if p == nil || b == nil || b.owner != p || b.rx {
		return
	}
	if !b.inUse.CompareAndSwap(true, false) {
		return
	}
	if p.closed.Load() {
		return
	}
	p.free.push(b.index)
}

// Close releases the arena and registration. All outstanding buffers become
// invalid. Close must not race Acquire on the same pool; Release of buffers
// already owned by the caller is ignored after close. It is idempotent. |
// Close 释放内存区与注册，所有未归还缓冲区失效。Close 不得与同一池的 Acquire
// 并发；关闭后对调用方已持有缓冲区的 Release 会被忽略。可重复调用。
func (p *Pool) Close() error {
	if p == nil {
		return nil
	}
	p.closeMu.Lock()
	defer p.closeMu.Unlock()
	if p.closed.Load() {
		return p.closeErr
	}
	// Block new acquisitions before deregistering so no caller can touch memory
	// while the provider is removing the region. | 在注销前阻止新的获取，避免提供方
	// 移除内存区时仍有调用方访问该内存。
	p.closed.Store(true)
	if err := p.mr.Close(); err != nil {
		// Keep the pool open so the failed deregistration can be retried. |
		// 保持池可用，使失败的注销可以重试。
		p.closed.Store(false)
		p.closeErr = err
		return err
	}
	p.closeErr = nil
	return nil
}

// slotStack is a bounded lock-free LIFO stack of slot indexes with a tag that
// prevents ABA reuse. | slotStack 是带标签的有界无锁后进先出槽位索引栈，标签
// 用于避免 ABA 复用。
type slotStack struct {
	next []atomic.Uint32
	head atomic.Uint64 // high 32 bits: tag; low 32 bits: index+1 | 高 32 位标签，低 32 位索引+1
}

// newSlotStack builds a stack holding indexes 0..n-1. | newSlotStack 构建持有
// 索引 0..n-1 的栈。
func newSlotStack(n int) *slotStack {
	s := &slotStack{next: make([]atomic.Uint32, n)}
	for i := 0; i < n; i++ {
		s.next[i].Store(uint32(i + 2))
	}
	if n > 0 {
		s.next[n-1].Store(0)
		s.head.Store(1)
	}
	return s
}

// pop removes the top index. | pop 取出栈顶索引。
func (s *slotStack) pop() (uint32, bool) {
	for {
		h := s.head.Load()
		slot := uint32(h)
		if slot == 0 {
			return 0, false
		}
		idx := slot - 1
		next := s.next[idx].Load()
		tag := h>>32 + 1
		if s.head.CompareAndSwap(h, uint64(next)|tag<<32) {
			return idx, true
		}
	}
}

// push adds idx to the top of the stack. | push 将 idx 压入栈顶。
func (s *slotStack) push(idx uint32) {
	for {
		h := s.head.Load()
		s.next[idx].Store(uint32(h))
		tag := h>>32 + 1
		if s.head.CompareAndSwap(h, uint64(idx+1)|tag<<32) {
			return
		}
	}
}
