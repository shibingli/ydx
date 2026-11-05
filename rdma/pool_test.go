package rdma

import (
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"
)

// newTestMR builds an MR over Go memory for tests that do not need a device. |
// newTestMR 在 Go 内存上构建 MR，供无需设备的测试使用。
func newTestMR(size int) *MR {
	buf := make([]byte, size)
	return &MR{mem: buf, ptr: unsafe.Pointer(&buf[0]), addr: uintptr(unsafe.Pointer(&buf[0])), size: size, lkey: 0x11, rkey: 0x22}
}

// TestNewPoolSplitsArena proves a pool exposes evenly sized, distinct slots. |
// TestNewPoolSplitsArena 证明池暴露等长且互不重叠的槽位。
func TestNewPoolSplitsArena(t *testing.T) {
	p, err := newPool(newTestMR(1024), 256, 0)
	if err != nil {
		t.Fatalf("newPool = %v | 创建池失败", err)
	}
	defer p.Close()
	if p.Slots() != 4 || p.SlotSize() != 256 {
		t.Fatalf("slots/size = %d/%d, want 4/256 | 槽位数量/大小不符", p.Slots(), p.SlotSize())
	}
	seen := make(map[uintptr]bool, 4)
	for i := 0; i < 4; i++ {
		b, ok := p.Acquire()
		if !ok {
			t.Fatalf("Acquire #%d failed | 第 %d 次获取失败", i, i)
		}
		if len(b.Bytes()) != 256 {
			t.Fatalf("buffer len = %d, want 256 | 缓冲区长度不符", len(b.Bytes()))
		}
		if b.LKey() != 0x11 {
			t.Fatalf("lkey = %#x, want 0x11 | lkey 不符", b.LKey())
		}
		if seen[b.Addr()] {
			t.Fatalf("duplicate slot address %#x | 槽位地址重复", b.Addr())
		}
		seen[b.Addr()] = true
	}
	if _, ok := p.Acquire(); ok {
		t.Fatal("Acquire on empty pool succeeded | 空池获取不应成功")
	}
}

// TestPoolReleaseReturnsSlot proves releasing a buffer makes it available
// again and a double release does not duplicate it. | TestPoolReleaseReturnsSlot
// 证明释放后槽位可再次获取，重复释放不会产生重复槽位。
func TestPoolReleaseReturnsSlot(t *testing.T) {
	p, err := newPool(newTestMR(512), 256, 0)
	if err != nil {
		t.Fatalf("newPool = %v | 创建池失败", err)
	}
	defer p.Close()
	first, ok := p.Acquire()
	if !ok {
		t.Fatal("Acquire failed | 获取失败")
	}
	second, ok := p.Acquire()
	if !ok {
		t.Fatal("Acquire #2 failed | 第二次获取失败")
	}
	first.Release()
	first.Release() // double release must be a no-op | 重复释放应为空操作
	reused, ok := p.Acquire()
	if !ok {
		t.Fatal("Acquire after release failed | 释放后获取失败")
	}
	if reused != first {
		t.Fatalf("reused = %p, want %p | 应复用刚释放的槽位", reused, first)
	}
	second.Release()
	reused.Release()
	if _, ok := p.Acquire(); !ok {
		t.Fatal("first slot missing after all releases | 全部释放后应有第一个槽位")
	}
	if _, ok := p.Acquire(); !ok {
		t.Fatal("second slot missing after all releases | 全部释放后应有第二个槽位")
	}
	if _, ok := p.Acquire(); ok {
		t.Fatal("pool not empty after all releases | 全部释放后池应为空")
	}
}

// TestPoolConcurrentExclusivity proves concurrent acquire/release never hands
// one slot to two goroutines. | TestPoolConcurrentExclusivity 证明并发获取/释放
// 不会把同一槽位交给两个协程。
func TestPoolConcurrentExclusivity(t *testing.T) {
	const slots = 8
	p, err := newPool(newTestMR(slots*128), 128, 0)
	if err != nil {
		t.Fatalf("newPool = %v | 创建池失败", err)
	}
	defer p.Close()
	var owners [slots]atomic.Int32
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				var b *Buffer
				for {
					var ok bool
					if b, ok = p.Acquire(); ok {
						break
					}
				}
				idx := int(b.index)
				if !owners[idx].CompareAndSwap(0, 1) {
					t.Errorf("slot %d acquired twice | 槽位 %d 被重复获取", idx, idx)
					return
				}
				owners[idx].Store(0)
				b.Release()
			}
		}()
	}
	wg.Wait()
	for i := 0; i < slots; i++ {
		if _, ok := p.Acquire(); !ok {
			t.Fatalf("slot %d leaked | 槽位 %d 泄漏", i, i)
		}
	}
}

// TestPoolCloseRejectsAcquire proves a closed pool returns no buffers. |
// TestPoolCloseRejectsAcquire 证明关闭后的池不再返回缓冲区。
func TestPoolCloseRejectsAcquire(t *testing.T) {
	p, err := newPool(newTestMR(256), 256, 0)
	if err != nil {
		t.Fatalf("newPool = %v | 创建池失败", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("Close = %v | 关闭失败", err)
	}
	if _, ok := p.Acquire(); ok {
		t.Fatal("Acquire after Close succeeded | 关闭后获取不应成功")
	}
	if err := p.Close(); err != nil {
		t.Fatalf("second Close = %v | 重复关闭应无害", err)
	}
}

// TestNewPoolRejectsBadGeometry proves invalid slot sizes are rejected. |
// TestNewPoolRejectsBadGeometry 证明非法槽位尺寸会被拒绝。
func TestNewPoolRejectsBadGeometry(t *testing.T) {
	if _, err := newPool(newTestMR(1024), 0, 0); err == nil {
		t.Fatal("newPool(slotSize=0) = nil, want error | 零槽位应报错")
	}
	if _, err := newPool(newTestMR(1024), 1500, 0); err == nil {
		t.Fatal("newPool(unaligned) = nil, want error | 未对齐槽位应报错")
	}
	if _, err := newPool(newTestMR(1024), 2048, 0); err == nil {
		t.Fatal("newPool(slot>arena) = nil, want error | 槽位超过容量应报错")
	}
}
