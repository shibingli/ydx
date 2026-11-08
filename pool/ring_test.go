package pool

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
)

// TestRingFIFO verifies that the ring preserves FIFO order after enqueueing exactly its capacity.
// | TestRingFIFO 验证环在填满容量后仍保持先进先出顺序。
func TestRingFIFO(t *testing.T) {
	r := newRing[int](8)
	for i := 1; i <= 8; i++ {
		if !r.tryEnqueue(i) {
			t.Fatalf("enqueue %d failed | 入队 %d 失败", i, i)
		}
	}
	for i := 1; i <= 8; i++ {
		got, ok := r.tryDequeue()
		if !ok || got != i {
			t.Fatalf("dequeue: got (%d, %v), want (%d, true) | 出队结果不符", got, ok, i)
		}
	}
	if _, ok := r.tryDequeue(); ok {
		t.Fatal("dequeue from empty ring succeeded | 空环出队成功")
	}
}

// TestRingFullEmpty verifies the full and empty boundaries at the minimum capacity.
// | TestRingFullEmpty 验证最小容量下的满与空边界。
func TestRingFullEmpty(t *testing.T) {
	r := newRing[int](2)
	if r.len() != 0 {
		t.Fatalf("empty len = %d, want 0 | 空环长度不符", r.len())
	}
	if !r.tryEnqueue(1) || !r.tryEnqueue(2) {
		t.Fatal("enqueue into empty ring failed | 空环入队失败")
	}
	if r.tryEnqueue(3) {
		t.Fatal("enqueue into full ring succeeded | 满环入队成功")
	}
	if r.len() != 2 {
		t.Fatalf("full len = %d, want 2 | 满环长度不符", r.len())
	}
	for _, want := range []int{1, 2} {
		got, ok := r.tryDequeue()
		if !ok || got != want {
			t.Fatalf("dequeue: got (%d, %v), want (%d, true) | 出队结果不符", got, ok, want)
		}
	}
	if !r.tryEnqueue(3) {
		t.Fatal("enqueue after drain failed | 排空后入队失败")
	}
	if got, ok := r.tryDequeue(); !ok || got != 3 {
		t.Fatalf("dequeue: got (%d, %v), want (3, true) | 出队结果不符", got, ok)
	}
	if _, ok := r.tryDequeue(); ok {
		t.Fatal("dequeue from drained ring succeeded | 排空后出队成功")
	}
	if !r.tryEnqueue(4) {
		t.Fatal("enqueue after drain failed | 排空后入队失败")
	}
	if got, ok := r.tryDequeue(); !ok || got != 4 {
		t.Fatalf("dequeue: got (%d, %v), want (4, true) | 出队结果不符", got, ok)
	}
}

// TestRingWrap verifies sequence-number reuse across many wrap-arounds.
// | TestRingWrap 验证多次回绕后的序列号复用。
func TestRingWrap(t *testing.T) {
	r := newRing[int](4)
	for i := 0; i < 1000; i++ {
		if !r.tryEnqueue(i) {
			t.Fatalf("enqueue %d failed | 入队失败", i)
		}
		got, ok := r.tryDequeue()
		if !ok || got != i {
			t.Fatalf("dequeue: got (%d, %v), want (%d, true) | 出队结果不符", got, ok, i)
		}
	}
}

// TestRingCapacityRoundsUp verifies that non-power-of-two capacities are rounded up.
// | TestRingCapacityRoundsUp 验证非 2 的幂容量会被向上取整。
func TestRingCapacityRoundsUp(t *testing.T) {
	r := newRing[int](3)
	if got := cap(r.vals); got != 4 {
		t.Fatalf("capacity = %d, want 4 | 容量不符", got)
	}
}

// TestRingConcurrent hammers the ring with multiple producers and consumers.
// | TestRingConcurrent 用多生产者/多消费者压测环。
func TestRingConcurrent(t *testing.T) {
	const (
		producers   = 4
		consumers   = 2
		perProducer = 10000
	)
	total := producers * perProducer
	r := newRing[int](128)
	seen := make([]atomic.Bool, total)
	var consumed atomic.Int64

	var prodWG sync.WaitGroup
	for p := 0; p < producers; p++ {
		prodWG.Add(1)
		go func(base int) {
			defer prodWG.Done()
			for i := 0; i < perProducer; i++ {
				v := base + i
				for !r.tryEnqueue(v) {
					runtime.Gosched()
				}
			}
		}(p * perProducer)
	}

	stop := make(chan struct{})
	var consWG sync.WaitGroup
	record := func(v int) bool {
		if v < 0 || v >= total {
			t.Errorf("value %d out of range | 值越界", v)
			return false
		}
		if seen[v].Swap(true) {
			t.Errorf("duplicate value %d | 重复值", v)
			return false
		}
		consumed.Add(1)
		return true
	}
	for c := 0; c < consumers; c++ {
		consWG.Add(1)
		go func() {
			defer consWG.Done()
			for {
				v, ok := r.tryDequeue()
				if ok {
					if !record(v) {
						return
					}
					continue
				}
				select {
				case <-stop:
					for {
						v, ok := r.tryDequeue()
						if !ok {
							return
						}
						if !record(v) {
							return
						}
					}
				default:
					runtime.Gosched()
				}
			}
		}()
	}

	prodWG.Wait()
	close(stop)
	consWG.Wait()

	if got := consumed.Load(); got != int64(total) {
		t.Fatalf("consumed = %d, want %d | 消费数量不符", got, total)
	}
}

// TestRingConcurrentMinimumCapacity hammers a two-slot ring with many producers
// and consumers so sequence-number reservation wraps while slots are reused. |
// TestRingConcurrentMinimumCapacity 用多生产者/多消费者压测两槽环，覆盖槽位复用时序列号
// 预占的回绕。
func TestRingConcurrentMinimumCapacity(t *testing.T) {
	const (
		producers   = 8
		consumers   = 8
		perProducer = 10000
	)
	total := producers * perProducer
	r := newRing[int](2)
	seen := make([]atomic.Bool, total)
	var consumed atomic.Int64

	var prodWG sync.WaitGroup
	for p := 0; p < producers; p++ {
		prodWG.Add(1)
		go func(base int) {
			defer prodWG.Done()
			for i := 0; i < perProducer; i++ {
				v := base + i
				for !r.tryEnqueue(v) {
					runtime.Gosched()
				}
			}
		}(p * perProducer)
	}

	stop := make(chan struct{})
	var consWG sync.WaitGroup
	record := func(v int) bool {
		if v < 0 || v >= total {
			t.Errorf("value %d out of range | 值越界", v)
			return false
		}
		if seen[v].Swap(true) {
			t.Errorf("duplicate value %d | 重复值", v)
			return false
		}
		consumed.Add(1)
		return true
	}
	for c := 0; c < consumers; c++ {
		consWG.Add(1)
		go func() {
			defer consWG.Done()
			for {
				v, ok := r.tryDequeue()
				if ok {
					if !record(v) {
						return
					}
					continue
				}
				select {
				case <-stop:
					for {
						v, ok := r.tryDequeue()
						if !ok {
							return
						}
						if !record(v) {
							return
						}
					}
				default:
					runtime.Gosched()
				}
			}
		}()
	}

	prodWG.Wait()
	close(stop)
	consWG.Wait()
	if got := consumed.Load(); got != int64(total) {
		t.Fatalf("consumed = %d, want %d | 消费数量不符", got, total)
	}
}
