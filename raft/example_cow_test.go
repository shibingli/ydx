package raft

import (
	"context"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// cowFSM is a copy-on-write state machine for read-heavy workloads. Apply
// publishes a new immutable map with one atomic pointer store; readers never
// take a lock and never observe a partially updated map. FSM.Apply/Snapshot/
// Restore still run on one goroutine, so the copy is cheap and uncontended. |
// cowFSM 是面向读多写少负载的写时复制状态机。Apply 通过一次原子指针替换发布新的
// 不可变 map；读者不加锁，也不会看到部分更新。FSM.Apply/Snapshot/Restore 仍在
// 单一协程运行，因此复制廉价且无竞争。
type cowFSM struct {
	state atomic.Pointer[map[string]string]
}

// newCOWFSM returns an empty copy-on-write state machine. | newCOWFSM 返回空的写时
// 复制状态机。
func newCOWFSM() *cowFSM {
	f := &cowFSM{}
	m := make(map[string]string)
	f.state.Store(&m)
	return f
}

// Apply stores one key=value command by publishing a fresh map. | Apply 通过发布
// 新 map 存储一条 key=value 命令。
func (f *cowFSM) Apply(_, _ uint64, data []byte) any {
	parts := strings.SplitN(string(data), "=", 2)
	if len(parts) != 2 {
		return nil
	}
	old := *f.state.Load()
	next := make(map[string]string, len(old)+1)
	for k, v := range old {
		next[k] = v
	}
	next[parts[0]] = parts[1]
	f.state.Store(&next)
	return nil
}

// Snapshot serializes the current map deterministically. | Snapshot 确定性地序列化
// 当前 map。
func (f *cowFSM) Snapshot() ([]byte, error) {
	m := *f.state.Load()
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(m[k])
		b.WriteByte('\n')
	}
	return []byte(b.String()), nil
}

// Restore replaces the current map with a parsed image. | Restore 用解析后的镜像替换
// 当前 map。
func (f *cowFSM) Restore(data []byte) error {
	next := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			next[parts[0]] = parts[1]
		}
	}
	f.state.Store(&next)
	return nil
}

// get reads one key without locks. | get 无锁读取一个键。
func (f *cowFSM) get(key string) (string, bool) {
	m := *f.state.Load()
	v, ok := m[key]
	return v, ok
}

// TestCOWFSMConcurrentReads demonstrates the lock-free read template under the
// race detector: Apply publishes immutable maps while readers load the pointer.
// | TestCOWFSMConcurrentReads 在竞态检测器下演示无锁读模板：Apply 发布不可变 map，
// 读者只加载指针。
func TestCOWFSMConcurrentReads(t *testing.T) {
	fsm := newCOWFSM()
	node, err := New(Config{
		ID: 1, Storage: NewMemStorage(), FSM: fsm,
		TickInterval: 5 * time.Millisecond, HeartbeatTicks: 1, ElectionTicks: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := node.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	var stop atomic.Bool
	var readers sync.WaitGroup
	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for !stop.Load() {
				_, _ = fsm.get("hot")
			}
		}()
	}
	for i := 0; i < 64; i++ {
		if _, err := node.Propose(ctx, []byte("hot="+string(rune('a'+i%26)))); err != nil {
			t.Fatal(err)
		}
	}
	if got, ok := fsm.get("hot"); !ok || got == "" {
		t.Fatalf("final value = %q, %v", got, ok)
	}
	stop.Store(true)
	readers.Wait()
}
