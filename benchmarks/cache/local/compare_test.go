package local

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/allegro/bigcache/v3"
	"github.com/coocood/freecache"
	ristretto "github.com/dgraph-io/ristretto/v2"
	gocache "github.com/patrickmn/go-cache"

	. "github.com/shibingli/ydx/cache/local"
)

// The comparison benchmarks use one fixed 32-byte value and a 1024-key read working set.
// Each cache is filled before the timer starts; the read loop only performs lookups. |
// 对比基准使用固定的 32 字节值与 1024 键的读取工作集。每个缓存在计时开始前完成填充，读取循环
// 只执行查找。

const (
	benchCompareReadKeys = 1024
	benchCompareSetKeys  = 4096
)

// benchCompareValue is the value stored by every cache. | benchCompareValue 是每个缓存存储的值。
var benchCompareValue = []byte("0123456789abcdef0123456789abcdef")

// benchNopLogger silences bigcache's queue-allocation messages so they do not corrupt the
// benchmark output. | benchNopLogger 静默 bigcache 的队列分配日志，避免污染基准输出。
type benchNopLogger struct{}

// Printf implements bigcache.Logger. | Printf 实现 bigcache.Logger。
func (benchNopLogger) Printf(string, ...any) {}

// benchCompareKeys returns n keys in the same format as the local cache benchmarks. |
// benchCompareKeys 返回与本地缓存基准相同格式的 n 个键。
func benchCompareKeys(n int) []string {
	keys := make([]string, n)
	for i := range keys {
		keys[i] = fmt.Sprintf("key:%05d", i)
	}
	return keys
}

// benchCompareByteKeys converts string keys once for freecache, which requires byte keys. |
// benchCompareByteKeys 一次性转换为字节键，供要求字节键的 freecache 使用。
func benchCompareByteKeys(keys []string) [][]byte {
	out := make([][]byte, len(keys))
	for i, k := range keys {
		out[i] = []byte(k)
	}
	return out
}

// BenchmarkLocalGetCompare compares the hit path of ydx/cache/local with bigcache, freecache,
// ristretto, sync.Map and patrickmn/go-cache. Each cache holds the same 1024 keys. |
// BenchmarkLocalGetCompare 对比 ydx/cache/local 与 bigcache、freecache、ristretto、sync.Map 及
// patrickmn/go-cache 的命中路径。每个缓存持有相同的 1024 个键。
func BenchmarkLocalGetCompare(b *testing.B) {
	keys := benchCompareKeys(benchCompareReadKeys)
	byteKeys := benchCompareByteKeys(keys)
	value := benchCompareValue

	b.Run("ydx", func(b *testing.B) {
		c, err := New(Options{MaxCost: 64 << 20, Shards: 8, MaxEntrySize: 1 << 20, CleanupInterval: time.Hour})
		if err != nil {
			b.Fatalf("New failed | New 失败: %v", err)
		}
		defer func() { _ = c.Close() }()
		for _, k := range keys {
			if err := c.Set(k, value, 0); err != nil {
				b.Fatalf("Set failed | Set 失败: %v", err)
			}
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, ok := c.Get(keys[i&(benchCompareReadKeys-1)]); !ok {
				b.Fatal("cache miss | 缓存未命中")
			}
		}
	})

	b.Run("bigcache", func(b *testing.B) {
		cfg := bigcache.DefaultConfig(time.Hour)
		cfg.Shards = 8
		cfg.MaxEntriesInWindow = benchCompareReadKeys
		cfg.MaxEntrySize = 1024
		cfg.HardMaxCacheSize = 64
		cfg.Verbose = false
		cfg.Logger = benchNopLogger{}
		c, err := bigcache.New(context.Background(), cfg)
		if err != nil {
			b.Fatalf("New failed | New 失败: %v", err)
		}
		defer func() { _ = c.Close() }()
		for _, k := range keys {
			if err := c.Set(k, value); err != nil {
				b.Fatalf("Set failed | Set 失败: %v", err)
			}
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := c.Get(keys[i&(benchCompareReadKeys-1)]); err != nil {
				b.Fatalf("Get failed | Get 失败: %v", err)
			}
		}
	})

	b.Run("freecache", func(b *testing.B) {
		c := freecache.NewCache(64 << 20)
		defer c.Clear()
		for _, k := range byteKeys {
			if err := c.Set(k, value, 0); err != nil {
				b.Fatalf("Set failed | Set 失败: %v", err)
			}
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := c.Get(byteKeys[i&(benchCompareReadKeys-1)]); err != nil {
				b.Fatalf("Get failed | Get 失败: %v", err)
			}
		}
	})

	b.Run("ristretto", func(b *testing.B) {
		c, err := ristretto.NewCache[string, []byte](&ristretto.Config[string, []byte]{
			NumCounters: 100_000,
			MaxCost:     64 << 20,
			BufferItems: 64,
		})
		if err != nil {
			b.Fatalf("NewCache failed | NewCache 失败: %v", err)
		}
		defer c.Close()
		for _, k := range keys {
			c.Set(k, value, int64(len(value)))
		}
		c.Wait()
		for _, k := range keys {
			if _, ok := c.Get(k); !ok {
				b.Skipf("ristretto rejected key %q during admission | ristretto 准入阶段拒绝了键 %q", k, k)
			}
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, ok := c.Get(keys[i&(benchCompareReadKeys-1)]); !ok {
				b.Fatal("cache miss | 缓存未命中")
			}
		}
	})

	b.Run("syncmap", func(b *testing.B) {
		var m sync.Map
		for _, k := range keys {
			m.Store(k, value)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, ok := m.Load(keys[i&(benchCompareReadKeys-1)]); !ok {
				b.Fatal("cache miss | 缓存未命中")
			}
		}
	})

	b.Run("go-cache", func(b *testing.B) {
		c := gocache.New(time.Hour, 0)
		for _, k := range keys {
			c.Set(k, value, 0)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, ok := c.Get(keys[i&(benchCompareReadKeys-1)]); !ok {
				b.Fatal("cache miss | 缓存未命中")
			}
		}
	})
}

// BenchmarkLocalSetCompare compares the insert path of the same caches. ristretto's Set is an
// asynchronous admission enqueue and does not wait for the write to become visible; the other
// implementations are synchronous. | BenchmarkLocalSetCompare 对比相同缓存的写入路径。
// ristretto 的 Set 是异步准入入队，不等待写入可见；其它实现是同步的。
func BenchmarkLocalSetCompare(b *testing.B) {
	keys := benchCompareKeys(benchCompareSetKeys)
	byteKeys := benchCompareByteKeys(keys)
	value := benchCompareValue

	b.Run("ydx", func(b *testing.B) {
		c, err := New(Options{MaxCost: 64 << 20, Shards: 8, MaxEntrySize: 1 << 20, CleanupInterval: time.Hour})
		if err != nil {
			b.Fatalf("New failed | New 失败: %v", err)
		}
		defer func() { _ = c.Close() }()
		_ = c.Set(keys[0], value, 0)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := c.Set(keys[i&(benchCompareSetKeys-1)], value, 0); err != nil {
				b.Fatalf("Set failed | Set 失败: %v", err)
			}
		}
	})

	b.Run("bigcache", func(b *testing.B) {
		cfg := bigcache.DefaultConfig(time.Hour)
		cfg.Shards = 8
		cfg.MaxEntriesInWindow = benchCompareSetKeys
		cfg.MaxEntrySize = 1024
		cfg.HardMaxCacheSize = 64
		cfg.Verbose = false
		cfg.Logger = benchNopLogger{}
		c, err := bigcache.New(context.Background(), cfg)
		if err != nil {
			b.Fatalf("New failed | New 失败: %v", err)
		}
		defer func() { _ = c.Close() }()
		_ = c.Set(keys[0], value)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := c.Set(keys[i&(benchCompareSetKeys-1)], value); err != nil {
				b.Fatalf("Set failed | Set 失败: %v", err)
			}
		}
	})

	b.Run("freecache", func(b *testing.B) {
		c := freecache.NewCache(64 << 20)
		defer c.Clear()
		_ = c.Set(byteKeys[0], value, 0)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := c.Set(byteKeys[i&(benchCompareSetKeys-1)], value, 0); err != nil {
				b.Fatalf("Set failed | Set 失败: %v", err)
			}
		}
	})

	b.Run("ristretto", func(b *testing.B) {
		c, err := ristretto.NewCache[string, []byte](&ristretto.Config[string, []byte]{
			NumCounters: 100_000,
			MaxCost:     64 << 20,
			BufferItems: 64,
		})
		if err != nil {
			b.Fatalf("NewCache failed | NewCache 失败: %v", err)
		}
		defer c.Close()
		c.Set(keys[0], value, int64(len(value)))
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			c.Set(keys[i&(benchCompareSetKeys-1)], value, int64(len(value)))
		}
	})

	b.Run("syncmap", func(b *testing.B) {
		var m sync.Map
		m.Store(keys[0], value)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			m.Store(keys[i&(benchCompareSetKeys-1)], value)
		}
	})

	b.Run("go-cache", func(b *testing.B) {
		c := gocache.New(time.Hour, 0)
		c.Set(keys[0], value, 0)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			c.Set(keys[i&(benchCompareSetKeys-1)], value, 0)
		}
	})
}

// BenchmarkLocalGetParallelCompare compares concurrent hit paths. Each goroutine keeps its own
// index so the benchmark introduces no shared counter. |
// BenchmarkLocalGetParallelCompare 对比并发命中路径。每个 goroutine 使用自己的索引，基准不引入
// 共享计数器。
func BenchmarkLocalGetParallelCompare(b *testing.B) {
	keys := benchCompareKeys(benchCompareReadKeys)
	byteKeys := benchCompareByteKeys(keys)
	value := benchCompareValue

	b.Run("ydx", func(b *testing.B) {
		c, err := New(Options{MaxCost: 64 << 20, Shards: 8, MaxEntrySize: 1 << 20, CleanupInterval: time.Hour})
		if err != nil {
			b.Fatalf("New failed | New 失败: %v", err)
		}
		defer func() { _ = c.Close() }()
		for _, k := range keys {
			if err := c.Set(k, value, 0); err != nil {
				b.Fatalf("Set failed | Set 失败: %v", err)
			}
		}
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				_, _ = c.Get(keys[i&(benchCompareReadKeys-1)])
				i++
			}
		})
	})

	b.Run("bigcache", func(b *testing.B) {
		cfg := bigcache.DefaultConfig(time.Hour)
		cfg.Shards = 8
		cfg.MaxEntriesInWindow = benchCompareReadKeys
		cfg.MaxEntrySize = 1024
		cfg.HardMaxCacheSize = 64
		cfg.Verbose = false
		cfg.Logger = benchNopLogger{}
		c, err := bigcache.New(context.Background(), cfg)
		if err != nil {
			b.Fatalf("New failed | New 失败: %v", err)
		}
		defer func() { _ = c.Close() }()
		for _, k := range keys {
			if err := c.Set(k, value); err != nil {
				b.Fatalf("Set failed | Set 失败: %v", err)
			}
		}
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				_, _ = c.Get(keys[i&(benchCompareReadKeys-1)])
				i++
			}
		})
	})

	b.Run("freecache", func(b *testing.B) {
		c := freecache.NewCache(64 << 20)
		defer c.Clear()
		for _, k := range byteKeys {
			if err := c.Set(k, value, 0); err != nil {
				b.Fatalf("Set failed | Set 失败: %v", err)
			}
		}
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				_, _ = c.Get(byteKeys[i&(benchCompareReadKeys-1)])
				i++
			}
		})
	})

	b.Run("ristretto", func(b *testing.B) {
		c, err := ristretto.NewCache[string, []byte](&ristretto.Config[string, []byte]{
			NumCounters: 100_000,
			MaxCost:     64 << 20,
			BufferItems: 64,
		})
		if err != nil {
			b.Fatalf("NewCache failed | NewCache 失败: %v", err)
		}
		defer c.Close()
		for _, k := range keys {
			c.Set(k, value, int64(len(value)))
		}
		c.Wait()
		for _, k := range keys {
			if _, ok := c.Get(k); !ok {
				b.Skipf("ristretto rejected key %q during admission | ristretto 准入阶段拒绝了键 %q", k, k)
			}
		}
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				_, _ = c.Get(keys[i&(benchCompareReadKeys-1)])
				i++
			}
		})
	})

	b.Run("syncmap", func(b *testing.B) {
		var m sync.Map
		for _, k := range keys {
			m.Store(k, value)
		}
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				_, _ = m.Load(keys[i&(benchCompareReadKeys-1)])
				i++
			}
		})
	})

	b.Run("go-cache", func(b *testing.B) {
		c := gocache.New(time.Hour, 0)
		for _, k := range keys {
			c.Set(k, value, 0)
		}
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				_, _ = c.Get(keys[i&(benchCompareReadKeys-1)])
				i++
			}
		})
	})
}
