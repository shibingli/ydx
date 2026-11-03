package buffpool

import (
	"sync"
	"testing"
	"unsafe"

	"github.com/valyala/bytebufferpool"

	ydxbuffpool "github.com/shibingli/ydx/buffpool"
)

// benchSizes mirrors the pool's published size classes. | benchSizes 镜像缓冲池公开的尺寸分级。
var benchSizes = []struct {
	name string
	size int
}{
	{name: "1KiB", size: 1 << 10},
	{name: "2KiB", size: 2 << 10},
	{name: "4KiB", size: 4 << 10},
	{name: "8KiB", size: 8 << 10},
	{name: "16KiB", size: 16 << 10},
	{name: "32KiB", size: 32 << 10},
	{name: "64KiB", size: 64 << 10},
	{name: "128KiB", size: 128 << 10},
	{name: "256KiB", size: 256 << 10},
}

// benchSink keeps a reference so the compiler cannot elide the Get call. | benchSink 持有引用，
// 防止编译器消除 Get 调用。
var benchSink []byte

// BenchmarkGetPut measures one pooled Get/Put cycle per size class for the adaptive size-class
// pool, a plain sync.Pool and valyala/bytebufferpool. The sync.Pool is created per size so its
// New function allocates the requested class; bytebufferpool has a single global pool and is
// therefore shared by all sizes. | BenchmarkGetPut 对自适应尺寸分级池、普通 sync.Pool 与
// valyala/bytebufferpool 测量每个尺寸分级的一次池化 Get/Put 循环。sync.Pool 按尺寸创建，使其
// New 函数分配目标分级；bytebufferpool 只有一个全局池，因此被所有尺寸共享。
func BenchmarkGetPut(b *testing.B) {
	for _, tc := range benchSizes {
		ydxbuffpool.Put(ydxbuffpool.Get(tc.size))
		pool := sync.Pool{New: func() any {
			buf := make([]byte, tc.size)
			return unsafe.SliceData(buf)
		}}
		pool.Put(pool.Get())
		bytebufferpool.Put(bytebufferpool.Get())

		b.Run(tc.name+"/ydx", func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				p := ydxbuffpool.Get(tc.size)
				benchSink = p
				ydxbuffpool.Put(p)
			}
		})
		b.Run(tc.name+"/syncpool", func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				p := unsafe.Slice(pool.Get().(*byte), tc.size)[:0]
				benchSink = p
				pool.Put(unsafe.SliceData(p))
			}
		})
		b.Run(tc.name+"/bytebufferpool", func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				p := bytebufferpool.Get()
				benchSink = p.Bytes()
				p.Reset()
				bytebufferpool.Put(p)
			}
		})
	}
}

// BenchmarkGetPutParallel measures the same 4 KiB cycle from many goroutines for each pool. |
// BenchmarkGetPutParallel 从多个 goroutine 对每个池测量相同的 4 KiB 循环。
func BenchmarkGetPutParallel(b *testing.B) {
	const size = 4 << 10

	ydxbuffpool.Put(ydxbuffpool.Get(size))
	pool := sync.Pool{New: func() any {
		buf := make([]byte, size)
		return unsafe.SliceData(buf)
	}}
	pool.Put(pool.Get())
	bytebufferpool.Put(bytebufferpool.Get())

	b.Run("ydx", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				p := ydxbuffpool.Get(size)
				ydxbuffpool.Put(p)
			}
		})
	})
	b.Run("syncpool", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				p := unsafe.Slice(pool.Get().(*byte), size)[:0]
				pool.Put(unsafe.SliceData(p))
			}
		})
	})
	b.Run("bytebufferpool", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				p := bytebufferpool.Get()
				p.Reset()
				bytebufferpool.Put(p)
			}
		})
	})
}

// BenchmarkGetPutMixedParallel cycles through every size class from many
// goroutines. It exposes false sharing between adjacent class slots and the
// cost of class selection when several classes are hot at once. |
// BenchmarkGetPutMixedParallel 从多个 goroutine 轮换所有尺寸分级，暴露相邻分级槽位
// 之间的伪共享以及多个分级同时活跃时的选择成本。
func BenchmarkGetPutMixedParallel(b *testing.B) {
	for _, tc := range benchSizes {
		ydxbuffpool.Put(ydxbuffpool.Get(tc.size))
	}
	pools := make([]sync.Pool, len(benchSizes))
	for i, tc := range benchSizes {
		size := tc.size
		pools[i] = sync.Pool{New: func() any {
			buf := make([]byte, size)
			return unsafe.SliceData(buf)
		}}
		pools[i].Put(pools[i].Get())
	}
	bytebufferpool.Put(bytebufferpool.Get())

	b.Run("ydx", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				size := benchSizes[i%len(benchSizes)].size
				p := ydxbuffpool.Get(size)
				ydxbuffpool.Put(p)
				i++
			}
		})
	})
	b.Run("syncpool", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				tc := benchSizes[i%len(benchSizes)]
				p := unsafe.Slice(pools[i%len(pools)].Get().(*byte), tc.size)[:0]
				pools[i%len(pools)].Put(unsafe.SliceData(p))
				i++
			}
		})
	})
	b.Run("bytebufferpool", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				p := bytebufferpool.Get()
				p.Reset()
				bytebufferpool.Put(p)
			}
		})
	})
}
