package buffpool

import (
	"sync"
	"testing"

	"github.com/valyala/bytebufferpool"

	ydxbuffpool "github.com/shibingli/ydx/buffpool"
)

// benchSizes mirrors the pool's published size classes. | benchSizes 镜像缓冲池公开的尺寸分级。
var benchSizes = []struct {
	name string
	size int
}{
	{name: "1KiB", size: 1 << 10},
	{name: "4KiB", size: 4 << 10},
	{name: "16KiB", size: 16 << 10},
	{name: "64KiB", size: 64 << 10},
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
			return &buf
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
				p := pool.Get().(*[]byte)
				benchSink = (*p)[:0]
				pool.Put(p)
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
		return &buf
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
				p := pool.Get().(*[]byte)
				pool.Put(p)
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
