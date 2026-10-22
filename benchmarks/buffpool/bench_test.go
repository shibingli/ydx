package buffpool

import (
	"testing"

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

// BenchmarkGetPut measures one pooled Get/Put cycle per size class. | BenchmarkGetPut 测量每个
// 尺寸分级的一次池化 Get/Put 循环。
func BenchmarkGetPut(b *testing.B) {
	for _, tc := range benchSizes {
		b.Run(tc.name, func(b *testing.B) {
			// Prime the class so the timed loop does not include the first allocation. | 预热该分级，
			// 使计时循环不包含首次分配。
			ydxbuffpool.Put(ydxbuffpool.Get(tc.size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				p := ydxbuffpool.Get(tc.size)
				benchSink = p
				ydxbuffpool.Put(p)
			}
		})
	}
}

// BenchmarkGetPutParallel measures the same cycle from many goroutines. | BenchmarkGetPutParallel
// 从多个 goroutine 测量同一循环。
func BenchmarkGetPutParallel(b *testing.B) {
	const size = 4 << 10
	ydxbuffpool.Put(ydxbuffpool.Get(size))
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			p := ydxbuffpool.Get(size)
			benchSink = p
			ydxbuffpool.Put(p)
		}
	})
}
