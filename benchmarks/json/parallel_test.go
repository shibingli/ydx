package json

import (
	"runtime"
	"testing"

	jsonx "github.com/shibingli/ydx/json"
)

// BenchmarkParallelMarshal measures aggregate Marshal throughput with RunParallel. Each operation
// carries its own result, so the number reflects how the implementation scales across Ps rather
// than the latency of one goroutine; run it with -cpu 1,4,16,32 to read the scaling curve. |
// BenchmarkParallelMarshal 用 RunParallel 测量 Marshal 的聚合吞吐量。每次操作独立持有结果，因此数字
// 反映实现跨 P 的扩展能力而非单协程延迟；用 -cpu 1,4,16,32 运行即可读出扩展曲线。
func BenchmarkParallelMarshal(b *testing.B) {
	cases := []struct {
		name string
		v    any
	}{
		{name: "one", v: benchUsers(1)[0]},
		{name: "many", v: benchUsers(64)},
		{name: "large", v: benchUsers(1024)},
	}
	for _, c := range cases {
		for _, enc := range benchMarshalers() {
			b.Run(c.name+"/"+enc.name, func(b *testing.B) {
				if _, err := enc.fn(c.v); err != nil {
					b.Fatalf("warm-up failed | 预热失败: %v", err)
				}
				b.ReportAllocs()
				b.ResetTimer()
				b.RunParallel(func(pb *testing.PB) {
					for pb.Next() {
						out, err := enc.fn(c.v)
						if err != nil {
							b.Errorf("Marshal failed | Marshal 失败: %v", err)
							return
						}
						runtime.KeepAlive(out)
					}
				})
			})
		}
	}
}

// BenchmarkParallelUnmarshal measures aggregate Unmarshal throughput with RunParallel and a fresh
// destination per operation, matching a request-scoped server workload. |
// BenchmarkParallelUnmarshal 用 RunParallel 测量 Unmarshal 的聚合吞吐量，每次操作使用全新目标，
// 与请求级服务负载一致。
func BenchmarkParallelUnmarshal(b *testing.B) {
	cases := []struct {
		name string
		in   []byte
		new  func() any
	}{
		{name: "one", in: mustMarshal(b, benchUsers(1)[0]), new: func() any { return new(benchUser) }},
		{name: "many", in: mustMarshal(b, benchUsers(64)), new: func() any { return new([]benchUser) }},
		{name: "large", in: mustMarshal(b, benchUsers(1024)), new: func() any { return new([]benchUser) }},
	}
	for _, c := range cases {
		for _, dec := range benchUnmarshalers() {
			b.Run(c.name+"/"+dec.name, func(b *testing.B) {
				if err := dec.fn(c.in, c.new()); err != nil {
					b.Fatalf("warm-up failed | 预热失败: %v", err)
				}
				b.ReportAllocs()
				b.ResetTimer()
				b.RunParallel(func(pb *testing.PB) {
					for pb.Next() {
						if err := dec.fn(c.in, c.new()); err != nil {
							b.Errorf("Unmarshal failed | Unmarshal 失败: %v", err)
							return
						}
					}
				})
			})
		}
	}
}

// BenchmarkPrewarm measures the idempotent cost of warming a complex type whose plans already
// exist. The first call builds the plans once and is the startup cost that Prewarm removes from
// the first request; it is measured separately rather than inside this loop. |
// BenchmarkPrewarm 测量复杂类型在计划已存在时的幂等预热成本。首次调用会一次性构建计划，正是
// Prewarm 从首个请求中移除的启动成本；该成本单独测量，不放在此循环内。
func BenchmarkPrewarm(b *testing.B) {
	v := benchUsers(64)
	jsonx.Prewarm(v, (*[]benchUser)(nil))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		jsonx.Prewarm(v, (*[]benchUser)(nil))
	}
}

func mustMarshal(b *testing.B, v any) []byte {
	b.Helper()
	out, err := jsonx.Marshal(v)
	if err != nil {
		b.Fatalf("setup failed | 准备失败: %v", err)
	}
	return out
}
