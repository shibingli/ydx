package base64

import (
	stdb64 "encoding/base64"
	"fmt"
	"runtime"
	"testing"

	cwb64 "github.com/cloudwego/base64x"
	cmpb64 "github.com/cristalhq/base64"

	b64x "github.com/shibingli/ydx/base64"
)

type parallelEncoder struct {
	name string
	fn   func(dst, src []byte)
}

type parallelDecoder struct {
	name string
	fn   func(dst, src []byte) (int, error)
}

// BenchmarkParallelEncode measures aggregate Encode throughput with RunParallel. Every goroutine
// owns its destination buffer, so the result isolates codec scaling from shared-buffer contention;
// run with -cpu 1,4,16,32 to read the curve across sizes. |
// BenchmarkParallelEncode 用 RunParallel 测量 Encode 的聚合吞吐量。每个协程持有自己的目标缓冲，
// 因此结果把编解码扩展性与共享缓冲争用分开；用 -cpu 1,4,16,32 读出各尺寸下的曲线。
func BenchmarkParallelEncode(b *testing.B) {
	encoders := []parallelEncoder{
		{name: "b64x", fn: b64x.StdEncoding.Encode},
		{name: "stdlib", fn: stdEncode},
		{name: "cristalhq", fn: cmpEncode},
		{name: "cloudwego", fn: cwEncode},
	}
	for _, size := range []int{16, 1 << 10, 64 << 10} {
		src := benchBuf(size)
		n := b64x.StdEncoding.EncodedLen(size)
		for _, e := range encoders {
			b.Run(fmt.Sprintf("%s/%d", e.name, size), func(b *testing.B) {
				b.SetBytes(int64(size))
				b.ReportAllocs()
				b.ResetTimer()
				b.RunParallel(func(pb *testing.PB) {
					dst := make([]byte, n)
					for pb.Next() {
						e.fn(dst, src)
						runtime.KeepAlive(dst)
					}
				})
			})
		}
	}
}

// BenchmarkParallelDecode measures aggregate Decode throughput with RunParallel and a destination
// owned by each goroutine. | BenchmarkParallelDecode 用 RunParallel 测量 Decode 的聚合吞吐量，
// 目标缓冲由每个协程独占。
func BenchmarkParallelDecode(b *testing.B) {
	decoders := []parallelDecoder{
		{name: "b64x", fn: b64x.StdEncoding.Decode},
		{name: "stdlib", fn: stdDecode},
		{name: "cristalhq", fn: cmpDecode},
		{name: "cloudwego", fn: cwDecode},
	}
	for _, size := range []int{16, 1 << 10, 64 << 10} {
		src := benchBuf(size)
		encoded := make([]byte, b64x.StdEncoding.EncodedLen(size))
		b64x.StdEncoding.Encode(encoded, src)
		n := b64x.StdEncoding.DecodedLen(len(encoded))
		for _, d := range decoders {
			b.Run(fmt.Sprintf("%s/%d", d.name, size), func(b *testing.B) {
				b.SetBytes(int64(size))
				b.ReportAllocs()
				b.ResetTimer()
				b.RunParallel(func(pb *testing.PB) {
					dst := make([]byte, n)
					for pb.Next() {
						m, err := d.fn(dst, encoded)
						if err != nil {
							b.Errorf("Decode failed | Decode 失败: %v", err)
							return
						}
						runtime.KeepAlive(dst[:m])
					}
				})
			})
		}
	}
}

func stdEncode(dst, src []byte) { stdb64.StdEncoding.Encode(dst, src) }

func stdDecode(dst, src []byte) (int, error) { return stdb64.StdEncoding.Decode(dst, src) }

func cmpEncode(dst, src []byte) { cmpb64.StdEncoding.Encode(dst, src) }

func cmpDecode(dst, src []byte) (int, error) { return cmpb64.StdEncoding.Decode(dst, src) }

func cwEncode(dst, src []byte) { cwb64.StdEncoding.Encode(dst, src) }

func cwDecode(dst, src []byte) (int, error) { return cwb64.StdEncoding.Decode(dst, src) }
