package base64

import (
	stdbase64 "encoding/base64"
	"fmt"
	"testing"

	cwb64 "github.com/cloudwego/base64x"
	cmpb64 "github.com/cristalhq/base64"

	b64x "github.com/shibingli/ydx/base64"
)

// benchSinkBytes keeps encoded/decoded results observable. | benchSinkBytes 让编解码结果保持可观测。
var benchSinkBytes []byte

// benchSinkString keeps string results observable. | benchSinkString 让字符串结果保持可观测。
var benchSinkString string

// benchBuf returns n deterministic bytes. | benchBuf 返回 n 个确定性字节。
func benchBuf(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i%251 + 1)
	}
	return b
}

// BenchmarkEncode compares the adaptive encoder with encoding/base64 on the same buffers. | BenchmarkEncode
// 在同一缓冲上对比自适应编码器与 encoding/base64。
func BenchmarkEncode(b *testing.B) {
	for _, size := range []int{16, 1 << 10, 64 << 10} {
		src := benchBuf(size)
		dst := make([]byte, b64x.StdEncoding.EncodedLen(size))
		b.Run(fmt.Sprintf("b64x/%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				b64x.StdEncoding.Encode(dst, src)
			}
			benchSinkBytes = dst
		})
		b.Run(fmt.Sprintf("stdlib/%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				stdbase64.StdEncoding.Encode(dst, src)
			}
			benchSinkBytes = dst
		})
		b.Run(fmt.Sprintf("cristalhq/%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				cmpb64.StdEncoding.Encode(dst, src)
			}
			benchSinkBytes = dst
		})
		b.Run(fmt.Sprintf("cloudwego/%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				cwb64.StdEncoding.Encode(dst, src)
			}
			benchSinkBytes = dst
		})
	}
}

// BenchmarkEncodeToString compares the allocating encoders. | BenchmarkEncodeToString 对比会分配结果的编码入口。
func BenchmarkEncodeToString(b *testing.B) {
	for _, size := range []int{16, 1 << 10} {
		src := benchBuf(size)
		b.Run(fmt.Sprintf("b64x/%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchSinkString = b64x.StdEncoding.EncodeToString(src)
			}
		})
		b.Run(fmt.Sprintf("stdlib/%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchSinkString = stdbase64.StdEncoding.EncodeToString(src)
			}
		})
		b.Run(fmt.Sprintf("cristalhq/%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchSinkString = cmpb64.StdEncoding.EncodeToString(src)
			}
		})
		b.Run(fmt.Sprintf("cloudwego/%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchSinkString = cwb64.StdEncoding.EncodeToString(src)
			}
		})
	}
}

// BenchmarkRawURLEncode measures the unpadded URL-safe variant used by JWTs. | BenchmarkRawURLEncode
// 测量 JWT 使用的无填充 URL 安全变体。
func BenchmarkRawURLEncode(b *testing.B) {
	for _, size := range []int{16, 1 << 10, 64 << 10} {
		src := benchBuf(size)
		dst := make([]byte, b64x.RawURLEncoding.EncodedLen(size))
		b.Run(fmt.Sprintf("b64x/%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				b64x.RawURLEncoding.Encode(dst, src)
			}
		})
		b.Run(fmt.Sprintf("stdlib/%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				stdbase64.RawURLEncoding.Encode(dst, src)
			}
		})
		b.Run(fmt.Sprintf("cristalhq/%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				cmpb64.RawURLEncoding.Encode(dst, src)
			}
		})
		b.Run(fmt.Sprintf("cloudwego/%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				cwb64.RawURLEncoding.Encode(dst, src)
			}
		})
	}
}

// BenchmarkDecode compares the decoders; dst is reused, so this measures pure codec cost. | BenchmarkDecode
// 对比解码器；dst 复用，因此只测量编解码本身。
func BenchmarkDecode(b *testing.B) {
	for _, size := range []int{16, 1 << 10, 64 << 10} {
		src := benchBuf(size)
		encoded := make([]byte, b64x.StdEncoding.EncodedLen(size))
		b64x.StdEncoding.Encode(encoded, src)
		dst := make([]byte, b64x.StdEncoding.DecodedLen(len(encoded)))
		b.Run(fmt.Sprintf("b64x/%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := b64x.StdEncoding.Decode(dst, encoded); err != nil {
					b.Fatalf("Decode failed | Decode 失败: %v", err)
				}
			}
		})
		b.Run(fmt.Sprintf("stdlib/%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := stdbase64.StdEncoding.Decode(dst, encoded); err != nil {
					b.Fatalf("Decode failed | Decode 失败: %v", err)
				}
			}
		})
		b.Run(fmt.Sprintf("cristalhq/%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := cmpb64.StdEncoding.Decode(dst, encoded); err != nil {
					b.Fatalf("Decode failed | Decode 失败: %v", err)
				}
			}
		})
		b.Run(fmt.Sprintf("cloudwego/%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := cwb64.StdEncoding.Decode(dst, encoded); err != nil {
					b.Fatalf("Decode failed | Decode 失败: %v", err)
				}
			}
		})
	}
}

// BenchmarkDecodeString compares the allocating string decoders (the JWT path). | BenchmarkDecodeString
// 对比会分配结果的字符串解码入口（JWT 路径）。
func BenchmarkDecodeString(b *testing.B) {
	for _, size := range []int{16, 256, 1 << 10, 64 << 10} {
		src := benchBuf(size)
		encoded := b64x.RawURLEncoding.EncodeToString(src)
		b.Run(fmt.Sprintf("b64x/%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				out, err := b64x.RawURLEncoding.DecodeString(encoded)
				if err != nil {
					b.Fatalf("DecodeString failed | DecodeString 失败: %v", err)
				}
				benchSinkBytes = out
			}
		})
		b.Run(fmt.Sprintf("stdlib/%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				out, err := stdbase64.RawURLEncoding.DecodeString(encoded)
				if err != nil {
					b.Fatalf("DecodeString failed | DecodeString 失败: %v", err)
				}
				benchSinkBytes = out
			}
		})
		b.Run(fmt.Sprintf("cristalhq/%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				out, err := cmpb64.RawURLEncoding.DecodeString(encoded)
				if err != nil {
					b.Fatalf("DecodeString failed | DecodeString 失败: %v", err)
				}
				benchSinkBytes = out
			}
		})
		b.Run(fmt.Sprintf("cloudwego/%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				out, err := cwb64.RawURLEncoding.DecodeString(encoded)
				if err != nil {
					b.Fatalf("DecodeString failed | DecodeString 失败: %v", err)
				}
				benchSinkBytes = out
			}
		})
	}
}

// BenchmarkAppendEncodeDecode measures the zero-copy append APIs. | BenchmarkAppendEncodeDecode 测量零拷贝追加接口。
func BenchmarkAppendEncodeDecode(b *testing.B) {
	src := benchBuf(1 << 10)
	encoded := make([]byte, 0, b64x.StdEncoding.EncodedLen(len(src)))
	b.Run("append_encode", func(b *testing.B) {
		b.SetBytes(int64(len(src)))
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			encoded = b64x.StdEncoding.AppendEncode(encoded[:0], src)
		}
		benchSinkBytes = encoded
	})
	decoded := make([]byte, 0, len(src))
	b.Run("append_decode", func(b *testing.B) {
		b.SetBytes(int64(len(src)))
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			var err error
			decoded, err = b64x.StdEncoding.AppendDecode(decoded[:0], encoded)
			if err != nil {
				b.Fatalf("AppendDecode failed | AppendDecode 失败: %v", err)
			}
		}
		benchSinkBytes = decoded
	})
}
