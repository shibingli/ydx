package crypto

// Benchmarks for the ydx/guomi wrapper, migrated from the package's own benchmark file so the
// component module stays free of Benchmark* symbols. | ydx/guomi 封装层基准，迁移自组件包内的
// 基准文件，使组件模块不包含任何 Benchmark*。

import (
	"fmt"
	"testing"

	"github.com/shibingli/ydx/guomi"
)

// BenchmarkGuomiSM3Sum measures the one-shot SM3 digest through the wrapper. |
// BenchmarkGuomiSM3Sum 测量封装层的一次性 SM3 摘要。
func BenchmarkGuomiSM3Sum(b *testing.B) {
	for _, size := range []int{64, 4 << 10, 64 << 10} {
		data := benchData(size)
		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchDigest = guomi.Sum(data)
			}
		})
	}
}

// BenchmarkGuomiHMACSM3 measures HMAC-SM3 over a short message. |
// BenchmarkGuomiHMACSM3 测量短消息上的 HMAC-SM3。
func BenchmarkGuomiHMACSM3(b *testing.B) {
	key := benchData(32)
	data := benchData(256)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchDigest = guomi.HMAC(key, data)
	}
}

// BenchmarkGuomiPBKDF2 measures PBKDF2-HMAC-SM3 with 1000 iterations. The default password hash
// uses 100000; the lower count keeps the benchmark fast while exposing per-iteration work. |
// BenchmarkGuomiPBKDF2 测量 1000 次迭代的 PBKDF2-HMAC-SM3；默认口令散列使用 100000 次，
// 较低次数让基准更快，同时暴露每轮工作。
func BenchmarkGuomiPBKDF2(b *testing.B) {
	password := []byte("correct horse battery staple")
	salt := benchData(16)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchBytes = guomi.PBKDF2(password, salt, 1000, guomi.SM3Size)
	}
}

// BenchmarkGuomiSM4CBC measures SM4-CBC encryption and decryption at two payload sizes. |
// BenchmarkGuomiSM4CBC 测量两种载荷大小下的 SM4-CBC 加解密。
func BenchmarkGuomiSM4CBC(b *testing.B) {
	key := benchData(guomi.SM4KeySize)
	iv := benchData(guomi.SM4IVSize)
	for _, size := range []int{256, 4 << 10} {
		plain := benchData(size)
		b.Run(fmt.Sprintf("encrypt/plain=%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				out, err := guomi.EncryptCBC(key, iv, plain)
				if err != nil {
					b.Fatalf("EncryptCBC failed | EncryptCBC 失败: %v", err)
				}
				benchBytes = out
			}
		})
		ct, err := guomi.EncryptCBC(key, iv, plain)
		if err != nil {
			b.Fatalf("setup failed | 准备失败: %v", err)
		}
		b.Run(fmt.Sprintf("decrypt/plain=%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				out, decErr := guomi.DecryptCBC(key, iv, ct)
				if decErr != nil {
					b.Fatalf("DecryptCBC failed | DecryptCBC 失败: %v", decErr)
				}
				benchBytes = out
			}
		})
	}
}

// BenchmarkGuomiSM4GCM measures SM4-GCM Seal and Open with the recommended 12-byte nonce. |
// BenchmarkGuomiSM4GCM 测量推荐 12 字节 nonce 下的 SM4-GCM Seal 与 Open。
func BenchmarkGuomiSM4GCM(b *testing.B) {
	key := benchData(guomi.SM4KeySize)
	nonce := benchData(guomi.SM4GCMNonceSize)
	aad := benchData(32)
	for _, size := range []int{256, 4 << 10} {
		plain := benchData(size)
		b.Run(fmt.Sprintf("seal/plain=%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				out, err := guomi.SealGCM(key, nonce, plain, aad)
				if err != nil {
					b.Fatalf("SealGCM failed | SealGCM 失败: %v", err)
				}
				benchBytes = out
			}
		})
		ct, err := guomi.SealGCM(key, nonce, plain, aad)
		if err != nil {
			b.Fatalf("setup failed | 准备失败: %v", err)
		}
		aead, err := guomi.NewGCM(key)
		if err != nil {
			b.Fatalf("NewGCM failed | NewGCM 失败: %v", err)
		}
		b.Run(fmt.Sprintf("seal_reused/plain=%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchBytes = aead.Seal(nil, nonce, plain, aad)
			}
		})
		b.Run(fmt.Sprintf("open_reused/plain=%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				out, openErr := aead.Open(nil, nonce, ct, aad)
				if openErr != nil {
					b.Fatalf("aead.Open failed | aead.Open 失败: %v", openErr)
				}
				benchBytes = out
			}
		})
		b.Run(fmt.Sprintf("open/plain=%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				out, openErr := guomi.OpenGCM(key, nonce, ct, aad)
				if openErr != nil {
					b.Fatalf("OpenGCM failed | OpenGCM 失败: %v", openErr)
				}
				benchBytes = out
			}
		})
	}
}

// BenchmarkGuomiSM2 measures key generation, signing and verification through the wrapper. |
// BenchmarkGuomiSM2 测量封装层的密钥生成、签名与验签。
func BenchmarkGuomiSM2(b *testing.B) {
	priv, err := guomi.GenerateKey()
	if err != nil {
		b.Fatalf("GenerateKey failed | GenerateKey 失败: %v", err)
	}
	pub := priv.Public()
	data := benchData(32)
	sig, err := guomi.Sign(priv, data)
	if err != nil {
		b.Fatalf("Sign failed | Sign 失败: %v", err)
	}

	b.Run("keygen", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, genErr := guomi.GenerateKey(); genErr != nil {
				b.Fatalf("GenerateKey failed | GenerateKey 失败: %v", genErr)
			}
		}
	})
	b.Run("sign", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			out, signErr := guomi.Sign(priv, data)
			if signErr != nil {
				b.Fatalf("Sign failed | Sign 失败: %v", signErr)
			}
			benchBytes = out
		}
	})
	b.Run("verify", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ok, verifyErr := guomi.Verify(pub, data, sig)
			if verifyErr != nil || !ok {
				b.Fatalf("Verify failed | Verify 失败: ok=%v err=%v", ok, verifyErr)
			}
			benchOK = ok
		}
	})
}
