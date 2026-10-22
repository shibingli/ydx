//go:build arm64 && goexperiment.simd && !b64x_std

package base64

import (
	"bytes"
	"errors"
	"testing"
)

// neonLengths covers empty, sub-block, exact-block, block-boundary and large inputs. | neonLengths
// 覆盖空输入、不足一块、恰好一块、块边界与大输入。
var neonLengths = []int{
	0, 1, 2, 3, 11, 12, 13, 15, 16, 17, 23, 24, 25, 27, 28, 29, 31, 32, 33,
	47, 48, 49, 63, 64, 65, 127, 128, 129, 255, 256, 1023, 1024, 65535, 65536,
}

// TestNEONEncodeAllLengths compares the NEON prefix plus the scalar tail with the scalar encoder
// and the standard library for every variant and block boundary. | TestNEONEncodeAllLengths 对每个
// 变体与块边界，比较 NEON 前缀加标量尾部与标量编码器、标准库的结果。
func TestNEONEncodeAllLengths(t *testing.T) {
	for _, v := range codecVariants() {
		t.Run(v.name, func(t *testing.T) {
			for _, n := range neonLengths {
				src := randomBytes(n)
				want := make([]byte, v.enc.EncodedLen(n))
				v.enc.encodeScalar(want, src)
				stdWant := make([]byte, v.std.EncodedLen(n))
				v.std.Encode(stdWant, src)
				if !bytes.Equal(want, stdWant) {
					t.Fatalf("n=%d: scalar encoder differs from stdlib | 标量编码与标准库不一致", n)
				}

				got := make([]byte, v.enc.EncodedLen(n))
				ni, no := encodeSIMDNEON(got, src, v.url, v.padded, v.enc.pad)
				v.enc.encodeScalar(got[no:], src[ni:])
				if !bytes.Equal(got, want) {
					t.Fatalf("n=%d: NEON encoding differs\nNEON:   %q\nscalar: %q | NEON 编码不一致", n, got, want)
				}
			}
		})
	}
}

// TestNEONDecodeAllLengths compares the NEON prefix plus the scalar tail with the scalar decoder
// and the standard library for every variant and block boundary. | TestNEONDecodeAllLengths 对每个
// 变体与块边界，比较 NEON 前缀加标量尾部与标量解码器、标准库的结果。
func TestNEONDecodeAllLengths(t *testing.T) {
	for _, v := range codecVariants() {
		t.Run(v.name, func(t *testing.T) {
			for _, n := range neonLengths {
				src := randomBytes(n)
				enc := make([]byte, v.enc.EncodedLen(n))
				v.enc.encodeScalar(enc, src)

				got := make([]byte, v.enc.DecodedLen(len(enc)))
				ni, no := decodeSIMDNEON(got, enc, v.url, !v.padded)
				tail, err := v.enc.decodeSlow(got[no:], enc[ni:])
				if err != nil {
					t.Fatalf("n=%d: NEON decode error: %v | NEON 解码出错", n, err)
				}
				if gotN := no + tail; gotN != n || !bytes.Equal(got[:gotN], src) {
					t.Fatalf("n=%d: NEON decoded %d bytes, want %d | NEON 解码长度或内容不一致", n, gotN, n)
				}

				stdOut := make([]byte, v.std.DecodedLen(len(enc)))
				stdN, stdErr := v.std.Decode(stdOut, enc)
				if stdErr != nil {
					t.Fatalf("n=%d: stdlib decode error: %v", n, stdErr)
				}
				if !bytes.Equal(got[:no+tail], stdOut[:stdN]) {
					t.Fatalf("n=%d: NEON decode differs from stdlib | NEON 解码与标准库不一致", n)
				}
			}
		})
	}
}

// TestNEONDecodeInvalid replaces each character with valid and invalid bytes and compares the
// NEON-prefix result with a fully scalar decode. | TestNEONDecodeInvalid 把每个字符替换为合法与
// 非法字节，比较 NEON 前缀结果与完全标量解码。
func TestNEONDecodeInvalid(t *testing.T) {
	replacements := []byte{
		'A', 'Z', 'a', 'z', '0', '9', '+', '/', '-', '_',
		'!', '=', '\r', '\n', 0x00, 0xFF,
	}
	for _, v := range codecVariants() {
		t.Run(v.name, func(t *testing.T) {
			src := randomBytes(64)
			enc := make([]byte, v.enc.EncodedLen(len(src)))
			v.enc.encodeScalar(enc, src)
			for pos := 0; pos < len(enc); pos++ {
				for _, r := range replacements {
					mutated := append([]byte(nil), enc...)
					mutated[pos] = r

					ref := make([]byte, v.enc.DecodedLen(len(mutated)))
					refN, refErr := v.enc.decodeSlow(ref, mutated)

					got := make([]byte, v.enc.DecodedLen(len(mutated)))
					ni, no := decodeSIMDNEON(got, mutated, v.url, !v.padded)
					tail, err := v.enc.decodeSlow(got[no:], mutated[ni:])
					gotN := no + tail

					if (refErr == nil) != (err == nil) {
						t.Fatalf("pos=%d repl=%q: error mismatch: scalar=%v NEON+tail=%v | 错误语义不一致", pos, r, refErr, err)
					}
					if err != nil {
						if !errors.Is(err, ErrInvalidData) {
							t.Fatalf("pos=%d repl=%q: error %v is not ErrInvalidData | 错误未包装 ErrInvalidData", pos, r, err)
						}
						continue
					}
					if gotN != refN || !bytes.Equal(got[:gotN], ref[:refN]) {
						t.Fatalf("pos=%d repl=%q: output mismatch: scalar=%d bytes NEON+tail=%d bytes | 输出不一致", pos, r, refN, gotN)
					}
				}
			}
		})
	}
}

// TestNEONUnaligned verifies NEON kernels accept unaligned source and destination slices. |
// TestNEONUnaligned 验证 NEON 内核接受非对齐的源与目标切片。
func TestNEONUnaligned(t *testing.T) {
	for _, v := range codecVariants() {
		t.Run(v.name, func(t *testing.T) {
			for _, n := range []int{16, 17, 32, 33, 47, 48, 1000} {
				raw := randomBytes(n + 1)
				src := raw[1:]
				want := make([]byte, v.enc.EncodedLen(n))
				v.enc.encodeScalar(want, src)

				gotBacking := make([]byte, v.enc.EncodedLen(n)+1)
				got := gotBacking[1:]
				ni, no := encodeSIMDNEON(got, src, v.url, v.padded, v.enc.pad)
				v.enc.encodeScalar(got[no:], src[ni:])
				if !bytes.Equal(got, want) {
					t.Fatalf("n=%d: unaligned encode differs | 非对齐编码不一致", n)
				}

				encBacking := append([]byte{0}, want...)
				enc := encBacking[1:]
				outBacking := make([]byte, v.enc.DecodedLen(len(enc))+1)
				out := outBacking[1:]
				di, do := decodeSIMDNEON(out, enc, v.url, !v.padded)
				tail, err := v.enc.decodeSlow(out[do:], enc[di:])
				if err != nil || do+tail != n || !bytes.Equal(out[:do+tail], src) {
					t.Fatalf("n=%d: unaligned decode: n=%d err=%v | 非对齐解码不一致", n, do+tail, err)
				}
			}
		})
	}
}

// TestNEONDispatch verifies the production dispatch installs the NEON kernels unless the
// force-scalar tag is set, and that the public API still round-trips. | TestNEONDispatch 验证生产
// 分派在未设置 force-scalar 标签时安装 NEON 内核，且公开 API 仍可往返。
func TestNEONDispatch(t *testing.T) {
	if forceScalar {
		if simdEncode != nil || simdDecode != nil {
			t.Fatal("force-scalar build installed SIMD kernels | force-scalar 构建不应安装 SIMD 内核")
		}
	} else if simdEncode == nil || simdDecode == nil {
		t.Fatal("production build did not install SIMD kernels | 生产构建未安装 SIMD 内核")
	}
	for _, v := range codecVariants() {
		for _, n := range []int{0, 1, 15, 16, 17, 63, 64, 1024, 65536} {
			src := randomBytes(n)
			enc := v.enc.EncodeToString(src)
			stdWant := make([]byte, v.std.EncodedLen(n))
			v.std.Encode(stdWant, src)
			if enc != string(stdWant) {
				t.Fatalf("%s n=%d: EncodeToString differs from stdlib | 编码与标准库不一致", v.name, n)
			}
			dec, err := v.enc.DecodeString(enc)
			if err != nil || !bytes.Equal(dec, src) {
				t.Fatalf("%s n=%d: DecodeString: err=%v | 解码不一致", v.name, n, err)
			}
		}
	}
}

// TestNEONNoWritePastDecodedLen verifies the 8+4 byte stores never touch bytes after the decoded
// length, even when the destination has spare capacity. | TestNEONNoWritePastDecodedLen 验证
// 8+4 字节存储在目标缓冲区有富余容量时也不会写到解码长度之后。
func TestNEONNoWritePastDecodedLen(t *testing.T) {
	for _, v := range codecVariants() {
		for _, n := range []int{16, 17, 32, 48, 64, 1024} {
			src := randomBytes(n)
			enc := make([]byte, v.enc.EncodedLen(n))
			v.enc.encodeScalar(enc, src)
			need := v.enc.DecodedLen(len(enc))
			buf := bytes.Repeat([]byte{0xA5}, need+32)
			ni, no := decodeSIMDNEON(buf, enc, v.url, !v.padded)
			tail, err := v.enc.decodeSlow(buf[no:], enc[ni:])
			if err != nil {
				t.Fatalf("n=%d: %v", n, err)
			}
			for i := no + tail; i < len(buf); i++ {
				if buf[i] != 0xA5 {
					t.Fatalf("n=%d: byte %d written past decoded length %d | 写入越过解码长度", n, i, no+tail)
				}
			}
		}
	}
}
