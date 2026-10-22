//go:build amd64 && !goexperiment.simd && !b64x_std

package base64

import (
	"bytes"
	"errors"
	"testing"
)

var avx2Lengths = []int{
	0, 1, 2, 3, 15, 16, 17, 23, 24, 27, 28, 31, 32, 33, 47, 48, 49,
	63, 64, 95, 96, 97, 127, 128, 255, 256, 1023, 1024, 65535, 65536,
}

// TestAVX2AsmEncodeAllLengths compares the AVX2 prefix plus scalar tail with the scalar encoder.
// | TestAVX2AsmEncodeAllLengths 比较 AVX2 前缀加标量尾部与标量编码器。
func TestAVX2AsmEncodeAllLengths(t *testing.T) {
	if !hasAVX2() {
		t.Skip("AVX2 not available | AVX2 不可用")
	}
	for _, v := range codecVariants() {
		t.Run(v.name, func(t *testing.T) {
			for _, n := range avx2Lengths {
				src := randomBytes(n)
				want := make([]byte, v.enc.EncodedLen(n))
				v.enc.encodeScalar(want, src)
				got := make([]byte, v.enc.EncodedLen(n))
				ni, no := encodeSIMDAsm(got, src, v.url, v.padded, v.enc.pad)
				v.enc.encodeScalar(got[no:], src[ni:])
				if !bytes.Equal(got, want) {
					t.Fatalf("n=%d: AVX2 encoding differs | AVX2 编码不一致", n)
				}
			}
		})
	}
}

// TestAVX2AsmDecodeAllLengths compares the AVX2 prefix plus scalar tail with the scalar decoder.
// | TestAVX2AsmDecodeAllLengths 比较 AVX2 前缀加标量尾部与标量解码器。
func TestAVX2AsmDecodeAllLengths(t *testing.T) {
	if !hasAVX2() {
		t.Skip("AVX2 not available | AVX2 不可用")
	}
	for _, v := range codecVariants() {
		t.Run(v.name, func(t *testing.T) {
			for _, n := range avx2Lengths {
				src := randomBytes(n)
				enc := make([]byte, v.enc.EncodedLen(n))
				v.enc.encodeScalar(enc, src)
				got := make([]byte, v.enc.DecodedLen(len(enc)))
				ni, no := decodeSIMDAsm(got, enc, v.url, !v.padded)
				tail, err := v.enc.decodeSlow(got[no:], enc[ni:])
				if err != nil || no+tail != n || !bytes.Equal(got[:no+tail], src) {
					t.Fatalf("n=%d: AVX2 decode: n=%d err=%v | AVX2 解码不一致", n, no+tail, err)
				}
			}
		})
	}
}

// TestAVX2AsmDecodeInvalid replaces characters and compares the AVX2-prefix result with a fully
// scalar decode. | TestAVX2AsmDecodeInvalid 替换字符并比较 AVX2 前缀结果与完全标量解码。
func TestAVX2AsmDecodeInvalid(t *testing.T) {
	if !hasAVX2() {
		t.Skip("AVX2 not available | AVX2 不可用")
	}
	replacements := []byte{
		'A', 'Z', 'a', 'z', '0', '9', '+', '/', '-', '_',
		'!', '=', '\r', '\n', 0x00, 0xFF,
	}
	for _, v := range codecVariants() {
		t.Run(v.name, func(t *testing.T) {
			src := randomBytes(48)
			enc := make([]byte, v.enc.EncodedLen(len(src)))
			v.enc.encodeScalar(enc, src)
			for pos := 0; pos < len(enc); pos++ {
				for _, r := range replacements {
					mutated := append([]byte(nil), enc...)
					mutated[pos] = r
					ref := make([]byte, v.enc.DecodedLen(len(mutated)))
					refN, refErr := v.enc.decodeSlow(ref, mutated)
					got := make([]byte, v.enc.DecodedLen(len(mutated)))
					ni, no := decodeSIMDAsm(got, mutated, v.url, !v.padded)
					tail, err := v.enc.decodeSlow(got[no:], mutated[ni:])
					if (refErr == nil) != (err == nil) {
						t.Fatalf("pos=%d repl=%q: error mismatch | 错误语义不一致", pos, r)
					}
					if err != nil {
						if !errors.Is(err, ErrInvalidData) {
							t.Fatalf("pos=%d repl=%q: error not ErrInvalidData | 错误未包装 ErrInvalidData", pos, r)
						}
						continue
					}
					if no+tail != refN || !bytes.Equal(got[:no+tail], ref[:refN]) {
						t.Fatalf("pos=%d repl=%q: output mismatch | 输出不一致", pos, r)
					}
				}
			}
		})
	}
}

// TestAVX2AsmDispatch verifies the production dispatch installs AVX2 kernels when available and
// that the public API round-trips. | TestAVX2AsmDispatch 验证可用时安装 AVX2 内核，且公开 API 可往返。
func TestAVX2AsmDispatch(t *testing.T) {
	if forceScalar || !hasAVX2() {
		if simdEncode != nil || simdDecode != nil {
			t.Fatal("dispatch installed SIMD kernels without AVX2/force-scalar | 不应安装 SIMD 内核")
		}
		return
	}
	if simdEncode == nil || simdDecode == nil {
		t.Fatal("dispatch did not install AVX2 kernels | 未安装 AVX2 内核")
	}
	for _, v := range codecVariants() {
		for _, n := range []int{0, 1, 15, 16, 31, 32, 64, 1024, 65536} {
			src := randomBytes(n)
			enc := v.enc.EncodeToString(src)
			dec, err := v.enc.DecodeString(enc)
			if err != nil || !bytes.Equal(dec, src) {
				t.Fatalf("%s n=%d: round trip: err=%v | 往返失败", v.name, n, err)
			}
		}
	}
}

// TestAVX2AsmNoWritePastDecodedLen verifies the exact 24-byte stores stay within the decoded
// length. | TestAVX2AsmNoWritePastDecodedLen 验证精确 24 字节存储不越过解码长度。
func TestAVX2AsmNoWritePastDecodedLen(t *testing.T) {
	if !hasAVX2() {
		t.Skip("AVX2 not available | AVX2 不可用")
	}
	for _, v := range codecVariants() {
		for _, n := range []int{48, 96, 1024} {
			src := randomBytes(n)
			enc := make([]byte, v.enc.EncodedLen(n))
			v.enc.encodeScalar(enc, src)
			need := v.enc.DecodedLen(len(enc))
			buf := bytes.Repeat([]byte{0xA5}, need+32)
			ni, no := decodeSIMDAsm(buf, enc, v.url, !v.padded)
			tail, err := v.enc.decodeSlow(buf[no:], enc[ni:])
			if err != nil {
				t.Fatalf("n=%d: %v", n, err)
			}
			for i := no + tail; i < len(buf); i++ {
				if buf[i] != 0xA5 {
					t.Fatalf("n=%d: byte %d written past decoded length | 写入越过解码长度", n, i)
				}
			}
		}
	}
}
