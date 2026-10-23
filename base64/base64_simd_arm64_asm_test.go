//go:build arm64 && !b64x_std

package base64

import (
	"bytes"
	"errors"
	"testing"
)

var neonAsmLengths = []int{
	0, 1, 2, 3, 15, 16, 17, 23, 24, 47, 48, 49, 63, 64, 95, 96, 97,
	127, 128, 255, 256, 1023, 1024, 65535, 65536,
}

// TestNEONAsmEncodeAllLengths compares the assembly prefix plus scalar tail with the scalar
// encoder for every variant and block boundary. | TestNEONAsmEncodeAllLengths 对每个变体与块边界，
// 比较汇编前缀加标量尾部与标量编码器的结果。
func TestNEONAsmEncodeAllLengths(t *testing.T) {
	for _, v := range codecVariants() {
		t.Run(v.name, func(t *testing.T) {
			for _, n := range neonAsmLengths {
				src := randomBytes(n)
				want := make([]byte, v.enc.EncodedLen(n))
				v.enc.encodeScalar(want, src)
				got := make([]byte, v.enc.EncodedLen(n))
				ni, no := encodeSIMDNEONAsm(got, src, v.url, v.padded, v.enc.pad)
				v.enc.encodeScalar(got[no:], src[ni:])
				if !bytes.Equal(got, want) {
					t.Fatalf("n=%d: assembly encoding differs | 汇编编码不一致", n)
				}
			}
		})
	}
}

// TestNEONAsmDecodeAllLengths compares the assembly prefix plus scalar tail with the scalar
// decoder for every variant and block boundary. | TestNEONAsmDecodeAllLengths 对每个变体与块边界，
// 比较汇编前缀加标量尾部与标量解码器的结果。
func TestNEONAsmDecodeAllLengths(t *testing.T) {
	for _, v := range codecVariants() {
		t.Run(v.name, func(t *testing.T) {
			for _, n := range neonAsmLengths {
				src := randomBytes(n)
				enc := make([]byte, v.enc.EncodedLen(n))
				v.enc.encodeScalar(enc, src)
				got := make([]byte, v.enc.DecodedLen(len(enc)))
				ni, no := decodeSIMDNEONAsm(got, enc, v.url, !v.padded)
				tail, err := v.enc.decodeSlow(got[no:], enc[ni:])
				if err != nil || no+tail != n || !bytes.Equal(got[:no+tail], src) {
					t.Fatalf("n=%d: assembly decode: n=%d err=%v | 汇编解码不一致", n, no+tail, err)
				}
			}
		})
	}
}

// TestNEONAsmDecodeInvalid replaces characters with valid and invalid bytes and compares the
// assembly-prefix result with a fully scalar decode. | TestNEONAsmDecodeInvalid 把字符替换为合法与
// 非法字节，比较汇编前缀结果与完全标量解码。
func TestNEONAsmDecodeInvalid(t *testing.T) {
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
					ni, no := decodeSIMDNEONAsm(got, mutated, v.url, !v.padded)
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

// TestNEONAsmDispatch verifies the default arm64 build installs the assembly kernels unless the
// force-scalar tag is set, and that the public API round-trips. | TestNEONAsmDispatch 验证默认
// arm64 构建安装汇编内核（force-scalar 除外），且公开 API 可往返。
func TestNEONAsmDispatch(t *testing.T) {
	if forceScalar {
		if simdEncode != nil || simdDecode != nil {
			t.Fatal("force-scalar build installed SIMD kernels | force-scalar 构建不应安装 SIMD 内核")
		}
	} else if simdEncode == nil || simdDecode == nil {
		t.Fatal("default arm64 build did not install assembly kernels | 默认 arm64 构建未安装汇编内核")
	}
	for _, v := range codecVariants() {
		for _, n := range []int{0, 1, 15, 16, 47, 48, 63, 64, 1024, 65536} {
			src := randomBytes(n)
			enc := v.enc.EncodeToString(src)
			dec, err := v.enc.DecodeString(enc)
			if err != nil || !bytes.Equal(dec, src) {
				t.Fatalf("%s n=%d: round trip: err=%v | 往返失败", v.name, n, err)
			}
		}
	}
}

// TestNEONAsmNoWritePastDecodedLen verifies the assembly store never touches bytes after the
// decoded length when the destination has spare capacity. | TestNEONAsmNoWritePastDecodedLen 验证
// 目标缓冲区有富余容量时汇编存储不会写到解码长度之后。
func TestNEONAsmNoWritePastDecodedLen(t *testing.T) {
	for _, v := range codecVariants() {
		for _, n := range []int{48, 96, 1024} {
			src := randomBytes(n)
			enc := make([]byte, v.enc.EncodedLen(n))
			v.enc.encodeScalar(enc, src)
			need := v.enc.DecodedLen(len(enc))
			buf := bytes.Repeat([]byte{0xA5}, need+32)
			ni, no := decodeSIMDNEONAsm(buf, enc, v.url, !v.padded)
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
