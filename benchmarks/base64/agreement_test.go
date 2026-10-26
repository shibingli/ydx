package base64

import (
	"bytes"
	stdbase64 "encoding/base64"
	"testing"

	cwb64 "github.com/cloudwego/base64x"
	cmpb64 "github.com/cristalhq/base64"

	b64x "github.com/shibingli/ydx/base64"
)

// TestCodecsAgree proves that every compared encoder produces the same bytes and that every
// decoder recovers the original input, so the benchmarks measure equivalent work. |
// TestCodecsAgree 证明参与对比的编码器输出完全一致、解码器都能还原输入，从而保证基准测量的是
// 等价工作。
func TestCodecsAgree(t *testing.T) {
	for _, size := range []int{0, 1, 2, 3, 16, 255, 1 << 10, 64 << 10} {
		src := benchBuf(size)
		t.Run(stringSize(size), func(t *testing.T) {
			for _, tc := range []struct {
				name string
				ydx  *b64x.Encoding
				std  *stdbase64.Encoding
				cmp  *cmpb64.Encoding
				cw   cwb64.Encoding
			}{
				{name: "std", ydx: b64x.StdEncoding, std: stdbase64.StdEncoding, cmp: cmpb64.StdEncoding, cw: cwb64.StdEncoding},
				{name: "raw_url", ydx: b64x.RawURLEncoding, std: stdbase64.RawURLEncoding, cmp: cmpb64.RawURLEncoding, cw: cwb64.RawURLEncoding},
			} {
				t.Run(tc.name, func(t *testing.T) {
					ydxOut := make([]byte, tc.ydx.EncodedLen(size))
					tc.ydx.Encode(ydxOut, src)
					stdOut := make([]byte, tc.std.EncodedLen(size))
					tc.std.Encode(stdOut, src)
					cmpOut := make([]byte, tc.cmp.EncodedLen(size))
					tc.cmp.Encode(cmpOut, src)
					cwOut := make([]byte, tc.cw.EncodedLen(size))
					tc.cw.Encode(cwOut, src)
					if !bytes.Equal(ydxOut, stdOut) || !bytes.Equal(ydxOut, cmpOut) || !bytes.Equal(ydxOut, cwOut) {
						t.Fatalf("encoded bytes differ | 编码结果不一致")
					}

					dst := make([]byte, tc.ydx.DecodedLen(len(ydxOut)))
					n, err := tc.ydx.Decode(dst, ydxOut)
					if err != nil {
						t.Fatalf("ydx Decode: %v", err)
					}
					if !bytes.Equal(dst[:n], src) {
						t.Fatalf("ydx decoded bytes differ | ydx 解码结果不一致")
					}
					n, err = tc.cmp.Decode(dst, cmpOut)
					if err != nil {
						t.Fatalf("cristalhq Decode: %v", err)
					}
					if !bytes.Equal(dst[:n], src) {
						t.Fatalf("cristalhq decoded bytes differ | cristalhq 解码结果不一致")
					}
					n, err = tc.cw.Decode(dst, cwOut)
					if err != nil {
						t.Fatalf("cloudwego Decode: %v", err)
					}
					if !bytes.Equal(dst[:n], src) {
						t.Fatalf("cloudwego decoded bytes differ | cloudwego 解码结果不一致")
					}
				})
			}
		})
	}
}

// stringSize renders an integer without importing strconv into the benchmark file. |
// stringSize 在不把 strconv 引入基准文件的前提下渲染整数。
func stringSize(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
