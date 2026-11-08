//go:build arm64 && !jsonx_std

package json

import (
	"math/rand"
	"testing"
)

// neonBodyDirty reports whether c terminates a fast string-body block scan. |
// neonBodyDirty 报告 c 是否会终止字符串体快速块扫描。
func neonBodyDirty(c byte) bool {
	return c == '"' || c == '\\' || c < 0x20 || c >= 0x80
}

// neonEscapeDirty reports whether c terminates a fast escape block scan. |
// neonEscapeDirty 报告 c 是否会终止转义快速块扫描。
func neonEscapeDirty(c byte, escapeHTML bool) bool {
	if neonBodyDirty(c) {
		return true
	}
	return escapeHTML && (c == '<' || c == '>' || c == '&')
}

// neonBodyRef is the block reference for scanStringBodyNEON: the start of the first 16-byte block
// containing a terminating byte, or the position after the last full block. |
// neonBodyRef 是 scanStringBodyNEON 的块级参考实现：返回首个含终止字节的 16 字节块起点，或最后一个
// 完整块之后的位置。
func neonBodyRef(data []byte, start int) (scan, needs int) {
	for i := start; len(data)-i >= 16; i += 16 {
		for j := 0; j < 16; j++ {
			if neonBodyDirty(data[i+j]) {
				return i, 1
			}
		}
	}
	return start + (len(data)-start)/16*16, 0
}

// neonEscapeRef is the block reference for stringNeedsEscapeNEON. |
// neonEscapeRef 是 stringNeedsEscapeNEON 的块级参考实现。
func neonEscapeRef(data []byte, escapeHTML bool) (scan, needs int) {
	for i := 0; len(data)-i >= 16; i += 16 {
		for j := 0; j < 16; j++ {
			if neonEscapeDirty(data[i+j], escapeHTML) {
				return i, 1
			}
		}
	}
	return len(data) / 16 * 16, 0
}

// neonDirtyPositions returns every position worth testing for a buffer of length n: none, the
// first and last byte, the middle, and both sides of every 16-byte block boundary. |
// neonDirtyPositions 返回长度为 n 的缓冲区值得测试的位置：无、首尾字节、中间，以及每个 16 字节块
// 边界两侧。
func neonDirtyPositions(n int) []int {
	if n == 0 {
		return []int{-1}
	}
	pos := []int{-1, 0, n / 2, n - 1}
	for i := 16; i < n; i += 16 {
		pos = append(pos, i-1, i)
	}
	return pos
}

// checkNEONBodyKernel verifies the raw body kernel against its reference for every start offset. |
// checkNEONBodyKernel 针对每个起始偏移校验字符串体原始内核与参考实现一致。
func checkNEONBodyKernel(t *testing.T, data []byte) {
	t.Helper()
	for start := 0; start <= len(data); start++ {
		wantScan, _ := neonBodyRef(data, start)
		gotScan := scanStringBodyNEON(data, start)
		if gotScan != wantScan {
			t.Fatalf("len=%d start=%d got=%d want=%d | 字符串体 NEON 内核不一致",
				len(data), start, gotScan, wantScan)
		}
	}
}

// checkNEONEscapeKernel verifies the raw escape kernel and its wrapper against the reference. |
// checkNEONEscapeKernel 校验转义原始内核及其包装与参考实现一致。
func checkNEONEscapeKernel(t *testing.T, data []byte) {
	t.Helper()
	s := string(data)
	for _, escapeHTML := range []bool{false, true} {
		wantScan, wantNeeds := neonEscapeRef(data, escapeHTML)
		gotScan, gotNeeds := stringNeedsEscapeNEON(s, escapeHTML)
		if gotScan != wantScan || gotNeeds != wantNeeds {
			t.Fatalf("len=%d html=%v got=(%d,%d) want=(%d,%d) | 转义 NEON 内核不一致",
				len(data), escapeHTML, gotScan, gotNeeds, wantScan, wantNeeds)
		}
		if got, want := jsonStringNeedsEscape(s, escapeHTML), jsonStringNeedsEscapeRef(s, escapeHTML); got != want {
			t.Fatalf("len=%d html=%v got=%v want=%v | 转义 NEON 包装不一致",
				len(data), escapeHTML, got, want)
		}
	}
}

// TestNEONKernelsBlockBoundaries pins the NEON block kernels at every length around 16-byte block
// boundaries with terminating bytes placed just before and after each boundary. |
// TestNEONKernelsBlockBoundaries 在每个 16 字节块边界前后放置终止字节，固定 NEON 块内核在各边界
// 长度上的行为。
func TestNEONKernelsBlockBoundaries(t *testing.T) {
	lengths := []int{0, 1, 2, 15, 16, 17, 30, 31, 32, 33, 47, 48, 63, 64, 65, 80, 96, 97, 127, 128, 129}
	dirty := []byte{'"', '\\', 0x00, 0x1f, 0x80, 0xff, '<', '>', '&'}
	for _, n := range lengths {
		for _, p := range neonDirtyPositions(n) {
			for _, d := range dirty {
				data := make([]byte, n)
				for i := range data {
					data[i] = 'a'
				}
				if p >= 0 {
					data[p] = d
				}
				checkNEONBodyKernel(t, data)
				checkNEONEscapeKernel(t, data)
			}
		}
	}
}

// TestNEONKernelsCleanBuffers pins the end position returned for buffers whose full blocks are all
// clean, including lengths that are and are not multiples of 16. |
// TestNEONKernelsCleanBuffers 固定全干净块缓冲区返回的结束位置，覆盖 16 的整数倍与非整数倍长度。
func TestNEONKernelsCleanBuffers(t *testing.T) {
	for n := 0; n <= 160; n++ {
		data := make([]byte, n)
		for i := range data {
			data[i] = 'a'
		}
		checkNEONBodyKernel(t, data)
		checkNEONEscapeKernel(t, data)
	}
}

// TestNEONKernelsRandomized cross-checks the NEON kernels against the reference on randomized
// buffers that mix control bytes, quotes, backslashes, non-ASCII and ordinary text. |
// TestNEONKernelsRandomized 在混合控制字节、引号、反斜杠、非 ASCII 与普通文本的随机缓冲区上，将 NEON
// 内核与参考实现交叉校验。
func TestNEONKernelsRandomized(t *testing.T) {
	rnd := rand.New(rand.NewSource(0x4E454F4E))
	for iter := 0; iter < 1000; iter++ {
		data := jsonScanData(rnd, rnd.Intn(256))
		checkNEONBodyKernel(t, data)
		checkNEONEscapeKernel(t, data)
	}
}
