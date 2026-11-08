//go:build arm64 && !jsonx_std

package json

import (
	"math/rand"
	"testing"
)

// neonRunBlockRef is the block reference for the arm64 run kernels: the start of the first
// 16-byte block containing a byte for which dirty reports true, or the position after the last
// full block. | neonRunBlockRef 是 arm64 连续段内核的块级参考实现：返回首个含 dirty 判定为真
// 的字节的 16 字节块起点，或最后一个完整块之后的位置。
func neonRunBlockRef(data []byte, start int, dirty func(byte) bool) int {
	i := start
	for len(data)-i >= 16 {
		for j := 0; j < 16; j++ {
			if dirty(data[i+j]) {
				return i
			}
		}
		i += 16
	}
	return i
}

// neonRunDirtyPositions returns every position worth testing for a buffer of length n: none,
// the first and last byte, the middle, and both sides of every 16-byte block boundary. |
// neonRunDirtyPositions 返回长度为 n 的缓冲区值得测试的位置：无、首尾字节、中间，以及每个
// 16 字节块边界两侧。
func neonRunDirtyPositions(n int) []int {
	if n == 0 {
		return []int{-1}
	}
	pos := []int{-1, 0, n / 2, n - 1}
	for i := 16; i < n; i += 16 {
		pos = append(pos, i-1, i)
	}
	return pos
}

// neonRunCase describes one run kernel, its clean filler byte, and its block-level stop set. |
// neonRunCase 描述一个连续段内核、其干净填充字节与块级停止集合。
type neonRunCase struct {
	name   string
	clean  byte
	dirty  func(byte) bool
	kernel func([]byte, int) int
}

// neonRunCases builds the kernel cases. The compact-inside case is built separately because its
// kernel also takes the escapeHTML flag. | neonRunCases 构造内核用例。压缩内部用例单独构造，
// 因为其内核还接收 escapeHTML 参数。
func neonRunCases() []neonRunCase {
	isDigit := func(c byte) bool { return c >= '0' && c <= '9' }
	isCompactStop := func(c byte) bool { return c == '"' || isJSONSpaceRef(c) }
	return []neonRunCase{
		{
			name:   "space",
			clean:  ' ',
			dirty:  func(c byte) bool { return !isJSONSpaceRef(c) },
			kernel: skipSpaceNEON,
		},
		{
			name:   "digits",
			clean:  '7',
			dirty:  func(c byte) bool { return !isDigit(c) },
			kernel: scanDigitsNEON,
		},
		{
			name:   "compact-outside",
			clean:  'a',
			dirty:  isCompactStop,
			kernel: scanCompactOutsideNEON,
		},
	}
}

// checkNEONRunKernel verifies one raw kernel against its block reference for every start offset.
// | checkNEONRunKernel 针对每个起始偏移校验一个原始内核与块级参考实现一致。
func checkNEONRunKernel(t *testing.T, name string, data []byte, dirty func(byte) bool, kernel func([]byte, int) int) {
	t.Helper()
	for start := 0; start <= len(data); start++ {
		want := neonRunBlockRef(data, start, dirty)
		got := kernel(data, start)
		if got != want {
			t.Fatalf("%s len=%d start=%d got=%d want=%d | arm64 连续段 NEON 内核不一致",
				name, len(data), start, got, want)
		}
	}
}

// TestNEONRunKernelsBlockBoundaries pins the whitespace, digit and compact-outside NEON kernels at
// every length around 16-byte block boundaries with a stop byte placed on each side. |
// TestNEONRunKernelsBlockBoundaries 在每个 16 字节块边界前后放置停止字节，固定空白、数字与压缩
// 外部 NEON 内核在各边界长度上的行为。
func TestNEONRunKernelsBlockBoundaries(t *testing.T) {
	lengths := []int{0, 1, 2, 15, 16, 17, 30, 31, 32, 33, 47, 48, 63, 64, 65, 80, 96, 97, 127, 128, 129}
	dirtyBytes := []byte{'x', 0x00, 0x1f, 0x7f, 0x80, 0xff, '"', ' ', '\t', '\n', '\r', '/', ':', '0', '9'}
	for _, tc := range neonRunCases() {
		for _, n := range lengths {
			for _, p := range neonRunDirtyPositions(n) {
				for _, d := range dirtyBytes {
					data := make([]byte, n)
					for i := range data {
						data[i] = tc.clean
					}
					if p >= 0 {
						data[p] = d
					}
					checkNEONRunKernel(t, tc.name, data, tc.dirty, tc.kernel)
				}
			}
		}
	}
}

// TestNEONCompactInsideKernelBlockBoundaries pins the raw compact-inside kernel for both
// escapeHTML modes, including bytes that are special in only one mode. |
// TestNEONCompactInsideKernelBlockBoundaries 固定两种 escapeHTML 模式下的压缩内部原始内核，覆盖仅在
// 其中一种模式下特殊的字节。
func TestNEONCompactInsideKernelBlockBoundaries(t *testing.T) {
	lengths := []int{0, 1, 2, 15, 16, 17, 30, 31, 32, 33, 47, 48, 63, 64, 65, 80, 96, 97, 127, 128, 129}
	dirtyBytes := []byte{'"', '\\', 0x00, 0x1f, 0x20, 0x7f, 0x80, 0xff, '<', '>', '&', 0xe2, 'a', ' '}
	for _, escapeHTML := range []bool{false, true} {
		dirty := func(c byte) bool {
			if c == '"' || c == '\\' || c < 0x20 {
				return true
			}
			return escapeHTML && (c == '<' || c == '>' || c == '&' || c == 0xE2)
		}
		kernel := func(data []byte, start int) int {
			return scanCompactInsideNEON(data, start, escapeHTML)
		}
		for _, n := range lengths {
			for _, p := range neonRunDirtyPositions(n) {
				for _, d := range dirtyBytes {
					data := make([]byte, n)
					for i := range data {
						data[i] = 'a'
					}
					if p >= 0 {
						data[p] = d
					}
					checkNEONRunKernel(t, "compact-inside", data, dirty, kernel)
				}
			}
		}
	}
}

// TestNEONRunWrappersExactPositions verifies the arm64 wrappers against the portable scalar
// references for every start offset, so the block kernels plus scalar tails return exact stop
// positions. | TestNEONRunWrappersExactPositions 针对每个起始偏移校验 arm64 包装与可移植标量参考
// 实现一致，确保块内核加标量尾部返回精确停止位置。
func TestNEONRunWrappersExactPositions(t *testing.T) {
	rnd := rand.New(rand.NewSource(0x52554E53))
	for _, n := range []int{0, 1, 15, 16, 17, 31, 32, 33, 47, 48, 63, 64, 65, 96, 97, 128, 160} {
		for _, data := range [][]byte{
			makeCleanRun(n, ' '),
			makeCleanRun(n, '7'),
			makeCleanRun(n, 'a'),
			jsonScanData(rnd, n),
		} {
			for start := 0; start <= len(data); start++ {
				if got, want := skipSpaceRun(data, start), skipSpaceRunRef(data, start); got != want {
					t.Fatalf("space len=%d start=%d got=%d want=%d | 空白包装不一致", len(data), start, got, want)
				}
				if got, want := scanDigits(data, start), scanDigitsRef(data, start); got != want {
					t.Fatalf("digits len=%d start=%d got=%d want=%d | 数字包装不一致", len(data), start, got, want)
				}
				if got, want := scanCompactOutsideRun(data, start), scanCompactOutsideRunRef(data, start); got != want {
					t.Fatalf("compact-outside len=%d start=%d got=%d want=%d | 压缩外部包装不一致", len(data), start, got, want)
				}
				for _, escapeHTML := range []bool{false, true} {
					if got, want := scanCompactInsideRun(data, start, escapeHTML), scanCompactInsideRunRef(data, start, escapeHTML); got != want {
						t.Fatalf("compact-inside len=%d start=%d html=%v got=%d want=%d | 压缩内部包装不一致",
							len(data), start, escapeHTML, got, want)
					}
				}
				if got, want := scanUnescapedASCII(data, start), scanUnescapedASCIIRef(data, start); got != want {
					t.Fatalf("unescaped len=%d start=%d got=%d want=%d | 未转义 ASCII 包装不一致", len(data), start, got, want)
				}
			}
		}
	}
}

// makeCleanRun returns a buffer of n copies of c. | makeCleanRun 返回由 n 个 c 组成的缓冲区。
func makeCleanRun(n int, c byte) []byte {
	data := make([]byte, n)
	for i := range data {
		data[i] = c
	}
	return data
}

// TestNEONRunWrappersAllBytes verifies each wrapper over every possible byte value, including the
// 0x80 and 0xE2 boundaries that distinguish the compact-inside modes. |
// TestNEONRunWrappersAllBytes 在全部字节值上校验各包装，覆盖区分压缩内部模式的 0x80 与 0xE2 边界。
func TestNEONRunWrappersAllBytes(t *testing.T) {
	data := make([]byte, 256*2)
	for i := 0; i < 256; i++ {
		data[i] = byte(i)
		data[256+i] = byte(255 - i)
	}
	for start := 0; start <= len(data); start++ {
		if got, want := skipSpaceRun(data, start), skipSpaceRunRef(data, start); got != want {
			t.Fatalf("space start=%d got=%d want=%d | 空白包装不一致", start, got, want)
		}
		if got, want := scanDigits(data, start), scanDigitsRef(data, start); got != want {
			t.Fatalf("digits start=%d got=%d want=%d | 数字包装不一致", start, got, want)
		}
		if got, want := scanCompactOutsideRun(data, start), scanCompactOutsideRunRef(data, start); got != want {
			t.Fatalf("compact-outside start=%d got=%d want=%d | 压缩外部包装不一致", start, got, want)
		}
		for _, escapeHTML := range []bool{false, true} {
			if got, want := scanCompactInsideRun(data, start, escapeHTML), scanCompactInsideRunRef(data, start, escapeHTML); got != want {
				t.Fatalf("compact-inside start=%d html=%v got=%d want=%d | 压缩内部包装不一致",
					start, escapeHTML, got, want)
			}
		}
		if got, want := scanUnescapedASCII(data, start), scanUnescapedASCIIRef(data, start); got != want {
			t.Fatalf("unescaped start=%d got=%d want=%d | 未转义 ASCII 包装不一致", start, got, want)
		}
	}
}
