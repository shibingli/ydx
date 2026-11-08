//go:build linux && arm64 && !jsonx_std

package json

import (
	"os"
	"os/exec"
	"syscall"
	"testing"
	"unsafe"
)

// neonGuardEnv marks the child process that runs the guard-page checks. |
// neonGuardEnv 标记运行守护页检查的子进程。
const neonGuardEnv = "YDX_JSON_NEON_GUARD_SCAN"

// TestNEONKernelsDoNotReadPastSlice places clean buffers immediately before an inaccessible guard
// page. Any 16-byte block load past the slice end faults, so the parent process runs the checks in
// a subprocess to turn that fault into a normal test failure. |
// TestNEONKernelsDoNotReadPastSlice 把干净缓冲区紧邻不可访问的守护页放置。任何越过切片末尾的
// 16 字节块加载都会触发故障，因此父进程在子进程中运行检查，把故障转换为普通的测试失败。
func TestNEONKernelsDoNotReadPastSlice(t *testing.T) {
	if os.Getenv(neonGuardEnv) == "1" {
		runNEONGuardPageChecks(t)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestNEONKernelsDoNotReadPastSlice$", "-test.v")
	cmd.Env = append(os.Environ(), neonGuardEnv+"=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("NEON scan crossed the slice end (child: %v) | NEON 扫描越过切片末尾：\n%s", err, out)
	}
}

// runNEONGuardPageChecks maps two pages, protects the second one and scans buffers that end on the
// first page boundary. | runNEONGuardPageChecks 映射两页内存，保护第二页，并扫描恰好结束于第一页
// 边界的缓冲区。
func runNEONGuardPageChecks(t *testing.T) {
	t.Helper()
	page := os.Getpagesize()
	region, err := syscall.Mmap(-1, 0, 2*page, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
	if err != nil {
		t.Fatalf("mmap: %v", err)
	}
	defer syscall.Munmap(region)
	if err := syscall.Mprotect(region[page:], syscall.PROT_NONE); err != nil {
		t.Fatalf("mprotect: %v", err)
	}
	for n := 16; n <= 96; n++ {
		data := region[page-n : page]
		for i := range data {
			data[i] = 'a'
		}
		s := unsafe.String(&data[0], len(data))
		for _, start := range []int{0, 1, n - 16} {
			if got, want := scanStringBodyNEON(data, start), start+(n-start)/16*16; got != want {
				t.Fatalf("len=%d start=%d got=%d want=%d | 字符串体 NEON 扫描越过末尾", n, start, got, want)
			}
		}
		if scan, needs := stringNeedsEscapeNEON(s, false); needs != 0 || scan != n/16*16 {
			t.Fatalf("len=%d plain got=(%d,%d) | 转义 NEON 扫描越过末尾", n, scan, needs)
		}
		if scan, needs := stringNeedsEscapeNEON(s, true); needs != 0 || scan != n/16*16 {
			t.Fatalf("len=%d html got=(%d,%d) | HTML 转义 NEON 扫描越过末尾", n, scan, needs)
		}
		if _, slow, _ := scanStringBody(data, 0); !slow {
			t.Fatalf("len=%d clean buffer without quote must be slow | 无引号的干净缓冲区必须走慢路径", n)
		}
		if jsonStringNeedsEscape(s, false) || jsonStringNeedsEscape(s, true) {
			t.Fatalf("len=%d clean buffer must not need escaping | 干净缓冲区不应需要转义", n)
		}
		for _, c := range []byte{'"', '<'} {
			data[n-1] = c
			wantScan := (n - 1) / 16 * 16
			wantNeeds := 0
			if n%16 == 0 {
				wantNeeds = 1
			}
			html := c == '<'
			scan, needs := stringNeedsEscapeNEON(s, html)
			if needs != wantNeeds || scan != wantScan {
				t.Fatalf("len=%d byte=%q got=(%d,%d) want=(%d,%d) | 末尾终止字节定位不一致",
					n, c, scan, needs, wantScan, wantNeeds)
			}
			if !jsonStringNeedsEscape(s, html) {
				t.Fatalf("len=%d byte=%q wrapper must report the terminating byte | 包装必须报告终止字节", n, c)
			}
			data[n-1] = 'a'
		}
	}
	for n := 16; n <= 96; n++ {
		data := region[page-n : page]
		fill := func(c byte) {
			for i := range data {
				data[i] = c
			}
		}
		// skipSpaceNEON and scanDigitsNEON scan a clean run to the slice end. |
		// skipSpaceNEON 与 scanDigitsNEON 把干净连续段扫描到切片末尾。
		fill(' ')
		for _, start := range []int{0, 1, n - 16} {
			if got, want := skipSpaceNEON(data, start), start+(n-start)/16*16; got != want {
				t.Fatalf("space len=%d start=%d got=%d want=%d | 空白 NEON 扫描越过末尾", n, start, got, want)
			}
		}
		if got := skipSpaceRun(data, 0); got != n {
			t.Fatalf("space len=%d wrapper got=%d want=%d | 空白包装越过末尾", n, got, n)
		}
		fill('7')
		for _, start := range []int{0, 1, n - 16} {
			if got, want := scanDigitsNEON(data, start), start+(n-start)/16*16; got != want {
				t.Fatalf("digits len=%d start=%d got=%d want=%d | 数字 NEON 扫描越过末尾", n, start, got, want)
			}
		}
		if got := scanDigits(data, 0); got != n {
			t.Fatalf("digits len=%d wrapper got=%d want=%d | 数字包装越过末尾", n, got, n)
		}
		// Both compact scanners allow ordinary text through to the slice end. |
		// 两个压缩扫描器都允许普通文本一直到达切片末尾。
		fill('a')
		for _, start := range []int{0, 1, n - 16} {
			if got, want := scanCompactOutsideNEON(data, start), start+(n-start)/16*16; got != want {
				t.Fatalf("compact-outside len=%d start=%d got=%d want=%d | 压缩外部 NEON 扫描越过末尾", n, start, got, want)
			}
			for _, escapeHTML := range []bool{false, true} {
				if got, want := scanCompactInsideNEON(data, start, escapeHTML), start+(n-start)/16*16; got != want {
					t.Fatalf("compact-inside len=%d start=%d html=%v got=%d want=%d | 压缩内部 NEON 扫描越过末尾",
						n, start, escapeHTML, got, want)
				}
			}
		}
		if got := scanCompactOutsideRun(data, 0); got != n {
			t.Fatalf("compact-outside len=%d wrapper got=%d want=%d | 压缩外部包装越过末尾", n, got, n)
		}
		for _, escapeHTML := range []bool{false, true} {
			if got := scanCompactInsideRun(data, 0, escapeHTML); got != n {
				t.Fatalf("compact-inside len=%d html=%v wrapper got=%d want=%d | 压缩内部包装越过末尾",
					n, escapeHTML, got, n)
			}
		}
		if got := scanUnescapedASCII(data, 0); got != n {
			t.Fatalf("unescaped len=%d wrapper got=%d want=%d | 未转义 ASCII 包装越过末尾", n, got, n)
		}
	}
}
