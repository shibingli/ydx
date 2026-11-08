//go:build linux && arm64 && !b64x_std

package base64

import (
	"bytes"
	"os"
	"os/exec"
	"syscall"
	"testing"
)

// base64GuardEnv marks the child process that runs the NEON guard-page checks. |
// base64GuardEnv 标记运行 NEON 守护页检查的子进程。
const base64GuardEnv = "YDX_BASE64_NEON_GUARD_SCAN"

// TestNEONAsmDoesNotReadPastSlice places encoded and raw buffers immediately before an
// inaccessible guard page. Any block load past the slice end faults, so the parent runs the
// checks in a subprocess and turns that fault into a normal test failure. |
// TestNEONAsmDoesNotReadPastSlice 把编码与原始缓冲区紧邻不可访问的守护页放置。任何越过切片末尾的块
// 加载都会触发故障，因此父进程在子进程中运行检查，把故障转换为普通的测试失败。
func TestNEONAsmDoesNotReadPastSlice(t *testing.T) {
	if os.Getenv(base64GuardEnv) == "1" {
		runBase64GuardPageChecks(t)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestNEONAsmDoesNotReadPastSlice$", "-test.v")
	cmd.Env = append(os.Environ(), base64GuardEnv+"=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("base64 NEON kernel crossed the slice end (child: %v) | base64 NEON 内核越过切片末尾：\n%s", err, out)
	}
}

// runBase64GuardPageChecks maps two pages, protects the second one and runs the arm64 kernels on
// buffers that end exactly on the first page boundary. | runBase64GuardPageChecks 映射两页内存，保护
// 第二页，并在恰好结束于第一页边界的缓冲区上运行 arm64 内核。
func runBase64GuardPageChecks(t *testing.T) {
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
	for _, v := range codecVariants() {
		encDst := make([]byte, 4096)
		decDst := make([]byte, 4096)
		for n := 48; n <= 192; n++ {
			raw := randomBytes(n)
			// Encoding reads raw bytes that end on the guard page. |
			// 编码读取恰好结束于守护页的原始字节。
			src := region[page-n : page]
			copy(src, raw)
			dst := encDst[:v.enc.EncodedLen(n)]
			ni, no := encodeSIMDNEONAsm(dst, src, v.url, v.padded, v.enc.pad)
			v.enc.encodeScalar(dst[no:], src[ni:])
			want := make([]byte, v.enc.EncodedLen(n))
			v.enc.encodeScalar(want, raw)
			if !bytes.Equal(dst, want) {
				t.Fatalf("%s n=%d: assembly encode differs at the guard page | 守护页处汇编编码不一致", v.name, n)
			}
			// Decoding reads encoded characters that end on the guard page. |
			// 解码读取恰好结束于守护页的编码字符。
			m := len(want)
			encSrc := region[page-m : page]
			copy(encSrc, want)
			dec := decDst[:v.enc.DecodedLen(m)]
			ni, no = decodeSIMDNEONAsm(dec, encSrc, v.url, !v.padded)
			tail, err := v.enc.decodeSlow(dec[no:], encSrc[ni:], ni)
			if err != nil || no+tail != n || !bytes.Equal(dec[:no+tail], raw) {
				t.Fatalf("%s n=%d: assembly decode at the guard page: n=%d err=%v | 守护页处汇编解码不一致",
					v.name, n, no+tail, err)
			}
		}
	}
}
