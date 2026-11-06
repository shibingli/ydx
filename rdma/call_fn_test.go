//go:build linux && rdma && (amd64 || arm64)

package rdma

import (
	"syscall"
	"testing"
	"unsafe"

	"github.com/ebitengine/purego"
)

// TestCallFnABI proves the purego-backed trampoline follows the platform C ABI
// for integer arguments, pointer arguments, pointer results and out-parameters.
// | TestCallFnABI 证明 purego 调用跳板在整数参数、指针参数、指针返回值与输出参数
// 上遵循平台 C ABI。
func TestCallFnABI(t *testing.T) {
	libc, err := purego.Dlopen("libc.so.6", purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		t.Fatalf("Dlopen(libc) = %v | 加载 libc 失败", err)
	}
	toupper, err := purego.Dlsym(libc, "toupper")
	if err != nil {
		t.Fatalf("Dlsym(toupper) = %v | 解析 toupper 失败", err)
	}
	if got := callFn(toupper, 'a', 0, 0); got != 'A' {
		t.Fatalf("callFn(toupper, 'a') = %#x, want 'A' | 整数参数调用错误", got)
	}
	memcmp, err := purego.Dlsym(libc, "memcmp")
	if err != nil {
		t.Fatalf("Dlsym(memcmp) = %v | 解析 memcmp 失败", err)
	}
	a := []byte("abcdef")
	b := []byte("abcxef")
	got := callFn(memcmp, uintptr(unsafe.Pointer(&a[0])), uintptr(unsafe.Pointer(&b[0])), uintptr(len(a)))
	if int32(got) >= 0 {
		t.Fatalf("callFn(memcmp) = %d, want negative | 指针参数调用错误", int32(got))
	}
	if string(a) != "abcdef" || string(b) != "abcxef" {
		t.Fatal("callFn(memcmp) modified its input | memcmp 修改了输入")
	}

	// purego clears the errno slot on Linux. Verify the control-plane helper
	// captures the thread-local errno from a NULL-returning libc call. | purego
	// 在 Linux 上会清零 errno 槽位。验证控制面辅助函数能从返回 NULL 的 libc 调用
	// 捕获线程局部 errno。
	fopen, err := purego.Dlsym(libc, "fopen")
	if err != nil {
		t.Fatalf("Dlsym(fopen) = %v", err)
	}
	errnoLoc, err := purego.Dlsym(libc, "__errno_location")
	if err != nil {
		t.Fatalf("Dlsym(__errno_location) = %v", err)
	}
	v := &verbsAPI{errnoLoc: errnoLoc}
	missing := []byte("/nonexistent-ydx-errno-test\x00")
	mode := []byte("r\x00")
	p, errno := v.callControl(fopen, uintptr(unsafe.Pointer(&missing[0])),
		uintptr(unsafe.Pointer(&mode[0])))
	if p != 0 || errno != int(syscall.ENOENT) {
		t.Fatalf("callControl(fopen) = %#x, errno %d, want 0, ENOENT", p, errno)
	}

	verbs, err := purego.Dlopen("libibverbs.so.1", purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		t.Logf("libibverbs unavailable, skipping provider call: %v | 无 libibverbs，跳过提供方调用", err)
		return
	}
	getList, err := purego.Dlsym(verbs, "ibv_get_device_list")
	if err != nil {
		t.Fatalf("Dlsym(ibv_get_device_list) = %v | 解析设备列表失败", err)
	}
	freeList, err := purego.Dlsym(verbs, "ibv_free_device_list")
	if err != nil {
		t.Fatalf("Dlsym(ibv_free_device_list) = %v | 解析设备列表释放失败", err)
	}
	var count int32
	list := callFn(getList, uintptr(unsafe.Pointer(&count)), 0, 0)
	if count < 0 {
		t.Fatalf("device count = %d | 设备数量非法", count)
	}
	if list != 0 {
		callFn(freeList, list, 0, 0)
	}
}
