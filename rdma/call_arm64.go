//go:build linux && rdma && arm64

package rdma

// callFn invokes a C function pointer with up to three integer arguments and
// returns its integer result. The assembly stub follows the AAPCS64 ABI and is
// used for the libibverbs hot-path operations. | callFn 以至多三个整数参数调用
// C 函数指针并返回其整数结果。汇编桩遵循 AAPCS64 ABI，用于 libibverbs 热路径
// 操作。
func callFn(fn, a1, a2, a3 uintptr) uintptr
