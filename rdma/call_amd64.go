//go:build linux && rdma && amd64

package rdma

// callFn invokes a C function pointer with up to three integer arguments and
// returns its integer result. The assembly stub follows the System V AMD64
// ABI and is used for the libibverbs hot-path operations, whose arguments and
// return value are all integers or pointers. | callFn 以至多三个整数参数调用
// C 函数指针并返回其整数结果。汇编桩遵循 System V AMD64 ABI，用于 libibverbs
// 热路径操作；这些操作的参数与返回值均为整数或指针。
func callFn(fn, a1, a2, a3 uintptr) uintptr
