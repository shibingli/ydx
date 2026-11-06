//go:build linux && rdma && (amd64 || arm64)

package rdma

import "github.com/ebitengine/purego"

// callFn invokes a provider C function through purego's system-stack
// trampoline. A direct CALL from a goroutine stack is not safe for arbitrary
// provider code: it bypasses stack-growth checks and the goroutine has only a
// small guard-page margin, so a deeper provider stack would fault. | callFn 经
// purego 的系统栈跳板调用提供方 C 函数。从 goroutine 栈直接 CALL 对任意提供方
// 代码都不安全：它绕过栈增长检查，而 goroutine 只有很小的保护页余量，提供方使用
// 更深的栈就会触发故障。
func callFn(fn, a1, a2, a3 uintptr) uintptr {
	r, _, _ := purego.SyscallN(fn, a1, a2, a3)
	return r
}
