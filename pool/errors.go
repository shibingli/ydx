package pool

import (
	"fmt"

	"github.com/shibingli/ydx/errs"
)

// ErrPoolClosed is returned when work is submitted to a closed pool. | ErrPoolClosed
// 由向已关闭协程池提交任务时返回。
var ErrPoolClosed = errs.New("pool closed | 协程池已关闭")

// ErrQueueFull is returned by a nonblocking pool when every queue is full. | ErrQueueFull
// 由非阻塞模式下的协程池在全部分片队列已满时返回。
var ErrQueueFull = errs.New("pool queue full | 协程池队列已满")

// ErrTaskPanicked is the sentinel wrapped by PanicError. | ErrTaskPanicked 是 PanicError
// 包装的哨兵错误。
var ErrTaskPanicked = errs.New("task panicked | 任务发生 panic")

// ErrNilTask is returned when a nil function, handler or task is submitted. | ErrNilTask
// 由提交空函数、空处理器或空任务时返回。
var ErrNilTask = errs.New("nil task | 任务为空")

// PanicInfo describes a recovered panic to a panic handler. | PanicInfo 向 panic 处理器
// 描述一次被恢复的 panic。
type PanicInfo struct {
	// Value is the value passed to panic. | Value 是传给 panic 的值。
	Value any
	// Stack is the stack trace captured at recovery time. | Stack 是恢复时抓取的调用栈。
	Stack []byte
}

// PanicError is delivered to a waiting task or error handler when a task panics. |
// PanicError 在任务发生 panic 时交给等待中的任务或错误处理器。
type PanicError struct {
	// Value is the value passed to panic. | Value 是传给 panic 的值。
	Value any
	// Stack is the stack trace captured at recovery time. | Stack 是恢复时抓取的调用栈。
	Stack []byte
	// Worker is the worker id that recovered the panic. | Worker 是恢复该 panic 的 worker 编号。
	Worker int
}

// Error implements error. | Error 实现 error 接口。
func (e *PanicError) Error() string {
	return ErrTaskPanicked.Error() + ": " + safePanicValue(e.Value)
}

// Unwrap returns ErrTaskPanicked so errors.Is works. | Unwrap 返回 ErrTaskPanicked，
// 使 errors.Is 生效。
func (e *PanicError) Unwrap() error { return ErrTaskPanicked }

// safePanicValue formats a recovered panic value without letting a second panic escape. |
// safePanicValue 格式化被恢复的 panic 值，避免二次 panic 逃逸。
func safePanicValue(v any) (s string) {
	defer func() {
		if recover() != nil {
			s = "<panic while formatting panic value>"
		}
	}()
	return fmt.Sprint(v)
}
