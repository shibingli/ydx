package uring

import "github.com/shibingli/ydx/errs"

// Sentinel errors returned by the io_uring engine. | io_uring 引擎返回的哨兵错误。
var (
	// ErrUnsupported reports a platform or kernel without usable io_uring. |
	// ErrUnsupported 表示平台或内核不支持可用的 io_uring。
	ErrUnsupported = errs.New("uring: io_uring is not supported | uring：不支持 io_uring")
	// ErrSetup reports a failed ring setup or mmap. | ErrSetup 表示 ring 初始化或
	// mmap 失败。
	ErrSetup = errs.New("uring: io_uring setup failed | uring：io_uring 初始化失败")
	// ErrClosed reports an operation after Close. | ErrClosed 表示 Close 之后的操作。
	ErrClosed = errs.New("uring: engine is closed | uring：引擎已关闭")
	// ErrIO reports a submission or completion failure. | ErrIO 表示提交或完成失败。
	ErrIO = errs.New("uring: I/O submission failed | uring：I/O 提交失败")
)
