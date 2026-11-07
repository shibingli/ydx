// Package uring implements an optional Linux io_uring IOEngine for ydx/wal.
// | Package uring 为 ydx/wal 实现可选的 Linux io_uring IOEngine。
//
// The engine uses raw io_uring_setup/io_uring_enter syscalls and mmap; it is
// pure Go and does not use cgo or liburing. It is built only on Linux
// amd64/arm64; every other platform gets a stub whose New returns
// ErrUnsupported. The default wal engine remains the portable synchronous
// engine, so users must opt in explicitly:
// | 引擎使用原始 io_uring_setup/io_uring_enter 系统调用与 mmap，纯 Go、不使用
// cgo 或 liburing。仅 Linux amd64/arm64 构建；其它平台得到 New 返回
// ErrUnsupported 的桩。wal 默认仍是可移植同步引擎，用户必须显式选择：
//
//	if !uring.Supported() {
//		return errors.New("io_uring unavailable")
//	}
//	engine, err := uring.New(uring.WithQueueDepth(256))
//	if err != nil {
//		return err
//	}
//	defer engine.Close()
//	w, err := wal.Open(dir, wal.WithIOEngine(engine))
//
// # Semantics | 语义
//
// WriteAt submits WRITEV and, when syncData is true, a linked FSYNC
// (IORING_FSYNC_DATASYNC). ReadAt submits READ and fills the caller buffer.
// Sync submits FSYNC. A single ring is protected by a mutex, so concurrent
// ReadAt calls are serialized; the WAL's single writer is the only WriteAt
// caller by contract. Close unmaps the rings and closes the ring fd. |
// WriteAt 提交 WRITEV，并在 syncData 为 true 时追加 FSYNC
// （IORING_FSYNC_DATASYNC）。ReadAt 提交 READ 并填充调用方缓冲；Sync 提交
// FSYNC。单 ring 由互斥量保护，因此并发 ReadAt 会串行化；按契约只有 WAL 单写
// 协程调用 WriteAt。Close 解除映射并关闭 ring fd。
//
// The package does not import the wal module: its methods satisfy wal.IOEngine
// structurally, so it can be built and tested independently. |
// 本包不 import wal 模块：其方法在结构上满足 wal.IOEngine，可独立构建与测试。
package uring
