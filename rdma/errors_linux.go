//go:build linux && rdma && (amd64 || arm64)

package rdma

import (
	"syscall"

	"github.com/shibingli/ydx/errs"
)

// errnoOf converts a raw errno value into an error. | errnoOf 将原始 errno
// 值转换为错误。
func errnoOf(rc int) error { return syscall.Errno(rc) }

// errnoError converts one positive errno returned by libibverbs into a
// sentinel error. | errnoError 将 libibverbs 返回的正 errno 转换为哨兵错误。
func errnoError(op string, rc int) error {
	errno := syscall.Errno(rc)
	switch errno {
	case syscall.ENOMEM, syscall.EAGAIN:
		return errs.WrapDetail(errno, ErrQueueFull, "%s | %s", op, op)
	case syscall.EINVAL, syscall.ENOTSUP:
		return errs.WrapDetail(errno, ErrInvalidConfig, "%s | %s", op, op)
	default:
		return errs.WrapDetail(errno, ErrDevice, "%s | %s", op, op)
	}
}
