//go:build !linux || (!amd64 && !arm64)

package uring

import "os"

// Engine is the non-Linux/no-arch stub. | Engine 是非 Linux/非目标架构的桩。
type Engine struct{}

// New returns ErrUnsupported on platforms without io_uring support. | New 在
// 不支持 io_uring 的平台上返回 ErrUnsupported。
func New(opts ...Option) (*Engine, error) { return nil, ErrUnsupported }

// Supported reports false on unsupported platforms. | Supported 在不支持的平台
// 返回 false。
func Supported() bool { return false }

// WriteAt reports ErrUnsupported. | WriteAt 返回 ErrUnsupported。
func (*Engine) WriteAt(f *os.File, parts [][]byte, off int64, syncData bool) error {
	return ErrUnsupported
}

// ReadAt reports ErrUnsupported. | ReadAt 返回 ErrUnsupported。
func (*Engine) ReadAt(f *os.File, dst []byte, off int64) (int, error) {
	return 0, ErrUnsupported
}

// Sync reports ErrUnsupported. | Sync 返回 ErrUnsupported。
func (*Engine) Sync(f *os.File) error { return ErrUnsupported }

// Close is a no-op. | Close 是空操作。
func (*Engine) Close() error { return nil }
