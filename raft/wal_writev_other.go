//go:build !darwin && !linux && !openbsd && !illumos

package raft

import (
	"os"

	"github.com/shibingli/ydx/errs"
)

// writevEnabled reports whether the WAL can issue vectored writes. This build
// falls back to the buffered single-write path. | writevEnabled 报告 WAL 是否
// 可以使用向量写。本构建回退到缓冲单次写路径。
const writevEnabled = false

// writevFile is never called on this platform. | writevFile 在本平台不会被调用。
func writevFile(*os.File, [][]byte) error {
	return errs.Detail(ErrUnsupported, "writev is not supported on this platform | 本平台不支持 writev")
}
