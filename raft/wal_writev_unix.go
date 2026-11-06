//go:build darwin || linux || openbsd || illumos

package raft

import (
	"os"

	"github.com/shibingli/ydx/errs"
	"golang.org/x/sys/unix"
)

// writevEnabled reports whether the WAL can issue vectored writes. |
// writevEnabled 报告 WAL 是否可以使用向量写。
const writevEnabled = true

// writevFile writes parts with writev, retrying interrupted and short writes.
// It is used only for regular WAL files. | writevFile 使用 writev 写入分段，并重试
// 被中断与短写。仅用于普通 WAL 文件。
func writevFile(f *os.File, parts [][]byte) error {
	for len(parts) > 0 {
		n, err := unix.Writev(int(f.Fd()), parts)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return errs.Wrap(err, ErrStorage)
		}
		if n <= 0 {
			return errs.Detail(ErrStorage, "WAL writev wrote %d bytes | WAL 向量写写入 %d 字节", n, n)
		}
		for n > 0 {
			if n >= len(parts[0]) {
				n -= len(parts[0])
				parts = parts[1:]
				if len(parts) == 0 {
					return nil
				}
				continue
			}
			parts[0] = parts[0][n:]
			n = 0
		}
	}
	return nil
}
