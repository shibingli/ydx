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
	return writevLoop(parts, func(vec [][]byte) (int, error) {
		return unix.Writev(int(f.Fd()), vec)
	})
}

// writevLoop drives one complete vectored write. A signal can end a regular-file
// writev with a short count, including a count that leaves only zero-length
// parts (the WAL encoder emits an empty part for an entry with no data). An
// all-empty remainder means every byte was already written, so it must return
// success instead of issuing a zero-length writev, whose legitimate zero return
// would otherwise be mistaken for a storage failure. | writevLoop 驱动一次完整的
// 向量写。信号可能让普通文件 writev 返回短写，甚至恰好只剩零长度分段（WAL 编码器
// 会为空 Data 日志项生成空分段）。剩余分段全为空表示所有字节已写完，必须直接成功
// 返回，而不是再发一次零长度 writev；后者合法返回零会被误判为存储失败。
func writevLoop(parts [][]byte, write func([][]byte) (int, error)) error {
	for {
		for len(parts) > 0 && len(parts[0]) == 0 {
			parts = parts[1:]
		}
		if len(parts) == 0 {
			return nil
		}
		n, err := write(parts)
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
}
