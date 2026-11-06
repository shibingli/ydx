//go:build !windows

package wal

import "os"

// readAtOnce performs one positional read. | readAtOnce 执行一次位置读取。
func readAtOnce(f *os.File, dst []byte, off int64) (int, error) {
	return f.ReadAt(dst, off)
}
