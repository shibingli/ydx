//go:build windows

package wal

import (
	"io"
	"os"

	"golang.org/x/sys/windows"
)

// readAtOnce performs one positional read through ReadFile with an explicit
// offset. Go's os.File.ReadAt saves and restores the file pointer around every
// blocking read on Windows (two extra Seek calls); WAL files never rely on the
// file pointer, so that bookkeeping is skipped here. | readAtOnce 通过带显式偏移的
// ReadFile 执行一次位置读取。Windows 上 os.File.ReadAt 会在每次阻塞读前后保存
// 与恢复文件指针（多出两次 Seek）；WAL 文件从不依赖文件指针，因此这里跳过该记账。
func readAtOnce(f *os.File, dst []byte, off int64) (int, error) {
	if len(dst) == 0 {
		return 0, nil
	}
	var ol windows.Overlapped
	ol.Offset = uint32(off)
	ol.OffsetHigh = uint32(off >> 32)
	var n uint32
	err := windows.ReadFile(windows.Handle(f.Fd()), dst, &n, &ol)
	if err == windows.ERROR_HANDLE_EOF {
		err = io.EOF
	}
	// Mirror os.File.ReadAt: a short read reports EOF together with the bytes
	// read. | 与 os.File.ReadAt 保持一致：短读同时返回已读字节数与 EOF。
	if err == nil && int(n) < len(dst) {
		err = io.EOF
	}
	return int(n), err
}
