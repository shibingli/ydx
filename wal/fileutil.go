package wal

import (
	"io"
	"os"
	"path/filepath"

	"github.com/shibingli/ydx/errs"
)

// writeFileAtomic writes data to a temporary sibling, synchronizes it, renames
// it over path, and synchronizes the directory. | writeFileAtomic 把数据写入同目录
// 临时文件，同步后 rename 覆盖目标，再同步目录。
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return errs.WrapDetail(err, ErrStorage, "create %s | 创建 %s 失败", tmp, tmp)
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if err := writeAll(f, data); err != nil {
		return errs.WrapDetail(err, ErrStorage, "write %s | 写入 %s 失败", tmp, tmp)
	}
	if err := f.Sync(); err != nil {
		return errs.WrapDetail(err, ErrStorage, "sync %s | 同步 %s 失败", tmp, tmp)
	}
	if err := f.Close(); err != nil {
		return errs.WrapDetail(err, ErrStorage, "close %s | 关闭 %s 失败", tmp, tmp)
	}
	if err := os.Rename(tmp, path); err != nil {
		return errs.WrapDetail(err, ErrStorage, "rename %s to %s | 把 %s 重命名为 %s 失败", tmp, path, tmp, path)
	}
	if err := syncDir(filepath.Dir(path)); err != nil {
		return errs.WrapDetail(err, ErrStorage, "sync directory of %s | 同步 %s 所在目录失败", path, path)
	}
	ok = true
	return nil
}

// writeAll writes every byte of p, handling short writes. | writeAll 写完全部字节并处理短写。
func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

// writeFullAt writes p at off, handling short writes and EINTR-style retries at
// the caller level. | writeFullAt 在 off 处写完全部字节并处理短写。
func writeFullAt(f *os.File, p []byte, off int64) error {
	for len(p) > 0 {
		n, err := f.WriteAt(p, off)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
		off += int64(n)
	}
	return nil
}

// readFullAt reads exactly len(dst) bytes at off. | readFullAt 在 off 处精确读取 len(dst) 字节。
func readFullAt(f *os.File, dst []byte, off int64) error {
	for len(dst) > 0 {
		n, err := readAtOnce(f, dst, off)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
		dst = dst[n:]
		off += int64(n)
	}
	return nil
}

// fileSize returns the logical size of f. | fileSize 返回 f 的逻辑大小。
func fileSize(f *os.File) (int64, error) {
	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// removeIfExists removes path, ignoring a missing file. | removeIfExists 删除 path，忽略文件不存在。
func removeIfExists(path string) error {
	err := os.Remove(path)
	if err == nil || os.IsNotExist(err) {
		return nil
	}
	return err
}

// ensureDir creates dir and any parent with mode when it does not exist. | ensureDir
// 在目录不存在时按 mode 创建 dir 及其父目录。
func ensureDir(dir string, mode os.FileMode) error {
	if err := os.MkdirAll(dir, mode); err != nil {
		return errs.WrapDetail(err, ErrStorage, "create directory %s | 创建目录 %s 失败", dir, dir)
	}
	return nil
}
