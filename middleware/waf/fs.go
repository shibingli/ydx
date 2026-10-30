package waf

import (
	"io/fs"
	"strings"
)

// slashFS adapts an fs.FS to the separator style Coraza's SecLang parser produces on Windows.
// filepath.Join turns "rules/main.conf" into "rules\main.conf", but io/fs requires forward
// slashes, so embedded rule trees fail to open without this translation. | slashFS 让 fs.FS
// 适配 Coraza SecLang 解析器在 Windows 上产生的路径风格。filepath.Join 会把
// "rules/main.conf" 变成 "rules\main.conf"，而 io/fs 要求正斜杠，缺少这层转换时嵌入式规则树
// 无法打开。
type slashFS struct {
	fsys fs.FS
}

// Open implements fs.FS. | Open 实现 fs.FS。
func (s slashFS) Open(name string) (fs.File, error) {
	return s.fsys.Open(toSlashPath(name))
}

// ReadFile implements fs.ReadFileFS. | ReadFile 实现 fs.ReadFileFS。
func (s slashFS) ReadFile(name string) ([]byte, error) {
	if reader, ok := s.fsys.(fs.ReadFileFS); ok {
		return reader.ReadFile(toSlashPath(name))
	}
	return fs.ReadFile(s.fsys, toSlashPath(name))
}

// ReadDir implements fs.ReadDirFS. | ReadDir 实现 fs.ReadDirFS。
func (s slashFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if reader, ok := s.fsys.(fs.ReadDirFS); ok {
		return reader.ReadDir(toSlashPath(name))
	}
	return fs.ReadDir(s.fsys, toSlashPath(name))
}

// Glob implements fs.GlobFS. | Glob 实现 fs.GlobFS。
func (s slashFS) Glob(pattern string) ([]string, error) {
	if globber, ok := s.fsys.(fs.GlobFS); ok {
		return globber.Glob(toSlashPath(pattern))
	}
	return fs.Glob(s.fsys, toSlashPath(pattern))
}

// toSlashPath converts the OS separators produced by filepath.Join back to io/fs form. |
// toSlashPath 把 filepath.Join 产生的操作系统分隔符转回 io/fs 形式。
func toSlashPath(name string) string {
	if strings.IndexByte(name, '\\') < 0 {
		return name
	}
	return strings.ReplaceAll(name, "\\", "/")
}
