// Package afs provides a unified filesystem facade over afero: the same API works
// against OS directories (OsFs / BasePathFs), in-memory filesystems (MemMapFs) and
// read-only embedded assets (io/fs, such as go:embed), which makes testing and
// virtualization straightforward. | Package afs 在 afero 之上提供统一文件系统门面：
// 同一套 API 可在操作系统目录（OsFs / BasePathFs）、内存（MemMapFs）与只读内嵌资产
// （io/fs，如 go:embed）之间无缝切换，便于测试与虚拟化。
//
// Path convention: paths are interpreted by the underlying afero.Fs. The OS backend uses
// the platform separator; io/fs backends use "/" and reject leading slashes. | 路径约定：
// 路径一律交给底层 afero.Fs 解释——操作系统后端使用 OS 分隔符，io/fs 语义的内嵌后端
// 使用 "/" 且不接受前导斜杠。
//
// Typical usage | 典型用法：
//
//	fsys := afs.NewOs("/srv/app")
//	embedFS := afs.NewEmbed(embedded)
//	b, err := afs.ReadFile(fsys, "config.yaml")
//
// The import path is github.com/shibingli/ydx/afs while the package identifier remains
// afs, so existing yd call sites only change their import path. | 导入路径是
// github.com/shibingli/ydx/afs，包标识符仍是 afs，因此 yd 既有调用点只需替换导入路径。
package afs
