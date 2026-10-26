# afs — 统一文件系统门面

`github.com/shibingli/ydx/afs` 在 [afero](https://github.com/spf13/afero) 之上提供统一文件
系统门面：同一套 API 可在操作系统目录、内存文件系统与只读内嵌资产（`go:embed`）之间
切换，便于测试、热重载与虚拟化。

| 项 | 值 |
|---|---|
| 模块路径 | `github.com/shibingli/ydx/afs` |
| 包名 | `afs` |
| Go 版本 | 1.27.3 |
| 许可证 | Apache-2.0 |

## 功能

- `NewOS(root)`：操作系统文件系统；非空 `root` 会解析为绝对目录并约束所有路径。
- `NewMem()`：独立的内存文件系统，用于测试与虚拟化。
- `NewEmbed(f)`：把 `io/fs`（典型为 `embed.FS`）适配为只读文件系统。
- `Overlay(base, upper)`：写时复制文件系统，`upper` 覆盖 `base`。
- `Sub(parent, dir)`：以 `dir` 为根的只读内嵌子树。
- `IOFSTree(fsys)`：取回内嵌文件系统背后的 `io/fs` 视图。
- `CopyDir`、`Walk`、`Exists`、`Sha256File`、`WriteFileIfChanged`、`NewHTTPFileSystem`、
  `HideShadowedMin` 等辅助函数。

## 特性

- **根目录约束**：`NewOS` 的非空 root 会拒绝词法 `..` 逃逸；根内符号链接仍按操作系统
  行为跟随。
- **嵌入式只读**：`NewEmbed` 的写操作返回包装了 `fs.ErrPermission` 的 `*fs.PathError`；
  路径必须满足 `fs.ValidPath`（`/` 分隔、无前导斜杠）。
- **跨平台遍历**：`Walk` 的回调路径始终以 `/` 分隔，Windows 下也不会注入反斜杠；io/fs
  后端走 `fs.WalkDir`，其它后端使用同语义的斜杠遍历。
- **原子写**：`WriteFileIfChanged` 内容相同时不触碰文件（保留 ModTime）；内容变化时先写
  同目录临时文件再改名覆盖，避免截断目标、替换而不是跟随符号链接。
- **深合并/隐藏**：`Overlay` 与 `HideShadowedMin` 支持“只读资产 + 可写磁盘”的组合。
- **流式哈希**：`Sha256File` 用 `io.Copy` 流式计算，适合大文件。

## 快速开始

```go
package main

import (
	"embed"
	"fmt"

	"github.com/shibingli/ydx/afs"
	"github.com/spf13/afero"
)

//go:embed assets
var embedded embed.FS

func main() {
	// 只读内嵌资产。afs.FS 就是 afero.Fs，可直接使用 afero 的读写辅助函数。
	assets := afs.NewEmbed(embedded)
	b, err := afero.ReadFile(assets, "assets/logo.svg")
	if err != nil {
		fmt.Println("read:", err)
		return
	}
	fmt.Println(len(b))

	// 操作系统目录 + 内嵌兜底：写入磁盘，读取回落到内嵌。
	root := afs.NewOS("/srv/app")
	fsys := afs.Overlay(assets, root)
	_ = afs.WriteFileIfChanged(fsys, "assets/generated.css", []byte("body{}"))

	// 测试用内存文件系统。
	mem := afs.NewMem()
	_ = afs.WriteFileIfChanged(mem, "config.yaml", []byte("name: test\n"))
}
```

## 应用场景

- **配置加载**：从磁盘、内存或嵌入目录读取 yaml/toml/json。
- **模板与静态资源**：开发期读磁盘，生产期读 `go:embed`。
- **热重载**：`WriteFileIfChanged` 避免无谓写入触发文件监听与全量重载。
- **单元测试**：`NewMem` 提供隔离、无磁盘依赖的文件系统。
- **虚拟化/镜像**：`Overlay` 把只读镜像垫在可写层下。
- **HTTP 静态文件**：`NewHTTPFileSystem` 适配 `http.FileSystem`。

## 性能指标

本模块没有独立基准；成本由底层 `afero.Fs` 决定：

- `NewMem` 的读写是内存操作，适合测试与短生命周期缓存。
- `NewOS` / `Overlay` 的读写受磁盘、页缓存与文件系统影响；`NewOS` 的根目录约束只做
  词法检查，不额外访问磁盘。
- `Walk` 是 O(目录条目数) 的深度优先遍历，按字典序返回；`filepath.SkipDir` 可跳过子树。
- `Sha256File` 流式读取，内存占用与文件大小无关。
- `WriteFileIfChanged` 内容相同时只读一次旧文件；不同时多一次临时文件写入与 rename。
- `WriteFileIfChanged` 的原子替换依赖同目录临时文件，跨文件系统 rename 不适用。

> 需要吞吐数字时，应在目标存储上对 `afero` 后端做基准；本模块不做缓存或预读。

## 第三方依赖与鸣谢

| 依赖 | 版本 | 许可证 | 用途 |
|---|---|---|---|
| [`spf13/afero`](https://github.com/spf13/afero) | v1.15.0 | Apache-2.0 | 文件系统抽象、OS/Mem/Overlay 实现 |

仓库内依赖：`errs`。

## 相关模块

- [`config`](../config/README.md)：从 `afero.Fs` 读取配置。
- [`i18n`](../i18n/README.md)：从 `afero.Fs` 加载语言目录。
- [`render`](../render/README.md)：从 `afero.Fs` 加载模板。
- [`openapi`](../openapi/README.md)：从 `afero.Fs` 扫描注解与提供查看器资源。
- [`router`](../router/README.md)：静态文件与模板渲染。

## 许可证

Apache-2.0，见仓库根目录 [`LICENSE`](../LICENSE)。
