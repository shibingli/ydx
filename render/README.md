# render — 编译式 html/template 引擎

`github.com/shibingli/ydx/render` 把 `html/template` 模板集编译为不可变、高吞吐的执行
程序。`html/template` 仍是解析器与上下文转义器，因此语法与安全语义与标准库完全一致；
执行阶段换成自研节点遍历，不再承担 `text/template` 每次渲染的反射装配开销。

| 项 | 值 |
|---|---|
| 模块路径 | `github.com/shibingli/ydx/render` |
| 包名 | `render` |
| Go 版本 | 1.27.3 |
| 许可证 | Apache-2.0 |
| 默认扩展名 | `.html`、`.gotmpl` |

## 功能

- `New(fsys, Options)`：扫描根目录、解析并编译模板集。
- `Engine.Render(w, name, data)`：渲染指定模板。
- `Engine.RenderAppend(dst, name, data)`：追加到调用方缓冲。
- `Engine.AcquireBuffer` / `ReleaseBuffer`：复用输出缓冲。
- `Engine.AddFunc` / `FuncMap`：注册模板函数。
- `Engine.Exists` / `Names` / `Filesystem` / `Options`。
- `Engine.Clone()`：派生独立引擎。
- `Engine.UsesFallback(name)`：检测某模板是否走了标准库回退执行器。
- `Dev` 模式：每次渲染重新编译，模板改动无需重启。
- `TranslatorKey`、`AuthzKey`、`LayoutKey`：从渲染数据注入译者、权限主体与布局。

## 特性

- **标准库语义**：解析、HTML/JS/CSS/URL 上下文转义、危险 URL 协议拦截全部由
  `html/template` 完成。
- **加载期编译**：`New` 时编译为不可变程序；渲染只做指针遍历，没有解析、clone 或逐请求
  函数表重建。
- **按次执行绑定**：译者与权限主体存放在每次渲染的状态中，不为每个语言/角色组合克隆
  整棵模板树。
- **零装箱热路径**：单字段动作走 `reflect.Value` 直通，字符串/整数/布尔不装箱；
  单绑定动作（`tr`、`perm`、`can`）有无接口输出路径。
- **单遍链式转义**：URL 过滤、规范化、百分号编码与属性转义在同一遍扫描中完成。
- **缓冲复用**：按页面实际增长后的容量保留输出缓冲。
- **并发安全**：渲染经原子指针读取不可变快照，并按调用分配状态。
- **回退检测**：`UsesFallback` 让框架模板集在跨包场景下断言仍处于快速执行器路径。

## 快速开始

```go
package main

import (
	"embed"
	"net/http"
	"strings"

	"github.com/shibingli/ydx/afs"
	"github.com/shibingli/ydx/render"
)

//go:embed templates
var templates embed.FS

type PageData struct {
	Title string
	Users []string
}

func main() {
	engine, err := render.New(afs.NewEmbed(templates), render.Options{
		Root: "templates",
		Dev:  false,
	})
	if err != nil {
		return
	}
	engine.AddFunc("upper", strings.ToUpper)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		err := engine.Render(w, "pages/users.html", PageData{
			Title: "Users",
			Users: []string{"Ada", "Linus"},
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
	_ = http.ListenAndServe(":8080", nil)
}
```

模板中使用译者与权限：

```gotemplate
{{ tr "page.users.title" }}
{{ if can "users.read" }}...{{ end }}
```

译者通过渲染数据中的 `render.TranslatorKey` 注入；未注入时 `tr` 返回键本身。权限同理，
通过 `render.AuthzKey` 注入。

## 应用场景

- **服务端渲染（SSR）**：高 QPS 页面、管理后台、营销页。
- **多语言站点**：结合 `i18n` 注入译者。
- **权限感知页面**：`can` / `perm` 按角色渲染。
- **开发热重载**：`Dev` 模式让模板修改立即生效。
- **静态资源版本化**：`Production` 与 asset 助手配合。
- **安全页面**：依赖标准库上下文转义与危险 URL 拦截。

## 性能指标

基准模块：[`benchmarks/template`](../benchmarks/template/README.md)。参考环境为
AMD Ryzen AI MAX+ 395、Go 1.27.3、Linux，`GOMAXPROCS=32`、`-count=5`、
`-benchtime=500ms` 中位数。

100 行列表页（`page100`）：

| 引擎 | 流式（`io.Discard`） | 物化（可复用 buffer） | page100 allocs/op |
|---|---:|---:|---:|
| quicktemplate | **15,147 ns** | 21,458 ns | 0 |
| **yd-render** | 18,326 ns | **18,777 ns** | **0** |
| templ | 58,521 ns | 57,568 ns | 1,823 |
| Jet | 67,480 ns | 71,476 ns | 6 |
| text/template | 103,015 ns | 107,100 ns | 811 |
| html/template | 472,690 ns | 473,245 ns | 7,142 |

- 物化口径下 yd-render 反超 quicktemplate 约 13%；流式口径下 quicktemplate 快约 21%
  （它是编译期生成的 Go 代码，不物化输出）。
- 比 `html/template` 快约 25.8×（page100），比 `text/template` 快约 5.6×，比 Jet 快约
  3.7×，比 templ 快约 3.2×，且 `page100` 为 0 allocs/op。
- 渲染微基准（带绑定）：253.7 ns；`html/template` 3.43 µs、`text/template` 2.12 µs。
- 并行吞吐约为 `html/template` 的 36.9×，顺序到并行加速约 4.8×。

> 不同引擎的模板语法不同，输出不要求逐字节相同；转义语义由 `TestEscapingMatrix` 实测。
> 完整表格与兼容性矩阵见基准 README。

## 第三方依赖与鸣谢

| 依赖 | 版本 | 许可证 | 用途 |
|---|---|---|---|
| [`spf13/afero`](https://github.com/spf13/afero) | v1.15.0 | Apache-2.0 | 模板来源文件系统 |

仓库内依赖：`afs`、`errs`、`json`、`log`。

本模块的解析与转义直接使用 Go 标准库 `html/template` / `text/template`，不引入第三方
模板引擎；鸣谢 Go 团队在上下文转义与模板语法上的工作。

基准对比对象：`html/template`、`text/template`、Jet、Pongo2、Liquid、Raymond、Mustache、
quicktemplate、templ，仅出现在 `benchmarks/template`。

## 相关模块

- [`i18n`](../i18n/README.md)：注入译者与多语言目录。
- [`router`](../router/README.md)：`SetRenderer` 与 `HTML` 渲染。
- [`afs`](../afs/README.md)：模板文件系统。
- [`openapi`](../openapi/README.md)：查看器页面也使用模板资源。

## 许可证

Apache-2.0，见仓库根目录 [`LICENSE`](../LICENSE)。
