# i18n — 多语言目录加载与语言协商

`github.com/shibingli/ydx/i18n` 从任意 `afero` 文件系统加载多语言消息目录，并为路由协商
请求语言。每种语言一份文件，文件名即语言标签：`zh-CN.yaml`、`en.toml`、`ja.json`。
目录文件由 viper 解析，与框架配置中心复用同一套解析能力。

| 项 | 值 |
|---|---|
| 模块路径 | `github.com/shibingli/ydx/i18n` |
| 包名 | `i18n` |
| Go 版本 | 1.27.3 |
| 许可证 | Apache-2.0 |
| 默认查询参数 | `lang`（`DefaultQueryParam`） |
| 默认请求头 | `X-Lang`（`HeaderName`） |

## 功能

- `New(fsys, dir, defaultLang)`：加载目录，返回 `*Bundle`。
- `Bundle.MatchLanguage(accept)`：按 `Accept-Language` 协商语言。
- `Bundle.Translator(lang)`：取得某语言的 `*Translator`。
- `Translator.T(key, args...)`：翻译并格式化消息；`Translator.T` 本身可作为模板函数。
- `Bundle.Reload()`：热重载目录。
- `Bundle.Langs()` / `Catalog()` / `DefaultLang()` / `Misses()` / `FormatErrors()`。
- `Middleware(bundle, Options)`：YD 路由中间件，按查询参数、Cookie、请求头与
  `Accept-Language` 选择语言。
- `TemplateFunc(c)`：从 `*router.Ctx` 取得模板翻译函数。
- `FromContext(c)`：读取当前请求的 `*Translator`。
- `Problem` / `ProblemKind` / `SetProblemHandler`：缺失键与格式化错误的可观测回调。

## 特性

- **文件名即语言**：`zh_CN.yaml` 与 `zh-CN.yaml` 视为同一语言；目录键统一小写，查找
  大小写不敏感，消息正文保留原始拼写。
- **无锁热路径**：目录在加载/重载时扁平化并预编译；读取通过 `atomic.Pointer` 取不可变
  快照，全程不加锁。
- **零分配简单消息**：无参数、无占位符的消息原样返回，不分配。
- **HTTP 无关核心**：`Bundle` 本身不依赖 HTTP；原生 `net/http` 处理器可直接调用
  `MatchLanguage` 与 `Translator`。
- **多种语言来源**：查询参数（默认 `lang`）、Cookie（默认 `yd_lang`）、请求头
  （默认 `X-Lang`）与 `Accept-Language`。
- **响应头**：`LanguageHeader`（`Content-Language`）可用于回写协商结果。
- **可观测**：缺失键与格式化错误分别计数，并可挂接 `ProblemHandler`。
- **模板集成**：`Translator.T` 可直接注册进 `render.FuncMap`。

## 快速开始

```go
package main

import (
	"net/http"

	"github.com/shibingli/ydx/afs"
	"github.com/shibingli/ydx/i18n"
	"github.com/shibingli/ydx/router"
)

func main() {
	bundle, err := i18n.New(afs.NewOS("configs/langs"), ".", "zh-CN")
	if err != nil {
		return
	}

	r := router.New()
	r.Use(i18n.Middleware(bundle, i18n.Options{}))
	r.GET("/", func(c *router.Ctx) {
		t := i18n.FromContext(c)
		_ = c.String(http.StatusOK, t.T("welcome", "Ada"))
	})

	_ = http.ListenAndServe(":8080", r)
}
```

原生 `net/http`：

```go
func handler(w http.ResponseWriter, r *http.Request) {
	lang := bundle.MatchLanguage(r.Header.Get("Accept-Language"))
	w.Header().Set(i18n.LanguageHeader, lang)
	_, _ = w.Write([]byte(bundle.Translator(lang).T("welcome", "Ada")))
}
```

模板集成：

```go
engine.AddFunc("t", func(key string, args ...any) string {
	return bundle.Translator(currentLang).T(key, args...)
})
```

> 更推荐在每次渲染时把对应语言的 `Translator.T` 注入渲染数据，而不是在全局函数里读取
> 共享变量；`Translator` 不可变且始终反映最新 `Reload`。

## 应用场景

- **多语言网站**：页面文案、导航、表单提示。
- **API 错误消息**：按 `Accept-Language` 返回本地化错误文案。
- **邮件/通知模板**：按用户语言渲染。
- **管理后台**：运行时切换语言并热重载目录。
- **与 `errs` 配合**：用哨兵身份作为消息键，集中维护翻译。

## 性能指标

本模块没有独立基准；热路径设计：

- 目录在 `New` / `Reload` 时扁平化并预编译一次；读取只做 `atomic.Pointer` 加载与 map
  查找，不加锁。
- 无参数、无占位符的消息原样返回，零分配。
- 带参数的消息需要一次格式化分配；缺失键直接返回键本身，并递增 `Misses`。
- `MatchLanguage` 解析 `Accept-Language` 的 q 值排序；只在中间件每请求执行一次。
- `Reload` 原子替换快照，不阻塞正在进行的读取。

> 需要吞吐数字时，应以目录规模与消息命中率为变量做基准；本模块不做磁盘 I/O 缓存之外的
> 额外缓存。

## 第三方依赖与鸣谢

| 依赖 | 版本 | 许可证 | 用途 |
|---|---|---|---|
| [`spf13/viper`](https://github.com/spf13/viper) | v1.21.0 | MIT | YAML/TOML/JSON 目录解析 |
| [`spf13/afero`](https://github.com/spf13/afero) | v1.15.0 | Apache-2.0 | 语言目录文件系统 |

仓库内依赖：`afs`、`errs`、`json`、`router`。

## 相关模块

- [`render`](../render/README.md)：模板中注入 `Translator.T`。
- [`router`](../router/README.md)：中间件与 `*Ctx`。
- [`afs`](../afs/README.md)：语言目录来源。
- [`config`](../config/README.md)：复用 viper 解析能力。
- [`errs`](../errs/README.md)：错误哨兵作为消息键。

## 许可证

Apache-2.0，见仓库根目录 [`LICENSE`](../LICENSE)。
