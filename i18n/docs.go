// Package i18n loads multi-language message catalogs from any afero filesystem and negotiates the request language for the router. | Package i18n 从任意 afero 文件系统加载多语言消息目录，并为路由协商请求语言。
// One file per language, named after its tag: `zh-CN.yaml`, `en.toml`, `ja.json`. | 每种语言一份文件，文件名即语言标签：`zh-CN.yaml`、`en.toml`、`ja.json`。
// The file base name is the language tag and `_` is normalized to `-`, so `zh_CN.yaml` and `zh-CN.yaml` are the same language. | 文件名（去扩展名）即语言标签，`_` 归一化为 `-`，故 `zh_CN.yaml` 与 `zh-CN.yaml` 是同一种语言。
// Catalogs are parsed by viper, sharing the parser of the framework configuration center; keys are therefore normalized to lower case and lookups are case-insensitive while message values keep their original spelling. | 目录文件由 viper 解析，与框架配置中心复用同一套解析能力；因此键名统一归一化为小写、查找对大小写不敏感，而消息正文保留原始拼写。
// Wire it once at startup with `b, err := i18n.New(afs.NewOS("configs/langs"), ".", "zh-CN")`, then `r.Use(i18n.Middleware(b, i18n.Options{}))` and `r.SetRenderer(render.New().Funcs(render.FuncMap{"t": i18n.TemplateFunc}))`. | 启动时装配一次即可：`b, err := i18n.New(afs.NewOS("configs/langs"), ".", "zh-CN")`，随后 `r.Use(i18n.Middleware(b, i18n.Options{}))` 与 `r.SetRenderer(render.New().Funcs(render.FuncMap{"t": i18n.TemplateFunc}))`。
//
// Hot path: catalogs are flattened and every message is precompiled once at load/Reload; reads take
// an immutable snapshot through atomic.Pointer and never lock. A message without arguments or
// placeholders is returned verbatim, with zero allocations. | 热路径：目录在加载/热重载时被扁平化，
// 每条消息预编译一次；读取通过 atomic.Pointer 取不可变快照，全程不加锁。无参数、无占位符的消息
// 原样返回，零分配。
//
// The Bundle itself has no HTTP dependency: a standard net/http handler can call
// Bundle.MatchLanguage with the request's Accept-Language header and Bundle.Translator to
// obtain the translated message. | Bundle 本身不依赖 HTTP：标准 net/http 处理器可以用
// Bundle.MatchLanguage 读取请求的 Accept-Language 头，再用 Bundle.Translator 取得译文。
package i18n
