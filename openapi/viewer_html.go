package openapi

import _ "embed"

// indexHTML is the standalone viewer template, embedded from index.html. | indexHTML 是从
// index.html 内嵌的独立查看器模板。
//
//go:embed pages/page/index.html
var indexHTML []byte

// indexCSS is the standalone viewer stylesheet, embedded from index.css. | indexCSS 是从
// index.css 内嵌的独立查看器样式表。
//
//go:embed pages/assets/index.css
var indexCSS []byte

// indexIcons is the standalone viewer icon sprite, embedded from icons.svg. | indexIcons 是从
// icons.svg 内嵌的独立查看器图标 sprite。
//
//go:embed pages/assets/icons.svg
var indexIcons []byte

// viewerTemplate is the built-in single page viewer as a string. | viewerTemplate 是内置单页
// 查看器的字符串形式。
//
// Layout: a navigation list on the left and the selected object on the right. The viewer
// renders document metadata, servers, tags, security schemes and their OAuth flows, operations
// with parameters, request bodies, responses, headers, links and callbacks, webhooks, component
// schemas with composition keywords and constraints, and every x-* extension. | 布局：左侧导航
// 列表，右侧当前对象。查看器渲染文档元数据、服务器、标签、安全方案及其 OAuth 流程，操作及其参数、
// 请求体、响应、响应头、链接与回调，Webhooks，组件 Schema 的组合关键字与约束，以及全部 x-* 扩展。
//
// Every dynamic value is HTML escaped by the esc() helper before injection; URLs are only
// emitted for http(s) schemes. | 所有动态值在注入前均由 esc() 辅助函数做 HTML 转义；只有 http(s)
// 地址会作为链接输出。
var viewerTemplate = string(indexHTML)

// ViewerHTML returns a copy of the standalone viewer template. | ViewerHTML 返回独立查看器模板的副本。
//
// The template contains placeholders for the page title, the escaped JSON document, the script
// URL, the stylesheet URL and the icon sprite URL. Most callers want ViewerPage, which fills
// them; this accessor is for packaging or inspecting the raw index.html shipped with the module.
// | 模板包含页面标题、转义后的 JSON 文档、脚本 URL、样式表 URL 与图标 sprite URL 的占位符。
// 多数调用方应使用会填充它们的 ViewerPage；本访问器用于打包或检查模块随附的原始 index.html。
func ViewerHTML() []byte {
	return append([]byte(nil), indexHTML...)
}

// ViewerCSS returns a copy of the embedded viewer stylesheet. | ViewerCSS 返回内嵌查看器样式表的副本。
//
// Callers packaging the viewer themselves can write these bytes next to index.html and point
// Options.ViewerCSS at the resulting URL. | 自行打包查看器的调用方可以把这些字节写在 index.html
// 旁边，并把 Options.ViewerCSS 指向最终 URL。
func ViewerCSS() []byte {
	return append([]byte(nil), indexCSS...)
}

// ViewerIcons returns a copy of the embedded viewer icon sprite. | ViewerIcons 返回内嵌查看器
// 图标 sprite 的副本。
//
// The sprite contains the three theme-toggle symbols (sun, moon, monitor). | sprite 包含三个主题
// 切换图标（太阳、月亮、显示器）。
func ViewerIcons() []byte {
	return append([]byte(nil), indexIcons...)
}
